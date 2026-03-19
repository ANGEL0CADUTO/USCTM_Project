#define EXPORT_SYMTAB
#include <linux/module.h>       
#include <linux/kernel.h>       
#include <linux/fs.h>           
#include <linux/cdev.h>         
#include <linux/device.h>       
#include <linux/slab.h>         
#include <linux/uaccess.h>      
#include <linux/hashtable.h>    
#include <linux/list.h>         
#include <linux/rculist.h>      
#include <linux/rcupdate.h>     
#include <linux/spinlock.h>     
#include <linux/atomic.h>       
#include <linux/sched.h>        
#include <linux/time.h>         
#include <linux/version.h>      
#include <linux/mm.h>
#include <linux/ktime.h>
#include <asm/page.h>           
#include <linux/jiffies.h>      
#include <linux/syscalls.h>     
#include <linux/percpu.h>      
#include <linux/kprobes.h>      
#include <linux/ftrace.h>       
#include <linux/delay.h>        

#include "sc_throttler.h" 

// Module metadata
// Developed and tested on Linux kernel 5.15.0-173-generic (x86-64)
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Angelo Romano");
MODULE_DESCRIPTION("System Call Throttler");
MODULE_VERSION("1.0");  


// Device driver setup
#define DEVICE_NAME "sc_throttler"
static int major_number;                 
static struct class* sc_driver_class = NULL;    
static struct device* sc_driver_device = NULL; 

// Global state for throttling
static atomic_t monitor_enabled = ATOMIC_INIT(0); 
static unsigned long max_throughput = 0; 
static atomic64_t global_counter = ATOMIC64_INIT(0); 
static unsigned long window_start_jiffies = 0;      
static spinlock_t window_reset_lock;                
static DECLARE_WAIT_QUEUE_HEAD(throttle_wq);        

// Data structures for rules and statistics
static DEFINE_HASHTABLE(rules_ht, HT_BITS); 
static DEFINE_MUTEX(conf_mutex);  
static DEFINE_PER_CPU(struct sc_cpu_stats, cpu_stats); 
static struct sc_peak_record peak_record;       
static unsigned long module_load_time_jiffies = 0; 
static unsigned long long last_window_blocked_sum = 0; 

static atomic_t active_threads = ATOMIC_INIT(0);

// Synchronous anti-recursion guard to prevent ftrace loops
DEFINE_PER_CPU(int, sc_in_hook); 

// Structure to hold ftrace hook information
struct ftrace_hook {
    const char *name;           
    void *function;             
    void *original;             
    unsigned long address;      
    struct ftrace_ops ops;      
    int registered;             
    unsigned long syscall_nr;
};

// Array to store hooks for each syscall number
#define MAX_SYSCALL_NR 512
static struct ftrace_hook __rcu *hooks[MAX_SYSCALL_NR];

// Simple string hash function for process names
unsigned long string_hash(const char *str){
    unsigned long hash = 0;
    int c;
    while((c=*str++)) hash = c + (hash << 6) + (hash << 16) - hash;
    return hash;
}

// Function pointer type for kallsyms lookup
typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
static kallsyms_lookup_name_t kallsyms_lookup_name_ref;

// Function pointer type for original syscall execution
typedef long (*sys_call_ptr_t)(struct pt_regs *);

// Safely lookup a kernel symbol address using kprobes
static unsigned long safe_lookup_name(const char *name) {
    if (!kallsyms_lookup_name_ref) {
        struct kprobe kp = { .symbol_name = "kallsyms_lookup_name" };
        if (register_kprobe(&kp) < 0) return 0;
        kallsyms_lookup_name_ref = (kallsyms_lookup_name_t)kp.addr;
        unregister_kprobe(&kp);
    }
    return kallsyms_lookup_name_ref(name);
}

// Pointer to the system call table
static unsigned long *sys_call_table = NULL;

// Ftrace callback function that redirects syscalls to our wrapper
static void notrace fh_ftrace_thunk(unsigned long ip, unsigned long parent_ip,
                                    struct ftrace_ops *ops, struct ftrace_regs *fregs) {
    struct pt_regs *regs = ftrace_get_regs(fregs); 
    struct ftrace_hook *hook = container_of(ops, struct ftrace_hook, ops);
    
    // If the current CPU has the guard raised, ignore the hook to prevent ftrace loops
    if (this_cpu_read(sc_in_hook)) return;

    if (regs) {
        regs->ip = (unsigned long)hook->function;
    }
}

// Install an ftrace hook for a specific syscall
static int fh_install_hook(struct ftrace_hook *hook) {
    int err;

    hook->ops.func = fh_ftrace_thunk;
    hook->ops.flags = FTRACE_OPS_FL_SAVE_REGS | FTRACE_OPS_FL_RECURSION | FTRACE_OPS_FL_IPMODIFY;

    err = ftrace_set_filter_ip(&hook->ops, hook->address, 0, 0);
    if (err) return err;

    err = register_ftrace_function(&hook->ops);
    if (err) {
        // Roll back the filter if registration fails
        ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
        return err;
    }

    hook->registered = 1;
    return 0;
}

// Remove an ftrace hook
static void fh_remove_hook(struct ftrace_hook *hook) {
    if (hook && hook->registered) {
        unregister_ftrace_function(&hook->ops);
        ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
        hook->registered = 0;
    }
}

// Check if the current syscall should be throttled based on throughput limits
int check_throttle(void){
    unsigned long now = jiffies;
    unsigned long flags;
    u64 val;
    int cpu;
    unsigned long long current_total_blocked = 0;
    unsigned long long window_blocked_delta = 0;

    // Reset the window every second (HZ jiffies)
    if(time_after(now, READ_ONCE(window_start_jiffies) + HZ)){
        spin_lock_irqsave(&window_reset_lock, flags);
        if(time_after(now, window_start_jiffies + HZ)){
            // Calculate total blocked calls across all CPUs
            for_each_online_cpu(cpu) current_total_blocked += per_cpu(cpu_stats.blocked_count, cpu);
            window_blocked_delta = current_total_blocked - last_window_blocked_sum;
            last_window_blocked_sum = current_total_blocked;

            // Update peak blocked window if necessary
            spin_lock(&peak_record.lock);
            if (window_blocked_delta > peak_record.peak_blocked_window) peak_record.peak_blocked_window = window_blocked_delta;
            spin_unlock(&peak_record.lock);

            // Reset counters for new window
            WRITE_ONCE(window_start_jiffies, now);
            atomic64_set(&global_counter, 0);
            wake_up_all(&throttle_wq);
        }
        spin_unlock_irqrestore(&window_reset_lock, flags);
    }

    // Increment global counter and check against max throughput
    val = atomic64_inc_return(&global_counter);
    if(val > max_throughput) return 1;
    return 0;
}

// Main syscall hook wrapper that intercepts and potentially throttles syscalls
asmlinkage long sys_hook_wrapper(struct pt_regs *regs) {
    unsigned long syscall_nr = regs->orig_ax; 
    int should_block = 0;
    unsigned long flags;
    ktime_t start_time, end_time;
    s64 delta;
    int is_syscall_monitored;
    int entity_match;
    unsigned long name_hash;
    struct sc_rule *rule;
    long ret;
    long timeout_jiffies;
    long wait_ret;
    struct ftrace_hook *hook;
    sys_call_ptr_t orig_func;

    // Validate syscall number
    if (unlikely(syscall_nr >= MAX_SYSCALL_NR)) return -ENOSYS; 

    atomic_inc(&active_threads);

retry_throttling:
    // Reset per-attempt flags before every retry
    is_syscall_monitored = 0;
    entity_match = 0;
    should_block = 0;
    orig_func = NULL;

    // Start RCU protection before reading hook pointer
    rcu_read_lock();

    // Safely read the hook pointer under RCU
    hook = rcu_dereference(hooks[syscall_nr]);

    // If the hook was unpublished while we entered the wrapper, fall back to the original syscall
    // through the syscall table to preserve user-space semantics
    if (unlikely(!hook)) {
        rcu_read_unlock();
        atomic_dec(&active_threads);

        if (sys_call_table && sys_call_table[syscall_nr])
            return ((sys_call_ptr_t)sys_call_table[syscall_nr])(regs);

        return -ENOSYS;
    }

    // Cache the original function pointer while hook memory is still protected by RCU
    orig_func = (sys_call_ptr_t)hook->original;

    // If monitoring is disabled, execute original syscall
    if (!atomic_read(&monitor_enabled)) {
        rcu_read_unlock();
        goto execute_original;
    }

    // 1. Check if this syscall is registered for monitoring
    hash_for_each_possible_rcu(rules_ht, rule, node, syscall_nr) {
        if(rule->type == MON_SYSCALL && rule->key == syscall_nr) {
            is_syscall_monitored = 1;
            break;
        }
    }

    if (!is_syscall_monitored) {
        rcu_read_unlock();
        goto execute_original;
    }

    // 2. Check if the current user or process is registered (as per spec 1.1)
    hash_for_each_possible_rcu(rules_ht, rule, node, current_euid().val) {
        if (rule->type == MON_UID && rule->key == current_euid().val) {
            entity_match = 1;
            break;
        }
    }
    
    if (!entity_match) {
        name_hash = string_hash(current->comm);
        hash_for_each_possible_rcu(rules_ht, rule, node, name_hash) {
            if (rule->type == MON_NAME && rule->key == name_hash) {
                if (strncmp(rule->name, current->comm, 16) == 0) {
                    entity_match = 1;
                    break;
                }
            }
        }
    }

    // Strict compliance: distinguish between generic user (Allowed) and monitored user (Throttled)
    if (!entity_match) {
        rcu_read_unlock();
        goto execute_original;
    }

    // Decide if we should throttle this call
    should_block = check_throttle();
    rcu_read_unlock(); 

    if(should_block){
        // Increment blocked count for this CPU
        this_cpu_inc(cpu_stats.blocked_count);
        start_time = ktime_get();
        
        // Wait until the end of the current window or monitoring is disabled
        timeout_jiffies = (long)(READ_ONCE(window_start_jiffies) + HZ - jiffies);
        if (timeout_jiffies < 1) timeout_jiffies = 1;

        wait_ret = wait_event_interruptible_timeout(throttle_wq, 
             !atomic_read(&monitor_enabled), 
             timeout_jiffies
        );

        // If interrupted, execute original syscall
        if (wait_ret == -ERESTARTSYS) goto execute_original; 

        // Record the delay for peak statistics
        end_time = ktime_get();
        delta = ktime_to_ns(ktime_sub(end_time, start_time));
        spin_lock_irqsave(&peak_record.lock, flags);
        if (delta > peak_record.delay_ns) {
            peak_record.delay_ns = delta;
            peak_record.uid = current_euid().val;
            memcpy(peak_record.comm, current->comm, 16);
        }
        spin_unlock_irqrestore(&peak_record.lock, flags);

        // Retry throttling check after waiting
        goto retry_throttling;
    }

execute_original:
    // Execute the original syscall with anti-recursion guard
    preempt_disable();
    this_cpu_write(sc_in_hook, 1);

    ret = orig_func(regs);

    this_cpu_write(sc_in_hook, 0);
    preempt_enable();

    atomic_dec(&active_threads);
    return ret;
}

// ---- IOCTL ----
// IOCTL handler for configuring the throttler via device file
static long sc_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {
    struct sc_conf conf;
    struct sc_stats stats;
    struct sc_rule *rule;
    struct hlist_node *tmp;
    unsigned long cpu_blocked = 0;
    int cpu;
    int ret = 0;
    unsigned long key;
    int found;
    unsigned long elapsed;
    unsigned long target_addr;
    struct ftrace_hook *h; 

    // Only root can configure
    if (current_euid().val != 0) return -EPERM;
    mutex_lock(&conf_mutex);

    switch (cmd) {
        case IOCTL_ADD_RULE: {
            // Add a new monitoring rule
            if (copy_from_user(&conf, (struct sc_conf __user *)arg, sizeof(conf))) {
                ret = -EFAULT;
                break;
            }

            // Validate rule type and payload before proceeding
            if (conf.type != MON_SYSCALL && conf.type != MON_UID && conf.type != MON_NAME) {
                ret = -EINVAL;
                break;
            }

            if (conf.type == MON_SYSCALL && conf.value >= MAX_SYSCALL_NR) {
                ret = -EINVAL;
                break;
            }

            if (conf.type == MON_NAME)
                conf.name[15] = '\0';

            key = (conf.type == MON_NAME) ? string_hash(conf.name) : conf.value;
            found = 0;

            // Reject duplicates to keep the rule-set and hook-set consistent
            rcu_read_lock();
            hash_for_each_possible_rcu(rules_ht, rule, node, key) {
                if (rule->type != conf.type) continue;
                if (rule->key != key) continue;
                if (conf.type == MON_NAME && strncmp(rule->name, conf.name, 16) != 0) continue;
                found = 1;
                break;
            }
            rcu_read_unlock();

            if (found) {
                ret = -EEXIST;
                break;
            }

            // If it's a syscall rule, install the hook BEFORE publishing the rule
            if (conf.type == MON_SYSCALL) {
                if (rcu_access_pointer(hooks[conf.value])) {
                    ret = -EEXIST;
                    break;
                }

                if (!sys_call_table) {
                    ret = -EINVAL;
                    break;
                }

                target_addr = sys_call_table[conf.value];
                if (!target_addr) {
                    ret = -EINVAL;
                    break;
                }

                h = kmalloc(sizeof(struct ftrace_hook), GFP_KERNEL);
                if (!h) {
                    ret = -ENOMEM;
                    break;
                }

                memset(h, 0, sizeof(struct ftrace_hook));
                h->address = target_addr;
                h->function = sys_hook_wrapper; 
                h->original = (void*)target_addr; 
                h->syscall_nr = conf.value;
                h->registered = 0;

                ret = fh_install_hook(h);
                if (ret) {
                    kfree(h);
                    break;
                }

                rcu_assign_pointer(hooks[conf.value], h);
                printk(KERN_INFO "SC_THROTTLER: Hook installed on Syscall %lu\n", conf.value);
            }

            rule = kmalloc(sizeof(struct sc_rule), GFP_KERNEL);
            if (!rule) {
                // Roll back hook installation if rule allocation fails after syscall hook install
                if (conf.type == MON_SYSCALL) {
                    h = rcu_dereference_protected(hooks[conf.value], lockdep_is_held(&conf_mutex));
                    if (h) {
                        RCU_INIT_POINTER(hooks[conf.value], NULL);
                        fh_remove_hook(h);
                        synchronize_rcu();
                        kfree(h);
                    }
                }
                ret = -ENOMEM;
                break;
            }

            rule->type = conf.type;
            rule->key = key;
            if (conf.type == MON_NAME) {
                memcpy(rule->name, conf.name, 16);
            } else {
                rule->name[0] = '\0';
            }

            hash_add_rcu(rules_ht, &rule->node, rule->key);
            break;
        }

        case IOCTL_DEL_RULE: {
            // Delete an existing rule
            struct ftrace_hook *old_hook = NULL;

            if (copy_from_user(&conf, (struct sc_conf __user *)arg, sizeof(conf))) {
                ret = -EFAULT;
                break;
            }

            // Validate input before lookup
            if (conf.type != MON_SYSCALL && conf.type != MON_UID && conf.type != MON_NAME) {
                ret = -EINVAL;
                break;
            }

            if (conf.type == MON_SYSCALL && conf.value >= MAX_SYSCALL_NR) {
                ret = -EINVAL;
                break;
            }

            if (conf.type == MON_NAME)
                conf.name[15] = '\0';

            key = (conf.type == MON_NAME) ? string_hash(conf.name) : conf.value;
            found = 0;

            hash_for_each_possible_safe(rules_ht, rule, tmp, node, key) {
                if (rule->type != conf.type) continue;
                if (rule->key != key) continue;
                if (conf.type == MON_NAME && strncmp(rule->name, conf.name, 16) != 0) continue;

                // If it's a syscall rule, remove the hook safely
                if (rule->type == MON_SYSCALL) {
                    old_hook = rcu_dereference_protected(hooks[rule->key], lockdep_is_held(&conf_mutex));
                    if (old_hook) {
                        // First disconnect ftrace so no new callbacks can enter the wrapper
                        fh_remove_hook(old_hook);

                        // Wait until all pre-existing RCU readers have left the wrapper
                        synchronize_rcu();

                        // Now it is safe to unpublish and free the hook
                        RCU_INIT_POINTER(hooks[rule->key], NULL);
                        kfree(old_hook);
                    }
                }

                hash_del_rcu(&rule->node);
                kfree_rcu(rule, rcu);
                found = 1;
                break; 
            }

            if (!found) ret = -ENOENT;
            break;
        }

        case IOCTL_SET_MAX: 
            // Set the maximum throughput
            if (arg == 0) {
                ret = -EINVAL;
                break;
            }
            max_throughput = arg; 
            break;

        case IOCTL_SET_ONOFF:
            // Enable or disable monitoring
            if (arg != 0 && arg != 1) {
                ret = -EINVAL;
                break;
            }

            if (arg == 0) {
                atomic_set(&monitor_enabled, 0);
                wake_up_all(&throttle_wq);
            } else {
                atomic_set(&monitor_enabled, 1);
            }
            break;

        case IOCTL_GET_STATS:
            // Retrieve current statistics
            for_each_online_cpu(cpu) cpu_blocked += per_cpu(cpu_stats.blocked_count, cpu);
            stats.blocked_total = cpu_blocked;
            elapsed = (jiffies - module_load_time_jiffies) / HZ;
            stats.avg_blocked = (elapsed > 0) ? cpu_blocked / elapsed : 0;

            spin_lock_irq(&peak_record.lock);
            stats.peak_delay_ns = peak_record.delay_ns;
            stats.peak_uid = peak_record.uid;
            stats.peak_blocked = peak_record.peak_blocked_window; 
            memcpy(stats.peak_comm, peak_record.comm, 16);
            spin_unlock_irq(&peak_record.lock);

            if (copy_to_user((struct sc_stats __user *)arg, &stats, sizeof(stats))) ret = -EFAULT;
            break;

        case IOCTL_LIST_RULES: {
            // List all current rules
            // Allocate a temporary buffer of one page (4KB) for the rules
            char *buf = kzalloc(PAGE_SIZE, GFP_KERNEL);
            int pos = 0;
            int bkt;
            
            if (!buf) {
                ret = -ENOMEM;
                break;
            }
            
            // Use RCU read lock to iterate the hash table safely and lock-free
            rcu_read_lock();
            hash_for_each_rcu(rules_ht, bkt, rule, node) {
                if (rule->type == MON_SYSCALL) 
                    pos += snprintf(buf + pos, PAGE_SIZE - pos, "SYSCALL : %lu\n", rule->key);
                else if (rule->type == MON_UID) 
                    pos += snprintf(buf + pos, PAGE_SIZE - pos, "UID     : %lu\n", rule->key);
                else if (rule->type == MON_NAME) 
                    pos += snprintf(buf + pos, PAGE_SIZE - pos, "NAME    : %s\n", rule->name);
                
                if (pos >= PAGE_SIZE - 64) break; // Prevent buffer overflow
            }
            rcu_read_unlock();
            
            if (pos == 0) {
                pos = snprintf(buf, PAGE_SIZE, "No rules registered.\n");
            }
            
            if (copy_to_user((char __user *)arg, buf, pos + 1)) ret = -EFAULT;
            kfree(buf);
            break;
        }

        default:
            ret = -EINVAL;
    }

    mutex_unlock(&conf_mutex);
    return ret;
}

// File operations for the device
static int sc_open(struct inode *inode, struct file *file) { return 0; }
static int sc_release(struct inode *inode, struct file *file){ return 0;}
static struct file_operations fops = { .owner = THIS_MODULE, .unlocked_ioctl = sc_ioctl, .open = sc_open, .release = sc_release };

// Module initialization
static int __init sc_throttler_init(void) {
    int i;

    printk(KERN_INFO "SC_THROTTLER: Initializing...\n");

    // Initialize locks and timestamps
    spin_lock_init(&window_reset_lock);
    spin_lock_init(&peak_record.lock);
    window_start_jiffies = jiffies;
    module_load_time_jiffies = jiffies; 

    // Initialize hook array explicitly
    for (i = 0; i < MAX_SYSCALL_NR; i++)
        RCU_INIT_POINTER(hooks[i], NULL);

    // Register the character device
    major_number = register_chrdev(0, DEVICE_NAME, &fops);
    if (major_number < 0) return major_number;

    sc_driver_class = class_create(THIS_MODULE, DEVICE_NAME);
    if (IS_ERR(sc_driver_class)) {
        unregister_chrdev(major_number, DEVICE_NAME);
        return PTR_ERR(sc_driver_class);
    }

    sc_driver_device = device_create(sc_driver_class, NULL, MKDEV(major_number, 0), NULL, DEVICE_NAME);
    if (IS_ERR(sc_driver_device)) {
        class_destroy(sc_driver_class);
        unregister_chrdev(major_number, DEVICE_NAME);
        return PTR_ERR(sc_driver_device);
    }

    // Locate the system call table
    sys_call_table = (unsigned long *)safe_lookup_name("sys_call_table");
    if (!sys_call_table) {
        device_destroy(sc_driver_class, MKDEV(major_number, 0));
        class_destroy(sc_driver_class);
        unregister_chrdev(major_number, DEVICE_NAME);
        return -EFAULT; 
    }
    
    return 0;
}

// Module cleanup
static void __exit sc_throttler_exit(void) {
    int i;
    struct sc_rule *rule;
    struct hlist_node *tmp;
    int bkt;
    struct ftrace_hook *to_free[MAX_SYSCALL_NR] = { NULL };
    
    // Disable monitoring and wake up any waiting threads
    atomic_set(&monitor_enabled, 0);
    wake_up_all(&throttle_wq);

    // First disconnect all ftrace hooks, but keep pointers published until
    // all pre-existing wrapper instances have safely left their RCU sections
    for (i = 0; i < MAX_SYSCALL_NR; i++) {
        struct ftrace_hook *old_hook;

        old_hook = rcu_dereference_protected(hooks[i], 1);
        if (old_hook) {
            to_free[i] = old_hook;
            fh_remove_hook(old_hook);
        }
    }

    // Wait until all old RCU readers have left the wrapper
    synchronize_rcu();

    // Now no new callbacks can enter, and old readers are gone:
    // unpublish hook pointers and free them
    for (i = 0; i < MAX_SYSCALL_NR; i++) {
        if (to_free[i]) {
            RCU_INIT_POINTER(hooks[i], NULL);
            kfree(to_free[i]);
        }
    }

    // Wakeup was already issued above; now active threads can drain safely
    while (atomic_read(&active_threads) > 0) {
        msleep(10);
    }

    // Remove all rules
    hash_for_each_safe(rules_ht, bkt, tmp, rule, node) {
        hash_del_rcu(&rule->node);
        kfree_rcu(rule, rcu);
    }

    // Ensure deferred rule reclamation has completed before module memory disappears
    synchronize_rcu();

    // Clean up device and unregister
    device_destroy(sc_driver_class, MKDEV(major_number, 0));
    class_destroy(sc_driver_class);
    unregister_chrdev(major_number, DEVICE_NAME);

    printk(KERN_INFO "SC_THROTTLER: Unloaded.\n");
}

module_init(sc_throttler_init);
module_exit(sc_throttler_exit);