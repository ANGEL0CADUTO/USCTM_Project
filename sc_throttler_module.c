/* sc_throttler_module.c
 * GOLDEN RELEASE: Safe Ftrace + Anti-Freeze + Deadlock Timeout
 * TARGET: Bare Metal / Kernel 5.15+
 */

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
#include <asm/page.h>           
#include <linux/jiffies.h>      
#include <linux/syscalls.h>     
#include <linux/percpu.h>      
#include <linux/kprobes.h>      
#include <linux/ftrace.h>       

#include "sc_throttler.h" //

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Angelo Romano");
MODULE_DESCRIPTION("System Call Throttler - Golden Ftrace");
MODULE_VERSION("8.0");  

// ---- GLOBALS ----
#define DEVICE_NAME "sc_throttler"
static int major_number;                 
static struct class* sc_driver_class = NULL;    
static struct device* sc_driver_device = NULL; 

static atomic_t monitor_enabled = ATOMIC_INIT(0); 
static unsigned long max_throughput = 0; 
static atomic64_t global_counter = ATOMIC64_INIT(0); 
static unsigned long window_start_jiffies = 0;      
static spinlock_t window_reset_lock;                
static DECLARE_WAIT_QUEUE_HEAD(throttle_wq);        

static DEFINE_HASHTABLE(rules_ht, HT_BITS); 
static DEFINE_MUTEX(conf_mutex);  
static DEFINE_PER_CPU(struct sc_cpu_stats, cpu_stats); 
static struct sc_peak_record peak_record;       
static unsigned long module_load_time_jiffies = 0; 
static unsigned long long last_window_blocked_sum = 0; 

// GUARDIA ANTI-RICORSIONE GLOBALE
DEFINE_PER_CPU(int, sc_in_hook); 

struct ftrace_hook {
    const char *name;           
    void *function;             
    void *original;             
    unsigned long address;      
    struct ftrace_ops ops;      
    int registered;             
    unsigned long syscall_nr;   
};

#define MAX_SYSCALL_NR 512
static struct ftrace_hook *hooks[MAX_SYSCALL_NR] = {NULL};

unsigned long string_hash(const char *str){
    unsigned long hash = 0;
    int c;
    while((c=*str++)) hash = c + (hash << 6) + (hash << 16) - hash;
    return hash;
}

// LOOKUP SICURO
typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
static kallsyms_lookup_name_t kallsyms_lookup_name_ref;

static unsigned long safe_lookup_name(const char *name) {
    if (!kallsyms_lookup_name_ref) {
        struct kprobe kp = { .symbol_name = "kallsyms_lookup_name" };
        if (register_kprobe(&kp) < 0) return 0;
        kallsyms_lookup_name_ref = (kallsyms_lookup_name_t)kp.addr;
        unregister_kprobe(&kp);
    }
    return kallsyms_lookup_name_ref(name);
}

static unsigned long *sys_call_table = NULL;

// ---- FTRACE MAGIC (ANTI-FREEZE) ----
static void notrace fh_ftrace_thunk(unsigned long ip, unsigned long parent_ip,
                                    struct ftrace_ops *ops, struct ftrace_regs *fregs) {
    
    struct pt_regs *regs = ftrace_get_regs(fregs); 
    struct ftrace_hook *hook = container_of(ops, struct ftrace_hook, ops);
    
    // GUARDIA: Se siamo già dentro, NON intercettiamo.
    // Questo previene il loop infinito su getpid e tail-call optimization.
    if (this_cpu_read(sc_in_hook)) return;

    if (regs) {
        regs->ip = (unsigned long)hook->function;
    }
}

static int fh_install_hook(struct ftrace_hook *hook) {
    int err;
    hook->ops.func = fh_ftrace_thunk;
    hook->ops.flags = FTRACE_OPS_FL_SAVE_REGS | FTRACE_OPS_FL_RECURSION | FTRACE_OPS_FL_IPMODIFY;

    err = ftrace_set_filter_ip(&hook->ops, hook->address, 0, 0);
    if (err) return err;

    err = register_ftrace_function(&hook->ops);
    if (err) return err;

    hook->registered = 1;
    return 0;
}

static void fh_remove_hook(struct ftrace_hook *hook) {
    if (hook->registered) {
        unregister_ftrace_function(&hook->ops);
        ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
        hook->registered = 0;
    }
}

// ---- THROTTLING LOGIC ----
int check_throttle(void){
    unsigned long now = jiffies;
    unsigned long flags;
    u64 val;
    int cpu;
    unsigned long long current_total_blocked = 0;
    unsigned long long window_blocked_delta = 0;

    if(time_after(now, READ_ONCE(window_start_jiffies) + HZ)){
        spin_lock_irqsave(&window_reset_lock, flags);
        if(time_after(now, window_start_jiffies + HZ)){
            for_each_online_cpu(cpu) current_total_blocked += per_cpu(cpu_stats.blocked_count, cpu);
            window_blocked_delta = current_total_blocked - last_window_blocked_sum;
            last_window_blocked_sum = current_total_blocked;
            spin_lock(&peak_record.lock);
            if (window_blocked_delta > peak_record.peak_blocked_window) peak_record.peak_blocked_window = window_blocked_delta;
            spin_unlock(&peak_record.lock);

            window_start_jiffies = now;
            atomic64_set(&global_counter, 0);
            wake_up_all(&throttle_wq);
        }
        spin_unlock_irqrestore(&window_reset_lock, flags);
    }
    val = atomic64_inc_return(&global_counter);
    if(val > max_throughput) return 1;
    return 0;
}

// ---- THE WRAPPER (TIMEOUT + ANTI-FREEZE) ----
asmlinkage long sys_hook_wrapper(struct pt_regs *regs) {
    int syscall_nr = regs->ax; 
    int should_block = 0;
    unsigned long flags;
    ktime_t start, end;
    s64 delta;
    int identity_match = 0;
    unsigned long name_hash;
    int *recursion_guard;
    struct sc_rule *rule;
    long ret;
    long timeout_jiffies;

    // 1. ATTIVAZIONE GUARDIA
    recursion_guard = &get_cpu_var(sc_in_hook); 
    *recursion_guard = 1; 
    
    // Global Switch
    if (!atomic_read(&monitor_enabled)) { 
        *recursion_guard = 0; 
        put_cpu_var(sc_in_hook); 
        goto execute_original; 
    }

retry_throttling:
    rcu_read_lock();
    
    // 2. Identity Check
    identity_match = 0;
    hash_for_each_possible_rcu(rules_ht, rule, node, current_uid().val){
        if(rule->type == MON_UID && rule->key == current_uid().val){ identity_match = 1; break; }
    }
    
    if (!identity_match) {
        name_hash = string_hash(current->comm);
        hash_for_each_possible_rcu(rules_ht,rule, node, name_hash){
            if(rule->type == MON_NAME && rule->key == name_hash){
                if(strncmp(rule->name, current->comm, 16) == 0){ identity_match = 1; break; }
            }
        }
    }
    
    if(!identity_match) { rcu_read_unlock(); goto safety_exit; }

    // 3. Throttle
    should_block = check_throttle();
    rcu_read_unlock(); 

    if(should_block){
        this_cpu_inc(cpu_stats.blocked_count);
        start = ktime_get();
        
        // RILASCIO GUARDIA PRIMA DI DORMIRE
        *recursion_guard = 0; 
        put_cpu_var(sc_in_hook);

        // --- TIMEOUT FIX ---
        // Svegliarsi automaticamente alla fine del secondo per resettare la finestra
        timeout_jiffies = (long)(READ_ONCE(window_start_jiffies) + HZ - jiffies);
        if (timeout_jiffies < 1) timeout_jiffies = 1;

        wait_event_interruptible_timeout(throttle_wq, 
             !atomic_read(&monitor_enabled), 
             timeout_jiffies
        );

        // RIACQUISIZIONE GUARDIA
        recursion_guard = &get_cpu_var(sc_in_hook); 
        *recursion_guard = 1;
        
        end = ktime_get();
        delta = ktime_to_ns(ktime_sub(end, start));
        spin_lock_irqsave(&peak_record.lock, flags);
        if (delta > peak_record.delay_ns) {
            peak_record.delay_ns = delta;
            peak_record.uid = current_uid().val;
            memcpy(peak_record.comm, current->comm, 16);
        }
        spin_unlock_irqrestore(&peak_record.lock, flags);
        goto retry_throttling;
    }

safety_exit:
    *recursion_guard = 0;
    put_cpu_var(sc_in_hook);

execute_original:
    // CALL ORIGINAL WITH BARRIER
    if (syscall_nr < MAX_SYSCALL_NR && hooks[syscall_nr]) {
        typedef long (*sys_call_ptr_t)(struct pt_regs *);
        ret = ((sys_call_ptr_t)hooks[syscall_nr]->original)(regs);
        
        // BARRIERA: Impedisce l'ottimizzazione Tail-Call (JMP invece di CALL)
        // Garantisce che le istruzioni dopo la return (se ce ne fossero) o lo stack frame
        // siano gestiti correttamente, vitale per la logica di Ftrace.
        __asm__ volatile ("");
        
        return ret;
    }
    return -ENOSYS;
}

// ---- IOCTL ----
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

    if (current_euid().val != 0) return -EPERM;
    mutex_lock(&conf_mutex);

    switch (cmd) {
        case IOCTL_ADD_RULE:
            if (copy_from_user(&conf, (struct sc_conf*)arg, sizeof(conf))) { ret = -EFAULT; break; }
            rule = kmalloc(sizeof(struct sc_rule), GFP_KERNEL);
            if (!rule) { ret = -ENOMEM; break; }
            rule->type = conf.type;
            if (conf.type == MON_NAME) {
                rule->key = string_hash(conf.name);
                memcpy(rule->name, conf.name, 16);
            } else {
                rule->key = conf.value;
                rule->name[0] = '\0';
            }
            hash_add_rcu(rules_ht, &rule->node, rule->key);
            
            if (conf.type == MON_SYSCALL && conf.value < MAX_SYSCALL_NR) {
                if (!hooks[conf.value]) {
                    if (sys_call_table) target_addr = sys_call_table[conf.value];
                    else { ret = -EINVAL; break; }
                    
                    if (!target_addr) { ret = -EINVAL; break; }

                    h = kmalloc(sizeof(struct ftrace_hook), GFP_KERNEL);
                    if (!h) { ret = -ENOMEM; break; }
                    
                    h->address = target_addr;
                    h->function = sys_hook_wrapper; 
                    h->original = (void*)target_addr; 
                    h->syscall_nr = conf.value;
                    h->registered = 0;

                    if (fh_install_hook(h) == 0) {
                        hooks[conf.value] = h;
                        printk(KERN_INFO "SC_THROTTLER: Hook installed on Syscall %lu\n", conf.value);
                    } else {
                        kfree(h);
                        ret = -EFAULT;
                    }
                }
            }
            break;

        case IOCTL_DEL_RULE:
            if (copy_from_user(&conf, (struct sc_conf*)arg, sizeof(conf))) { ret = -EFAULT; break; }
            key = (conf.type == MON_NAME) ? string_hash(conf.name) : conf.value;
            found = 0;
            hash_for_each_possible_safe(rules_ht, rule, tmp, node, key) {
                if (rule->type == conf.type && rule->key == key) {
                    if (rule->type == MON_SYSCALL && hooks[rule->key]) {
                        fh_remove_hook(hooks[rule->key]);
                        kfree(hooks[rule->key]);
                        hooks[rule->key] = NULL;
                    }
                    hash_del_rcu(&rule->node);
                    kfree_rcu(rule, rcu);
                    found = 1;
                    break; 
                }
            }
            if (!found) ret = -EINVAL;
            break;

        case IOCTL_SET_MAX: max_throughput = arg; break;
        case IOCTL_SET_ONOFF:
            if (arg == 0) { atomic_set(&monitor_enabled, 0); wake_up_all(&throttle_wq); } 
            else { atomic_set(&monitor_enabled, 1); }
            break;
        case IOCTL_GET_STATS:
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
            if (copy_to_user((struct sc_stats*)arg, &stats, sizeof(stats))) ret = -EFAULT;
            break;
        default: ret = -EINVAL;
    }
    mutex_unlock(&conf_mutex);
    return ret;
}

static int sc_open(struct inode *inode, struct file *file) { return 0; }
static int sc_release(struct inode *inode, struct file *file){ return 0;}
static struct file_operations fops = { .owner = THIS_MODULE, .unlocked_ioctl = sc_ioctl, .open = sc_open, .release = sc_release };

static int __init sc_throttler_init(void) {
    printk(KERN_INFO "SC_THROTTLER: Initializing (Golden Ftrace)...\n");
    spin_lock_init(&window_reset_lock);
    spin_lock_init(&peak_record.lock);
    window_start_jiffies = jiffies;
    module_load_time_jiffies = jiffies; 

    major_number = register_chrdev(0, DEVICE_NAME, &fops);
    sc_driver_class = class_create(THIS_MODULE, DEVICE_NAME);
    sc_driver_device = device_create(sc_driver_class, NULL, MKDEV(major_number, 0), NULL, DEVICE_NAME);

    // Usa kprobes per trovare la tabella (No manual scan)
    sys_call_table = (unsigned long *)safe_lookup_name("sys_call_table");
    
    if (!sys_call_table) {
        printk(KERN_ERR "SC_THROTTLER: FATAL - 'sys_call_table' not found.\n");
        return -EFAULT; 
    }
    
    printk(KERN_INFO "SC_THROTTLER: Table found at %px.\n", sys_call_table);
    return 0;
}

static void __exit sc_throttler_exit(void) {
    int i;
    struct sc_rule *rule;
    struct hlist_node *tmp;
    int bkt;
    
    for (i=0; i<MAX_SYSCALL_NR; i++) {
        if (hooks[i]) {
            fh_remove_hook(hooks[i]);
            kfree(hooks[i]);
        }
    }

    device_destroy(sc_driver_class, MKDEV(major_number, 0));
    class_destroy(sc_driver_class);
    unregister_chrdev(major_number, DEVICE_NAME);
    hash_for_each_safe(rules_ht, bkt, tmp, rule, node) {
        hash_del(&rule->node);
        kfree(rule);
    }
    printk(KERN_INFO "SC_THROTTLER: Unloaded.\n");
}
module_init(sc_throttler_init);
module_exit(sc_throttler_exit);