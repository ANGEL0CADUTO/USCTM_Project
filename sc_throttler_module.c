/* 
 * sc_throttler_module.c
 * PART 1: Setup, Device Registration, and Skeleton
 * (FIXED VERSION: Kprobes Discovery + Robust CR0 Handling + Safe Preemption)
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
#include <asm/page.h>           // Memory management 
#include <linux/jiffies.h>      // Page definitions
#include <linux/syscalls.h>     // Syscall definitions
#include <linux/percpu.h>       // Per-CPU variables
#include <linux/kprobes.h>      // NEW: Needed for safe symbol lookup

// Include custom header
#include "sc_throttler.h"

// ---- MODULE METADATA ----
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Angelo Romano");
MODULE_DESCRIPTION("System Call Throttler with Syscall Table Hacking and RCU");
MODULE_VERSION("1.1");  

// ---- MODULE PARAMETERS ----
static unsigned long sys_call_table_addr = 0x0;     // Manual address of sys_call_table (optional)
module_param(sys_call_table_addr, ulong, 0644);     // Allow read/write by root
MODULE_PARM_DESC(sys_call_table_addr, "Manual address of sys_call_table (optional)");   

// ---- GLOBAL VARIABLES ----

// 1. Device Driver Variables
#define DEVICE_NAME "sc_throttler"
static int major_number;                 // Major number for the device
static struct class* sc_driver_class = NULL;    //  Device class structure
static struct device* sc_driver_device = NULL; // Device structure

// 2. Monitoring State
static atomic_t monitor_enabled = ATOMIC_INIT(0); // 0=Disabled, 1=Enabled
static unsigned long max_throughput = 0; // Max allowed syscalls per time window

// 3. Rules Storage
static DEFINE_HASHTABLE(rules_ht, HT_BITS); //  Hash table for rules

// 4. Concurrency control
static DEFINE_MUTEX(conf_mutex);  // Mutex for configuration changes

// 5. Throttling Logic State
// Design Choice: We use a global counter and a time window of 1 second (HZ jiffies)
static atomic64_t global_counter = ATOMIC64_INIT(0); // Global counter for allowed syscalls
static unsigned long window_start_jiffies = 0;      // Start of current time window
static spinlock_t window_reset_lock;                // Lock for window reset
static DECLARE_WAIT_QUEUE_HEAD(throttle_wq);        // Wait queue for throttled processes

// 6. Statistics
static DEFINE_PER_CPU(struct sc_cpu_stats, cpu_stats); // Per-CPU stats
static struct sc_peak_record peak_record;       // Shared peak record
static unsigned long module_load_time_jiffies = 0; // For average calculation

// 7. Syscall Hacking Variables
unsigned long *sys_call_table = NULL; // Pointer to the found table 

// 8. Reentrancy Protection Per-CPU
// This flag prevents the hook from intercepting itself (e.g. printk triggering write)
DEFINE_PER_CPU(int, sc_in_hook); // 0=Not in hook, 1=In Hook


// Array to save original syscalls pointers so we can restore them later
// We only hack specific syscalls on demand, but we need a place to store originals.
#define MAX_SYSCALL_NR 512
static unsigned long original_sys_call_table[MAX_SYSCALL_NR];
static int hacked_status[MAX_SYSCALL_NR] = {0}; // 0=Original, 1=Hacked
static int syscall_refcount[MAX_SYSCALL_NR] = {0}; // Refcount for each hooked syscall


// ---- CR0 Manipulation Macros (FIXED) ----
// These are needed to write into read-only pages (like the syscall table).
// We utilize inline assembly to strictly control CR0 register, bypassing
// potential kernel restrictions on set_memory_rw symbols.

static inline void write_cr0_forced(unsigned long val) {
    unsigned long __force_order;
    asm volatile("mov %0, %%cr0"
                 : "+r"(val), "+m"(__force_order));
}

// Enables writing to Read-Only pages by clearing the WP (Write Protect) bit in CR0.
// CRITICAL: We disable preemption to prevent being scheduled out while WP is off.
static inline void enable_page_rw(void) {
    unsigned long val;
    preempt_disable(); // 1. Pin CPU
    barrier();
    val = read_cr0();
    write_cr0_forced(val & ~0x00010000); // 2. Clear WP bit (16)
}

// Restores protection
static inline void disable_page_rw(void) {
    unsigned long val;
    val = read_cr0();
    write_cr0_forced(val | 0x00010000); // 1. Set WP bit
    barrier();
    preempt_enable(); // 2. Enable Preemption
}


// ---- Helper Functions ----

unsigned long string_hash(const char *str){
    unsigned long hash = 0;
    int c;

    while((c=*str++)){
        hash = c + (hash << 6) + (hash << 16) - hash;
    }
    return hash;
}

// ---- SYSCALL TABLE DISCOVERY HELPER (KPROBES) ----
// Used to find 'kallsyms_lookup_name' which is not exported in kernels > 5.7.
typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
static kallsyms_lookup_name_t kallsyms_lookup_name_ref;

static unsigned long lookup_name(const char *name) {
    struct kprobe kp = { .symbol_name = "kallsyms_lookup_name" };
    unsigned long addr;

    if (register_kprobe(&kp) < 0) return 0;
    addr = (unsigned long)kp.addr;
    unregister_kprobe(&kp);
    
    kallsyms_lookup_name_ref = (kallsyms_lookup_name_t)addr;
    return kallsyms_lookup_name_ref(name);
}


// ---- CORE Logic: Throttling Check ----
// Returns 1 if should throttle (block), 0 if allowed
int check_throttle(void){
    unsigned long now = jiffies;
    unsigned long flags;
    u64 val;

    // 1. Lazy Reset of Window
    if(time_after(now, window_start_jiffies + HZ)){
        spin_lock_irqsave(&window_reset_lock, flags);
        // Double-check after acquiring lock
        if(time_after(now, window_start_jiffies + HZ)){
            window_start_jiffies = now;
            atomic64_set(&global_counter, 0);
            // Wake up all waiting processes
            wake_up_all(&throttle_wq);
        }
        spin_unlock_irqrestore(&window_reset_lock, flags);
    }

    // 2. Increment Global Counter & Check
    val = atomic64_inc_return(&global_counter);

    if(val > max_throughput){
        return 1; // Throttle because limit exceeded
    }
    return 0; // Allowed
}


// ---- The HOOK (Syscall Wrapper) ----
// This function wraps around the original syscall
// It performs the throttling check before calling the original syscall
asmlinkage long sys_hook_wrapper(struct pt_regs *regs){
    int syscall_nr = regs->ax; // Syscall number is in RAX
    struct sc_rule *rule;
    int rule_found = 0;
    int should_block = 0;
    unsigned long flags;
    ktime_t start, end;
    s64 delta;
    int identity_match = 0;
    unsigned long name_hash;
    int *recursion_guard;

    // A. Reentrancy Protection (Per-CPU Flag)
    // We disable preemption to safely access per-cpu var via get_cpu_var.
    // If we are already in the hook, we simply skip and execute original.
    recursion_guard = &get_cpu_var(sc_in_hook); // DISALBE PREEMPTION
    if (*recursion_guard) {
        put_cpu_var(sc_in_hook); // ENABLE PREEMPTION
        goto execute_original;
    }
    *recursion_guard = 1; 
    // We KEEP preemption disabled strictly for the logic phase to avoid migration.
    // However, if we need to sleep, we MUST handle preemption carefully.

    // Global Switch Check
    if (!atomic_read(&monitor_enabled)) {
        *recursion_guard = 0;
        put_cpu_var(sc_in_hook); // Re-enable before exit
        goto execute_original;
    }

    // B. RCU Read Lock (Start Critical Section)
    rcu_read_lock();

    // C. Check Rules (Hash Table Lookup)
    // 1. Check Syscall Number
    hash_for_each_possible_rcu(rules_ht, rule, node, syscall_nr){
        if(rule->type == MON_SYSCALL && rule->key == syscall_nr){
            rule_found = 1;
            break;
        }
    }

    // If syscall not monitored skip other checks
    if(!rule_found) goto unlock_and_exit;

    // 2. Check Identity (UID or Name)
    // In this implementation we throttle if (syscall match) AND ( (UID Match) OR (Name Match))

    // Check UID
    hash_for_each_possible_rcu(rules_ht,rule, node, current_uid().val){
        if(rule->type == MON_UID && rule->key == current_uid().val){
            identity_match = 1;
            break;
        }
    }

    // Check Name HASH (if UID didn't match yet)
    if (!identity_match) {
        name_hash = string_hash(current->comm);
        hash_for_each_possible_rcu(rules_ht,rule, node, name_hash){
            if(rule->type == MON_NAME && rule->key == name_hash){
                // Verify exact string to avoid hash collision
                if(strncmp(rule->name, current->comm, 16) == 0){
                    identity_match = 1;
                    break;
                }   
            }
        }
    }

    // If NO identity matched we do NOT throttle
    if(!identity_match) goto unlock_and_exit;

    // D. Throttling Logic
    should_block = check_throttle();

    rcu_read_unlock(); // End Critical Section

    // SAFETY CHECK: We must clear recursion flag before potentially sleeping.
    // If we sleep with the flag set on this CPU, no one else can use the hook on this core.
    *recursion_guard = 0;
    put_cpu_var(sc_in_hook); // RE-ENABLE PREEMPTION HERE

    if(should_block){
        // Update Stats
        this_cpu_inc(cpu_stats.blocked_count);

        start = ktime_get();
        // Wait Event schedules the process out (sleep)
        wait_event_interruptible(throttle_wq, 
            time_after(jiffies, window_start_jiffies + HZ) || !atomic_read(&monitor_enabled)
        );
        end = ktime_get();

        // Update Peak Delay
        delta = ktime_to_ns(ktime_sub(end, start));
        spin_lock_irqsave(&peak_record.lock, flags);
        if (delta > peak_record.delay_ns) {
            peak_record.delay_ns = delta;
            peak_record.uid = current_uid().val;
            memcpy(peak_record.comm, current->comm, 16);
        }
        spin_unlock_irqrestore(&peak_record.lock, flags);
        
        goto execute_original; // Preemption already enabled, flag already cleared
    }

    // If we didn't block, we still need to jump to execute original
    goto execute_original;

unlock_and_exit:
    rcu_read_unlock();
    // Cleanup recursion guard if we exit early
    *recursion_guard = 0;
    put_cpu_var(sc_in_hook);
    goto execute_original;


execute_original:
    // Execute the original syscall if valid
    if (syscall_nr >= 0 && syscall_nr < MAX_SYSCALL_NR && original_sys_call_table[syscall_nr]) {
        typedef long (*sys_call_ptr_t)(struct pt_regs *);
        return ((sys_call_ptr_t)original_sys_call_table[syscall_nr])(regs);
    }
    return -ENOSYS;
}


// ---- FORWARD DECLARATIONS ----
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

    // 1. Security Check (Only Root)
    if (current_euid().val != 0) return -EPERM;

    mutex_lock(&conf_mutex);

    switch (cmd) {

        case IOCTL_ADD_RULE:
            if (copy_from_user(&conf, (struct sc_conf*)arg, sizeof(conf))) {
                ret = -EFAULT; break;
            }
            
            // Allocate new rule
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

            // Insert into Hash Table
            hash_add_rcu(rules_ht, &rule->node, rule->key);
            
            // If it's a Syscall Rule, we must Hook it in the table
            if (conf.type == MON_SYSCALL) {
                if (conf.value < MAX_SYSCALL_NR) {
                    if (syscall_refcount[conf.value] == 0) {
                        // First rule -> Install Hook SAFELY
                        enable_page_rw(); // Uses robust CR0 assembly
                        original_sys_call_table[conf.value] = sys_call_table[conf.value];
                        sys_call_table[conf.value] = (unsigned long)sys_hook_wrapper;
                        disable_page_rw(); 
                        
                        hacked_status[conf.value] = 1;
                        printk(KERN_INFO "SC_THROTTLER: Hooked syscall %lu\n", conf.value);
                    }
                    syscall_refcount[conf.value]++; // Increment refcount!
                }
            }
            break; 

            
        case IOCTL_DEL_RULE:
            if (copy_from_user(&conf, (struct sc_conf*)arg, sizeof(conf))) {
                ret = -EFAULT; break;
            }
            
            key = (conf.type == MON_NAME) ? string_hash(conf.name) : conf.value;
            found = 0;
            
            hash_for_each_possible_safe(rules_ht, rule, tmp, node, key) {
                if (rule->type == conf.type && rule->key == key) {
                    
                    // Logic: Syscall RefCount Check
                    if (rule->type == MON_SYSCALL) {
                        unsigned long sc = rule->key;
                        if (sc < MAX_SYSCALL_NR && syscall_refcount[sc] > 0) {
                            syscall_refcount[sc]--;
                            if (syscall_refcount[sc] == 0) {
                                // Refcount is 0 -> Restore Original SAFELY
                                enable_page_rw();
                                sys_call_table[sc] = original_sys_call_table[sc];
                                disable_page_rw();
                                
                                hacked_status[sc] = 0;
                                printk(KERN_INFO "SC_THROTTLER: Restored syscall %lu\n", sc);
                            }
                        }
                    }

                    // Remove from Hash Table 
                    hash_del_rcu(&rule->node);
                    kfree_rcu(rule, rcu);
                    found = 1;
                    break; 
                }
            }
            if (!found) ret = -EINVAL;
            break;

        case IOCTL_SET_MAX:
            max_throughput = arg;
            break;

        case IOCTL_SET_ONOFF:
            if (arg == 0) {
                atomic_set(&monitor_enabled, 0);
                wake_up_all(&throttle_wq); // Wake up everyone if disabled
            } else {
                atomic_set(&monitor_enabled, 1);
            }
            break;

        case IOCTL_GET_STATS:
            // Aggregate Per-CPU stats
            for_each_online_cpu(cpu) {
                cpu_blocked += per_cpu(cpu_stats.blocked_count, cpu);
            }
            stats.blocked_total = cpu_blocked;
            
            // Calculate Average
            elapsed = (jiffies - module_load_time_jiffies) / HZ;
            if (elapsed > 0) stats.avg_blocked = cpu_blocked / elapsed;
            else stats.avg_blocked = 0;

            // Get Peak Record
            spin_lock_irq(&peak_record.lock);
            stats.peak_delay_ns = peak_record.delay_ns;
            stats.peak_uid = peak_record.uid;
            memcpy(stats.peak_comm, peak_record.comm, 16);
            spin_unlock_irq(&peak_record.lock);

            if (copy_to_user((struct sc_stats*)arg, &stats, sizeof(stats))) {
                ret = -EFAULT;
            }
            break;

        default:
            ret = -EINVAL;
    }

    mutex_unlock(&conf_mutex);
    return ret;
}


// ---- Device Operations ----
static int sc_open(struct inode *inode, struct file *file) { return 0; }
static int sc_release(struct inode *inode, struct file *file){ return 0;}


static struct file_operations fops = {
    .owner = THIS_MODULE,
    .unlocked_ioctl = sc_ioctl, 
    .open = sc_open,
    .release = sc_release,
};


// ---- INITIALIZATION ----
static int __init sc_throttler_init(void) {
    printk(KERN_INFO "SC_THROTTLER: Initializing module...\n");

    // 1. Initialize Locks
    spin_lock_init(&window_reset_lock);
    spin_lock_init(&peak_record.lock);

    // 2. Initialize Window
    window_start_jiffies = jiffies;
    module_load_time_jiffies = jiffies; // Track load time

    // 3. Register Char Device
    major_number = register_chrdev(0, DEVICE_NAME, &fops);
    if (major_number < 0) {
        printk(KERN_ALERT "SC_THROTTLER: Failed to register major number\n");
        return major_number;
    }

    // 4. Create Device Class
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,4,0)
    sc_driver_class = class_create(DEVICE_NAME);
#else
    sc_driver_class = class_create(THIS_MODULE, DEVICE_NAME);
#endif

    if (IS_ERR(sc_driver_class)) {
        unregister_chrdev(major_number, DEVICE_NAME);
        return PTR_ERR(sc_driver_class);
    }

    // 5. Create Device File
    sc_driver_device = device_create(sc_driver_class, NULL, MKDEV(major_number, 0), NULL, DEVICE_NAME);
    if (IS_ERR(sc_driver_device)) {
        class_destroy(sc_driver_class);
        unregister_chrdev(major_number, DEVICE_NAME);
        return PTR_ERR(sc_driver_device);
    }

    printk(KERN_INFO "SC_THROTTLER: Device Registered: /dev/%s (Major: %d)\n", DEVICE_NAME, major_number);

    // 6. Syscall Table Discovery (UPDATED: Using Kprobes for robust lookup)
    if (sys_call_table_addr) {
        sys_call_table = (unsigned long*)sys_call_table_addr;
        printk(KERN_INFO "SC_THROTTLER: Using manual sys_call_table address: %px\n", sys_call_table);
    } else {
        // Use the Kprobe trick to find kallsyms_lookup_name, then find the table
        sys_call_table = (unsigned long*)lookup_name("sys_call_table");
    }

    if(!sys_call_table){
        printk(KERN_ERR "SC_THROTTLER: Failed to find sys_call_table! ABORTING\n");

        // Cleanup devide before aborting
        device_destroy(sc_driver_class, MKDEV(major_number, 0));
        class_destroy(sc_driver_class);
        unregister_chrdev(major_number, DEVICE_NAME);
        return -EFAULT;
    }

    printk(KERN_INFO "SC_THROTTLER: sys_call_table found at: %px\n", sys_call_table);
    return 0; 
}

// ---- CLEANUP ----
static void __exit sc_throttler_exit(void)
{
    int i;
    struct sc_rule *rule;
    struct hlist_node *tmp;
    int bkt;

    // 1. Restore Syscall Table (Undo Hacking)
    if (sys_call_table) {
        enable_page_rw(); // Use safe CR0 function
        for (i = 0; i < MAX_SYSCALL_NR; i++) {
            if (hacked_status[i]) {
                sys_call_table[i] = original_sys_call_table[i];
            }
        }
        disable_page_rw(); // Use safe CR0 function
        printk(KERN_INFO "SC_THROTTLER: Syscall table restored.\n");
    }
    // 2. Cleanup Device
    device_destroy(sc_driver_class, MKDEV(major_number, 0));
    class_destroy(sc_driver_class);
    unregister_chrdev(major_number, DEVICE_NAME);

    // 3. Free Memory (Hash Table)
    // We iterate over all buckets and free remaining nodes.
    // Since we are unloading, we don't need RCU protection here (no readers left).
    hash_for_each_safe(rules_ht, bkt, tmp, rule, node) {
        hash_del(&rule->node);
        kfree(rule);
    }

    printk(KERN_INFO "SC_THROTTLER: Unloaded and Memory Freed.\n");
}


module_init(sc_throttler_init);
module_exit(sc_throttler_exit);