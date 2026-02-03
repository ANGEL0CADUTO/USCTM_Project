/* 
 * sc_throttler_module.c
 * PART 1: Setup, Device Registration, and Skeleton
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
#include <asm/page.h>           // Memory management (pgd_t, etc...) for VTPMO
#include <linux/jiffies.h>      // Page definitions
#include <linux/syscalls.h>     // Syscall definitions
#include <linux/percpu.h>      // Per-CPU variables


// Include custom header
#include "sc_throttler.h"

// ---- MODULE METADATA ----
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Angelo Romano");
MODULE_DESCRIPTION("System Call Throttler with Syscall Table Hacking and RCU");
MODULE_VERSION("1.0");  

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
// This flag precents the hook from intercepting itself (e.g. printk triggering write)
DEFINE_PER_CPU(int, sc_in_hook); // 0=Not in hook, 1=In Hook


//Array to save original syscalls pointers so we can restore them later
// We only hack specific syscalls on demand, but we need a place to store originals.
// For this reason we install a wrapper on the register calls dinamically
#define MAX_SYSCALL_NR 512
static unsigned long original_sys_call_table[MAX_SYSCALL_NR];
static int hacked_status[MAX_SYSCALL_NR] = {0}; // 0=Original, 1=Hacked

// ---- CR0 Manipulation Macros ----
//These are needed to write into read-only pages (like the syscall table)
unsigned long cr0;

static inline void write_cr0_forced(unsigned long val) {
    unsigned long __force_order;
    asm volatile("mov %0, %%cr0"
                 : "+r"(val), "+m"(__force_order));
}

static inline void protect_memory(void){
    write_cr0_forced(cr0);
}

static inline void unprotect_memory(void){
    cr0 = read_cr0(); // 1. Leggi il valore attuale del registro CPU
    write_cr0_forced(cr0 & ~0x00010000); // 2. Disabilita il bit 16 (Write Protect)
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
    int identity_match;
    unsigned long name_hash;
    int *recursion_guard;

    // A. Reentrancy Protection (Per-CPU Flag)
    // We disable preemption to safely access per-cpu var, 
    // although in syscall context we are mostly pinned.
    // get_cpu_var disables preemption, put_cpu_var enables it.
    recursion_guard = &get_cpu_var(sc_in_hook);
    if (*recursion_guard) {
        put_cpu_var(sc_in_hook);
        goto execute_original;
    }
    *recursion_guard = 1; // Set flag: We are inside the hook
    put_cpu_var(sc_in_hook);

    // Global Switch Check
    if (!atomic_read(&monitor_enabled)) goto exit_hook;

    //B. RCU Read Lock (Start Critical Section)
    rcu_read_lock();

    // C.Check Rules (Hash Table Lookup)
    // 1 Check Syscall Number
    hash_for_each_possible_rcu(rules_ht, rule, node, syscall_nr){
        if(rule->type == MON_SYSCALL && rule->key == syscall_nr){
            rule_found = 1;
            break;
        }
    }

    //If syscall not monitored skip other checks
    if(!rule_found) goto unlock_and_exit;

    // 2. Check Identity (UID or Name) - 
    //If we found the syscall is monitored then whe check WHO is calling it
    //If we have specific rules for User/Name we throttle ONLY if the match
    //NOTE: the spec says "invoked by a program... OR by a user"
    // SO if I register UID 1000 and syscall READ, I throttle READ for user 1000

    //In this SIMPLFIED implementation we throttle if (syscall match) AND ( (UID Match) OR (Name Match))

    // Check UID
    hash_for_each_possible_rcu(rules_ht,rule, node, current_uid().val){
        if(rule->type == MON_UID && rule->key == current_uid().val){
            identity_match = 1;
            break;
        }
    }

    //Check Name HASH
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

    // If NO identity matched we do NOT throttle
    if(!identity_match) goto unlock_and_exit;

    // D. Throttling Logic
    should_block = check_throttle();

    rcu_read_unlock(); // End Critical Section

    
    if(should_block){
        // Update Stats
        this_cpu_inc(cpu_stats.blocked_count);

        // Note: We must clear the recursion flag before sleeping, 
        // otherwise if we are rescheduled on this CPU, no one can use the hook!
        // However, wait_event schedules out. The flag is per-CPU, not per-task.
        // Correct logic: Clear flag -> Sleep -> Set flag on wake (if needed to protect rest).
        // Since after sleep we just calc stats and exit, we can clear it now.
        
        recursion_guard = &get_cpu_var(sc_in_hook);
        *recursion_guard = 0;
        put_cpu_var(sc_in_hook);

        start = ktime_get();
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
        
        goto execute_original; // Flag already cleared
    }

exit_hook:
    // Reset recursion flag
    recursion_guard = &get_cpu_var(sc_in_hook);
    *recursion_guard = 0;
    put_cpu_var(sc_in_hook);
    goto execute_original;

unlock_and_exit:
    rcu_read_unlock();
    goto exit_hook;


execute_original:
    if (syscall_nr >= 0 && syscall_nr < MAX_SYSCALL_NR && original_sys_call_table[syscall_nr]) {
        // Cast the original pointer to function signature and call it
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
                if (conf.value < MAX_SYSCALL_NR && !hacked_status[conf.value]) {
                    unprotect_memory();
                    original_sys_call_table[conf.value] = sys_call_table[conf.value];
                    sys_call_table[conf.value] = (unsigned long)sys_hook_wrapper;
                    protect_memory();
                    hacked_status[conf.value] = 1;
                    printk(KERN_INFO "SC_THROTTLER: Hooked syscall %lu\n", conf.value);
                }
            }
            break;

        case IOCTL_DEL_RULE:
            if (copy_from_user(&conf, (struct sc_conf*)arg, sizeof(conf))) {
                ret = -EFAULT; break;
            }
            // Find and Remove (Safe for RCU)
            key = (conf.type == MON_NAME) ? string_hash(conf.name) : conf.value;
            found = 0;
            
            hash_for_each_possible_safe(rules_ht, rule, tmp, node, key) {
                if (rule->type == conf.type && rule->key == key) {
                    hash_del_rcu(&rule->node);
                    kfree_rcu(rule, rcu);
                    found = 1;
                    // Note: We don't unhook the syscall from the table to avoid complexity/races.
                    // The hook will just see "rule not found" and execute original. 
                    // This is standard practice for simple LKM hooks.
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


        // TODO: IOCTL_LIST_RULES implementation would require a loop over hash table
        // copying data to user buffer. Omitted for brevity but defined in header.


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



// ---- VTPMO (Virtual To Physical Mapping Oracle) ----
// This function checks if a Virtual Address is mapped to a Physical Page.
// It walks the 4/5-level Page Table of the current process (kernel space).
// Returns: 1 (Valid), 0 (Invalid/Not Mapped).

int vtpmo(unsigned long vaddr){
    pgd_t *pgd;
    p4d_t *p4d;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *pte;

    // 1. Get Page Global Directory(Level 4-5)
    pgd = pgd_offset(current->mm, vaddr);
    if (pgd_none(*pgd) || pgd_bad(*pgd)) return 0;

    // 2. Get Page 4th Directory (Level 4)
    p4d = p4d_offset(pgd, vaddr);
    if (p4d_none(*p4d) || p4d_bad(*p4d)) return 0;   

    // 3. Get Page Upper Directory (Level 3)
    pud = pud_offset(p4d, vaddr);
    if (pud_none(*pud) || pud_bad(*pud)) return 0;

    // 4. Get Page Middle Directory (Level 2)
    pmd = pmd_offset(pud, vaddr);
    if (pmd_none(*pmd) || pmd_bad(*pmd)) return 0;
    
    // 5. Check for Huge Pages (2MB pages stop at PMD level)
    if (pmd_trans_huge(*pmd)) return 1; 

    // 6. Get Page Table Entry (Level 1)
    pte = pte_offset_kernel(pmd, vaddr);
    if (!pte_present(*pte)) return 0;


    return 1; // Valid Mapping
}

// ---- SYSCALL TABLE DISCOVERY ----
// Scans Kernel memory to find the sys_call_table array
// Heuristic: Looks for a sequence of pointers to sys_ni_syscalls

#define START_ADDR 0xffffffff80000000UL // Start of Kernel Memory (typically)
#define MAX_ADDR   0xffffffffff000000UL // End of Kernel Memory (typically)
#define STEP sizeof(void*)        // Jump by 8 bytes (64-bit pointers)

unsigned long* find_sys_call_table(void){
    unsigned long i = START_ADDR;
    unsigned long *chk; // Pointer to check memory
    int cnt = 0; // Counter for consecutive matches

    printk(KERN_INFO "SC_THROTTLER: Starting sys_call_table scan...\n");

    for(; i<MAX_ADDR; i += STEP){

        // 1. Safety Check with VTPMO
        if (!vtpmo(i)) continue;

        chk = (unsigned long*)i;

        // 2. Heuristic Pattern Matching
        // The sys_call_table contains many pointers to 'sys_ni_syscall' (Not Implemented).
        // Specifically, entries 134, 174, 182, 183 usually point to the same address (sys_ni_syscall).
        // This pattern is consistent across most x86-64 kernels.
        
        //We verify that a block of memory is readable first
        if (!vtpmo((unsigned long)&(chk[134])) || !vtpmo((unsigned long)&(chk[183]))) continue;

        if (chk[134] == chk[135] && chk[134] == chk[174] && chk[134] == chk[182] && chk[134] == chk[183]){
            printk(KERN_INFO "SC_THROTTLER: sys_call_table found at address: 0x%lx\n", i);
            return chk;
        }
        

        // Anti-freeze: Schedule every now and then to avoid locking up the CPU during scan
        cnt++;
        if (cnt % 1000000 == 0){ cond_resched(); } // Yield to avoid watchdog timer    
    }
    return NULL;
}





// ---- INITIALIZATION ----
static int __init sc_throttler_init(void) {
    printk(KERN_INFO "SC_THROTTLER: Initializing module...\n");

    // 1. Initialize Locks
    spin_lock_init(&window_reset_lock);
    spin_lock_init(&peak_record.lock);

    // 2. Initialize Window
    window_start_jiffies = jiffies;

    // 3. Register Char Device
    major_number = register_chrdev(0, DEVICE_NAME, &fops);
    if (major_number < 0) {
        printk(KERN_ALERT "SC_THROTTLER: Failed to register major number\n");
        return major_number;
    }

    // 4. Create Device Class (Corrected #if syntax)
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

    // 6. Syscall Table Discovery
    if (sys_call_table_addr) {
        sys_call_table = (unsigned long*)sys_call_table_addr;
        printk(KERN_INFO "SC_THROTTLER: Using manual sys_call_table address: %px\n", sys_call_table);
    } else {
        sys_call_table = find_sys_call_table();
    }

    if(!sys_call_table){
        printk(KERN_ERR "SC_THROTTLER: Failed to find sys_call_table! ABORTING\n");

        // Cleanup devide before aborting
        device_destroy(sc_driver_class, MKDEV(major_number, 0));
        class_destroy(sc_driver_class);
        unregister_chrdev(major_number, DEVICE_NAME);
        return -EFAULT;
    }


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
        unprotect_memory();
        for (i = 0; i < MAX_SYSCALL_NR; i++) {
            if (hacked_status[i]) {
                sys_call_table[i] = original_sys_call_table[i];
            }
        }
        protect_memory();
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