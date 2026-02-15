/* * sc_throttler_module.c
 * PART 1: Setup, Device Registration, and Skeleton
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
#include <asm/tlbflush.h>       
#include <asm/pgtable.h>       

// Include custom header
#include "sc_throttler.h"

// ---- MODULE METADATA ----
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Angelo Romano");
MODULE_DESCRIPTION("System Call Throttler - Bare Metal Edition");
MODULE_VERSION("5.0");  

// ---- MODULE PARAMETERS ----
static unsigned long sys_call_table_addr = 0x0;     
module_param(sys_call_table_addr, ulong, 0644);     
MODULE_PARM_DESC(sys_call_table_addr, "Manual address of sys_call_table (optional)");   

// ---- GLOBAL VARIABLES ----

// 1. Device Driver Variables
#define DEVICE_NAME "sc_throttler"
static int major_number;                 
static struct class* sc_driver_class = NULL;    
static struct device* sc_driver_device = NULL; 

// 2. Monitoring State
static atomic_t monitor_enabled = ATOMIC_INIT(0); 
static unsigned long max_throughput = 0; 

// 3. Rules Storage
static DEFINE_HASHTABLE(rules_ht, HT_BITS); 

// 4. Concurrency control
static DEFINE_MUTEX(conf_mutex);  

// 5. Throttling Logic State
static atomic64_t global_counter = ATOMIC64_INIT(0); 
static unsigned long window_start_jiffies = 0;      
static spinlock_t window_reset_lock;                
static DECLARE_WAIT_QUEUE_HEAD(throttle_wq);        

// 6. Statistics
static DEFINE_PER_CPU(struct sc_cpu_stats, cpu_stats); 
static struct sc_peak_record peak_record;       
static unsigned long module_load_time_jiffies = 0; 

// Used to calculate "threads blocked in the CURRENT window" for peak detection
static unsigned long long last_window_blocked_sum = 0; 

// 7. Syscall Hacking Variables
unsigned long *sys_call_table = NULL; 
DEFINE_PER_CPU(int, sc_in_hook); // Reentrancy Guard

#define MAX_SYSCALL_NR 512
static unsigned long original_sys_call_table[MAX_SYSCALL_NR];
static int hacked_status[MAX_SYSCALL_NR] = {0}; 
static int syscall_refcount[MAX_SYSCALL_NR] = {0}; 


// ---- UTILS: Lookup & PTE Manipulation ----

// We need to find lookup_address symbol dynamically
typedef pte_t *(*lookup_address_t)(unsigned long address, unsigned int *level);
static lookup_address_t lookup_address_func = NULL;

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

// CRITICAL: Helper to set page Read-Write
static int set_pte_rw(unsigned long addr) {
    pte_t *pte;
    unsigned int level;

    if (!lookup_address_func) return -1;
    
    pte = lookup_address_func(addr, &level);
    if (pte && pte_present(*pte)) {
        pte->pte |= _PAGE_RW; 
        return 0;
    }
    return -1;
}

// CRITICAL: Helper to set page Read-Only (Safety)
static void set_pte_ro(unsigned long addr) {
    pte_t *pte;
    unsigned int level;
    if (!lookup_address_func) return;
    pte = lookup_address_func(addr, &level);
    if (pte && pte_present(*pte)) {
        pte->pte &= ~_PAGE_RW; 
    }
}


// ---- CR0 MANIPULATION (NUCLEAR OPTION) ----
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
    cr0 = read_cr0();
    write_cr0_forced(cr0 & ~0x00010000); // Unset WP bit (16)
}


unsigned long string_hash(const char *str){
    unsigned long hash = 0;
    int c;
    while((c=*str++)) hash = c + (hash << 6) + (hash << 16) - hash;
    return hash;
}

// ---- BULLETPROOF SCANNER (_text to _end with PTE check) ----
// ---- AUDIT SCANNER (Find ALL tables) ----
static unsigned long *find_real_sys_call_table(void) {
    unsigned long i;
    unsigned long close_addr;
    unsigned long *chk;
    unsigned long start_addr, end_addr;
    pte_t *pte;
    unsigned int level;
    unsigned long *found_table = NULL;
    int found_count = 0;

    // 1. Target: sys_close
    close_addr = lookup_name("__x64_sys_close");
    if (!close_addr) return NULL;

    // 2. Confini Kernel
    start_addr = lookup_name("_text");
    end_addr = lookup_name("_end");
    
    // Allineamento pagina
    start_addr &= PAGE_MASK;

    printk(KERN_INFO "SC_AUDIT: Scanning %lx - %lx for close: %lx\n", 
           start_addr, end_addr, close_addr);

    // 3. Scansione Totale
    for (i = start_addr; i < end_addr; i += PAGE_SIZE) {
        
        // Verifica PTE
        pte = lookup_address_func(i, &level);
        if (!pte || !pte_present(*pte)) continue;

        for (chk = (unsigned long *)i; (unsigned long)chk < (i + PAGE_SIZE); chk++) {
            if ((unsigned long)chk + (3 * sizeof(void*)) >= (i + PAGE_SIZE)) break;

            // Check Euristico
            if (chk[3] == close_addr) {
                 // Check Robusto (read/write non nulli)
                 if (chk[0] >= start_addr && chk[0] < end_addr &&
                     chk[1] >= start_addr && chk[1] < end_addr) {
                     
                     printk(KERN_INFO "SC_AUDIT: CANDIDATE #%d found at %px\n", ++found_count, chk);
                     
                     // Salviamo l'ultimo trovato, ma CONTINUIAMO a cercare
                     found_table = chk;
                 }
            }
        }
        cond_resched();
    }
    
    if (found_count > 1) {
        printk(KERN_INFO "SC_AUDIT: WARNING! Multiple tables found. Using the LAST one.\n");
    }

    return found_table; // Ritorna l'ultimo trovato (spesso quello "vivo")
}

// ---- CORE Logic: Throttling Check ----
// Returns 1 if should throttle (block), 0 if allowed
int check_throttle(void){
    unsigned long now = jiffies;
    unsigned long flags;
    u64 val;
    int cpu;
    unsigned long long current_total_blocked = 0;
    unsigned long long window_blocked_delta = 0;

    // 1. Lazy Reset of Window
    // Optimization: READ_ONCE avoids compiler caching the value outside lock
    if(time_after(now, READ_ONCE(window_start_jiffies) + HZ)){
        spin_lock_irqsave(&window_reset_lock, flags);
        
        // Double-check after acquiring lock
        if(time_after(now, window_start_jiffies + HZ)){
            
            // --- STATISTICS UPDATE (PEAK BLOCKED) ---
            // Sum all blocked counts from CPUs to see how many were blocked in this finished window
            for_each_online_cpu(cpu) {
                current_total_blocked += per_cpu(cpu_stats.blocked_count, cpu);
            }
            
            // Calculate delta (blocked in THIS window)
            window_blocked_delta = current_total_blocked - last_window_blocked_sum;
            last_window_blocked_sum = current_total_blocked;

            spin_lock(&peak_record.lock); // Nested lock (safe, different lock)
            if (window_blocked_delta > peak_record.peak_blocked_window) {
                peak_record.peak_blocked_window = window_blocked_delta;
            }
            spin_unlock(&peak_record.lock);
            // ----------------------------------------

            window_start_jiffies = now;
            atomic64_set(&global_counter, 0);
            
            // Wake up all waiting processes (Broadcast)
            wake_up_all(&throttle_wq);
        }
        spin_unlock_irqrestore(&window_reset_lock, flags);
    }

    // 2. Increment Global Counter & Check
    val = atomic64_inc_return(&global_counter);

    if(val > max_throughput){
        return 1; // Throttle
    }
    return 0; // Allow
}


// ---- The HOOK (Syscall Wrapper) ----
asmlinkage long sys_hook_wrapper(struct pt_regs *regs){
    int syscall_nr = regs->ax;
    struct sc_rule *rule;
    int rule_found = 0;
    int should_block = 0;
    unsigned long flags;
    ktime_t start, end;
    s64 delta;
    int identity_match = 0;
    unsigned long name_hash;
    int *recursion_guard;

    if (syscall_nr == 83) {
        printk(KERN_INFO "SC_DEBUG: Hook attivato! Monitor=%d, Syscall=%d\n", 
               atomic_read(&monitor_enabled), syscall_nr);
    }

    // A. Reentrancy Protection
    recursion_guard = &get_cpu_var(sc_in_hook); 
    if (*recursion_guard) {
        put_cpu_var(sc_in_hook); 
        goto execute_original;
    }
    *recursion_guard = 1; 
    
    // Global Switch Check
    if (!atomic_read(&monitor_enabled)) {
        *recursion_guard = 0;
        put_cpu_var(sc_in_hook); 
        goto execute_original;
    }

retry_throttling: 
    // B. RCU Read Lock
    rcu_read_lock();

    // C. Check Rules
    // 1. Check Syscall
    rule_found = 0;
    hash_for_each_possible_rcu(rules_ht, rule, node, syscall_nr){
        if(rule->type == MON_SYSCALL && rule->key == syscall_nr){
            rule_found = 1;
            break;
        }
    }
    if(!rule_found) { rcu_read_unlock(); goto safety_exit; }

    // 2. Check Identity
    identity_match = 0;
    // Check UID
    hash_for_each_possible_rcu(rules_ht,rule, node, current_uid().val){
        if(rule->type == MON_UID && rule->key == current_uid().val){
            identity_match = 1;
            break;
        }
    }
    // Check Name (if UID didn't match)
    if (!identity_match) {
        name_hash = string_hash(current->comm);
        hash_for_each_possible_rcu(rules_ht,rule, node, name_hash){
            if(rule->type == MON_NAME && rule->key == name_hash){
                if(strncmp(rule->name, current->comm, 16) == 0){
                    identity_match = 1;
                    break;
                }   
            }
        }
    }
    if(!identity_match) { rcu_read_unlock(); goto safety_exit; }

    // D. Throttling Logic
    should_block = check_throttle();
    rcu_read_unlock(); 

    if(should_block){
        this_cpu_inc(cpu_stats.blocked_count);
        start = ktime_get();
        
        // Clear guard before sleeping
        *recursion_guard = 0;
        put_cpu_var(sc_in_hook);

        // SMP SAFETY: No timeout. Sleep until condition is met.
        // We rely on wake_up_all in check_throttle() or IOCTL_SET_ONOFF
        wait_event_interruptible(throttle_wq, 
             time_after(jiffies, READ_ONCE(window_start_jiffies) + HZ) || 
             !atomic_read(&monitor_enabled)
        );

        // Re-acquire guard after wake-up
        recursion_guard = &get_cpu_var(sc_in_hook);
        *recursion_guard = 1;

        end = ktime_get();
        delta = ktime_to_ns(ktime_sub(end, start));
        
        // Update Peak Delay
        spin_lock_irqsave(&peak_record.lock, flags);
        if (delta > peak_record.delay_ns) {
            peak_record.delay_ns = delta;
            peak_record.uid = current_uid().val;
            memcpy(peak_record.comm, current->comm, 16);
        }
        spin_unlock_irqrestore(&peak_record.lock, flags);
        
        // Retry logic: We woke up because window reset. 
        // We must re-check if there is quota in the NEW window.
        // (If many threads wake up at once, they might race for the new quota)
        goto retry_throttling; 
    }

    goto safety_exit;

safety_exit:
    *recursion_guard = 0;
    put_cpu_var(sc_in_hook);

execute_original:
    if (syscall_nr >= 0 && syscall_nr < MAX_SYSCALL_NR && original_sys_call_table[syscall_nr]) {
        typedef long (*sys_call_ptr_t)(struct pt_regs *);
        return ((sys_call_ptr_t)original_sys_call_table[syscall_nr])(regs);
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
    unsigned long original_fn;

    // 1. Security Check (Only Root can CONFIGURE)
    if (current_euid().val != 0) return -EPERM;

    mutex_lock(&conf_mutex);

    switch (cmd) {
        case IOCTL_ADD_RULE:
            if (copy_from_user(&conf, (struct sc_conf*)arg, sizeof(conf))) {
                ret = -EFAULT; break;
            }
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
            
            // Hook Syscall if needed
            if (conf.type == MON_SYSCALL) {
                if (conf.value < MAX_SYSCALL_NR) {
                    if (syscall_refcount[conf.value] == 0) {
                        unsigned long *entry_ptr = &sys_call_table[conf.value];
                        
                        // 1. SALVA ORIGINALE
                        original_fn = *entry_ptr;
                        original_sys_call_table[conf.value] = original_fn;
                        
                        // --- DEBUG FORENSE: STAMPA PRE-SCRITTURA ---
                        printk(KERN_INFO "SC_FORENSIC: Target Address: %px\n", entry_ptr);
                        printk(KERN_INFO "SC_FORENSIC: Wrapper Address: %lx\n", (unsigned long)sys_hook_wrapper);
                        printk(KERN_INFO "SC_FORENSIC: Value BEFORE: %lx\n", *entry_ptr);
                        
                        // 2. NUCLEAR WRITE (Unprotect -> Write -> Protect)
                        unprotect_memory();
                        *entry_ptr = (unsigned long)sys_hook_wrapper;
                        protect_memory();
                        
                        // --- DEBUG FORENSE: STAMPA POST-SCRITTURA ---
                        printk(KERN_INFO "SC_FORENSIC: Value AFTER:  %lx\n", *entry_ptr);
                        
                        // 3. VERIFICA MATEMATICA
                        if (*entry_ptr == (unsigned long)sys_hook_wrapper) {
                             printk(KERN_INFO "SC_FORENSIC: SUCCESS - Memory matched wrapper address.\n");
                        } else {
                             printk(KERN_ERR "SC_FORENSIC: FAILURE - Memory check FAILED! Write ignored.\n");
                        }

                        hacked_status[conf.value] = 1;
                    }
                    syscall_refcount[conf.value]++;
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
                    if (rule->type == MON_SYSCALL) {
                        unsigned long sc = rule->key;
                        if (sc < MAX_SYSCALL_NR && syscall_refcount[sc] > 0) {
                            syscall_refcount[sc]--;
                            if (syscall_refcount[sc] == 0) {
                                // Restore original
                                unprotect_memory();
                                sys_call_table[sc] = original_sys_call_table[sc];
                                protect_memory();
                                
                                hacked_status[sc] = 0;
                                printk(KERN_INFO "SC_THROTTLER: Restored syscall %lu\n", sc);
                            }
                        }
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
            stats.peak_blocked = peak_record.peak_blocked_window; // NEW STAT
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


// ---- INITIALIZATION ----
static int __init sc_throttler_init(void) {
    pte_t *pte;
    unsigned int level;

    printk(KERN_INFO "SC_THROTTLER: Initializing (Bare Metal Mode)...\n");
    
    // 1. Initialize Locks
    spin_lock_init(&window_reset_lock);
    spin_lock_init(&peak_record.lock);
    window_start_jiffies = jiffies;
    module_load_time_jiffies = jiffies; 

    // 2. Register Device
    major_number = register_chrdev(0, DEVICE_NAME, &fops);
    sc_driver_class = class_create(THIS_MODULE, DEVICE_NAME);
    sc_driver_device = device_create(sc_driver_class, NULL, MKDEV(major_number, 0), NULL, DEVICE_NAME);

    // 3. Find Table and Lookup Function
    lookup_address_func = (void *)lookup_name("lookup_address");
    if (!lookup_address_func) {
        printk(KERN_ERR "SC_THROTTLER: lookup_address not found. Cannot proceed safely.\n");
        return -EFAULT;
    }

    if (sys_call_table_addr) sys_call_table = (unsigned long*)sys_call_table_addr;
    else sys_call_table = find_real_sys_call_table();

    //DEBUG
    printk(KERN_INFO "SC_DEBUG: sys_call_table found at: %px\n", sys_call_table);
    
    if(!sys_call_table) {
        printk(KERN_ERR "SC_THROTTLER: Syscall table not found.\n");
        return -EFAULT;
    }

    // 4. CRITICAL PTE SURGICAL TEST (As requested)
    // We verify NOW if we can touch the table, to avoid panics later.
    pte = lookup_address_func((unsigned long)sys_call_table, &level);
    if (!pte) {
        printk(KERN_ERR "SC_THROTTLER: FATAL - Cannot retrieve PTE for sys_call_table.\n");
        return -EFAULT;
    }

    printk(KERN_INFO "SC_THROTTLER: PTE Address: %px, Val: %lx\n", pte, pte->pte);
    if (!(pte->pte & _PAGE_RW)) {
        printk(KERN_INFO "SC_THROTTLER: Table is RO. Test enabling RW...\n");
        pte->pte |= _PAGE_RW;
        __flush_tlb_all();
        if (pte->pte & _PAGE_RW) {
            printk(KERN_INFO "SC_THROTTLER: RW enabled successfully. Reverting to RO for now.\n");
            pte->pte &= ~_PAGE_RW;
            __flush_tlb_all();
        } else {
            printk(KERN_ERR "SC_THROTTLER: FATAL - Failed to modify PTE permissions.\n");
            return -EPERM;
        }
    }

    printk(KERN_INFO "SC_THROTTLER: Loaded successfully.\n");
    return 0;
}

static void __exit sc_throttler_exit(void) {
    int i;
    struct sc_rule *rule;
    struct hlist_node *tmp;
    int bkt;
    
    // 1. Restore Everything
    if (sys_call_table) {
        unprotect_memory(); // Sblocca una volta per tutte le scritture
        for (i = 0; i < MAX_SYSCALL_NR; i++) {
            if (hacked_status[i]) {
                sys_call_table[i] = original_sys_call_table[i];
            }
        }
        protect_memory(); // Riblocca
        printk(KERN_INFO "SC_THROTTLER: Syscall table restored.\n");
    }
    
    // 2. Destroy Device
    device_destroy(sc_driver_class, MKDEV(major_number, 0));
    class_destroy(sc_driver_class);
    unregister_chrdev(major_number, DEVICE_NAME);
    
    // 3. Free Memory
    hash_for_each_safe(rules_ht, bkt, tmp, rule, node) {
        hash_del(&rule->node);
        kfree(rule);
    }
    printk(KERN_INFO "SC_THROTTLER: Unloaded.\n");
}
module_init(sc_throttler_init);
module_exit(sc_throttler_exit);