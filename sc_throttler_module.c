/* * sc_throttler_module.c
 * FINAL RELEASE: Simulation Ready + Strict Blocking Logic
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

#include "sc_throttler.h"

// ---- MODULE METADATA ----
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Angelo Romano");
MODULE_DESCRIPTION("System Call Throttler Final");
MODULE_VERSION("5.0");

// ---- PARAMETERS ----
static unsigned long sys_call_table_addr = 0x0;
module_param(sys_call_table_addr, ulong, 0644);

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

unsigned long *sys_call_table = NULL;
DEFINE_PER_CPU(int, sc_in_hook);

#define MAX_SYSCALL_NR 512
static unsigned long original_sys_call_table[MAX_SYSCALL_NR];
static int hacked_status[MAX_SYSCALL_NR] = {0}; 
static int syscall_refcount[MAX_SYSCALL_NR] = {0};

// ---- UTILS ----
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

static void set_pte_rw(unsigned long addr) {
    pte_t *pte;
    unsigned int level;
    if (!lookup_address_func) return;
    pte = lookup_address_func(addr, &level);
    if (pte && pte_present(*pte)) pte->pte |= _PAGE_RW; 
    __flush_tlb_all();
}

unsigned long string_hash(const char *str){
    unsigned long hash = 0;
    int c;
    while((c=*str++)) hash = c + (hash << 6) + (hash << 16) - hash;
    return hash;
}

#define __NR_close 3
static unsigned long *find_real_sys_call_table(void) {
    unsigned long *table_ptr;
    unsigned long close_addr;
    unsigned long offset;
    close_addr = lookup_name("__x64_sys_close");
    if (!close_addr) return NULL;
    table_ptr = (unsigned long *)lookup_name("sys_call_table");
    if (!table_ptr) return NULL;
    for (offset = 0; offset < 512; offset++) {
        if (table_ptr[offset + __NR_close] == close_addr) return &table_ptr[offset];
        if (table_ptr[-offset + __NR_close] == close_addr) return &table_ptr[-offset];
    }
    return table_ptr; 
}

// ---- LOGIC ----
int check_throttle(void){
    unsigned long now = jiffies;
    unsigned long flags;
    u64 val;

    // Reset window logic
    if(time_after(now, window_start_jiffies + HZ)){
        spin_lock_irqsave(&window_reset_lock, flags);
        if(time_after(now, window_start_jiffies + HZ)){
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

// ---- THE HOOK ----
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

    recursion_guard = &get_cpu_var(sc_in_hook); 
    if (*recursion_guard) {
        put_cpu_var(sc_in_hook); 
        goto execute_original;
    }
    *recursion_guard = 1; 

    if (!atomic_read(&monitor_enabled)) {
        *recursion_guard = 0;
        put_cpu_var(sc_in_hook); 
        goto execute_original;
    }

retry_throttling: 
    rcu_read_lock();

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
    hash_for_each_possible_rcu(rules_ht,rule, node, current_uid().val){
        if(rule->type == MON_UID && rule->key == current_uid().val){
            identity_match = 1;
            break;
        }
    }
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

    // 3. Throttle Check
    should_block = check_throttle();
    rcu_read_unlock(); 

    if(should_block){
        this_cpu_inc(cpu_stats.blocked_count);
        start = ktime_get();
        
        *recursion_guard = 0;
        put_cpu_var(sc_in_hook);

        // --- FIX: LOOP CON TIMEOUT ---
        // Continua a dormire finché siamo nello stesso secondo E il monitor è attivo.
        // Il timeout (10ms) serve per "auto-svegliarsi" nella simulazione single-thread.
        while(time_before(jiffies, window_start_jiffies + HZ) && atomic_read(&monitor_enabled)) {
             wait_event_interruptible_timeout(throttle_wq, 
                time_after(jiffies, window_start_jiffies + HZ) || !atomic_read(&monitor_enabled),
                msecs_to_jiffies(10) 
            );
            // Al risveglio, il while ricontrolla "time_before". 
            // Se il secondo è passato, il while diventa falso ed esce.
        }

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
        
        // Ritenta per vedere se c'è posto nel nuovo secondo
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

    // 1. SIMULATION BYPASS (Permesso a tutti)
    if (cmd == _IOW('s', 99, int)) { 
        struct pt_regs regs;
        memset(&regs, 0, sizeof(regs));
        regs.ax = arg; 
        sys_hook_wrapper(&regs);
        return 0;
    }

    // 2. Security Check (Only Root can CONFIGURE)
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
            
            if (conf.type == MON_SYSCALL) {
                if (conf.value < MAX_SYSCALL_NR) {
                    if (syscall_refcount[conf.value] == 0) {
                        original_fn = sys_call_table[conf.value];
                        original_sys_call_table[conf.value] = original_fn;
                        printk(KERN_INFO "SC_THROTTLER: Hooking Syscall %lu\n", conf.value);
                        set_pte_rw((unsigned long)&sys_call_table[conf.value]);
                        sys_call_table[conf.value] = (unsigned long)sys_hook_wrapper;
                        __flush_tlb_all();
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
                                set_pte_rw((unsigned long)&sys_call_table[sc]);
                                sys_call_table[sc] = original_sys_call_table[sc];
                                __flush_tlb_all();
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
    printk(KERN_INFO "SC_THROTTLER: Initializing module...\n");
    spin_lock_init(&window_reset_lock);
    spin_lock_init(&peak_record.lock);
    window_start_jiffies = jiffies;
    module_load_time_jiffies = jiffies; 
    major_number = register_chrdev(0, DEVICE_NAME, &fops);
    sc_driver_class = class_create(THIS_MODULE, DEVICE_NAME);
    sc_driver_device = device_create(sc_driver_class, NULL, MKDEV(major_number, 0), NULL, DEVICE_NAME);

    if (sys_call_table_addr) sys_call_table = (unsigned long*)sys_call_table_addr;
    else sys_call_table = find_real_sys_call_table();
    if(!sys_call_table) return -EFAULT;

    lookup_address_func = (void *)lookup_name("lookup_address");
    return 0;
}

static void __exit sc_throttler_exit(void) {
    int i;
    struct sc_rule *rule;
    struct hlist_node *tmp;
    int bkt;
    if (sys_call_table) {
        for (i = 0; i < MAX_SYSCALL_NR; i++) {
            if (hacked_status[i]) {
                set_pte_rw((unsigned long)&sys_call_table[i]);
                sys_call_table[i] = original_sys_call_table[i];
            }
        }
        __flush_tlb_all();
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