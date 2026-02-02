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
static atomic64_t global_counter = ATOMIC64_INIT(0); // Global counter for allowed syscalls
static unsigned long window_start_jiffies = 0;      // Start of current time window
static spinlock_t window_reset_lock;                // Lock for window reset
static DECLARE_WAIT_QUEUE_HEAD(throttle_wq);        // Wait queue for throttled processes

// 6. Statistics
DEFINE_PER_CPU(struct sc_cpu_stats, cpu_stats); // Per-CPU stats
static struct sc_peak_record peak_record;       // Shared peak record

// 7. Syscall Hacking Variabler
unsigned long *sys_call_table = NULL; // Pointer to the found table 

// ---- FORWARD DECLARATIONS ----
static int sc_open(struct inode *inode, struct file *file);
static int sc_release(struct inode *inode, struct file *file);
static long sc_ioctl(struct file *file, unsigned int cmd, unsigned long arg);



// ---- VTPMO (Virtual To Physical Mapping Oracle) ----
// This function checks if a Virtual Address is mapped to a Physical Page.
// It walks the 4/5-level Page Table of the current process (kernel space).
// Returns: 1 (Valid), 0 (Invalid/Not Mapped).

int vtpmo(usigned long vaddr){
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
        if (!vtpmo((unsigned long)(chk + 134))) || !vtpmo((unsigned long)&(chk[183])) continue;

        if (chk[134] == chk[135] && chk[134] == chk[174] && chk[134] == chk[182] && chk[134] == chk[183]){
            printk(KERN_INFO "SC_THROTTLER: sys_call_table found at address: 0x%lx\n", i);
            return chk;
        }
        +

        // Anti-freeze: Schedule every now and then to avoid locking up the CPU during scan
        cnt++;
        if (cnt % 1000000 == 0){ cond_reschedule(); } // Yield to avoid watchdog timer    
    }
    return NULL;
}





// Placeholder for Open (Success)
static int sc_open(struct inode *inode, struct file *file) {
    return 0;
}

// Placeholder for Release (Success)
static int sc_release(struct inode *inode, struct file *file) {
    return 0;
}

// Placeholder for IOCTL (We will implement logic in Part 3)
static long sc_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {
    printk(KERN_INFO "SC_THROTTLER: IOCTL called with cmd %u\n", cmd);
    return 0; 
}

// File Operations
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
static void __exit sc_throttler_exit(void) {
    device_destroy(sc_driver_class, MKDEV(major_number, 0));
    class_destroy(sc_driver_class);
    unregister_chrdev(major_number, DEVICE_NAME);
    printk(KERN_INFO "SC_THROTTLER: Module unloaded\n");
}

module_init(sc_throttler_init);
module_exit(sc_throttler_exit);