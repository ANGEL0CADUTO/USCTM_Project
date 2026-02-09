/*
 * sc_throttler.h
 * Header file for the System Call Throttler Module.
 * 
 * This file defines the Interface between User-space and Kernel-space,
 * including IOCTL commands, configuration structures, and internal
 * kernel data structures protected by RCU.
 */

#ifndef _SC_THROTTLER_C 
#define _SC_THROTTLER_C

#include <linux/ioctl.h>
#include <linux/types.h>



// ---- ARCHITECTURAL CONFIGURATION ----
// Dual-Mode Implementation:
// If commented out, the module uses a Global Atomic Counter (Strict Consistency).
// If uncommented, it uses Per-CPU counters (High Scalability, eventual consistency).
// #define USE_PERCPU_COUNTERS 




// ---- USER-SPACE INTERFACE ----

// Magic Number used to uniquely identify this driver's IOCTL commands.
#define SC_IOC_MAGIC 's'

// We use this to map the different types of request
enum sc_monitor_type {
    MON_SYSCALL = 1,    // Monitor based on Syscall Number (RAX)
    MON_UID,            // Monitor based on Effective User ID (EUID)
    MON_NAME            // Monitor based on Executable Name (current->comm)
};



// Configuration structure passed from User-space via IOCTL 
struct sc_conf{
    int operation;          // 0=Add, 1=Remove
    int type;               // One of the values in enum sc_monitor_type
    unsigned long value;    // Number of the syscall or UID. 
    char name[16];           // Executable name. We use 16 so that it matches kernel's TASK_COMM_LEN 
};


// Structure for the statistics of the driver
//We use long long to prevent overflows with nanosecond timers

struct sc_stats{
    unsigned long long blocked_total;   // Number of throttled/blocked calls
    unsigned long long avg_blocked;     // Average number of blocked threads per second
    unsigned long long peak_delay_ns;   // Highest Peak delay observed for the actual execution of an invoked system call (nanoseconds)
    unsigned long peak_uid;             // UID associated with the system call who experienced highest peak delay
    char peak_comm[16];                 // Program Name associated with the system call who experienced the highest peak delay
};




// ---- IOCTL OPERATIONS ----

// Parameters:  (MAGIC_NUMBER, PROGESSIVE_ID, DATA_TYPE)

#define IOCTL_ADD_RULE      _IOW(SC_IOC_MAGIC, 1, struct sc_conf)
#define IOCTL_DEL_RULE      _IOW(SC_IOC_MAGIC, 2, struct sc_conf)
#define IOCTL_SET_MAX       _IOW(SC_IOC_MAGIC, 3, unsigned long)
#define IOCTL_SET_ONOFF     _IOW(SC_IOC_MAGIC, 4, int)
#define IOCTL_GET_STATS     _IOR(SC_IOC_MAGIC, 5, struct sc_stats)
#define IOCTL_LIST_RULES    _IOWR(SC_IOC_MAGIC,6, char*)
#define IOCTL_SIMULATE_SYSCALL _IOW(SC_IOC_MAGIC, 99, int)





// ---- KERNEL-SPACE INTERNAL STRUCTURES ----

#ifdef __KERNEL__

#include <linux/hashtable.h>
#include <linux/list.h>
#include <linux/rcupdate.h>
#include <linux/spinlock.h>

// Size of Hash Table for the lookup of rules in the table
// Size is arbitrary, I pick 10 just to make it big enough to handle a normal amount of requests
#define HT_BITS 10 //2^HT_BITS, in this case 2^10 = 1024

// Structure for the rule, it's its passport
struct sc_rule {
        int type;               // Type of rule (to distinguish beetween rules in same slot)
        unsigned long key;      // Hash Key (derived from UID, SyscallNr, or Name Hash)
        char name[16];          // Copy of the name (for safety checks when)

        struct hlist_node node; // Hook for the Hash Table
        struct rcu_head rcu;    // Hook for RCU (to guarantee garbage collection when doing deferred reclamation)
};



// This structure counts the stats Per-CPU, and it's used only if running with Per-CPU counter instead of global
struct sc_cpu_stats{
    unsigned long blocked_count; // Number of blocked thread by this CPU
};


// Structure shared by all CPUs to register peak stats
struct sc_peak_record{
    unsigned long long delay_ns;
    unsigned int uid;
    char comm[16];
    spinlock_t lock;                // Lock so that different CPUS cannot write simultaneosly
};



#endif /* __KERNEL__ */
#endif /* _SC_THROTTLER_H */