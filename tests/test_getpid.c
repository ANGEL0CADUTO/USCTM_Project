/* test_getpid.c - Basic Syscall Workload Generator (Syscall 39) */
#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <sys/syscall.h>

int main() {
    unsigned long count = 0;
    time_t start, now;
    long target_syscall = 39; // getpid

    printf("[*] TEST: Starting HIGH-FREQUENCY syscall loop (Target: getpid / 39)...\n");
    printf("[*] TEST: My PID is %d\n", getpid());

    start = time(NULL);
    while(1) {
        syscall(target_syscall);
        count++;

        // Artificial slowdown (10ms sleep) -> generates ~100 calls/sec maximum.
        // If the throttler works (e.g., MAX=5), this output will drop significantly.
        usleep(10000);

        now = time(NULL);
        if (now > start) {
            printf("[+] TEST: %lu calls/sec\n", count);
            count = 0;
            start = now;
        }
    }
    return 0;
}