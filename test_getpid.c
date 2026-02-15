/* test_getpid.c */
#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <sys/syscall.h>
#include <sys/types.h>

int main() {
    unsigned long count = 0;
    time_t start, now;
    
    // TARGET: Syscall 39 (getpid)
    long target_syscall = 39; 

    printf("TEST: Starting HARDCORE syscall loop (Target: getpid / 39)...\n");
    printf("TEST: My PID is %d\n", getpid());
    
    start = time(NULL);
    while(1) {
        syscall(target_syscall);
        count++;

        // Rallentamento per vedere i log umani (100 calls/sec)
        // Se il throttler funziona, scenderà a 5.
        usleep(10000); 

        now = time(NULL);
        if (now > start) {
            printf("TEST: %lu calls/sec\n", count);
            count = 0;
            start = now;
        }
    }
    return 0;
}