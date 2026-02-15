/* syscall_generator.c - VERSIONE GETPID (39) */
#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <sys/syscall.h>
#include <sys/types.h>

int main() {
    unsigned long count = 0;
    time_t start, now;
    
    printf("TEST: Starting CONTROLLED syscall loop (Target: getpid / 39)...\n");
    // PID del processo corrente (così verifichi anche che sia quello giusto)
    printf("TEST: My PID is %d\n", getpid()); 
    
    start = time(NULL);
    while(1) {
        // FORZIAMO la syscall 39 (getpid)
        // getpid è molto leggera, quindi il loop sarà velocissimo.
        syscall(39);
        
        count++;

        // RALLENTAMENTO ARTIFICIALE
        // 10ms di sleep -> ~100 calls/sec
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