/* test_mkdir.c - Generatore Sicuro (Syscall 83) */
#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <errno.h>
#include <string.h>
#include <sys/stat.h>

int main() {
    unsigned long count = 0;
    time_t start, now;
    
    // Target: Syscall 83 (mkdir su x64)
    long target_syscall = 83; 

    printf("TEST: Starting SAFEST syscall loop (Target: mkdir / 83)...\n");
    printf("TEST: My PID is %d\n", getpid());
    
    start = time(NULL);
    while(1) {
        // Facciamo una vera syscall mkdir
        // Usiamo un nome dummy, fallirà quasi sempre o creerà la cartella, 
        // ma a noi interessa solo che il kernel la esegua.
        syscall(target_syscall, "/tmp/sc_test_dir", 0777);
        
        count++;

        // RALLENTAMENTO
        // 10ms sleep -> Max 100 calls/sec
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