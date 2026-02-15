/* test_workload.c - GENERATORE DI TRAFFICO REALE */
#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <errno.h>

int main() {
    unsigned long count = 0;
    time_t start, now;
    
    // Scegli qui quale syscall bombardare. 
    // Usa 39 (getpid) se hai configurato quella, o 83 (mkdir) se hai configurato quella.
    // Consiglio 39 per testare Ftrace in sicurezza.
    long target_syscall = 83; 

    printf("TEST: Starting REAL syscall loop (Target: %ld)...\n", target_syscall);
    printf("TEST: My PID is %d (Register this UID/Name if needed!)\n", getpid());
    
    start = time(NULL);
    while(1) {
        // QUESTA È LA CHIAVE: Facciamo una VERA syscall.
        // Ftrace la vedrà passare e la bloccherà se supera il limite.
        syscall(target_syscall);
        
        count++;

        // RALLENTAMENTO ARTIFICIALE
        // Dorme per 10ms -> Genera circa 100 chiamate/sec massime.
        // Se il throttler è impostato a 5, vedrai il conteggio crollare.
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