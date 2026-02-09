/* syscall_generator_slow.c - Generates Syscall 39 (getpid) with Delay */
#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <sys/syscall.h>
#include <sys/types.h>

int main() {
    unsigned long count = 0;
    time_t start, now;
    
    printf("TEST: Starting CONTROLLED syscall loop (Force Syscall 83)...\n");
    printf("TEST: Generating approx 100 calls/sec natively to save VM CPU.\n");
    
    start = time(NULL);
    while(1) {
        // FORZIAMO la syscall 83 (mkdir)
        syscall(83);
        count++;

        // RALLENTAMENTO ARTIFICIALE
        // Dorme per 10.000 microsecondi (0.01 secondi) -> ~100 chiamate/sec max
        // Se il throttler funziona e metti MAX=10, dovrai vedere 10, non 100.
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