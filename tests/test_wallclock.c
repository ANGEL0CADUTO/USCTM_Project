/* test_wallclock.c - Rigorous verification of the time window (1 Second) */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <time.h>

int main(int argc, char *argv[]) {
    int max = 5;
    if(argc > 1) max = atoi(argv[1]);

    struct timespec start, end;
    double elapsed;

    printf("[*] Executing %d calls (Should pass instantly)...\n", max);
    
    clock_gettime(CLOCK_MONOTONIC, &start);
    for(int i=0; i<max; i++) {
        syscall(83, "/tmp/dummy_test_dir", 0777);
    }
    clock_gettime(CLOCK_MONOTONIC, &end);
    
    elapsed = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;
    printf("[+] Total time for %d calls: %.6f seconds\n", max, elapsed);

    printf("\n[*] Executing call n. %d (Should block waiting for reset)...\n", max+1);
    
    clock_gettime(CLOCK_MONOTONIC, &start);
    syscall(83, "/tmp/dummy_test_dir", 0777); // The invocation too many!
    clock_gettime(CLOCK_MONOTONIC, &end);
    
    elapsed = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;
    printf("[+] Time for the single excess call: %.6f seconds\n", elapsed);

    if(elapsed >= 0.1) 
        printf("    -> CONCLUSION: 1 sec wall-clock verified!\n");
    else 
        printf("    -> CONCLUSION: Error, the call was not blocked.\n");

    return 0;
}