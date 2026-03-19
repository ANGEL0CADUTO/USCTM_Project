/* test_stress.c - Generates 20 parallel processes to test the Peak/Blocked Counter */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/syscall.h>

#define NUM_PROCS 20

void spam_syscall() {
    // Each process bombards syscall 39
    while(1) {
        syscall(39);
        usleep(50000); // 50ms (20 calls/sec per process)
    }
}

int main() {
    pid_t pids[NUM_PROCS];
    
    printf("STRESS TEST: Starting %d parallel processes on getpid...\n", NUM_PROCS);
    
    for(int i = 0; i < NUM_PROCS; i++) {
        if((pids[i] = fork()) == 0) {
            spam_syscall();
            exit(0);
        }
    }

    printf("STRESS TEST: Processes running (Press Enter to terminate them)...\n");
    getchar();

    for(int i = 0; i < NUM_PROCS; i++) {
        kill(pids[i], 9);
    }
    
    printf("STRESS TEST: Terminated.\n");
    return 0;
}