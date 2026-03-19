/* test_barrier.c - Concurrency & Multithreading Stress Test */
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <time.h>

pthread_barrier_t barrier;
long target_syscall = 39; // getpid
int throttled_count = 0;
pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

void* thread_func(void* arg) {
    struct timespec start, end;
    
    // ALIGNMENT: Threads wait here
    pthread_barrier_wait(&barrier); 
    
    clock_gettime(CLOCK_MONOTONIC, &start);
    syscall(target_syscall); // The real kernel call
    clock_gettime(CLOCK_MONOTONIC, &end);

    double elapsed = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;
    
    // If the syscall took more than 100 milliseconds, it means it was intercepted 
    // and put to sleep by the Wait Queue of our module!
    if (elapsed > 0.1) { 
        pthread_mutex_lock(&lock);
        throttled_count++;
        pthread_mutex_unlock(&lock);
    }
    return NULL;
}

int main(int argc, char *argv[]) {
    int num_threads = 50;
    if(argc > 1) num_threads = atoi(argv[1]);

    printf("[*] Initializing Barrier for %d Threads...\n", num_threads);
    pthread_t threads[num_threads];
    pthread_barrier_init(&barrier, NULL, num_threads);

    for(int i=0; i<num_threads; i++) pthread_create(&threads[i], NULL, thread_func, NULL);
    for(int i=0; i<num_threads; i++) pthread_join(threads[i], NULL);

    printf("[+] Concurrency Result (Instant Burst):\n");
    printf("    - Total unleashed threads : %d\n", num_threads);
    printf("    - Threads that passed immediately : %d\n", num_threads - throttled_count);
    printf("    - Threads blocked (Sleep) : %d\n", throttled_count);
    
    return 0;
}