/* test_mkdir.c - */
#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <sys/syscall.h>

int main() {
    unsigned long count = 0;
    time_t start, now;
    long target_syscall = 83; // mkdir

    printf("[*] TEST: Starting SAFE syscall loop (Target: mkdir / 83)...\n");
    printf("[*] TEST: My PID is %d\n", getpid());

    start = time(NULL);
    while(1) {
        // We use a dummy directory path. It will fail or succeed, 
        // but the kernel will still execute and intercept the syscall.
        syscall(target_syscall, "/tmp/sc_dummy_dir", 0777);
        count++;

        // Artificial slowdown (10ms sleep) -> generates ~100 calls/sec maximum.
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