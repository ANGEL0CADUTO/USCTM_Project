/* test_identity.c - Dynamic Program-Name Identity Test */
#include <stdio.h>
#include <sys/prctl.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <time.h>

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <program_name>\n", argv[0]);
        return 1;
    }

    // Change the current->comm value observed by the kernel
    prctl(PR_SET_NAME, argv[1], 0, 0, 0);
    printf("[*] Process name set to: '%s' (PID: %d)\n", argv[1], getpid());

    time_t start = time(NULL);
    int count = 0;

    printf("[*] Executing syscall 39 (getpid) for 2 seconds...\n");
    while (time(NULL) - start < 2) {
        syscall(39);
        count++;
    }

    printf("[+] RESULT: '%s' executed %d calls (Rate: %d calls/sec)\n",
           argv[1], count, count / 2);

    if ((count / 2) < 20)
        printf("    -> CONCLUSION: Throttled by Kernel.\n");
    else
        printf("    -> CONCLUSION: Allowed to pass.\n");

    return 0;
}