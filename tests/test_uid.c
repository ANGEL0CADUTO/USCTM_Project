/* test_uid.c - Test to verify EUID-Based Identity */
#include <stdio.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <time.h>

int main() {
    int count = 0;
    uid_t current_uid = getuid();
    uid_t current_euid = geteuid();
    time_t start = time(NULL);

    printf("[*] Process (RUID: %d, EUID: %d) - Executing syscall 83 (mkdir)...\n",
           current_uid, current_euid);

    // Loop for 2 seconds
    while (time(NULL) - start < 2) {
        syscall(83, "/tmp/dummy_test_dir", 0777); // Real syscall
        count++;
    }

    int rate = count / 2;
    printf("[+] RESULT (RUID: %d, EUID: %d): %d total calls (Rate: %d calls/sec)\n",
           current_uid, current_euid, count, rate);

    if (rate < 20)
        printf("    -> CONCLUSION: Throttled by Kernel (target matched).\n");
    else
        printf("    -> CONCLUSION: Allowed to pass (target not matched or monitor off).\n");

    return 0;
}