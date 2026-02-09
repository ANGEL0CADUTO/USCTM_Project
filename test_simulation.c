/* test_simulatio.c - DEBUG VERSION */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <time.h>
#include <errno.h>
#include <string.h>

#define SC_IOC_MAGIC 's'
#define IOCTL_SIMULATE_SYSCALL _IOW(SC_IOC_MAGIC, 99, int)

int main() {
    int fd;
    unsigned long count = 0;
    time_t start, now;
    int target_syscall = 83; 
    int ret;

    printf("TEST DEBUG: Opening driver...\n");
    fd = open("/dev/sc_throttler", O_RDWR);
    if (fd < 0) {
        perror("FATAL: Cannot open driver");
        return -1;
    }

    printf("TEST DEBUG: Driver opened. FD: %d\n", fd);
    printf("TEST DEBUG: Starting stress test loop...\n");

    start = time(NULL);
    
    while(1) {
        // Chiamata al driver
        ret = ioctl(fd, IOCTL_SIMULATE_SYSCALL, target_syscall);
        
        // --- CONTROLLO ERRORE FONDAMENTALE ---
        if (ret < 0) {
            // Se fallisce, stampa l'errore e muori. 
            // Cosi capiamo perche non vedevi log nel kernel.
            printf("\nFATAL ERROR in Loop: IOCTL failed! Return: %d, Error: %s\n", 
                   ret, strerror(errno));
            break;
        }
        // -------------------------------------

        count++;
        now = time(NULL);
        if (now > start) {
            printf("TEST DEBUG: %lu calls/sec\n", count);
            count = 0;
            start = now;
        }
    }

    close(fd);
    return 0;
}