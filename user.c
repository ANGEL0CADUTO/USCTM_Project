/*
 * user.c
 * User-space CLI tool to control the System Call Throttler.
 * Usage: sudo ./user_cli
 */


 #include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <string.h>
#include <errno.h>

// Include the shared header file
#include "sc_throttler.h"

#define DEVICE_PATH "/dev/sc_throttler"

void print_menu() {
    printf("\n--- SC_THROTTLER CONTROL PANEL ---\n");
    printf("1. Add Rule (Monitor Syscall/UID/Name)\n");
    printf("2. Remove Rule\n");
    printf("3. Set Max Throughput (N/sec)\n");
    printf("4. Enable/Disable Monitor\n");
    printf("5. Get Statistics\n");
    printf("0. Exit\n");
    printf("Select: ");
}

void get_input_rule(struct sc_conf *conf) {
    int choice;
    printf("\n--- Rule Type ---\n");
    printf("1. Monitor Syscall Number\n");
    printf("2. Monitor UID\n");
    printf("3. Monitor Program Name\n");
    printf("Select: ");
    scanf("%d", &choice);

    if (choice == 1) {
        conf->type = MON_SYSCALL;
        printf("Enter Syscall Number (e.g., 39 for getpid): ");
        scanf("%lu", &conf->value);
    } else if (choice == 2) {
        conf->type = MON_UID;
        printf("Enter UID (e.g., 1000): ");
        scanf("%lu", &conf->value);
    } else if (choice == 3) {
        conf->type = MON_NAME;
        printf("Enter Program Name (max 15 chars): ");
        scanf("%15s", conf->name); // Limit input to avoid overflow
    } else {
        printf("Invalid choice.\n");
        conf->type = 0; // Invalid
    }
}

int main() {
    int fd;
    int cmd;
    struct sc_conf conf;
    struct sc_stats stats;
    unsigned long val;
    int ret;

    // Open the device
    fd = open(DEVICE_PATH, O_RDWR);
    if (fd < 0) {
        perror("Failed to open device. Is the module loaded?");
        return -1;
    }

    while (1) {
        print_menu();
        if (scanf("%d", &cmd) != 1) break;

        // Clean memory
        memset(&conf, 0, sizeof(conf));
        memset(&stats, 0, sizeof(stats));

        switch (cmd) {
            case 1: // ADD RULE
                conf.operation = 0; // Add
                get_input_rule(&conf);
                if (conf.type == 0) break;
                
                ret = ioctl(fd, IOCTL_ADD_RULE, &conf);
                if (ret == 0) printf("[OK] Rule Added.\n");
                else perror("[ERR] Failed to add rule");
                break;

            case 2: // REMOVE RULE
                conf.operation = 1; // Remove
                get_input_rule(&conf);
                if (conf.type == 0) break;

                ret = ioctl(fd, IOCTL_DEL_RULE, &conf);
                if (ret == 0) printf("[OK] Rule Removed.\n");
                else perror("[ERR] Failed to remove rule");
                break;

            case 3: // SET MAX
                printf("Enter Max Throughput (calls/sec): ");
                scanf("%lu", &val);
                ret = ioctl(fd, IOCTL_SET_MAX, val);
                if (ret == 0) printf("[OK] Max set to %lu.\n", val);
                else perror("[ERR] Failed to set max");
                break;

            case 4: // ON/OFF
                printf("1 = Enable, 0 = Disable: ");
                scanf("%lu", &val); // Reuse val
                ret = ioctl(fd, IOCTL_SET_ONOFF, (int)val);
                if (ret == 0) printf("[OK] Monitor %s.\n", val ? "ENABLED" : "DISABLED");
                else perror("[ERR] Failed to set status");
                break;

            case 5: // GET STATS
                ret = ioctl(fd, IOCTL_GET_STATS, &stats);
                if (ret == 0) {
                    printf("\n--- STATISTICS ---\n");
                    printf("Total Blocked Calls: %llu\n", stats.blocked_total);
                    printf("Average Blocked/Sec: %llu\n", stats.avg_blocked);
                    printf("Peak Delay:          %llu ns\n", stats.peak_delay_ns);
                    printf("Peak Victim UID:     %lu\n", stats.peak_uid);
                    printf("Peak Victim Comm:    %s\n", stats.peak_comm);
                } else {
                    perror("[ERR] Failed to get stats");
                }
                break;

            case 0:
                close(fd);
                return 0;

            default:
                printf("Invalid option.\n");
        }
    }

    close(fd);
    return 0;
}