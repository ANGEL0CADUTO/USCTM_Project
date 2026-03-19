/*
 * user.c
 * User-space CLI tool to control the System Call Throttler.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <string.h>
#include <errno.h>

#include "sc_throttler.h"

#define DEVICE_PATH "/dev/sc_throttler"

void print_menu() {
    printf("\n=========================================\n");
    printf("     SC_THROTTLER CONTROL PANEL       \n");
    printf("=========================================\n");
    printf(" 1. Add Rule (Syscall / EUID / Name)\n");
    printf(" 2. Remove Rule\n");
    printf(" 3. Set Max Throughput (Calls/sec)\n");
    printf(" 4. Enable / Disable Monitor\n");
    printf(" 5. Get Real-Time Statistics\n");
    printf(" 6. List Active Rules\n");
    printf(" 0. Exit\n");
    printf("=========================================\n");
    printf("Select option: ");
}

void get_input_rule(struct sc_conf *conf) {
    int choice;
    printf("\n--- Rule Type ---\n");
    printf("1. Syscall Number (e.g., 39 for getpid, 83 for mkdir)\n");
    printf("2. User ID (e.g., 1000)\n");
    printf("3. Program Name (max 15 chars)\n");
    printf("Select: ");
    if (scanf("%d", &choice) != 1) return;

    if (choice == 1) {
        conf->type = MON_SYSCALL;
        printf("Enter Syscall Number: ");
        scanf("%lu", &conf->value);
    } else if (choice == 2) {
        conf->type = MON_UID;
        printf("Enter Effective User ID (EUID): ");
        scanf("%lu", &conf->value);
    } else if (choice == 3) {
        conf->type = MON_NAME;
        printf("Enter Program Name: ");
        scanf("%15s", conf->name); 
    } else {
        printf("Invalid choice.\n");
        conf->type = 0; 
    }
}

int main() {
    int fd;
    int cmd;
    struct sc_conf conf;
    struct sc_stats stats;
    unsigned long val;
    int ret;
    char list_buf[4096]; // 4KB Buffer for rules

    fd = open(DEVICE_PATH, O_RDWR);
    if (fd < 0) {
        perror("[FATAL] Failed to open device. Are you running as ROOT? Is the module loaded?");
        return -1;
    }

    while (1) {
        print_menu();
        if (scanf("%d", &cmd) != 1) {
            int c; while ((c = getchar()) != '\n' && c != EOF); // Clear stdin
            continue;
        }

        memset(&conf, 0, sizeof(conf));
        memset(&stats, 0, sizeof(stats));

        switch (cmd) {
            case 1: // ADD RULE
                conf.operation = 0;
                get_input_rule(&conf);
                if (conf.type == 0) break;
                
                ret = ioctl(fd, IOCTL_ADD_RULE, &conf);
                if (ret == 0) printf("\n[+] Rule Successfully Added.\n");
                else perror("\n[-] Failed to add rule");
                break;

            case 2: // REMOVE RULE
                conf.operation = 1;
                get_input_rule(&conf);
                if (conf.type == 0) break;

                ret = ioctl(fd, IOCTL_DEL_RULE, &conf);
                if (ret == 0) printf("\n[+] Rule Successfully Removed.\n");
                else perror("\n[-] Failed to remove rule");
                break;

            case 3: // SET MAX
                printf("Enter Max Throughput (calls/sec): ");
                scanf("%lu", &val);
                ret = ioctl(fd, IOCTL_SET_MAX, val);
                if (ret == 0) printf("\n[+] Max Throughput set to %lu.\n", val);
                else perror("\n[-] Failed to set max");
                break;

            case 4: // ON/OFF
                printf("1 = Enable, 0 = Disable: ");
                scanf("%lu", &val); 
                ret = ioctl(fd, IOCTL_SET_ONOFF, (int)val);
                if (ret == 0) printf("\n[+] Monitor %s.\n", val ? "ENABLED" : "DISABLED");
                else perror("\n[-] Failed to set status");
                break;

            case 5: // GET STATS
                ret = ioctl(fd, IOCTL_GET_STATS, &stats);
                if (ret == 0) {
                    printf("\n--- REAL-TIME STATISTICS ---\n");
                    printf("Total Blocked Calls : %llu\n", stats.blocked_total);
                    printf("Average Blocked/Sec : %llu\n", stats.avg_blocked);
                    printf("Peak Blocked Threads: %llu (in a 1s window)\n", stats.peak_blocked);
                    printf("Peak Delay          : %llu ns\n", stats.peak_delay_ns);
                    if(stats.peak_delay_ns > 0) {
                        printf("Peak Victim EUID     : %lu\n", stats.peak_uid);
                        printf("Peak Victim Comm    : %s\n", stats.peak_comm);
                    }
                } else {
                    perror("\n[-] Failed to get stats");
                }
                break;

            case 6: // LIST RULES (Crucial for Specification!)
                memset(list_buf, 0, sizeof(list_buf));
                ret = ioctl(fd, IOCTL_LIST_RULES, list_buf);
                if (ret == 0) {
                    printf("\n--- ACTIVE REGISTERED RULES ---\n");
                    printf("%s", list_buf);
                    printf("-------------------------------\n");
                } else {
                    perror("\n[-] Failed to list rules");
                }
                break;

            case 0:
                close(fd);
                printf("Exiting. Have a nice day!\n");
                return 0;

            default:
                printf("\n[-] Invalid option.\n");
        }
    }

    close(fd);
    return 0;
}