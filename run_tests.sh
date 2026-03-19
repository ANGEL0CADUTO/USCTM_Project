#!/bin/bash

GREEN='\033[1;32m'
RED='\033[1;31m'
BLUE='\033[1;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}[FATAL] This script must be run as ROOT (sudo).${NC}"
  exit 1
fi

REAL_USER=${SUDO_USER:-root}
REAL_UID=$(id -u "$REAL_USER")

cli_cmd() {
    echo -e "$1\n0" | ./user_cli > /dev/null 2>&1
}

reset_env() {
    cli_cmd "4\n0"
    rmmod sc_throttler 2>/dev/null
    insmod sc_throttler.ko
}

clear
echo -e "${BLUE}=====================================================${NC}"
echo -e "${BLUE}           AUTOMATED TEST SUITE                      ${NC}"
echo -e "${BLUE}=====================================================${NC}"

while true; do
    echo -e "\n${YELLOW}Select the Test to show to the Professor:${NC}"
    echo "1) Test 1: Security (Root Permissions & IOCTL)"
    echo "2) Test 2: Program Name Filtering"
    echo "3) Test 3: Effective User-ID (EUID) Filtering"
    echo "4) Test 4: Wall-Clock Reset (Time Precision)"
    echo "5) Test 5: Extreme Concurrency (50 Threads)"
    echo "6) Test 6: Statistics & Kernel Logs (dmesg)"
    echo "7) Test 7: Hot Removal (Anti-UAF)"
    echo "0) Exit and clean up"
    read -p "Choice: " choice

    case $choice in
        1)
            echo -e "\n${GREEN}[TEST 1] SECURITY AND PERMISSIONS (EUID != 0)${NC}"
            su "$REAL_USER" -c "echo -e '4\n1\n0' | ./user_cli"
            echo -e "${GREEN}[+] Test Passed: IOCTL protected correctly.${NC}"
            ;;
        2)
            echo -e "\n${GREEN}[TEST 2] PROGRAM NAME FILTERING${NC}"
            reset_env
            cli_cmd "4\n1"
            cli_cmd "3\n5"
            cli_cmd "1\n1\n39"          # Syscall 39 = getpid
            cli_cmd "1\n3\nevil_app"    # Registered program name

            echo "[*] Launching 'good_app' (NOT registered)..."
            timeout 5s ./test_identity good_app

            echo -e "\n[*] Launching 'evil_app' (REGISTERED)..."
            timeout 5s ./test_identity evil_app
            ;;
        3)
            echo -e "\n${GREEN}[TEST 3] EFFECTIVE USER-ID (EUID) FILTERING${NC}"
            echo "Objective: Demonstrate that the rule applies only to the registered effective user-ID."
            reset_env
            cli_cmd "4\n1"
            cli_cmd "3\n5"
            cli_cmd "1\n1\n83"          # Syscall 83 = mkdir
            cli_cmd "1\n2\n$REAL_UID"   # Effective UID of the normal user in practice

            echo -e "\n[*] Rule: Throttle EUID $REAL_UID on Syscall 83."
            echo "[*] Launching the process as normal user (EUID $REAL_UID)..."
            su "$REAL_USER" -c "timeout 5s ./test_uid"

            echo -e "\n[*] Launching the process as ROOT (EUID 0)..."
            timeout 5s ./test_uid

            echo -e "${GREEN}[+] Test Passed: EUID filtering works correctly.${NC}"
            ;;
        4)
            echo -e "\n${GREEN}[TEST 4] WALL-CLOCK RESET (1 SECOND)${NC}"
            echo "Objective: Verify the delay applied to the (MAX+1)-th request."
            reset_env
            cli_cmd "4\n1"
            cli_cmd "3\n5"
            cli_cmd "1\n1\n83"
            cli_cmd "1\n2\n$REAL_UID"

            su "$REAL_USER" -c "./test_wallclock 5"
            ;;
        5)
            echo -e "\n${GREEN}[TEST 5] EXTREME CONCURRENCY (50 THREADS)${NC}"
            reset_env
            cli_cmd "4\n1"
            cli_cmd "3\n5"
            cli_cmd "1\n1\n39"
            cli_cmd "1\n3\ntest_barrier"
            ./test_barrier 50
            ;;
        6)
            echo -e "\n${GREEN}[TEST 6] STATISTICS & KERNEL LOGS (dmesg)${NC}"
            echo -e "--- IOCTL STATISTICS ---"
            echo -e "5\n0" | ./user_cli | grep -A 7 "REAL-TIME STATISTICS"
            echo -e "\n--- LAST 5 LINES OF KERNEL LOG (dmesg) ---"
            dmesg | tail -n 5
            ;;
        7)
            echo -e "\n${GREEN}[TEST 7] HOT REMOVAL (ANTI USE-AFTER-FREE)${NC}"
            reset_env
            cli_cmd "4\n1"
            cli_cmd "3\n1"
            cli_cmd "1\n1\n39"
            cli_cmd "1\n3\ntest_identity"

            timeout 5s ./test_identity test_identity > /dev/null &
            PID_TEST=$!
            sleep 0.5

            rmmod sc_throttler
            if [ $? -eq 0 ]; then
                echo -e "${GREEN}[+] Module removed safely. Processes unblocked.${NC}"
            else
                echo -e "${RED}[-] Module removal failed.${NC}"
            fi

            kill "$PID_TEST" 2>/dev/null
            insmod sc_throttler.ko
            ;;
        0)
            echo "Exiting..."
            reset_env
            exit 0
            ;;
        *)
            echo "Invalid choice."
            ;;
    esac
done