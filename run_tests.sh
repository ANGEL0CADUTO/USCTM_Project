#!/usr/bin/env bash
set -uo pipefail

GREEN='\033[1;32m'
RED='\033[1;31m'
BLUE='\033[1;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_DIR"

MODULE_NAME="sc_throttler"
MODULE_FILE="./sc_throttler.ko"
FULL_MODE=0
NO_PAUSE=0
FAILURE_COUNT=0
CLEANED_UP=0
# Restore the device mode even if the security test is interrupted.
DEVICE_MODE_TO_RESTORE=""

case "${1:-}" in
    --full) FULL_MODE=1 ;;
    --full-auto) FULL_MODE=1; NO_PAUSE=1 ;;
    "") ;;
    *)
        echo "Usage: $0 [--full|--full-auto]"
        exit 1
        ;;
esac

if [[ "$EUID" -ne 0 ]]; then
    echo -e "${RED}[FATAL] This script must be run as root (use sudo).${NC}"
    exit 1
fi

REAL_USER="${SUDO_USER:-}"
if [[ -z "$REAL_USER" || "$REAL_USER" == root ]]; then
    REAL_USER="$(logname 2>/dev/null || true)"
fi
if [[ -z "$REAL_USER" || "$REAL_USER" == root ]]; then
    echo -e "${RED}[FATAL] A non-root caller is required for the security and EUID tests.${NC}"
    echo "Run the demo from your normal account with: ./demo.sh"
    exit 1
fi
REAL_UID="$(id -u "$REAL_USER")"

for file in "$MODULE_FILE" ./user_cli ./test_identity ./test_uid ./test_wallclock ./test_barrier; do
    if [[ ! -x "$file" && "$file" != "$MODULE_FILE" ]]; then
        echo -e "${RED}[FATAL] Missing executable: $file. Run ./deploy.sh first.${NC}"
        exit 1
    fi
    if [[ "$file" == "$MODULE_FILE" && ! -f "$file" ]]; then
        echo -e "${RED}[FATAL] Missing module: $file. Run ./deploy.sh first.${NC}"
        exit 1
    fi
done

MARKER="USCTM_DEMO_$(date +%s)_$$"
if ! printf '%s\n' "$MARKER" > /dev/kmsg; then
    echo -e "${RED}[FATAL] Cannot write the demo marker to /dev/kmsg.${NC}"
    exit 1
fi

module_loaded() {
    grep -q "^${MODULE_NAME}[[:space:]]" /proc/modules
}

cli_cmd() {
    local output status
    output="$(printf '%b\n0\n' "$1" | ./user_cli 2>&1)"
    status=$?
    if [[ "$status" -ne 0 ]] || grep -qE '\[-\]|Failed|Invalid' <<<"$output"; then
        echo "$output" >&2
        return 1
    fi
}

ensure_module_loaded() {
    if ! module_loaded; then
        insmod "$MODULE_FILE" || return 1
    fi
    [[ -e /dev/sc_throttler ]]
}

reset_env() {
    if [[ -e /dev/sc_throttler ]]; then
        cli_cmd '4\n0' || true
    fi
    rmmod "$MODULE_NAME" 2>/dev/null || true
    insmod "$MODULE_FILE" || return 1
    [[ -e /dev/sc_throttler ]]
}

cleanup_env() {
    [[ "$CLEANED_UP" -eq 1 ]] && return 0

    if [[ -n "$DEVICE_MODE_TO_RESTORE" && -e /dev/sc_throttler ]]; then
        chmod "$DEVICE_MODE_TO_RESTORE" /dev/sc_throttler || true
        DEVICE_MODE_TO_RESTORE=""
    fi

    if [[ -e /dev/sc_throttler ]]; then
        cli_cmd '4\n0' || true
    fi
    rmmod "$MODULE_NAME" 2>/dev/null || true
    pkill -x test_stress 2>/dev/null || true
    pkill -x test_barrier 2>/dev/null || true
    pkill -x test_identity 2>/dev/null || true
    pkill -x test_uid 2>/dev/null || true
    pkill -x test_wallclock 2>/dev/null || true
    pkill -x test_getpid 2>/dev/null || true
    pkill -x test_mkdir 2>/dev/null || true
    CLEANED_UP=1
}

cleanup_on_exit() {
    cleanup_env
}
trap cleanup_on_exit EXIT
trap 'cleanup_env; exit 130' INT TERM

pause_demo() {
    if [[ "$NO_PAUSE" -eq 0 ]]; then
        echo
        read -r -p "Press ENTER to continue..." _ || true
    fi
}

configure_name_test() {
    echo "[*] Reset: monitor OFF -> rmmod sc_throttler -> insmod ./sc_throttler.ko"
    echo "[*] CLI inputs (configured as root):"
    echo "    3 -> 5           Set MAX = 5"
    echo "    1 -> 1 -> 39     Add syscall getpid (39)"
    echo "    1 -> 3 -> evil_app  Add program name evil_app"
    echo "    4 -> 1           Enable monitor"
    reset_env &&
        cli_cmd '3\n5' &&
        cli_cmd '1\n1\n39' &&
        cli_cmd '1\n3\nevil_app' &&
        cli_cmd '4\n1'
}

configure_uid_test() {
    echo "[*] Reset: monitor OFF -> rmmod sc_throttler -> insmod ./sc_throttler.ko"
    echo "[*] CLI inputs (configured as root):"
    echo "    3 -> 5           Set MAX = 5"
    echo "    1 -> 1 -> 83     Add syscall mkdir (83)"
    echo "    1 -> 2 -> $REAL_UID  Add EUID of $REAL_USER"
    echo "    4 -> 1           Enable monitor"
    reset_env &&
        cli_cmd '3\n5' &&
        cli_cmd '1\n1\n83' &&
        cli_cmd "1\n2\n$REAL_UID" &&
        cli_cmd '4\n1'
}

configure_concurrency_test() {
    echo "[*] Reset: monitor OFF -> rmmod sc_throttler -> insmod ./sc_throttler.ko"
    echo "[*] CLI inputs (configured as root):"
    echo "    3 -> 5           Set MAX = 5"
    echo "    1 -> 1 -> 39     Add syscall getpid (39)"
    echo "    1 -> 3 -> test_barrier  Add program name test_barrier"
    echo "    4 -> 1           Enable monitor"
    reset_env &&
        cli_cmd '3\n5' &&
        cli_cmd '1\n1\n39' &&
        cli_cmd '1\n3\ntest_barrier' &&
        cli_cmd '4\n1'
}

run_and_expect() {
    local expected="$1"
    shift
    local output status

    echo "[*] Command: $*"
    output="$("$@" 2>&1)"
    status=$?
    printf '%s\n' "$output"
    [[ "$status" -eq 0 ]] && grep -qF -- "$expected" <<<"$output"
}

run_test_1() {
    local output status original_mode
    echo -e "\n${GREEN}[TEST 1] SECURITY: DEVICE PERMISSIONS + ROOT-ONLY IOCTL${NC}"
    reset_env || return 1

    echo "[*] Layer 1: non-root attempts open() with the original device permissions."
    echo "[*] Executing user_cli as $REAL_USER (EUID $REAL_UID), input: 0 -> Exit"
    echo "[*] Expect open() to fail with EACCES / Permission denied."
    ls -l /dev/sc_throttler
    output="$(su -s /bin/bash "$REAL_USER" -c "printf '0\\n' | ./user_cli" 2>&1)"
    status=$?
    printf '%s\n' "$output"
    if [[ "$status" -eq 0 ]] || ! grep -qF 'Permission denied' <<<"$output"; then
        echo -e "${RED}[-] Layer 1 FAIL: expected open() to be denied by device permissions.${NC}"
        return 1
    fi
    echo -e "${GREEN}[+] Layer 1 PASS: open() denied by /dev/sc_throttler permissions.${NC}"

    echo "[*] Layer 2: temporarily allow open(), then attempt a configuration IOCTL as non-root."
    echo "[*] Temporarily chmod 0666 /dev/sc_throttler; original permissions will be restored."
    echo "[*] Executing user_cli as $REAL_USER (EUID $REAL_UID) with inputs:"
    echo "    4 -> Enable / Disable Monitor"
    echo "    1 -> Attempt to enable monitoring"
    echo "    0 -> Exit CLI"
    echo "[*] Expect open() to succeed, then ioctl() to fail with EPERM."
    original_mode="$(stat -c '%a' /dev/sc_throttler)" || return 1
    DEVICE_MODE_TO_RESTORE="$original_mode"
    if ! chmod 0666 /dev/sc_throttler; then
        echo -e "${RED}[-] Unable to temporarily adjust device permissions.${NC}"
        return 1
    fi
    output="$(su -s /bin/bash "$REAL_USER" -c "printf '4\\n1\\n0\\n' | ./user_cli" 2>&1)"
    status=$?
    if ! chmod "$original_mode" /dev/sc_throttler; then
        echo -e "${RED}[-] Could not restore the original device permissions.${NC}"
        return 1
    fi
    DEVICE_MODE_TO_RESTORE=""
    # Show the genuine error and the first CLI menu; suppress the repeated menu.
    # Keep the full, unfiltered output in $output for the actual PASS/FAIL checks.
    printf '%s\n' "$output" | awk '
        /^=========================================$/ {
            separators++
            if (separators == 3) exit
        }
        { print }
    '
    if [[ "$status" -ne 0 ]] ||
       grep -qF '[FATAL] Failed to open device' <<<"$output" ||
       ! grep -qF 'Failed to set status: Operation not permitted' <<<"$output"; then
        echo -e "${RED}[-] Layer 2 FAIL: expected open() success and ioctl() -> EPERM.${NC}"
        return 1
    fi
    echo -e "${GREEN}[+] Layer 2 PASS: open() succeeded, IOCTL rejected with EPERM.${NC}"
}

run_test_2() {
    echo -e "\n${GREEN}[TEST 2] PROGRAM NAME FILTERING${NC}"
    configure_name_test || return 1

    echo "[*] Comparison: identical syscall 39, different current->comm; expect only evil_app to be throttled."
    echo "[*] Launching 'good_app' (NOT registered)..."
    run_and_expect 'CONCLUSION: Allowed to pass.' timeout 5s ./test_identity good_app || return 1

    echo -e "\n[*] Launching 'evil_app' (REGISTERED)..."
    run_and_expect 'CONCLUSION: Throttled by Kernel.' timeout 5s ./test_identity evil_app
}

run_test_3() {
    echo -e "\n${GREEN}[TEST 3] EFFECTIVE USER-ID (EUID) FILTERING${NC}"
    echo "Objective: apply the rule only to the registered effective user-ID."
    echo "[*] Comparison: syscall 83 is identical; EUID $REAL_UID is registered, EUID 0 is not."
    configure_uid_test || return 1

    echo -e "\n[*] Rule: throttle EUID $REAL_UID on syscall 83."
    echo "[*] Launching as $REAL_USER (EUID $REAL_UID)..."
    run_and_expect 'CONCLUSION: Throttled by Kernel (target matched).' \
        su -s /bin/bash "$REAL_USER" -c "timeout 5s ./test_uid" || return 1

    echo -e "\n[*] Launching as root (EUID 0)..."
    run_and_expect 'CONCLUSION: Allowed to pass (target not matched or monitor off).' \
        timeout 5s ./test_uid
}

run_test_4() {
    echo -e "\n${GREEN}[TEST 4] WALL-CLOCK RESET (1 SECOND)${NC}"
    echo "Objective: verify the delay applied to the (MAX+1)-th request."
    echo "[*] Test program: 5 immediate mkdir calls, then measure elapsed time for call 6."
    configure_uid_test || return 1
    run_and_expect 'CONCLUSION: 1 sec wall-clock verified!' \
        su -s /bin/bash "$REAL_USER" -c "./test_wallclock 5"
}

run_test_5() {
    local output blocked
    echo -e "\n${GREEN}[TEST 5] CONCURRENCY (50 THREADS)${NC}"
    echo "[*] A pthread barrier releases 50 threads against the same global MAX = 5."
    configure_concurrency_test || return 1

    echo "[*] Command executed: ./test_barrier 50 (as root)"
    echo "[*] Script PASS criterion: parsed number of blocked threads is > 0 (not a proof of exactly 45)."
    output="$(./test_barrier 50 2>&1)"
    printf '%s\n' "$output"
    blocked="$(awk -F: '/Threads blocked \(Sleep\)/ {gsub(/[[:space:]]/, "", $2); print $2}' <<<"$output")"
    [[ "$blocked" =~ ^[0-9]+$ ]] && (( blocked > 0 ))
}

run_test_6() {
    local output
    echo -e "\n${GREEN}[TEST 6] STATISTICS & KERNEL LOGS${NC}"
    echo "--- IOCTL STATISTICS ---"
    echo "[*] CLI inputs as root: 5 -> Get Real-Time Statistics; 0 -> Exit CLI"
    echo "[*] Reading statistics from the immediately preceding concurrency test."
    output="$(printf '5\n0\n' | ./user_cli 2>&1)"
    printf '%s\n' "$output" | grep -A 7 'REAL-TIME STATISTICS' || return 1
    echo -e "\n--- LAST 8 MODULE LOGS ---"
    echo "[*] Command: dmesg | grep SC_THROTTLER | tail -n 8"
    dmesg | grep 'SC_THROTTLER' | tail -n 8
}

run_test_7() {
    local pid_test status
    echo -e "\n${GREEN}[TEST 7] HOT REMOVAL (ANTI USE-AFTER-FREE)${NC}"
    echo "[*] Reset module, then configure MAX=1, syscall 39 and program name test_identity."
    echo "[*] CLI inputs: 3 -> 1; 1 -> 1 -> 39; 1 -> 3 -> test_identity; 4 -> 1"
    reset_env || return 1
    cli_cmd '3\n1' || return 1
    cli_cmd '1\n1\n39' || return 1
    cli_cmd '1\n3\ntest_identity' || return 1
    cli_cmd '4\n1' || return 1

    echo "[*] Command: timeout 5s ./test_identity test_identity >/dev/null &"
    timeout 5s ./test_identity test_identity >/dev/null &
    pid_test=$!
    echo "[*] Test process PID: $pid_test; sleep 0.5; then rmmod sc_throttler."
    sleep 0.5

    if ! rmmod "$MODULE_NAME"; then
        echo -e "${RED}[-] Module removal failed.${NC}"
        kill "$pid_test" 2>/dev/null || true
        wait "$pid_test" 2>/dev/null || true
        return 1
    fi
    echo -e "${GREEN}[+] Module removed safely.${NC}"

    echo "[*] Command: wait $pid_test; expect exit status 0."
    wait "$pid_test"
    status=$?
    if [[ "$status" -ne 0 ]]; then
        echo -e "${RED}[-] Test process exited abnormally: status $status.${NC}"
        return 1
    fi
    echo -e "${GREEN}[+] Test process resumed and terminated normally.${NC}"

    echo "[*] Reload module after hot removal: insmod $MODULE_FILE"
    insmod "$MODULE_FILE"
}

final_health_check() {
    local kernel_slice
    echo -e "\n${YELLOW}--- FINAL HEALTH CHECK ---${NC}"
    echo "[*] Checking kernel messages since the demo marker for errors."
    if ! kernel_slice="$(dmesg | sed -n "/$MARKER/,\$p")"; then
        echo -e "${RED}[-] Unable to read the kernel log.${NC}"
        return 1
    fi
    if ! grep -qF "$MARKER" <<<"$kernel_slice"; then
        echo -e "${RED}[-] Demo marker not found in the kernel log.${NC}"
        return 1
    fi

    if grep -Ei 'BUG:|WARNING:|Oops|panic|scheduling while atomic|use-after-free|general protection|soft lockup|deadlock' \
        <<<"$kernel_slice"; then
        echo -e "${RED}[-] Kernel warnings/errors detected after the demo marker.${NC}"
        return 1
    fi

    echo -e "${GREEN}[+] No kernel errors detected during the demo.${NC}"
    echo -e "\n--- LAST 8 MODULE LOGS ---"
    grep 'SC_THROTTLER' <<<"$kernel_slice" | tail -n 8 || true
}

run_demo_step() {
    local label="$1"
    shift

    if "$@"; then
        echo -e "${GREEN}[PASS] $label${NC}"
    else
        echo -e "${RED}[FAIL] $label${NC}"
        FAILURE_COUNT=$((FAILURE_COUNT + 1))
    fi
}

run_full_demo() {
    run_demo_step "Test 1 - Security" run_test_1; pause_demo
    run_demo_step "Test 2 - Program name" run_test_2; pause_demo
    run_demo_step "Test 3 - EUID" run_test_3; pause_demo
    run_demo_step "Test 4 - Wall clock" run_test_4; pause_demo
    run_demo_step "Test 5 - Concurrency" run_test_5; pause_demo
    run_demo_step "Test 6 - Statistics" run_test_6; pause_demo
    run_demo_step "Test 7 - Hot removal" run_test_7; pause_demo
    run_demo_step "Kernel health check" final_health_check

    echo
    if [[ "$NO_PAUSE" -eq 0 ]]; then
        read -r -p "Press ENTER to clean up and finish..." _ || true
    fi
    cleanup_env

    if [[ "$FAILURE_COUNT" -eq 0 ]]; then
        echo -e "${GREEN}[+] Demo completed: all checks passed and the environment was cleaned.${NC}"
        return 0
    fi

    echo -e "${RED}[-] Demo completed with $FAILURE_COUNT failed check(s); cleanup was performed.${NC}"
    return 1
}

show_menu() {
    local choice
    clear
    echo -e "${BLUE}=====================================================${NC}"
    echo -e "${BLUE}           AUTOMATED TEST SUITE                      ${NC}"
    echo -e "${BLUE}=====================================================${NC}"

    while true; do
        echo -e "\n${YELLOW}Select the test:${NC}"
        echo "1) Security"
        echo "2) Program Name Filtering"
        echo "3) Effective User-ID Filtering"
        echo "4) Wall-Clock Reset"
        echo "5) Extreme Concurrency"
        echo "6) Statistics & Kernel Logs"
        echo "7) Hot Removal"
        echo "8) Complete presentation demo"
        echo "9) Final health check"
        echo "0) Exit and clean up"
        read -r -p "Choice: " choice

        case "$choice" in
            1) run_demo_step "Test 1 - Security" run_test_1 ;;
            2) run_demo_step "Test 2 - Program name" run_test_2 ;;
            3) run_demo_step "Test 3 - EUID" run_test_3 ;;
            4) run_demo_step "Test 4 - Wall clock" run_test_4 ;;
            5) run_demo_step "Test 5 - Concurrency" run_test_5 ;;
            6) run_demo_step "Test 6 - Statistics" run_test_6 ;;
            7) run_demo_step "Test 7 - Hot removal" run_test_7 ;;
            8) run_full_demo; return $? ;;
            9) run_demo_step "Kernel health check" final_health_check ;;
            0)
                cleanup_env
                echo -e "${GREEN}[+] Module unloaded successfully.${NC}"
                return 0
                ;;
            *) echo "Invalid choice." ;;
        esac
    done
}

ensure_module_loaded || {
    echo -e "${RED}[FATAL] Unable to load $MODULE_FILE or create the device.${NC}"
    exit 1
}

if [[ "$FULL_MODE" -eq 1 ]]; then
    run_full_demo
else
    show_menu
fi
