#!/usr/bin/env bash
set -Eeuo pipefail

GREEN='\033[1;32m'
RED='\033[1;31m'
BLUE='\033[1;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_DIR"

MODULE_NAME="sc_throttler"
MODULE_FILE="./sc_throttler.ko"
MODE="${1:-menu}"

log()  { echo -e "${BLUE}[*]${NC} $*"; }
ok()   { echo -e "${GREEN}[+]${NC} $*"; }
fail() { echo -e "${RED}[-]${NC} $*" >&2; }

require_files() {
    local missing=0 file

    for file in Makefile run_tests.sh sc_throttler_module.c sc_throttler.h user.c; do
        if [[ ! -e "$file" ]]; then
            fail "Missing required file: $file"
            missing=1
        fi
    done
    [[ "$missing" -eq 0 ]]
}

module_loaded() {
    grep -q "^${MODULE_NAME}[[:space:]]" /proc/modules
}

unload_module() {
    if module_loaded; then
        sudo rmmod "$MODULE_NAME"
    fi
}

disable_monitor() {
    if [[ -x ./user_cli && -e /dev/sc_throttler ]]; then
        printf '4\n0\n0\n' | sudo ./user_cli >/dev/null 2>&1 || true
    fi
}

build_project() {
    log "Stopping any previously loaded module..."
    disable_monitor
    unload_module || true

    log "Cleaning and compiling the project..."
    make clean
    make 2>&1 | tee build-demo.log

    [[ -f "$MODULE_FILE" ]] || {
        fail "Module file was not generated."
        return 1
    }

    local kernel vermagic
    kernel="$(uname -r)"
    vermagic="$(modinfo -F vermagic "$MODULE_FILE" | awk '{print $1}')"
    if [[ "$kernel" != "$vermagic" ]]; then
        fail "Kernel/vermagic mismatch: kernel=$kernel module=$vermagic"
        return 1
    fi
    ok "Compilation completed for kernel $kernel."
}

load_module() {
    log "Loading the freshly compiled module..."
    unload_module || true
    sudo insmod "$MODULE_FILE"

    if ! module_loaded; then
        fail "Module is not listed by lsmod after insmod."
        return 1
    fi

    local attempt
    for attempt in {1..20}; do
        [[ -e /dev/sc_throttler ]] && break
        sleep 0.1
    done
    if [[ ! -e /dev/sc_throttler ]]; then
        fail "Device /dev/sc_throttler was not created."
        return 1
    fi
    ok "Module loaded and /dev/sc_throttler created."
}

show_status() {
    echo
    echo -e "${YELLOW}--- CURRENT STATUS ---${NC}"
    printf 'Kernel:   %s\n' "$(uname -r)"
    printf 'Vermagic: %s\n' "$(modinfo -F vermagic "$MODULE_FILE")"
    lsmod | grep "^${MODULE_NAME}[[:space:]]" || true
    ls -l /dev/sc_throttler 2>/dev/null || true
    sudo dmesg | grep 'SC_THROTTLER' | tail -n 8 || true
}

cleanup() {
    log "Cleaning the demo environment..."
    disable_monitor
    unload_module || true
    sudo pkill -x test_stress 2>/dev/null || true
    sudo pkill -x test_barrier 2>/dev/null || true
    sudo pkill -x test_identity 2>/dev/null || true
    sudo pkill -x test_uid 2>/dev/null || true
    sudo pkill -x test_wallclock 2>/dev/null || true
    sudo pkill -x test_getpid 2>/dev/null || true
    sudo pkill -x test_mkdir 2>/dev/null || true

    if module_loaded; then
        fail "Module is still loaded."
        return 1
    fi
    ok "Module and test processes removed."
}

prepare() {
    build_project
    load_module
    show_status
}

main() {
    require_files

    case "$MODE" in
        prepare)
            prepare
            ;;
        cli)
            prepare
            sudo ./user_cli
            ;;
        tests)
            prepare
            sudo ./run_tests.sh
            ;;
        full)
            prepare
            sudo ./run_tests.sh --full
            ;;
        full-auto)
            prepare
            sudo ./run_tests.sh --full-auto
            ;;
        cleanup)
            cleanup
            ;;
        menu)
            clear
            echo -e "${BLUE}=====================================================${NC}"
            echo -e "${BLUE}              USCTM DEMO LAUNCHER                    ${NC}"
            echo -e "${BLUE}=====================================================${NC}"
            echo "1) Prepare environment only"
            echo "2) Prepare and open manual CLI"
            echo "3) Prepare and open test menu"
            echo "4) Run complete presentation demo"
            echo "5) Cleanup"
            echo "0) Exit"
            read -r -p "Choice: " choice
            case "$choice" in
                1) MODE=prepare; main ;;
                2) MODE=cli; main ;;
                3) MODE=tests; main ;;
                4) MODE=full; main ;;
                5) MODE=cleanup; main ;;
                0) exit 0 ;;
                *) fail "Invalid choice."; exit 1 ;;
            esac
            ;;
        *)
            fail "Usage: $0 [prepare|cli|tests|full|full-auto|cleanup]"
            exit 1
            ;;
    esac
}

main
