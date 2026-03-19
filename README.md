```markdown
# SC_THROTTLER

Linux Kernel Module (LKM) implementing a **system call throttling mechanism** for x86-64 Linux systems.

The module exposes a **character device driver** that allows privileged user-space software to register and deregister:

- **program names**
- **effective user-IDs (EUIDs)**
- **syscall numbers**

Whenever a **registered syscall** is invoked by either:

- a **registered program name**, or
- a **registered effective user-ID**

the module applies a runtime monitor that enforces a configurable global limit `MAX` over a **1-second wall-clock window**.

If the number of matching syscall invocations exceeds `MAX`, the corresponding invoking threads are **temporarily blocked** until the current window expires.

---

## Project Goal

The goal of the project is to implement, test, and document a kernel-level monitoring mechanism that can selectively throttle system calls according to the following logic:

```text
Throttle_Check ⟺ (SyscallID ∈ S) ∧ ((EUID ∈ U) ∨ (ProgramName ∈ N))

Where:
S = registered syscall numbers
U = registered effective user-IDs
N = registered program names
```

This ensures that:
* A syscall is not throttled just because it is registered.
* Throttling applies only when the syscall is invoked by a monitored identity.

## Main Features

* **Registration / deregistration of:**
  * Syscall numbers
  * Effective user-IDs
  * Program names
* **Runtime configuration** through `ioctl(...)`
* **Global throughput limit** `MAX` (calls per second)
* **On/off toggle** for the monitor
* **Rule listing** from user space
* **Statistics collection:**
  * Peak delay
  * Corresponding victim program name and user-ID
  * Average blocked threads
  * Peak blocked threads
* **Root-only configuration**
* **Safe runtime removal** of the module
* **User-space CLI** and automated test suite included

---

## Architecture Overview

### Interception Mechanism
The module uses **Ftrace with IPMODIFY** to intercept selected syscalls safely on modern Linux kernels. This was chosen instead of direct syscall table patching because Ftrace is more robust and appropriate on recent kernels.

### Identity Matching
The module supports two identity classes:
1. **Effective User-ID (EUID)**, using `current_euid()`
2. **Program name**, using `current->comm`

Program-name matching is implemented through:
* Hash-based lookup for fast search
* String comparison only for collision resolution

### Rule Storage
Rules are stored in a kernel hash table for near O(1) average lookup.

### Concurrency Control
The module uses:
* **RCU** for lock-free lookups in the syscall fast path
* **Mutex** protection for configuration updates
* **Spinlocks** for synchronization of timing / statistics updates
* **Per-CPU counters** for scalable blocked-thread accounting

### Time Window
The enforcement window is based on `jiffies` and approximates a wall-clock interval of 1 second with low overhead. `ktime_get()` is used only for precise delay statistics.

### Safe Unloading
To avoid teardown races and use-after-free conditions, the final implementation combines:
* Synchronous Ftrace unregistration
* RCU grace periods (`synchronize_rcu()`)
* An `active_threads` barrier
* Wake-up of sleeping threads during shutdown

---

## Repository Structure

```text
.
├── Makefile
├── README.md
├── deploy.sh
├── run_tests.sh
├── user.c
├── sc_throttler.h
├── sc_throttler_module.c
└── tests/
    ├── test_barrier.c
    ├── test_getpid.c
    ├── test_identity.c
    ├── test_mkdir.c
    ├── test_stress.c
    ├── test_uid.c
    └── test_wallclock.c
```

---

## Requirements

* Linux x86-64
* Kernel headers installed
* GCC
* `make`
* Root privileges for loading / unloading the module
* A kernel configuration that supports Ftrace

Typical packages needed on Debian/Ubuntu:
```bash
sudo apt install build-essential linux-headers-$(uname -r)
```

---

## Build

Compile the kernel module, the CLI, and all user-space tests:
```bash
make
```

Clean build artifacts:
```bash
make clean
```

---

## Deployment

To compile, remove any old instance, insert the module, and start the CLI:
```bash
sudo ./deploy.sh
```

This script:
1. Runs `make clean && make`
2. Removes any old `sc_throttler` instance
3. Inserts the new module
4. Prints recent kernel logs
5. Starts the manual CLI

---

## Manual CLI

The project includes a simple user-space CLI:
```bash
sudo ./user_cli
```

**Available operations:**
1. Add rule
2. Remove rule
3. Set max throughput
4. Enable / disable monitor
5. Get statistics
6. List registered rules

### Rule Types
* Syscall Number
* Effective User-ID (EUID)
* Program Name

---

## Example Manual Demo

### Example 1 — Program-name filtering
Start the CLI:
```bash
sudo ./user_cli
```
Set:
* Monitor ON
* MAX = 5
* Syscall 39 (`getpid`)
* Program name `evil_app`

Then run:
```bash
./test_identity good_app
./test_identity evil_app
```
**Expected behavior:**
* `good_app` → not throttled
* `evil_app` → throttled

### Example 2 — EUID filtering
Start the CLI and register:
* Monitor ON
* MAX = 5
* Syscall 83 (`mkdir`)
* Target EUID

Then run:
```bash
su throttleuser -c "./test_uid"
./test_uid
```
**Expected behavior:**
* matching EUID → throttled
* root / non-matching EUID → not throttled

---

## Automated Test Suite

Run the automated test suite:
```bash
sudo ./run_tests.sh
```
The test suite provides a menu with the following demonstrations:
1. Security (root permissions / IOCTL protection)
2. Program-name filtering
3. Effective user-ID filtering
4. Wall-clock reset behavior
5. Extreme concurrency with synchronized thread bursts
6. Statistics and kernel logs
7. Hot removal / anti-UAF teardown

---

## User-Space Test Programs

* **`test_identity`**: Changes the process name using `prctl(PR_SET_NAME, ...)` and repeatedly invokes syscall 39 (`getpid`). Used to demonstrate program-name based filtering.
* **`test_uid`**: Repeatedly invokes syscall 83 (`mkdir`) and prints both RUID and EUID. Used to demonstrate effective user-ID based filtering.
* **`test_wallclock`**: Validates that the (`MAX` + 1)-th call is delayed until the current 1-second window expires.
* **`test_barrier`**: Spawns multiple threads synchronized through `pthread_barrier_wait()` to simulate a highly concurrent burst.
* **`test_getpid`, `test_mkdir`, `test_stress`**: Additional workload generators used for manual or stress testing.

---

## IOCTL Interface

The kernel module exposes a character device at `/dev/sc_throttler`.
The main IOCTL commands are:

* `IOCTL_ADD_RULE`
* `IOCTL_DEL_RULE`
* `IOCTL_SET_MAX`
* `IOCTL_SET_ONOFF`
* `IOCTL_GET_STATS`
* `IOCTL_LIST_RULES`

*Note: Only a process running with effective user-ID 0 (root) may modify the configuration.*

---

## Statistics Provided

The module can report:
* Total blocked calls
* Average blocked calls per second
* Peak blocked window
* Peak delay
* EUID associated with the peak delay
* Program name associated with the peak delay

---

## Important Notes

### Effective User-ID vs Real User-ID
The specification explicitly refers to *effective* user-ID, not real user-ID. Therefore, the kernel module matches registered user rules against `current_euid()` and not `current_uid()`.

### Program Name Semantics
Program-name matching is implemented against `current->comm`, which is the task command name maintained by the kernel.

### Wall-Clock Interpretation
The 1-second enforcement interval is implemented using `jiffies`, providing an efficient kernel-level approximation of a wall-clock window.

---

## Known Limitations

* Program names are limited by `TASK_COMM_LEN` (typically 16 bytes including terminator).
* The implementation is designed for x86-64 syscall numbering.
* The throttling window is based on `jiffies`, not high-resolution timers.
* Some syscall choices are unsafe for live demonstrations on a desktop if applied to broad identities (e.g., your primary user session).

---

## Recommended Demo Strategy

For a stable presentation:
* Prefer **program-name filtering** for live demos.
* Use a dedicated user such as `throttleuser` for EUID-based tests.
* Avoid broad throttling on your main desktop user.
* Use `timeout` when launching long-running tests, e.g.:
  ```bash
  timeout 5s ./test_identity evil_app
  timeout 5s su throttleuser -c "./test_uid"
  ```

---

## Author
Angelo Romano

## License
GPL
```