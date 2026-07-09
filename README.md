# proto-d: DynamoRIO Syscall Virtualization

A prototype sandbox using [DynamoRIO](https://dynamorio.org/) for **syscall virtualization** — not just allow/block, but intercepting syscalls and replacing them with safe, controlled behavior.

## Current Docker-first Wolfram direction

For Wolfram/LambdaFeedback-style work, use Docker/regular container runtime as the primary target. AWS Lambda is only a side/negative target unless the explicit goal is a Wolfram-on-Lambda port.

This prototype now supports two runtime modes:

| Env | Behavior |
|---|---|
| `DR_SANDBOX_MODE=observe` | Compatibility-first: log syscalls, pass most through, and redirect private writable temp/cache paths when enabled. This is the default for complex runtimes such as Wolfram. |
| `DR_SANDBOX_MODE=strict` / `enforce` | Original deny-by-default sandbox policy. Useful as a canary, too restrictive for Wolfram first-pass integration. |
| `DR_REDIRECT_TMP=1` | Redirect write/create opens under `/tmp`, `/var/tmp`, `/.Wolfram`, and `/.cache` into `/tmp/dr-sandbox/<session-id>/...`, except rendezvous/shared-memory paths such as `/tmp/MathLink` and `/dev/shm`. |
| `DR_AUDIT_JSONL=1` | Emit machine-readable JSONL audit records for observed/remapped path/syscall events. |
| `DR_AUDIT_PATH=/tmp/dr-audit.jsonl` | Write JSONL audit to a separate append-only file instead of stderr, avoiding corrupted/interleaved audit when Wolfram child processes also write stderr. |
| `DR_HUMAN_LOG=0` | Disable human-readable `[dr-sandbox]` logs; useful when collecting clean audit files. |
| `DR_PATH_POLICY='ro:/data/ref;rw:/tmp/shared;private:/tmp/work;block:/secrets'` | Optional first-match path policy. Actions: `ro`/`readonly` allows reads but blocks write-intent opens and mutating path ops; `rw`/`pass` leaves the path shared; `private` remaps into `/tmp/dr-sandbox/<session-id>/...`; `block` denies access. Rules are separated by `;` or `,`. |
| `DR_NETWORK=allow|block` | Override network syscall policy. Strict mode defaults to `block`; observe mode defaults to `allow`. |
| `DR_EXEC=allow|block` | Override `execve`/`execveat` policy. Strict mode defaults to `block`; observe mode defaults to `allow`. |
| `DR_PROT_EXEC=allow|block` | Override executable memory (`mmap`/`mprotect` with `PROT_EXEC`). Strict defaults to `block`; observe defaults to `allow`. |
| `DR_FILE_WRITE=allow|block` | Override fd-write policy. `block` means only stdout/stderr writes are allowed; strict defaults to this. |
| `DR_MAX_READ_BYTES=1m` | Cap bytes per `read`/`pread64` syscall; default is `1 MiB`. |
| `DR_MAX_PROCS=5` | In-client fork/clone process limit; pair with Docker `--pids-limit` for kernel-level enforcement. |

Use observe mode first, then derive a narrower enforce profile from logs. Do not start by blocking everything: Wolfram may legitimately write license/cache/paclet/temp files.

See `docker-first-wolfram-dynamorio-roadmap-20260709.md` for the current scope and verified CodeBuild smoke.

## Architecture

```
┌─────────────────────────────────────────────────────┐
│  Docker container  (--network=none, --cap-drop ALL) │
│                                                     │
│  drrun  ──── JIT recompiles app ────────────────┐   │
│              inserting pre-syscall hooks         │   │
│                                                  ▼   │
│              syscall_filter.so                       │
│              ├── ALLOWED    → pass through           │
│              ├── VIRTUALIZED→ rewrite args / result  │
│              └── BLOCKED    → return -EPERM          │
│                                                     │
│  /tmp/dr-sandbox/<session-id>/   (isolated rootfs)  │
└─────────────────────────────────────────────────────┘
```

DynamoRIO operates **entirely in userspace** via JIT code rewriting — no `ptrace`, no kernel modules, no `CAP_SYS_PTRACE`. It intercepts every syscall instruction before it reaches the kernel.

## Syscall Policy

### ALLOWED (pass-through)

| Syscall(s) | Reason |
|---|---|
| `read` | Basic I/O; capped at 1 MiB per call |
| `exit`, `exit_group` | Must be allowed to terminate |
| `brk`, `munmap`, `mremap` | Heap/memory management |
| `futex` | Mutex/condvar for threading |
| `clock_gettime`, `nanosleep` | Timing; no security risk |
| `rt_sigaction`, `rt_sigreturn` | Signal handling |
| `getpid`, `gettid` | Process identity (read-only) |
| `getrandom` | Secure entropy; no side-channel risk |
| `arch_prctl`, `prctl` | Stack/thread control; no privilege escalation |
| `close`, `fstat`, `fcntl`, … | Operations on already-open fds |

### VIRTUALIZED (intercepted and replaced)

| Syscall | Behavior | Security Reason |
|---|---|---|
| `open`, `openat`, `creat` | Path remapped to `/tmp/dr-sandbox/<session>/`; `/proc`, `/sys`, `/etc`, `/dev`, `/home`, … rejected with EPERM | Prevents host filesystem exfiltration and credential access |
| `write`, `writev` | Only `fd 1` (stdout) and `fd 2` (stderr) allowed; others → EPERM | Prevents writing to sockets, pipes, or other processes' files |
| `read`, `pread64` | Allowed but capped at **1 MiB per call** | Prevents I/O amplification and DoS via huge reads |
| `socket`, `connect`, `bind`, `listen`, … | Return `-ENETDOWN` | No network access; isolation from C2, exfiltration |
| `execve`, `execveat` | Return `-EPERM` | No exec chain; sandbox cannot spawn unsandboxed children |
| `fork`, `vfork`, `clone` (new process) | Counted; return `-EAGAIN` after **5 processes** | Prevents fork bombs and resource exhaustion |
| `mmap(PROT_EXEC)` | Return `-EPERM` | Blocks JIT compilers and shellcode injection |
| `mprotect(PROT_EXEC)` | Return `-EPERM` | Blocks RWX page tricks used in exploitation |

### BLOCKED (everything else → `-EPERM`)

All syscalls not explicitly listed above are blocked. This includes:
- `ptrace` (would escape the sandbox)
- `mount`, `chroot`, `pivot_root` (namespace manipulation)
- `setuid`, `setgid`, `capset` (privilege escalation)
- `kexec_load`, `init_module` (kernel code execution)
- `bpf` (eBPF program loading)
- `io_uring_*` (async I/O that bypasses filter)

## Session Management

Each sandbox run gets a unique **session ID** (auto-generated from PID + random bytes, or supplied via `DR_SESSION_ID`):

```
/tmp/dr-sandbox/
└── <session-id>/        ← isolated directory for this run
    ├── <any files the sandboxed program creates>
```

The Go wrapper auto-generates the session ID; pass `--session` to fix it for reproducible tests.

**Cleanup**: the container is run with `--rm`, so all files inside the container (including `/tmp/dr-sandbox/<session-id>/`) are destroyed on exit.

## Quick Start

```bash
# Build image
make docker-build

# Run the demo (strict mode: test_open tries to open /etc/passwd)
make demo

# Verify observe-mode private tmp redirection on native x86_64/CodeBuild
make smoke-private-tmp

# Verify JSONL audit output on native x86_64/CodeBuild
make smoke-audit-jsonl

# Verify Wolfram-style rendezvous paths stay shared while normal /tmp stays private
make smoke-wolfram-path-policy

# Verify configurable path policies: read-only, read-write/shared, private/remapped, blocked
make smoke-policy-config

# Verify configurable runtime controls: read cap, network block, executable-memory block
make smoke-runtime-config

# Verify a real dynamic /bin/bash process can run through observe mode
make smoke-dynamic-shell

# Run an arbitrary program in observe mode
make docker-run EXEC=/bin/ls EXEC_ARGS="/tmp"

# Run an arbitrary program in strict/enforce mode
make docker-run DR_MODE=strict EXEC=/bin/ls EXEC_ARGS="/tmp"

# Use the Go wrapper
go run ./cmd/dynamorio-sandbox --exec /bin/ls --args "/tmp" --timeout 10s
```

## Go Wrapper

```
dynamorio-sandbox [flags]

  --exec      string    Program to run (required)
  --args      string    Space-separated arguments
  --timeout   duration  Max execution time (default 30s)
  --max-mem   string    Memory limit (default 256m)
  --max-procs int       Docker pids-limit (default 5)
  --mode      string    DR mode: observe or strict (default observe)
  --path-policy string  DR_PATH_POLICY rules, e.g. ro:/data;private:/tmp/work;block:/secrets
  --network-policy string    Network policy override: allow or block
  --exec-policy string       execve policy override: allow or block
  --prot-exec-policy string  Executable-memory policy override: allow or block
  --file-write-policy string fd write policy override: allow or block/stdio
  --max-read-bytes string    Per-read cap, e.g. 1m or 4096
  --dr-max-procs int         In-client fork/clone limit
  --image     string    Docker image (default dynamorio-sandbox)
  --session   string    Session ID (auto-generated)
  --dry-run             Print docker command, don't run
```

## Comparison with seccomp-bpf

| Feature | seccomp-bpf | DynamoRIO |
|---|---|---|
| Kernel required | Yes (Linux 3.5+) | No |
| Argument inspection | Partial (BPF can read args) | Full (arbitrary C logic) |
| Argument rewriting | No | Yes |
| Path remapping | No | Yes |
| Return value spoofing | No | Yes |
| Userspace only | No | Yes |
| Lambda/Fargate compatible | With permissions | Yes |

DynamoRIO's main advantage is **argument rewriting** — we can transparently redirect file paths into the sandbox directory without the application knowing. seccomp can only observe, not mutate.

## Limitations (Prototype)

- Path remapping patches app memory in-place; if the remapped path is longer than the original, we allocate via DynamoRIO's heap and patch the register (and leak it — acceptable for a prototype).
- `io_uring` is blocked because it bypasses the pre-syscall hook mechanism.
- `fork` counting uses a simple integer; in a multi-threaded app, the mutex makes it correct but non-atomic with the kernel's actual process creation.
