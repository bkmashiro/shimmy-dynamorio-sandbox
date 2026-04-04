# Proto-D: DynamoRIO Syscall Interception Sandbox

This prototype demonstrates syscall interception using [DynamoRIO](https://dynamorio.org/),
a runtime code manipulation framework that works via **dynamic binary instrumentation (DBI)**.

## Why DynamoRIO Doesn't Need ptrace

### Traditional ptrace-based sandboxing

Tools like seccomp-bpf, strace, and many sandbox implementations rely on `ptrace` or kernel-level
syscall filtering. In containerized environments (AWS Lambda, Firecracker), `ptrace` is typically
**unavailable** because:

- Lambda functions run without `CAP_SYS_PTRACE` capability
- Nested ptrace (tracing inside a traced process) is blocked by the kernel
- Container runtimes like runc strip dangerous capabilities by default

### How DynamoRIO Works (No ptrace Required)

DynamoRIO operates as a **Dynamic Binary Instrumentation (DBI) engine**:

```
Application binary
      │
      ▼
DynamoRIO JIT compiler (in-process)
      │  ├── Decodes basic blocks of application code
      │  ├── Instruments each basic block (inserts callbacks)
      │  └── Emits new native code to a "code cache"
      ▼
Modified code executes natively
      │  └── Syscall instructions trigger pre/post callbacks
      ▼
syscall_filter.so (our client)
      │  ├── pre_syscall: check allowlist
      │  ├── ALLOWED → return true (syscall executes)
      └── BLOCKED → set result=-EPERM, return false (syscall skipped)
```

**Key insight**: DynamoRIO loads into the application process as a shared library (similar to
`LD_PRELOAD`) and intercepts syscalls by rewriting the `syscall` instruction's surrounding code.
No kernel cooperation, no ptrace, no special capabilities required.

### Injection mechanism

DynamoRIO uses `drrun` (or `libdynamorio.so` preloaded via `LD_PRELOAD`) to:

1. Set `LD_PRELOAD=libdynamorio.so` before the target process starts
2. DynamoRIO's constructor takes control before `main()`
3. All code execution goes through DynamoRIO's JIT engine
4. Every `syscall` instruction is replaced with a call into DynamoRIO's dispatcher
5. Our `event_pre_syscall` callback fires before each syscall

This is **entirely userspace** - no kernel modules, no ptrace, no special capabilities.

## Syscall Allowlist

The filter permits only these syscalls:

| Syscall | Number | Reason |
|---------|--------|--------|
| `read` | 0 | Read from fd |
| `write` | 1 | Write to fd |
| `exit` | 60 | Process exit |
| `exit_group` | 231 | Thread group exit |
| `brk` | 12 | Heap management |
| `mmap` | 9 | Memory mapping |
| `mprotect` | 10 | Memory protection |
| `munmap` | 11 | Unmap memory |
| `futex` | 202 | Thread synchronization |
| `clock_gettime` | 228 | Time queries |
| `rt_sigaction` | 13 | Signal handling |
| `rt_sigreturn` | 15 | Signal return |

All other syscalls (including `open`, `openat`, `socket`, `connect`, `execve`, etc.)
return `-EPERM` immediately without executing.

## Lambda Feasibility Analysis

### What works

DynamoRIO's LD_PRELOAD injection mode is **viable in Lambda** because:

1. **No ptrace needed**: Lambda functions can't use ptrace, but DynamoRIO doesn't need it
2. **No kernel modules**: Pure userspace DBI, no `/dev/kvm` or similar
3. **No special capabilities**: Works with standard Lambda IAM execution role
4. **Low overhead**: ~5-15% runtime overhead (much less than ptrace-based tools)
5. **Firecracker compatible**: Works inside the MicroVM that Lambda uses

### Challenges

| Challenge | Severity | Mitigation |
|-----------|----------|------------|
| Binary size | Medium | DynamoRIO adds ~20MB; use Lambda layers |
| Cold start latency | Medium | DynamoRIO JIT adds ~50-200ms startup |
| Self-modifying code | Low | DynamoRIO handles most cases |
| Static binaries | Low | DynamoRIO supports static binaries |
| Multi-threaded programs | Medium | Requires careful allowlist tuning |

### Architecture for Lambda deployment

```
Lambda function
├── /opt/dynamorio/          (Lambda layer)
│   ├── bin64/drrun
│   └── lib64/release/libdynamorio.so
├── /opt/sandbox/
│   └── syscall_filter.so    (Lambda layer)
└── handler.py               (wraps subprocess call through drrun)
```

The Lambda handler would invoke user code as:
```
drrun -c /opt/sandbox/syscall_filter.so -- /path/to/user/binary
```

### vs. seccomp-bpf

| Feature | seccomp-bpf | DynamoRIO |
|---------|-------------|-----------|
| Requires ptrace | No (kernel) | No (userspace) |
| Requires CAP_SYS_ADMIN | For filter install | No |
| Works in Lambda | Depends on runtime | Yes |
| Performance overhead | ~1% | ~5-15% |
| Granularity | Per-syscall | Per-syscall + instruction |
| Argument inspection | Limited (BPF) | Full access |
| Portability | Linux only | Linux/Windows/Mac |

DynamoRIO's main advantage over seccomp-bpf in Lambda is that it operates entirely in userspace
without requiring any kernel-level filter installation, making it suitable for environments where
you can't control the kernel security policy.

## Usage

### Build

```bash
# Build everything inside Docker
./build.sh
```

### Demo

```bash
# Run the full demonstration
./demo.sh
```

### Go wrapper

```bash
# Run an arbitrary command under DynamoRIO syscall filtering
go run ./cmd/dynamorio-sandbox/ -- ./test_open

# Dry run (see docker command without executing)
go run ./cmd/dynamorio-sandbox/ --dry-run -- /usr/bin/python3 -c "import os; os.open('/etc/passwd', 0)"
```

### Manual Docker usage

```bash
docker build -t dynamorio-sandbox-demo .
docker run --rm dynamorio-sandbox-demo bash -c \
    "cd /sandbox && make && drrun -c syscall_filter.so -- ./test_open"
```

## Expected Output

```
[syscall-filter] DynamoRIO syscall filter loaded
[syscall-filter] Allowlist: read/write/exit/exit_group/brk/mmap/mprotect/munmap/futex/clock_gettime/rt_sigaction/rt_sigreturn
test_open: attempting open("/etc/passwd", O_RDONLY)...
[syscall-filter] BLOCKED syscall 2 (open) -> EPERM
test_open: open() returned EPERM (errno=1) - correctly blocked!
```
