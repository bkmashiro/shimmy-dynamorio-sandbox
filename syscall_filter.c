/*
 * DynamoRIO Syscall Filter Client
 *
 * Intercepts all syscalls and enforces an allowlist.
 * Blocked syscalls return EPERM without executing.
 *
 * This works in DynamoRIO's "LD_PRELOAD-like" injection mode,
 * which does NOT require ptrace - it rewrites the application's
 * code at runtime using dynamic binary instrumentation (DBI).
 */

/* DynamoRIO headers - available at compile time inside Docker (/opt/dynamorio/include/).
 * clangd on the host will report "file not found" since the headers live only in the
 * container; the actual build (make / build.sh) works correctly. */
#include "dr_api.h"   /* NOLINT(build/include) */
#include "drsyms.h"   /* NOLINT(build/include) */
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

/* Linux x86_64 syscall numbers */
#define SYS_READ            0
#define SYS_WRITE           1
#define SYS_OPEN            2
#define SYS_CLOSE           3
#define SYS_OPENAT          257
#define SYS_BRK             12
#define SYS_MMAP            9
#define SYS_MPROTECT        10
#define SYS_MUNMAP          11
#define SYS_FUTEX           202
#define SYS_CLOCK_GETTIME   228
#define SYS_RT_SIGACTION    13
#define SYS_RT_SIGRETURN    15
#define SYS_EXIT            60
#define SYS_EXIT_GROUP      231
#define SYS_ARCH_PRCTL      158
#define SYS_SET_TID_ADDRESS 218
#define SYS_SET_ROBUST_LIST 273
#define SYS_PRLIMIT64       302
#define SYS_GETRANDOM       318
#define SYS_RSEQ            334

#define EPERM 1

/* Allowlisted syscalls - these are permitted to execute */
static const int ALLOWED_SYSCALLS[] = {
    SYS_READ,
    SYS_WRITE,
    SYS_EXIT,
    SYS_EXIT_GROUP,
    SYS_BRK,
    SYS_MMAP,
    SYS_MPROTECT,
    SYS_MUNMAP,
    SYS_FUTEX,
    SYS_CLOCK_GETTIME,
    SYS_RT_SIGACTION,
    SYS_RT_SIGRETURN,
    /* Additional syscalls needed for basic program startup */
    SYS_ARCH_PRCTL,
    SYS_SET_TID_ADDRESS,
    SYS_SET_ROBUST_LIST,
    SYS_PRLIMIT64,
    SYS_GETRANDOM,
    SYS_RSEQ,
    SYS_CLOSE,      /* Allow close for fd cleanup */
};

static const int NUM_ALLOWED = sizeof(ALLOWED_SYSCALLS) / sizeof(ALLOWED_SYSCALLS[0]);

/* Syscall name lookup for logging */
static const char *
syscall_name(int sysnum)
{
    switch (sysnum) {
    case 0:   return "read";
    case 1:   return "write";
    case 2:   return "open";
    case 3:   return "close";
    case 4:   return "stat";
    case 5:   return "fstat";
    case 6:   return "lstat";
    case 7:   return "poll";
    case 8:   return "lseek";
    case 9:   return "mmap";
    case 10:  return "mprotect";
    case 11:  return "munmap";
    case 12:  return "brk";
    case 13:  return "rt_sigaction";
    case 14:  return "rt_sigprocmask";
    case 15:  return "rt_sigreturn";
    case 20:  return "writev";
    case 21:  return "access";
    case 39:  return "getpid";
    case 56:  return "clone";
    case 57:  return "fork";
    case 58:  return "vfork";
    case 59:  return "execve";
    case 60:  return "exit";
    case 61:  return "wait4";
    case 62:  return "kill";
    case 158: return "arch_prctl";
    case 202: return "futex";
    case 218: return "set_tid_address";
    case 228: return "clock_gettime";
    case 231: return "exit_group";
    case 257: return "openat";
    case 273: return "set_robust_list";
    case 302: return "prlimit64";
    case 318: return "getrandom";
    case 334: return "rseq";
    default:  return "unknown";
    }
}

static bool
is_allowed(int sysnum)
{
    for (int i = 0; i < NUM_ALLOWED; i++) {
        if (ALLOWED_SYSCALLS[i] == sysnum)
            return true;
    }
    return false;
}

/* pre_syscall event handler - called before every syscall */
static bool
event_pre_syscall(void *drcontext, int sysnum)
{
    if (is_allowed(sysnum)) {
        /* Permitted: let it execute */
        return true;
    }

    /* Blocked syscall: print warning and deny */
    dr_fprintf(STDERR,
        "[syscall-filter] BLOCKED syscall %d (%s) -> EPERM\n",
        sysnum, syscall_name(sysnum));

    /* Set return value to -EPERM */
    dr_syscall_set_result(drcontext, (uintptr_t)(-(intptr_t)EPERM));

    /* Return false = skip the actual syscall execution */
    return false;
}

DR_EXPORT void
dr_client_main(client_id_t id, int argc, const char *argv[])
{
    dr_set_client_name("syscall-filter", "https://github.com/example/shimmy");

    /* Register pre-syscall event */
    dr_register_pre_syscall_event(event_pre_syscall);

    dr_fprintf(STDERR, "[syscall-filter] DynamoRIO syscall filter loaded\n");
    dr_fprintf(STDERR, "[syscall-filter] Allowlist: read/write/exit/exit_group/brk/mmap/mprotect/munmap/futex/clock_gettime/rt_sigaction/rt_sigreturn\n");
}
