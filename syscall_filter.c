/* syscall_filter.c - DynamoRIO syscall virtualization client
 *
 * Policy:
 *   ALLOWED     – pass through unchanged
 *   VIRTUALIZED – intercept and replace with safe behavior
 *   BLOCKED     – return -EPERM immediately
 *
 * Session isolation: reads DR_SESSION_ID env var; all file opens are
 * remapped to /tmp/dr-sandbox/<session-id>/ and paths under
 * /proc /sys /etc /dev are rejected.
 */

#include "dr_api.h"
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/mman.h>

/* ── Linux x86-64 syscall numbers ───────────────────────────── */
#define SYS_read        0
#define SYS_write       1
#define SYS_open        2
#define SYS_close       3
#define SYS_stat        4
#define SYS_fstat       5
#define SYS_lstat       6
#define SYS_poll        7
#define SYS_lseek       8
#define SYS_mmap        9
#define SYS_mprotect    10
#define SYS_munmap      11
#define SYS_brk         12
#define SYS_rt_sigaction 13
#define SYS_rt_sigprocmask 14
#define SYS_rt_sigreturn 15
#define SYS_ioctl       16
#define SYS_pread64     17
#define SYS_pwrite64    18
#define SYS_readv       19
#define SYS_writev      20
#define SYS_access      21
#define SYS_pipe        22
#define SYS_select      23
#define SYS_sched_yield 24
#define SYS_mremap      25
#define SYS_msync       26
#define SYS_socket      41
#define SYS_connect     42
#define SYS_accept      43
#define SYS_sendto      44
#define SYS_recvfrom    45
#define SYS_sendmsg     46
#define SYS_recvmsg     47
#define SYS_shutdown    48
#define SYS_bind        49
#define SYS_listen      50
#define SYS_getsockname 51
#define SYS_getpeername 52
#define SYS_socketpair  53
#define SYS_setsockopt  54
#define SYS_getsockopt  55
#define SYS_clone       56
#define SYS_fork        57
#define SYS_vfork       58
#define SYS_execve      59
#define SYS_exit        60
#define SYS_wait4       61
#define SYS_kill        62
#define SYS_uname       63
#define SYS_fcntl       72
#define SYS_flock       73
#define SYS_fsync       74
#define SYS_fdatasync   75
#define SYS_truncate    76
#define SYS_ftruncate   77
#define SYS_getdents    78
#define SYS_getcwd      79
#define SYS_chdir       80
#define SYS_fchdir      81
#define SYS_rename      82
#define SYS_mkdir       83
#define SYS_rmdir       84
#define SYS_creat       85
#define SYS_link        86
#define SYS_unlink      87
#define SYS_symlink     88
#define SYS_readlink    89
#define SYS_chmod       90
#define SYS_fchmod      91
#define SYS_chown       92
#define SYS_fchown      93
#define SYS_lchown      94
#define SYS_umask       95
#define SYS_gettimeofday 96
#define SYS_getrlimit   97
#define SYS_getrusage   98
#define SYS_sysinfo     99
#define SYS_times       100
#define SYS_ptrace      101
#define SYS_getuid      102
#define SYS_syslog      103
#define SYS_getgid      104
#define SYS_setuid      105
#define SYS_setgid      106
#define SYS_geteuid     107
#define SYS_getegid     108
#define SYS_setpgid     109
#define SYS_getppid     110
#define SYS_getpgrp     111
#define SYS_setsid      112
#define SYS_setreuid    113
#define SYS_setregid    114
#define SYS_getgroups   115
#define SYS_setgroups   116
#define SYS_setresuid   117
#define SYS_getresuid   118
#define SYS_setresgid   119
#define SYS_getresgid   120
#define SYS_getpgid     121
#define SYS_setfsuid    122
#define SYS_setfsgid    123
#define SYS_getsid      124
#define SYS_capget      125
#define SYS_capset      126
#define SYS_rt_sigsuspend 130
#define SYS_rt_sigpending 127
#define SYS_rt_sigtimedwait 128
#define SYS_rt_sigqueueinfo 129
#define SYS_sigaltstack 131
#define SYS_utime       132
#define SYS_mknod       133
#define SYS_personality 135
#define SYS_statfs      137
#define SYS_fstatfs     138
#define SYS_sysfs       139
#define SYS_getpriority 140
#define SYS_setpriority 141
#define SYS_sched_setparam 142
#define SYS_sched_getparam 143
#define SYS_sched_setscheduler 144
#define SYS_sched_getscheduler 145
#define SYS_sched_get_priority_max 146
#define SYS_sched_get_priority_min 147
#define SYS_sched_rr_get_interval 148
#define SYS_mlock       149
#define SYS_munlock     150
#define SYS_mlockall    151
#define SYS_munlockall  152
#define SYS_vhangup     153
#define SYS_pivot_root  155
#define SYS_prctl       157
#define SYS_arch_prctl  158
#define SYS_adjtimex    159
#define SYS_setrlimit   160
#define SYS_chroot      161
#define SYS_sync        162
#define SYS_acct        163
#define SYS_settimeofday 164
#define SYS_mount       165
#define SYS_umount2     166
#define SYS_swapon      167
#define SYS_swapoff     168
#define SYS_reboot      169
#define SYS_sethostname 170
#define SYS_setdomainname 171
#define SYS_iopl        172
#define SYS_ioperm      173
#define SYS_init_module 175
#define SYS_delete_module 176
#define SYS_futex       202
#define SYS_sched_setaffinity 203
#define SYS_sched_getaffinity 204
#define SYS_io_setup    206
#define SYS_io_destroy  207
#define SYS_io_getevents 208
#define SYS_io_submit   209
#define SYS_io_cancel   210
#define SYS_lookup_dcookie 212
#define SYS_epoll_create 213
#define SYS_remap_file_pages 216
#define SYS_getdents64  217
#define SYS_set_tid_address 218
#define SYS_restart_syscall 219
#define SYS_semtimedop  220
#define SYS_fadvise64   221
#define SYS_timer_create 222
#define SYS_timer_settime 223
#define SYS_timer_gettime 224
#define SYS_timer_getoverrun 225
#define SYS_timer_delete 226
#define SYS_clock_settime 227
#define SYS_clock_gettime 228
#define SYS_clock_getres 229
#define SYS_clock_nanosleep 230
#define SYS_exit_group  231
#define SYS_epoll_wait  232
#define SYS_epoll_ctl   233
#define SYS_tgkill      234
#define SYS_utimes      235
#define SYS_mbind       237
#define SYS_set_mempolicy 238
#define SYS_get_mempolicy 239
#define SYS_mq_open     240
#define SYS_mq_unlink   241
#define SYS_mq_timedsend 242
#define SYS_mq_timedreceive 243
#define SYS_mq_notify   244
#define SYS_mq_getsetattr 245
#define SYS_kexec_load  246
#define SYS_waitid      247
#define SYS_add_key     248
#define SYS_request_key 249
#define SYS_keyctl      250
#define SYS_ioprio_set  251
#define SYS_ioprio_get  252
#define SYS_inotify_init 253
#define SYS_inotify_add_watch 254
#define SYS_inotify_rm_watch 255
#define SYS_migrate_pages 256
#define SYS_openat      257
#define SYS_mkdirat     258
#define SYS_mknodat     259
#define SYS_fchownat    260
#define SYS_futimesat   261
#define SYS_fstatat     262
#define SYS_unlinkat    263
#define SYS_renameat    264
#define SYS_linkat      265
#define SYS_symlinkat   266
#define SYS_readlinkat  267
#define SYS_fchmodat    268
#define SYS_faccessat   269
#define SYS_pselect6    270
#define SYS_ppoll       271
#define SYS_unshare     272
#define SYS_set_robust_list 273
#define SYS_get_robust_list 274
#define SYS_splice      275
#define SYS_tee         276
#define SYS_sync_file_range 277
#define SYS_vmsplice    278
#define SYS_move_pages  279
#define SYS_utimensat   280
#define SYS_epoll_pwait 281
#define SYS_signalfd    282
#define SYS_timerfd_create 283
#define SYS_eventfd     284
#define SYS_fallocate   285
#define SYS_timerfd_settime 286
#define SYS_timerfd_gettime 287
#define SYS_accept4     288
#define SYS_signalfd4   289
#define SYS_eventfd2    290
#define SYS_epoll_create1 291
#define SYS_dup3        292
#define SYS_pipe2       293
#define SYS_inotify_init1 294
#define SYS_preadv      295
#define SYS_pwritev     296
#define SYS_rt_tgsigqueueinfo 297
#define SYS_perf_event_open 298
#define SYS_recvmmsg    299
#define SYS_fanotify_init 300
#define SYS_fanotify_mark 301
#define SYS_prlimit64   302
#define SYS_name_to_handle_at 303
#define SYS_open_by_handle_at 304
#define SYS_clock_adjtime 305
#define SYS_syncfs      306
#define SYS_sendmmsg    307
#define SYS_setns       308
#define SYS_getcpu      309
#define SYS_process_vm_readv 310
#define SYS_process_vm_writev 311
#define SYS_kcmp        312
#define SYS_finit_module 313
#define SYS_sched_setattr 314
#define SYS_sched_getattr 315
#define SYS_renameat2   316
#define SYS_seccomp     317
#define SYS_getrandom   318
#define SYS_memfd_create 319
#define SYS_kexec_file_load 320
#define SYS_bpf         321
#define SYS_execveat    322
#define SYS_userfaultfd 323
#define SYS_membarrier  324
#define SYS_mlock2      325
#define SYS_copy_file_range 326
#define SYS_preadv2     327
#define SYS_pwritev2    328
#define SYS_pkey_mprotect 329
#define SYS_pkey_alloc  330
#define SYS_pkey_free   331
#define SYS_statx       332
#define SYS_io_pgetevents 333
#define SYS_rseq        334
#define SYS_pidfd_send_signal 424
#define SYS_io_uring_setup 425
#define SYS_io_uring_enter 426
#define SYS_io_uring_register 427
#define SYS_open_tree   428
#define SYS_move_mount  429
#define SYS_fsopen      430
#define SYS_fsconfig    431
#define SYS_fsmount     432
#define SYS_fspick      433
#define SYS_pidfd_open  434
#define SYS_clone3      435
#define SYS_close_range 436
#define SYS_openat2     437
#define SYS_pidfd_getfd 438
#define SYS_faccessat2  439
#define SYS_process_madvise 440
#define SYS_nanosleep   35

/* ── limits ──────────────────────────────────────────────────── */
#define MAX_PROCS       5
#define MAX_READ_BYTES  (1 * 1024 * 1024)   /* 1 MiB per read() call  */
#define SANDBOX_BASE    "/tmp/dr-sandbox/"
#define SANDBOX_BASE_LEN 16                 /* strlen(SANDBOX_BASE)    */

/* ── blocked path prefixes (checked after canonicalization) ─────── */
static const char *BLOCKED_PREFIXES[] = {
    "/proc", "/sys", "/etc", "/dev", "/run", "/boot", "/root",
    "/home", "/var", "/usr", "/lib", "/lib64", "/bin", "/sbin",
    NULL
};

/* ── specifically blocked exact paths / sub-paths ─────────────── */
static const char *BLOCKED_EXACT[] = {
    "/etc/shadow",
    "/proc/self/maps",
    "/proc/self/mem",
    NULL
};

/* ── global state ────────────────────────────────────────────── */
static char    g_session_id[64];
static char    g_sandbox_root[256];   /* /tmp/dr-sandbox/<session-id>/ */
static int     g_proc_count = 0;
static void   *g_mutex;

static file_t  g_log;                 /* DynamoRIO file handle for stderr */

/* ── logging helper ──────────────────────────────────────────── */
#define LOG(fmt, ...) \
    dr_fprintf(g_log, "[dr-sandbox][%s] " fmt "\n", g_session_id, ##__VA_ARGS__)

/* ── path canonicalization: resolve ".." components in-place ─── */
/*
 * Resolves ".." and "." components without touching the filesystem.
 * Does NOT follow symlinks (symlink escapes are prevented by path remapping).
 * Input must be an absolute path (starting with '/').
 * Result is written into out[outsz].
 */
static void canonicalize_path(const char *path, char *out, size_t outsz)
{
    /* Work with a local copy */
    char tmp[512];
    size_t plen = strlen(path);
    if (plen >= sizeof(tmp)) plen = sizeof(tmp) - 1;
    memcpy(tmp, path, plen);
    tmp[plen] = '\0';

    /* Component stack: pointers into 'out' after each '/' */
    const char *parts[128];
    int depth = 0;

    out[0] = '\0';
    char *w = out;
    char *end = out + outsz - 1;

    char *tok = tmp;
    char *next;
    /* Skip leading slash */
    while (*tok == '/') tok++;

    while (*tok) {
        /* Find end of component */
        next = tok;
        while (*next && *next != '/') next++;
        char saved = *next;
        *next = '\0';

        if (tok[0] == '\0' || (tok[0] == '.' && tok[1] == '\0')) {
            /* skip empty or "." */
        } else if (tok[0] == '.' && tok[1] == '.' && tok[2] == '\0') {
            /* go up one level */
            if (depth > 0) {
                depth--;
                /* rewind writer to the saved part pointer */
                w = (char *)parts[depth];
                *w = '\0';
            }
        } else {
            /* push component */
            if (depth < 128) parts[depth++] = w;
            if (w < end) { *w++ = '/'; }
            size_t clen = strlen(tok);
            if (w + clen > end) clen = (size_t)(end - w);
            memcpy(w, tok, clen);
            w += clen;
            *w = '\0';
        }

        *next = saved;
        tok = next;
        while (*tok == '/') tok++;
    }

    if (w == out) {
        /* root */
        out[0] = '/';
        out[1] = '\0';
    }
}

/* ── path utility: check if path starts with a blocked prefix ── */
/*
 * Canonicalizes the path first to resolve ".." traversal attempts,
 * then checks against blocked prefixes and exact blocked paths.
 */
static bool path_is_blocked(const char *path)
{
    char canonical[512];

    /* Only canonicalize absolute paths */
    if (path[0] == '/') {
        canonicalize_path(path, canonical, sizeof(canonical));
    } else {
        /* relative path — treat as-is; remap_path will anchor it */
        size_t plen = strlen(path);
        if (plen >= sizeof(canonical)) plen = sizeof(canonical) - 1;
        memcpy(canonical, path, plen);
        canonical[plen] = '\0';
    }

    /* Check exact blocked paths first */
    for (int i = 0; BLOCKED_EXACT[i]; i++) {
        if (strcmp(canonical, BLOCKED_EXACT[i]) == 0)
            return true;
    }

    /* Check blocked prefixes */
    for (int i = 0; BLOCKED_PREFIXES[i]; i++) {
        size_t plen = strlen(BLOCKED_PREFIXES[i]);
        if (strncmp(canonical, BLOCKED_PREFIXES[i], plen) == 0) {
            char c = canonical[plen];
            if (c == '\0' || c == '/')
                return true;
        }
    }
    return false;
}

/* ── path remapping: rewrite path → sandbox root ─────────────── */
static bool remap_path(const char *orig, char *out, size_t outsz)
{
    /* strip leading slashes for joining */
    const char *rel = orig;
    while (*rel == '/') rel++;

    int n = dr_snprintf(out, outsz, "%s%s", g_sandbox_root, rel);
    return (n > 0 && (size_t)n < outsz);
}

/* ── helper: read string from app memory ────────────────────── */
static bool read_app_string(void *drcontext, reg_t ptr, char *buf, size_t bufsz)
{
    size_t sofar = 0;
    while (sofar < bufsz - 1) {
        char c;
        if (!dr_safe_read((void *)(ptr + sofar), 1, &c, NULL))
            return false;
        buf[sofar++] = c;
        if (c == '\0')
            return true;
    }
    buf[sofar] = '\0';
    return true;
}

/* ══════════════════════════════════════════════════════════════
 *  PRE-SYSCALL EVENT
 * ══════════════════════════════════════════════════════════════ */
/* Ask DynamoRIO to deliver syscall callbacks for every app syscall.  Without a
 * filter event, pre/post syscall events are only delivered for syscalls DR
 * already needs to intercept internally, so policy code may appear to load but
 * never see open/openat.
 */
static bool event_filter_syscall(void *drcontext, int sysnum)
{
    (void)drcontext;
    (void)sysnum;
    return true;
}

static bool event_pre_syscall(void *drcontext, int sysnum)
{
    /* ── ALWAYS ALLOWED ──────────────────────────────────────── */
    switch (sysnum) {
        /* core I/O on already-open fds */
        case SYS_close:
        case SYS_fstat:
        case SYS_lseek:
        case SYS_fcntl:
        case SYS_flock:
        case SYS_fsync:
        case SYS_fdatasync:
        case SYS_ftruncate:
        case SYS_fallocate:
        case SYS_getdents:
        case SYS_getdents64:
        case SYS_dup3:
        case SYS_pipe2:
        /* memory management (no PROT_EXEC check here – see mmap/mprotect below) */
        case SYS_brk:
        case SYS_munmap:
        case SYS_mremap:
        case SYS_msync:
        /* signal handling */
        case SYS_rt_sigaction:
        case SYS_rt_sigprocmask:
        case SYS_rt_sigreturn:
        case SYS_rt_sigsuspend:
        case SYS_rt_sigpending:
        case SYS_sigaltstack:
        /* threading/futex */
        case SYS_futex:
        case SYS_set_tid_address:
        case SYS_set_robust_list:
        case SYS_get_robust_list:
        case SYS_tgkill:
        /* process identity (read-only) */
        case SYS_getuid:
        case SYS_geteuid:
        case SYS_getgid:
        case SYS_getegid:
        case SYS_getpgrp:
        case SYS_getpgid:
        case SYS_getsid:
        case SYS_getppid:
        case SYS_getresuid:
        case SYS_getresgid:
        case SYS_getcwd:
        /* time */
        case SYS_clock_gettime:
        case SYS_clock_getres:
        case SYS_clock_nanosleep:
        case SYS_nanosleep:
        case SYS_gettimeofday:
        /* misc safe */
        case SYS_uname:
        case SYS_getrandom:
        case SYS_sched_yield:
        case SYS_sched_getaffinity:
        case SYS_sched_getparam:
        case SYS_sched_getscheduler:
        case SYS_sched_get_priority_max:
        case SYS_sched_get_priority_min:
        case SYS_getrlimit:
        case SYS_getrusage:
        case SYS_arch_prctl:
        case SYS_prctl:
        case SYS_prlimit64:
        case SYS_rseq:
        case SYS_membarrier:
        case SYS_restart_syscall:
        /* exit */
        case SYS_exit:
        case SYS_exit_group:
            return true;   /* allow */
    }

    /* ── VIRTUALIZED ─────────────────────────────────────────── */

    /* --- open / openat: path remapping ----------------------- */
    if (sysnum == SYS_open || sysnum == SYS_openat || sysnum == SYS_creat) {
        reg_t path_arg;
        if (sysnum == SYS_openat)
            path_arg = dr_syscall_get_param(drcontext, 1);  /* dirfd, path, flags */
        else
            path_arg = dr_syscall_get_param(drcontext, 0);  /* path, flags */

        char orig[512];
        if (!read_app_string(drcontext, path_arg, orig, sizeof(orig))) {
            dr_syscall_set_result(drcontext, -EPERM);
            return false;
        }

        /* reject blocked prefixes; use ENOENT for shadow to avoid leaking existence */
        if (path_is_blocked(orig)) {
            LOG("BLOCK open: %s", orig);
            /* /etc/shadow: return ENOENT to avoid leaking that the file exists */
            if (strncmp(orig, "/etc/shadow", 11) == 0 &&
                    (orig[11] == '\0' || orig[11] == '/')) {
                dr_syscall_set_result(drcontext, -ENOENT);
            } else {
                dr_syscall_set_result(drcontext, -EPERM);
            }
            return false;
        }

        /* remap into sandbox root */
        char remapped[512];
        if (!remap_path(orig, remapped, sizeof(remapped))) {
            dr_syscall_set_result(drcontext, -EPERM);
            return false;
        }
        LOG("REMAP open: %s -> %s", orig, remapped);

        /* write remapped string back into app memory in-place if it fits,
         * otherwise just log and allow the remapped path.
         * DynamoRIO doesn't give us a good way to allocate new strings in the
         * app address space portably, so we use dr_write_memory. */
        if (strlen(remapped) <= strlen(orig)) {
            /* fits: overwrite in place */
            dr_safe_write((void *)(uintptr_t)path_arg, strlen(remapped) + 1,
                          remapped, NULL);
        } else {
            /* allocate a new page via DynamoRIO heap and patch the register */
            void *newbuf = dr_global_alloc(512);
            if (newbuf) {
                memcpy(newbuf, remapped, strlen(remapped) + 1);
                if (sysnum == SYS_openat)
                    dr_syscall_set_param(drcontext, 1, (reg_t)(uintptr_t)newbuf);
                else
                    dr_syscall_set_param(drcontext, 0, (reg_t)(uintptr_t)newbuf);
                /* Note: we intentionally leak this; it's a prototype */
            } else {
                dr_syscall_set_result(drcontext, -ENOMEM);
                return false;
            }
        }
        return true;
    }

    /* --- write: only fd 1 (stdout) and fd 2 (stderr) --------- */
    if (sysnum == SYS_write || sysnum == SYS_writev || sysnum == SYS_pwrite64) {
        reg_t fd = dr_syscall_get_param(drcontext, 0);
        if (fd != 1 && fd != 2) {
            LOG("BLOCK write: fd=%ld", (long)fd);
            dr_syscall_set_result(drcontext, -EPERM);
            return false;
        }
        return true;
    }

    /* --- read: allow but cap at MAX_READ_BYTES --------------- */
    if (sysnum == SYS_read || sysnum == SYS_pread64) {
        reg_t count = dr_syscall_get_param(drcontext, 2);
        if (count > MAX_READ_BYTES) {
            LOG("CAP read: %ld -> %d", (long)count, MAX_READ_BYTES);
            dr_syscall_set_param(drcontext, 2, MAX_READ_BYTES);
        }
        return true;
    }

    /* --- mmap: block PROT_EXEC ------------------------------- */
    if (sysnum == SYS_mmap) {
        reg_t prot = dr_syscall_get_param(drcontext, 2);
        if (prot & PROT_EXEC) {
            LOG("WARN mmap PROT_EXEC requested (prot=0x%lx) - BLOCKED", (long)prot);
            dr_syscall_set_result(drcontext, -EPERM);
            return false;
        }
        return true;
    }

    /* --- mprotect: block PROT_EXEC --------------------------- */
    if (sysnum == SYS_mprotect) {
        reg_t prot = dr_syscall_get_param(drcontext, 2);
        if (prot & PROT_EXEC) {
            LOG("WARN mprotect PROT_EXEC requested (prot=0x%lx) - BLOCKED", (long)prot);
            dr_syscall_set_result(drcontext, -EPERM);
            return false;
        }
        return true;
    }

    /* --- socket / connect / bind / listen / accept ----------- */
    switch (sysnum) {
        case SYS_socket:
        case SYS_connect:
        case SYS_bind:
        case SYS_listen:
        case SYS_accept:
        case SYS_accept4:
        case SYS_sendto:
        case SYS_recvfrom:
        case SYS_sendmsg:
        case SYS_recvmsg:
        case SYS_sendmmsg:
        case SYS_recvmmsg:
        case SYS_shutdown:
        case SYS_getsockname:
        case SYS_getpeername:
        case SYS_socketpair:
        case SYS_setsockopt:
        case SYS_getsockopt:
            LOG("BLOCK network syscall %d", sysnum);
            dr_syscall_set_result(drcontext, -ENETDOWN);
            return false;
    }

    /* --- execve / execveat ----------------------------------- */
    if (sysnum == SYS_execve || sysnum == SYS_execveat) {
        LOG("BLOCK execve");
        dr_syscall_set_result(drcontext, -EPERM);
        return false;
    }

    /* --- fork / clone (new process) -------------------------- */
    if (sysnum == SYS_fork || sysnum == SYS_vfork) {
        dr_mutex_lock(g_mutex);
        int cnt = ++g_proc_count;
        dr_mutex_unlock(g_mutex);
        if (cnt > MAX_PROCS) {
            LOG("BLOCK fork: proc limit %d exceeded", MAX_PROCS);
            dr_syscall_set_result(drcontext, -EAGAIN);
            return false;
        }
        LOG("ALLOW fork (%d/%d)", cnt, MAX_PROCS);
        return true;
    }

    if (sysnum == SYS_clone || sysnum == SYS_clone3) {
        /* clone with CLONE_VM but not CLONE_THREAD = new process */
        reg_t flags = dr_syscall_get_param(drcontext, 0);
        bool new_proc = !(flags & 0x00010000 /*CLONE_THREAD*/);
        if (new_proc) {
            dr_mutex_lock(g_mutex);
            int cnt = ++g_proc_count;
            dr_mutex_unlock(g_mutex);
            if (cnt > MAX_PROCS) {
                LOG("BLOCK clone(new-proc): proc limit %d exceeded", MAX_PROCS);
                dr_syscall_set_result(drcontext, -EAGAIN);
                return false;
            }
            LOG("ALLOW clone(new-proc) (%d/%d)", cnt, MAX_PROCS);
        }
        return true;
    }

    /* ── BLOCKED (everything else) ───────────────────────────── */
    LOG("BLOCK syscall %d", sysnum);
    dr_syscall_set_result(drcontext, -EPERM);
    return false;
}

/* ── client init ─────────────────────────────────────────────── */
DR_EXPORT void dr_client_main(client_id_t id, int argc, const char *argv[])
{
    dr_set_client_name("syscall-virtualization-filter",
                       "https://github.com/example/shimmy");

    g_log = STDERR;

    /* read or generate session id */
    const char *env_sid = getenv("DR_SESSION_ID");
    if (env_sid && *env_sid) {
        strncpy(g_session_id, env_sid, sizeof(g_session_id) - 1);
    } else {
        /* generate from PID + timestamp */
        uint64 ts = dr_get_milliseconds();
        dr_snprintf(g_session_id, sizeof(g_session_id),
                    "%u-%llu", dr_get_process_id(), (unsigned long long)ts);
    }
    dr_snprintf(g_sandbox_root, sizeof(g_sandbox_root),
                "%s%s/", SANDBOX_BASE, g_session_id);

    /* create sandbox directory */
    if (!dr_create_dir(SANDBOX_BASE))
        ; /* may already exist */
    if (!dr_create_dir(g_sandbox_root))
        ; /* may already exist */

    g_mutex = dr_mutex_create();

    dr_register_filter_syscall_event(event_filter_syscall);
    dr_register_pre_syscall_event(event_pre_syscall);

    LOG("syscall virtualization active - sandbox: %s", g_sandbox_root);
}
