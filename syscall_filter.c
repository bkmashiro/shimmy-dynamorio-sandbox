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
#include <stdint.h>
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
#define SYS_dup         32
#define SYS_dup2        33
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

/* ── runtime mode ────────────────────────────────────────────── */
typedef enum {
    MODE_OBSERVE = 0,  /* log/interpose only selected virtualized paths; otherwise pass through */
    MODE_STRICT  = 1,  /* original deny-by-default sandbox policy */
} sandbox_mode_t;

typedef enum {
    PATH_POLICY_DEFAULT = 0,
    PATH_POLICY_PASS,
    PATH_POLICY_READONLY,
    PATH_POLICY_PRIVATE,
    PATH_POLICY_BLOCK,
} path_policy_action_t;

typedef struct {
    path_policy_action_t action;
    char prefix[256];
} path_policy_rule_t;

typedef struct {
    bool in_use;
    bool block_write;
    char path[512];
} fd_shadow_t;

typedef struct {
    bool block;
    bool any_ip;
    char ip[64];
    int port; /* -1 = any */
} network_policy_rule_t;

/* ── global state ────────────────────────────────────────────── */
static char           g_session_id[64];
static char           g_sandbox_root[256];   /* /tmp/dr-sandbox/<session-id>/ */
static sandbox_mode_t g_mode = MODE_OBSERVE;
static bool           g_redirect_tmp = true;
static bool           g_audit_jsonl = false;
static bool           g_semantic_audit = false;
static bool           g_human_log = true;
static size_t         g_max_read_bytes = MAX_READ_BYTES;
static size_t         g_max_alloc_bytes = 0; /* 0 = unlimited; DR-only mmap/brk budget */
static size_t         g_alloc_bytes = 0;
static reg_t          g_initial_brk = 0;
static reg_t          g_current_brk = 0;
static int            g_max_procs = MAX_PROCS;
static bool           g_block_network = false;
static bool           g_block_exec = false;
static bool           g_block_prot_exec = false;
static bool           g_stdio_only_writes = false;
static size_t         g_max_stdout_bytes = 0; /* 0 = unlimited */
static size_t         g_max_stderr_bytes = 0; /* 0 = unlimited */
static size_t         g_stdout_bytes = 0;
static size_t         g_stderr_bytes = 0;
static bool           g_output_truncate = false;
static uint64         g_start_ms = 0;
static uint64         g_max_cpu_ms = 0; /* syscall-active wall/CPU-ish budget; 0 = unlimited */
static int            g_proc_count = 0;
static void          *g_mutex;
static path_policy_rule_t g_path_rules[32];
static int            g_path_rule_count = 0;
static path_policy_rule_t g_fd_write_rules[32];
static int            g_fd_write_rule_count = 0;
static fd_shadow_t    g_fd_shadow[1024];
static bool           g_pending_open;
static bool           g_pending_open_block_write;
static char           g_pending_open_path[512];
static network_policy_rule_t g_network_rules[32];
static int            g_network_rule_count = 0;
static int            g_last_sysnum;
static size_t         g_last_mmap_len;
static size_t         g_last_mremap_old_len;
static size_t         g_last_mremap_new_len;
static size_t         g_last_munmap_len;
static bool           g_pending_dup;
static int            g_pending_dup_src;
static int            g_pending_dup_dst;
static bool           g_pending_dup_has_dst;

static file_t         g_log;                 /* human log handle, stderr by default */
static file_t         g_audit_log;           /* JSONL audit handle, stderr unless DR_AUDIT_PATH is set */

/* ── logging helper ──────────────────────────────────────────── */
#define LOG(fmt, ...) do { \
    if (g_human_log) \
        dr_fprintf(g_log, "[dr-sandbox][%s] " fmt "\n", g_session_id, ##__VA_ARGS__); \
} while (0)

static void audit_append_raw(char **p, char *end, const char *s)
{
    while (*s && *p < end)
        *(*p)++ = *s++;
}

static void audit_append_json_string(char **p, char *end, const char *s)
{
    if (*p < end) *(*p)++ = '"';
    for (const unsigned char *q = (const unsigned char *)s; q && *q && *p < end; q++) {
        unsigned char c = *q;
        switch (c) {
            case '\\': audit_append_raw(p, end, "\\\\"); break;
            case '"':  audit_append_raw(p, end, "\\\""); break;
            case '\n': audit_append_raw(p, end, "\\n"); break;
            case '\r': audit_append_raw(p, end, "\\r"); break;
            case '\t': audit_append_raw(p, end, "\\t"); break;
            default:
                if (c < 0x20) {
                    char esc[8];
                    dr_snprintf(esc, sizeof(esc), "\\u%04x", c);
                    audit_append_raw(p, end, esc);
                } else {
                    *(*p)++ = (char)c;
                }
        }
    }
    if (*p < end) *(*p)++ = '"';
}

static void audit_write_line(const char *line)
{
    dr_write_file(g_audit_log, line, strlen(line));
}

static void audit_path_event(const char *action, int sysnum, const char *label,
                             const char *path, const char *remapped)
{
    if (!g_audit_jsonl)
        return;
    char line[2048];
    char *p = line;
    char *end = line + sizeof(line) - 2;
    audit_append_raw(&p, end, "{\"type\":\"path\",\"session\":");
    audit_append_json_string(&p, end, g_session_id);
    p += dr_snprintf(p, (size_t)(end - p), ",\"mode\":\"%s\",\"action\":",
                     g_mode == MODE_STRICT ? "strict" : "observe");
    audit_append_json_string(&p, end, action);
    p += dr_snprintf(p, (size_t)(end - p), ",\"syscall\":%d,\"label\":", sysnum);
    audit_append_json_string(&p, end, label);
    audit_append_raw(&p, end, ",\"path\":");
    audit_append_json_string(&p, end, path);
    if (remapped && *remapped) {
        audit_append_raw(&p, end, ",\"remapped\":");
        audit_append_json_string(&p, end, remapped);
    }
    audit_append_raw(&p, end, "}\n");
    *p = '\0';
    audit_write_line(line);
}

static void audit_syscall_event(const char *action, int sysnum)
{
    if (!g_audit_jsonl)
        return;
    char line[512];
    char *p = line;
    char *end = line + sizeof(line) - 2;
    audit_append_raw(&p, end, "{\"type\":\"syscall\",\"session\":");
    audit_append_json_string(&p, end, g_session_id);
    p += dr_snprintf(p, (size_t)(end - p), ",\"mode\":\"%s\",\"action\":",
                     g_mode == MODE_STRICT ? "strict" : "observe");
    audit_append_json_string(&p, end, action);
    p += dr_snprintf(p, (size_t)(end - p), ",\"syscall\":%d}\n", sysnum);
    *p = '\0';
    audit_write_line(line);
}

static void audit_resource_event(const char *name, const char *action, int sysnum,
                                 unsigned long long used, unsigned long long limit)
{
    if (!g_audit_jsonl)
        return;
    char line[768];
    char *p = line;
    char *end = line + sizeof(line) - 2;
    audit_append_raw(&p, end, "{\"type\":\"resource\",\"session\":");
    audit_append_json_string(&p, end, g_session_id);
    p += dr_snprintf(p, (size_t)(end - p), ",\"mode\":\"%s\",\"name\":",
                     g_mode == MODE_STRICT ? "strict" : "observe");
    audit_append_json_string(&p, end, name);
    audit_append_raw(&p, end, ",\"action\":");
    audit_append_json_string(&p, end, action);
    p += dr_snprintf(p, (size_t)(end - p), ",\"syscall\":%d,\"used\":%llu,\"limit\":%llu}\n",
                     sysnum, used, limit);
    *p = '\0';
    audit_write_line(line);
}

static void audit_semantic_event(const char *name, const char *action, int sysnum,
                                 long fd, const char *path, const char *peer)
{
    if (!g_semantic_audit)
        return;
    char line[2048];
    char *p = line;
    char *end = line + sizeof(line) - 2;
    audit_append_raw(&p, end, "{\"type\":\"semantic\",\"session\":");
    audit_append_json_string(&p, end, g_session_id);
    p += dr_snprintf(p, (size_t)(end - p), ",\"mode\":\"%s\",\"name\":",
                     g_mode == MODE_STRICT ? "strict" : "observe");
    audit_append_json_string(&p, end, name);
    audit_append_raw(&p, end, ",\"action\":");
    audit_append_json_string(&p, end, action);
    p += dr_snprintf(p, (size_t)(end - p), ",\"syscall\":%d", sysnum);
    if (fd >= 0)
        p += dr_snprintf(p, (size_t)(end - p), ",\"fd\":%ld", fd);
    if (path && *path) {
        audit_append_raw(&p, end, ",\"path\":");
        audit_append_json_string(&p, end, path);
    }
    if (peer && *peer) {
        audit_append_raw(&p, end, ",\"peer\":");
        audit_append_json_string(&p, end, peer);
    }
    audit_append_raw(&p, end, "}\n");
    *p = '\0';
    audit_write_line(line);
}

static bool env_is_false(const char *value)
{
    return value && (strcmp(value, "0") == 0 || strcmp(value, "false") == 0 ||
                     strcmp(value, "no") == 0 || strcmp(value, "allow") == 0 ||
                     strcmp(value, "off") == 0);
}

static bool env_is_true(const char *value)
{
    return value && *value && !env_is_false(value);
}

static bool env_policy_blocks(const char *value, bool default_block)
{
    if (!value || !*value)
        return default_block;
    if (env_is_false(value))
        return false;
    if (strcmp(value, "block") == 0 || strcmp(value, "deny") == 0 ||
        strcmp(value, "strict") == 0)
        return true;
    return env_is_true(value);
}

static size_t parse_size_env(const char *value, size_t fallback)
{
    if (!value || !*value)
        return fallback;
    char *endp = NULL;
    unsigned long long n = strtoull(value, &endp, 10);
    if (endp == value)
        return fallback;
    if (*endp == 'k' || *endp == 'K') n *= 1024ULL;
    else if (*endp == 'm' || *endp == 'M') n *= 1024ULL * 1024ULL;
    else if (*endp == 'g' || *endp == 'G') n *= 1024ULL * 1024ULL * 1024ULL;
    return n > 0 ? (size_t)n : fallback;
}

static int parse_int_env(const char *value, int fallback)
{
    if (!value || !*value)
        return fallback;
    char *endp = NULL;
    long n = strtol(value, &endp, 10);
    if (endp == value || n < 1 || n > 100000)
        return fallback;
    return (int)n;
}

static uint64 parse_uint64_env(const char *value, uint64 fallback)
{
    if (!value || !*value)
        return fallback;
    char *endp = NULL;
    unsigned long long n = strtoull(value, &endp, 10);
    if (endp == value)
        return fallback;
    return (uint64)n;
}

static bool alloc_budget_enabled(void)
{
    return g_max_alloc_bytes > 0;
}

static bool alloc_budget_has_room(size_t bytes)
{
    return !alloc_budget_enabled() || bytes <= g_max_alloc_bytes - g_alloc_bytes;
}

static void alloc_budget_add(size_t bytes)
{
    if (!alloc_budget_enabled() || bytes == 0)
        return;
    dr_mutex_lock(g_mutex);
    if (bytes > g_max_alloc_bytes - g_alloc_bytes)
        g_alloc_bytes = g_max_alloc_bytes;
    else
        g_alloc_bytes += bytes;
    dr_mutex_unlock(g_mutex);
}

static void alloc_budget_sub(size_t bytes)
{
    if (!alloc_budget_enabled() || bytes == 0)
        return;
    dr_mutex_lock(g_mutex);
    if (bytes > g_alloc_bytes)
        g_alloc_bytes = 0;
    else
        g_alloc_bytes -= bytes;
    dr_mutex_unlock(g_mutex);
}

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

static bool path_is_private_write_candidate(const char *path);

/* ── path utility: check if path starts with a prefix at a component boundary ── */
static bool path_has_prefix_component(const char *path, const char *prefix)
{
    size_t plen = strlen(prefix);
    if (strncmp(path, prefix, plen) != 0)
        return false;
    char c = path[plen];
    return c == '\0' || c == '/';
}

static const char *path_policy_action_name(path_policy_action_t action)
{
    switch (action) {
        case PATH_POLICY_PASS:     return "pass";
        case PATH_POLICY_READONLY: return "readonly";
        case PATH_POLICY_PRIVATE:  return "private";
        case PATH_POLICY_BLOCK:    return "block";
        default:                   return "default";
    }
}

static bool parse_path_policy_action(const char *name, size_t len,
                                     path_policy_action_t *out)
{
    if ((len == 2 && strncmp(name, "ro", len) == 0) ||
        (len == 4 && strncmp(name, "read", len) == 0) ||
        (len == 8 && strncmp(name, "readonly", len) == 0)) {
        *out = PATH_POLICY_READONLY;
        return true;
    }
    if ((len == 2 && strncmp(name, "rw", len) == 0) ||
        (len == 4 && strncmp(name, "pass", len) == 0) ||
        (len == 5 && strncmp(name, "allow", len) == 0)) {
        *out = PATH_POLICY_PASS;
        return true;
    }
    if ((len == 7 && strncmp(name, "private", len) == 0) ||
        (len == 5 && strncmp(name, "remap", len) == 0)) {
        *out = PATH_POLICY_PRIVATE;
        return true;
    }
    if ((len == 5 && strncmp(name, "block", len) == 0) ||
        (len == 4 && strncmp(name, "deny", len) == 0)) {
        *out = PATH_POLICY_BLOCK;
        return true;
    }
    return false;
}

static void parse_path_policy_rules(const char *spec)
{
    g_path_rule_count = 0;
    if (!spec || !*spec)
        return;

    const char *p = spec;
    while (*p && g_path_rule_count < (int)(sizeof(g_path_rules) / sizeof(g_path_rules[0]))) {
        while (*p == ';' || *p == ',' || *p == ' ' || *p == '\t' || *p == '\n')
            p++;
        if (!*p)
            break;

        const char *action_start = p;
        while (*p && *p != ':' && *p != '=')
            p++;
        if (!*p)
            break;
        const char *action_end = p++;

        const char *path_start = p;
        while (*p && *p != ';' && *p != ',')
            p++;
        const char *path_end = p;
        while (path_end > path_start &&
               (path_end[-1] == ' ' || path_end[-1] == '\t' || path_end[-1] == '\n'))
            path_end--;

        path_policy_action_t action;
        if (parse_path_policy_action(action_start, (size_t)(action_end - action_start), &action) &&
            path_end > path_start) {
            char raw[256];
            size_t len = (size_t)(path_end - path_start);
            if (len >= sizeof(raw)) len = sizeof(raw) - 1;
            memcpy(raw, path_start, len);
            raw[len] = '\0';

            path_policy_rule_t *rule = &g_path_rules[g_path_rule_count++];
            rule->action = action;
            if (raw[0] == '/')
                canonicalize_path(raw, rule->prefix, sizeof(rule->prefix));
            else {
                size_t rlen = strlen(raw);
                if (rlen >= sizeof(rule->prefix)) rlen = sizeof(rule->prefix) - 1;
                memcpy(rule->prefix, raw, rlen);
                rule->prefix[rlen] = '\0';
            }
        }
    }
}

static void parse_fd_write_policy_rules(const char *spec)
{
    g_fd_write_rule_count = 0;
    if (!spec || !*spec)
        return;
    const char *p = spec;
    while (*p && g_fd_write_rule_count < (int)(sizeof(g_fd_write_rules) / sizeof(g_fd_write_rules[0]))) {
        while (*p == ';' || *p == ',' || *p == ' ' || *p == '\t' || *p == '\n')
            p++;
        if (!*p)
            break;
        const char *action_start = p;
        while (*p && *p != ':' && *p != '=')
            p++;
        if (!*p)
            break;
        const char *action_end = p++;
        const char *path_start = p;
        while (*p && *p != ';' && *p != ',')
            p++;
        const char *path_end = p;
        while (path_end > path_start &&
               (path_end[-1] == ' ' || path_end[-1] == '\t' || path_end[-1] == '\n'))
            path_end--;
        path_policy_action_t action;
        if (parse_path_policy_action(action_start, (size_t)(action_end - action_start), &action) &&
            path_end > path_start) {
            char raw[256];
            size_t len = (size_t)(path_end - path_start);
            if (len >= sizeof(raw)) len = sizeof(raw) - 1;
            memcpy(raw, path_start, len);
            raw[len] = '\0';
            path_policy_rule_t *rule = &g_fd_write_rules[g_fd_write_rule_count++];
            rule->action = action;
            if (raw[0] == '/')
                canonicalize_path(raw, rule->prefix, sizeof(rule->prefix));
            else {
                size_t rlen = strlen(raw);
                if (rlen >= sizeof(rule->prefix)) rlen = sizeof(rule->prefix) - 1;
                memcpy(rule->prefix, raw, rlen);
                rule->prefix[rlen] = '\0';
            }
        }
    }
}

static path_policy_action_t fd_write_policy_for(const char *path)
{
    if (!path || !*path || g_fd_write_rule_count <= 0)
        return PATH_POLICY_DEFAULT;
    char canonical[512];
    if (path[0] == '/')
        canonicalize_path(path, canonical, sizeof(canonical));
    else {
        size_t plen = strlen(path);
        if (plen >= sizeof(canonical)) plen = sizeof(canonical) - 1;
        memcpy(canonical, path, plen);
        canonical[plen] = '\0';
    }
    for (int i = 0; i < g_fd_write_rule_count; i++) {
        if (path_has_prefix_component(canonical, g_fd_write_rules[i].prefix))
            return g_fd_write_rules[i].action;
    }
    return PATH_POLICY_DEFAULT;
}

static uint16_t bswap16(uint16_t v)
{
    return (uint16_t)((v >> 8) | (v << 8));
}

static void parse_network_policy_rules(const char *spec)
{
    g_network_rule_count = 0;
    if (!spec || !*spec)
        return;
    const char *p = spec;
    while (*p && g_network_rule_count < (int)(sizeof(g_network_rules) / sizeof(g_network_rules[0]))) {
        while (*p == ';' || *p == ',' || *p == ' ' || *p == '\t' || *p == '\n')
            p++;
        if (!*p)
            break;
        const char *action_start = p;
        while (*p && *p != ':') p++;
        if (!*p) break;
        const char *action_end = p++;
        const char *host_start = p;
        while (*p && *p != ':' && *p != ';' && *p != ',') p++;
        const char *host_end = p;
        int port = -1;
        if (*p == ':') {
            p++;
            if (*p == '*') {
                port = -1;
                p++;
            } else {
                port = (int)strtol(p, (char **)&p, 10);
            }
        }
        while (*p && *p != ';' && *p != ',') p++;
        if (host_end <= host_start)
            continue;
        network_policy_rule_t *rule = &g_network_rules[g_network_rule_count++];
        rule->block = (action_end - action_start == 5 && strncmp(action_start, "block", 5) == 0) ||
                      (action_end - action_start == 4 && strncmp(action_start, "deny", 4) == 0);
        rule->port = port;
        size_t hlen = (size_t)(host_end - host_start);
        if (hlen >= sizeof(rule->ip)) hlen = sizeof(rule->ip) - 1;
        memcpy(rule->ip, host_start, hlen);
        rule->ip[hlen] = '\0';
        rule->any_ip = strcmp(rule->ip, "*") == 0;
    }
}

static bool read_ipv4_peer(void *drcontext, reg_t sockaddr_ptr, char *peer, size_t peersz,
                           char *ip, size_t ipsz, int *port)
{
    (void)drcontext;
    unsigned char raw[16];
    if (!dr_safe_read((void *)(uintptr_t)sockaddr_ptr, sizeof(raw), raw, NULL))
        return false;
    uint16_t family;
    memcpy(&family, raw, sizeof(family));
    if (family != 2) /* AF_INET */
        return false;
    uint16_t nport;
    memcpy(&nport, raw + 2, sizeof(nport));
    *port = (int)bswap16(nport);
    dr_snprintf(ip, ipsz, "%u.%u.%u.%u", raw[4], raw[5], raw[6], raw[7]);
    dr_snprintf(peer, peersz, "%s:%d", ip, *port);
    return true;
}

static bool network_policy_blocks_peer(const char *ip, int port, bool default_block)
{
    if (g_network_rule_count <= 0)
        return default_block;
    for (int i = 0; i < g_network_rule_count; i++) {
        network_policy_rule_t *rule = &g_network_rules[i];
        bool ip_match = rule->any_ip || strcmp(rule->ip, ip) == 0;
        bool port_match = rule->port < 0 || rule->port == port;
        if (ip_match && port_match)
            return rule->block;
    }
    return default_block;
}

static path_policy_action_t configured_path_policy_for(const char *path)
{
    if (g_path_rule_count <= 0)
        return PATH_POLICY_DEFAULT;

    char canonical[512];
    if (path[0] == '/')
        canonicalize_path(path, canonical, sizeof(canonical));
    else {
        size_t plen = strlen(path);
        if (plen >= sizeof(canonical)) plen = sizeof(canonical) - 1;
        memcpy(canonical, path, plen);
        canonical[plen] = '\0';
    }

    for (int i = 0; i < g_path_rule_count; i++) {
        if (path_has_prefix_component(canonical, g_path_rules[i].prefix))
            return g_path_rules[i].action;
    }
    return PATH_POLICY_DEFAULT;
}

static path_policy_action_t effective_path_policy_for(const char *path)
{
    path_policy_action_t configured = configured_path_policy_for(path);
    if (configured != PATH_POLICY_DEFAULT)
        return configured;
    if (g_redirect_tmp && path_is_private_write_candidate(path))
        return PATH_POLICY_PRIVATE;
    return PATH_POLICY_PASS;
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
static bool read_app_string(void *drcontext, reg_t ptr, char *buf, size_t bufsz);
static bool path_is_private_write_candidate(const char *path);
static void set_errno_result(void *drcontext, int err);

static bool remap_path(const char *orig, char *out, size_t outsz)
{
    /* strip leading slashes for joining */
    const char *rel = orig;
    while (*rel == '/') rel++;

    int n = dr_snprintf(out, outsz, "%s%s", g_sandbox_root, rel);
    return (n > 0 && (size_t)n < outsz);
}

static void ensure_parent_dirs(const char *path)
{
    char tmp[512];
    size_t plen = strlen(path);
    if (plen >= sizeof(tmp)) plen = sizeof(tmp) - 1;
    memcpy(tmp, path, plen);
    tmp[plen] = '\0';

    size_t root_len = strlen(g_sandbox_root);
    for (size_t i = root_len; tmp[i] != '\0'; i++) {
        if (tmp[i] == '/') {
            tmp[i] = '\0';
            if (strlen(tmp) > root_len)
                dr_create_dir(tmp);
            tmp[i] = '/';
        }
    }
}

static bool remap_private_path_param(void *drcontext, int sysnum, int param_index,
                                     const char *label, bool ensure_parent)
{
    reg_t path_arg = dr_syscall_get_param(drcontext, param_index);
    char orig[512];
    if (!read_app_string(drcontext, path_arg, orig, sizeof(orig))) {
        set_errno_result(drcontext, EFAULT);
        return false;
    }

    path_policy_action_t policy = effective_path_policy_for(orig);
    if (policy == PATH_POLICY_BLOCK) {
        LOG("BLOCK %s syscall=%d param=%d: %s", label, sysnum, param_index, orig);
        audit_path_event("block", sysnum, label, orig, NULL);
        set_errno_result(drcontext, EPERM);
        return false;
    }
    if (policy == PATH_POLICY_READONLY && ensure_parent) {
        LOG("READONLY %s syscall=%d param=%d: %s", label, sysnum, param_index, orig);
        audit_path_event("readonly", sysnum, label, orig, NULL);
        set_errno_result(drcontext, EPERM);
        return false;
    }
    if (policy != PATH_POLICY_PRIVATE) {
        if (g_mode == MODE_OBSERVE)
            audit_path_event(path_policy_action_name(policy), sysnum, label, orig, NULL);
        return true;
    }

    char remapped[512];
    if (!remap_path(orig, remapped, sizeof(remapped))) {
        set_errno_result(drcontext, EPERM);
        return false;
    }
    if (ensure_parent)
        ensure_parent_dirs(remapped);

    LOG("REMAP %s syscall=%d param=%d: %s -> %s", label, sysnum, param_index, orig, remapped);
    audit_path_event("remap", sysnum, label, orig, remapped);
    if (strlen(remapped) <= strlen(orig)) {
        if (!dr_safe_write((void *)(uintptr_t)path_arg, strlen(remapped) + 1,
                           remapped, NULL)) {
            set_errno_result(drcontext, EFAULT);
            return false;
        }
    } else {
        void *newbuf = dr_global_alloc(512);
        if (!newbuf) {
            set_errno_result(drcontext, ENOMEM);
            return false;
        }
        memcpy(newbuf, remapped, strlen(remapped) + 1);
        dr_syscall_set_param(drcontext, param_index, (reg_t)(uintptr_t)newbuf);
    }
    return true;
}

static bool open_flags_write_intent(int flags)
{
    int accmode = flags & O_ACCMODE;
    return accmode == O_WRONLY || accmode == O_RDWR ||
           (flags & (O_CREAT | O_TRUNC | O_APPEND)) != 0;
}

static bool path_is_private_write_candidate(const char *path)
{
    char canonical[512];
    if (path[0] == '/')
        canonicalize_path(path, canonical, sizeof(canonical));
    else {
        size_t plen = strlen(path);
        if (plen >= sizeof(canonical)) plen = sizeof(canonical) - 1;
        memcpy(canonical, path, plen);
        canonical[plen] = '\0';
    }

    if (path_has_prefix_component(canonical, "/tmp/MathLink") ||
        path_has_prefix_component(canonical, "/dev/shm"))
        return false;

    if (path_has_prefix_component(canonical, "/tmp") ||
        path_has_prefix_component(canonical, "/var/tmp"))
        return true;

    /* Wolfram and many language runtimes write caches/state below HOME.  Keep
     * this broad in observe mode so we can get complex commercial runtimes to
     * start, while still making those writes disposable.
     */
    if (strstr(canonical, "/.Wolfram") != NULL ||
        strstr(canonical, "/.cache") != NULL)
        return true;

    return false;
}

static void ensure_private_dirs(void)
{
    char path[256];
    dr_create_dir(SANDBOX_BASE);
    dr_create_dir(g_sandbox_root);

    dr_snprintf(path, sizeof(path), "%stmp", g_sandbox_root);
    dr_create_dir(path);
    dr_snprintf(path, sizeof(path), "%svar", g_sandbox_root);
    dr_create_dir(path);
    dr_snprintf(path, sizeof(path), "%svar/tmp", g_sandbox_root);
    dr_create_dir(path);
}

static void set_errno_result(void *drcontext, int err)
{
    dr_syscall_result_info_t info;
    memset(&info, 0, sizeof(info));
    info.size = sizeof(info);
    info.succeeded = false;
    info.use_errno = true;
    info.errno_value = (uint)err;
    dr_syscall_set_result_ex(drcontext, &info);
}

/* ── helper: read string from app memory ────────────────────── */
static bool read_app_string(void *drcontext, reg_t ptr, char *buf, size_t bufsz)
{
    (void)drcontext;
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

static void fd_shadow_clear(int fd)
{
    if (fd >= 0 && fd < (int)(sizeof(g_fd_shadow) / sizeof(g_fd_shadow[0])))
        memset(&g_fd_shadow[fd], 0, sizeof(g_fd_shadow[fd]));
}

static void fd_shadow_set(int fd, const char *path, bool block_write)
{
    if (fd < 0 || fd >= (int)(sizeof(g_fd_shadow) / sizeof(g_fd_shadow[0])) || !path)
        return;
    g_fd_shadow[fd].in_use = true;
    g_fd_shadow[fd].block_write = block_write;
    size_t len = strlen(path);
    if (len >= sizeof(g_fd_shadow[fd].path)) len = sizeof(g_fd_shadow[fd].path) - 1;
    memcpy(g_fd_shadow[fd].path, path, len);
    g_fd_shadow[fd].path[len] = '\0';
}

static fd_shadow_t *fd_shadow_get(int fd)
{
    if (fd < 0 || fd >= (int)(sizeof(g_fd_shadow) / sizeof(g_fd_shadow[0])) ||
        !g_fd_shadow[fd].in_use)
        return NULL;
    return &g_fd_shadow[fd];
}

static bool proc_self_fd_target(const char *path, int *fd_out)
{
    const char *prefix = "/proc/self/fd/";
    size_t plen = strlen(prefix);
    if (strncmp(path, prefix, plen) != 0)
        return false;
    char *endp = NULL;
    long fd = strtol(path + plen, &endp, 10);
    if (endp == path + plen || *endp != '\0' || fd < 0 || fd > 100000)
        return false;
    *fd_out = (int)fd;
    return true;
}

static void fd_shadow_copy(int dst, int src)
{
    fd_shadow_t *shadow = fd_shadow_get(src);
    if (!shadow) {
        fd_shadow_clear(dst);
        return;
    }
    fd_shadow_set(dst, shadow->path, shadow->block_write);
    audit_semantic_event("fd", shadow->block_write ? "dup-track-block-write" : "dup-track",
                         g_last_sysnum, dst, shadow->path, NULL);
}

static bool network_policy_blocks_unknown_peer(void)
{
    return network_policy_blocks_peer("*", -1, g_block_network);
}

static bool check_cpuish_budget(void *drcontext, int sysnum)
{
    if (g_max_cpu_ms == 0 || g_start_ms == 0)
        return true;
    if (!(sysnum == SYS_read || sysnum == SYS_pread64 || sysnum == SYS_write ||
          sysnum == SYS_pwrite64 || sysnum == SYS_open || sysnum == SYS_openat ||
          sysnum == SYS_creat))
        return true;
    uint64 elapsed = dr_get_milliseconds() - g_start_ms;
    if (elapsed <= g_max_cpu_ms)
        return true;
    LOG("BLOCK cpu-ish timeout: elapsed=%llu max=%llu", (unsigned long long)elapsed,
        (unsigned long long)g_max_cpu_ms);
    audit_resource_event("cpu-timeout", "block", sysnum,
                         (unsigned long long)elapsed, (unsigned long long)g_max_cpu_ms);
    set_errno_result(drcontext, ETIMEDOUT);
    return false;
}

static bool enforce_output_limit(void *drcontext, int sysnum, int fd, size_t requested)
{
    size_t *used = NULL;
    size_t limit = 0;
    const char *name = NULL;
    if (fd == 1 && g_max_stdout_bytes > 0) {
        used = &g_stdout_bytes;
        limit = g_max_stdout_bytes;
        name = "stdout-limit";
    } else if (fd == 2 && g_max_stderr_bytes > 0) {
        used = &g_stderr_bytes;
        limit = g_max_stderr_bytes;
        name = "stderr-limit";
    } else {
        return true;
    }

    if (*used >= limit) {
        audit_resource_event(name, g_output_truncate ? "truncate" : "block", sysnum,
                             (unsigned long long)*used, (unsigned long long)limit);
        if (g_output_truncate) {
            dr_syscall_result_info_t info;
            memset(&info, 0, sizeof(info));
            info.size = sizeof(info);
            info.succeeded = true;
            info.value = 0;
            dr_syscall_set_result_ex(drcontext, &info);
        } else {
            set_errno_result(drcontext, EFBIG);
        }
        return false;
    }

    size_t remaining = limit - *used;
    if (requested > remaining) {
        audit_resource_event(name, g_output_truncate ? "truncate" : "block", sysnum,
                             (unsigned long long)(*used + requested), (unsigned long long)limit);
        if (!g_output_truncate) {
            set_errno_result(drcontext, EFBIG);
            return false;
        }
        if (sysnum == SYS_write || sysnum == SYS_pwrite64)
            dr_syscall_set_param(drcontext, 2, (reg_t)remaining);
        requested = remaining;
    }
    *used += requested;
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
    g_last_sysnum = sysnum;
    g_last_mmap_len = 0;
    g_last_mremap_old_len = 0;
    g_last_mremap_new_len = 0;
    g_last_munmap_len = 0;
    g_pending_open = false;
    g_pending_dup = false;

    if (!check_cpuish_budget(drcontext, sysnum))
        return false;

    if (sysnum == SYS_close) {
        int fd = (int)dr_syscall_get_param(drcontext, 0);
        audit_semantic_event("close", "allow", sysnum, fd, fd_shadow_get(fd) ? fd_shadow_get(fd)->path : NULL, NULL);
        fd_shadow_clear(fd);
        return true;
    }

    if (sysnum == SYS_dup || sysnum == SYS_dup2 || sysnum == SYS_dup3) {
        g_pending_dup = true;
        g_pending_dup_src = (int)dr_syscall_get_param(drcontext, 0);
        g_pending_dup_has_dst = sysnum == SYS_dup2 || sysnum == SYS_dup3;
        g_pending_dup_dst = g_pending_dup_has_dst ? (int)dr_syscall_get_param(drcontext, 1) : -1;
        if (g_pending_dup_has_dst)
            fd_shadow_clear(g_pending_dup_dst);
        return true;
    }

    if (sysnum == SYS_fcntl) {
        int cmd = (int)dr_syscall_get_param(drcontext, 1);
        if (cmd == 0 || cmd == 1030 /* F_DUPFD_CLOEXEC */) {
            g_pending_dup = true;
            g_pending_dup_src = (int)dr_syscall_get_param(drcontext, 0);
            g_pending_dup_has_dst = false;
            g_pending_dup_dst = -1;
        }
        return true;
    }

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
        /* memory management checks are below so DR can own Lambda-compatible limits */
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

    /* --- open / openat / creat: observe or private scratch remap -------- */
    if (sysnum == SYS_open || sysnum == SYS_openat || sysnum == SYS_creat) {
        reg_t path_arg;
        int flags = 0;
        if (sysnum == SYS_openat) {
            path_arg = dr_syscall_get_param(drcontext, 1);  /* dirfd, path, flags */
            flags = (int)dr_syscall_get_param(drcontext, 2);
        } else if (sysnum == SYS_creat) {
            path_arg = dr_syscall_get_param(drcontext, 0);  /* path, mode */
            flags = O_WRONLY | O_CREAT | O_TRUNC;
        } else {
            path_arg = dr_syscall_get_param(drcontext, 0);  /* path, flags */
            flags = (int)dr_syscall_get_param(drcontext, 1);
        }

        char orig[512];
        if (!read_app_string(drcontext, path_arg, orig, sizeof(orig))) {
            set_errno_result(drcontext, EPERM);
            return false;
        }

        path_policy_action_t policy = effective_path_policy_for(orig);
        bool has_configured_policy = configured_path_policy_for(orig) != PATH_POLICY_DEFAULT;
        if (policy == PATH_POLICY_BLOCK) {
            LOG("BLOCK open: %s", orig);
            audit_path_event("block", sysnum, "open", orig, NULL);
            set_errno_result(drcontext, EPERM);
            return false;
        }
        if (policy == PATH_POLICY_READONLY && open_flags_write_intent(flags)) {
            LOG("READONLY open: %s flags=0x%x", orig, flags);
            audit_path_event("readonly", sysnum, "open", orig, NULL);
            set_errno_result(drcontext, EPERM);
            return false;
        }

        if (!has_configured_policy && g_mode == MODE_STRICT && path_is_blocked(orig)) {
            LOG("BLOCK open: %s", orig);
            if (strncmp(orig, "/etc/shadow", 11) == 0 &&
                    (orig[11] == '\0' || orig[11] == '/'))
                set_errno_result(drcontext, ENOENT);
            else
                set_errno_result(drcontext, EPERM);
            return false;
        }

        g_pending_open = true;
        int proc_fd = -1;
        fd_shadow_t *proc_shadow = NULL;
        if (proc_self_fd_target(orig, &proc_fd))
            proc_shadow = fd_shadow_get(proc_fd);
        g_pending_open_block_write = proc_shadow ? proc_shadow->block_write : fd_write_policy_for(orig) == PATH_POLICY_BLOCK;
        size_t open_path_len = strlen(proc_shadow ? proc_shadow->path : orig);
        if (open_path_len >= sizeof(g_pending_open_path)) open_path_len = sizeof(g_pending_open_path) - 1;
        memcpy(g_pending_open_path, proc_shadow ? proc_shadow->path : orig, open_path_len);
        g_pending_open_path[open_path_len] = '\0';
        audit_semantic_event("open", "allow", sysnum, -1, orig, NULL);

        bool should_redirect = policy == PATH_POLICY_PRIVATE;
        if (!should_redirect) {
            if (g_mode == MODE_OBSERVE) {
                LOG("%s open: %s flags=0x%x", path_policy_action_name(policy), orig, flags);
                audit_path_event(path_policy_action_name(policy), sysnum, "open", orig, NULL);
            }
            return true;
        }

        char remapped[512];
        if (!remap_path(orig, remapped, sizeof(remapped))) {
            set_errno_result(drcontext, EPERM);
            return false;
        }
        if (open_flags_write_intent(flags))
            ensure_parent_dirs(remapped);
        LOG("REMAP private open: %s -> %s flags=0x%x", orig, remapped, flags);
        audit_path_event("remap", sysnum, "open", orig, remapped);

        if (strlen(remapped) <= strlen(orig)) {
            if (!dr_safe_write((void *)(uintptr_t)path_arg, strlen(remapped) + 1,
                               remapped, NULL)) {
                set_errno_result(drcontext, EFAULT);
                return false;
            }
        } else {
            void *newbuf = dr_global_alloc(512);
            if (newbuf) {
                memcpy(newbuf, remapped, strlen(remapped) + 1);
                if (sysnum == SYS_openat)
                    dr_syscall_set_param(drcontext, 1, (reg_t)(uintptr_t)newbuf);
                else
                    dr_syscall_set_param(drcontext, 0, (reg_t)(uintptr_t)newbuf);
            } else {
                set_errno_result(drcontext, ENOMEM);
                return false;
            }
        }
        return true;
    }

    /* --- private scratch VFS path operations ------------------ */
    switch (sysnum) {
        case SYS_stat:
        case SYS_lstat:
        case SYS_access:
        case SYS_readlink:
        case SYS_rmdir:
        case SYS_unlink:
        case SYS_truncate:
        case SYS_statfs:
            return remap_private_path_param(drcontext, sysnum, 0, "path", false);
        case SYS_mkdir:
            return remap_private_path_param(drcontext, sysnum, 0, "mkdir", true);
        case SYS_fstatat:
        case SYS_faccessat:
        case SYS_faccessat2:
        case SYS_readlinkat:
        case SYS_unlinkat:
        case SYS_utimensat:
            return remap_private_path_param(drcontext, sysnum, 1, "at-path", false);
        case SYS_mkdirat:
            return remap_private_path_param(drcontext, sysnum, 1, "mkdirat", true);
        case SYS_statx:
            return remap_private_path_param(drcontext, sysnum, 1, "statx", false);
        case SYS_rename:
            if (!remap_private_path_param(drcontext, sysnum, 0, "rename-old", false)) return false;
            return remap_private_path_param(drcontext, sysnum, 1, "rename-new", true);
        case SYS_renameat:
        case SYS_renameat2:
            if (!remap_private_path_param(drcontext, sysnum, 1, "renameat-old", false)) return false;
            return remap_private_path_param(drcontext, sysnum, 3, "renameat-new", true);
        case SYS_link:
            if (!remap_private_path_param(drcontext, sysnum, 0, "link-old", false)) return false;
            return remap_private_path_param(drcontext, sysnum, 1, "link-new", true);
        case SYS_linkat:
            if (!remap_private_path_param(drcontext, sysnum, 1, "linkat-old", false)) return false;
            return remap_private_path_param(drcontext, sysnum, 3, "linkat-new", true);
        case SYS_symlink:
            return remap_private_path_param(drcontext, sysnum, 1, "symlink-new", true);
        case SYS_symlinkat:
            return remap_private_path_param(drcontext, sysnum, 2, "symlinkat-new", true);
    }

    /* --- configurable non-path controls ----------------------- */
    if (sysnum == SYS_write || sysnum == SYS_writev || sysnum == SYS_pwrite64) {
        reg_t fd = dr_syscall_get_param(drcontext, 0);
        if ((sysnum == SYS_write || sysnum == SYS_pwrite64) &&
            !enforce_output_limit(drcontext, sysnum, (int)fd,
                                  (size_t)dr_syscall_get_param(drcontext, 2)))
            return false;
        fd_shadow_t *shadow = fd_shadow_get((int)fd);
        if (shadow && shadow->block_write) {
            LOG("BLOCK fd write: fd=%ld path=%s", (long)fd, shadow->path);
            audit_semantic_event("write", "block", sysnum, (long)fd, shadow->path, NULL);
            audit_syscall_event("block", sysnum);
            set_errno_result(drcontext, EPERM);
            return false;
        }
        audit_semantic_event("write", "allow", sysnum, (long)fd, shadow ? shadow->path : NULL, NULL);
        if (g_stdio_only_writes && fd != 1 && fd != 2) {
            LOG("BLOCK write: fd=%ld", (long)fd);
            audit_syscall_event("block", sysnum);
            set_errno_result(drcontext, EPERM);
            return false;
        }
        return true;
    }

    if (sysnum == SYS_read || sysnum == SYS_pread64) {
        reg_t count = dr_syscall_get_param(drcontext, 2);
        if ((size_t)count > g_max_read_bytes) {
            LOG("CAP read: %ld -> %llu", (long)count, (unsigned long long)g_max_read_bytes);
            audit_syscall_event("cap", sysnum);
            dr_syscall_set_param(drcontext, 2, (reg_t)g_max_read_bytes);
        }
        return true;
    }

    if (sysnum == SYS_brk) {
        reg_t requested = dr_syscall_get_param(drcontext, 0);
        if (requested == 0)
            return true; /* learn current break in post-syscall */
        if (alloc_budget_enabled() && g_initial_brk != 0 && requested > g_initial_brk) {
            size_t requested_heap = (size_t)(requested - g_initial_brk);
            if (requested_heap > g_max_alloc_bytes) {
                LOG("BLOCK brk: requested heap %llu > max_alloc %llu",
                    (unsigned long long)requested_heap,
                    (unsigned long long)g_max_alloc_bytes);
                audit_syscall_event("block", sysnum);
                set_errno_result(drcontext, ENOMEM);
                return false;
            }
        }
        return true;
    }

    if (sysnum == SYS_munmap) {
        g_last_munmap_len = (size_t)dr_syscall_get_param(drcontext, 1);
        return true;
    }

    if (sysnum == SYS_mremap) {
        size_t old_len = (size_t)dr_syscall_get_param(drcontext, 1);
        size_t new_len = (size_t)dr_syscall_get_param(drcontext, 2);
        g_last_mremap_old_len = old_len;
        g_last_mremap_new_len = new_len;
        if (new_len > old_len && !alloc_budget_has_room(new_len - old_len)) {
            LOG("BLOCK mremap: grow %llu exceeds max_alloc %llu (used %llu)",
                (unsigned long long)(new_len - old_len),
                (unsigned long long)g_max_alloc_bytes,
                (unsigned long long)g_alloc_bytes);
            audit_syscall_event("block", sysnum);
            set_errno_result(drcontext, ENOMEM);
            return false;
        }
        return true;
    }

    if (sysnum == SYS_mmap) {
        reg_t len = dr_syscall_get_param(drcontext, 1);
        reg_t prot = dr_syscall_get_param(drcontext, 2);
        if (g_block_prot_exec && (prot & PROT_EXEC)) {
            LOG("WARN mmap PROT_EXEC requested (prot=0x%lx) - BLOCKED", (long)prot);
            audit_syscall_event("block", sysnum);
            set_errno_result(drcontext, EPERM);
            return false;
        }
        if (!alloc_budget_has_room((size_t)len)) {
            LOG("BLOCK mmap: len %llu exceeds max_alloc %llu (used %llu)",
                (unsigned long long)len,
                (unsigned long long)g_max_alloc_bytes,
                (unsigned long long)g_alloc_bytes);
            audit_syscall_event("block", sysnum);
            set_errno_result(drcontext, ENOMEM);
            return false;
        }
        g_last_mmap_len = (size_t)len;
        return true;
    }

    if (sysnum == SYS_mprotect) {
        reg_t prot = dr_syscall_get_param(drcontext, 2);
        if (g_block_prot_exec && (prot & PROT_EXEC)) {
            LOG("WARN mprotect PROT_EXEC requested (prot=0x%lx) - BLOCKED", (long)prot);
            audit_syscall_event("block", sysnum);
            set_errno_result(drcontext, EPERM);
            return false;
        }
        return true;
    }

    switch (sysnum) {
        case SYS_socket:
        case SYS_socketpair:
            if (g_block_network && g_network_rule_count <= 0) {
                LOG("BLOCK network syscall %d", sysnum);
                audit_syscall_event("block", sysnum);
                set_errno_result(drcontext, ENETDOWN);
                return false;
            }
            audit_semantic_event("socket", "allow", sysnum, -1, NULL, NULL);
            return true;
        case SYS_connect:
        case SYS_bind:
        case SYS_sendto: {
            char peer[96] = "";
            char ip[64] = "";
            int port = -1;
            bool have_peer = false;
            if (sysnum == SYS_sendto)
                have_peer = read_ipv4_peer(drcontext, dr_syscall_get_param(drcontext, 4), peer, sizeof(peer), ip, sizeof(ip), &port);
            else
                have_peer = read_ipv4_peer(drcontext, dr_syscall_get_param(drcontext, 1), peer, sizeof(peer), ip, sizeof(ip), &port);
            bool block = have_peer ? network_policy_blocks_peer(ip, port, g_block_network) : network_policy_blocks_unknown_peer();
            if (block) {
                LOG("BLOCK network syscall %d peer=%s", sysnum, have_peer ? peer : "unknown");
                audit_semantic_event(sysnum == SYS_connect ? "connect" : (sysnum == SYS_bind ? "bind" : "sendto"),
                                     "block", sysnum, -1, NULL, have_peer ? peer : NULL);
                audit_syscall_event("block", sysnum);
                set_errno_result(drcontext, ENETDOWN);
                return false;
            }
            audit_semantic_event(sysnum == SYS_connect ? "connect" : (sysnum == SYS_bind ? "bind" : "sendto"),
                                 "allow", sysnum, -1, NULL, have_peer ? peer : NULL);
            return true;
        }
        case SYS_listen:
        case SYS_accept:
        case SYS_accept4:
        case SYS_recvfrom:
        case SYS_sendmsg:
        case SYS_recvmsg:
        case SYS_sendmmsg:
        case SYS_recvmmsg:
        case SYS_shutdown:
        case SYS_getsockname:
        case SYS_getpeername:
        case SYS_setsockopt:
        case SYS_getsockopt:
            if (network_policy_blocks_unknown_peer()) {
                LOG("BLOCK network syscall %d", sysnum);
                audit_syscall_event("block", sysnum);
                set_errno_result(drcontext, ENETDOWN);
                return false;
            }
            return true;
    }

    if (sysnum == SYS_execve || sysnum == SYS_execveat) {
        if (g_block_exec) {
            LOG("BLOCK execve");
            audit_syscall_event("block", sysnum);
            set_errno_result(drcontext, EPERM);
            return false;
        }
        return true;
    }

    if (sysnum == SYS_fork || sysnum == SYS_vfork) {
        dr_mutex_lock(g_mutex);
        int cnt = ++g_proc_count;
        dr_mutex_unlock(g_mutex);
        if (cnt > g_max_procs) {
            LOG("BLOCK fork: proc limit %d exceeded", g_max_procs);
            audit_syscall_event("block", sysnum);
            set_errno_result(drcontext, EAGAIN);
            return false;
        }
        LOG("ALLOW fork (%d/%d)", cnt, g_max_procs);
        return true;
    }

    if (sysnum == SYS_clone || sysnum == SYS_clone3) {
        reg_t flags = dr_syscall_get_param(drcontext, 0);
        bool new_proc = !(flags & 0x00010000 /*CLONE_THREAD*/);
        if (new_proc) {
            dr_mutex_lock(g_mutex);
            int cnt = ++g_proc_count;
            dr_mutex_unlock(g_mutex);
            if (cnt > g_max_procs) {
                LOG("BLOCK clone(new-proc): proc limit %d exceeded", g_max_procs);
                audit_syscall_event("block", sysnum);
                set_errno_result(drcontext, EAGAIN);
                return false;
            }
            LOG("ALLOW clone(new-proc) (%d/%d)", cnt, g_max_procs);
        }
        return true;
    }

    /* Observe mode is the compatibility-first mode for Wolfram/LF-style
     * Docker probes: after selected path virtualization above, pass every other
     * syscall through while logging enough to build an enforce profile later.
     */
    if (g_mode == MODE_OBSERVE) {
        LOG("OBSERVE syscall %d", sysnum);
        audit_syscall_event("observe", sysnum);
        return true;
    }

    /* --- write: only fd 1 (stdout) and fd 2 (stderr) --------- */
    if (sysnum == SYS_write || sysnum == SYS_writev || sysnum == SYS_pwrite64) {
        reg_t fd = dr_syscall_get_param(drcontext, 0);
        if (fd != 1 && fd != 2) {
            LOG("BLOCK write: fd=%ld", (long)fd);
            set_errno_result(drcontext, EPERM);
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
            set_errno_result(drcontext, EPERM);
            return false;
        }
        return true;
    }

    /* --- mprotect: block PROT_EXEC --------------------------- */
    if (sysnum == SYS_mprotect) {
        reg_t prot = dr_syscall_get_param(drcontext, 2);
        if (prot & PROT_EXEC) {
            LOG("WARN mprotect PROT_EXEC requested (prot=0x%lx) - BLOCKED", (long)prot);
            set_errno_result(drcontext, EPERM);
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
            set_errno_result(drcontext, ENETDOWN);
            return false;
    }

    /* --- execve / execveat ----------------------------------- */
    if (sysnum == SYS_execve || sysnum == SYS_execveat) {
        LOG("BLOCK execve");
        set_errno_result(drcontext, EPERM);
        return false;
    }

    /* --- fork / clone (new process) -------------------------- */
    if (sysnum == SYS_fork || sysnum == SYS_vfork) {
        dr_mutex_lock(g_mutex);
        int cnt = ++g_proc_count;
        dr_mutex_unlock(g_mutex);
        if (cnt > MAX_PROCS) {
            LOG("BLOCK fork: proc limit %d exceeded", MAX_PROCS);
            set_errno_result(drcontext, EAGAIN);
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
                set_errno_result(drcontext, EAGAIN);
                return false;
            }
            LOG("ALLOW clone(new-proc) (%d/%d)", cnt, MAX_PROCS);
        }
        return true;
    }

    /* ── BLOCKED (everything else) ───────────────────────────── */
    LOG("BLOCK syscall %d", sysnum);
    set_errno_result(drcontext, EPERM);
    return false;
}

static void event_post_syscall(void *drcontext, int sysnum)
{
    dr_syscall_result_info_t info;
    memset(&info, 0, sizeof(info));
    info.size = sizeof(info);
    info.use_errno = true;
    if (!dr_syscall_get_result_ex(drcontext, &info))
        return;
    reg_t result = info.value;

    if ((sysnum == SYS_open || sysnum == SYS_openat || sysnum == SYS_creat) &&
        g_pending_open && info.succeeded) {
        int fd = (int)result;
        fd_shadow_set(fd, g_pending_open_path, g_pending_open_block_write);
        audit_semantic_event("fd", g_pending_open_block_write ? "track-block-write" : "track", sysnum,
                             fd, g_pending_open_path, NULL);
        return;
    }

    if (g_pending_dup && info.succeeded) {
        int dst = g_pending_dup_has_dst ? g_pending_dup_dst : (int)result;
        fd_shadow_copy(dst, g_pending_dup_src);
        return;
    }

    if (sysnum == SYS_mmap) {
        if (g_last_sysnum == SYS_mmap && g_last_mmap_len > 0 && info.succeeded)
            alloc_budget_add(g_last_mmap_len);
        return;
    }

    if (sysnum == SYS_munmap) {
        if (g_last_sysnum == SYS_munmap && g_last_munmap_len > 0 && info.succeeded)
            alloc_budget_sub(g_last_munmap_len);
        return;
    }

    if (sysnum == SYS_mremap) {
        if (g_last_sysnum == SYS_mremap && info.succeeded) {
            if (g_last_mremap_new_len > g_last_mremap_old_len)
                alloc_budget_add(g_last_mremap_new_len - g_last_mremap_old_len);
            else
                alloc_budget_sub(g_last_mremap_old_len - g_last_mremap_new_len);
        }
        return;
    }

    if (sysnum == SYS_brk) {
        reg_t requested = dr_syscall_get_param(drcontext, 0);
        if (info.succeeded && result != 0) {
            if (g_initial_brk == 0)
                g_initial_brk = result;
            g_current_brk = result;
        }
        if (requested != 0 && result == requested && g_initial_brk != 0 && result > g_initial_brk) {
            size_t heap_bytes = (size_t)(result - g_initial_brk);
            if (heap_bytes > g_alloc_bytes)
                g_alloc_bytes = heap_bytes;
        }
    }
}

/* ── client init ─────────────────────────────────────────────── */
DR_EXPORT void dr_client_main(client_id_t id, int argc, const char *argv[])
{
    (void)id;
    (void)argc;
    (void)argv;
    dr_set_client_name("syscall-virtualization-filter",
                       "https://github.com/example/shimmy");

    g_log = STDERR;
    g_audit_log = STDERR;

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

    const char *env_mode = getenv("DR_SANDBOX_MODE");
    if (env_mode && (strcmp(env_mode, "strict") == 0 || strcmp(env_mode, "enforce") == 0))
        g_mode = MODE_STRICT;
    else
        g_mode = MODE_OBSERVE;

    const char *env_redirect_tmp = getenv("DR_REDIRECT_TMP");
    if (env_redirect_tmp && env_is_false(env_redirect_tmp))
        g_redirect_tmp = false;

    g_block_network = g_mode == MODE_STRICT;
    g_block_exec = g_mode == MODE_STRICT;
    g_block_prot_exec = g_mode == MODE_STRICT;
    g_stdio_only_writes = g_mode == MODE_STRICT;
    g_max_read_bytes = parse_size_env(getenv("DR_MAX_READ_BYTES"), MAX_READ_BYTES);
    g_max_alloc_bytes = parse_size_env(getenv("DR_MAX_ALLOC_BYTES"), 0);
    g_max_stdout_bytes = parse_size_env(getenv("DR_MAX_STDOUT_BYTES"), 0);
    g_max_stderr_bytes = parse_size_env(getenv("DR_MAX_STDERR_BYTES"), 0);
    const char *env_output_action = getenv("DR_OUTPUT_LIMIT_ACTION");
    g_output_truncate = env_output_action && strcmp(env_output_action, "truncate") == 0;
    g_max_cpu_ms = parse_uint64_env(getenv("DR_MAX_CPU_MS"), 0);
    g_start_ms = dr_get_milliseconds();
    g_max_procs = parse_int_env(getenv("DR_MAX_PROCS"), MAX_PROCS);
    g_block_network = env_policy_blocks(getenv("DR_NETWORK"), g_block_network);
    g_block_exec = env_policy_blocks(getenv("DR_EXEC"), g_block_exec);
    g_block_prot_exec = env_policy_blocks(getenv("DR_PROT_EXEC"), g_block_prot_exec);
    g_stdio_only_writes = env_policy_blocks(getenv("DR_FILE_WRITE"), g_stdio_only_writes);
    g_semantic_audit = env_is_true(getenv("DR_SEMANTIC_AUDIT"));
    if (g_semantic_audit)
        g_audit_jsonl = true;

    const char *env_audit_jsonl = getenv("DR_AUDIT_JSONL");
    if (env_audit_jsonl && *env_audit_jsonl &&
        strcmp(env_audit_jsonl, "0") != 0 && strcmp(env_audit_jsonl, "false") != 0 &&
        strcmp(env_audit_jsonl, "no") != 0)
        g_audit_jsonl = true;

    const char *env_human_log = getenv("DR_HUMAN_LOG");
    if (env_human_log &&
        (strcmp(env_human_log, "0") == 0 || strcmp(env_human_log, "false") == 0 ||
         strcmp(env_human_log, "no") == 0))
        g_human_log = false;

    const char *env_audit_path = getenv("DR_AUDIT_PATH");
    if (env_audit_path && *env_audit_path) {
        file_t audit_file = dr_open_file(env_audit_path,
                                         DR_FILE_WRITE_APPEND | DR_FILE_ALLOW_LARGE);
        if (audit_file != INVALID_FILE) {
            g_audit_log = audit_file;
            g_audit_jsonl = true;
        } else {
            LOG("WARN could not open DR_AUDIT_PATH=%s; using stderr", env_audit_path);
        }
    }

    const char *env_path_policy = getenv("DR_PATH_POLICY");
    parse_path_policy_rules(env_path_policy);
    parse_fd_write_policy_rules(getenv("DR_FD_WRITE_POLICY"));
    parse_network_policy_rules(getenv("DR_NETWORK_POLICY"));

    ensure_private_dirs();

    g_mutex = dr_mutex_create();

    dr_register_filter_syscall_event(event_filter_syscall);
    dr_register_pre_syscall_event(event_pre_syscall);
    dr_register_post_syscall_event(event_post_syscall);

    LOG("syscall virtualization active - sandbox: %s mode=%s redirect_tmp=%s audit_jsonl=%s path_rules=%d net=%s exec=%s prot_exec=%s file_write=%s max_read=%llu max_procs=%d max_alloc=%llu",
        g_sandbox_root, g_mode == MODE_STRICT ? "strict" : "observe",
        g_redirect_tmp ? "true" : "false", g_audit_jsonl ? "true" : "false",
        g_path_rule_count,
        g_block_network ? "block" : "allow", g_block_exec ? "block" : "allow",
        g_block_prot_exec ? "block" : "allow", g_stdio_only_writes ? "stdio" : "allow",
        (unsigned long long)g_max_read_bytes, g_max_procs,
        (unsigned long long)g_max_alloc_bytes);
}
