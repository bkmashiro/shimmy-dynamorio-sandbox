/*
 * host-stubs/dr_api.h
 *
 * Minimal stubs for DynamoRIO's public API, used ONLY so that clangd on the
 * host can parse syscall_filter.c without errors.  This file is NOT used
 * during the actual Docker build - the real dr_api.h lives at
 * /opt/dynamorio/include/ inside the container.
 */
#pragma once
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/* ── basic types ─────────────────────────────────────────────── */
typedef uint32_t  client_id_t;
typedef void     *dr_context_t;   /* opaque */
typedef void     *drcontext_t;    /* per-thread context */
typedef uintptr_t reg_t;
typedef uint64_t  uint64;
typedef int       file_t;         /* DynamoRIO uses int for file handles */

/* ── DR_EXPORT / STDERR ──────────────────────────────────────── */
#define DR_EXPORT  __attribute__((visibility("default")))
#define STDERR     STDERR_FILENO  /* DynamoRIO maps STDERR -> fd 2 on Linux */

/* ── Logging ─────────────────────────────────────────────────── */
static inline void dr_fprintf(file_t f, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vdprintf(f, fmt, ap);
    va_end(ap);
}

/* ── Syscall parameter access ────────────────────────────────── */
static inline reg_t dr_syscall_get_param(void *ctx, int param_num)
    { (void)ctx; (void)param_num; return 0; }

static inline void dr_syscall_set_param(void *ctx, int param_num, reg_t val)
    { (void)ctx; (void)param_num; (void)val; }

static inline void dr_syscall_set_result(void *ctx, uintptr_t val)
    { (void)ctx; (void)val; }

/* ── Safe memory access ──────────────────────────────────────── */
static inline bool dr_safe_read(const void *base, size_t size, void *out_buf,
                                size_t *bytes_read)
{
    memcpy(out_buf, base, size);
    if (bytes_read) *bytes_read = size;
    return true;
}

static inline bool dr_safe_write(void *base, size_t size, const void *in_buf,
                                 size_t *bytes_written)
{
    memcpy(base, in_buf, size);
    if (bytes_written) *bytes_written = size;
    return true;
}

/* ── String formatting ───────────────────────────────────────── */
static inline int dr_snprintf(char *buf, size_t max, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf, max, fmt, ap);
    va_end(ap);
    return n;
}

/* ── Heap allocation ─────────────────────────────────────────── */
static inline void *dr_global_alloc(size_t size)   { return malloc(size); }
static inline void  dr_global_free(void *ptr, size_t size)
    { (void)size; free(ptr); }

/* ── Time / process identity ─────────────────────────────────── */
static inline uint64 dr_get_milliseconds(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64)ts.tv_sec * 1000ULL + (uint64)(ts.tv_nsec / 1000000);
}

static inline unsigned int dr_get_process_id(void)
    { return (unsigned int)getpid(); }

/* dr_time_t is a simple struct in real DynamoRIO; accept NULL here */
typedef struct { int year, month, day, hour, minute, second, milliseconds; } dr_time_t;
static inline void dr_get_time(dr_time_t *t) { (void)t; }

/* ── Mutex ───────────────────────────────────────────────────── */
static inline void *dr_mutex_create(void)    { return (void *)1; }
static inline void  dr_mutex_destroy(void *m){ (void)m; }
static inline void  dr_mutex_lock(void *m)   { (void)m; }
static inline void  dr_mutex_unlock(void *m) { (void)m; }

/* ── Directory creation ──────────────────────────────────────── */
#include <sys/stat.h>
static inline bool dr_create_dir(const char *path)
    { return mkdir(path, 0700) == 0; }

/* ── Registration ────────────────────────────────────────────── */
typedef bool (*dr_pre_syscall_event_t)(void *drcontext, int sysnum);
static inline void dr_register_pre_syscall_event(dr_pre_syscall_event_t cb)
    { (void)cb; }

static inline void dr_set_client_name(const char *name, const char *url)
    { (void)name; (void)url; }

/* ── Entry point called by DynamoRIO after injection ─────────── */
void dr_client_main(client_id_t id, int argc, const char *argv[]);
