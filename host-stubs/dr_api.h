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

typedef uint32_t client_id_t;
typedef void *   dr_context_t;   /* opaque */
typedef void *   drcontext_t;    /* per-thread context */
typedef uintptr_t reg_t;

#define DR_EXPORT __attribute__((visibility("default")))
#define STDERR    stderr          /* DynamoRIO maps STDERR -> stderr on Linux */

/* Logging */
static inline void dr_fprintf(FILE *f, const char *fmt, ...) { (void)f; (void)fmt; }

/* Syscall helpers */
static inline void dr_syscall_set_result(void *ctx, uintptr_t val) { (void)ctx; (void)val; }

/* Registration */
typedef bool (*dr_pre_syscall_event_t)(void *drcontext, int sysnum);
static inline void dr_register_pre_syscall_event(dr_pre_syscall_event_t cb) { (void)cb; }
static inline void dr_set_client_name(const char *name, const char *url)    { (void)name; (void)url; }

/* Entry point called by DynamoRIO after injection */
void dr_client_main(client_id_t id, int argc, const char *argv[]);
