/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SPARC64RT_RUNTIME_EXEC_STATE_H
#define SPARC64RT_RUNTIME_EXEC_STATE_H

#include "linux/exec_args.h"
#include "linux/file.h"
#include "linux/signal_exec.h"
#include "aot/authority.h"
#include "runtime/family.h"
#include "runtime/process_children.h"

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#define SPARC64_EXEC_CACHE_DIRECTORY_MAX ((size_t)8192)

#define SPARC64_EXEC_FLAG_JIT UINT32_C(1)
#define SPARC64_EXEC_FLAG_TRACE UINT32_C(2)
#define SPARC64_EXEC_FLAG_TRACE_SYSCALLS UINT32_C(4)
#define SPARC64_EXEC_FLAG_STATS UINT32_C(8)
#define SPARC64_EXEC_FLAG_FAMILY_FORKED UINT32_C(16)
#define SPARC64_EXEC_FLAG_FILE_IDENTITY_HL_APFS UINT32_C(32)
#ifdef SPARC64_RUNTIME_TEST_ATTRIBUTED_FILE
#define SPARC64_EXEC_FLAG_SERVICE_CLEANUP_DELEGATED UINT32_C(64)
#define SPARC64_EXEC_FLAG_VFORK_PENDING UINT32_C(128)
#define SPARC64_EXEC_FLAG_ALL UINT32_C(255)
#else
#define SPARC64_EXEC_FLAG_ALL UINT32_C(63)
#endif

typedef struct {
    uint64_t max_steps, steps, jit_steps, fallback_steps;
    uint64_t progress_period, stats_period, worker_attempts;
#ifdef SPARC64_RUNTIME_TEST_ATTRIBUTED_FILE
    /* Value-only internal image state; no copied mutex or service handle. */
    uint64_t fsize_soft, fsize_hard;
#endif
    uint32_t quantum, flags, xlen;
    uint32_t cache_authority, cache_blocks;
} sparc64_exec_config_t;

/* A successful native exec retires sibling guest tasks. Their clear-tid
 * stores must reach shared family pages after the old address space is gone.
 * Each record names only retained family slots, never an old guest pointer. */
typedef enum {
    SPARC64_EXEC_TID_SIBLING = 0,
    /* The exec caller's mm_release store occurs only if a different native
     * owner still uses the exact old MM at replay linearization. */
    SPARC64_EXEC_TID_CALLER_IF_LIVE_PEER = 1
} sparc64_exec_tid_role_t;

typedef struct {
    uint64_t address;
    sparc64_exec_tid_role_t role;
} sparc64_exec_tid_request_t;

typedef struct {
    sparc64_family_page_key_t keys[2];
    uint32_t offsets[2], lengths[2];
    uint32_t segment_count;
    /* Zero for object-keyed waits. Otherwise this exact old-MM guest address
     * selects the anonymous-private shared futex wait after replay. */
    uint64_t mm_shared_wake_address;
    sparc64_exec_tid_role_t role;
} sparc64_exec_tid_clear_t;

/* Process-local owned state, never a wire representation. The caller captures
 * it under the family guard after workers and native I/O are quiescent. */
typedef struct {
    sparc64_linux_exec_args_t args;
    sparc64_linux_signal_exec_state_t signals;
    sparc64_family_exec_state_t family;
    uint64_t old_mm_id;
    /* Original current-parent binding for the private pidfd transported by
     * the same-PID exec vector; zero means there was no parent capability. */
    pid_t parent_pid;
#ifdef SPARC64_RUNTIME_TEST_ATTRIBUTED_FILE
    /* Zero for borrowed sessions; a canonical same-PID exec carries the
     * exact old root/member so resume can retire it before new MM seeding. */
    uint64_t old_mm_root_object, old_mm_task_id;
#endif
    char *sysroot; /* NULL or absolute, shorter than 8192 bytes. */
    /* Value-only absolute launch-time directory spelling. No directory FD,
     * record, host code, or stage crosses native exec. */
    char *cache_directory;
    sparc64_process_child_cap_t *children;
    size_t child_count;
    sparc64_linux_fifo_identity_t *fifos;
    size_t fifo_count;
    sparc64_exec_tid_clear_t *clear_tids;
    size_t clear_tid_count;
    sparc64_exec_config_t config;
} sparc64_exec_state_t;

typedef struct sparc64_exec_state_export sparc64_exec_state_export_t;

void sparc64_exec_state_destroy(sparc64_exec_state_t *state);
/* Build a versioned, explicitly encoded state record in an unlinked 0600
 * inode. The borrowed resolver protects that inode until owner destruction.
 * Complete quiescence and a held family guard are caller preconditions. */
int sparc64_exec_state_export_create(const sparc64_exec_state_t *state,
                                sparc64_path_resolver_t *resolver,
                                sparc64_exec_state_export_t **out);
int sparc64_exec_state_export_fd(const sparc64_exec_state_export_t *owner);
int sparc64_exec_state_export_activate(sparc64_exec_state_export_t *owner);
int sparc64_exec_state_export_deactivate(sparc64_exec_state_export_t *owner);
void sparc64_exec_state_export_destroy(sparc64_exec_state_export_t **owner);
/* Early native self-exec startup: consumes an explicit owned FD >=3 on every
 * outcome, restores CLOEXEC before parsing, and leaves *out zero on failure.
 * The destination must be fresh and own no prior resources.
 * Same-UID native callers must preserve the capability provenance. */
int sparc64_exec_state_import(int owned_fd, sparc64_exec_state_t *out);

#endif
