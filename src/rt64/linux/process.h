/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SPARC64RT_LINUX_PROCESS_H
#define SPARC64RT_LINUX_PROCESS_H

#include <stdbool.h>
#include <stdint.h>

typedef struct {
    int32_t pid;
    uint64_t status_address;
    uint32_t options;
} sparc64_linux_wait4_request_t;

typedef struct {
    enum {
        SPARC64_LINUX_FORK_COPY_MM,
        SPARC64_LINUX_FORK_SHARE_MM,
        SPARC64_LINUX_FORK_VFORK_MM
    } mode;
    uint64_t child_stack;
    uint64_t parent_tid;
    uint64_t child_tid;
    bool parent_set_tid;
    bool child_set_tid;
    bool child_clear_tid;
} sparc64_linux_fork_request_t;

/* RISC-V raw clone uses the low 32 flag bits. Accept process-local signal
 * dispositions with either a copied MM, a shared MM, or shared-MM vfork.
 * CLONE_SIGHAND and CLONE_FILES require separate sharing contracts. Thread
 * clone has its own decoder. a1 is the optional child stack; a2 and a4 are
 * parent and child TID addresses. Unused a3 (TLS) is ignored. */
uint64_t sparc64_linux_fork_decode(const uint64_t args[6],
                              sparc64_linux_fork_request_t *out);
/* First wait4 profile: a child PID or -1, optional WNOHANG, no rusage.
 * Return a guest negative errno, leaving unsupported flags to later work. */
uint64_t sparc64_linux_wait4_decode(const uint64_t args[6],
                               sparc64_linux_wait4_request_t *out);

#endif
