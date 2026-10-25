/* src/os/guest_proc.h — guest /proc/self emulation (Phase 5, L5a)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Synthetic /proc/self/{exe,maps,cmdline,stat,auxv} for the guest:
 * exe resolves to the guest argv[0] path, maps reflects the
 * translator's guest mapping (app + ld.so + stack/heap), auxv matches
 * the initial-stack bytes. Read-only; anything else is -ENOENT.
 * The snapshot lives per guest state (guest is guest_state_t *,
 * opaque here to avoid a header cycle) and is replaced on execve.
 */

#ifndef SPARC64RT_OS_GUEST_PROC_H
#define SPARC64RT_OS_GUEST_PROC_H

#include <stddef.h>
#include <stdint.h>

#include "os/syscalls_min.h"

typedef struct sparc64_guest_proc sparc64_guest_proc_t;

/* Nonzero when path names a handled /proc/self file (exact match on
 * /proc/self/{exe,maps,cmdline,stat,auxv}). */
int sparc64_guest_proc_handles(const char *path);

/* Snapshot the host load path backing /proc/self/exe opens. */
void sparc64_guest_proc_note_exec(void *guest, const char *load_path);

/* Absolute host load path for /proc/self/exe (NULL when none): lets
 * execve("/proc/self/exe") re-exec the running guest image. */
const char *sparc64_guest_proc_exec_path(void *guest);

/* Snapshot argv, the auxv pairs just written to the stack, the biased
 * %sp, and the stack span for [stack] labeling. Replaces any older
 * snapshot (execve). argv strings are copied (bounded). */
int sparc64_guest_proc_note_stack(void *guest, char **argv, uint64_t argc,
    const uint64_t *keys, const uint64_t *vals, unsigned nkeys,
    uint64_t sp_biased, uint64_t stack_lo, uint64_t stack_hi);

/* Log one file-backed span (app PT_LOAD or the whole ld.so span) for
 * maps pathname labeling. Keeps the first 16 spans. */
void sparc64_guest_proc_note_map(void *guest, uint64_t lo, uint64_t hi,
    const char *path);

/* Drop the snapshot (fork child, error paths). */
void sparc64_guest_proc_forget(void *guest);

/* openat interception: handled paths return a read-only synthetic fd
 * (pipe) or the reopened exe file, else -ENOENT so the caller falls
 * through to the host. host_flags are translated host O_* bits. */
long sparc64_guest_proc_openat(void *guest,
    const sparc64_syscall_mem_t *mem, const char *path, int host_flags);

/* open(path, flags, mode) shared body (dirfd is AT_FDCWD). */
long sparc64_guest_proc_open(void *guest,
    const sparc64_syscall_mem_t *mem, uint64_t path_va, uint64_t flags,
    uint64_t mode);

/* readlinkat body: /proc/self/exe yields the absolute load path
 * (truncated like readlink, no NUL); other synthetic files are
 * regular files (EINVAL); everything else is the host readlinkat. */
long sparc64_guest_proc_readlinkat(void *guest,
    const sparc64_syscall_mem_t *mem, uint64_t dirfd, uint64_t path_va,
    uint64_t buf_va, uint64_t bufsz);

#endif /* SPARC64RT_OS_GUEST_PROC_H */
