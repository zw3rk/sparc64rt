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

/* Classification of one (dirfd, path) pair (S64-R13-1/2): canonicalizes
 * the effective guest path (redundant slashes, "/./", "/..", dirfd
 * resolution, guest-pid and thread-self spellings) before deciding.
 * Returns SPARC64_PROC_HANDLED when path names a synthetic file this
 * TU serves (norm_out holds the canonical "/proc/self/<entry>"
 * spelling), SPARC64_PROC_BLOCKED for "/proc/self",
 * "/proc/thread-self" or "/proc/<own-pid>" with no synthetic meaning
 * (the guest call must fail -ENOENT and never reach the host tree),
 * else SPARC64_PROC_OTHER. norm_out needs room for 4096 bytes and is
 * only set for HANDLED/BLOCKED. */
#define SPARC64_PROC_OTHER 0
#define SPARC64_PROC_HANDLED 1
#define SPARC64_PROC_BLOCKED (-1)
int sparc64_guest_proc_classify(int dirfd, const char *path,
    char *norm_out);

/* openat interception: HANDLED canonical paths return a read-only
 * synthetic fd (pipe) or the reopened exe file, anything else is
 * -ENOENT (callers classify first and only invoke this for HANDLED
 * paths). host_flags are translated host O_* bits. */
long sparc64_guest_proc_openat(void *guest,
    const sparc64_syscall_mem_t *mem, const char *path, int host_flags);

/* readlinkat body: HANDLED paths serve the load path (exe, truncated
 * like readlink, no NUL) or EINVAL (synthetic regular files); BLOCKED
 * paths are -ENOENT; everything else is the host readlinkat. */
long sparc64_guest_proc_readlinkat(void *guest,
    const sparc64_syscall_mem_t *mem, uint64_t dirfd, uint64_t path_va,
    uint64_t buf_va, uint64_t bufsz);

#endif /* SPARC64RT_OS_GUEST_PROC_H */
