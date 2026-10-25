/*
 * src/os/proc.h — Process lifecycle syscalls (Phase 4, lane L4c)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * fork(2)/vfork(66)/clone(217, no CLONE_VM)/execve(59)/wait4(7)/
 * waitid(279)/pipe(42)/pipe2(321)/dup(41)/dup2(90)/dup3(320) on top of
 * host fork/waitpid/pipe/dup. Handlers return host-style results
 * (>= 0 value, negative host errno); the dual-carry commit in
 * src/os/syscalls_min.c applies unchanged.
 *
 * Oracle-grounded SPARC conventions (qemu-sparc64 probes, not the
 * generic Linux guess):
 * - fork/vfork child: %o0 = 0, %o1 = 1; parent: %o0 = child pid,
 *   %o1 = 0. The handler sets %o1 itself and returns the %o0 value.
 * - pipe(42) takes no pointer: fds return in %o0/%o1 (handler sets
 *   %o1, returns fd[0]). pipe2(321) is (pipefd_va, flags), returns 0.
 * - glibc fork() issues clone(CLEARTID|CHILD_SETTID|SIGCHLD) without
 *   CLONE_VM; glibc vfork() issues raw vfork(66). clone() with
 *   CLONE_VM/CLONE_THREAD/CLONE_SIGHAND/CLONE_SETTLS returns -EINVAL:
 *   host-thread-backed threads belong to lane L4b.
 * - fork/vfork/clone-noVM are host fork(): the child inherits a
 *   copy-on-write snapshot of the whole guest space, so no rt64
 *   family/mm fork-protocol dance is needed in this single-threaded
 *   lane. vfork is fork with a documented immediate-execve expectation.
 * - execve reloads the image in place through the single exported
 *   loader entry sparc64_guest_exec_image (guest_run.c), keeping the
 *   host pid; the dispatch arm resumes absolutely (no pc advance).
 */

#ifndef SPARC64RT_OS_PROC_H
#define SPARC64RT_OS_PROC_H

#include <stdint.h>

#include "core/cpu.h"
#include "os/syscalls_min.h"

/* fork(2): parent gets the child pid (%o0, %o1 = 0), child gets 0
 * (%o0 = 0, %o1 = 1). Tracks the child in the internal table. */
long sparc64_proc_fork(sparc64_ctx_t *ctx,
    const sparc64_syscall_mem_t *mem);

/* vfork(66): fork with an immediate-execve expectation. */
long sparc64_proc_vfork(sparc64_ctx_t *ctx,
    const sparc64_syscall_mem_t *mem);

/* clone(217) without CLONE_VM: fork-like (child %o0 = 0, %o1 = 1).
 * Honors CLONE_PARENT_SETTID/CHILD_SETTID stores. Returns -EINVAL
 * when CLONE_VM/CLONE_THREAD/CLONE_SIGHAND/CLONE_SETTLS is set
 * (lane L4b owns host-thread-backed threads). */
long sparc64_proc_clone(sparc64_ctx_t *ctx, const sparc64_syscall_mem_t *mem,
    uint64_t flags, uint64_t stack_va, uint64_t parent_tid_va,
    uint64_t child_tid_va, uint64_t tls_va);

/* execve(59): validate ELF, close CLOEXEC, reload the image, reset
 * ctx/signals/brk/tids, keep the pid. Returns 0 with ctx already at
 * the new entry (caller resumes absolutely), else a negative errno. */
long sparc64_proc_execve(sparc64_ctx_t *ctx, const sparc64_syscall_mem_t *mem,
    uint64_t path_va, uint64_t argv_va, uint64_t envp_va);

/* Image open for sparc64_guest_exec_image lives in guest_run_priv.h
 * (implemented in proc.c) so the loader sees it without a cycle. */

/* wait4(7): host waitpid with a guest-BE status word and an optional
 * guest struct rusage. Positive pids must be known guest children. */
long sparc64_proc_wait4(sparc64_ctx_t *ctx, const sparc64_syscall_mem_t *mem,
    uint64_t pid, uint64_t status_va, uint64_t options, uint64_t rusage_va);

/* waitid(279): P_ALL/P_PID/P_PGID with a guest-BE siginfo128.
 * si_signo is translated to the SPARC SIGCHLD (20). */
long sparc64_proc_waitid(sparc64_ctx_t *ctx, const sparc64_syscall_mem_t *mem,
    uint64_t idtype, uint64_t id, uint64_t infop_va, uint64_t options,
    uint64_t rusage_va);

/* pipe(42): fds return in %o0/%o1 (handler sets %o1). */
long sparc64_proc_pipe(sparc64_ctx_t *ctx,
    const sparc64_syscall_mem_t *mem);

/* pipe2(321): (guest int[2] va, SPARC O_* flags), returns 0. */
long sparc64_proc_pipe2(sparc64_ctx_t *ctx, const sparc64_syscall_mem_t *mem,
    uint64_t fds_va, uint64_t flags);

/* dup(41)/dup2(90)/dup3(320, flags 0 or O_CLOEXEC). */
long sparc64_proc_dup(uint64_t fd);
long sparc64_proc_dup2(uint64_t oldfd, uint64_t newfd);
long sparc64_proc_dup3(uint64_t oldfd, uint64_t newfd, uint64_t flags);

#endif /* SPARC64RT_OS_PROC_H */
