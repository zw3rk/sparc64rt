/*
 * src/os/syscalls_poll.h — blocking wait family (poll/select/sleep/locks)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Handlers return host-style results (>= 0 value, negative host errno).
 * Every blocking host call runs with the big guest lock dropped, and an
 * internal host EINTR (SIGUSR2 quiescence) is retried against a
 * monotonic deadline unless a guest signal is deliverable.
 */

#ifndef SPARC64RT_OS_SYSCALLS_POLL_H
#define SPARC64RT_OS_SYSCALLS_POLL_H

#include <stdint.h>

#include "core/cpu.h"
#include "os/syscalls_min.h"

/* poll(fds, nfds, timeout_ms); a negative timeout blocks forever. */
long sparc64_fs_poll(const sparc64_ctx_t *ctx,
                     const sparc64_syscall_mem_t *mem, uint64_t fds,
                     uint64_t nfds, int timeout_ms);

/* ppoll(fds, nfds, timespec, sigmask, sigsetsize). With a sigmask, an
 * -EINTR caused by a signal only the temporary mask unblocks delivers
 * that signal before the original mask returns; *delivered is then set
 * and the result is already committed with pc/npc redirected (the
 * dispatch tail must skip its commit and advance). */
long sparc64_fs_ppoll(sparc64_ctx_t *ctx,
                      const sparc64_syscall_mem_t *mem, uint64_t fds,
                      uint64_t nfds, uint64_t tva, uint64_t sigva,
                      uint64_t sigsetsize, int *delivered);

/* _newselect (timeval timeout). */
long sparc64_fs_select(const sparc64_ctx_t *ctx,
                       const sparc64_syscall_mem_t *mem, uint64_t nfds,
                       uint64_t r, uint64_t w, uint64_t x, uint64_t tva);

/* pselect6: sigarg points at {BE64 sigset_ptr, BE64 sigsetsize}.
 * *delivered as for ppoll. */
long sparc64_fs_pselect6(sparc64_ctx_t *ctx,
                         const sparc64_syscall_mem_t *mem, uint64_t nfds,
                         uint64_t r, uint64_t w, uint64_t x, uint64_t tva,
                         uint64_t sigarg, int *delivered);

long sparc64_fs_nanosleep(const sparc64_ctx_t *ctx,
                          const sparc64_syscall_mem_t *mem, uint64_t req,
                          uint64_t rem);

/* flock(2); the blocking forms drop the big lock. */
long sparc64_fs_flock(const sparc64_ctx_t *ctx, uint64_t fd, uint64_t op);

/* fcntl record locks: sparc64 cmds F_GETLK/F_SETLK/F_SETLKW 7/8/9 and
 * F_OFD_GETLK/F_OFD_SETLK/F_OFD_SETLKW 36/37/38. */
long sparc64_fs_fcntl_lock(const sparc64_ctx_t *ctx,
                           const sparc64_syscall_mem_t *mem, uint64_t fd,
                           uint64_t cmd, uint64_t arg);

#endif /* SPARC64RT_OS_SYSCALLS_POLL_H */
