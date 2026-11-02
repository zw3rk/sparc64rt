/*
 * src/os/threads_darwin.h — Darwin guest-futex dispatch (S64-R3-4)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Backend-contract WAIT/WAKE for the CLONE_VM futex path in
 * src/os/threads.c: validated private keys, pinned backing lifetime,
 * and per-worker signal state. Only meaningful on macOS arm64; every
 * declaration below is a no-op stub elsewhere (the .c is an empty TU
 * off Darwin, so Linux links need no extra objects).
 */

#ifndef SPARC64RT_OS_THREADS_DARWIN_H
#define SPARC64RT_OS_THREADS_DARWIN_H

#include <stdint.h>
#include <time.h>

#include "core/cpu.h"
#include "os/syscalls_min.h"

/* Real WAIT/WAIT_BITSET on the shared mapping. The big guest lock is
 * held on entry AND on return; the callee drops it across the backend
 * sleep (pinning keeps the backing alive meanwhile). Returns 0,
 * -EAGAIN, -ETIMEDOUT, -EINTR, or -EFAULT like the Linux path. */
long thr_darwin_futex_wait(sparc64_ctx_t *ctx,
    const sparc64_syscall_mem_t *mem, uint64_t uaddr, uint64_t op,
    uint64_t val, uint32_t bitset, const struct timespec *ts);

/* Guest WAKE through the keyed backend (all-bits match). The big lock
 * is held across the call. Returns the woken count or a negative
 * host errno. */
long thr_darwin_futex_wake(const sparc64_syscall_mem_t *mem,
    uint64_t uaddr, uint64_t val);

/* Release the calling host thread's worker sync (pipe, kqueue) and
 * backend table slot. Called once on worker-thread teardown. */
void thr_darwin_ws_teardown(void);

#endif /* SPARC64RT_OS_THREADS_DARWIN_H */
