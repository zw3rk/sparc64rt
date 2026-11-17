/*
 * src/os/proc_stackframe.h — clone() child stack frame relocation
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SPARC64RT_OS_PROC_STACKFRAME_H
#define SPARC64RT_OS_PROC_STACKFRAME_H

#include <stdint.h>

#include "core/cpu.h"
#include "os/syscalls_min.h"

/* Snapshot of the parent's current frame [%sp+2047, %fp+2047). */
typedef struct {
    uint8_t *data;
    uint64_t distance;
} sparc64_clone_frame_t;

/* Parent side (before fork), mirroring Linux clone_stackframe(): read
 * the current frame. Returns 0, -EFAULT (unreadable or %fp below %sp),
 * or -ENOMEM; on success the caller owns f->data (free it). */
long sparc64_clone_frame_capture(const sparc64_ctx_t *ctx,
                                 const sparc64_syscall_mem_t *mem,
                                 sparc64_clone_frame_t *f);

/* Child side: place the frame just below stack_va, point %sp/%fp at
 * it, and keep the in-frame saved %fp slot consistent. Returns 0 or
 * -EFAULT when the new stack is not writable. */
long sparc64_clone_frame_install(sparc64_ctx_t *ctx,
                                 const sparc64_syscall_mem_t *mem,
                                 uint64_t stack_va,
                                 const sparc64_clone_frame_t *f);

#endif /* SPARC64RT_OS_PROC_STACKFRAME_H */
