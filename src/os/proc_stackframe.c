/*
 * src/os/proc_stackframe.c — clone() child stack frame relocation
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Linux never installs the clone stack pointer verbatim: copy_thread
 * runs clone_stackframe(), which copies the caller's current frame
 * [%sp+2047, %fp+2047) to just below the new stack top and starts the
 * child at %sp = (stack + 2047 - distance) - 2047. Without it the
 * child's first window spill lands at or above the top of the mapping
 * glibc's posix_spawn provides.
 */

#include "os/proc_stackframe.h"

#include <errno.h>
#include <stdlib.h>

#include "os/syscalls_min.h"

/* Upper bound on a single frame (guards the staging allocation). */
#define CLONE_FRAME_MAX (1024U * 1024U)
/* ins[6] (saved %fp) inside a register-window save area. */
#define CLONE_FRAME_FP_OFF 0x70U

long sparc64_clone_frame_capture(const sparc64_ctx_t *ctx,
                                 const sparc64_syscall_mem_t *mem,
                                 sparc64_clone_frame_t *f)
{
    uint64_t psp = ctx->r[SPARC64_SP] + SPARC64_STACK_BIAS;
    uint64_t pfp = ctx->r[SPARC64_FP] + SPARC64_STACK_BIAS;
    uint64_t distance;

    f->data = NULL;
    f->distance = 0U;
    if (pfp < psp || pfp - psp > CLONE_FRAME_MAX) {
        return -EFAULT;
    }
    distance = pfp - psp;
    if (distance == 0U) {
        return 0;
    }
    f->data = (uint8_t *)malloc((size_t)distance);
    if (f->data == NULL) {
        return -ENOMEM;
    }
    if (!mem->read(mem->context, psp, f->data, distance)) {
        free(f->data);
        f->data = NULL;
        return -EFAULT;
    }
    f->distance = distance;
    return 0;
}

long sparc64_clone_frame_install(sparc64_ctx_t *ctx,
                                 const sparc64_syscall_mem_t *mem,
                                 uint64_t stack_va,
                                 const sparc64_clone_frame_t *f)
{
    uint64_t csp;
    uint8_t fp_be[8];
    unsigned i;

    if (f->distance > stack_va + SPARC64_STACK_BIAS) {
        return -EFAULT;
    }
    csp = (stack_va + SPARC64_STACK_BIAS) - f->distance;
    if (f->distance != 0U) {
        if (!mem->prepare_write(mem->context, csp, f->distance) ||
            !mem->write(mem->context, csp, f->data, f->distance)) {
            return -EFAULT;
        }
        /* Re-point the copied frame's saved %fp at the new stack top,
         * as the kernel does (only when the frame holds the slot). */
        if (f->distance > CLONE_FRAME_FP_OFF + 7U) {
            for (i = 0U; i < 8U; i++) {
                fp_be[i] = (uint8_t)(stack_va >> (56U - 8U * i));
            }
            if (!mem->write(mem->context, csp + CLONE_FRAME_FP_OFF, fp_be,
                            sizeof fp_be)) {
                return -EFAULT;
            }
        }
    }
    /* The current window is live in ctx->r (its winsp is not cached
     * until the next SAVE/RESTORE), so updating %sp/%fp is enough. */
    ctx->r[SPARC64_SP] = csp - SPARC64_STACK_BIAS;
    ctx->r[SPARC64_FP] = stack_va;
    return 0;
}
