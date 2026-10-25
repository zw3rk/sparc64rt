/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#define _GNU_SOURCE 1
#include "runtime/mm_runtime_binding.h"
#include "runtime/mm_view_internal.h"
#include "linux/error.h"

#include <errno.h>
#include <fcntl.h>

static int mmap_file(sparc64_mm_view_t *view, sparc64_family_guard_t *guard,
    sparc64_linux_file_t *files, const uint64_t arguments[6], uint64_t *result)
{
    /* riscv_sys_mmap validates the byte offset before ksys_mmap_pgoff/fget. */
    if (arguments[5] % SPARC64_PAGE_SIZE != 0) {
        *result = UINT64_C(0) - 22; return 0;
    }
    if ((arguments[3] & UINT64_C(0x20)) != 0)
        return sparc64_mm_view_mmap_anon(view, guard, arguments[0], arguments[1],
            arguments[2], arguments[3], arguments[5], result);
    /* File shared mappings are an explicit unsupported policy, independent
     * of native MAP_SHARED behavior or the descriptor's access mode. */
    if ((arguments[3] & 3) != 2) {
        *result = UINT64_C(0) - ((arguments[3] & 3) == 0 ? 22u : 95u); return 0;
    }
    sparc64_fd_borrow_t borrow = {0};
    if (sparc64_fd_borrow(&files->descriptors, (uint32_t)arguments[4], &borrow) != 0) {
        if (errno != EBADF && errno != ENOMEM && errno != EMFILE && errno != ENFILE)
            return -1;
        *result = UINT64_C(0) - sparc64_linux_errno(errno); return 0;
    }
    int outcome = -1, saved = 0;
    int flags = fcntl(borrow.host_fd, F_GETFL);
    if (flags < 0) {
        saved = errno;
    }
#ifdef O_PATH
    else if ((flags & O_PATH) != 0) {
        *result = UINT64_C(0) - 9;
        outcome = 0;
    }
#endif
    else {
        outcome = sparc64_mm_view_mmap_file_private_fd(view, guard, arguments[0],
            arguments[1], arguments[2], arguments[3], borrow.host_fd,
            arguments[5], result);
        saved = errno;
    }
    /* Unborrow neither duplicates nor closes a still-live table descriptor. */
    if (sparc64_fd_unborrow(&borrow) != 0) {
        /* The root may already be published. A last-reference native close
         * error, including ENOSPC, is never a preparation rejection. */
        errno = EIO;
        return -1;
    }
    if (outcome != 0)
        errno = saved;
    return outcome;
}

int sparc64_runtime_mm_dispatch(sparc64_mm_view_t *view, sparc64_family_guard_t *guard,
    sparc64_linux_file_t *files, sparc64_linux_memory_t *memory, uint64_t number,
    const uint64_t arguments[6], uint64_t *guest_result)
{
    if (view == NULL || (number != 214 && number != 215 && number != 216 &&
                        number != 222 && number != 226))
        return 0;
    if (arguments == NULL || guest_result == NULL || memory == NULL ||
        memory != view->memory || (number == 222 &&
        (files == NULL || files->space != memory->space))) {
        errno = EINVAL; return -1;
    }
    /* Catch-up errors are fatal: never report a syscall result while retaining
     * an unapplied root. Only a later transaction's preparation ENOMEM can be
     * converted to a guest rejection. */
    if (sparc64_mm_view_refresh(view, guard) != 0)
        return -1;
    uint64_t result = 0;
    int outcome;
    switch (number) {
    case 214:
        outcome = sparc64_mm_view_brk(view, guard, arguments[0], &result);
        break;
    case 215:
        outcome = sparc64_mm_view_munmap(view, guard, arguments[0], arguments[1], &result);
        break;
    case 216:
        outcome = sparc64_mm_view_mremap(view, guard, arguments[0], arguments[1],
            arguments[2], arguments[3], arguments[4], &result);
        break;
    case 222:
        outcome = mmap_file(view, guard, files, arguments, &result);
        break;
    default: /* 226 */
        outcome = sparc64_mm_view_mprotect(view, guard, arguments[0], arguments[1],
            arguments[2], &result);
        break;
    }
    if (outcome != 0) {
        if (errno != ENOMEM && errno != ENOSPC)
            return -1;
        result = number == 214 ? memory->current_break : UINT64_C(0) - 12;
    }
    *guest_result = result;
    return 1;
}
