/*
 * src/os/threads_fork.c — fork-child thread-table reset (S64-R9-8)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Split from src/os/threads.c so that TU stays under the 900-line
 * limit: this file owns sparc64_threads_note_fork_child, which proc.c
 * calls on the child leg of fork/vfork/clone-noVM. Host fork() clones
 * only the calling thread, so every other slot still marked
 * used/running would be a ghost: thr_futex_wait counts live slots and
 * a ghost peer defeats the lone-thread spurious-wakeup shortcut.
 *
 * No locking here: at this point the child has exactly one thread
 * (the caller), so no peer can observe the table mid-reset.
 */

#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include "core/cpu.h"
#include "os/threads.h"

void sparc64_threads_note_fork_child(sparc64_ctx_t *ctx, void *space_ctx)
{
    unsigned i;
    int kept = 0;
    if (ctx == NULL) {
        return;
    }
    for (i = 0U; i < THR_MAX_THREADS; i++) {
        if (thr_table[i].used && thr_table[i].ctx_ref == ctx) {
            /* Survivor: refresh the tid (host pid changed) and mark
             * it plainly running (a stale done bit would hide it
             * from the live count). Robust-list state and the
             * space context survive (guest memory is CoW-shared). */
            thr_table[i].tid = (long)getpid();
            thr_table[i].running = 1;
            thr_table[i].done = 0;
            kept = 1;
        } else {
            memset(&thr_table[i], 0, sizeof(thr_table[i]));
        }
    }
    if (!kept) {
        /* The caller had no slot (fork raced boot bookkeeping):
         * install slot 0 so exactly the forking context survives. */
        thr_table[0].used = 1;
        thr_table[0].running = 1;
        thr_table[0].engine = 0;
        thr_table[0].tid = (long)getpid();
        thr_table[0].space_ctx = space_ctx;
        thr_table[0].ctx_ref = ctx;
    }
}
