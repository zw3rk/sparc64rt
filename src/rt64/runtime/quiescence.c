/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#include "runtime/quiescence.h"

#include <errno.h>
#include <unistd.h>

int sparc64_quiescence_begin(sparc64_sched_ticket_t *owner,
                        sparc64_native_signal_process_t *native_process)
{
    if (owner == NULL || native_process == NULL) {
        errno = EINVAL;
        return -1;
    }
    if (sparc64_scheduler_quiesce_begin(owner) != 0)
        return -1;
    /* A broadcast failure may follow partial fanout. Guest I/O may already
     * have been interrupted, so an ordinary failed-prepare return would
     * falsely promise a clean, fully resumable state. */
    if (!sparc64_native_signal_process_request_wake(native_process, 0))
        _exit(125);
    return 0;
}

int sparc64_quiescence_wait(sparc64_sched_ticket_t *owner,
                       sparc64_guest_memory_worker_t *memory_worker)
{
    if (owner == NULL || memory_worker == NULL) {
        errno = EINVAL;
        return -1;
    }
    for (;;) {
        int state = sparc64_scheduler_quiesce_wait(owner);
        if (state < 0)
            return -1;
        if (state == 1)
            return 1;
        if (sparc64_guest_memory_worker_leave(memory_worker) != 0)
            return -1;
        int admitted = sparc64_scheduler_wait_turn(owner);
        if (admitted < 0 || sparc64_guest_memory_worker_enter(memory_worker) != 0)
            return -1;
        if (admitted == 0)
            return 0;
    }
}

int sparc64_quiescence_checkpoint(sparc64_sched_ticket_t *ticket,
                             sparc64_guest_memory_worker_t *memory_worker)
{
    if (ticket == NULL || memory_worker == NULL) {
        errno = EINVAL;
        return -1;
    }
    int state = sparc64_scheduler_quiesce_checkpoint(ticket);
    if (state <= 0)
        return state < 0 ? -1 : 1;
    if (sparc64_guest_memory_worker_leave(memory_worker) != 0)
        return -1;
    int admitted = sparc64_scheduler_wait_turn(ticket);
    if (admitted < 0 || sparc64_guest_memory_worker_enter(memory_worker) != 0)
        return -1;
    return admitted;
}

int sparc64_quiescence_abort(sparc64_sched_ticket_t *owner)
{
    return sparc64_scheduler_quiesce_abort(owner);
}

int sparc64_quiescence_native_phase(sparc64_sched_ticket_t *owner,
                               sparc64_guest_memory_worker_t *memory_worker,
                               sparc64_native_signal_process_t *native_process,
                               unsigned int phase)
{
    if (owner == NULL || memory_worker == NULL || native_process == NULL ||
        phase == 0) {
        errno = EINVAL;
        return -1;
    }
    if (sparc64_scheduler_quiesce_hook_begin(owner, phase) != 0)
        return -1;
    if (!sparc64_native_signal_process_request_wake(native_process, 0))
        _exit(125);
    for (;;) {
        int state = sparc64_scheduler_quiesce_hook_wait(owner);
        if (state < 0)
            return -1;
        if (state == 1)
            return 1;
        if (sparc64_guest_memory_worker_leave(memory_worker) != 0)
            return -1;
        int admitted = sparc64_scheduler_wait_turn(owner);
        if (admitted < 0 || sparc64_guest_memory_worker_enter(memory_worker) != 0)
            return -1;
        if (admitted == 0)
            return 0;
    }
}
