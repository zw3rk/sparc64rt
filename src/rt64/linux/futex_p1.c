/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#include "futex_split.h"


bool sparc64_linux_futex_resume(sparc64_linux_futex_t *futex,
                            sparc64_linux_futex_waiter_t *waiter,
                            bool deliverable_signal, uint64_t *result,
                            sparc64_futex_resume_t *state)
{
    if (futex == NULL || waiter == NULL || waiter->backing == NULL ||
        result == NULL || state == NULL) {
        errno = EINVAL;
        return false;
    }
    bool woken = atomic_load_explicit(&waiter->woken, memory_order_acquire);
    if (waiter->wait_id != 0 &&
        !family_wait_state(futex, waiter, false, &woken))
        return false;
    if (woken) {
        if (waiter->wait_id != 0 &&
            !family_wait_state(futex, waiter, true, &woken))
            return false;
        *result = 0;
        *state = SPARC64_FUTEX_COMPLETE;
        waiter_finish(futex, waiter);
        return true;
    }
    if (waiter->has_deadline) {
        uint64_t now;
        if (!clock_now(waiter->realtime, &now))
            return false;
        if (now >= waiter->deadline_ns) {
            if (waiter->wait_id != 0 &&
                !family_wait_state(futex, waiter, true, &woken))
                return false;
            *result = linux_error(ETIMEDOUT);
            *state = SPARC64_FUTEX_COMPLETE;
            waiter_finish(futex, waiter);
            return true;
        }
    }
    if (deliverable_signal) {
        if (waiter->wait_id != 0 &&
            !family_wait_state(futex, waiter, true, &woken))
            return false;
        *result = linux_error(EINTR);
        *state = SPARC64_FUTEX_COMPLETE;
        waiter_finish(futex, waiter);
        return true;
    }
    *state = SPARC64_FUTEX_PENDING;
    return true;
}

bool sparc64_linux_futex_poll_interval(const sparc64_linux_futex_waiter_t *waiter,
                                   uint64_t *nanoseconds)
{
    if (waiter == NULL || waiter->backing == NULL || nanoseconds == NULL) {
        errno = EINVAL;
        return false;
    }
    uint64_t interval = UINT64_C(10000000);
    if (waiter->has_deadline) {
        uint64_t now;
        if (!clock_now(waiter->realtime, &now))
            return false;
        uint64_t remaining = now >= waiter->deadline_ns ?
            0 : waiter->deadline_ns - now;
        if (remaining < interval)
            interval = remaining;
    }
    *nanoseconds = interval;
    return true;
}

bool sparc64_linux_futex_cancel(sparc64_linux_futex_t *futex,
                            sparc64_linux_futex_waiter_t *waiter)
{
    if (futex != NULL && waiter != NULL && waiter->backing != NULL) {
        bool woken;
        if (waiter->wait_id != 0 &&
            !family_wait_state(futex, waiter, true, &woken))
            return false;
        waiter_finish(futex, waiter);
    }
    return true;
}

bool sparc64_linux_futex_abandon_child_waiter(sparc64_linux_futex_t *copied,
                                         sparc64_linux_futex_waiter_t *waiter)
{
    if (copied == NULL || waiter == NULL || copied->owner_pid == 0 ||
        copied->owner_pid == getpid()) {
        errno = EPERM;
        return false;
    }
    if (waiter->queued) {
        bool found = false;
        for (sparc64_linux_futex_waiter_t *entry = copied->head;
             entry != NULL; entry = entry->next)
            found = found || entry == waiter;
        if (!found) {
            errno = EINVAL;
            return false;
        }
    } else if (waiter->next != NULL) {
        errno = EINVAL;
        return false;
    }
    waiter_finish(copied, waiter);
    waiter->next = NULL;
    waiter->queued = false;
    return true;
}

bool sparc64_linux_futex_clear_tid_wake(sparc64_linux_futex_t *futex, uint64_t address)
{
    uint64_t ignored;
    return wake_key(futex, address, false, 1, UINT32_MAX, &ignored);
}

bool sparc64_linux_futex_clear_tid(sparc64_linux_futex_t *futex, uint64_t address)
{
    const unsigned char zero[4] = {0};
    if (!sparc64_space_prepare_write(futex->space, address, sizeof(zero)))
        return !sparc64_fault_is_runtime(futex->space->fault_reason);
    if (futex->family_context == NULL)
        return sparc64_space_write(futex->space, address, zero, sizeof(zero)) &&
               sparc64_linux_futex_clear_tid_wake(futex, address);
    sparc64_linux_futex_context_t context;
    if (!family_context(futex, &context))
        return false;
    sparc64_family_wait_key_t key;
    uint64_t error;
    if (!sparc64_linux_futex_key(context.memory, context.backing, context.mm_id,
                             address, false, true, &key, &error))
        return false;
    sparc64_family_wait_table_t table = {0};
    if (family_snapshot(&context, &table) != 0) {
        sparc64_family_wait_table_destroy(&table);
        return false;
    }
    if (error == 0)
        (void)table_wake(&table, key, 1, UINT32_MAX);
    family_word_context_t commit = {context.backing, &table};
    bool success = sparc64_space_write_word_commit(futex->space, address, zero,
                                               family_word_commit, &commit) &&
                   family_notify(futex, &table);
    sparc64_family_wait_table_destroy(&table);
    return success;
}

bool sparc64_linux_futex_notice_woken(const sparc64_linux_futex_waiter_t *waiter)
{
    return waiter != NULL &&
           atomic_load_explicit(&waiter->woken, memory_order_acquire);
}

bool sparc64_linux_futex_empty(const sparc64_linux_futex_t *futex)
{
    return futex == NULL || futex->head == NULL;
}
