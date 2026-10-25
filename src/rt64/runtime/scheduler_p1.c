/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#include "scheduler_split.h"


int sparc64_scheduler_quiesce_hook_wait(sparc64_sched_ticket_t *owner)
{
    if (owner == NULL) {
        errno = EINVAL;
        return -1;
    }
    sparc64_scheduler_t *scheduler = owner->scheduler;
    if (lock_scheduler(scheduler) != 0)
        return -1;
    if (!owned(owner) || !current(owner) ||
        scheduler->quiesce_owner != owner || scheduler->terminal ||
        scheduler->io_flights != 0) {
        (void)unlock_scheduler(scheduler);
        errno = EPERM;
        return -1;
    }
    if (scheduler->native_hook_pending == 0) {
        (void)unlock_scheduler(scheduler);
        return 1;
    }
    owner->phase = SPARC64_TICKET_OWNER_WAIT;
    scheduler->turn = NULL;
    select_next(scheduler);
    (void)unlock_scheduler(scheduler);
    return 0;
}

#ifdef SPARC64_RUNTIME_TEST_EXEC_SUSPENDED_IO
int sparc64_scheduler_test_suspended_io(sparc64_sched_ticket_t *owner, uint32_t *count)
{
    if (owner == NULL || count == NULL) {
        errno = EINVAL;
        return -1;
    }
    *count = 0;
    sparc64_scheduler_t *scheduler = owner->scheduler;
    if (lock_scheduler(scheduler) != 0)
        return -1;
    if (!owned(owner) || !current(owner) ||
        scheduler->creator_pid != getpid() ||
        scheduler->quiesce_owner != owner || scheduler->terminal ||
        scheduler->io_flights != 0 || scheduler->native_hook_pending != 0) {
        (void)unlock_scheduler(scheduler);
        errno = EPERM;
        return -1;
    }
    for (sparc64_sched_ticket_t *ticket = scheduler->all; ticket != NULL;
         ticket = ticket->all_next) {
        if (ticket == owner || !ticket->io_inflight)
            continue;
        if (!ticket->io_suspended || ticket->phase != SPARC64_TICKET_SUSPENDED ||
            *count == UINT32_MAX) {
            (void)unlock_scheduler(scheduler);
            errno = EIO;
            return -1;
        }
        ++*count;
    }
    return unlock_scheduler(scheduler);
}
#endif

int sparc64_scheduler_quiesce_abort(sparc64_sched_ticket_t *owner)
{
    if (owner == NULL) {
        errno = EINVAL;
        return -1;
    }
    sparc64_scheduler_t *scheduler = owner->scheduler;
    if (lock_scheduler(scheduler) != 0)
        return -1;
    if (!owned(owner) || !current(owner) ||
        scheduler->quiesce_owner != owner || scheduler->terminal ||
        scheduler->native_hook_pending != 0) {
        (void)unlock_scheduler(scheduler);
        errno = EPERM;
        return -1;
    }
    scheduler->quiesce_owner = NULL;
    while (scheduler->suspended_head != NULL) {
        sparc64_sched_ticket_t *ticket = scheduler->suspended_head;
        suspended_remove(scheduler, ticket);
        queue_push(scheduler, ticket);
    }
    atomic_store_explicit(&scheduler->quiescing, false, memory_order_release);
    notify_all(scheduler);
    return unlock_scheduler(scheduler);
}

int sparc64_scheduler_retire(sparc64_sched_ticket_t *ticket)
{
    if (ticket == NULL) {
        errno = EINVAL;
        return -1;
    }
    sparc64_scheduler_t *scheduler = ticket->scheduler;
    if (lock_scheduler(scheduler) != 0)
        return -1;
    if (!owned(ticket) || !current(ticket)) {
        (void)unlock_scheduler(scheduler);
        errno = EPERM;
        return -1;
    }
    ticket->phase = SPARC64_TICKET_DEAD;
    scheduler->turn = NULL;
    select_next(scheduler);
    notify_all(scheduler);
    return unlock_scheduler(scheduler);
}

int sparc64_scheduler_discard(sparc64_scheduler_t *scheduler, sparc64_sched_ticket_t *ticket)
{
    if (scheduler == NULL || ticket == NULL || ticket->scheduler != scheduler) {
        errno = EINVAL;
        return -1;
    }
    if (lock_scheduler(scheduler) != 0)
        return -1;
    if (ticket->phase == SPARC64_TICKET_RUNNING ||
        ticket->phase == SPARC64_TICKET_DEAD) {
        (void)unlock_scheduler(scheduler);
        errno = EBUSY;
        return -1;
    }
    if (ticket->queued) {
        if (ticket->phase == SPARC64_TICKET_SUSPENDED)
            suspended_remove(scheduler, ticket);
        else
            queue_remove(scheduler, ticket);
    }
    if (ticket == scheduler->turn) {
        scheduler->turn = NULL;
        select_next(scheduler);
    }
    ticket->phase = SPARC64_TICKET_DEAD;
    notify_all(scheduler);
    return unlock_scheduler(scheduler);
}

int sparc64_scheduler_terminate(sparc64_scheduler_t *scheduler)
{
    if (scheduler == NULL) {
        errno = EINVAL;
        return -1;
    }
    if (lock_scheduler(scheduler) != 0)
        return -1;
    scheduler->terminal = true;
    notify_all(scheduler);
    return unlock_scheduler(scheduler);
}

int sparc64_scheduler_ticket_destroy(sparc64_sched_ticket_t **owned_ticket)
{
    if (owned_ticket == NULL || *owned_ticket == NULL) {
        errno = EINVAL;
        return -1;
    }
    sparc64_sched_ticket_t *ticket = *owned_ticket;
    sparc64_scheduler_t *scheduler = ticket->scheduler;
    if (lock_scheduler(scheduler) != 0)
        return -1;
    if (!scheduler->terminal &&
        (ticket->phase != SPARC64_TICKET_DEAD || ticket == scheduler->turn ||
         ticket->queued)) {
        (void)unlock_scheduler(scheduler);
        errno = EBUSY;
        return -1;
    }
    /* After group termination the caller has joined every worker. Tickets
     * can still be selected or queued, but none can execute or wait again. */
    if (ticket->queued) {
        if (ticket->phase == SPARC64_TICKET_SUSPENDED)
            suspended_remove(scheduler, ticket);
        else
            queue_remove(scheduler, ticket);
    }
    if (scheduler->turn == ticket)
        scheduler->turn = NULL;
    if (scheduler->quiesce_owner == ticket)
        scheduler->quiesce_owner = NULL;
    if (ticket->io_inflight && !ticket->io_suspended) {
        if (scheduler->io_flights == 0)
            _exit(125);
        --scheduler->io_flights;
    }
    sparc64_sched_ticket_t **position = &scheduler->all;
    while (*position != NULL && *position != ticket)
        position = &(*position)->all_next;
    if (*position != ticket) {
        (void)unlock_scheduler(scheduler);
        errno = EINVAL;
        return -1;
    }
    *position = ticket->all_next;
    (void)unlock_scheduler(scheduler);
    free(ticket);
    *owned_ticket = NULL;
    return 0;
}

int sparc64_scheduler_destroy(sparc64_scheduler_t **owned_scheduler)
{
    if (owned_scheduler == NULL || *owned_scheduler == NULL) {
        errno = EINVAL;
        return -1;
    }
    sparc64_scheduler_t *scheduler = *owned_scheduler;
    if (lock_scheduler(scheduler) != 0)
        return -1;
    if (scheduler->all != NULL || scheduler->turn != NULL ||
        scheduler->queue_head != NULL || scheduler->suspended_head != NULL ||
        scheduler->quiesce_owner != NULL || scheduler->io_flights != 0) {
        (void)unlock_scheduler(scheduler);
        errno = EBUSY;
        return -1;
    }
    if (unlock_scheduler(scheduler) != 0)
        return -1;
    int result = pthread_cond_destroy(&scheduler->changed);
    if (result == 0)
        result = pthread_mutex_destroy(&scheduler->lock);
    if (result != 0) {
        errno = result;
        return -1;
    }
    free(scheduler);
    *owned_scheduler = NULL;
    return 0;
}

int sparc64_scheduler_fork_child_abandon(sparc64_scheduler_t **owned_scheduler)
{
    if (owned_scheduler == NULL || *owned_scheduler == NULL) {
        errno = EINVAL;
        return -1;
    }
    sparc64_scheduler_t *scheduler = *owned_scheduler;
    /* Never inspect a copied mutex. The parent still owns its original
     * tickets and callback frames; this process only disposes their copies
     * after the native seal and all copied I/O/futex capabilities are gone. */
    if (scheduler->creator_pid == getpid() ||
        scheduler->all == NULL || scheduler->quiesce_owner == NULL ||
        scheduler->turn != scheduler->quiesce_owner || scheduler->terminal ||
        scheduler->quiesce_owner->phase != SPARC64_TICKET_RUNNING ||
        scheduler->io_flights != 0 || scheduler->native_hook_pending != 0 ||
        !atomic_load_explicit(&scheduler->quiescing, memory_order_relaxed)) {
        errno = EPERM;
        return -1;
    }
    bool owner_found = false;
    for (sparc64_sched_ticket_t *ticket = scheduler->all; ticket != NULL;
         ticket = ticket->all_next) {
        bool is_owner = ticket == scheduler->quiesce_owner;
        if (ticket->scheduler != scheduler ||
            (is_owner ? ticket->io_inflight || ticket->io_suspended :
             (ticket->phase != SPARC64_TICKET_SUSPENDED &&
              ticket->phase != SPARC64_TICKET_BLOCKED &&
              ticket->phase != SPARC64_TICKET_DEAD)) ||
            (ticket->io_inflight && (!ticket->io_suspended ||
                                     ticket->phase != SPARC64_TICKET_SUSPENDED)) ||
            (!ticket->io_inflight && ticket->io_suspended)) {
            errno = EPERM;
            return -1;
        }
        owner_found = owner_found || is_owner;
    }
    if (!owner_found) {
        errno = EPERM;
        return -1;
    }
    sparc64_sched_ticket_t *ticket = scheduler->all;
    while (ticket != NULL) {
        sparc64_sched_ticket_t *next = ticket->all_next;
        free(ticket);
        ticket = next;
    }
    free(scheduler);
    *owned_scheduler = NULL;
    return 0;
}
