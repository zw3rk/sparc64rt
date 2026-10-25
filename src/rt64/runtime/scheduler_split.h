/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SPARC64RT_RUNTIME_SCHEDULER_SPLIT_H
#define SPARC64RT_RUNTIME_SCHEDULER_SPLIT_H

/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#include "runtime/scheduler.h"

#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <unistd.h>

typedef enum {
    SPARC64_TICKET_RUNNABLE,
    SPARC64_TICKET_SELECTED,
    SPARC64_TICKET_RUNNING,
    SPARC64_TICKET_BLOCKED,
    SPARC64_TICKET_SUSPENDED,
    SPARC64_TICKET_OWNER_WAIT,
    SPARC64_TICKET_DEAD
} ticket_phase_t;

struct sparc64_sched_ticket {
    sparc64_scheduler_t *scheduler;
    sparc64_sched_ticket_t *all_next;
    sparc64_sched_ticket_t *queue_next;
    pthread_t owner;
    ticket_phase_t phase;
    uint32_t remaining;
    unsigned int sequence_length;
    bool attached;
    bool queued;
    bool io_inflight;
    bool io_suspended;
    sparc64_sched_native_hook_fn native_hook;
    void *native_hook_context;
    uint64_t native_hook_ack;
    uint64_t native_hook_requested;
};

struct sparc64_scheduler {
    pthread_mutex_t lock;
    pthread_cond_t changed;
    sparc64_sched_ticket_t *all;
    sparc64_sched_ticket_t *queue_head;
    sparc64_sched_ticket_t *queue_tail;
    sparc64_sched_ticket_t *suspended_head;
    sparc64_sched_ticket_t *suspended_tail;
    sparc64_sched_ticket_t *turn;
    sparc64_sched_ticket_t *quiesce_owner;
    _Atomic bool quiescing;
    size_t io_flights;
    size_t native_hook_pending;
    uint64_t native_hook_epoch;
    unsigned int native_hook_phase;
    uint32_t quantum;
    bool terminal;
    pid_t creator_pid;
};

/* Cross-part declarations (generated L0a split). */
int lock_scheduler(sparc64_scheduler_t *scheduler);
int unlock_scheduler(sparc64_scheduler_t *scheduler);
void notify_all(sparc64_scheduler_t *scheduler);
bool owned(const sparc64_sched_ticket_t *ticket);
bool current(const sparc64_sched_ticket_t *ticket);
void queue_push(sparc64_scheduler_t *scheduler, sparc64_sched_ticket_t *ticket);
void suspended_remove(sparc64_scheduler_t *scheduler, sparc64_sched_ticket_t *ticket);
void queue_remove(sparc64_scheduler_t *scheduler, sparc64_sched_ticket_t *ticket);
void select_next(sparc64_scheduler_t *scheduler);
int sparc64_scheduler_create(sparc64_scheduler_t **out, sparc64_sched_ticket_t **initial, uint32_t quantum);
int sparc64_scheduler_add(sparc64_sched_ticket_t *current_ticket, sparc64_sched_ticket_t **child);
int sparc64_scheduler_attach(sparc64_sched_ticket_t *ticket);
int sparc64_scheduler_wait_turn(sparc64_sched_ticket_t *ticket);
int sparc64_scheduler_budget(sparc64_sched_ticket_t *ticket, uint32_t *budget, bool *interpreter_only);
int sparc64_scheduler_account(sparc64_sched_ticket_t *ticket, uint32_t retired, sparc64_sched_sequence_t sequence, sparc64_sched_decision_t *decision);
int sparc64_scheduler_yield(sparc64_sched_ticket_t *ticket);
int sparc64_scheduler_park(sparc64_sched_ticket_t *ticket);
int sparc64_scheduler_wake(sparc64_scheduler_t *scheduler, sparc64_sched_ticket_t *ticket);
int sparc64_scheduler_io_begin(sparc64_sched_ticket_t *ticket);
int sparc64_scheduler_io_end(sparc64_sched_ticket_t *ticket);
int sparc64_scheduler_io_suspend(sparc64_sched_ticket_t *ticket);
int sparc64_scheduler_io_resume(sparc64_sched_ticket_t *ticket);
int sparc64_scheduler_quiesce_begin(sparc64_sched_ticket_t *owner);
bool sparc64_scheduler_quiesce_pending(const sparc64_sched_ticket_t *ticket);
int sparc64_scheduler_quiesce_ready(sparc64_sched_ticket_t *owner);
int sparc64_scheduler_quiesce_wait(sparc64_sched_ticket_t *owner);
int sparc64_scheduler_quiesce_checkpoint(sparc64_sched_ticket_t *ticket);
int sparc64_scheduler_native_hook_bind(sparc64_sched_ticket_t *ticket, sparc64_sched_native_hook_fn hook, void *context);
int sparc64_scheduler_parked_native_hook(sparc64_sched_ticket_t *ticket);
int sparc64_scheduler_quiesce_hook_begin(sparc64_sched_ticket_t *owner, unsigned int phase);
int sparc64_scheduler_quiesce_hook_wait(sparc64_sched_ticket_t *owner);
#ifdef SPARC64_RUNTIME_TEST_EXEC_SUSPENDED_IO
int sparc64_scheduler_test_suspended_io(sparc64_sched_ticket_t *owner, uint32_t *count);
#endif

int sparc64_scheduler_quiesce_abort(sparc64_sched_ticket_t *owner);
int sparc64_scheduler_retire(sparc64_sched_ticket_t *ticket);
int sparc64_scheduler_discard(sparc64_scheduler_t *scheduler, sparc64_sched_ticket_t *ticket);
int sparc64_scheduler_terminate(sparc64_scheduler_t *scheduler);
int sparc64_scheduler_ticket_destroy(sparc64_sched_ticket_t **owned_ticket);
int sparc64_scheduler_destroy(sparc64_scheduler_t **owned_scheduler);
int sparc64_scheduler_fork_child_abandon(sparc64_scheduler_t **owned_scheduler);

#endif /* SPARC64RT_RUNTIME_SCHEDULER_SPLIT_H */
