/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SPARC64RT_LINUX_FUTEX_H
#define SPARC64RT_LINUX_FUTEX_H

#include "memory/space.h"
#include "memory/family_backing.h"
#include "linux/memory.h"
#include "runtime/scheduler.h"
#include "runtime/family_wait.h"

#include <stdbool.h>
#include <stdatomic.h>
#include <stdint.h>
#include <sys/types.h>

typedef struct sparc64_linux_futex_waiter sparc64_linux_futex_waiter_t;
struct sparc64_linux_futex_waiter {
    sparc64_linux_futex_waiter_t *next;
    sparc64_backing_t *backing; /* Original lifetime anchor across unmap/requeue, not key. */
    sparc64_sched_ticket_t *ticket;
    uint64_t address;
    uint64_t deadline_ns;
    uint32_t bitset;
    bool private_key;
    bool has_deadline;
    bool realtime;
    bool queued;
    uint64_t wait_id, owner_incarnation, mm_id, worker_id;
    _Atomic bool woken; /* The sole observation permitted without the guard. */
};

typedef struct {
    sparc64_family_guard_t *guard;
    sparc64_family_backing_t *backing;
    sparc64_linux_memory_t *memory;
    uint64_t mm_id, worker_id;
} sparc64_linux_futex_context_t;

typedef struct {
    sparc64_space_t *space; /* Borrowed until every waiter has completed. */
    sparc64_scheduler_t *scheduler;
    sparc64_linux_futex_waiter_t *head, *tail;
    pid_t owner_pid;
    bool (*family_context)(void *context, sparc64_linux_futex_context_t *out);
    void *context;
} sparc64_linux_futex_t;

typedef enum {
    SPARC64_FUTEX_PENDING,
    SPARC64_FUTEX_COMPLETE
} sparc64_futex_resume_t;

/* Every call except notice_woken requires the caller's held family guard.
 * A bound manager uses family-owned rows and tagged mm/object keys. An unbound
 * manager is the local reference implementation used by focused units. No guest
 * pointer is passed to a native futex syscall. Scheduler tickets and waiters
 * are heap-stable and remain strictly process-local. */
void sparc64_linux_futex_init(sparc64_linux_futex_t *futex, sparc64_space_t *space,
                         sparc64_scheduler_t *scheduler);
/* The callback supplies only the calling worker's currently held guard. Its
 * result is borrowed for one uninterrupted call, never retained across a poll. */
void sparc64_linux_futex_bind_family(sparc64_linux_futex_t *futex,
    bool (*context)(void *, sparc64_linux_futex_context_t *), void *opaque);
bool sparc64_linux_futex_dispatch(sparc64_linux_futex_t *futex,
                              sparc64_linux_futex_waiter_t *waiter,
                              sparc64_sched_ticket_t *ticket,
                              const uint64_t args[6], uint64_t *result,
                              bool *waiting);
/* Resume after the caller has reacquired the guard. Poll/selection alone is
 * not a futex wake: only a matching WAKE sets woken. A deliverable signal
 * interrupts a still-queued waiter; wake has priority over timeout/signal. */
bool sparc64_linux_futex_resume(sparc64_linux_futex_t *futex,
                            sparc64_linux_futex_waiter_t *waiter,
                            bool deliverable_signal, uint64_t *result,
                            sparc64_futex_resume_t *state);
/* Fresh native clock sample; cap every token-free poll at 10 ms. Zero means
 * the deadline is already due and the caller should reenter without sleep. */
bool sparc64_linux_futex_poll_interval(const sparc64_linux_futex_waiter_t *waiter,
                                   uint64_t *nanoseconds);
/* Called under the guard during group terminal teardown, if still waiting. */
bool sparc64_linux_futex_cancel(sparc64_linux_futex_t *futex,
                            sparc64_linux_futex_waiter_t *waiter);
/* Child-only after the parent scheduler/native/lifecycle seals and native
 * fork. Visit EVERY copied worker's waiter, including WAKE-removed waiters
 * that have not resumed and requeued waiters retaining their original pin.
 * Release backing refs before copied workers/space/backing destruction. No
 * copied guard, scheduler wake, clear-tid store or native mutex is used. The
 * copied initialized manager's PID rejects same-process disposal. Initialize
 * a fresh child manager after all inherited waiters have been abandoned. */
bool sparc64_linux_futex_abandon_child_waiter(sparc64_linux_futex_t *copied,
                                         sparc64_linux_futex_waiter_t *waiter);
/* Kernel clear_child_tid performs a shared-namespace wake after a successful
 * best-effort zero store. This helper does not repeat that store. */
bool sparc64_linux_futex_clear_tid_wake(sparc64_linux_futex_t *futex, uint64_t address);
/* Best-effort clear with recoverable shared zero+wake publication. Guest
 * access faults are ignored as mm_release does; internal failures are fatal. */
bool sparc64_linux_futex_clear_tid(sparc64_linux_futex_t *futex, uint64_t address);
bool sparc64_linux_futex_notice_woken(const sparc64_linux_futex_waiter_t *waiter);
bool sparc64_linux_futex_empty(const sparc64_linux_futex_t *futex);

#endif
