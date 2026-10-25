/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SPARC64RT_LINUX_FUTEX_SPLIT_H
#define SPARC64RT_LINUX_FUTEX_SPLIT_H

/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L
#include "linux/futex.h"
#include "linux/error.h"
#include "linux/futex_key.h"

#include <errno.h>
#include <limits.h>
#include <stddef.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#if defined(__linux__)
#include <sys/syscall.h>
#endif

enum {
    FUTEX_WAIT_OP = 0,
    FUTEX_WAKE_OP = 1,
    FUTEX_REQUEUE_OP = 3,
    FUTEX_CMP_REQUEUE_OP = 4,
    FUTEX_WAKE_OPERATION = 5,
    FUTEX_WAIT_BITSET_OP = 9,
    FUTEX_WAKE_BITSET_OP = 10,
    FUTEX_PRIVATE_BIT = 128,
    FUTEX_REALTIME_BIT = 256
};

typedef struct {
    sparc64_family_backing_t *backing;
    sparc64_family_wait_table_t *table;
} family_word_context_t;

/* Cross-part declarations (generated L0a split). */
uint64_t linux_error(int host_error);
bool clock_now(bool realtime, uint64_t *nanoseconds);
bool family_context(sparc64_linux_futex_t *futex, sparc64_linux_futex_context_t *context);
int family_snapshot(sparc64_linux_futex_context_t *context, sparc64_family_wait_table_t *table);
bool family_notify(sparc64_linux_futex_t *futex, const sparc64_family_wait_table_t *table);
uint32_t table_wake(sparc64_family_wait_table_t *table, sparc64_family_wait_key_t key, uint32_t count, uint32_t bitset);
bool family_wait_state(sparc64_linux_futex_t *futex, const sparc64_linux_futex_waiter_t *waiter, bool remove, bool *woken);
bool family_word_commit(void *opaque, const sparc64_managed_page_update_t *updates, size_t count);
void waiter_finish(sparc64_linux_futex_t *futex, sparc64_linux_futex_waiter_t *waiter);
bool wake_key(sparc64_linux_futex_t *futex, uint64_t address, bool private_key, uint32_t count, uint32_t bitset, uint64_t *result);
void sparc64_linux_futex_init(sparc64_linux_futex_t *futex, sparc64_space_t *space, sparc64_scheduler_t *scheduler);
void sparc64_linux_futex_bind_family(sparc64_linux_futex_t *futex, bool (*context)(void *, sparc64_linux_futex_context_t *), void *opaque);
bool sparc64_linux_futex_dispatch(sparc64_linux_futex_t *futex, sparc64_linux_futex_waiter_t *waiter, sparc64_sched_ticket_t *ticket, const uint64_t args[6], uint64_t *result, bool *waiting);
bool sparc64_linux_futex_resume(sparc64_linux_futex_t *futex, sparc64_linux_futex_waiter_t *waiter, bool deliverable_signal, uint64_t *result, sparc64_futex_resume_t *state);
bool sparc64_linux_futex_poll_interval(const sparc64_linux_futex_waiter_t *waiter, uint64_t *nanoseconds);
bool sparc64_linux_futex_cancel(sparc64_linux_futex_t *futex, sparc64_linux_futex_waiter_t *waiter);
bool sparc64_linux_futex_abandon_child_waiter(sparc64_linux_futex_t *copied, sparc64_linux_futex_waiter_t *waiter);
bool sparc64_linux_futex_clear_tid_wake(sparc64_linux_futex_t *futex, uint64_t address);
bool sparc64_linux_futex_clear_tid(sparc64_linux_futex_t *futex, uint64_t address);
bool sparc64_linux_futex_notice_woken(const sparc64_linux_futex_waiter_t *waiter);
bool sparc64_linux_futex_empty(const sparc64_linux_futex_t *futex);

#endif /* SPARC64RT_LINUX_FUTEX_SPLIT_H */
