/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SPARC64RT_RUNTIME_WORKER_H
#define SPARC64RT_RUNTIME_WORKER_H

#include "core/cpu.h"
#include "linux/restart.h"
#include "linux/signal.h"
#include "linux/futex.h"
#include "runtime/guest_memory.h"
#include "runtime/native_signal.h"
#include "runtime/scheduler.h"

#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

typedef struct sparc64_runtime_worker sparc64_runtime_worker_t;
struct sparc64_runtime_worker {
    sparc64_cpu_t cpu;
    sparc64_linux_signals_t signals;
    sparc64_native_signals_t *native;
    sparc64_guest_memory_worker_t *memory_worker;
    sparc64_sched_ticket_t *ticket;
    sparc64_restart_flight_t flight;
    sparc64_linux_futex_waiter_t futex_waiter;
    bool flight_active;
#ifdef SPARC64_RUNTIME_TEST_ATTRIBUTED_FILE
    /* Private parent endpoint while this worker waits for its own shared-MM
     * child JOIN/exec/exit. The family guard serializes publication/retire. */
    int pending_shared_reader;
#endif
    uint64_t clear_tid_address;
    uint32_t guest_tid;
    pthread_t host_thread;
    bool host_thread_created;
    bool joined;
    bool initial;
    bool memory_before_native; /* Restore native/memory cancellation in reverse order. */
    sparc64_runtime_worker_t *next;
    void *process; /* Borrowed until every helper has joined. */
    int exit_status;
    bool group_exit;
    bool guest_exited;
    pthread_mutex_t start_lock;
    pthread_cond_t start_changed;
    bool native_ready;
    bool setup_ok;
    bool start;
    bool abort_start;
    bool start_initialized;
    pid_t creator_pid;
};

/* Heap-stable record and publication gate. The child attaches native capture
 * and guest-memory ownership before reporting ready. Parent opens start only
 * after clone identity/TID publication; failed setup aborts and joins the
 * native thread without guest execution. No pthread cancellation is used. */
sparc64_runtime_worker_t *sparc64_runtime_worker_create(void);
int sparc64_runtime_worker_report_ready(sparc64_runtime_worker_t *worker, bool setup_ok);
int sparc64_runtime_worker_wait_ready(sparc64_runtime_worker_t *worker);
int sparc64_runtime_worker_publish(sparc64_runtime_worker_t *worker, bool start);
int sparc64_runtime_worker_wait_start(sparc64_runtime_worker_t *worker);
void sparc64_runtime_worker_destroy(sparc64_runtime_worker_t *worker);
/* Child-only after all copied waiter/flight capabilities were abandoned.
 * The copied start mutex and condition are never touched. */
int sparc64_runtime_worker_fork_child_abandon(sparc64_runtime_worker_t **owned);

#endif
