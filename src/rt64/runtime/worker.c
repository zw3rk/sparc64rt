/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#include "runtime/worker.h"

#include <errno.h>
#include <stdlib.h>
#include <unistd.h>

static void lock_gate(sparc64_runtime_worker_t *worker)
{
    if (pthread_mutex_lock(&worker->start_lock) != 0)
        _exit(125);
}

static void unlock_gate(sparc64_runtime_worker_t *worker)
{
    if (pthread_mutex_unlock(&worker->start_lock) != 0)
        _exit(125);
}

sparc64_runtime_worker_t *sparc64_runtime_worker_create(void)
{
    sparc64_runtime_worker_t *worker = calloc(1, sizeof(*worker));
    if (worker == NULL)
        return NULL;
#ifdef SPARC64_RUNTIME_TEST_ATTRIBUTED_FILE
    worker->pending_shared_reader = -1;
#endif
    int result = pthread_mutex_init(&worker->start_lock, NULL);
    if (result != 0) {
        free(worker);
        errno = result;
        return NULL;
    }
    result = pthread_cond_init(&worker->start_changed, NULL);
    if (result != 0) {
        (void)pthread_mutex_destroy(&worker->start_lock);
        free(worker);
        errno = result;
        return NULL;
    }
    worker->start_initialized = true;
    worker->creator_pid = getpid();
    return worker;
}

int sparc64_runtime_worker_fork_child_abandon(sparc64_runtime_worker_t **owned)
{
    if (owned == NULL || *owned == NULL) {
        errno = EINVAL;
        return -1;
    }
    if ((*owned)->creator_pid == getpid()) {
        errno = EPERM;
        return -1;
    }
    free(*owned);
    *owned = NULL;
    return 0;
}

int sparc64_runtime_worker_report_ready(sparc64_runtime_worker_t *worker, bool setup_ok)
{
    if (worker == NULL || !worker->start_initialized) {
        errno = EINVAL;
        return -1;
    }
    lock_gate(worker);
    worker->setup_ok = setup_ok;
    worker->native_ready = true;
    if (pthread_cond_broadcast(&worker->start_changed) != 0)
        _exit(125);
    unlock_gate(worker);
    return 0;
}

int sparc64_runtime_worker_wait_ready(sparc64_runtime_worker_t *worker)
{
    if (worker == NULL || !worker->start_initialized) {
        errno = EINVAL;
        return -1;
    }
    lock_gate(worker);
    while (!worker->native_ready) {
        if (pthread_cond_wait(&worker->start_changed, &worker->start_lock) != 0)
            _exit(125);
    }
    int result = worker->setup_ok ? 1 : 0;
    unlock_gate(worker);
    return result;
}

int sparc64_runtime_worker_publish(sparc64_runtime_worker_t *worker, bool start)
{
    if (worker == NULL || !worker->start_initialized) {
        errno = EINVAL;
        return -1;
    }
    lock_gate(worker);
    if (!worker->native_ready || worker->start || worker->abort_start) {
        unlock_gate(worker);
        errno = EINVAL;
        return -1;
    }
    worker->start = start;
    worker->abort_start = !start;
    if (pthread_cond_broadcast(&worker->start_changed) != 0)
        _exit(125);
    unlock_gate(worker);
    return 0;
}

int sparc64_runtime_worker_wait_start(sparc64_runtime_worker_t *worker)
{
    if (worker == NULL || !worker->start_initialized) {
        errno = EINVAL;
        return -1;
    }
    lock_gate(worker);
    while (!worker->start && !worker->abort_start) {
        if (pthread_cond_wait(&worker->start_changed, &worker->start_lock) != 0)
            _exit(125);
    }
    int result = worker->start ? 1 : 0;
    unlock_gate(worker);
    return result;
}

void sparc64_runtime_worker_destroy(sparc64_runtime_worker_t *worker)
{
    if (worker == NULL)
        return;
    if (worker->start_initialized) {
        if (pthread_cond_destroy(&worker->start_changed) != 0 ||
            pthread_mutex_destroy(&worker->start_lock) != 0)
            _exit(125);
    }
    free(worker);
}
