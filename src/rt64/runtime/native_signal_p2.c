/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#include "native_signal_split.h"


bool sparc64_native_signal_process_request_wake(sparc64_native_signal_process_t *process,
                                            uint32_t guest_tid)
{
    if (!local_process(process) ||
        process->teardown_only || process->stop_signal == 0) {
        errno = EINVAL;
        return false;
    }
    int error = lock_registration(process);
    if (error != 0) {
        errno = error;
        return false;
    }
    bool found = false;
    int first_error = 0;
    if (process->stopped)
        first_error = ECANCELED;
    for (sparc64_native_signals_t *worker = process->workers;
         first_error == 0 && worker != NULL;
         worker = worker->registration_next) {
        if (worker->guest_tid == 0 ||
            (guest_tid != 0 && worker->guest_tid != guest_tid))
            continue;
        found = true;
        /* A prior wake can remain pending while the carrier is blocked. One
         * native instance then suffices for any number of coalesced guest
         * standard signals, and the guard serializes their publication. */
        atomic_store_explicit(&worker->wake, 1, memory_order_release);
        if (pthread_equal(worker->owner, pthread_self()))
            continue;
        unsigned int empty = 0;
        if (!atomic_compare_exchange_strong_explicit(&worker->kick_pending,
                &empty, 1, memory_order_acq_rel, memory_order_acquire))
            continue;
        error = pthread_kill(worker->owner, process->stop_signal);
        if (error != 0) {
            atomic_store_explicit(&worker->kick_pending, 0, memory_order_release);
            first_error = error;
        }
    }
    if (pthread_mutex_unlock(&process->registration_lock) != 0)
        _exit(125);
    if (first_error != 0 || (guest_tid != 0 && !found)) {
        errno = first_error != 0 ? first_error : ESRCH;
        return false;
    }
    return true;
}

static bool worker_detach_internal(sparc64_native_signals_t *signals, bool free_worker)
{
    if (!local_worker(signals) || signals->detached || signals->pipe_active) {
        errno = EINVAL;
        return false;
    }
    if (!sparc64_native_signals_block(signals))
        return false;
    sigset_t child_only;
    sigemptyset(&child_only);
    sigaddset(&child_only, SIGCHLD);
    int child_error = pthread_sigmask(SIG_BLOCK, &child_only, NULL);
    if (child_error != 0) {
        errno = child_error;
        return false;
    }
    sparc64_native_signal_process_t *process = signals->process;
    int error = lock_registration(process);
    if (error != 0) {
        errno = error;
        return false;
    }
    signals->teardown_only = true;
#ifdef __linux__
    if (process->stop_signal != 0) {
        sigset_t only_stop;
        sigemptyset(&only_stop);
        sigaddset(&only_stop, process->stop_signal);
        const struct timespec zero = {0, 0};
        while (sigtimedwait(&only_stop, NULL, &zero) >= 0) {
        }
        if (errno != EAGAIN) {
            int saved = errno;
            if (pthread_mutex_unlock(&process->registration_lock) != 0)
                _exit(125);
            errno = saved;
            return false;
        }
    }
#endif
    sparc64_native_signals_t **link = &process->workers;
    while (*link != NULL && *link != signals)
        link = &(*link)->registration_next;
    if (*link != signals)
        _exit(125);
    if (!restore_worker_stack(signals)) {
        int saved = errno;
        if (pthread_mutex_unlock(&process->registration_lock) != 0)
            _exit(125);
        errno = saved;
        return false;
    }
    *link = signals->registration_next;
    int old_cancel_state = signals->prior_cancel_state;
    atomic_store_explicit(&native_signals, NULL, memory_order_release);
    atomic_fetch_sub_explicit(&process->attached_workers, 1, memory_order_acq_rel);
    free(signals->stack);
    signals->stack = NULL;
    signals->stack_installed = false;
    signals->detached = true;
    if (free_worker) {
        free(signals);
    }
    /* Disposal precedes unlock: a seal cannot copy a removed worker's heap
     * or stack after losing the registry entry needed to abandon it. */
    if (pthread_mutex_unlock(&process->registration_lock) != 0)
        _exit(125);
    if (free_worker && pthread_setcancelstate(old_cancel_state, NULL) != 0)
        _exit(125);
    return true;
}

bool sparc64_native_signal_process_request_stop(sparc64_native_signal_process_t *process)
{
    if (!local_process(process) ||
        process->teardown_only || process->stop_signal == 0) {
        errno = EINVAL;
        return false;
    }
    int error = lock_registration(process);
    if (error != 0) {
        errno = error;
        return false;
    }
    if (process->stopped) {
        if (pthread_mutex_unlock(&process->registration_lock) != 0)
            _exit(125);
        return true; /* The first request latched and kicked every owner. */
    }
    int first_error = 0;
    process->stopped = true;
    for (sparc64_native_signals_t *worker = process->workers; worker != NULL;
         worker = worker->registration_next) {
        atomic_store_explicit(&worker->stop, 1, memory_order_release);
        atomic_store_explicit(&worker->wake, 1, memory_order_release);
        if (!pthread_equal(worker->owner, pthread_self())) {
            error = pthread_kill(worker->owner, process->stop_signal);
            if (error != 0 && first_error == 0)
                first_error = error;
        }
    }
    if (pthread_mutex_unlock(&process->registration_lock) != 0)
        _exit(125);
    if (first_error != 0) {
        errno = first_error;
        return false;
    }
    return true;
}

bool sparc64_native_signals_stop_requested(const sparc64_native_signals_t *signals)
{
    if (!local_worker(signals)) {
        errno = EINVAL;
        return false;
    }
    return atomic_load_explicit(&signals->stop, memory_order_acquire) != 0;
}

bool sparc64_native_signal_worker_detach(sparc64_native_signals_t *signals)
{
    if (signals == NULL || signals->compatibility_owner) {
        errno = EINVAL; /* The compatibility wrapper owns its process too. */
        return false;
    }
    return worker_detach_internal(signals, true);
}

sparc64_native_signals_t *sparc64_native_signals_create(void)
{
    sparc64_native_signal_process_t *process = sparc64_native_signal_process_create();
    if (process == NULL)
        return NULL;
    sparc64_native_signals_t *signals = sparc64_native_signal_worker_attach(process);
    if (signals == NULL) {
        int saved = errno;
        if (!sparc64_native_signal_process_destroy(process))
            _exit(125);
        errno = saved;
        return NULL;
    }
    signals->compatibility_owner = true;
    return signals;
}

bool sparc64_native_signals_destroy(sparc64_native_signals_t *signals)
{
    if (signals == NULL || !local_process(signals->process) ||
        !signals->compatibility_owner || !pthread_equal(signals->owner, pthread_self())) {
        errno = EINVAL;
        return false;
    }
    sparc64_native_signal_process_t *process = signals->process;
    if (!signals->detached) {
        if (atomic_load_explicit(&process->attached_workers, memory_order_acquire) != 1) {
            errno = EBUSY;
            return false;
        }
        if (!worker_detach_internal(signals, false))
            return false;
    }
    int old_cancel_state = process->creator_cancel_state;
    if (!process_destroy_internal(process, false, true))
        return false;
    free(signals);
    if (pthread_setcancelstate(old_cancel_state, NULL) != 0)
        _exit(125);
    return true;
}
