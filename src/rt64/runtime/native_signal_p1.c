/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#include "native_signal_split.h"


bool sparc64_native_signal_fork_captured_export(
    const sparc64_native_signal_fork_freeze_t *seal,
    sparc64_native_signal_captured_t *records, size_t capacity,
    size_t *out_count)
{
    size_t required = 0;
    if (!captured_scan(seal, NULL, &required))
        return false;
    if (out_count == NULL || capacity < required ||
        (required != 0 && records == NULL)) {
        errno = capacity < required ? ENOSPC : EINVAL;
        return false;
    }
    /* The held registration seal and blocked capture windows make this
     * second scan stable. Only now may caller memory be written. */
    size_t written = 0;
    if (!captured_scan(seal, records, &written))
        _exit(125);
    if (written != required)
        _exit(125);
    *out_count = written;
    return true;
}

bool sparc64_native_signal_fork_child_rebase(sparc64_native_signal_process_t **owned,
                                        sparc64_native_signals_t **surviving,
                                        sparc64_native_signal_fork_freeze_t **sealed,
                                        uint32_t new_guest_tid)
{
    if (owned == NULL || surviving == NULL || sealed == NULL ||
        (void *)owned == (void *)surviving || (void *)owned == (void *)sealed ||
        (void *)surviving == (void *)sealed || new_guest_tid == 0) {
        errno = EINVAL;
        return false;
    }
    sparc64_native_signal_process_t *copied = *owned;
    sparc64_native_signals_t *survivor = *surviving;
    sparc64_native_signal_fork_freeze_t *freeze = *sealed;
    if (copied != NULL && copied->local_pid == getpid()) {
        errno = EPERM;
        return false;
    }
    if (copied == NULL || survivor == NULL || freeze == NULL ||
        native_fork_freeze != freeze || freeze->process != copied ||
        freeze->survivor != survivor || freeze->parent_pid != copied->local_pid ||
        copied->freeze != freeze || freeze->generation != copied->freeze_generation ||
        atomic_load(&process_owner) != copied ||
        atomic_load(&native_signals) != survivor || survivor->process != copied ||
        copied->teardown_only || !copied->mask_saved ||
        copied->actions_installed != copied->carrier_count ||
        survivor->detached || survivor->teardown_only || survivor->open ||
        survivor->pipe_active || !survivor->stack_installed) {
        errno = EINVAL;
        return false;
    }
    /* Never inspect a copied pthread owner or acquire the copied lock. The
     * complete frozen registry is plain child-local ownership metadata. */
    uint32_t count = atomic_load_explicit(&copied->attached_workers,
                                          memory_order_acquire);
    uint32_t visited = 0;
    bool found = false;
    for (sparc64_native_signals_t *worker = copied->workers; worker != NULL;
         worker = worker->registration_next) {
        if (visited == count || worker->process != copied || worker->detached ||
            worker->teardown_only || worker->open || !worker->stack_installed) {
            errno = EBUSY;
            return false;
        }
        ++visited;
        if (worker == survivor)
            found = true;
    }
    if (!found || visited != count) {
        errno = EINVAL;
        return false;
    }
    sigset_t current_mask;
    int error = pthread_sigmask(SIG_BLOCK, NULL, &current_mask);
    if (error != 0) {
        errno = error;
        return false;
    }
    for (unsigned int i = 0; i < copied->carrier_count; ++i)
        if (!(carrier_at(copied, i) == SIGCHLD &&
              child_uncaptured(copied,
                  atomic_load_explicit(&copied->child_policy,
                                       memory_order_acquire)) &&
              !survivor->child_guest_blocked) &&
            sigismember(&current_mask, carrier_at(copied, i)) != 1) {
            errno = EINVAL;
            return false;
        }
    stack_t current_stack;
    if (sigaltstack(NULL, &current_stack) != 0)
        return false;
    bool install_stack = false;
#if defined(__APPLE__)
    /* Native Darwin fork units observe a disabled kernel altstack in the
     * child. Linux fork retains it, and keeps the strict check below. */
    install_stack = current_stack.ss_flags == SS_DISABLE &&
                    current_stack.ss_sp == NULL && current_stack.ss_size == 0;
#endif
    if (!install_stack && (current_stack.ss_flags != 0 ||
        current_stack.ss_sp != survivor->stack ||
        current_stack.ss_size != survivor->stack_size)) {
        errno = EINVAL;
        return false;
    }
    sparc64_native_signal_process_t *fresh = calloc(1, sizeof(*fresh));
    if (fresh == NULL)
        return false;
    error = pthread_mutex_init(&fresh->registration_lock, NULL);
    if (error != 0) {
        free(fresh);
        errno = error;
        return false;
    }
    if (install_stack) {
        stack_t replacement = {
            .ss_sp = survivor->stack, .ss_size = survivor->stack_size
        };
        if (sigaltstack(&replacement, NULL) != 0) {
            int saved = errno;
            if (pthread_mutex_destroy(&fresh->registration_lock) != 0)
                _exit(125);
            free(fresh);
            errno = saved;
            return false;
        }
    }
    fresh->local_pid = getpid();
    fresh->creator = pthread_self();
    fresh->creator_cancel_state = survivor->creator_thread ?
        copied->creator_cancel_state : survivor->prior_cancel_state;
    fresh->original_mask = survivor->creator_thread ?
        copied->original_mask : survivor->original_mask;
    fresh->mask_saved = true;
    fresh->carriers = copied->carriers;
    memcpy(fresh->original_actions, copied->original_actions,
             sizeof(fresh->original_actions));
    fresh->carrier_count = copied->carrier_count;
    fresh->stop_signal = copied->stop_signal;
    fresh->exec_resume = copied->exec_resume;
    fresh->resume_guest_child_blocked = copied->resume_guest_child_blocked;
    fresh->child_action_changed = copied->child_action_changed;
    atomic_init(&fresh->child_policy,
                atomic_load_explicit(&copied->child_policy,
                                     memory_order_acquire));
    atomic_init(&fresh->child_generation,
                atomic_load_explicit(&copied->child_generation,
                                     memory_order_acquire));
    fresh->actions_installed = copied->actions_installed;
    fresh->initial_mask = copied->initial_mask;
    fresh->initial_ignored = copied->initial_ignored;
    atomic_init(&fresh->attached_workers, 1);
    fresh->workers = survivor;

    sparc64_native_signals_t *old_workers = copied->workers;
    /* Publication and disposal run with carriers continuously blocked. Do
     * not restore/reinstall process handlers or drain new child signals. */
    survivor->process = fresh;
    survivor->owner = pthread_self();
    survivor->guest_tid = new_guest_tid;
    survivor->creator_thread = true;
    survivor->prior_cancel_state = PTHREAD_CANCEL_DISABLE;
    for (unsigned int i = 0; i < NATIVE_SLOT_COUNT; ++i) {
        memset(&survivor->slots[i].event, 0, sizeof(survivor->slots[i].event));
        atomic_store_explicit(&survivor->slots[i].state, 0, memory_order_relaxed);
    }
    atomic_store_explicit(&survivor->wake, 0, memory_order_relaxed);
    atomic_store_explicit(&survivor->kick_pending, 0, memory_order_relaxed);
    atomic_store_explicit(&survivor->stop, 0, memory_order_relaxed);
    atomic_store_explicit(&survivor->syscall_origin, 0, memory_order_relaxed);
    atomic_store_explicit(&process_owner, fresh, memory_order_release);
    atomic_store_explicit(&native_signals, survivor, memory_order_release);
    native_fork_freeze = NULL;
    *owned = fresh;
    *sealed = NULL;
    /* Retain each next link until the copied list is fully walked; the
     * survivor can be in any position, including the head. */
    for (sparc64_native_signals_t *worker = old_workers; worker != NULL;) {
        sparc64_native_signals_t *next = worker->registration_next;
        if (worker != survivor) {
            free(worker->stack);
            free(worker);
        }
        worker = next;
    }
    survivor->registration_next = NULL;
    free(freeze);
    free(copied); /* No pthread operation on its possibly locked mutex. */
    return true;
}

static sparc64_native_signal_process_t *process_create(bool exec_resume,
                                                  sparc64_native_child_policy_t policy,
                                                  bool guest_child_blocked)
{
    struct sigaction inherited_child = {0};
    if (exec_resume) {
        if (policy != SPARC64_NATIVE_CHILD_DEFAULT &&
            policy != SPARC64_NATIVE_CHILD_IGNORED) {
            errno = EINVAL;
            return NULL;
        }
        if (sigaction(SIGCHLD, NULL, &inherited_child) != 0)
            return NULL;
        if (inherited_child.sa_handler !=
                (policy == SPARC64_NATIVE_CHILD_IGNORED ? SIG_IGN : SIG_DFL) ||
            (policy == SPARC64_NATIVE_CHILD_DEFAULT &&
             (inherited_child.sa_flags & SA_NOCLDWAIT) != 0)) {
            errno = EINVAL;
            return NULL;
        }
    }
    int old_cancel_state;
    int error = pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &old_cancel_state);
    if (error != 0) {
        errno = error;
        return NULL;
    }
    sparc64_native_signal_process_t *process = calloc(1, sizeof(*process));
    if (process == NULL) {
        int saved = errno;
        (void)pthread_setcancelstate(old_cancel_state, NULL);
        errno = saved;
        return NULL;
    }
    process->creator = pthread_self();
    process->local_pid = getpid();
    process->creator_cancel_state = old_cancel_state;
    process->exec_resume = exec_resume;
    process->resume_guest_child_blocked = guest_child_blocked;
    atomic_init(&process->attached_workers, 0);
    atomic_init(&process->child_generation, 0);
    atomic_init(&process->child_policy,
                exec_resume ? policy : SPARC64_NATIVE_CHILD_CAUGHT);
    error = pthread_mutex_init(&process->registration_lock, NULL);
    if (error != 0) {
        free(process);
        (void)pthread_setcancelstate(old_cancel_state, NULL);
        errno = error;
        return NULL;
    }
#ifdef __linux__
    process->stop_signal = SIGRTMIN;
    process->carrier_count = 5;
#else
    process->carrier_count = 4;
#endif
    sparc64_native_signal_process_t *empty = NULL;
    if (!atomic_compare_exchange_strong_explicit(&process_owner, &empty, process,
                                                  memory_order_acq_rel,
                                                  memory_order_acquire)) {
        (void)pthread_mutex_destroy(&process->registration_lock);
        free(process);
        (void)pthread_setcancelstate(old_cancel_state, NULL);
        errno = EBUSY;
        return NULL;
    }
    sigemptyset(&process->carriers);
    sigaddset(&process->carriers, SIGUSR1);
    sigaddset(&process->carriers, SIGUSR2);
    sigaddset(&process->carriers, SIGTERM);
    sigaddset(&process->carriers, SIGCHLD);
    if (process->stop_signal != 0)
        sigaddset(&process->carriers, process->stop_signal);
    sigset_t to_block = process->carriers;
    if (exec_resume)
        sigdelset(&to_block, SIGCHLD);
    error = pthread_sigmask(SIG_BLOCK, &to_block, &process->original_mask);
    if (error != 0) {
        errno = error;
        goto fail;
    }
    process->mask_saved = true;
    if (sigismember(&process->original_mask, SIGUSR1) == 1)
        process->initial_mask |= UINT64_C(1) << 9;
    if (sigismember(&process->original_mask, SIGUSR2) == 1)
        process->initial_mask |= UINT64_C(1) << 11;
    if (sigismember(&process->original_mask, SIGTERM) == 1)
        process->initial_mask |= UINT64_C(1) << 14;
    if (exec_resume ? guest_child_blocked :
        sigismember(&process->original_mask, SIGCHLD) == 1)
        process->initial_mask |= UINT64_C(1) << 16;
    struct sigaction action;
    memset(&action, 0, sizeof(action));
    action.sa_sigaction = capture;
    action.sa_flags = SA_SIGINFO | SA_ONSTACK | SA_NOCLDSTOP;
    action.sa_mask = process->carriers;
    for (unsigned int i = 0; i < process->carrier_count; ++i) {
        if (exec_resume && carrier_at(process, i) == SIGCHLD) {
            process->original_actions[i] = inherited_child;
        } else if (sigaction(carrier_at(process, i), &action,
                             &process->original_actions[i]) != 0) {
            goto fail;
        }
        process->actions_installed = i + 1;
        if (carrier_at(process, i) == SIGUSR1 ||
            carrier_at(process, i) == SIGUSR2 ||
            carrier_at(process, i) == SIGTERM) {
            if (process->original_actions[i].sa_handler == SIG_IGN)
                process->initial_ignored |= UINT64_C(1) <<
                    (carrier_at(process, i) == SIGUSR1 ? 9 :
                     carrier_at(process, i) == SIGUSR2 ? 11 : 14);
        }
        if (carrier_at(process, i) == SIGCHLD &&
            process->original_actions[i].sa_handler == SIG_IGN)
            process->initial_ignored |= UINT64_C(1) << 16;
    }
    return process;
fail: {
        int saved = errno;
        if (!process_destroy_internal(process, true, true))
            _exit(125);
        errno = saved;
        return NULL;
    }
}

sparc64_native_signal_process_t *sparc64_native_signal_process_create(void)
{
    return process_create(false, SPARC64_NATIVE_CHILD_CAUGHT, false);
}

sparc64_native_signal_process_t *sparc64_native_signal_process_create_exec(
    sparc64_native_child_policy_t policy, bool guest_child_blocked)
{
    return process_create(true, policy, guest_child_blocked);
}

bool sparc64_native_signal_process_set_child_policy(
    sparc64_native_signal_process_t *process, sparc64_native_child_policy_t policy,
    bool discard_pending)
{
    if (!local_process(process) || process->teardown_only ||
        process->actions_installed != process->carrier_count ||
        policy > SPARC64_NATIVE_CHILD_IGNORED) {
        errno = EINVAL;
        return false;
    }
    int error = lock_registration(process);
    if (error != 0) {
        errno = error;
        return false;
    }
    if (discard_pending)
        for (sparc64_native_signals_t *worker = process->workers; worker != NULL;
             worker = worker->registration_next)
            if (worker->open) {
                (void)pthread_mutex_unlock(&process->registration_lock);
                errno = EBUSY;
                return false;
            }
    bool okay = true;
    if (atomic_load_explicit(&process->child_policy,
                             memory_order_acquire) != policy || discard_pending) {
        struct sigaction action;
        memset(&action, 0, sizeof(action));
        action.sa_mask = process->carriers;
        if (policy == SPARC64_NATIVE_CHILD_IGNORED) {
            action.sa_handler = SIG_IGN;
        } else if (child_default(policy)) {
            action.sa_handler = SIG_DFL;
            if (policy == SPARC64_NATIVE_CHILD_DEFAULT_NOCLDWAIT)
                action.sa_flags = SA_NOCLDWAIT;
        } else {
            action.sa_sigaction = capture;
            action.sa_flags = SA_SIGINFO | SA_ONSTACK | SA_NOCLDSTOP |
                              (policy == SPARC64_NATIVE_CHILD_CAUGHT_NOCLDWAIT ?
                               SA_NOCLDWAIT : 0);
        }
        okay = sigaction(SIGCHLD, &action, NULL) == 0;
        if (okay) {
            atomic_store_explicit(&process->child_policy, policy,
                                  memory_order_release);
            process->child_action_changed = true;
        }
    }
    if (okay && discard_pending) {
        uint64_t old = atomic_load_explicit(&process->child_generation,
                                            memory_order_acquire);
        if (old == UINT64_MAX)
            _exit(125); /* Never allow a stale captured generation to recur. */
        atomic_store_explicit(&process->child_generation, old + 1,
                              memory_order_release);
        /* The caller's quiescence rendezvous has made every receiver block
         * SIGCHLD and finish any selected handler. No slot writer can now
         * race this discard. Kernel-pending instances are purged by the
         * sigaction publication above; captured instances live here. */
        for (sparc64_native_signals_t *worker = process->workers; worker != NULL;
             worker = worker->registration_next)
            atomic_store_explicit(&worker->slots[NATIVE_SLOT_CHLD].state, 0,
                                  memory_order_release);
    }
    int saved = errno;
    if (pthread_mutex_unlock(&process->registration_lock) != 0)
        _exit(125);
    if (!okay)
        errno = saved;
    return okay;
}

bool sparc64_native_signal_process_reset_child_policy(
    sparc64_native_signal_process_t *process, sparc64_native_child_policy_t policy)
{
    sparc64_native_signals_t *self = atomic_load_explicit(&native_signals,
                                                      memory_order_acquire);
    if (!local_process(process) || !local_worker(self) ||
        self->process != process || self->open || !child_default(policy) ||
        child_reset_process != NULL) {
        errno = EINVAL;
        return false;
    }
    int error = lock_registration(process);
    if (error != 0) {
        errno = error;
        return false;
    }
    sparc64_native_child_policy_t old = atomic_load_explicit(
        &process->child_policy, memory_order_acquire);
    if (child_default(old) || old == SPARC64_NATIVE_CHILD_IGNORED) {
        (void)pthread_mutex_unlock(&process->registration_lock);
        errno = EINVAL;
        return false;
    }
    for (sparc64_native_signals_t *worker = process->workers; worker != NULL;
         worker = worker->registration_next)
        if (worker->open) {
            (void)pthread_mutex_unlock(&process->registration_lock);
            errno = EBUSY;
            return false;
        }
    sigset_t current;
    error = pthread_sigmask(SIG_BLOCK, NULL, &current);
    if (error != 0 || sigismember(&current, SIGCHLD) != 1) {
        (void)pthread_mutex_unlock(&process->registration_lock);
        errno = error != 0 ? error : EINVAL;
        return false;
    }
    struct sigaction marker;
    memset(&marker, 0, sizeof(marker));
    marker.sa_sigaction = child_reset_marker;
    marker.sa_mask = process->carriers;
    marker.sa_flags = SA_SIGINFO | SA_ONSTACK | SA_NOCLDSTOP | SA_RESETHAND |
                      (policy == SPARC64_NATIVE_CHILD_DEFAULT_NOCLDWAIT ?
                       SA_NOCLDWAIT : 0);
    child_reset_process = process;
    child_reset_seen = 0;
    bool okay = sigaction(SIGCHLD, &marker, NULL) == 0;
    if (okay) {
        error = pthread_kill(pthread_self(), SIGCHLD);
        if (error != 0) {
            errno = error;
            okay = false;
        }
    }
    if (okay) {
        sigset_t only_child;
        sigfillset(&only_child);
        sigdelset(&only_child, SIGCHLD);
        errno = 0;
        int result = sigsuspend(&only_child);
        okay = result == -1 && errno == EINTR && child_reset_seen == 1;
        if (!okay)
            errno = EIO;
    }
    if (okay) {
        struct sigaction installed;
        okay = sigaction(SIGCHLD, NULL, &installed) == 0 &&
               installed.sa_handler == SIG_DFL;
        if (!okay)
            errno = EIO;
    }
    child_reset_process = NULL;
    child_reset_seen = 0;
    if (okay) {
        atomic_store_explicit(&process->child_policy, policy,
                              memory_order_release);
        process->child_action_changed = true;
    }
    int saved = errno;
    if (pthread_mutex_unlock(&process->registration_lock) != 0)
        _exit(125);
    if (!okay)
        errno = saved;
    return okay;
}

sparc64_native_child_policy_t sparc64_native_signal_process_child_policy(
    const sparc64_native_signal_process_t *process)
{
    if (!local_process(process))
        _exit(125);
    return atomic_load_explicit(&process->child_policy, memory_order_acquire);
}

bool sparc64_native_signal_pending_child(sparc64_native_signal_process_t *process)
{
    sparc64_native_signals_t *signals = atomic_load_explicit(&native_signals,
                                                        memory_order_acquire);
    if (!local_process(process) || !local_worker(signals) ||
        signals->process != process || signals->open)
        _exit(125);
    sigset_t pending;
    if (sigpending(&pending) != 0)
        _exit(125);
    int child = sigismember(&pending, SIGCHLD);
    if (child < 0)
        _exit(125);
    return child == 1;
}

bool sparc64_native_signal_transition_block_child(sparc64_native_signal_process_t *process)
{
    sparc64_native_signals_t *signals = atomic_load_explicit(&native_signals,
                                                        memory_order_acquire);
    if (!local_process(process) || !local_worker(signals) ||
        signals->process != process || signals->open) {
        errno = EINVAL;
        return false;
    }
    sigset_t only_child;
    sigemptyset(&only_child);
    sigaddset(&only_child, SIGCHLD);
    int error = pthread_sigmask(SIG_BLOCK, &only_child, NULL);
    if (error != 0) {
        errno = error;
        return false;
    }
    return true;
}

bool sparc64_native_signal_reconcile_child_mask(sparc64_native_signal_process_t *process,
                                            bool guest_blocked)
{
    sparc64_native_signals_t *signals = atomic_load_explicit(&native_signals,
                                                        memory_order_acquire);
    if (!local_process(process) || !local_worker(signals) ||
        signals->process != process || signals->open) {
        errno = EINVAL;
        return false;
    }
    sigset_t only_child;
    sigemptyset(&only_child);
    sigaddset(&only_child, SIGCHLD);
    bool block = !child_uncaptured(process,
        atomic_load_explicit(&process->child_policy,
                             memory_order_acquire)) ||
                 guest_blocked;
    int error = pthread_sigmask(block ? SIG_BLOCK : SIG_UNBLOCK,
                                &only_child, NULL);
    if (error != 0) {
        errno = error;
        return false;
    }
    signals->child_guest_blocked = guest_blocked;
    return true;
}

sparc64_native_signals_t *sparc64_native_signal_worker_attach(sparc64_native_signal_process_t *process)
{
    if (!local_process(process) ||
        process->actions_installed != process->carrier_count || process->teardown_only ||
        atomic_load(&native_signals) != NULL) {
        errno = EBUSY;
        return NULL;
    }
    int old_cancel_state;
    int error = pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &old_cancel_state);
    if (error != 0) {
        errno = error;
        return NULL;
    }
    sigset_t original_mask;
    sigset_t to_block = process->carriers;
    /* Only the exec survivor may carry an inherited uncaptured SIGCHLD mask
     * through its first attachment. Later workers must block a capture
     * carrier before their TLS and alternate stack are published. */
    if (process->exec_resume &&
        pthread_equal(process->creator, pthread_self()) &&
        atomic_load_explicit(&process->attached_workers,
                             memory_order_acquire) == 0 &&
        child_uncaptured(process,
            atomic_load_explicit(&process->child_policy,
                                 memory_order_acquire)))
        sigdelset(&to_block, SIGCHLD);
    error = pthread_sigmask(SIG_BLOCK, &to_block, &original_mask);
    if (error != 0) {
        (void)pthread_setcancelstate(old_cancel_state, NULL);
        errno = error;
        return NULL;
    }
    /* Include allocation, altstack installation, registry/count publication
     * and rollback in the seal's lifetime boundary. There must be no copied
     * unlisted capture allocation owned by a vanished attaching thread. */
    error = lock_registration(process);
    if (error != 0) {
        if (pthread_setcancelstate(old_cancel_state, NULL) != 0)
            _exit(125);
        errno = error;
        return NULL;
    }
    sparc64_native_signals_t *signals = NULL;
    unsigned int count = atomic_load_explicit(&process->attached_workers,
                                               memory_order_relaxed);
    if (process->stopped || count == UINT32_MAX) {
        errno = process->stopped ? ECANCELED : EOVERFLOW;
        goto fail;
    }
    signals = calloc(1, sizeof(*signals));
    if (signals == NULL)
        goto fail;
    signals->process = process;
    signals->owner = pthread_self();
    signals->prior_cancel_state = old_cancel_state;
    signals->original_mask = original_mask;
    signals->child_guest_blocked = process->exec_resume ?
                                   process->resume_guest_child_blocked : false;
    signals->creator_thread = pthread_equal(process->creator, pthread_self()) != 0;
    atomic_init(&signals->wake, 0);
    atomic_init(&signals->kick_pending, 0);
    atomic_init(&signals->stop, 0);
    atomic_init(&signals->syscall_origin, 0);
    for (unsigned int i = 0; i < NATIVE_SLOT_COUNT; ++i)
        atomic_init(&signals->slots[i].state, 0);
    size_t stack_size = 64U * 1024U;
#if defined(__linux__) && defined(__aarch64__) && defined(AT_MINSIGSTKSZ)
    unsigned long minimum = getauxval(AT_MINSIGSTKSZ);
    if (minimum > SIZE_MAX - 32U * 1024U) {
        errno = ENOMEM;
        goto fail;
    }
    if ((size_t)minimum + 32U * 1024U > stack_size)
        stack_size = (size_t)minimum + 32U * 1024U;
#endif
    signals->stack = malloc(stack_size);
    if (signals->stack == NULL)
        goto fail;
    signals->stack_size = stack_size;
    stack_t stack = {.ss_sp = signals->stack, .ss_size = stack_size, .ss_flags = 0};
    if (sigaltstack(&stack, &signals->original_stack) != 0)
        goto fail;
    signals->stack_installed = true;
    signals->registration_next = process->workers;
    process->workers = signals;
    atomic_store_explicit(&native_signals, signals, memory_order_release);
    atomic_store_explicit(&process->attached_workers, count + 1,
                           memory_order_release);
    if (pthread_mutex_unlock(&process->registration_lock) != 0)
        _exit(125);
    return signals;
fail: {
        int saved = errno;
        if (signals != NULL) {
            if (signals->stack_installed && !restore_worker_stack(signals))
                _exit(125);
            free(signals->stack);
            free(signals);
        }
        if (pthread_mutex_unlock(&process->registration_lock) != 0)
            _exit(125);
        /* A failed attach never exposes a thread with handlers but no TLS. */
        if (pthread_setcancelstate(old_cancel_state, NULL) != 0)
            _exit(125);
        errno = saved;
        return NULL;
    }
}

bool sparc64_native_signal_worker_bind_tid(sparc64_native_signals_t *signals,
                                       uint32_t guest_tid)
{
    if (!local_worker(signals) || guest_tid == 0 ||
        signals->teardown_only || signals->process->teardown_only) {
        errno = EINVAL;
        return false;
    }
    sparc64_native_signal_process_t *process = signals->process;
    int error = lock_registration(process);
    if (error != 0) {
        errno = error;
        return false;
    }
    bool found = false, duplicate = false;
    for (sparc64_native_signals_t *worker = process->workers; worker != NULL;
         worker = worker->registration_next) {
        if (worker == signals)
            found = true;
        else if (worker->guest_tid == guest_tid)
            duplicate = true;
    }
    bool okay = found && !duplicate && !process->stopped &&
                (signals->guest_tid == 0 || signals->guest_tid == guest_tid);
    int failure = process->stopped ? ECANCELED : (duplicate ? EEXIST : EINVAL);
    if (okay)
        signals->guest_tid = guest_tid;
    if (pthread_mutex_unlock(&process->registration_lock) != 0)
        _exit(125);
    if (!okay)
        errno = failure;
    return okay;
}
