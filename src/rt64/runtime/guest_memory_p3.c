/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#include "guest_memory_split.h"


int sparc64_guest_memory_worker_detach(sparc64_guest_memory_worker_t **owned)
{
    if (owned == NULL || *owned == NULL) {
        errno = EINVAL;
        return -1;
    }
    sparc64_guest_memory_worker_t *worker = *owned;
    if (worker->initial) {
        errno = EINVAL;
        return -1;
    }
    sparc64_guest_memory_t *session = worker->session;
    if (!local_session(session)) {
        errno = EPERM;
        return -1;
    }
    if (!owned_by_current(worker)) {
        errno = EPERM;
        return -1;
    }
    lifecycle_lock(session);
    if (session->phase != SPARC64_GUEST_MEMORY_READY ||
        worker->phase != SPARC64_WORKER_IDLE || worker->admitted ||
        worker->retiring || session->retirement != NULL) {
        int saved = session->phase == SPARC64_GUEST_MEMORY_FATAL ? EIO : EBUSY;
        lifecycle_unlock(session);
        errno = saved;
        return -1;
    }
    sparc64_guest_memory_worker_t **position = &session->workers;
    while (*position != NULL && *position != worker)
        position = &(*position)->next;
    if (*position != worker || session->extra_workers == 0)
        _exit(125);
    *position = worker->next;
    --session->extra_workers;
    int previous_cancel_state = worker->previous_cancel_state;
    free(worker);
    *owned = NULL;
    lifecycle_unlock(session);
    restore_cancellation(previous_cancel_state);
    return 0;
}

int sparc64_guest_memory_round_trip(sparc64_guest_memory_t *session)
{
    if (session == NULL || !sparc64_guest_memory_active(session)) {
        errno = EINVAL;
        return -1;
    }
    if (sparc64_guest_memory_worker_leave(&session->initial) != 0)
        return -1;
    return sparc64_guest_memory_worker_enter(&session->initial);
}

int sparc64_guest_memory_stop(sparc64_guest_memory_t *session)
{
    if (session == NULL) {
        errno = EINVAL;
        return -1;
    }
    if (!local_session(session)) {
        errno = EPERM;
        return -1;
    }
    if (!owned_by_current(&session->initial)) {
        errno = EPERM;
        return -1;
    }
    lifecycle_lock(session);
    bool idle_canonical = session->phase == SPARC64_GUEST_MEMORY_READY &&
        session->canonical_space != NULL && session->initial.phase == SPARC64_WORKER_IDLE &&
        session->held_worker == NULL && !session->bound;
    if ((session->phase != SPARC64_GUEST_MEMORY_READY &&
         session->phase != SPARC64_GUEST_MEMORY_STARTING) ||
        session->extra_workers != 0 || session->transitioning ||
        session->retirement != NULL ||
        (session->phase == SPARC64_GUEST_MEMORY_READY && !idle_canonical &&
         (session->held_worker != &session->initial ||
          session->initial.phase != SPARC64_WORKER_HELD))) {
        int saved = session->phase == SPARC64_GUEST_MEMORY_FATAL ? EIO : EBUSY;
        lifecycle_unlock(session);
        errno = saved;
        return -1;
    }
    session->phase = SPARC64_GUEST_MEMORY_STOPPING;
    lifecycle_unlock(session);
    if (idle_canonical) {
        /* Teardown-only reacquisition cannot admit guest memory, copyout or
         * dispatch. In particular it must not require a successful refresh. */
        if (sparc64_family_enter(session->family, &session->initial.guard) != 0 ||
            sparc64_family_backing_bind(session->backing, &session->initial.guard) != 0) {
            poison(session); return -1;
        }
        session->bound = true;
    }
    if (session->canonical_space != NULL) {
        sparc64_mm_view_destroy(&session->mm_view);
        /* A native canonical child owns these structs through owned_image;
         * startup/exec canonical sessions borrow stable caller storage. */
        if (session->owned_image == NULL) {
            sparc64_linux_memory_destroy(session->canonical_memory);
            sparc64_space_destroy(session->canonical_space);
        }
        session->canonical_space = NULL; session->canonical_memory = NULL;
    }
    if (session->bound) {
        sparc64_family_backing_unbind(session->backing);
        session->bound = false;
    }
    if (session->owned_image != NULL) {
        sparc64_process_memory_discard(&session->owned_image);
        session->backing = NULL;
    } else if (session->backing != NULL) {
        if (sparc64_family_backing_destroy(session->backing) != 0) {
            poison(session);
            return -1;
        }
        session->backing = NULL;
    }
    if (session->observing) {
        if (sparc64_family_unobserve_inodes(&session->initial.guard) != 0) {
            poison(session);
            return -1;
        }
        session->observing = false;
    }
    if (session->initial.guard.held &&
        (session->resolver != NULL ?
         sparc64_family_leave_with_cleanup(&session->initial.guard,
                                      sparc64_path_drain_quarantine,
                                      session->resolver) :
         sparc64_family_leave(&session->initial.guard)) != 0) {
        poison(session);
        return -1;
    }
    lifecycle_lock(session);
    session->initial.phase = SPARC64_WORKER_IDLE;
    session->held_worker = NULL;
    session->phase = SPARC64_GUEST_MEMORY_STOPPED;
    lifecycle_unlock(session);
    return 0;
}

static int guest_memory_finish(sparc64_guest_memory_t **owned, bool restore_prior,
                               int *prior_state)
{
    if (owned == NULL || *owned == NULL) {
        errno = EINVAL;
        return -1;
    }
    sparc64_guest_memory_t *session = *owned;
    if (!local_session(session)) {
        errno = EPERM;
        return -1;
    }
    if (!owned_by_current(&session->initial)) {
        errno = EPERM;
        return -1;
    }
    lifecycle_lock(session);
    if (session->phase != SPARC64_GUEST_MEMORY_STOPPED ||
        session->extra_workers != 0) {
        int saved = session->phase == SPARC64_GUEST_MEMORY_FATAL ? EIO : EBUSY;
        lifecycle_unlock(session);
        errno = saved;
        return -1;
    }
    lifecycle_unlock(session);
    if (session->resolver != NULL && session->resolver->initialized) {
        errno = EBUSY;
        return -1;
    }
    if (session->family != NULL) {
        if ((session->owns_family_cleanup &&
             sparc64_family_cleanup(session->family) != 0) ||
            sparc64_family_destroy(session->family) != 0) {
            poison(session);
            return -1;
        }
    }
    int previous_cancel_state = session->initial.previous_cancel_state;
    if (pthread_cond_destroy(&session->changed) != 0 ||
        pthread_mutex_destroy(&session->lock) != 0)
        _exit(125);
    free(session);
    *owned = NULL;
    if (prior_state != NULL)
        *prior_state = previous_cancel_state;
    if (restore_prior)
        restore_cancellation(previous_cancel_state);
    return 0;
}

int sparc64_guest_memory_finish(sparc64_guest_memory_t **owned)
{
    return guest_memory_finish(owned, true, NULL);
}

int sparc64_guest_memory_finish_keep_cancellation_disabled(sparc64_guest_memory_t **owned,
                                                       int *prior_state)
{
    if (prior_state == NULL) {
        errno = EINVAL;
        return -1;
    }
    int current;
    int result = pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &current);
    if (result != 0) {
        errno = result;
        return -1;
    }
    if (current != PTHREAD_CANCEL_DISABLE) {
        (void)pthread_setcancelstate(current, NULL);
        errno = EPERM;
        return -1;
    }
    return guest_memory_finish(owned, false, prior_state);
}

int sparc64_guest_memory_register_service_cleanup(sparc64_guest_memory_t *session)
{
    if (!local_session(session) || !session->family_creator ||
        !session->source_restricted || session->canonical_space == NULL ||
        session->phase != SPARC64_GUEST_MEMORY_READY || session->extra_workers != 0 ||
        session->held_worker != &session->initial ||
        !session->initial.guard.held ||
        session->cleanup_registration_attempted) {
        errno = EINVAL;
        return -1;
    }
    session->cleanup_registration_attempted = true;
    bool may_have_delegated = false;
    int result = sparc64_family_register_service_cleanup(&session->initial.guard,
                                                     &may_have_delegated);
    if (may_have_delegated)
        session->owns_family_cleanup = false;
    if (result == 0 && may_have_delegated)
        session->cleanup_delegated = true;
    return result;
}

bool sparc64_guest_memory_service_cleanup_delegated(const sparc64_guest_memory_t *session)
{
    return local_session(session) && session->source_restricted &&
           session->cleanup_delegated;
}

int sparc64_guest_memory_departure_begin(sparc64_guest_memory_t *session,
                                   sparc64_file_caps_departure_t *out)
{
    if (!local_session(session) || out == NULL ||
        !session->source_restricted || !session->cleanup_delegated ||
        session->phase != SPARC64_GUEST_MEMORY_READY ||
        session->held_worker != &session->initial ||
        session->extra_workers != 0 || session->retirement != NULL ||
        !owned_by_current(&session->initial) ||
        !session->initial.guard.held) {
        errno = EINVAL;
        return -1;
    }
    const sparc64_file_caps_client_t *sources =
        sparc64_family_sources(&session->initial.guard);
    if (sources == NULL)
        return -1;
    return sparc64_file_caps_departure_begin(sources, out);
}

const char *sparc64_guest_memory_private_directory(const sparc64_guest_memory_t *session)
{
    return session == NULL ? NULL : sparc64_family_private_directory(session->family);
}
