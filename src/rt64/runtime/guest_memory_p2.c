/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#include "guest_memory_split.h"


static int fork_child_start_canonical_frozen(
    sparc64_guest_memory_fork_freeze_t **frozen,
    sparc64_guest_memory_t **copied_parent, sparc64_linux_memory_t *copied_vmas,
    sparc64_space_t *copied_space, sparc64_file_registry_t *copied_files,
    sparc64_path_resolver_t *resolver, uint32_t slots_per_object,
    uint64_t child_task_id, sparc64_guest_memory_t **out, bool shared)
{
    if (copied_parent == out || (frozen != NULL &&
        (frozen == (void *)copied_parent || frozen == (void *)out))) {
        errno = EINVAL;
        return -1;
    }
    if (frozen == NULL || *frozen == NULL || copied_parent == NULL ||
        *copied_parent == NULL || copied_vmas == NULL || copied_space == NULL ||
        copied_files == NULL || copied_vmas->space != copied_space ||
        copied_files->space != copied_space || resolver == NULL ||
        !resolver->initialized || out == NULL || *out != NULL || child_task_id == 0 ||
        slots_per_object == 0 || slots_per_object > SPARC64_FAMILY_OBJECT_MAX_SLOTS) {
        errno = EINVAL;
        return -1;
    }
    sparc64_guest_memory_t *copied = *copied_parent;
    sparc64_guest_memory_fork_freeze_t *freeze = *frozen;
    if (copied->owner_pid == getpid() ||
        copied->phase != SPARC64_GUEST_MEMORY_READY ||
        copied->canonical_space != copied_space ||
        copied->canonical_memory != copied_vmas ||
        copied->mm_view == NULL || !copied->source_restricted ||
        copied->transitioning || !copied->bound || !copied->fork_frozen ||
        freeze->exec_only || freeze->exec != NULL ||
        (shared ? freeze->canonical_join == NULL || freeze->canonical_child != NULL :
                  freeze->canonical_child == NULL || freeze->canonical_join != NULL) ||
        freeze->session != copied || freeze->parent_pid != copied->owner_pid ||
        freeze->caller != copied->held_worker ||
        local_frozen_session != copied ||
        copied_space->page_factory.context != copied->backing ||
        copied_space->managed.context != copied->backing ||
        (copied->owned_image != NULL &&
         (sparc64_process_memory_space(copied->owned_image) != copied_space ||
          sparc64_process_memory_vmas(copied->owned_image) != copied_vmas ||
          sparc64_process_memory_files(copied->owned_image) != copied_files ||
          sparc64_process_memory_backing(copied->owned_image) != copied->backing))) {
        errno = EPERM;
        return -1;
    }
    /* Borrow only immutable scalar configuration before retiring copied local
     * owners. No copied mutex, guard, source view or payload enters the child. */
    uint64_t limit = copied_space->limit;
    sparc64_file_identity_policy_t identity_policy = copied_files->identity_policy;
    sparc64_guest_memory_t *child = calloc(1, sizeof(*child));
    if (child == NULL)
        return -1;
    int result = pthread_mutex_init(&child->lock, NULL);
    if (result != 0) {
        free(child); errno = result; return -1;
    }
    result = pthread_cond_init(&child->changed, NULL);
    if (result != 0) {
        (void)pthread_mutex_destroy(&child->lock);
        free(child); errno = result; return -1;
    }
    child->owner_pid = getpid();
    child->resolver = resolver;
    child->phase = SPARC64_GUEST_MEMORY_STARTING;
    child->source_restricted = true;
    child->cleanup_delegated = copied->cleanup_delegated;
    child->initial.session = child;
    child->initial.owner = pthread_self();
    child->initial.initial = true;
    child->initial.previous_cancel_state = freeze->previous_cancel_state;
    *out = child;

    sparc64_mm_view_destroy(&copied->mm_view);
    if (copied->owned_image != NULL) {
        sparc64_process_memory_discard(&copied->owned_image);
    } else {
        sparc64_linux_memory_destroy(copied_vmas);
        sparc64_space_destroy(copied_space);
        sparc64_file_registry_destroy(copied_files);
        sparc64_family_backing_unbind(copied->backing);
        if (sparc64_family_backing_destroy(copied->backing) != 0)
            _exit(125);
    }
    copied->backing = NULL;
    sparc64_guest_memory_worker_t *worker = copied->workers;
    while (worker != NULL) {
        sparc64_guest_memory_worker_t *next = worker->next;
        free(worker);
        worker = next;
    }
    copied->workers = NULL;
    if (sparc64_family_fork_child_transfer(&copied->family, &child->family) != 0)
        _exit(125);
    free(copied);
    *copied_parent = NULL;
    local_frozen_session = NULL;
    if (sparc64_family_enter(child->family, &child->initial.guard) != 0)
        _exit(125);
    child->initial.phase = SPARC64_WORKER_HELD;
    child->held_worker = &child->initial;
    if (sparc64_family_observe_inodes(&child->initial.guard,
                                 observe_inode, resolver) != 0)
        _exit(125);
    child->observing = true;
    if (sparc64_process_memory_create_canonical_empty(&child->owned_image,
            child->family, &child->initial.guard, limit,
            slots_per_object, identity_policy) != 0)
        _exit(125);
    child->backing = sparc64_process_memory_backing(child->owned_image);
    child->bound = true;
    child->canonical_space = sparc64_process_memory_space(child->owned_image);
    child->canonical_memory = sparc64_process_memory_vmas(child->owned_image);
    int adopted = shared ?
        sparc64_mm_join_child_adopt(&freeze->canonical_join, &child->initial.guard,
            child->backing, child->canonical_space, child->canonical_memory,
            identity_policy, child_task_id, &child->mm_view) :
        sparc64_mm_fork_child_adopt(&freeze->canonical_child, &child->initial.guard,
            child->backing, child->canonical_space, child->canonical_memory,
            identity_policy, child_task_id, &child->mm_view);
    if (adopted != 0)
        _exit(125); /* A member commit may have taken effect. Never retry. */
    free(freeze);
    *frozen = NULL;
    child->mm_id = sparc64_mm_view_identity(child->mm_view).mm_id;
    child->initial.task_id = child_task_id;
    child->initial.admitted = true;
    child->last_task_id = child_task_id;
    child->phase = SPARC64_GUEST_MEMORY_READY;
    return 0;
}

int sparc64_guest_memory_fork_child_start_canonical_frozen(
    sparc64_guest_memory_fork_freeze_t **frozen,
    sparc64_guest_memory_t **copied_parent, sparc64_linux_memory_t *copied_vmas,
    sparc64_space_t *copied_space, sparc64_file_registry_t *copied_files,
    sparc64_path_resolver_t *resolver, uint32_t slots_per_object,
    uint64_t child_task_id, sparc64_guest_memory_t **out)
{
    return fork_child_start_canonical_frozen(frozen, copied_parent, copied_vmas,
        copied_space, copied_files, resolver, slots_per_object, child_task_id,
        out, false);
}

int sparc64_guest_memory_fork_child_start_shared_frozen(
    sparc64_guest_memory_fork_freeze_t **frozen,
    sparc64_guest_memory_t **copied_parent, sparc64_linux_memory_t *copied_vmas,
    sparc64_space_t *copied_space, sparc64_file_registry_t *copied_files,
    sparc64_path_resolver_t *resolver, uint32_t slots_per_object,
    uint64_t child_task_id, sparc64_guest_memory_t **out)
{
    return fork_child_start_canonical_frozen(frozen, copied_parent, copied_vmas,
        copied_space, copied_files, resolver, slots_per_object, child_task_id,
        out, true);
}

sparc64_space_t *sparc64_guest_memory_child_space(sparc64_guest_memory_t *session)
{
    return session == NULL ? NULL : sparc64_process_memory_space(session->owned_image);
}

sparc64_linux_memory_t *sparc64_guest_memory_child_vmas(sparc64_guest_memory_t *session)
{
    return session == NULL ? NULL : sparc64_process_memory_vmas(session->owned_image);
}

sparc64_file_registry_t *sparc64_guest_memory_child_files(sparc64_guest_memory_t *session)
{
    return session == NULL ? NULL : sparc64_process_memory_files(session->owned_image);
}

sparc64_guest_memory_worker_t *sparc64_guest_memory_initial_worker(sparc64_guest_memory_t *session)
{
    return session == NULL ? NULL : &session->initial;
}

bool sparc64_guest_memory_worker_active(const sparc64_guest_memory_worker_t *worker)
{
    if (worker == NULL || !local_session(worker->session) ||
        !owned_by_current(worker))
        return false;
    sparc64_guest_memory_t *session = worker->session;
    lifecycle_lock(session);
    bool active = session->phase == SPARC64_GUEST_MEMORY_READY &&
                  session->held_worker == worker && session->bound &&
                  worker->phase == SPARC64_WORKER_HELD &&
                  (session->canonical_space == NULL ||
                   (worker->admitted && !worker->retired &&
                    !worker->cleanup_only)) &&
                  sparc64_family_guard_matches(&worker->guard, session->family);
    lifecycle_unlock(session);
    return active;
}

bool sparc64_guest_memory_active(const sparc64_guest_memory_t *session)
{
    return session != NULL &&
           sparc64_guest_memory_worker_active(&session->initial);
}

bool sparc64_guest_memory_worker_resources(sparc64_guest_memory_worker_t *worker,
    sparc64_family_guard_t **guard, sparc64_family_backing_t **backing, uint64_t *mm_id)
{
    if (guard == NULL || backing == NULL || mm_id == NULL ||
        !sparc64_guest_memory_worker_active(worker))
        return false;
    *guard = &worker->guard;
    *backing = worker->session->backing;
    *mm_id = worker->session->mm_id;
    return *mm_id != 0;
}

sparc64_mm_view_t *sparc64_guest_memory_worker_mm(sparc64_guest_memory_worker_t *worker)
{
    return sparc64_guest_memory_worker_active(worker) ? worker->session->mm_view : NULL;
}

static int worker_attach(sparc64_guest_memory_t *session, uint64_t task_id,
                         bool canonical, sparc64_guest_memory_worker_t **out)
{
    if (out != NULL)
        *out = NULL;
    if (session == NULL || out == NULL) {
        errno = EINVAL;
        return -1;
    }
    if (!local_session(session)) {
        errno = EPERM;
        return -1;
    }
    int previous_cancel_state;
    int result = pthread_setcancelstate(PTHREAD_CANCEL_DISABLE,
                                         &previous_cancel_state);
    if (result != 0) {
        errno = result;
        return -1;
    }
    lifecycle_lock(session);
    /* Allocation and publication share the lifecycle seal. A fork cannot
     * copy a worker allocated but not yet linked into the session. */
    if (sparc64_family_zero_backing(session->family)) {
        lifecycle_unlock(session);
        restore_cancellation(previous_cancel_state);
        errno = EOPNOTSUPP;
        return -1;
    }
    sparc64_guest_memory_worker_t *worker = NULL;
    if (session->phase != SPARC64_GUEST_MEMORY_READY ||
        session->extra_workers == SIZE_MAX || session->fork_frozen ||
        session->retirement != NULL) {
        int saved = session->phase == SPARC64_GUEST_MEMORY_FATAL ? EIO : EBUSY;
        lifecycle_unlock(session);
        restore_cancellation(previous_cancel_state);
        errno = saved;
        return -1;
    }
    if ((!canonical && (session->canonical_space != NULL ||
                        session->source_restricted)) ||
        (canonical && (session->canonical_space == NULL ||
                       session->mm_view == NULL || task_id == 0 ||
                       task_id <= session->last_task_id))) {
        lifecycle_unlock(session);
        restore_cancellation(previous_cancel_state);
        errno = canonical ? EINVAL : EOPNOTSUPP;
        return -1;
    }
    worker = calloc(1, sizeof(*worker));
    if (worker == NULL) {
        int saved = errno;
        lifecycle_unlock(session);
        restore_cancellation(previous_cancel_state);
        errno = saved;
        return -1;
    }
    worker->session = session;
    worker->owner = pthread_self();
    worker->previous_cancel_state = previous_cancel_state;
    worker->task_id = task_id;
    /* One thread owns exactly one guard. A second handle could deadlock on
     * the process-local family mutex and restore cancellation out of order. */
    bool duplicate_owner =
        pthread_equal(session->initial.owner, worker->owner) != 0;
    for (sparc64_guest_memory_worker_t *present = session->workers;
         present != NULL && !duplicate_owner; present = present->next)
        duplicate_owner = pthread_equal(present->owner, worker->owner) != 0;
    if (duplicate_owner) {
        free(worker);
        lifecycle_unlock(session);
        restore_cancellation(previous_cancel_state);
        errno = EBUSY;
        return -1;
    }
    worker->next = session->workers;
    session->workers = worker;
    ++session->extra_workers;
    if (canonical)
        session->last_task_id = task_id;
    lifecycle_unlock(session);
    *out = worker;
    return 0;
}

int sparc64_guest_memory_worker_attach(sparc64_guest_memory_t *session,
                                   sparc64_guest_memory_worker_t **out)
{
    return worker_attach(session, 0, false, out);
}

int sparc64_guest_memory_worker_attach_task(sparc64_guest_memory_t *session,
                                       uint64_t task_id,
                                       sparc64_guest_memory_worker_t **out)
{
    if (out == NULL || *out != NULL) {
        errno = out == NULL ? EINVAL : EBUSY;
        return -1;
    }
    return worker_attach(session, task_id, true, out);
}

static bool held_canonical_caller(const sparc64_guest_memory_worker_t *caller)
{
    sparc64_guest_memory_t *session = caller->session;
    return session->phase == SPARC64_GUEST_MEMORY_READY &&
           session->canonical_space != NULL && session->mm_view != NULL &&
           session->held_worker == caller && caller->phase == SPARC64_WORKER_HELD &&
           caller->admitted && !caller->cleanup_only && session->bound &&
           sparc64_family_guard_matches(&caller->guard, session->family);
}

static int member_order(sparc64_family_mm_member_t left,
                        sparc64_family_mm_member_t right)
{
    if (left.owner_incarnation != right.owner_incarnation)
        return left.owner_incarnation < right.owner_incarnation ? -1 : 1;
    if (left.task_id == right.task_id)
        return 0;
    return left.task_id < right.task_id ? -1 : 1;
}

static bool session_has_worker(const sparc64_guest_memory_t *session,
                               const sparc64_guest_memory_worker_t *target)
{
    if (target == &session->initial)
        return true;
    for (const sparc64_guest_memory_worker_t *worker = session->workers;
         worker != NULL; worker = worker->next)
        if (worker == target)
            return true;
    return false;
}

static bool state_has_member(const sparc64_family_mm_state_t *state,
                             sparc64_family_mm_member_t member)
{
    for (size_t i = 0; i < state->member_count; ++i)
        if (member_order(state->members[i], member) == 0)
            return true;
    return false;
}

int sparc64_guest_memory_worker_admit(sparc64_guest_memory_worker_t *caller,
                                  sparc64_guest_memory_worker_t *child)
{
    if (caller == NULL || child == NULL || caller->session == NULL ||
        child->session != caller->session ||
        !local_session(caller->session) || !owned_by_current(caller)) {
        errno = EINVAL; return -1;
    }
    sparc64_guest_memory_t *session = caller->session;
    lifecycle_lock(session);
    if (!held_canonical_caller(caller) || session->retirement != NULL ||
        session->fork_frozen || child->initial || child->phase != SPARC64_WORKER_IDLE ||
        child->admitted || child->retiring || child->retired ||
        child->task_id == 0 || !session_has_worker(session, child)) {
        lifecycle_unlock(session); errno = EBUSY; return -1;
    }
    sparc64_family_mm_state_t state = {0};
    sparc64_family_mm_t mm = sparc64_mm_view_identity(session->mm_view);
    if (sparc64_family_mm_read(&caller->guard, mm, &state) != 0) {
        int saved = errno;
        if (saved != ENOMEM) {
            session->phase = SPARC64_GUEST_MEMORY_FATAL;
            lifecycle_signal(session);
        }
        lifecycle_unlock(session); errno = saved; return -1;
    }
    if (state.member_count >= SPARC64_FAMILY_MM_MAX_RECORDS) {
        sparc64_family_mm_state_destroy(&state);
        lifecycle_unlock(session); errno = ENOMEM; return -1;
    }
    sparc64_family_mm_member_t caller_member = {
        .owner_incarnation = caller->guard.incarnation, .task_id = caller->task_id};
    if (!state_has_member(&state, caller_member)) {
        sparc64_family_mm_state_destroy(&state);
        session->phase = SPARC64_GUEST_MEMORY_FATAL;
        lifecycle_signal(session);
        lifecycle_unlock(session); errno = EIO; return -1;
    }
    sparc64_family_mm_member_t member = {
        .owner_incarnation = caller->guard.incarnation, .task_id = child->task_id};
    size_t at = 0;
    while (at < state.member_count &&
           member_order(state.members[at], member) < 0)
        ++at;
    if (at < state.member_count && member_order(state.members[at], member) == 0) {
        sparc64_family_mm_state_destroy(&state);
        lifecycle_unlock(session); errno = EEXIST; return -1;
    }
    sparc64_family_mm_member_t *larger = realloc(state.members,
        (state.member_count + 1u) * sizeof(*larger));
    if (larger == NULL) {
        int saved = errno;
        sparc64_family_mm_state_destroy(&state);
        lifecycle_unlock(session); errno = saved; return -1;
    }
    state.members = larger;
    memmove(&state.members[at + 1], &state.members[at],
            (state.member_count - at) * sizeof(*larger));
    state.members[at] = member;
    ++state.member_count;
    int result = sparc64_family_mm_commit(&caller->guard, mm, &state);
    int saved = errno;
    sparc64_family_mm_state_destroy(&state);
    if (result == 0)
        child->admitted = true;
    else if (saved != ENOMEM) {
        session->phase = SPARC64_GUEST_MEMORY_FATAL;
        lifecycle_signal(session);
    }
    lifecycle_unlock(session);
    errno = saved;
    return result;
}

int sparc64_guest_memory_worker_retire_prepare(sparc64_guest_memory_worker_t *caller,
                                          sparc64_guest_memory_worker_t *target,
                                          sparc64_guest_memory_retirement_t **out)
{
    if (out != NULL && *out != NULL) {
        errno = EBUSY; return -1;
    }
    if (caller == NULL || target == NULL || out == NULL ||
        caller->session == NULL || target->session != caller->session ||
        !local_session(caller->session) || !owned_by_current(caller)) {
        errno = EINVAL; return -1;
    }
    sparc64_guest_memory_t *session = caller->session;
    lifecycle_lock(session);
    if (!held_canonical_caller(caller) || session->retirement != NULL ||
        session->fork_frozen || !target->admitted || target->retiring ||
        target->retired || !session_has_worker(session, target) ||
        (target != caller && target->phase != SPARC64_WORKER_IDLE)) {
        lifecycle_unlock(session); errno = EBUSY; return -1;
    }
    sparc64_guest_memory_retirement_t *ticket = calloc(1, sizeof(*ticket));
    if (ticket == NULL) {
        int saved = errno;
        lifecycle_unlock(session); errno = saved; return -1;
    }
    ticket->session = session;
    ticket->caller = caller;
    ticket->target = target;
    ticket->mm = sparc64_mm_view_identity(session->mm_view);
    if (sparc64_family_mm_read(&caller->guard, ticket->mm, &ticket->state) != 0) {
        int saved = errno;
        free(ticket); lifecycle_unlock(session); errno = saved; return -1;
    }
    sparc64_family_mm_member_t caller_member = {
        .owner_incarnation = caller->guard.incarnation, .task_id = caller->task_id};
    if (!state_has_member(&ticket->state, caller_member)) {
        sparc64_family_mm_state_destroy(&ticket->state);
        free(ticket);
        session->phase = SPARC64_GUEST_MEMORY_FATAL;
        lifecycle_signal(session);
        lifecycle_unlock(session); errno = EIO; return -1;
    }
    sparc64_family_mm_member_t member = {
        .owner_incarnation = caller->guard.incarnation, .task_id = target->task_id};
    size_t at = 0;
    while (at < ticket->state.member_count &&
           member_order(ticket->state.members[at], member) < 0)
        ++at;
    if (at == ticket->state.member_count ||
        member_order(ticket->state.members[at], member) != 0) {
        sparc64_family_mm_state_destroy(&ticket->state);
        free(ticket); lifecycle_unlock(session); errno = EIO; return -1;
    }
    if (at + 1u < ticket->state.member_count)
        memmove(&ticket->state.members[at], &ticket->state.members[at + 1],
                (ticket->state.member_count - at - 1u) *
                sizeof(*ticket->state.members));
    --ticket->state.member_count;
    target->retiring = true;
    session->retirement = ticket;
    lifecycle_unlock(session);
    *out = ticket;
    return 0;
}

int sparc64_guest_memory_worker_retire_commit(sparc64_guest_memory_retirement_t **owned)
{
    if (owned == NULL || *owned == NULL) {
        errno = EINVAL; return -1;
    }
    sparc64_guest_memory_retirement_t *ticket = *owned;
    sparc64_guest_memory_t *session = ticket->session;
    if (!local_session(session) || !owned_by_current(ticket->caller)) {
        errno = EPERM; return -1;
    }
    lifecycle_lock(session);
    if (session->retirement != ticket || !ticket->target->retiring ||
        !held_canonical_caller(ticket->caller)) {
        lifecycle_unlock(session); errno = EBUSY; return -1;
    }
    /* This is a metadata-only plan. Clear-TID and wait cleanup may change
     * payload bytes/epochs, but no MM-root transaction may intervene. The
     * revision check in commit rejects a stale plan. A failure after those
     * effects is fatal, never a guest-visible retry. */
    int result = sparc64_family_mm_commit(&ticket->caller->guard, ticket->mm,
                                      &ticket->state);
    int saved = errno;
    if (result == 0) {
        ticket->target->admitted = false;
        ticket->target->retired = true;
        ticket->target->retiring = false;
        session->retirement = NULL;
    } else {
        session->phase = SPARC64_GUEST_MEMORY_FATAL;
        lifecycle_signal(session);
    }
    lifecycle_unlock(session);
    if (result == 0) {
        sparc64_family_mm_state_destroy(&ticket->state);
        free(ticket);
        *owned = NULL;
    }
    errno = saved;
    return result;
}

static int worker_enter(sparc64_guest_memory_worker_t *worker, bool cleanup)
{
    if (worker == NULL || worker->session == NULL) {
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
        worker->phase != SPARC64_WORKER_IDLE || session->retirement != NULL ||
        (cleanup && (worker != &session->initial ||
                     session->canonical_space == NULL || !worker->retired)) ||
        (!cleanup && session->canonical_space != NULL &&
         (!worker->admitted || worker->retired || worker->retiring))) {
        int saved = session->phase == SPARC64_GUEST_MEMORY_FATAL ? EIO : EBUSY;
        lifecycle_unlock(session);
        errno = saved;
        return -1;
    }
    worker->phase = SPARC64_WORKER_WAITING;
    lifecycle_unlock(session);
    /* Never hold the lifecycle lock while waiting for the family token. */
    if (sparc64_family_enter(session->family, &worker->guard) != 0) {
        poison(session);
        return -1;
    }
    lifecycle_lock(session);
    while (session->transitioning && session->phase == SPARC64_GUEST_MEMORY_READY) {
        if (pthread_cond_wait(&session->changed, &session->lock) != 0)
            _exit(125);
    }
    if (session->phase != SPARC64_GUEST_MEMORY_READY ||
        session->held_worker != NULL || session->bound ||
        sparc64_family_backing_bind(session->backing, &worker->guard) != 0) {
        session->phase = SPARC64_GUEST_MEMORY_FATAL;
        lifecycle_signal(session);
        lifecycle_unlock(session);
        errno = EIO;
        return -1;
    }
    session->bound = true;
    if (!cleanup && session->mm_view != NULL &&
        sparc64_mm_view_refresh(session->mm_view, &worker->guard) != 0) {
        int saved = errno;
        if (saved != ENOMEM) {
            session->phase = SPARC64_GUEST_MEMORY_FATAL;
            lifecycle_signal(session); lifecycle_unlock(session);
            errno = saved; return -1;
        }
        /* Never publish HELD with stale mappings. Serialize guard release with
         * the existing leave transition; retry and teardown remain possible. */
        sparc64_family_backing_unbind(session->backing);
        session->bound = false; session->transitioning = true;
        lifecycle_unlock(session);
        int left = sparc64_family_leave_with_cleanup(&worker->guard,
                                                  sparc64_path_drain_quarantine, session->resolver);
        int leave_error = errno;
        lifecycle_lock(session);
        worker->phase = SPARC64_WORKER_IDLE;
        session->transitioning = false;
        if (left != 0)
            session->phase = SPARC64_GUEST_MEMORY_FATAL;
        lifecycle_signal(session); lifecycle_unlock(session);
        errno = left == 0 ? saved : leave_error;
        return -1;
    }
    if (!cleanup && session->mm_view != NULL &&
        !sparc64_mm_view_has_member(session->mm_view, &worker->guard,
                               worker->task_id)) {
        session->phase = SPARC64_GUEST_MEMORY_FATAL;
        lifecycle_signal(session);
        lifecycle_unlock(session);
        errno = EIO;
        return -1;
    }
    session->held_worker = worker;
    worker->phase = SPARC64_WORKER_HELD;
    worker->cleanup_only = cleanup;
    lifecycle_unlock(session);
    return 0;
}

int sparc64_guest_memory_worker_enter(sparc64_guest_memory_worker_t *worker)
{
    return worker_enter(worker, false);
}

int sparc64_guest_memory_worker_enter_cleanup(sparc64_guest_memory_worker_t *initial)
{
    return worker_enter(initial, true);
}

bool sparc64_guest_memory_worker_cleanup_guard(sparc64_guest_memory_worker_t *initial,
                                           sparc64_family_guard_t **guard)
{
    if (initial == NULL || guard == NULL || initial->session == NULL ||
        !local_session(initial->session) || !owned_by_current(initial))
        return false;
    sparc64_guest_memory_t *session = initial->session;
    lifecycle_lock(session);
    bool valid = initial == &session->initial && initial->retired &&
        initial->cleanup_only && session->phase == SPARC64_GUEST_MEMORY_READY &&
        session->held_worker == initial && initial->phase == SPARC64_WORKER_HELD &&
        session->bound && session->retirement == NULL &&
        sparc64_family_guard_matches(&initial->guard, session->family);
    lifecycle_unlock(session);
    if (valid)
        *guard = &initial->guard;
    return valid;
}

int sparc64_guest_memory_worker_leave(sparc64_guest_memory_worker_t *worker)
{
    if (worker == NULL || worker->session == NULL) {
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
        session->held_worker != worker || worker->phase != SPARC64_WORKER_HELD ||
        !session->bound || session->retirement != NULL) {
        int saved = session->phase == SPARC64_GUEST_MEMORY_FATAL ? EIO : EBUSY;
        lifecycle_unlock(session);
        errno = saved;
        return -1;
    }
    sparc64_family_backing_unbind(session->backing);
    session->bound = false;
    session->held_worker = NULL;
    worker->phase = SPARC64_WORKER_IDLE;
    worker->cleanup_only = false;
    session->transitioning = true;
    lifecycle_unlock(session);
#ifdef SPARC64_GUEST_MEMORY_TEST_TRANSITION
    if (session->test_transition_hook != NULL)
        session->test_transition_hook(session->test_transition_context);
#endif
    int result = sparc64_family_leave_with_cleanup(&worker->guard,
                                                sparc64_path_drain_quarantine,
                                                session->resolver);
    int saved = errno;
    lifecycle_lock(session);
    if (result != 0)
        session->phase = SPARC64_GUEST_MEMORY_FATAL;
    session->transitioning = false;
    lifecycle_signal(session);
    lifecycle_unlock(session);
    if (result != 0) {
        errno = saved;
        return -1;
    }
    return 0;
}
