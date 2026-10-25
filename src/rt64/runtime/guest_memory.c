/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#include "guest_memory_split.h"


/* Only the sealing thread observes this pointer. It prevents accidental
 * recursive entry into its held lifecycle mutex, including after native fork. */
_Thread_local sparc64_guest_memory_t *local_frozen_session;

bool local_session(const sparc64_guest_memory_t *session)
{
    return session != NULL && session->owner_pid == getpid();
}

/* A pthread synchronization failure makes ownership uncertain. The family
 * control descriptor must not be closed through ordinary cleanup in that case. */
void lifecycle_lock(sparc64_guest_memory_t *session)
{
    if (local_frozen_session == session)
        _exit(125);
    if (pthread_mutex_lock(&session->lock) != 0)
        _exit(125);
}

void lifecycle_unlock(sparc64_guest_memory_t *session)
{
    if (pthread_mutex_unlock(&session->lock) != 0)
        _exit(125);
}

#ifdef SPARC64_GUEST_MEMORY_TEST_TRANSITION
void sparc64_guest_memory_test_set_transition_hook(sparc64_guest_memory_t *session,
                                              void (*hook)(void *), void *context)
{
    if (!local_session(session))
        _exit(125);
    lifecycle_lock(session);
    if (session->transitioning)
        _exit(125);
    session->test_transition_hook = hook;
    session->test_transition_context = context;
    lifecycle_unlock(session);
}
#endif

void lifecycle_signal(sparc64_guest_memory_t *session)
{
    if (pthread_cond_broadcast(&session->changed) != 0)
        _exit(125);
}

bool owned_by_current(const sparc64_guest_memory_worker_t *worker)
{
    return worker != NULL && pthread_equal(worker->owner, pthread_self()) != 0;
}

void restore_cancellation(int previous_state)
{
    if (pthread_setcancelstate(previous_state, NULL) != 0)
        _exit(125);
}

int observe_inode(void *context, const struct stat *status)
{
    sparc64_path_resolver_t *resolver = context;
    if (status == NULL) {
        errno = EINVAL;
        return -1;
    }
    return sparc64_path_protect_identity(resolver, status->st_dev, status->st_ino);
}

void poison(sparc64_guest_memory_t *session)
{
    lifecycle_lock(session);
    session->phase = SPARC64_GUEST_MEMORY_FATAL;
    session->transitioning = false;
    lifecycle_signal(session);
    lifecycle_unlock(session);
}

static int allocate_session(sparc64_guest_memory_t **out, sparc64_path_resolver_t *resolver)
{
    int previous_cancel_state;
    int result = pthread_setcancelstate(PTHREAD_CANCEL_DISABLE,
                                         &previous_cancel_state);
    if (result != 0) {
        errno = result;
        return -1;
    }
    sparc64_guest_memory_t *session = calloc(1, sizeof(*session));
    if (session == NULL) {
        int saved = errno;
        restore_cancellation(previous_cancel_state);
        errno = saved;
        return -1;
    }
    result = pthread_mutex_init(&session->lock, NULL);
    if (result != 0) {
        free(session);
        restore_cancellation(previous_cancel_state);
        errno = result;
        return -1;
    }
    result = pthread_cond_init(&session->changed, NULL);
    if (result != 0) {
        (void)pthread_mutex_destroy(&session->lock);
        free(session);
        restore_cancellation(previous_cancel_state);
        errno = result;
        return -1;
    }
    session->resolver = resolver;
    session->owner_pid = getpid();
    session->phase = SPARC64_GUEST_MEMORY_STARTING;
    session->initial.session = session;
    session->initial.owner = pthread_self();
    session->initial.initial = true;
    session->initial.previous_cancel_state = previous_cancel_state;
    *out = session;
    return 0;
}

static int adopt_space(sparc64_guest_memory_t *session, sparc64_space_t *space,
                        uint32_t slots_per_object)
{
    session->initial.phase = SPARC64_WORKER_HELD;
    session->held_worker = &session->initial;
    if (sparc64_family_mm_id(&session->initial.guard, &session->mm_id) != 0)
        return -1;
    if (sparc64_family_observe_inodes(&session->initial.guard,
                                 observe_inode, session->resolver) != 0)
        return -1;
    session->observing = true;
    if (sparc64_family_backing_create(&session->backing, session->family,
                                 slots_per_object) != 0 ||
        sparc64_family_backing_bind(session->backing, &session->initial.guard) != 0)
        return -1;
    session->bound = true;
    if (!sparc64_family_backing_adopt(session->backing, space)) {
        errno = space->fault_reason == SPARC64_FAULT_RESOURCE ? ENOMEM : EIO;
        return -1;
    }
    return 0;
}

bool valid_start(sparc64_guest_memory_t **out, sparc64_space_t *space,
                         sparc64_path_resolver_t *resolver, uint32_t slots_per_object)
{
    return out != NULL && space != NULL && resolver != NULL &&
           resolver->initialized && slots_per_object != 0 &&
           slots_per_object <= SPARC64_FAMILY_OBJECT_MAX_SLOTS;
}

static int start_session(sparc64_guest_memory_t **out, sparc64_space_t *space,
                           sparc64_path_resolver_t *resolver, uint32_t slots_per_object,
                           sparc64_linux_memory_t *canonical_memory, uint64_t task_id,
                           sparc64_file_caps_client_t *sources,
                           sparc64_file_identity_policy_t identity_policy,
                           sparc64_family_storage_authority_t authority)
{
    if (out != NULL)
        *out = NULL;
    if (!valid_start(out, space, resolver, slots_per_object)) {
        errno = EINVAL;
        return -1;
    }
    if (canonical_memory != NULL) {
        if (canonical_memory->space != space || task_id == 0 ||
            canonical_memory->count > SPARC64_FAMILY_MM_MAX_RECORDS ||
            (canonical_memory->count != 0 && canonical_memory->vmas == NULL)) {
            errno = EINVAL; return -1;
        }
        for (size_t i = 0; i < canonical_memory->count; ++i) {
            if (canonical_memory->vmas[i].kind == SPARC64_VMA_FILE_PRIVATE ||
                canonical_memory->vmas[i].kind == SPARC64_VMA_ANONYMOUS_SHARED) {
                errno = EOPNOTSUPP; return -1;
            }
        }
    }
    if (allocate_session(out, resolver) != 0)
        return -1;
    sparc64_guest_memory_t *session = *out;
    session->canonical_space = canonical_memory == NULL ? NULL : space;
    session->canonical_memory = canonical_memory;
    session->owns_family_cleanup = true;
    session->family_creator = true;
    session->source_restricted = sources != NULL;
    int created = sources == NULL ?
        sparc64_family_create_with_authority(&session->family, authority) :
        sparc64_family_create_with_sources_authority(&session->family, sources,
                                                authority);
    if (created != 0)
        return -1;
    if (sparc64_family_enter(session->family, &session->initial.guard) != 0) {
        /* Enter can fail after an attempted file-lock rollback. */
        poison(session);
        return -1;
    }
    if (adopt_space(session, space, slots_per_object) != 0)
        return -1;
    if (canonical_memory != NULL) {
        if (sparc64_mm_view_seed(&session->mm_view, session->backing,
                             &session->initial.guard, space, canonical_memory, task_id) != 0)
            return -1;
        session->mm_id = sparc64_mm_view_identity(session->mm_view).mm_id;
        if (sources != NULL && sparc64_mm_view_bind_family_sources(session->mm_view,
                &session->initial.guard, identity_policy) != 0)
            return -1;
        session->initial.task_id = task_id;
        session->initial.admitted = true;
        session->last_task_id = task_id;
    }
    session->phase = SPARC64_GUEST_MEMORY_READY;
    return 0;
}

int sparc64_guest_memory_start(sparc64_guest_memory_t **out, sparc64_space_t *space,
                          sparc64_path_resolver_t *resolver, uint32_t slots_per_object)
{
    return start_session(out, space, resolver, slots_per_object, NULL, 0, NULL,
                         SPARC64_FILE_IDENTITY_AUTO, SPARC64_FAMILY_AUTHORITY_AUTO);
}

int sparc64_guest_memory_start_authority(sparc64_guest_memory_t **out, sparc64_space_t *space,
                          sparc64_path_resolver_t *resolver, uint32_t slots_per_object,
                          sparc64_family_storage_authority_t authority)
{
    return start_session(out, space, resolver, slots_per_object, NULL, 0, NULL,
                         SPARC64_FILE_IDENTITY_AUTO, authority);
}

int sparc64_guest_memory_start_canonical(sparc64_guest_memory_t **out, sparc64_space_t *space,
                                    sparc64_path_resolver_t *resolver, uint32_t slots_per_object,
                                    sparc64_linux_memory_t *memory, uint64_t initial_task_id)
{
    if (out == NULL || *out != NULL) { errno = EINVAL; return -1; }
    if (memory == NULL) {
        errno = EINVAL; return -1;
    }
    return start_session(out, space, resolver, slots_per_object, memory, initial_task_id,
                         NULL, SPARC64_FILE_IDENTITY_AUTO, SPARC64_FAMILY_AUTHORITY_AUTO);
}

static int start_owned_sources(sparc64_guest_memory_t **out,
                               sparc64_space_t *space, sparc64_path_resolver_t *resolver,
                               uint32_t slots_per_object,
                               sparc64_linux_memory_t *memory, uint64_t initial_task_id,
                               sparc64_file_caps_client_t *owned_sources,
                               sparc64_file_identity_policy_t identity_policy,
                               sparc64_family_storage_authority_t authority)
{
    if (owned_sources == NULL) { errno = EINVAL; return -1; }
    /* Ownership crosses allocator, native-cap validation and family creation.
     * Keep cancellation disabled until a returned session owns cleanup, or all
     * supplied caps are closed. A partial session retains the original caller
     * state, not the nested DISABLE state observed by allocate_session. */
    int previous;
    int error = pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &previous);
    if (error != 0) {
        sparc64_file_caps_client_close(owned_sources);
        errno = error;
        return -1;
    }
    sparc64_file_caps_client_t supplied = *owned_sources;
    *owned_sources = (sparc64_file_caps_client_t)SPARC64_FILE_CAPS_CLIENT_INITIALIZER;
    sparc64_file_caps_client_t sources = SPARC64_FILE_CAPS_CLIENT_INITIALIZER;
    sparc64_guest_memory_t *created_session = NULL;
    int result = -1;
    if (out == NULL || *out != NULL || (memory == NULL && initial_task_id != 0) ||
        !sparc64_file_identity_policy_valid(identity_policy) ||
        (authority != SPARC64_FAMILY_AUTHORITY_AUTO &&
         authority != SPARC64_FAMILY_AUTHORITY_HYPER_LINUX_APFS_ACL_V1) ||
        !valid_start(out, space, resolver, slots_per_object)) {
        sparc64_file_caps_client_close(&supplied);
        errno = EINVAL;
        goto done;
    }
    if (sparc64_file_caps_client_adopt(&sources, supplied.request_fd,
                                  supplied.lifetime_fd) != 0)
        goto done;
    result = start_session(&created_session, space, resolver, slots_per_object, memory,
                           initial_task_id, &sources, identity_policy, authority);
done: {
        int saved = errno;
        sparc64_file_caps_client_close(&sources);
        if (created_session != NULL) {
            created_session->initial.previous_cancel_state = previous;
            *out = created_session;
        } else
            restore_cancellation(previous);
        errno = saved;
        return result;
    }
}

int sparc64_guest_memory_start_canonical_sources(sparc64_guest_memory_t **out,
                                    sparc64_space_t *space, sparc64_path_resolver_t *resolver,
                                    uint32_t slots_per_object,
                                    sparc64_linux_memory_t *memory, uint64_t initial_task_id,
                                    sparc64_file_caps_client_t *owned_sources,
                                    sparc64_file_identity_policy_t identity_policy)
{
    if (memory == NULL || initial_task_id == 0) {
        if (owned_sources != NULL) sparc64_file_caps_client_close(owned_sources);
        errno = EINVAL;
        return -1;
    }
    return start_owned_sources(out, space, resolver, slots_per_object,
                               memory, initial_task_id, owned_sources,
                               identity_policy, SPARC64_FAMILY_AUTHORITY_AUTO);
}

int sparc64_guest_memory_start_canonical_sources_authority(sparc64_guest_memory_t **out,
                                    sparc64_space_t *space, sparc64_path_resolver_t *resolver,
                                    uint32_t slots_per_object,
                                    sparc64_linux_memory_t *memory, uint64_t initial_task_id,
                                    sparc64_file_caps_client_t *owned_sources,
                                    sparc64_file_identity_policy_t identity_policy,
                                    sparc64_family_storage_authority_t authority)
{
    if (memory == NULL || initial_task_id == 0) {
        if (owned_sources != NULL) sparc64_file_caps_client_close(owned_sources);
        errno = EINVAL;
        return -1;
    }
    return start_owned_sources(out, space, resolver, slots_per_object,
                               memory, initial_task_id, owned_sources,
                               identity_policy, authority);
}

int sparc64_guest_memory_start_borrowed_sources(sparc64_guest_memory_t **out,
                                    sparc64_space_t *space, sparc64_path_resolver_t *resolver,
                                    uint32_t slots_per_object,
                                    sparc64_file_caps_client_t *owned_sources)
{
    return start_owned_sources(out, space, resolver, slots_per_object,
                               NULL, 0, owned_sources, SPARC64_FILE_IDENTITY_AUTO,
                               SPARC64_FAMILY_AUTHORITY_AUTO);
}

static int replay_exec_exit(sparc64_family_guard_t *guard,
                            const sparc64_family_exec_state_t *state,
                            sparc64_family_mm_t old_mm,
                            const sparc64_exec_tid_clear_t *intents, size_t count)
{
    /* Same-PID exec keeps its owner lease, so death sweeping cannot retire
     * the vanished sibling tasks. Do this before any clear-TID selects a
     * foreign waiter; a returning native exec never reaches this path. */
    sparc64_family_wait_table_t table = {0};
    if (sparc64_family_wait_table_read(guard, &table) != 0)
        return -1;
    size_t kept = 0;
    for (size_t i = 0; i < table.count; ++i) {
        sparc64_family_wait_row_t row = table.rows[i];
        if (row.owner_incarnation == state->incarnation) {
            if (old_mm.mm_id == 0 || row.mm_id != old_mm.mm_id) {
                sparc64_family_wait_table_destroy(&table);
                errno = EINVAL;
                return -1;
            }
        } else
            table.rows[kept++] = row;
    }
    bool changed = kept != table.count;
    table.count = kept;
    int retired = changed ? sparc64_family_wait_table_commit(guard, &table, NULL, 0) : 0;
    sparc64_family_wait_table_destroy(&table);
    if (retired != 0)
        return -1;
    return sparc64_exec_tid_replay_old_mm(guard, old_mm, intents, count);
}

static int exec_receive_clear_mm(sparc64_guest_memory_t **out,
                               int owned_control_fd, int owned_directory_fd,
                               sparc64_inode_pins_t owned_pins,
                               sparc64_file_caps_client_t sources,
                               const sparc64_family_exec_state_t *state,
                               sparc64_family_mm_t old_mm,
                               const sparc64_exec_tid_clear_t *intents, size_t count)
{
    bool valid = out != NULL && *out == NULL && state != NULL &&
                 (count == 0 || intents != NULL);
    if (!valid || allocate_session(out, NULL) != 0) {
        int saved = valid ? errno : EINVAL;
        sparc64_family_close_source_capabilities(owned_control_fd, owned_directory_fd,
                                              owned_pins, sources);
        errno = saved;
        return -1;
    }
    sparc64_guest_memory_t *session = *out;
    session->owns_family_cleanup = state->creator;
    session->family_creator = state->creator;
    session->source_restricted = sources.request_fd >= 3;
    int result = sources.request_fd == -1 && sources.lifetime_fd == -1 ?
        sparc64_family_exec_receive(&session->family, &session->initial.guard,
                                owned_control_fd, owned_directory_fd, owned_pins, state) :
        sparc64_family_exec_receive_sources(&session->family, &session->initial.guard,
                                owned_control_fd, owned_directory_fd, owned_pins, sources, state);
    if (result != 0)
        return -1;
    return replay_exec_exit(&session->initial.guard, state, old_mm, intents, count);
}

int sparc64_guest_memory_exec_receive_clear_mm(sparc64_guest_memory_t **out,
                               int owned_control_fd, int owned_directory_fd,
                               sparc64_inode_pins_t owned_pins,
                               const sparc64_family_exec_state_t *state,
                               uint64_t old_mm_id,
                               const sparc64_exec_tid_clear_t *intents, size_t count)
{
    return exec_receive_clear_mm(out, owned_control_fd, owned_directory_fd,
        owned_pins, (sparc64_file_caps_client_t)SPARC64_FILE_CAPS_CLIENT_INITIALIZER,
        state, (sparc64_family_mm_t){.mm_id = old_mm_id}, intents, count);
}

int sparc64_guest_memory_exec_outside_guard(sparc64_guest_memory_t *session,
                                      int (*operation)(void *), void *opaque)
{
    if (!local_session(session) || !owned_by_current(&session->initial) ||
        operation == NULL || session->phase != SPARC64_GUEST_MEMORY_STARTING ||
        session->terminal_only || !session->initial.guard.held ||
        session->backing != NULL || session->resolver != NULL ||
        session->mm_view != NULL || session->held_worker != NULL) {
        errno = EINVAL;
        return -1;
    }
    /* allocate_session kept cancellation disabled. The callback cannot
     * abandon the family between native unlock and exact reentry. */
    if (sparc64_family_leave(&session->initial.guard) != 0) {
        poison(session);
        return -1;
    }
    int result = operation(opaque);
    int operation_error = errno;
    if (sparc64_family_enter(session->family, &session->initial.guard) != 0) {
        poison(session);
        errno = EIO;
        return -1;
    }
    errno = operation_error;
    return result;
}

int sparc64_guest_memory_exec_receive_sources_mm(sparc64_guest_memory_t **out,
                               int owned_control_fd, int owned_directory_fd,
                               sparc64_inode_pins_t owned_pins,
                               sparc64_file_caps_client_t owned_sources,
                               const sparc64_family_exec_state_t *state,
                               uint64_t old_mm_id,
                               const sparc64_exec_tid_clear_t *intents, size_t count)
{
    if (owned_sources.request_fd < 3 || owned_sources.lifetime_fd < 3) {
        sparc64_family_close_source_capabilities(owned_control_fd, owned_directory_fd,
                                              owned_pins, owned_sources);
        errno = EINVAL;
        return -1;
    }
    return exec_receive_clear_mm(out, owned_control_fd, owned_directory_fd,
        owned_pins, owned_sources, state,
        (sparc64_family_mm_t){.mm_id = old_mm_id}, intents, count);
}

static int retire_old_canonical_mm(sparc64_family_guard_t *guard,
                                   const sparc64_family_exec_state_t *state,
                                   sparc64_family_mm_t old_mm, uint64_t old_task_id)
{
    if (guard->incarnation != state->incarnation) {
        errno = EIO;
        return -1;
    }
    /* The exec lease excludes another local publisher across native exec.
     * Clear-TID replay precedes retiring this incarnation's tasks. A separate
     * CLONE_VM process retains its rows, mappings and all payload keys. */
    return sparc64_mm_retire_exec_owner(guard, old_mm, old_task_id);
}

int sparc64_guest_memory_exec_receive_sources_canonical_mm(sparc64_guest_memory_t **out,
                               int owned_control_fd, int owned_directory_fd,
                               sparc64_inode_pins_t owned_pins,
                               sparc64_file_caps_client_t owned_sources,
                               const sparc64_family_exec_state_t *state,
                               sparc64_family_mm_t old_mm, uint64_t old_task_id,
                               const sparc64_exec_tid_clear_t *intents, size_t count)
{
    if (old_mm.mm_id == 0 || old_mm.root_object == 0 || old_task_id == 0) {
        sparc64_family_close_source_capabilities(owned_control_fd, owned_directory_fd,
                                              owned_pins, owned_sources);
        errno = EINVAL;
        return -1;
    }
    if (owned_sources.request_fd < 3 || owned_sources.lifetime_fd < 3) {
        sparc64_family_close_source_capabilities(owned_control_fd, owned_directory_fd,
                                              owned_pins, owned_sources);
        errno = EINVAL;
        return -1;
    }
    if (exec_receive_clear_mm(out, owned_control_fd, owned_directory_fd,
            owned_pins, owned_sources, state, old_mm, intents, count) != 0)
        return -1;
    return retire_old_canonical_mm(&(*out)->initial.guard, state, old_mm, old_task_id);
}

static int require_idle_file_cursor(sparc64_family_guard_t *guard)
{
    sparc64_family_file_cursor_t cursor = {0};
    if (sparc64_family_file_index_cursor_read(guard, &cursor) != 0)
        return -1;
    if (cursor.phase != SPARC64_FILE_IDLE) {
        errno = EBUSY;
        return -1;
    }
    return 0;
}

static int receive_clean_source_exec(
                               sparc64_guest_memory_t **out,
                               int owned_control_fd, int owned_directory_fd,
                               sparc64_inode_pins_t owned_pins,
                               sparc64_file_caps_client_t owned_sources,
                               const sparc64_family_exec_state_t *state,
                               sparc64_family_mm_t old_mm, uint64_t old_task_id,
                               const sparc64_exec_tid_clear_t *intents, size_t count)
{
    bool valid = out != NULL && *out == NULL && state != NULL &&
                 old_mm.mm_id != 0 && old_mm.root_object != 0 &&
                 old_task_id != 0 && (count == 0 || intents != NULL) &&
                 owned_sources.request_fd >= 3 && owned_sources.lifetime_fd >= 3;
    if (!valid || allocate_session(out, NULL) != 0) {
        int saved = valid ? errno : EINVAL;
        sparc64_family_close_source_capabilities(owned_control_fd, owned_directory_fd,
                                              owned_pins, owned_sources);
        errno = saved;
        return -1;
    }
    sparc64_guest_memory_t *session = *out;
    session->family_creator = state->creator;
    session->source_restricted = true;
    session->terminal_only = true;
    if (sparc64_family_exec_receive_sources_terminal(&session->family,
            &session->initial.guard, owned_control_fd, owned_directory_fd,
            owned_pins, owned_sources, state) != 0)
        return -1;
    /* The prior exec preparation drained the file cursor before exporting
     * caps. A nonidle cursor here cannot be recovered against a dead peer,
     * and no exit effect may precede this proof. */
    if (require_idle_file_cursor(&session->initial.guard) != 0 ||
        replay_exec_exit(&session->initial.guard, state, old_mm,
                         intents, count) != 0 ||
        retire_old_canonical_mm(&session->initial.guard, state,
                                old_mm, old_task_id) != 0)
        return -1;
    /* An incomplete receive or nonidle cursor must not attempt ordinary
     * creator cleanup, which could recover against a dead source service. */
    session->terminal_replay_complete = true;
    return 0;
}

static int exec_receive_sources_canonical_mm_classified(
                               sparc64_guest_memory_t **out,
                               int owned_control_fd, int owned_directory_fd,
                               sparc64_inode_pins_t owned_pins,
                               sparc64_file_caps_client_t owned_sources,
                               const sparc64_family_exec_state_t *state,
                               sparc64_family_mm_t old_mm, uint64_t old_task_id,
                               const sparc64_exec_tid_clear_t *intents, size_t count,
                               bool cleanup_delegated)
{
    if (receive_clean_source_exec(out, owned_control_fd, owned_directory_fd,
            owned_pins, owned_sources, state, old_mm, old_task_id,
            intents, count) != 0)
        return -1;
    sparc64_guest_memory_t *session = *out;
    const sparc64_file_caps_client_t *sources = sparc64_family_sources(&session->initial.guard);
    if (sources == NULL)
        return -1;
    if (sparc64_file_caps_client_live(sources)) {
        session->terminal_only = false;
        session->owns_family_cleanup = state->creator &&
                                        !cleanup_delegated;
        session->cleanup_delegated = cleanup_delegated;
        return 0;
    }
    /* The peer can die before or during receive. Its exit effects are now
     * durable. Return only cleanup ownership; the caller must fail-stop. */
    return 1;
}

int sparc64_guest_memory_exec_receive_sources_canonical_mm_classified(
                               sparc64_guest_memory_t **out,
                               int owned_control_fd, int owned_directory_fd,
                               sparc64_inode_pins_t owned_pins,
                               sparc64_file_caps_client_t owned_sources,
                               const sparc64_family_exec_state_t *state,
                               sparc64_family_mm_t old_mm, uint64_t old_task_id,
                               const sparc64_exec_tid_clear_t *intents, size_t count)
{
    return exec_receive_sources_canonical_mm_classified(out,
        owned_control_fd, owned_directory_fd, owned_pins, owned_sources,
        state, old_mm, old_task_id, intents, count, false);
}

#ifdef SPARC64_RUNTIME_TEST_ATTRIBUTED_FILE
int sparc64_guest_memory_exec_receive_sources_canonical_mm_classified_delegated(
                               sparc64_guest_memory_t **out,
                               int owned_control_fd, int owned_directory_fd,
                               sparc64_inode_pins_t owned_pins,
                               sparc64_file_caps_client_t owned_sources,
                               const sparc64_family_exec_state_t *state,
                               sparc64_family_mm_t old_mm, uint64_t old_task_id,
                               const sparc64_exec_tid_clear_t *intents, size_t count)
{
    return exec_receive_sources_canonical_mm_classified(out,
        owned_control_fd, owned_directory_fd, owned_pins, owned_sources,
        state, old_mm, old_task_id, intents, count, true);
}
#endif

int sparc64_guest_memory_exec_replay_dead_sources(
                               sparc64_guest_memory_t **out,
                               int owned_control_fd, int owned_directory_fd,
                               sparc64_inode_pins_t owned_pins,
                               sparc64_file_caps_client_t owned_sources,
                               const sparc64_family_exec_state_t *state,
                               sparc64_family_mm_t old_mm, uint64_t old_task_id,
                               const sparc64_exec_tid_clear_t *intents, size_t count)
{
    return receive_clean_source_exec(out, owned_control_fd,
        owned_directory_fd, owned_pins, owned_sources, state,
        old_mm, old_task_id, intents, count);
}

int sparc64_guest_memory_terminal_cleanup(sparc64_guest_memory_t *session,
                                     bool proven_sole_family_owner)
{
    if (!local_session(session) || !owned_by_current(&session->initial) ||
        !session->terminal_only || !session->terminal_replay_complete ||
        session->phase != SPARC64_GUEST_MEMORY_STARTING ||
        !session->initial.guard.held || !proven_sole_family_owner) {
        errno = EPERM;
        return -1;
    }
    if (require_idle_file_cursor(&session->initial.guard) != 0)
        return -1;
    return sparc64_family_cleanup_held_terminal(&session->initial.guard, true);
}

int sparc64_guest_memory_exec_receive_clear(sparc64_guest_memory_t **out,
                               int owned_control_fd, int owned_directory_fd,
                               sparc64_inode_pins_t owned_pins,
                               const sparc64_family_exec_state_t *state,
                               const sparc64_exec_tid_clear_t *intents, size_t count)
{
    return sparc64_guest_memory_exec_receive_clear_mm(out, owned_control_fd,
        owned_directory_fd, owned_pins, state, 0, intents, count);
}

int sparc64_guest_memory_exec_adopt(sparc64_guest_memory_t *session,
                               sparc64_space_t *space, sparc64_path_resolver_t *resolver,
                               uint32_t slots_per_object)
{
    if (!local_session(session) || !owned_by_current(&session->initial) ||
        session->phase != SPARC64_GUEST_MEMORY_STARTING ||
        session->terminal_only ||
        session->resolver != NULL || session->backing != NULL ||
        session->canonical_space != NULL ||
        !session->initial.guard.held ||
        !valid_start(&session, space, resolver, slots_per_object)) {
        errno = EINVAL;
        return -1;
    }
    session->resolver = resolver;
    int result = adopt_space(session, space, slots_per_object);
    if (result == 0)
        session->phase = SPARC64_GUEST_MEMORY_READY;
    return result;
}

int sparc64_guest_memory_exec_adopt_canonical(sparc64_guest_memory_t *session,
                               sparc64_space_t *space, sparc64_linux_memory_t *memory,
                               sparc64_path_resolver_t *resolver,
                               uint32_t slots_per_object, uint64_t initial_task_id,
                               sparc64_file_identity_policy_t identity_policy)
{
    if (!local_session(session) || !owned_by_current(&session->initial) ||
        session->phase != SPARC64_GUEST_MEMORY_STARTING ||
        session->terminal_only ||
        session->resolver != NULL || session->backing != NULL ||
        session->canonical_space != NULL || !session->initial.guard.held ||
        !valid_start(&session, space, resolver, slots_per_object) ||
        memory == NULL || memory->space != space || initial_task_id == 0 ||
        memory->count > SPARC64_FAMILY_MM_MAX_RECORDS ||
        (memory->count != 0 && memory->vmas == NULL) ||
        !sparc64_file_identity_policy_valid(identity_policy)) {
        errno = EINVAL;
        return -1;
    }
    for (size_t i = 0; i < memory->count; ++i) {
        if (memory->vmas[i].kind == SPARC64_VMA_FILE_PRIVATE ||
            memory->vmas[i].kind == SPARC64_VMA_ANONYMOUS_SHARED) {
            errno = EOPNOTSUPP;
            return -1;
        }
    }
    /* No fallible step precedes the ownership transfer. In particular,
     * teardown must not leave a partially installed backing in caller-owned
     * space after seed or source binding fails. */
    session->canonical_space = space;
    session->canonical_memory = memory;
    session->resolver = resolver;
    if (adopt_space(session, space, slots_per_object) != 0)
        return -1;
    if (sparc64_mm_view_seed(&session->mm_view, session->backing,
                        &session->initial.guard, space, memory,
                        initial_task_id) != 0)
        return -1;
    if (session->source_restricted &&
        sparc64_mm_view_bind_family_sources(session->mm_view,
                                       &session->initial.guard,
                                       identity_policy) != 0)
        return -1;
    session->mm_id = sparc64_mm_view_identity(session->mm_view).mm_id;
    session->initial.task_id = initial_task_id;
    session->initial.admitted = true;
    session->last_task_id = initial_task_id;
    session->phase = SPARC64_GUEST_MEMORY_READY;
    return 0;
}

bool sparc64_guest_memory_owns_image(const sparc64_guest_memory_t *session,
                                const sparc64_space_t *space,
                                const sparc64_linux_memory_t *memory)
{
    return local_session(session) && session->canonical_space == space &&
           session->canonical_memory == memory && space != NULL && memory != NULL;
}
