/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#include "family_split.h"


int family_enter_internal(sparc64_family_t *family, sparc64_family_guard_t *guard,
                                 bool allow_retired)
{
    if (family == NULL || guard == NULL || !family->initialized || guard->held ||
        family->local_pid != getpid()) {
        errno = EINVAL;
        return -1;
    }
    if (family->exec_active) {
        errno = EBUSY;
        return -1;
    }
    int old_cancel_state;
    int result = pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &old_cancel_state);
    if (result != 0) {
        errno = result;
        return -1;
    }
    result = pthread_mutex_lock(&family->local_mutex);
    if (result != 0) {
        (void)pthread_setcancelstate(old_cancel_state, NULL);
        errno = result;
        return -1;
    }
    if (family->destroying || family->cleaned || family->poisoned) {
        (void)pthread_mutex_unlock(&family->local_mutex);
        (void)pthread_setcancelstate(old_cancel_state, NULL);
        errno = family->poisoned ? EIO : EIDRM;
        return -1;
    }
    if (lock_file(family->control_fd, F_WRLCK) != 0) {
        int saved = errno;
        (void)pthread_mutex_unlock(&family->local_mutex);
        (void)pthread_setcancelstate(old_cancel_state, NULL);
        errno = saved;
        return -1;
    }
    atomic_thread_fence(memory_order_acquire);
    if (family->inode_observer != NULL &&
        sparc64_family_scan_inodes(family->control_fd, family->dir_fd,
                              family->inode_observer,
                              family->inode_observer_context) != 0)
        goto unlock_fail;
    sparc64_family_control_t *control = family->control;
    if (control->active != 0) {
        if (control->recovery_epoch == UINT64_MAX) {
            errno = EOVERFLOW;
            goto unlock_fail;
        }
        ++control->recovery_epoch;
        if (replay_committed(family) != 0)
            goto unlock_fail;
        if (atomic_load_explicit(&control->log_marker, memory_order_acquire) ==
            SPARC64_LOG_PREPARED)
            atomic_store_explicit(&control->log_marker, SPARC64_LOG_EMPTY,
                                  memory_order_release);
    } else {
        uint32_t marker = atomic_load_explicit(&control->log_marker, memory_order_acquire);
        if (marker == SPARC64_LOG_COMMITTED && replay_committed(family) != 0)
            goto unlock_fail;
        if (marker != SPARC64_LOG_EMPTY && marker != SPARC64_LOG_PREPARED && marker != SPARC64_LOG_COMMITTED) {
            errno = EIO;
            goto unlock_fail;
        }
        if (marker == SPARC64_LOG_PREPARED)
            atomic_store_explicit(&control->log_marker, SPARC64_LOG_EMPTY, memory_order_release);
    }
    if (family->incarnation == 0) {
        off_t ignored;
        if (!owner_lease_offset(control->next_incarnation, &ignored)) {
            errno = EOVERFLOW;
            goto unlock_fail;
        }
        /* Consume the identity before attempting its lease. A failed entry
         * may leave a gap, but must never allow an identity to be reused. */
        uint64_t incarnation = control->next_incarnation++;
        if (acquire_owner_lease(family, incarnation) != 0)
            goto unlock_fail;
        family->incarnation = incarnation;
    }
    if (control->retired != 0 && !allow_retired) {
        errno = EIDRM;
        goto unlock_fail;
    }
    control->active_incarnation = family->incarnation;
    control->active = 1;
    family->active_guard = guard;
    guard->family = family;
    guard->incarnation = family->incarnation;
    guard->owner_thread = pthread_self();
    guard->previous_cancel_state = old_cancel_state;
    guard->held = true;
    /* Ordinary redo above restores a cursor/payload pair first. The complete
     * resize then drains under a provisional guard before any caller sees it,
     * including an intent left by a graceful leave rather than process death. */
    if (control->source_mode != 0 && recover_file_state(guard) != 0) {
        family->active_guard = NULL;
        memset(guard, 0, sizeof(*guard));
        goto unlock_fail;
    }
    refresh_acquire(family, guard);
    return 0;

unlock_fail: {
        int saved = errno;
        if (unlock_family_file(family) != 0) {
            family->poisoned = true;
            saved = EIO;
        }
        (void)pthread_mutex_unlock(&family->local_mutex);
        (void)pthread_setcancelstate(old_cancel_state, NULL);
        errno = saved;
        return -1;
    }
}

int sparc64_family_enter(sparc64_family_t *family, sparc64_family_guard_t *guard)
{
    return family_enter_internal(family, guard, false);
}

int sparc64_family_leave(sparc64_family_guard_t *guard)
{
    return sparc64_family_leave_with_cleanup(guard, NULL, NULL);
}

int sparc64_family_leave_with_cleanup(sparc64_family_guard_t *guard,
                                  void (*after_unlock)(void *context),
                                  void *context)
{
    if (!guard_valid(guard)) {
        errno = EINVAL;
        return -1;
    }
    sparc64_family_t *family = guard->family;
    if (family->exec_prepared != NULL) {
        errno = EBUSY;
        return -1;
    }
    family->control->active = 0;
    family->control->active_incarnation = 0;
    atomic_thread_fence(memory_order_release);
    int unlock_result = unlock_family_file(family);
    int saved = errno;
    if (unlock_result != 0)
        family->poisoned = true;
    guard->held = false;
    guard->family = NULL;
    guard->refresh_acquisition = 0;
    refresh_invalidate(family);
    family->active_guard = NULL;
    if (unlock_result == 0 && after_unlock != NULL)
        after_unlock(context);
    int mutex_result = pthread_mutex_unlock(&family->local_mutex);
    int cancel_result = pthread_setcancelstate(guard->previous_cancel_state, NULL);
    if (unlock_result != 0) {
        errno = saved;
        return -1;
    }
    if (mutex_result != 0) {
        errno = mutex_result;
        return -1;
    }
    if (cancel_result != 0) {
        errno = cancel_result;
        return -1;
    }
    return 0;
}

uint64_t sparc64_family_incarnation(const sparc64_family_t *family)
{
    return family == NULL ? 0 : family->incarnation;
}

bool sparc64_family_zero_backing(const sparc64_family_t *family)
{
    return family != NULL && family->zero_backing;
}

int sparc64_family_owner_alive(const sparc64_family_guard_t *guard, uint64_t incarnation,
                           bool *alive)
{
    off_t offset;
    if (!guard_valid(guard) || alive == NULL ||
        !owner_lease_offset(incarnation, &offset) ||
        incarnation >= guard->family->control->next_incarnation) {
        errno = EINVAL;
        return -1;
    }
    if (incarnation == guard->family->incarnation) {
        *alive = true;
        return 0;
    }
    struct flock lock = {.l_type = F_WRLCK, .l_whence = SEEK_SET,
                          .l_start = offset, .l_len = 1};
    int result;
    do { result = fcntl(guard->family->control_fd, F_GETLK, &lock); }
    while (result < 0 && errno == EINTR);
    if (result != 0)
        return -1;
    if (lock.l_type != F_UNLCK && lock.l_type != F_WRLCK) {
        errno = EIO;
        return -1;
    }
    *alive = lock.l_type == F_WRLCK;
    return 0;
}

int sparc64_family_identity(const sparc64_family_guard_t *guard,
                        sparc64_family_identity_t *out)
{
    if (!guard_valid(guard) || out == NULL) {
        errno = EINVAL;
        return -1;
    }
    struct stat control, directory;
    if (fstat(guard->family->control_fd, &control) != 0 ||
        fstat(guard->family->dir_fd, &directory) != 0)
        return -1;
    *out = (sparc64_family_identity_t){
        .control_device = control.st_dev,
        .directory_device = directory.st_dev,
        .control_inode = control.st_ino,
        .directory_inode = directory.st_ino
    };
    return 0;
}

int sparc64_family_pin_file(sparc64_family_guard_t *guard, int source_fd)
{
    if (!guard_valid(guard)) {
        errno = EINVAL;
        return -1;
    }
    sparc64_family_t *family = guard->family;
    if (family->exec_prepared != NULL) {
        errno = EBUSY;
        return -1;
    }
    return sparc64_inode_pins_keep(&family->pins, source_fd,
                               &family->control->inode_pin_attempts);
}

const sparc64_file_caps_client_t *sparc64_family_sources(const sparc64_family_guard_t *guard)
{
    if (!guard_valid(guard)) {
        errno = EINVAL;
        return NULL;
    }
    if (!source_caps_present(guard->family->sources)) {
        errno = EOPNOTSUPP;
        return NULL;
    }
    return &guard->family->sources;
}

uint64_t sparc64_family_file_index_object(const sparc64_family_guard_t *guard)
{
    if (!guard_valid(guard)) { errno = EINVAL; return 0; }
    sparc64_family_control_t *control = guard->family->control;
    if (control->source_mode == 0) { errno = EOPNOTSUPP; return 0; }
    if (control->file_index_object == 0 || control->file_index_object >= control->next_object_id) {
        errno = EIO; return 0;
    }
    return control->file_index_object;
}

static int reject_source_inode(void *context, const struct stat *candidate)
{
    const struct stat *source = context;
    if (source->st_dev == candidate->st_dev && source->st_ino == candidate->st_ino) {
        errno = EACCES;
        return -1;
    }
    return 0;
}

int sparc64_family_file_target_check(sparc64_family_guard_t *guard, int source_fd)
{
    if (!guard_valid(guard) || source_fd < 0) {
        errno = EINVAL;
        return -1;
    }
    sparc64_family_t *family = guard->family;
    sparc64_family_control_t *control = family->control;
    if (!source_caps_present(family->sources) || control->source_mode != 1) {
        errno = EOPNOTSUPP;
        return -1;
    }
    if (family->exec_prepared != NULL ||
        atomic_load_explicit(&control->log_marker, memory_order_acquire) != SPARC64_LOG_EMPTY) {
        errno = EBUSY;
        return -1;
    }
    struct stat source;
    if (fstat(source_fd, &source) != 0)
        return -1;
    if (!S_ISREG(source.st_mode) || source.st_size < 0) {
        errno = EINVAL;
        return -1;
    }
    /* Never open/duplicate control or any alias while holding its POSIX lock.
     * Scan through nofollow stat only, retaining borrowed source ownership. */
    if (sparc64_family_scan_inodes(family->control_fd, family->dir_fd,
                              reject_source_inode, &source) != 0)
        return -1;
    return 0;
}

int sparc64_family_source_register(sparc64_family_guard_t *guard,
                                int source_fd, uint64_t *source_id)
{
    if (source_id == NULL) { errno = EINVAL; return -1; }
    if (sparc64_family_file_target_check(guard, source_fd) != 0)
        return -1;
    sparc64_family_t *family = guard->family;
    sparc64_family_control_t *control = family->control;
    if (control->next_source_id == 0 ||
        control->next_source_id > SPARC64_FILE_CAPS_MAX_ATTEMPTS + 1u ||
        control->source_attempts > SPARC64_FILE_CAPS_MAX_ATTEMPTS ||
        control->source_attempts >= control->next_source_id) {
        errno = EIO;
        return -1;
    }
    if (control->next_source_id > SPARC64_FILE_CAPS_MAX_ATTEMPTS ||
        control->source_attempts == SPARC64_FILE_CAPS_MAX_ATTEMPTS) {
        errno = ENOSPC;
        return -1;
    }
    uint64_t id = control->next_source_id++;
    atomic_thread_fence(memory_order_release);
#ifdef SPARC64_FAMILY_TESTING
    if (family->hook != NULL)
        family->hook(SPARC64_FAMILY_TEST_SOURCE_ALLOCATED, family->hook_context);
#endif
    if (sparc64_file_caps_register(&family->sources, source_fd, id, &control->source_attempts) != 0)
        return -1;
    *source_id = id;
    return 0;
}

/* The sole control FD also owns this reserved extent. Never reopen/duplicate
 * it: closing any second descriptor would release the process's token lock. */
int read_file_catalog(sparc64_family_t *family, size_t count,
                              sparc64_file_catalog_record_t **out)
{
    *out = NULL;
    uint64_t end;
    uint64_t extent;
    if (count > SPARC64_FILE_CATALOG_CAPACITY ||
        family->control->file_count > SPARC64_FILE_CATALOG_CAPACITY ||
        count > family->control->inode_pin_attempts ||
        family->control->next_file_id == 0 || !catalog_reserved_end(&end)) {
        errno = EIO;
        return -1;
    }
    if (family_control_extent(family, &extent) != 0)
        return -1;
    if (extent < end) {
        errno = EIO;
        return -1;
    }
    if (count == 0)
        return 0;
    size_t bytes = count * sizeof(sparc64_file_catalog_record_t);
    sparc64_file_catalog_record_t *records = malloc(bytes);
    if (records == NULL)
        return -1;
    uint64_t start = end - SPARC64_FILE_CATALOG_CAPACITY * sizeof(*records);
    if (family_control_read(family, records, bytes, start) != 0) {
        int saved = errno;
        free(records);
        errno = saved;
        return -1;
    }
    if (!sparc64_file_catalog_validate(records, count, family->control->next_file_id)) {
        free(records);
        errno = EIO;
        return -1;
    }
    *out = records;
    return 0;
}

static int find_file_record(const sparc64_file_catalog_record_t *records, size_t count,
                             uint64_t next_id, const sparc64_file_identity_t *identity,
                             uint64_t *id)
{
    for (size_t i = 0; i < count; ++i) {
        sparc64_file_identity_t stored;
        uint64_t stored_id;
        if (!sparc64_file_catalog_decode(&records[i], next_id, &stored_id, &stored)) {
            errno = EIO;
            return -1;
        }
        if (sparc64_file_identity_equal(&stored, identity)) {
            *id = stored_id;
            return 1;
        }
    }
    return 0;
}

static int apply_file_record(sparc64_family_t *family)
{
    sparc64_family_control_t *control = family->control;
    uint64_t end;
    if (!catalog_reserved_end(&end)) {
        errno = EIO;
        return -1;
    }
    uint64_t start = end - SPARC64_FILE_CATALOG_CAPACITY * sizeof(control->file_target);
    uint64_t offset = start + control->file_target_slot * sizeof(control->file_target);
    if (family_control_write(family, &control->file_target,
                             sizeof(control->file_target), offset) != 0)
        return -1;
#ifdef SPARC64_FAMILY_TESTING
    if (family->hook != NULL)
        family->hook(SPARC64_FAMILY_TEST_FILE_RECORD_APPLIED, family->hook_context);
#endif
    control->file_count = control->file_target_count;
    atomic_thread_fence(memory_order_release);
#ifdef SPARC64_FAMILY_TESTING
    if (family->hook != NULL)
        family->hook(SPARC64_FAMILY_TEST_FILE_COUNT_APPLIED, family->hook_context);
#endif
    return 0;
}

int replay_file_record(sparc64_family_t *family)
{
    sparc64_family_control_t *control = family->control;
    uint64_t slot = control->file_target_slot, id;
    sparc64_file_identity_t identity;
    if (slot >= SPARC64_FILE_CATALOG_CAPACITY || control->file_target_count != slot + 1 ||
        (control->file_count != slot && control->file_count != slot + 1) ||
        control->file_target_count > control->inode_pin_attempts ||
        !sparc64_file_catalog_decode(&control->file_target, control->next_file_id,
                                   &id, &identity)) {
        errno = EIO;
        return -1;
    }
    /* The final slot/count may be only partly applied. Validate the immutable
     * prefix, then overwrite the target slot with the absolute redo bytes. */
    sparc64_file_catalog_record_t *prefix = NULL;
    if (read_file_catalog(family, (size_t)slot, &prefix) != 0)
        return -1;
    uint64_t ignored;
    int found = find_file_record(prefix, (size_t)slot, control->next_file_id,
                                  &identity, &ignored);
    bool ordered = true;
    if (slot != 0) {
        uint64_t previous;
        sparc64_file_identity_t previous_identity;
        ordered = sparc64_file_catalog_decode(&prefix[slot - 1], control->next_file_id,
                                           &previous, &previous_identity) &&
                  previous < id;
    }
    free(prefix);
    if (found != 0 || !ordered) {
        errno = EIO;
        return -1;
    }
    return apply_file_record(family);
}

int sparc64_family_file_intern(sparc64_family_guard_t *guard,
                           const sparc64_file_identity_t *identity, int source_fd,
                           uint64_t *file_id)
{
    if (file_id != NULL)
        *file_id = 0;
    if (!guard_valid(guard) || file_id == NULL || source_fd < 0) {
        errno = EINVAL;
        return -1;
    }
    if (!sparc64_file_identity_valid(identity) || !identity->mapped_key_eligible) {
        errno = EOPNOTSUPP;
        return -1;
    }
    sparc64_family_t *family = guard->family;
    sparc64_family_control_t *control = family->control;
    if (family->exec_prepared != NULL ||
        atomic_load_explicit(&control->log_marker, memory_order_acquire) != SPARC64_LOG_EMPTY) {
        errno = EBUSY;
        return -1;
    }
    sparc64_file_catalog_record_t *records = NULL;
    if (read_file_catalog(family, (size_t)control->file_count, &records) != 0)
        return -1;
    uint64_t found_id;
    int found = find_file_record(records, (size_t)control->file_count,
                                  control->next_file_id, identity, &found_id);
    free(records);
    if (found < 0)
        return -1;
    if (found > 0) {
        *file_id = found_id;
        return 0;
    }
    if (control->file_count == SPARC64_FILE_CATALOG_CAPACITY) {
        errno = ENOSPC;
        return -1;
    }
    if (control->next_file_id == UINT64_MAX) {
        errno = EOVERFLOW;
        return -1;
    }
    /* Consume IDs before pinning. Failed/killed producers leave permanent
     * gaps; an uncertain queued pin is never refunded or repurposed. */
    uint64_t id = control->next_file_id++;
    sparc64_file_catalog_record_t target;
    if (!sparc64_file_catalog_encode(&target, id, identity)) {
        errno = EIO;
        return -1;
    }
#ifdef SPARC64_FAMILY_TESTING
    if (family->hook != NULL)
        family->hook(SPARC64_FAMILY_TEST_FILE_ID_ALLOCATED, family->hook_context);
#endif
    if (sparc64_family_pin_file(guard, source_fd) != 0)
        return -1;
#ifdef SPARC64_FAMILY_TESTING
    if (family->hook != NULL)
        family->hook(SPARC64_FAMILY_TEST_FILE_PINNED, family->hook_context);
#endif
    control->file_target_slot = control->file_count;
    control->file_target_count = control->file_count + 1;
    control->file_target = target;
    control->log_kind = SPARC64_LOG_FILE;
    atomic_store_explicit(&control->log_marker, SPARC64_LOG_PREPARED, memory_order_release);
#ifdef SPARC64_FAMILY_TESTING
    if (family->hook != NULL)
        family->hook(SPARC64_FAMILY_TEST_PREPARED, family->hook_context);
#endif
    atomic_store_explicit(&control->log_marker, SPARC64_LOG_COMMITTED, memory_order_release);
    atomic_thread_fence(memory_order_seq_cst);
#ifdef SPARC64_FAMILY_TESTING
    if (family->hook != NULL)
        family->hook(SPARC64_FAMILY_TEST_COMMITTED, family->hook_context);
#endif
    /* No allocation after pin/publication in the normal path. Recovery may
     * allocate a bounded prefix snapshot before replaying the absolute record. */
    if (apply_file_record(family) != 0) {
        family->poisoned = true;
        if (errno == 0)
            errno = EIO;
        return -1;
    }
    atomic_store_explicit(&control->log_marker, SPARC64_LOG_EMPTY, memory_order_release);
    *file_id = id;
    return 0;
}
