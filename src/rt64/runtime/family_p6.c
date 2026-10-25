/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#include "family_split.h"


int sparc64_family_wait_backend_commit(sparc64_family_guard_t *guard,
                                  sparc64_family_wait_table_t *table,
                                  const sparc64_family_object_update_t *updates,
                                  size_t update_count)
{
    if (!guard_valid(guard) || table == NULL || update_count > 2 ||
        (update_count != 0 && updates == NULL) || table->count > table->capacity ||
        table->count > SPARC64_WAIT_MAX_ROWS ||
        (table->count != 0 && table->rows == NULL)) {
        errno = EINVAL;
        return -1;
    }
    sparc64_family_t *family = guard->family;
    sparc64_family_control_t *control = family->control;
    sparc64_family_wait_row_t *current_rows = NULL;
    if (catalog_wait_keys(family, table->rows, table->count) != 0)
        return -1;
    if (validate_wait_root(family, &current_rows) != 0)
        return -1;
    free(current_rows);
    if (table->revision != control->wait_revision) {
        errno = ESTALE;
        return -1;
    }
    if (table->revision == UINT64_MAX) {
        errno = EOVERFLOW;
        return -1;
    }

    sparc64_family_page_key_t keys[2] = {{0, 0}, {0, 0}};
    sparc64_family_page_state_t *destinations[2] = {NULL, NULL};
    const sparc64_family_page_state_t *targets[2] = {NULL, NULL};
    for (size_t i = 0; i < update_count; ++i) {
        sparc64_family_object_t *object = updates[i].object;
        if (object == NULL || updates[i].target == NULL ||
            object->family != family || updates[i].page_index >= object->slot_count) {
            errno = EINVAL;
            return -1;
        }
        keys[i] = (sparc64_family_page_key_t){object->object_id, updates[i].page_index};
        destinations[i] = &object->mapping->slots[updates[i].page_index].state;
        targets[i] = updates[i].target;
        if (i != 0 && key_equal(keys[0], keys[i])) {
            errno = EINVAL;
            return -1;
        }
        if (validate_target(destinations[i], targets[i]) != 0)
            return -1;
    }
    if (atomic_load_explicit(&control->log_marker, memory_order_acquire) != SPARC64_LOG_EMPTY) {
        errno = EBUSY;
        return -1;
    }

    uint64_t old_end = 0;
    if (control->wait_bank_capacity != 0) {
        if (!wait_pair_end(control->wait_bank_base, control->wait_bank_capacity,
                           &old_end)) {
            errno = EIO;
            return -1;
        }
    } else if (!wait_aligned_control_end(&old_end)) {
        errno = EOVERFLOW;
        return -1;
    }
    uint64_t target_capacity = control->wait_bank_capacity;
    uint64_t target_base = control->wait_bank_base;
    uint32_t target_index = control->wait_bank_index ^ 1u;
    bool growing = target_capacity == 0 || table->count > target_capacity;
    if (growing) {
        target_capacity = target_capacity == 0 ? SPARC64_WAIT_INITIAL_CAPACITY : target_capacity;
        while (target_capacity < table->count) {
            if (target_capacity > SPARC64_WAIT_MAX_ROWS / 2u) {
                errno = ENOSPC;
                return -1;
            }
            target_capacity *= 2u;
        }
        target_base = old_end;
        target_index = 0;
    }
    uint64_t target_end = 0;
    if (!wait_pair_end(target_base, target_capacity, &target_end)) {
        errno = EOVERFLOW;
        return -1;
    }
    if (growing) {
        uint64_t extent;
        if (family_control_extent(family, &extent) != 0)
            return -1;
        if (family->zero_backing) {
            if (ensure_control_extent(family, target_end) != 0)
                return -1;
        } else {
            if (extent > old_end &&
                ftruncate(family->control_fd, (off_t)old_end) != 0)
                return -1;
            if (ftruncate(family->control_fd, (off_t)target_end) != 0)
                return -1;
        }
    }
    uint64_t target_revision = control->wait_revision + 1u;
#ifdef SPARC64_FAMILY_TESTING
    if (family->hook != NULL)
        family->hook(SPARC64_FAMILY_TEST_WAIT_BEFORE_BANK_WRITE, family->hook_context);
#endif
    if (write_wait_bank(family, target_base, target_index, target_capacity,
                        table->count, target_revision, table->rows) != 0) {
        int saved = errno;
        if (growing)
            truncate_growth_tail(family, old_end);
        errno = saved;
        return -1;
    }
#ifdef SPARC64_FAMILY_TESTING
    if (family->hook != NULL)
        family->hook(SPARC64_FAMILY_TEST_WAIT_BANK_WRITTEN, family->hook_context);
#endif
    control->wait_target_base = target_base;
    control->wait_target_capacity = target_capacity;
    control->wait_target_index = target_index;
    control->wait_target_count = table->count;
    control->wait_target_revision = target_revision;
    if (update_count != 0) {
        control->log_key = keys[0];
        memcpy(&control->log_target, targets[0], sizeof(*targets[0]));
    }
    if (update_count == 2) {
        control->log_second_key = keys[1];
        memcpy(&control->log_second_target, targets[1], sizeof(*targets[1]));
    }
    control->log_kind = update_count == 0 ? SPARC64_LOG_WAIT :
                        update_count == 1 ? SPARC64_LOG_WAIT_OBJECT : SPARC64_LOG_WAIT_PAIR;
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
    if (replay_committed(family) != 0) {
        int saved = errno == 0 ? EIO : errno;
        family->poisoned = true;
        errno = saved;
        return -1;
    }
    table->revision = target_revision;
    return 0;
}

int sparc64_family_wait_backend_id(sparc64_family_guard_t *guard, bool mm_id,
                              uint64_t *out)
{
    if (!guard_valid(guard) || out == NULL) {
        errno = EINVAL;
        return -1;
    }
    sparc64_family_control_t *control = guard->family->control;
    uint64_t *counter = mm_id ? &control->next_mm_id : &control->next_wait_id;
    if (*counter == 0 || *counter == UINT64_MAX) {
        errno = EOVERFLOW;
        return -1;
    }
    uint64_t value = *counter;
    *counter = value + 1u;
    *out = value;
    return 0;
}

int sparc64_family_page_commit(sparc64_family_guard_t *guard, sparc64_family_page_t *page,
                          const sparc64_family_page_state_t *target)
{
    if (!guard_valid(guard) || page == NULL || target == NULL ||
        guard->family != page->family) {
        errno = EINVAL;
        return -1;
    }
    sparc64_family_page_key_t keys[2] = {page->key, {0, 0}};
    sparc64_family_page_state_t *destinations[2] = {&page->mapping->state, NULL};
    const sparc64_family_page_state_t *targets[2] = {target, NULL};
    return commit_states(guard, SPARC64_LOG_PAGE, 1, keys, destinations, targets, false);
}

int sparc64_family_object_create(sparc64_family_guard_t *guard, uint32_t slot_count,
                            sparc64_family_object_t **out)
{
    size_t size;
    if (out == NULL || !guard_valid(guard) ||
        !object_file_size(slot_count, &size)) {
        errno = EINVAL;
        return -1;
    }
    *out = NULL;
    sparc64_family_t *family = guard->family;
    uint64_t id = family->control->next_object_id;
    if (id == 0 || id == UINT64_MAX) {
        errno = EOVERFLOW;
        return -1;
    }
    char name[48];
    if (object_name(id, name) != 0)
        return -1;
    /* Like one-page creation, an interrupted O_EXCL may leave an orphan;
     * consume the ID first so that it can never identify a later object. */
    family->control->next_object_id = id + 1;
    int fd = openat(family->dir_fd, name,
                    O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0)
        return -1;
    if (normalize_owned_fd(&fd) != 0) {
        int saved = errno;
        if (fd >= 0)
            (void)close(fd);
        (void)unlinkat(family->dir_fd, name, 0);
        errno = saved;
        return -1;
    }
    if (fchmod(fd, 0600) != 0) {
        int saved = errno;
        (void)close(fd);
        (void)unlinkat(family->dir_fd, name, 0);
        errno = saved;
        return -1;
    }
    sparc64_family_object_t *object = map_object(family, id, slot_count, fd, true);
    if (object == NULL) {
        int saved = errno;
        (void)close(fd);
        (void)unlinkat(family->dir_fd, name, 0);
        errno = saved;
        return -1;
    }
    if (observe_open_inode(family, fd) != 0) {
        int saved = errno;
        sparc64_family_object_close(object);
        /* A possibly registered identity retains this initialized inode. */
        errno = saved;
        return -1;
    }
    *out = object;
    return 0;
}

int sparc64_family_object_open(sparc64_family_guard_t *guard, uint64_t object_id,
                          sparc64_family_object_t **out)
{
    if (out == NULL || !guard_valid(guard) || object_id == 0) {
        errno = EINVAL;
        return -1;
    }
    *out = NULL;
    char name[48];
    if (object_name(object_id, name) != 0)
        return -1;
    if (sparc64_family_reject_control_alias(guard->family->control_fd,
                                        guard->family->dir_fd, name) != 0)
        return -1;
    int fd = openat(guard->family->dir_fd, name, O_RDWR | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0)
        return -1;
    if (normalize_owned_fd(&fd) != 0) {
        int saved = errno;
        if (fd >= 0)
            (void)close(fd);
        errno = saved;
        return -1;
    }
    sparc64_family_object_t *object = map_object(guard->family, object_id, 0, fd, false);
    if (object == NULL) {
        int saved = errno;
        (void)close(fd);
        errno = saved;
        return -1;
    }
    if (observe_open_inode(guard->family, fd) != 0) {
        int saved = errno;
        sparc64_family_object_close(object);
        errno = saved;
        return -1;
    }
    *out = object;
    return 0;
}

void sparc64_family_object_close(sparc64_family_object_t *object)
{
    if (object == NULL)
        return;
    int saved = errno;
    if (object->mapping != NULL && !object->family->zero_backing)
        (void)munmap(object->mapping, object->mapping_size);
    if (object->fd >= 0)
        (void)close(object->fd);
    (void)atomic_fetch_sub_explicit(&object->family->live_views, 1,
                                    memory_order_relaxed);
    free(object);
    errno = saved;
}

uint64_t sparc64_family_object_id(const sparc64_family_object_t *object)
{
    return object == NULL ? 0 : object->object_id;
}

uint32_t sparc64_family_object_count(const sparc64_family_object_t *object)
{
    return object == NULL ? 0 : object->slot_count;
}

int sparc64_family_object_snapshot_observed(const sparc64_family_guard_t *guard,
                                       const sparc64_family_object_t *object,
                                       uint32_t page_index, sparc64_family_page_state_t *out,
                                       sparc64_measure_observer_t *measure)
{
    if (!guard_valid_observed(guard, measure) || object == NULL || out == NULL ||
        object->family != guard->family || page_index >= object->slot_count) {
        errno = EINVAL;
        return -1;
    }
    memcpy(out, &object->mapping->slots[page_index].state, sizeof(*out));
    return 0;
}

int sparc64_family_object_snapshot(const sparc64_family_guard_t *guard,
                              const sparc64_family_object_t *object,
                              uint32_t page_index, sparc64_family_page_state_t *out)
{
    return sparc64_family_object_snapshot_observed(guard, object, page_index, out, NULL);
}

int sparc64_family_object_snapshot_for_observed(const sparc64_family_guard_t *guard,
                                           const sparc64_family_t *expected_family,
                                           const sparc64_family_object_t *object,
                                           uint32_t page_index,
                                           sparc64_family_page_state_t *out,
                                           sparc64_measure_observer_t *measure)
{
    if (expected_family == NULL || object == NULL ||
        object->family != expected_family) {
        errno = EINVAL;
        return -1;
    }
    return sparc64_family_object_snapshot_observed(guard, object, page_index, out, measure);
}

int sparc64_family_object_commitv(sparc64_family_guard_t *guard,
                             const sparc64_family_object_update_t *updates,
                             size_t count)
{
    if (!guard_valid(guard) || updates == NULL || count == 0 || count > 2) {
        errno = EINVAL;
        return -1;
    }
    sparc64_family_page_key_t keys[2] = {{0, 0}, {0, 0}};
    sparc64_family_page_state_t *destinations[2] = {NULL, NULL};
    const sparc64_family_page_state_t *targets[2] = {NULL, NULL};
    for (size_t i = 0; i < count; ++i) {
        sparc64_family_object_t *object = updates[i].object;
        if (object == NULL || updates[i].target == NULL ||
            object->family != guard->family ||
            updates[i].page_index >= object->slot_count) {
            errno = EINVAL;
            return -1;
        }
        keys[i] = (sparc64_family_page_key_t){object->object_id, updates[i].page_index};
        destinations[i] = &object->mapping->slots[updates[i].page_index].state;
        targets[i] = updates[i].target;
    }
    return commit_states(guard, count == 2 ? SPARC64_LOG_OBJECT_PAIR : SPARC64_LOG_OBJECT,
                         count, keys, destinations, targets, false);
}

int sparc64_family_object_commit(sparc64_family_guard_t *guard, sparc64_family_object_t *object,
                            uint32_t page_index,
                            const sparc64_family_page_state_t *target)
{
    sparc64_family_object_update_t update = {object, page_index, target};
    return sparc64_family_object_commitv(guard, &update, 1);
}

int sparc64_family_object_commit_file_refresh(sparc64_family_guard_t *guard,
                                         sparc64_family_object_t *object,
                                         uint32_t page_index,
                                         const sparc64_family_page_state_t *target)
{
    if (!guard_valid(guard) || object == NULL || target == NULL ||
        object->family != guard->family || page_index >= object->slot_count) {
        errno = EINVAL;
        return -1;
    }
    sparc64_family_page_key_t keys[2] = {{object->object_id, page_index}, {0, 0}};
    sparc64_family_page_state_t *destinations[2] = {
        &object->mapping->slots[page_index].state, NULL
    };
    const sparc64_family_page_state_t *targets[2] = {target, NULL};
    return commit_states(guard, SPARC64_LOG_OBJECT, 1, keys, destinations, targets, true);
}

int cleanup_held(sparc64_family_guard_t *guard, bool fresh_scan)
{
    if (!guard_valid(guard) || !guard->family->creator ||
        guard->family->cleaned) {
        errno = EINVAL;
        return -1;
    }
    sparc64_family_t *family = guard->family;
    if (family->inode_observer != NULL) {
        errno = EBUSY;
        return -1;
    }
    if (atomic_load_explicit(&family->live_views, memory_order_relaxed) != 0) {
        errno = EBUSY;
        return -1;
    }
    bool was_retired = family->control->retired != 0;
    family->control->retired = 1;
    atomic_thread_fence(memory_order_release);
    /* A service receiving a metadata-only directory right has no inherited
     * DIR* cursor. Open a fresh enumerator relative to that exact capability;
     * every authority-bearing fstatat/unlinkat still uses the retained FD. */
    int scan_fd = fresh_scan ?
        openat(family->dir_fd, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW) :
        fcntl(family->dir_fd, F_DUPFD_CLOEXEC, 3);
    if (scan_fd < 0) {
        int saved = errno;
        if (!was_retired)
            family->control->retired = 0;
        errno = saved;
        return -1;
    }
    if (fresh_scan) {
        struct stat exact, opened;
        int stat_error = 0;
        if (fstat(family->dir_fd, &exact) != 0 ||
            fstat(scan_fd, &opened) != 0)
            stat_error = errno;
        else if (exact.st_dev != opened.st_dev || exact.st_ino != opened.st_ino)
            stat_error = EIO;
        if (stat_error != 0) {
            (void)close(scan_fd);
            if (!was_retired)
                family->control->retired = 0;
            errno = stat_error;
            return -1;
        }
    }
    DIR *directory = fdopendir(scan_fd);
    if (directory == NULL) {
        int saved = errno;
        (void)close(scan_fd);
        if (!was_retired)
            family->control->retired = 0;
        errno = saved;
        return -1;
    }
    struct dirent *entry;
    int unlink_error = 0;
    /* The service's fresh openat(".") stream starts at offset zero; its
     * metadata-only host scan role need not implement cursor seek. An
     * ordinary duplicated local stream may share an advanced offset. */
    if (!fresh_scan)
        rewinddir(directory);
    for (;;) {
        errno = 0;
        entry = readdir(directory);
        if (entry == NULL) {
            if (errno != 0 && unlink_error == 0)
                unlink_error = errno;
            break;
        }
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;
        if (!sparc64_family_owned_entry_name(entry->d_name)) {
            if (unlink_error == 0)
                unlink_error = EBUSY;
            continue;
        }
        struct stat status;
        if (fstatat(family->dir_fd, entry->d_name, &status, AT_SYMLINK_NOFOLLOW) != 0) {
            if (unlink_error == 0)
                unlink_error = errno;
            continue;
        }
        size_t object_maximum = 0;
        (void)object_file_size(SPARC64_FAMILY_OBJECT_MAX_SLOTS, &object_maximum);
        off_t maximum_size = strcmp(entry->d_name, "control") == 0
                           ? 0
                           : memcmp(entry->d_name, "object-", 7) == 0
                           ? (off_t)object_maximum
                           : (off_t)sizeof(sparc64_family_page_file_t);
        bool control_file = strcmp(entry->d_name, "control") == 0;
        if (control_file && !wait_control_max_size(&maximum_size)) {
            if (unlink_error == 0)
                unlink_error = EOVERFLOW;
            continue;
        }
        if (!S_ISREG(status.st_mode) || (status.st_mode & 07777) != 0600 ||
            status.st_uid != geteuid() || status.st_nlink != 1 ||
            status.st_size < 0 || status.st_size > maximum_size ||
            (control_file && !family->zero_backing &&
             status.st_size < (off_t)sizeof(sparc64_family_control_t)) ||
            (family->zero_backing && status.st_size != 0)) {
            if (unlink_error == 0)
                unlink_error = EPERM;
            continue;
        }
        if (unlinkat(family->dir_fd, entry->d_name, 0) != 0 && unlink_error == 0)
            unlink_error = errno;
    }
    if (closedir(directory) != 0 && unlink_error == 0)
        unlink_error = errno;
    if (unlink_error != 0) {
        errno = unlink_error;
        return -1;
    }
    if (rmdir(family->directory) != 0) {
        return -1;
    }
    family->cleaned = true;
    return 0;
}

int sparc64_family_cleanup(sparc64_family_t *family)
{
    if (family == NULL || !family->creator || family->cleaned) {
        errno = EINVAL;
        return -1;
    }
    sparc64_family_guard_t guard = {0};
    if (family_enter_internal(family, &guard, true) != 0)
        return -1;
    int result = cleanup_held(&guard, false);
    int saved = errno;
    if (sparc64_family_leave(&guard) != 0)
        return -1;
    errno = saved;
    return result;
}

int sparc64_family_cleanup_held_terminal(sparc64_family_guard_t *guard,
                                    bool sole_family_owner)
{
    /* The caller proves no other process can hold a family member, source
     * client, or view. Creator status by itself is never this proof. */
    if (!sole_family_owner) {
        errno = EPERM;
        return -1;
    }
    if (!guard_valid(guard) || guard->family->control->source_mode != 1 ||
        atomic_load_explicit(&guard->family->control->log_marker,
                             memory_order_acquire) != SPARC64_LOG_EMPTY) {
        errno = EBUSY;
        return -1;
    }
    return cleanup_held(guard, false);
}

int sparc64_family_register_service_cleanup(sparc64_family_guard_t *guard,
                                       bool *may_have_delegated)
{
    if (may_have_delegated != NULL)
        *may_have_delegated = false;
    if (!guard_valid(guard) || may_have_delegated == NULL ||
        !guard->family->creator || guard->family->cleaned ||
        guard->family->control->source_mode != 1 ||
        guard->family->directory[0] == '\0') {
        errno = EINVAL;
        return -1;
    }
    sparc64_family_t *family = guard->family;
    return sparc64_file_caps_register_terminal_cleanup(&family->sources,
        family->control_fd, family->dir_fd, family->directory,
        may_have_delegated);
}
