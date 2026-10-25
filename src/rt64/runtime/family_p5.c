/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#include "family_split.h"


int catalog_wait_keys(sparc64_family_t *family,
                               const sparc64_family_wait_row_t *rows, size_t count)
{
    bool needed = false;
    for (size_t i = 0; i < count; ++i)
        needed = needed || rows[i].key.kind == SPARC64_FAMILY_WAIT_FILE;
    if (!needed)
        return 0;
    sparc64_file_catalog_record_t *records = NULL;
    sparc64_family_control_t *control = family->control;
    if (read_file_catalog(family, (size_t)control->file_count, &records) != 0)
        return -1;
    bool valid = true;
    for (size_t i = 0; i < count && valid; ++i) {
        if (rows[i].key.kind != SPARC64_FAMILY_WAIT_FILE)
            continue;
        bool found = false;
        for (size_t j = 0; j < control->file_count; ++j) {
            uint64_t id;
            sparc64_file_identity_t identity;
            if (!sparc64_file_catalog_decode(&records[j], control->next_file_id,
                                          &id, &identity)) {
                valid = false;
                break;
            }
            if (rows[i].key.identity == id) {
                found = true;
                break;
            }
        }
        /* This is an unsigned inode byte offset, not a native pread off_t.
         * The zero-filled tail of a valid final page can lie beyond EOF. */
        valid = valid && found && (rows[i].key.offset & 3u) == 0;
    }
    free(records);
    if (!valid) {
        errno = EIO;
        return -1;
    }
    return 0;
}

uint64_t sparc64_family_recovery_epoch(const sparc64_family_guard_t *guard)
{
    return guard_valid(guard) ? guard->family->control->recovery_epoch : 0;
}

const char *sparc64_family_private_directory(const sparc64_family_t *family)
{
    return family == NULL || !family->creator ? NULL : family->directory;
}

int sparc64_family_observe_inodes(sparc64_family_guard_t *guard,
                             sparc64_family_inode_observer_t observer, void *context)
{
    if (!guard_valid(guard) || observer == NULL) {
        errno = EINVAL;
        return -1;
    }
    sparc64_family_t *family = guard->family;
    if (family->inode_observer != NULL) {
        errno = EBUSY;
        return -1;
    }
    if (sparc64_family_scan_inodes(family->control_fd, family->dir_fd,
                              observer, context) != 0)
        return -1;
    family->inode_observer_context = context;
    family->inode_observer = observer;
    return 0;
}

int sparc64_family_unobserve_inodes(sparc64_family_guard_t *guard)
{
    if (!guard_valid(guard) || guard->family->inode_observer == NULL) {
        errno = EINVAL;
        return -1;
    }
    guard->family->inode_observer = NULL;
    guard->family->inode_observer_context = NULL;
    return 0;
}

int sparc64_family_page_create(sparc64_family_guard_t *guard, sparc64_family_page_t **out)
{
    if (out == NULL || !guard_valid(guard)) {
        errno = EINVAL;
        return -1;
    }
    *out = NULL;
    sparc64_family_t *family = guard->family;
    if (family->zero_backing) {
        errno = EOPNOTSUPP;
        return -1;
    }
    uint64_t id = family->control->next_object_id;
    if (id == 0 || id == UINT64_MAX) {
        errno = EOVERFLOW;
        return -1;
    }
    sparc64_family_page_key_t key = {.object_id = id, .page_index = 0};
    char name[48];
    if (page_name(key, name) != 0)
        return -1;
    /* Consume the identity before filesystem side effects. A creator killed
     * after O_EXCL may leave an orphan file; its key is never reused. */
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
    sparc64_family_page_t *page = map_page(family, key, fd, true);
    if (page == NULL) {
        int saved = errno;
        (void)close(fd);
        (void)unlinkat(family->dir_fd, name, 0);
        errno = saved;
        return -1;
    }
    if (observe_open_inode(family, fd) != 0) {
        int saved = errno;
        sparc64_family_page_close(page);
        /* The callback may already have retained this inode identity.
         * Keep its valid file until resolver teardown and family cleanup. */
        errno = saved;
        return -1;
    }
    *out = page;
    return 0;
}

int sparc64_family_page_open(sparc64_family_guard_t *guard, sparc64_family_page_key_t key,
                        sparc64_family_page_t **out)
{
    if (out == NULL || !guard_valid(guard) ||
        key.object_id == 0 || key.page_index != 0) {
        errno = EINVAL;
        return -1;
    }
    *out = NULL;
    if (guard->family->zero_backing) {
        errno = EOPNOTSUPP;
        return -1;
    }
    char name[48];
    if (page_name(key, name) != 0)
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
    sparc64_family_page_t *page = map_page(guard->family, key, fd, false);
    if (page == NULL) {
        int saved = errno;
        (void)close(fd);
        errno = saved;
        return -1;
    }
    if (observe_open_inode(guard->family, fd) != 0) {
        int saved = errno;
        sparc64_family_page_close(page);
        errno = saved;
        return -1;
    }
    *out = page;
    return 0;
}

void sparc64_family_page_close(sparc64_family_page_t *page)
{
    if (page == NULL)
        return;
    int saved = errno;
    if (page->mapping != NULL)
        (void)munmap(page->mapping, page->mapping_size);
    if (page->fd >= 0)
        (void)close(page->fd);
    (void)atomic_fetch_sub_explicit(&page->family->live_views, 1, memory_order_relaxed);
    free(page);
    errno = saved;
}

sparc64_family_page_key_t sparc64_family_page_key(const sparc64_family_page_t *page)
{
    return page == NULL ? (sparc64_family_page_key_t){0, 0} : page->key;
}

const sparc64_family_page_state_t *sparc64_family_page_readonly(const sparc64_family_guard_t *guard,
                                                       const sparc64_family_page_t *page)
{
    return !guard_valid(guard) || page == NULL || page->family != guard->family
         ? NULL : &page->mapping->state;
}

static int validate_target_mode(const sparc64_family_page_state_t *current,
                                const sparc64_family_page_state_t *target,
                                bool file_refresh)
{
    bool bytes_changed = false;
    if (file_refresh) {
        static const uint64_t zero[4] = {0};
        if (current->private_cow != 0 || target->private_cow != 0 ||
            current->reserved != 0 || target->reserved != 0 ||
            memcmp(target->notified, zero, sizeof(zero)) != 0) {
            errno = EINVAL;
            return -1;
        }
        if (current->content_generation == UINT64_MAX) {
            errno = EOVERFLOW;
            return -1;
        }
        if (target->content_generation != current->content_generation + 1u) {
            errno = EINVAL;
            return -1;
        }
    }
    if (target->private_cow > 1 || target->reserved != 0) {
        errno = EINVAL;
        return -1;
    }
    bool metadata_changed = target->private_cow != current->private_cow ||
        memcmp(target->notified, current->notified, sizeof(target->notified)) != 0;
    if (target->content_generation < current->content_generation) {
        errno = EINVAL;
        return -1;
    }
    for (size_t i = 0; i < SPARC64_FAMILY_EPOCHS; ++i) {
        bool prepaid = file_refresh &&
            (current->notified[i / 64u] & (UINT64_C(1) << (i % 64u))) != 0;
        if (prepaid && current->epochs[i] == 0) {
            errno = EINVAL;
            return -1;
        }
        if (target->epochs[i] < current->epochs[i]) {
            errno = EINVAL;
            return -1;
        }
        size_t offset = i * 16;
        if (memcmp(target->bytes + offset, current->bytes + offset, 16) != 0) {
            bytes_changed = true;
            if (target->epochs[i] == current->epochs[i] && !prepaid) {
                errno = current->epochs[i] == UINT64_MAX ? EOVERFLOW : EINVAL;
                return -1;
            }
        }
    }
    /* COW and notification state affects later refresh even when bytes and
     * reservation epochs stay unchanged. It needs an observable publication. */
    if ((bytes_changed || metadata_changed) &&
        target->content_generation == current->content_generation) {
        errno = current->content_generation == UINT64_MAX ? EOVERFLOW : EINVAL;
        return -1;
    }
    return 0;
}

int validate_target(const sparc64_family_page_state_t *current,
                           const sparc64_family_page_state_t *target)
{
    return validate_target_mode(current, target, false);
}

int commit_states(sparc64_family_guard_t *guard, uint32_t kind, size_t count,
                         const sparc64_family_page_key_t keys[2],
                         sparc64_family_page_state_t *const destinations[2],
                         const sparc64_family_page_state_t *const targets[2],
                         bool file_refresh)
{
    sparc64_family_t *family = guard->family;
    sparc64_family_control_t *control = family->control;
    if (count == 0 || count > 2 ||
        (file_refresh && (kind != SPARC64_LOG_OBJECT || count != 1)) ||
        (count == 2 && key_equal(keys[0], keys[1]))) {
        errno = EINVAL;
        return -1;
    }
    for (size_t i = 0; i < count; ++i)
        if (validate_target_mode(destinations[i], targets[i], file_refresh) != 0)
            return -1;
    if (atomic_load_explicit(&control->log_marker, memory_order_acquire) != SPARC64_LOG_EMPTY) {
        errno = EBUSY;
        return -1;
    }
    control->log_kind = kind;
    control->log_key = keys[0];
    memcpy(&control->log_target, targets[0], sizeof(*targets[0]));
    if (count == 2) {
        control->log_second_key = keys[1];
        memcpy(&control->log_second_target, targets[1], sizeof(*targets[1]));
    }
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
    apply_absolute_state(destinations[0], &control->log_target, family, false);
    if (count == 2)
        apply_absolute_state(destinations[1], &control->log_second_target, family, false);
    atomic_store_explicit(&control->log_marker, SPARC64_LOG_EMPTY, memory_order_release);
    return 0;
}

int validate_wait_root(sparc64_family_t *family,
                              sparc64_family_wait_row_t **rows_out)
{
    sparc64_family_control_t *control = family->control;
    if (control->wait_bank_capacity == 0) {
        if (control->wait_bank_base != 0 || control->wait_bank_index != 0 ||
            control->wait_count != 0 || control->wait_revision != 0) {
            errno = EIO;
            return -1;
        }
        if (rows_out != NULL)
            *rows_out = NULL;
        return 0;
    }
    uint64_t end = 0, minimum_base = 0;
    uint64_t extent;
    if (control->wait_bank_capacity > SPARC64_WAIT_MAX_ROWS ||
        control->wait_count > control->wait_bank_capacity ||
        control->wait_revision == 0 || control->wait_bank_index > 1 ||
        !catalog_reserved_end(&minimum_base) ||
        control->wait_bank_base < minimum_base ||
        control->wait_bank_base % SPARC64_FAMILY_PAGE_SIZE != 0 ||
        !wait_pair_end(control->wait_bank_base, control->wait_bank_capacity, &end)) {
        errno = EIO;
        return -1;
    }
    if (family_control_extent(family, &extent) != 0)
        return -1;
    if (end > extent) {
        errno = EIO;
        return -1;
    }
    sparc64_family_wait_row_t *rows = NULL;
    if (read_wait_bank(family, control->wait_bank_base,
                       control->wait_bank_index, control->wait_bank_capacity,
                       control->wait_count, control->wait_revision, &rows) != 0)
        return -1;
    if (catalog_wait_keys(family, rows, (size_t)control->wait_count) != 0) {
        int saved = errno;
        free(rows);
        errno = saved;
        return -1;
    }
    if (rows_out != NULL)
        *rows_out = rows;
    else
        free(rows);
    return 0;
}

int sparc64_family_wait_backend_read(sparc64_family_guard_t *guard,
                                sparc64_family_wait_table_t *table)
{
    if (!guard_valid(guard) || table == NULL) {
        errno = EINVAL;
        return -1;
    }
    sparc64_family_t *family = guard->family;
    sparc64_family_wait_row_t *rows = NULL;
    if (validate_wait_root(family, &rows) != 0)
        return -1;
    *table = (sparc64_family_wait_table_t){
        .rows = rows,
        .count = (size_t)family->control->wait_count,
        .capacity = (size_t)family->control->wait_bank_capacity,
        .revision = family->control->wait_revision
    };
    return 0;
}

bool catalog_reserved_end(uint64_t *end)
{
    size_t size = sizeof(sparc64_family_control_t);
    if (size > SIZE_MAX - (SPARC64_FAMILY_PAGE_SIZE - 1u))
        return false;
    size_t aligned = (size + SPARC64_FAMILY_PAGE_SIZE - 1u) &
                     ~(size_t)(SPARC64_FAMILY_PAGE_SIZE - 1u);
    if (SPARC64_FILE_CATALOG_CAPACITY >
        ((uint64_t)INT64_MAX - aligned) / sizeof(sparc64_file_catalog_record_t))
        return false;
    *end = (uint64_t)aligned +
           SPARC64_FILE_CATALOG_CAPACITY * sizeof(sparc64_file_catalog_record_t);
    return *end <= (uint64_t)INT64_MAX;
}

bool wait_aligned_control_end(uint64_t *end)
{
    return catalog_reserved_end(end);
}

bool wait_control_max_size(off_t *size_out)
{
    uint64_t end = 0;
    if (size_out == NULL || !wait_aligned_control_end(&end))
        return false;
    for (uint64_t capacity = SPARC64_WAIT_INITIAL_CAPACITY;; capacity *= 2u) {
        size_t bank_size = 0;
        if (!wait_bank_size(capacity, &bank_size) ||
            bank_size > ((uint64_t)INT64_MAX - end) / 2u)
            return false;
        end += (uint64_t)bank_size * 2u;
        if (capacity == SPARC64_WAIT_MAX_ROWS)
            break;
        if (capacity > SPARC64_WAIT_MAX_ROWS / 2u)
            return false;
    }
    *size_out = (off_t)end;
    return true;
}

void truncate_growth_tail(sparc64_family_t *family, uint64_t old_end)
{
    if (!family->zero_backing && old_end <= (uint64_t)INT64_MAX)
        (void)ftruncate(family->control_fd, (off_t)old_end);
}
