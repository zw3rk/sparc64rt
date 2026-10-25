/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#include "family_split.h"


int write_wait_bank(sparc64_family_t *family, uint64_t base, uint32_t index,
                           uint64_t capacity, uint64_t count, uint64_t revision,
                           const sparc64_family_wait_row_t *rows)
{
    if (capacity == 0 || count > capacity || capacity > SPARC64_WAIT_MAX_ROWS ||
        (count != 0 && rows == NULL)) {
        errno = EINVAL;
        return -1;
    }
    uint64_t offset = 0;
    size_t bank_size = 0;
    if (!wait_offset(base, index, capacity, &offset) ||
        !wait_bank_size(capacity, &bank_size)) {
        errno = EOVERFLOW;
        return -1;
    }
    size_t bytes_size = (size_t)capacity * sizeof(sparc64_family_wait_row_t);
    sparc64_family_wait_row_t *bank_rows = calloc(1, bytes_size);
    if (bank_rows == NULL)
        return -1;
    if (count != 0)
        memcpy(bank_rows, rows, (size_t)count * sizeof(*rows));
    sparc64_family_wait_bank_header_t header = {
        .magic = SPARC64_WAIT_BANK_MAGIC,
        .version = SPARC64_WAIT_BANK_VERSION,
        .header_size = sizeof(header),
        .capacity = capacity,
        .count = count,
        .revision = revision,
        .checksum = wait_checksum(bank_rows, bytes_size),
        .reserved = 0
    };
    int result = family_control_write(family, bank_rows, bytes_size,
                                      offset + sizeof(header));
    int saved = errno;
    free(bank_rows);
    if (result != 0) {
        errno = saved;
        return -1;
    }
    /* Publish the bank header only after every fixed-capacity row was written. */
    if (family_control_write(family, &header, sizeof(header), offset) != 0)
        return -1;
    uint64_t pair_end = 0;
    if (!wait_pair_end(base, capacity, &pair_end) || pair_end > (uint64_t)INT64_MAX) {
        errno = EOVERFLOW;
        return -1;
    }
    uint64_t extent;
    if (family_control_extent(family, &extent) != 0)
        return -1;
    if (extent < pair_end) {
        errno = EIO;
        return -1;
    }
    (void)bank_size;
    return 0;
}

int replay_committed(sparc64_family_t *family)
{
    sparc64_family_control_t *control = family->control;
    uint32_t marker = atomic_load_explicit(&control->log_marker, memory_order_acquire);
    if (marker == SPARC64_LOG_EMPTY || marker == SPARC64_LOG_PREPARED)
        return 0;
    if (marker != SPARC64_LOG_COMMITTED) {
        errno = EIO;
        return -1;
    }
#ifdef SPARC64_FAMILY_TESTING
    if (family->test_fail_wait_replay_once &&
        (control->log_kind == SPARC64_LOG_WAIT ||
         control->log_kind == SPARC64_LOG_WAIT_OBJECT ||
         control->log_kind == SPARC64_LOG_WAIT_PAIR)) {
        family->test_fail_wait_replay_once = false;
        errno = EIO;
        return -1;
    }
#endif
#ifdef SPARC64_FAMILY_TESTING
    if (family->hook != NULL)
        family->hook(SPARC64_FAMILY_TEST_RECOVERY_COMMITTED, family->hook_context);
#endif
    if (control->log_kind == SPARC64_LOG_FILE) {
        if (replay_file_record(family) != 0)
            return -1;
    } else if (control->log_kind == SPARC64_LOG_PAGE) {
        char name[48];
        if (control->log_key.object_id == 0 || control->log_key.page_index != 0 ||
            page_name(control->log_key, name) != 0) {
            errno = EIO;
            return -1;
        }
        if (sparc64_family_reject_control_alias(family->control_fd, family->dir_fd, name) != 0)
            return -1;
        int fd = openat(family->dir_fd, name, O_RDWR | O_CLOEXEC | O_NOFOLLOW);
        if (fd < 0)
            return -1;
        if (normalize_owned_fd(&fd) != 0) {
            int saved = errno;
            if (fd >= 0)
                (void)close(fd);
            errno = saved;
            return -1;
        }
        sparc64_family_page_t *page = map_page(family, control->log_key, fd, false);
        if (page == NULL) {
            int saved = errno;
            (void)close(fd);
            errno = saved;
            return -1;
        }
        apply_absolute_state(&page->mapping->state, &control->log_target, family, true);
        sparc64_family_page_close(page);
    } else if (control->log_kind == SPARC64_LOG_OBJECT ||
               control->log_kind == SPARC64_LOG_OBJECT_PAIR) {
        bool pair = control->log_kind == SPARC64_LOG_OBJECT_PAIR;
        if (pair && key_equal(control->log_key, control->log_second_key)) {
            errno = EIO;
            return -1;
        }
        sparc64_family_object_t *first = open_logged_object(family, control->log_key);
        if (first == NULL)
            return -1;
        sparc64_family_object_t *second = NULL;
        if (pair) {
            second = open_logged_object(family, control->log_second_key);
            if (second == NULL) {
                int saved = errno;
                sparc64_family_object_close(first);
                errno = saved;
                return -1;
            }
        }
        /* Both destinations are pinned and checked before applying either.
         * A death during either copy leaves COMMITTED for idempotent replay. */
        apply_absolute_state(&first->mapping->slots[control->log_key.page_index].state,
                             &control->log_target, family, true);
        if (pair)
            apply_absolute_state(&second->mapping->slots[control->log_second_key.page_index].state,
                                 &control->log_second_target, family, true);
        sparc64_family_object_close(second);
        sparc64_family_object_close(first);
    } else if (control->log_kind == SPARC64_LOG_WAIT ||
               control->log_kind == SPARC64_LOG_WAIT_OBJECT ||
               control->log_kind == SPARC64_LOG_WAIT_PAIR) {
        bool has_first = control->log_kind != SPARC64_LOG_WAIT;
        bool has_second = control->log_kind == SPARC64_LOG_WAIT_PAIR;
        uint64_t target_end = 0;
        uint64_t minimum_base = 0;
        uint64_t target_extent = 0;
        if (control->wait_target_capacity == 0 ||
            control->wait_target_count > control->wait_target_capacity ||
            control->wait_target_capacity > SPARC64_WAIT_MAX_ROWS ||
            !catalog_reserved_end(&minimum_base) ||
            control->wait_target_base < minimum_base ||
            control->wait_target_base % SPARC64_FAMILY_PAGE_SIZE != 0 ||
            control->wait_target_revision == 0 ||
            control->wait_target_index > 1 ||
            !wait_pair_end(control->wait_target_base,
                           control->wait_target_capacity, &target_end) ||
            family_control_extent(family, &target_extent) != 0 ||
            target_end > target_extent) {
            errno = EIO;
            return -1;
        }
        sparc64_family_wait_row_t *rows = NULL;
        if (read_wait_bank(family, control->wait_target_base,
                           control->wait_target_index,
                           control->wait_target_capacity,
                           control->wait_target_count,
                           control->wait_target_revision, &rows) != 0)
            return -1;
        if (catalog_wait_keys(family, rows, (size_t)control->wait_target_count) != 0) {
            int saved = errno;
            free(rows);
            errno = saved;
            return -1;
        }
        sparc64_family_object_t *first = NULL;
        sparc64_family_object_t *second = NULL;
        if (has_first) {
            first = open_logged_object(family, control->log_key);
            if (first == NULL) {
                free(rows);
                return -1;
            }
        }
        if (has_second) {
            second = open_logged_object(family, control->log_second_key);
            if (second == NULL) {
                int saved = errno;
                sparc64_family_object_close(first);
                free(rows);
                errno = saved;
                return -1;
            }
        }
        /* The targets were checked before PREPARED was published. The source
         * may now contain part of a previous replay (generation/epochs before
         * bytes), so recovery must validate immutable object/key shape only. */
        control->wait_bank_base = control->wait_target_base;
        control->wait_bank_capacity = control->wait_target_capacity;
        control->wait_bank_index = control->wait_target_index;
        control->wait_count = control->wait_target_count;
        control->wait_revision = control->wait_target_revision;
#ifdef SPARC64_FAMILY_TESTING
        if (family->hook != NULL)
            family->hook(SPARC64_FAMILY_TEST_WAIT_RECOVERY_ROOT_APPLIED,
                         family->hook_context);
#endif
        if (has_first) {
            apply_absolute_state(&first->mapping->slots[control->log_key.page_index].state,
                                 &control->log_target, family, true);
#ifdef SPARC64_FAMILY_TESTING
            if (has_second && family->hook != NULL)
                family->hook(SPARC64_FAMILY_TEST_WAIT_RECOVERY_FIRST_OBJECT_APPLIED,
                             family->hook_context);
#endif
        }
        if (has_second)
            apply_absolute_state(&second->mapping->slots[control->log_second_key.page_index].state,
                                 &control->log_second_target, family, true);
        sparc64_family_object_close(second);
        sparc64_family_object_close(first);
        free(rows);
    } else {
        errno = EIO;
        return -1;
    }
    atomic_store_explicit(&control->log_marker, SPARC64_LOG_EMPTY, memory_order_release);
    return 0;
}

int initialize_family(sparc64_family_t **out, int control_fd, int dir_fd,
                             sparc64_inode_pins_t pins, sparc64_file_caps_client_t sources,
                             bool creator, const char *directory,
                             bool terminal_sources,
                             sparc64_family_storage_authority_t authority)
{
    if (out == NULL || !authority_valid(authority) ||
        !distinct_source_fds(control_fd, dir_fd, pins, sources)) {
        close_family_sources(control_fd, dir_fd, pins, sources);
        errno = EINVAL;
        return -1;
    }
    *out = NULL;
    sparc64_inode_pins_t adopted = SPARC64_INODE_PINS_INITIALIZER;
    if (sparc64_inode_pins_adopt(&adopted, pins.sender, pins.receiver) != 0) {
        int saved = errno;
        close_owned_fds(control_fd, dir_fd);
        sparc64_file_caps_client_close(&sources);
        errno = saved;
        return -1;
    }
    pins = adopted;
    if (source_caps_present(sources)) {
        sparc64_file_caps_client_t adopted_sources = SPARC64_FILE_CAPS_CLIENT_INITIALIZER;
        int adopted_result = terminal_sources ?
            sparc64_file_caps_client_adopt_terminal(&adopted_sources, sources.request_fd,
                                                sources.lifetime_fd) :
            sparc64_file_caps_client_adopt(&adopted_sources, sources.request_fd,
                                       sources.lifetime_fd);
        if (adopted_result != 0) {
            int saved = errno;
            sparc64_family_close_capabilities(control_fd, dir_fd, pins);
            errno = saved;
            return -1;
        }
        sources = adopted_sources;
    }
    struct stat dir_status, control_status, named_status;
    int saved = 0;
    if (fstat(dir_fd, &dir_status) != 0 || fstat(control_fd, &control_status) != 0 ||
        fstatat(dir_fd, "control", &named_status, AT_SYMLINK_NOFOLLOW) != 0) {
        saved = errno;
        goto fail_fds;
    }
    if (control_fd < 3 || dir_fd < 3 || control_fd == dir_fd ||
        !S_ISDIR(dir_status.st_mode) || (dir_status.st_mode & 07777) != 0700 ||
        !S_ISREG(control_status.st_mode) || (control_status.st_mode & 07777) != 0600 ||
        dir_status.st_uid != geteuid() || control_status.st_uid != geteuid() ||
        control_status.st_nlink != 1 ||
        control_status.st_dev != named_status.st_dev || control_status.st_ino != named_status.st_ino) {
        saved = EPERM;
        goto fail_fds;
    }
    int control_flags = fcntl(control_fd, F_GETFD);
    int directory_flags = fcntl(dir_fd, F_GETFD);
    if (control_flags < 0 || directory_flags < 0 ||
        fcntl(control_fd, F_SETFD, control_flags | FD_CLOEXEC) != 0 ||
        fcntl(dir_fd, F_SETFD, directory_flags | FD_CLOEXEC) != 0) {
        saved = errno;
        goto fail_fds;
    }
    size_t control_size = sizeof(sparc64_family_control_t);
    uint64_t minimum_size = 0;
    bool zero_backing = control_status.st_size == 0;
    if (!catalog_reserved_end(&minimum_size) || control_status.st_size < 0 ||
        (!zero_backing && (uint64_t)control_status.st_size < minimum_size) ||
        (zero_backing && !creator)) {
        saved = EINVAL;
        goto fail_fds;
    }
    if (zero_backing &&
        (!family_authorize_fd(dir_fd, true, authority) ||
         !family_authorize_fd(control_fd, false, authority))) {
        saved = errno;
        goto fail_fds;
    }
    sparc64_family_zero_segment_t zero_control = {0};
    void *mapping;
    if (zero_backing) {
        if (minimum_size > SPARC64_ZERO_CONTROL_HEAD_SIZE ||
            sparc64_family_zero_segment_attach_fd(control_fd,
                SPARC64_FAMILY_ZERO_SEGMENT_CONTROL, 0,
                SPARC64_ZERO_CONTROL_HEAD_SIZE,
                &zero_control) != 0) {
            saved = errno;
            goto fail_fds;
        }
        mapping = zero_control.payload;
    } else {
        mapping = mmap(NULL, control_size, PROT_READ | PROT_WRITE, MAP_SHARED,
                       control_fd, 0);
        if (mapping == MAP_FAILED) {
            saved = errno;
            goto fail_fds;
        }
    }
    sparc64_family_control_t *control = mapping;
    if (control->magic != SPARC64_FAMILY_MAGIC || control->version != SPARC64_FAMILY_VERSION ||
        control->size != control_size || control->source_reserved != 0 ||
        control->source_mode != (source_caps_present(sources) ? 1u : 0u) ||
        control->next_object_id == 0 ||
        (control->source_mode == 0 ? control->file_index_object != 0 :
         (control->file_index_object == 0 || control->file_index_object >= control->next_object_id)) ||
        control->inode_pin_attempts > SPARC64_INODE_PINS_MAX_ATTEMPTS ||
        control->file_count > SPARC64_FILE_CATALOG_CAPACITY ||
        control->next_file_id == 0 ||
        control->next_source_id == 0 ||
        control->next_source_id > SPARC64_FILE_CAPS_MAX_ATTEMPTS + 1u ||
        control->source_attempts > SPARC64_FILE_CAPS_MAX_ATTEMPTS ||
        !atomic_is_lock_free(&control->log_marker)) {
        if (zero_backing)
            sparc64_family_zero_segment_detach(&zero_control);
        else
            (void)munmap(mapping, control_size);
        saved = EINVAL;
        goto fail_fds;
    }
    sparc64_family_t *family = calloc(1, sizeof(*family));
    if (family == NULL) {
        saved = errno;
        if (zero_backing)
            sparc64_family_zero_segment_detach(&zero_control);
        else
            (void)munmap(mapping, control_size);
        goto fail_fds;
    }
    family->control_fd = control_fd;
    family->dir_fd = dir_fd;
    family->pins = pins;
    family->sources = sources;
    family->control = control;
    family->zero_backing = zero_backing;
    family->zero_control = zero_control;
    family->zero_fragment_pending_fd = -1;
    family->storage_authority = authority;
    family->local_pid = getpid();
    family->creator = creator;
    if (directory != NULL) {
        int count = snprintf(family->directory, sizeof(family->directory), "%s", directory);
        if (count < 0 || (size_t)count >= sizeof(family->directory)) {
            free(family);
            if (zero_backing)
                sparc64_family_zero_segment_detach(&zero_control);
            else
                (void)munmap(mapping, control_size);
            saved = ENAMETOOLONG;
            goto fail_fds;
        }
    }
    int pthread_error = pthread_mutex_init(&family->local_mutex, NULL);
    if (pthread_error != 0) {
        free(family);
        if (zero_backing)
            sparc64_family_zero_segment_detach(&zero_control);
        else
            (void)munmap(mapping, control_size);
        saved = pthread_error;
        goto fail_fds;
    }
    family->initialized = true;
    *out = family;
    return 0;

fail_fds:
    close_family_sources(control_fd, dir_fd, pins, sources);
    errno = saved;
    return -1;
}

int sparc64_family_attach(sparc64_family_t **out, int owned_control_fd, int owned_dir_fd,
                       sparc64_inode_pins_t owned_pins)
{
    return initialize_family(out, owned_control_fd, owned_dir_fd, owned_pins,
                               (sparc64_file_caps_client_t)SPARC64_FILE_CAPS_CLIENT_INITIALIZER,
                               false, NULL, false, SPARC64_FAMILY_AUTHORITY_AUTO);
}

int sparc64_family_attach_with_sources(sparc64_family_t **out, int owned_control_fd,
                                    int owned_dir_fd, sparc64_inode_pins_t owned_pins,
                                    sparc64_file_caps_client_t owned_sources)
{
    if (out == NULL || *out != NULL || !source_caps_present(owned_sources)) {
        close_family_sources(owned_control_fd, owned_dir_fd, owned_pins, owned_sources);
        errno = EINVAL;
        return -1;
    }
    return initialize_family(out, owned_control_fd, owned_dir_fd, owned_pins,
                               owned_sources, false, NULL, false,
                               SPARC64_FAMILY_AUTHORITY_AUTO);
}

bool exec_guard_valid(const sparc64_family_exec_t *exec)
{
    return exec != NULL && exec->family != NULL && exec->guard != NULL &&
           exec->family->initialized && !exec->family->poisoned &&
           exec->family->exec_prepared == exec &&
           exec->family->local_pid == getpid() && exec->guard->held &&
           exec->guard->family == exec->family &&
           exec->family->active_guard == exec->guard &&
           exec->guard->incarnation == exec->state.incarnation &&
           pthread_equal(exec->guard->owner_thread, pthread_self()) != 0;
}

bool exec_identity_matches(int control_fd, int dir_fd,
                                   const sparc64_family_identity_t *identity)
{
    struct stat control, directory;
    return fstat(control_fd, &control) == 0 && fstat(dir_fd, &directory) == 0 &&
           control.st_dev == identity->control_device &&
           control.st_ino == identity->control_inode &&
           directory.st_dev == identity->directory_device &&
           directory.st_ino == identity->directory_inode;
}

static int exec_prepare(sparc64_family_guard_t *guard, sparc64_family_exec_t **out,
                         bool with_sources)
{
    if (out != NULL && *out != NULL) {
        errno = EBUSY;
        return -1;
    }
    if (out == NULL || !guard_valid(guard)) {
        errno = EINVAL;
        return -1;
    }
    sparc64_family_t *family = guard->family;
    if (family->zero_backing) {
        errno = EOPNOTSUPP;
        return -1;
    }
    if (source_caps_present(family->sources) != with_sources) {
        errno = EOPNOTSUPP;
        return -1;
    }
    if (family->exec_prepared != NULL) {
        errno = EBUSY;
        return -1;
    }
    if (family->poisoned || family->control->active != 1 ||
        family->control->active_incarnation != family->incarnation ||
        family->control->retired != 0 ||
        atomic_load_explicit(&family->control->log_marker, memory_order_acquire) !=
        SPARC64_LOG_EMPTY) {
        errno = EIO;
        return -1;
    }
    /* A returning resize error can leave an intent behind under this same
     * guard. Never export an exec owner that could resume stale file views. */
    if (with_sources && recover_file_state(guard) != 0)
        return -1;
    sparc64_family_exec_t *exec = calloc(1, sizeof(*exec));
    if (exec == NULL)
        return -1;
    int descriptors[6];
    exec->capability_count = family_all_fds(family, descriptors);
    bool valid = distinct_source_fds(descriptors[0], descriptors[1],
                                      family->pins, family->sources);
    for (size_t i = 0; i < exec->capability_count; ++i) {
        exec->flags[i] = fcntl(descriptors[i], F_GETFD);
        valid = valid && exec->flags[i] >= 0 &&
                (exec->flags[i] & FD_CLOEXEC) != 0;
    }
    if (!valid || sparc64_family_identity(guard, &exec->state.identity) != 0) {
        free(exec);
        errno = EIO;
        return -1;
    }
    exec->family = family;
    exec->guard = guard;
    exec->state.owner_pid = (uint64_t)getpid();
    exec->state.incarnation = family->incarnation;
    exec->state.recovery_epoch = family->control->recovery_epoch;
    exec->state.next_incarnation = family->control->next_incarnation;
    exec->state.creator = family->creator;
    memcpy(exec->state.directory, family->directory, sizeof(family->directory));
    family->exec_prepared = exec;
    *out = exec;
    return 0;
}

int sparc64_family_exec_prepare(sparc64_family_guard_t *guard, sparc64_family_exec_t **out)
{
    return exec_prepare(guard, out, false);
}

int sparc64_family_exec_prepare_sources(sparc64_family_guard_t *guard, sparc64_family_exec_t **out)
{
    return exec_prepare(guard, out, true);
}

const sparc64_family_exec_state_t *sparc64_family_exec_state(const sparc64_family_exec_t *exec)
{
    return exec_guard_valid(exec) ? &exec->state : NULL;
}

int sparc64_family_exec_capabilities(const sparc64_family_exec_t *exec, int output[4])
{
    if (!exec_guard_valid(exec) || output == NULL) {
        errno = EINVAL;
        return -1;
    }
    if (exec->capability_count != 4) {
        errno = EOPNOTSUPP;
        return -1;
    }
    family_fds(exec->family, output);
    return 0;
}

int sparc64_family_exec_source_capabilities(const sparc64_family_exec_t *exec, int output[6])
{
    if (!exec_guard_valid(exec) || output == NULL) {
        errno = EINVAL;
        return -1;
    }
    if (exec->capability_count != 6) {
        errno = EOPNOTSUPP;
        return -1;
    }
    (void)family_all_fds(exec->family, output);
    return 0;
}

int exec_restore_flags(sparc64_family_exec_t *exec)
{
    int descriptors[6];
    (void)family_all_fds(exec->family, descriptors);
    bool failed = false;
    for (size_t i = 0; i < exec->capability_count; ++i)
        if (fcntl(descriptors[i], F_SETFD, exec->flags[i]) != 0)
            failed = true;
    if (failed) {
        exec->family->poisoned = true;
        errno = EIO;
        return -1;
    }
    return 0;
}
