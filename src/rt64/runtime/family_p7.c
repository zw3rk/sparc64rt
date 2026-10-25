/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#include "family_split.h"


void sparc64_family_cleanup_service_release(void *retained)
{
    sparc64_zero_service_retained_t *owner = retained;
    if (owner == NULL)
        return;
    sparc64_family_zero_segment_detach(&owner->root.segment);
    sparc64_family_zero_segment_detach(&owner->control);
    free(owner);
}

int sparc64_family_cleanup_service_prepare_authority(int borrowed_control_fd,
    int borrowed_directory_fd, const char *directory, void **out,
    sparc64_family_storage_authority_t authority)
{
    if (out == NULL || *out != NULL || borrowed_control_fd < 3 ||
        borrowed_directory_fd < 3 || directory == NULL ||
        !authority_valid(authority)) {
        errno = EINVAL;
        return -1;
    }
    struct stat control_status;
    if (fstat(borrowed_control_fd, &control_status) != 0)
        return -1;
    if (control_status.st_size != 0)
        return 0;
#ifndef __linux__
    errno = EOPNOTSUPP;
    return -1;
#else
    if (!family_authorize_fd(borrowed_directory_fd, true, authority) ||
        !family_authorize_fd(borrowed_control_fd, false, authority)) {
        errno = EACCES;
        return -1;
    }
    uint64_t minimum_size;
    if (!catalog_reserved_end(&minimum_size) ||
        minimum_size > SPARC64_ZERO_CONTROL_HEAD_SIZE) {
        errno = EOVERFLOW;
        return -1;
    }
    sparc64_zero_service_retained_t *owner = calloc(1, sizeof(*owner));
    if (owner == NULL)
        return -1;
    owner->storage_authority = authority;
    int result = sparc64_family_zero_segment_attach_fd(borrowed_control_fd,
        SPARC64_FAMILY_ZERO_SEGMENT_CONTROL, 0, SPARC64_ZERO_CONTROL_HEAD_SIZE,
        &owner->control);
    if (result == 0) {
        sparc64_family_control_t *control = owner->control.payload;
        uint64_t root_id = control->file_index_object;
        char name[48];
        if (control->magic != SPARC64_FAMILY_MAGIC ||
            control->version != SPARC64_FAMILY_VERSION ||
            control->size != sizeof(*control) || control->source_mode != 1 ||
            root_id == 0 || root_id >= control->next_object_id ||
            object_name(root_id, name) != 0) {
            errno = EIO;
            result = -1;
        } else {
            int root_fd = openat(borrowed_directory_fd, name,
                                 O_RDWR | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
            if (root_fd < 0)
                result = -1;
            else {
                struct stat root_status;
                size_t root_size;
                if (fstat(root_fd, &root_status) != 0 ||
                    !object_file_size(1, &root_size) ||
                    !S_ISREG(root_status.st_mode) ||
                    (root_status.st_mode & 07777) != 0600 ||
                    root_status.st_uid != geteuid() ||
                    root_status.st_nlink != 1 || root_status.st_size != 0 ||
                    !family_authorize_fd(root_fd, false, authority)) {
                    errno = EACCES;
                    result = -1;
                } else {
                    result = sparc64_family_zero_segment_attach_fd(root_fd,
                        SPARC64_FAMILY_ZERO_SEGMENT_OBJECT, root_id, root_size,
                        &owner->root.segment);
                    if (result == 0) {
                        sparc64_family_object_file_t *root = owner->root.segment.payload;
                        if (root->magic != SPARC64_OBJECT_MAGIC ||
                            root->version != SPARC64_FAMILY_VERSION ||
                            root->header_size != SPARC64_OBJECT_HEADER_SIZE ||
                            root->object_id != root_id ||
                            root->slot_count != 1 || root->reserved != 0) {
                            errno = EIO;
                            result = -1;
                        } else {
                            owner->root.object_id = root_id;
                            owner->root.size = root_size;
                        }
                    }
                }
                int saved = errno;
                (void)close(root_fd);
                errno = saved;
            }
        }
    }
    if (result != 0) {
        int saved = errno;
        sparc64_family_cleanup_service_release(owner);
        errno = saved;
        return -1;
    }
    *out = owner;
    return 0;
#endif
}

int sparc64_family_cleanup_service_prepare(int borrowed_control_fd,
                                      int borrowed_directory_fd,
                                      const char *directory, void **out)
{
    return sparc64_family_cleanup_service_prepare_authority(borrowed_control_fd,
        borrowed_directory_fd, directory, out, SPARC64_FAMILY_AUTHORITY_AUTO);
}

int sparc64_family_cleanup_service_prepare_context(int borrowed_control_fd,
    int borrowed_directory_fd, const char *directory, void **out,
    void *context)
{
    if (context == NULL) {
        errno = EINVAL;
        return -1;
    }
    return sparc64_family_cleanup_service_prepare_authority(borrowed_control_fd,
        borrowed_directory_fd, directory, out,
        *(const sparc64_family_storage_authority_t *)context);
}

static int cleanup_service(int borrowed_control_fd,
                           int borrowed_directory_fd,
                           const char *directory, void *retained)
{
    if (borrowed_control_fd < 3 || borrowed_directory_fd < 3 ||
        borrowed_control_fd == borrowed_directory_fd || directory == NULL) {
        errno = EINVAL;
        return -1;
    }
    size_t length = strnlen(directory, 64);
    struct stat control_status, named_status, directory_status, path_status;
    if (length == 0 || length >= 64 || directory[0] != '/' ||
        fstat(borrowed_control_fd, &control_status) != 0 ||
        fstat(borrowed_directory_fd, &directory_status) != 0 ||
        fstatat(borrowed_directory_fd, "control", &named_status,
                AT_SYMLINK_NOFOLLOW) != 0 ||
        fstatat(AT_FDCWD, directory, &path_status,
                AT_SYMLINK_NOFOLLOW) != 0)
        return -1;
    uint64_t minimum_size = 0;
    sparc64_zero_service_retained_t *owner = retained;
    bool zero_backing = control_status.st_size == 0;
    if (!catalog_reserved_end(&minimum_size) ||
        !S_ISREG(control_status.st_mode) ||
        (control_status.st_mode & 07777) != 0600 ||
        control_status.st_uid != geteuid() || control_status.st_nlink != 1 ||
        control_status.st_size < 0 ||
        (!zero_backing && (uint64_t)control_status.st_size < minimum_size) ||
        (zero_backing && (owner == NULL ||
            !family_authorize_fd(borrowed_control_fd, false,
                                  owner->storage_authority) ||
            !family_authorize_fd(borrowed_directory_fd, true,
                                  owner->storage_authority))) ||
        (!zero_backing && owner != NULL) ||
        !S_ISDIR(directory_status.st_mode) ||
        (directory_status.st_mode & 07777) != 0700 ||
        directory_status.st_uid != geteuid() ||
        control_status.st_dev != named_status.st_dev ||
        control_status.st_ino != named_status.st_ino ||
        directory_status.st_dev != path_status.st_dev ||
        directory_status.st_ino != path_status.st_ino) {
        errno = EPERM;
        return -1;
    }
    int previous_cancel_state;
    int cancel_error = pthread_setcancelstate(PTHREAD_CANCEL_DISABLE,
                                                &previous_cancel_state);
    if (cancel_error != 0) {
        errno = cancel_error;
        return -1;
    }
    void *mapping = zero_backing ? owner->control.payload :
        mmap(NULL, sizeof(sparc64_family_control_t),
             PROT_READ | PROT_WRITE, MAP_SHARED,
             borrowed_control_fd, 0);
    if (mapping == MAP_FAILED) {
        int saved = errno;
        (void)pthread_setcancelstate(previous_cancel_state, NULL);
        errno = saved;
        return -1;
    }
    sparc64_family_control_t *control = mapping;
    int result = -1;
    int saved = EIO;
    struct flock lock = {.l_type = F_WRLCK, .l_whence = SEEK_SET,
                         .l_start = 0, .l_len = 1};
    if (fcntl(borrowed_control_fd, F_SETLK, &lock) != 0) {
        saved = errno;
        goto done;
    }
    atomic_thread_fence(memory_order_acquire);
    if (control->magic != SPARC64_FAMILY_MAGIC ||
        control->version != SPARC64_FAMILY_VERSION ||
        control->size != sizeof(*control) || control->source_mode != 1 ||
        control->source_reserved != 0 || control->file_index_object == 0 ||
        control->file_index_object >= control->next_object_id ||
        !atomic_is_lock_free(&control->log_marker) ||
        atomic_load_explicit(&control->log_marker,
                             memory_order_acquire) != SPARC64_LOG_EMPTY) {
        saved = EBUSY;
        goto unlock;
    }
    sparc64_family_t family = {0};
    family.control_fd = borrowed_control_fd;
    family.dir_fd = borrowed_directory_fd;
    family.pins = (sparc64_inode_pins_t)SPARC64_INODE_PINS_INITIALIZER;
    family.sources = (sparc64_file_caps_client_t)SPARC64_FILE_CAPS_CLIENT_INITIALIZER;
    family.control = control;
    family.zero_backing = zero_backing;
    if (zero_backing) {
        family.zero_control = owner->control;
        family.zero_objects = &owner->root;
        family.storage_authority = owner->storage_authority;
    }
    family.local_pid = getpid();
    family.initialized = true;
    family.creator = true;
    family.incarnation = control->active_incarnation != 0 ?
                         control->active_incarnation : 1;
    memcpy(family.directory, directory, length + 1u);
    sparc64_family_guard_t guard = {.family = &family,
                               .incarnation = family.incarnation,
                               .owner_thread = pthread_self(), .held = true};
    family.active_guard = &guard;
    sparc64_family_file_cursor_t cursor = {0};
    if (sparc64_family_file_index_cursor_read(&guard, &cursor) != 0) {
        saved = errno;
        goto unlock;
    }
    if (cursor.phase != SPARC64_FILE_IDLE) {
        saved = EBUSY;
        goto unlock;
    }
    result = cleanup_held(&guard, true);
    saved = errno;
unlock:
    lock.l_type = F_UNLCK;
    if (fcntl(borrowed_control_fd, F_SETLK, &lock) != 0) {
        result = -1;
        saved = EIO;
    }
done:
    if (!zero_backing && munmap(mapping, sizeof(sparc64_family_control_t)) != 0) {
        result = -1;
        saved = EIO;
    }
    (void)pthread_setcancelstate(previous_cancel_state, NULL);
    errno = saved;
    return result;
}

int sparc64_family_cleanup_service(int borrowed_control_fd,
                              int borrowed_directory_fd,
                              const char *directory)
{
    return cleanup_service(borrowed_control_fd, borrowed_directory_fd,
                           directory, NULL);
}

int sparc64_family_cleanup_service_retained(int borrowed_control_fd,
                                       int borrowed_directory_fd,
                                       const char *directory, void *retained)
{
    return cleanup_service(borrowed_control_fd, borrowed_directory_fd,
                           directory, retained);
}

int sparc64_family_destroy(sparc64_family_t *family)
{
    if (family == NULL)
        return 0;
    if (family->local_pid != getpid()) {
        errno = EPERM;
        return -1;
    }
    int result = pthread_mutex_trylock(&family->local_mutex);
    if (result != 0) {
        errno = result == EBUSY ? EBUSY : result;
        return -1;
    }
    if (family->active_guard != NULL ||
        family->exec_prepared != NULL ||
        atomic_load_explicit(&family->live_views, memory_order_relaxed) != 0 ||
        family->inode_observer != NULL) {
        (void)pthread_mutex_unlock(&family->local_mutex);
        errno = EBUSY;
        return -1;
    }
    family->destroying = true;
    (void)pthread_mutex_unlock(&family->local_mutex);
    if (family->zero_backing) {
        if (family->zero_fragment_pending_fd >= 0)
            (void)close(family->zero_fragment_pending_fd);
        for (size_t i = 0; i < family->zero_fragment_count; ++i)
            sparc64_family_zero_segment_detach(&family->zero_fragments[i]);
        sparc64_zero_object_segment_t *entry = family->zero_objects;
        while (entry != NULL) {
            sparc64_zero_object_segment_t *next = entry->next;
            sparc64_family_zero_segment_detach(&entry->segment);
            free(entry);
            entry = next;
        }
        sparc64_family_zero_segment_detach(&family->zero_control);
    } else if (family->control != NULL) {
        (void)munmap(family->control, sizeof(sparc64_family_control_t));
    }
    close_family_sources(family->control_fd, family->dir_fd, family->pins, family->sources);
    if (family->creator && family->directory[0] != '\0')
        if (family->cleaned)
            (void)rmdir(family->directory);
    if (family->initialized)
        (void)pthread_mutex_destroy(&family->local_mutex);
    free(family);
    return 0;
}

#ifdef SPARC64_FAMILY_TESTING
void sparc64_family_test_set_hook(sparc64_family_t *family, sparc64_family_test_hook_t hook,
                             void *context)
{
    if (family == NULL)
        return;
    family->hook = hook;
    family->hook_context = context;
}

void sparc64_family_test_point(sparc64_family_guard_t *guard, sparc64_family_test_point_t point)
{
    if (guard_valid(guard) && guard->family->hook != NULL)
        guard->family->hook(point, guard->family->hook_context);
}

void sparc64_family_test_fail_next_file_recovery(sparc64_family_t *family)
{
    if (family != NULL)
        family->test_fail_file_recovery_once = true;
}

void sparc64_family_test_set_refresh_counters(sparc64_family_t *family,
                                          uint64_t next_acquisition,
                                          uint64_t mutation)
{
    if (family == NULL)
        return;
    family->refresh_next_acquisition = next_acquisition;
    family->refresh_mutation = mutation;
}

void sparc64_family_test_fail_next_unlock(sparc64_family_t *family)
{
    if (family != NULL)
        family->test_fail_unlock_once = true;
}

void sparc64_family_test_fail_child_transfer_attach(sparc64_family_t *family)
{
    if (family != NULL)
        family->test_fail_child_transfer_attach = true;
}

void sparc64_family_test_fail_exec_activation(sparc64_family_t *family)
{
    if (family != NULL) {
        family->test_fail_exec_activation = true;
        family->test_fail_exec_activation_index = 0;
    }
}

void sparc64_family_test_fail_exec_activation_at(sparc64_family_t *family, size_t index)
{
    if (family != NULL && index < 6) {
        family->test_fail_exec_activation = true;
        family->test_fail_exec_activation_index = index;
    }
}

void sparc64_family_test_fail_next_wait_replay(sparc64_family_t *family)
{
    if (family != NULL)
        family->test_fail_wait_replay_once = true;
}

void sparc64_family_test_descriptors(const sparc64_family_t *family,
                                 int *control_fd, int *dir_fd)
{
    if (family != NULL && control_fd != NULL && dir_fd != NULL) {
        *control_fd = family->control_fd;
        *dir_fd = family->dir_fd;
    }
}

void sparc64_family_test_pin_state(const sparc64_family_t *family,
                               sparc64_inode_pins_t *pins, uint64_t *attempts)
{
    if (family == NULL)
        return;
    if (pins != NULL)
        *pins = family->pins;
    if (attempts != NULL)
        *attempts = family->control->inode_pin_attempts;
}
#endif

