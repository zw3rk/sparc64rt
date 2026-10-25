/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#include "family_split.h"


int sparc64_family_exec_activate(sparc64_family_exec_t *exec)
{
    if (!exec_guard_valid(exec) || exec->active || exec->family->exec_active) {
        errno = EINVAL;
        return -1;
    }
    sparc64_family_t *family = exec->family;
    int descriptors[6];
    (void)family_all_fds(family, descriptors);
    bool flags_match = true;
    for (size_t i = 0; i < exec->capability_count; ++i)
        flags_match = flags_match && fcntl(descriptors[i], F_GETFD) == exec->flags[i];
    if (family->control->active != 1 || family->control->retired != 0 ||
        family->control->active_incarnation != exec->state.incarnation ||
        family->control->recovery_epoch != exec->state.recovery_epoch ||
        family->control->next_incarnation != exec->state.next_incarnation ||
        atomic_load_explicit(&family->control->log_marker, memory_order_acquire) != SPARC64_LOG_EMPTY ||
        !flags_match ||
        !exec_identity_matches(family->control_fd, family->dir_fd,
                               &exec->state.identity)) {
        errno = EIO;
        return -1;
    }
    int result = 0;
    for (size_t i = 0; i < exec->capability_count && result == 0; ++i) {
        result = fcntl(descriptors[i], F_SETFD, exec->flags[i] & ~FD_CLOEXEC);
#ifdef SPARC64_FAMILY_TESTING
        if (result == 0 && family->test_fail_exec_activation &&
            i == family->test_fail_exec_activation_index) {
            family->test_fail_exec_activation = false;
            errno = EIO;
            result = -1;
        }
#endif
    }
    if (result != 0) {
        int saved = errno;
        if (exec_restore_flags(exec) != 0)
            return -1;
        errno = saved;
        return -1;
    }
    exec->active = true;
    family->exec_active = true;
    refresh_invalidate(family);
    return 0;
}

int sparc64_family_exec_deactivate(sparc64_family_exec_t *exec)
{
    if (!exec_guard_valid(exec) || !exec->active || !exec->family->exec_active) {
        errno = EINVAL;
        return -1;
    }
    if (!exec_identity_matches(exec->family->control_fd, exec->family->dir_fd,
                                &exec->state.identity)) {
        exec->family->poisoned = true;
        errno = EIO;
        return -1;
    }
    if (exec_restore_flags(exec) != 0)
        return -1;
    exec->active = false;
    exec->family->exec_active = false;
    refresh_acquire(exec->family, exec->guard);
    return 0;
}

int sparc64_family_exec_destroy(sparc64_family_exec_t **owned)
{
    if (owned == NULL || *owned == NULL || !exec_guard_valid(*owned)) {
        errno = EINVAL;
        return -1;
    }
    sparc64_family_exec_t *exec = *owned;
    if (exec->active) {
        errno = EBUSY;
        return -1;
    }
    exec->family->exec_prepared = NULL;
    free(exec);
    *owned = NULL;
    return 0;
}

static int exec_receive(sparc64_family_t **out, sparc64_family_guard_t *guard,
                         int owned_control_fd, int owned_dir_fd,
                         sparc64_inode_pins_t owned_pins, sparc64_file_caps_client_t sources,
                         const sparc64_family_exec_state_t *state, bool terminal_sources)
{
    if (out == NULL || *out != NULL || guard == NULL || guard->held || state == NULL ||
        state->owner_pid != (uint64_t)getpid() || state->incarnation == 0 ||
        state->incarnation >= state->next_incarnation ||
        !distinct_source_fds(owned_control_fd, owned_dir_fd, owned_pins, sources) ||
        !exec_identity_matches(owned_control_fd, owned_dir_fd, &state->identity)) {
        close_family_sources(owned_control_fd, owned_dir_fd, owned_pins, sources);
        errno = EINVAL;
        return -1;
    }
    size_t length = strnlen(state->directory, sizeof(state->directory));
    struct stat path_status;
    if (length == sizeof(state->directory) ||
        (!state->creator && length != 0) ||
        (state->creator && (state->directory[0] != '/' ||
         fstatat(AT_FDCWD, state->directory, &path_status, AT_SYMLINK_NOFOLLOW) != 0 ||
         !S_ISDIR(path_status.st_mode) ||
         path_status.st_dev != state->identity.directory_device ||
         path_status.st_ino != state->identity.directory_inode))) {
        close_family_sources(owned_control_fd, owned_dir_fd, owned_pins, sources);
        errno = EINVAL;
        return -1;
    }
    sparc64_family_t *family = NULL;
    if (initialize_family(&family, owned_control_fd, owned_dir_fd, owned_pins,
                           sources, state->creator,
                           state->creator ? state->directory : NULL,
                           terminal_sources, SPARC64_FAMILY_AUTHORITY_AUTO) != 0)
        return -1;
    int previous_cancel_state;
    int result = pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &previous_cancel_state);
    if (result != 0) {
        (void)sparc64_family_destroy(family);
        errno = result;
        return -1;
    }
    result = pthread_mutex_lock(&family->local_mutex);
    if (result != 0) {
        (void)sparc64_family_destroy(family);
        (void)pthread_setcancelstate(previous_cancel_state, NULL);
        errno = result;
        return -1;
    }
    /* A conflicting owner means continuity was lost. Never block here and
     * silently reacquire ownership after another process has run. */
    struct flock lock = {.l_type = F_WRLCK, .l_whence = SEEK_SET, .l_start = 0, .l_len = 1};
    result = fcntl(family->control_fd, F_SETLK, &lock);
    int saved = errno;
    sparc64_family_control_t *control = family->control;
    atomic_thread_fence(memory_order_acquire);
    if (result == 0 && (control->active != 1 || control->retired != 0 ||
        control->active_incarnation != state->incarnation ||
        control->recovery_epoch != state->recovery_epoch ||
        control->next_incarnation != state->next_incarnation ||
        atomic_load_explicit(&control->log_marker, memory_order_acquire) != SPARC64_LOG_EMPTY)) {
        result = -1;
        saved = EIO;
    }
    /* The exact inherited descriptor retains this same-PID lease through
     * exec. Reassert its range without releasing any existing record lock. */
    if (result == 0 && acquire_owner_lease(family, state->incarnation) != 0) {
        result = -1;
        saved = errno;
    }
    if (result != 0) {
        (void)pthread_mutex_unlock(&family->local_mutex);
        (void)sparc64_family_destroy(family);
        (void)pthread_setcancelstate(previous_cancel_state, NULL);
        errno = saved;
        return -1;
    }
    family->incarnation = state->incarnation;
    family->active_guard = guard;
    *guard = (sparc64_family_guard_t){.family = family, .incarnation = state->incarnation,
                                .owner_thread = pthread_self(),
                                .previous_cancel_state = previous_cancel_state, .held = true};
    if (control->source_mode != 0 && !terminal_sources &&
        recover_file_state(guard) != 0) {
        saved = errno;
        family->active_guard = NULL;
        memset(guard, 0, sizeof(*guard));
        if (unlock_family_file(family) != 0)
            saved = EIO;
        (void)pthread_mutex_unlock(&family->local_mutex);
        (void)sparc64_family_destroy(family);
        (void)pthread_setcancelstate(previous_cancel_state, NULL);
        errno = saved;
        return -1;
    }
    refresh_acquire(family, guard);
    *out = family;
    return 0;
}

int sparc64_family_exec_receive(sparc64_family_t **out, sparc64_family_guard_t *guard,
                            int owned_control_fd, int owned_dir_fd,
                            sparc64_inode_pins_t owned_pins,
                            const sparc64_family_exec_state_t *state)
{
    return exec_receive(out, guard, owned_control_fd, owned_dir_fd, owned_pins,
                          (sparc64_file_caps_client_t)SPARC64_FILE_CAPS_CLIENT_INITIALIZER,
                          state, false);
}

int sparc64_family_exec_receive_sources(sparc64_family_t **out, sparc64_family_guard_t *guard,
                                    int owned_control_fd, int owned_dir_fd,
                                    sparc64_inode_pins_t owned_pins,
                                    sparc64_file_caps_client_t owned_sources,
                                    const sparc64_family_exec_state_t *state)
{
    if (!source_caps_present(owned_sources)) {
        close_family_sources(owned_control_fd, owned_dir_fd, owned_pins, owned_sources);
        errno = EINVAL;
        return -1;
    }
    return exec_receive(out, guard, owned_control_fd, owned_dir_fd, owned_pins,
                          owned_sources, state, false);
}

int sparc64_family_exec_receive_sources_terminal(sparc64_family_t **out,
                                    sparc64_family_guard_t *guard,
                                    int owned_control_fd, int owned_dir_fd,
                                    sparc64_inode_pins_t owned_pins,
                                    sparc64_file_caps_client_t owned_sources,
                                    const sparc64_family_exec_state_t *state)
{
    if (!source_caps_present(owned_sources)) {
        close_family_sources(owned_control_fd, owned_dir_fd, owned_pins, owned_sources);
        errno = EINVAL;
        return -1;
    }
    return exec_receive(out, guard, owned_control_fd, owned_dir_fd, owned_pins,
                        owned_sources, state, true);
}

int sparc64_family_fork_child_transfer(sparc64_family_t **inherited,
                                   sparc64_family_t **attached)
{
    if (inherited == NULL || attached == NULL || inherited == attached) {
        errno = EINVAL;
        return -1;
    }
    *attached = NULL;
    sparc64_family_t *copied = *inherited;
    if (copied != NULL && copied->local_pid == getpid()) {
        errno = EPERM;
        return -1;
    }
    if (copied == NULL || !copied->initialized ||
        copied->destroying || copied->cleaned || copied->poisoned ||
        copied->control == NULL || copied->control_fd < 3 ||
        copied->dir_fd < 3 || copied->control_fd == copied->dir_fd) {
        errno = EINVAL;
        return -1;
    }
    if (copied->zero_backing) {
        errno = EOPNOTSUPP;
        return -1;
    }
    if (atomic_load_explicit(&copied->live_views, memory_order_relaxed) != 0) {
        errno = EBUSY;
        return -1;
    }
    /* The mapped control is shared, but this unmap only drops this child's
     * inherited VA. Never clear control.active: the parent still owns its
     * POSIX record lock and will leave using its own guard and mutex. */
    if (munmap(copied->control, sizeof(sparc64_family_control_t)) != 0)
        return -1;
    int control_fd = copied->control_fd;
    int dir_fd = copied->dir_fd;
    sparc64_inode_pins_t pins = copied->pins;
    sparc64_file_caps_client_t sources = copied->sources;
#ifdef SPARC64_FAMILY_TESTING
    bool inject_failure = copied->test_fail_child_transfer_attach;
#endif
    copied->control = NULL;
    copied->control_fd = -1;
    copied->dir_fd = -1;
    copied->pins = (sparc64_inode_pins_t)SPARC64_INODE_PINS_INITIALIZER;
    copied->sources = (sparc64_file_caps_client_t)SPARC64_FILE_CAPS_CLIENT_INITIALIZER;
    copied->active_guard = NULL;
    copied->inode_observer = NULL;
    copied->inode_observer_context = NULL;
    /* The copied local mutex may be locked by a vanished native worker.
     * Neither lock, unlock nor destroy it in the child. */
    free(copied);
    *inherited = NULL;
#ifdef SPARC64_FAMILY_TESTING
    if (inject_failure) {
        (void)close(control_fd);
        control_fd = -1;
    }
#endif
    return initialize_family(attached, control_fd, dir_fd, pins, sources,
                             false, NULL, false, SPARC64_FAMILY_AUTHORITY_AUTO);
}

int sparc64_family_create_with_authority(sparc64_family_t **out,
                                     sparc64_family_storage_authority_t authority)
{
    if (out == NULL || !authority_valid(authority)) {
        errno = EINVAL;
        return -1;
    }
    *out = NULL;
    struct rlimit native_fsize;
    if (getrlimit(RLIMIT_FSIZE, &native_fsize) != 0)
        return -1;
    bool zero_backing = native_fsize.rlim_max == 0;
    if (!zero_backing && authority != SPARC64_FAMILY_AUTHORITY_AUTO) {
        errno = EOPNOTSUPP; /* No policy transport through native exec yet. */
        return -1;
    }
#ifndef __linux__
    if (zero_backing) {
        errno = EOPNOTSUPP;
        return -1;
    }
#endif
    /* Family directories are hidden dot-directories keyed by creator pid
     * and a per-process sequence number:
     * .sparc64rt-family-<pid>-<seq>-XXXXXX. */
    static unsigned long family_seq = 0;
    char path[64];
    int path_len = snprintf(path, sizeof(path),
                            "/tmp/.sparc64rt-family-%ld-%lu-XXXXXX",
                            (long)getpid(), family_seq++);
    if (path_len < 0 || (size_t)path_len >= sizeof(path)) {
        errno = ENAMETOOLONG;
        return -1;
    }
    if (mkdtemp(path) == NULL)
        return -1;
    if (chmod(path, 0700) != 0) {
        int saved = errno;
        (void)rmdir(path);
        errno = saved;
        return -1;
    }
    int dir_fd = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (dir_fd < 0) {
        int saved = errno;
        (void)rmdir(path);
        errno = saved;
        return -1;
    }
    if (normalize_owned_fd(&dir_fd) != 0) {
        int saved = errno;
        (void)close(dir_fd);
        (void)rmdir(path);
        errno = saved;
        return -1;
    }
    int control_fd = openat(dir_fd, "control", O_RDWR | O_CREAT | O_EXCL |
                            O_CLOEXEC | O_NOFOLLOW, 0600);
    if (control_fd < 0) {
        int saved = errno;
        (void)close(dir_fd);
        (void)rmdir(path);
        errno = saved;
        return -1;
    }
    if (normalize_owned_fd(&control_fd) != 0) {
        int saved = errno;
        (void)close(control_fd);
        (void)unlinkat(dir_fd, "control", 0);
        (void)close(dir_fd);
        (void)rmdir(path);
        errno = saved;
        return -1;
    }
    uint64_t control_extent = 0;
    if (!catalog_reserved_end(&control_extent) || fchmod(control_fd, 0600) != 0 ||
        (zero_backing ? (control_extent > SPARC64_ZERO_CONTROL_HEAD_SIZE ||
                         !family_authorize_fd(dir_fd, true, authority) ||
                         !family_authorize_fd(control_fd, false, authority)) :
                        ftruncate(control_fd, (off_t)control_extent) != 0)) {
        int saved = errno;
        (void)close(control_fd);
        (void)unlinkat(dir_fd, "control", 0);
        (void)close(dir_fd);
        (void)rmdir(path);
        errno = saved;
        return -1;
    }
    sparc64_family_zero_segment_t zero_control = {0};
    void *mapping;
    if (zero_backing) {
        int result = sparc64_family_zero_segment_create(
            SPARC64_FAMILY_ZERO_SEGMENT_CONTROL, 0,
            SPARC64_ZERO_CONTROL_HEAD_SIZE,
            &zero_control);
        if (result == 0)
            result = sparc64_family_zero_segment_publish_fd(control_fd,
                                                        &zero_control);
        mapping = result == 0 ? zero_control.payload : MAP_FAILED;
    } else {
        mapping = mmap(NULL, sizeof(sparc64_family_control_t),
                       PROT_READ | PROT_WRITE, MAP_SHARED, control_fd, 0);
    }
    if (mapping == MAP_FAILED) {
        int saved = errno;
        sparc64_family_zero_segment_detach(&zero_control);
        (void)close(control_fd);
        (void)unlinkat(dir_fd, "control", 0);
        (void)close(dir_fd);
        (void)rmdir(path);
        errno = saved;
        return -1;
    }
    memset(mapping, 0, sizeof(sparc64_family_control_t));
    sparc64_family_control_t *control = mapping;
    control->magic = SPARC64_FAMILY_MAGIC;
    control->version = SPARC64_FAMILY_VERSION;
    control->size = (uint32_t)sizeof(sparc64_family_control_t);
    control->next_incarnation = 1;
    control->next_object_id = 1;
    control->next_wait_id = 1;
    control->next_mm_id = 1;
    control->next_file_id = 1;
    control->next_source_id = 1;
    atomic_init(&control->log_marker, SPARC64_LOG_EMPTY);
    int sync_result = zero_backing ? 0 :
        msync(mapping, sizeof(sparc64_family_control_t), MS_SYNC);
    int sync_errno = errno;
    if (!zero_backing)
        (void)munmap(mapping, sizeof(sparc64_family_control_t));
    if (sync_result != 0) {
        sparc64_family_zero_segment_detach(&zero_control);
        (void)close(control_fd);
        (void)unlinkat(dir_fd, "control", 0);
        (void)close(dir_fd);
        (void)rmdir(path);
        errno = sync_errno;
        return -1;
    }
    sparc64_inode_pins_t pins = SPARC64_INODE_PINS_INITIALIZER;
    int created = sparc64_inode_pins_create(&pins);
    int initialized;
    if (created == 0)
        initialized = initialize_family(out, control_fd, dir_fd, pins,
                                           (sparc64_file_caps_client_t)SPARC64_FILE_CAPS_CLIENT_INITIALIZER,
                                           true, path, false, authority);
    else {
        int saved = errno;
        close_owned_fds(control_fd, dir_fd);
        errno = saved;
        initialized = -1;
    }
    if (initialized != 0) {
        int saved = errno;
        sparc64_family_zero_segment_detach(&zero_control);
        int cleanup_fd = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        if (cleanup_fd >= 0) {
            (void)unlinkat(cleanup_fd, "control", 0);
            (void)close(cleanup_fd);
        }
        (void)rmdir(path);
        errno = saved;
        return -1;
    }
    sparc64_family_zero_segment_detach(&zero_control);
    return 0;
}

int sparc64_family_create(sparc64_family_t **out)
{
    return sparc64_family_create_with_authority(out, SPARC64_FAMILY_AUTHORITY_AUTO);
}

/* Only for a new, never-published family: the service predates its creation,
 * and there are no workers, views or borrowed native capabilities. Discarding
 * unreachable staging does not need replay. Cancellation is restored only
 * when this guard is still held, and only after the local FDs are destroyed.
 * A guard that leave already released is not changed here. */
static void discard_unpublished_family(sparc64_family_t *family, sparc64_family_guard_t *guard)
{
    bool held = guard->held;
    int previous = guard->previous_cancel_state;
    if (held) {
        family->active_guard = NULL;
        guard->held = false;
        guard->family = NULL;
        (void)pthread_mutex_unlock(&family->local_mutex);
    }
    int scan_fd = fcntl(family->dir_fd, F_DUPFD_CLOEXEC, 3);
    DIR *stream = scan_fd < 0 ? NULL : fdopendir(scan_fd);
    if (stream == NULL && scan_fd >= 0)
        (void)close(scan_fd);
    if (stream != NULL) {
        struct dirent *entry;
        while ((entry = readdir(stream)) != NULL) {
            if (!sparc64_family_owned_entry_name(entry->d_name))
                continue;
            struct stat status;
            if (fstatat(family->dir_fd, entry->d_name, &status, AT_SYMLINK_NOFOLLOW) == 0 &&
                S_ISREG(status.st_mode) && status.st_uid == geteuid() &&
                (status.st_mode & 07777) == 0600 && status.st_nlink == 1)
                (void)unlinkat(family->dir_fd, entry->d_name, 0);
        }
        (void)closedir(stream);
    }
    /* Directory failure can leave private orphan files; native failure cannot
     * justify publishing an incomplete family or retaining a local FD owner. */
    (void)rmdir(family->directory);
    (void)sparc64_family_destroy(family);
    if (held)
        (void)pthread_setcancelstate(previous, NULL);
}

int sparc64_family_create_with_sources_authority(sparc64_family_t **out,
    sparc64_file_caps_client_t *owned, sparc64_family_storage_authority_t authority)
{
    sparc64_file_caps_client_t sources = SPARC64_FILE_CAPS_CLIENT_INITIALIZER;
    if (owned == NULL) {
        errno = EINVAL;
        return -1;
    }
    sparc64_file_caps_client_t supplied = *owned;
    *owned = (sparc64_file_caps_client_t)SPARC64_FILE_CAPS_CLIENT_INITIALIZER;
    if (out == NULL || *out != NULL || !authority_valid(authority)) {
        sparc64_file_caps_client_close(&supplied);
        errno = EINVAL;
        return -1;
    }
    if (sparc64_file_caps_client_adopt(&sources, supplied.request_fd,
                                   supplied.lifetime_fd) != 0)
        return -1;
    sparc64_family_t *family = NULL;
    if (sparc64_family_create_with_authority(&family, authority) != 0) {
        int saved = errno;
        sparc64_file_caps_client_close(&sources);
        errno = saved;
        return -1;
    }
    sparc64_family_guard_t guard = {0};
    uint64_t root = 0;
    int result = sparc64_family_enter(family, &guard);
    if (result == 0)
        result = sparc64_family_file_index_create_empty(&guard, &root);
    int saved = errno;
    if (result == 0) {
        result = sparc64_family_leave(&guard);
        saved = errno;
    }
    if (result != 0) {
        sparc64_file_caps_client_close(&sources);
        discard_unpublished_family(family, &guard);
        errno = saved;
        return -1;
    }
    /* No attachment/worker sees this private mode0 family before its complete
     * index, original client and immutable mode/root agree. */
    family->sources = sources;
    family->control->file_index_object = root;
    family->control->source_mode = 1;
    atomic_thread_fence(memory_order_release);
    *out = family;
    return 0;
}

int sparc64_family_create_with_sources(sparc64_family_t **out, sparc64_file_caps_client_t *owned)
{
    return sparc64_family_create_with_sources_authority(out, owned,
                                                   SPARC64_FAMILY_AUTHORITY_AUTO);
}
