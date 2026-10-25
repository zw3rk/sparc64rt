/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#include "exec_state_split.h"


static bool decode(const unsigned char *bytes, size_t length,
                   sparc64_exec_state_t *out)
{
    if (length < EXEC_RECORD_HEADER || memcmp(bytes, EXEC_RECORD_MAGIC, 8) != 0 ||
        get32(bytes + 8) != EXEC_RECORD_VERSION ||
        get32(bytes + 12) != EXEC_RECORD_HEADER ||
        get64(bytes + 16) != length) {
        errno = EINVAL;
        return false;
    }
    reader_t reader = {.bytes = bytes, .pos = EXEC_RECORD_HEADER,
                       .limit = length};
    sparc64_exec_state_t staged = {0};
    sparc64_family_exec_state_t *family = &staged.family;
    sparc64_exec_config_t *config = &staged.config;
    uint32_t argc, envc, children, fifos, creator;
    uint64_t control_device, control_inode, directory_device, directory_inode;
    uint64_t parent_pid;
    bool valid = read32(&reader, &argc) && read32(&reader, &envc) &&
        read32(&reader, &children) && read32(&reader, &fifos) &&
        read64(&reader, &config->max_steps) &&
        read64(&reader, &config->steps) &&
        read64(&reader, &config->jit_steps) &&
        read64(&reader, &config->fallback_steps) &&
        read64(&reader, &config->progress_period) &&
        read64(&reader, &config->stats_period) &&
        read64(&reader, &config->worker_attempts) &&
#ifdef SPARC64_RUNTIME_TEST_ATTRIBUTED_FILE
        read64(&reader, &config->fsize_soft) &&
        read64(&reader, &config->fsize_hard) &&
#endif
        read32(&reader, &config->quantum) &&
        read32(&reader, &config->flags) &&
        read32(&reader, &config->xlen) &&
        read64(&reader, &family->owner_pid) &&
        read64(&reader, &family->incarnation) &&
        read64(&reader, &family->recovery_epoch) &&
        read64(&reader, &family->next_incarnation) &&
        read64(&reader, &staged.old_mm_id) &&
        read64(&reader, &parent_pid) &&
#ifdef SPARC64_RUNTIME_TEST_ATTRIBUTED_FILE
        read64(&reader, &staged.old_mm_root_object) &&
        read64(&reader, &staged.old_mm_task_id) &&
#endif
        read64(&reader, &control_device) &&
        read64(&reader, &control_inode) &&
        read64(&reader, &directory_device) &&
        read64(&reader, &directory_inode) &&
        read32(&reader, &creator);
    if (!valid)
        goto fail;
    if (argc == 0 || argc > SPARC64_LINUX_EXEC_VECTOR_MAX ||
        envc > SPARC64_LINUX_EXEC_VECTOR_MAX ||
        children > EXEC_INVENTORY_MAX || fifos > EXEC_INVENTORY_MAX ||
        parent_pid > INT_MAX ||
        creator > 1 || (uint64_t)(dev_t)control_device != control_device ||
        (uint64_t)(ino_t)control_inode != control_inode ||
        (uint64_t)(dev_t)directory_device != directory_device ||
        (uint64_t)(ino_t)directory_inode != directory_inode) {
        errno = EINVAL;
        goto fail;
    }
    staged.parent_pid = (pid_t)parent_pid;
    family->identity = (sparc64_family_identity_t){
        .control_device = (dev_t)control_device,
        .control_inode = (ino_t)control_inode,
        .directory_device = (dev_t)directory_device,
        .directory_inode = (ino_t)directory_inode
    };
    family->creator = creator != 0;
    char *directory = NULL;
    if (!read_string(&reader, sizeof(family->directory), &directory))
        goto fail;
    size_t directory_length = strlen(directory) + 1;
    memcpy(family->directory, directory, directory_length);
    free(directory);
    if (!read64(&reader, &staged.signals.ignored) ||
        !read64(&reader, &staged.signals.blocked) ||
        !read64(&reader, &staged.signals.process_pending) ||
        !read64(&reader, &staged.signals.thread_pending) ||
        !read_bytes(&reader, staged.signals.process_information,
                    sizeof(staged.signals.process_information)) ||
        !read_bytes(&reader, staged.signals.thread_information,
                    sizeof(staged.signals.thread_information)) ||
        !read_string(&reader, SPARC64_LINUX_EXEC_PATH_MAX, &staged.args.path))
        goto fail;
    staged.args.argc = argc;
    staged.args.envc = envc;
    staged.args.argv = calloc((size_t)argc + 1, sizeof(char *));
    staged.args.envp = calloc((size_t)envc + 1, sizeof(char *));
    if (staged.args.argv == NULL || staged.args.envp == NULL)
        goto fail;
    for (size_t i = 0; i < argc; ++i)
        if (!read_string(&reader, SPARC64_LINUX_EXEC_BYTES_MAX,
                         &staged.args.argv[i]))
            goto fail;
    for (size_t i = 0; i < envc; ++i)
        if (!read_string(&reader, SPARC64_LINUX_EXEC_BYTES_MAX,
                         &staged.args.envp[i]))
            goto fail;
    uint32_t sysroot_length;
    if (!read32(&reader, &sysroot_length))
        goto fail;
    if (sysroot_length != 0) {
        reader.pos -= 4;
        if (!read_string(&reader, EXEC_SYSROOT_MAX, &staged.sysroot))
            goto fail;
    }
    staged.child_count = children;
    staged.fifo_count = fifos;
    if (children != 0) {
        staged.children = calloc(children, sizeof(*staged.children));
        if (staged.children == NULL)
            goto fail;
    }
    for (size_t i = 0; i < children; ++i) {
        uint64_t pid, cap_fd;
        uint32_t role, reserved;
        if (!read64(&reader, &pid) || !read64(&reader, &cap_fd) ||
            !read32(&reader, &role) || !read32(&reader, &reserved))
            goto fail;
        if (pid == 0 || pid > INT_MAX || cap_fd < 3 || cap_fd > INT_MAX ||
            (role != SPARC64_PROCESS_CHILD_FAMILY &&
             role != SPARC64_PROCESS_CHILD_EXTERNAL) || reserved != 0) {
            errno = EINVAL;
            goto fail;
        }
        staged.children[i] = (sparc64_process_child_cap_t){
            .pid = (pid_t)pid, .cap_fd = (int)cap_fd,
            .role = (sparc64_process_child_role_t)role};
    }
    if (fifos != 0) {
        staged.fifos = calloc(fifos, sizeof(*staged.fifos));
        if (staged.fifos == NULL)
            goto fail;
    }
    for (size_t i = 0; i < fifos; ++i) {
        sparc64_linux_fifo_identity_t *fifo = &staged.fifos[i];
        uint64_t seconds;
        uint32_t reserved;
        if (!read32(&reader, &fifo->device_major) ||
            !read32(&reader, &fifo->device_minor) ||
            !read64(&reader, &fifo->inode) ||
            !read64(&reader, &seconds) ||
            !read32(&reader, &fifo->birth_nanoseconds) ||
            !read32(&reader, &reserved))
            goto fail;
        if (reserved != 0) {
            errno = EINVAL;
            goto fail;
        }
        fifo->birth_seconds = decode_i64(seconds);
    }
    uint32_t clear_count;
    if (!read32(&reader, &clear_count))
        goto fail;
    if (clear_count > EXEC_INVENTORY_MAX ||
#ifdef SPARC64_RUNTIME_TEST_ATTRIBUTED_FILE
        clear_count > (reader.limit - reader.pos) / 68u) {
#else
        clear_count > (reader.limit - reader.pos) / 52u) {
#endif
        errno = EINVAL;
        goto fail;
    }
    staged.clear_tid_count = clear_count;
    if (clear_count != 0) {
        staged.clear_tids = calloc(clear_count, sizeof(*staged.clear_tids));
        if (staged.clear_tids == NULL)
            goto fail;
    }
    for (size_t i = 0; i < clear_count; ++i) {
        sparc64_exec_tid_clear_t *clear = &staged.clear_tids[i];
        if (!read32(&reader, &clear->segment_count))
            goto fail;
        for (size_t segment = 0; segment < 2; ++segment)
            if (!read64(&reader, &clear->keys[segment].object_id) ||
                !read64(&reader, &clear->keys[segment].page_index) ||
                !read32(&reader, &clear->offsets[segment]) ||
                !read32(&reader, &clear->lengths[segment]))
                goto fail;
#ifdef SPARC64_RUNTIME_TEST_ATTRIBUTED_FILE
        uint64_t role = 0;
        if (!read64(&reader, &clear->mm_shared_wake_address) ||
            !read64(&reader, &role) || role > SPARC64_EXEC_TID_CALLER_IF_LIVE_PEER)
            goto fail;
        clear->role = (sparc64_exec_tid_role_t)role;
#endif
    }
    uint32_t cache_directory_length;
    if (!read32(&reader, &config->cache_authority) ||
        !read32(&reader, &config->cache_blocks) ||
        !read32(&reader, &cache_directory_length))
        goto fail;
    if (cache_directory_length != 0) {
        reader.pos -= 4;
        if (!read_string(&reader, EXEC_CACHE_DIRECTORY_MAX,
                         &staged.cache_directory))
            goto fail;
    }
    if (reader.pos != reader.limit || !state_valid(&staged)) {
        if (reader.pos != reader.limit)
            errno = EINVAL;
        goto fail;
    }
    *out = staged;
    return true;
fail: {
        int saved = errno;
        sparc64_exec_state_destroy(&staged);
        errno = saved;
        return false;
    }
}

static bool private_metadata(int fd, struct stat *status)
{
    return fd >= 3 && fstat(fd, status) == 0 && S_ISREG(status->st_mode) &&
           status->st_uid == geteuid() && status->st_nlink == 0 &&
           (status->st_mode & 07777) == 0600;
}

static bool same_record_stat(const struct stat *before, const struct stat *after)
{
#ifdef __APPLE__
    struct timespec before_mtime = {before->st_mtime, before->st_mtimensec};
    struct timespec after_mtime = {after->st_mtime, after->st_mtimensec};
    struct timespec before_ctime = {before->st_ctime, before->st_ctimensec};
    struct timespec after_ctime = {after->st_ctime, after->st_ctimensec};
#else
    struct timespec before_mtime = before->st_mtim, after_mtime = after->st_mtim;
    struct timespec before_ctime = before->st_ctim, after_ctime = after->st_ctim;
#endif
    return before->st_dev == after->st_dev && before->st_ino == after->st_ino &&
           before->st_size == after->st_size &&
           before_mtime.tv_sec == after_mtime.tv_sec &&
           before_mtime.tv_nsec == after_mtime.tv_nsec &&
           before_ctime.tv_sec == after_ctime.tv_sec &&
           before_ctime.tv_nsec == after_ctime.tv_nsec;
}

static int write_all(int fd, const unsigned char *bytes, size_t length)
{
    size_t done = 0;
    while (done < length) {
        ssize_t count = pwrite(fd, bytes + done, length - done, (off_t)done);
        if (count < 0 && errno == EINTR)
            continue;
        if (count <= 0) {
            if (count == 0)
                errno = EIO;
            return -1;
        }
        done += (size_t)count;
    }
    return 0;
}

static int read_all(int fd, unsigned char *bytes, size_t length)
{
    size_t done = 0;
    while (done < length) {
        ssize_t count = pread(fd, bytes + done, length - done, (off_t)done);
        if (count < 0 && errno == EINTR)
            continue;
        if (count <= 0) {
            if (count == 0)
                errno = EINVAL;
            return -1;
        }
        done += (size_t)count;
    }
    return 0;
}

void sparc64_exec_state_export_destroy(sparc64_exec_state_export_t **handle)
{
    if (handle == NULL || *handle == NULL)
        return;
    int saved = errno;
    sparc64_exec_state_export_t *owner = *handle;
    sparc64_path_retire_temporary(&owner->registration);
    if (owner->metadata >= 3)
        (void)close(owner->metadata);
    free(owner->child_caps);
    free(owner->child_flags);
    free(owner);
    *handle = NULL;
    errno = saved;
}

int sparc64_exec_state_export_create(const sparc64_exec_state_t *state,
                                sparc64_path_resolver_t *resolver,
                                sparc64_exec_state_export_t **out)
{
    if (out == NULL) {
        errno = EINVAL;
        return -1;
    }
    *out = NULL;
    if (resolver == NULL || !resolver->initialized) {
        errno = EINVAL;
        return -1;
    }
    unsigned char *data = NULL;
    size_t length = 0;
    if (!encode(state, &data, &length))
        return -1;
    sparc64_exec_state_export_t *owner = calloc(1, sizeof(*owner));
    if (owner == NULL) {
        free(data);
        return -1;
    }
    owner->metadata = -1;
    owner->child_count = state->child_count;
    if (owner->child_count != 0) {
        owner->child_caps = calloc(owner->child_count,
                                   sizeof(*owner->child_caps));
        owner->child_flags = calloc(owner->child_count,
                                    sizeof(*owner->child_flags));
        if (owner->child_caps == NULL || owner->child_flags == NULL)
            goto fail;
        for (size_t i = 0; i < owner->child_count; ++i) {
            int cap = state->children[i].cap_fd;
            int flags = fcntl(cap, F_GETFD);
            if (flags < 0 || (flags & FD_CLOEXEC) == 0) {
                if (flags >= 0)
                    errno = EINVAL;
                goto fail;
            }
            owner->child_caps[i] = cap;
            owner->child_flags[i] = flags;
        }
    }
    char path[] = "/tmp/sparc64rt-exec-state-XXXXXX";
    int fd = mkstemp(path);
    if (fd < 0)
        goto fail;
    if (unlink(path) != 0) {
        int saved = errno;
        (void)close(fd);
        errno = saved;
        goto fail;
    }
    owner->metadata = fcntl(fd, F_DUPFD_CLOEXEC, 3);
    int saved = errno;
    (void)close(fd);
    errno = saved;
    if (owner->metadata < 0 || fchmod(owner->metadata, 0600) != 0)
        goto fail;
    struct stat before, after;
    if (!private_metadata(owner->metadata, &before)) {
        errno = EINVAL;
        goto fail;
    }
    if (sparc64_path_protect_temporary(resolver, before.st_dev, before.st_ino,
                                  &owner->registration) != 0)
        goto fail;
    if (write_all(owner->metadata, data, length) != 0)
        goto fail;
    if (!private_metadata(owner->metadata, &after) ||
        after.st_dev != before.st_dev || after.st_ino != before.st_ino ||
        after.st_size < 0 || (uint64_t)after.st_size != length) {
        errno = EINVAL;
        goto fail;
    }
    free(data);
    *out = owner;
    return 0;
fail: {
        int failure = errno;
        free(data);
        sparc64_exec_state_export_destroy(&owner);
        errno = failure;
        return -1;
    }
}

int sparc64_exec_state_export_fd(const sparc64_exec_state_export_t *owner)
{
    if (owner == NULL) {
        errno = EINVAL;
        return -1;
    }
    return owner->metadata;
}

int sparc64_exec_state_export_activate(sparc64_exec_state_export_t *owner)
{
    if (owner == NULL || owner->poisoned || owner->active) {
        errno = owner != NULL && owner->active ? EALREADY : EINVAL;
        return -1;
    }
    int flags = fcntl(owner->metadata, F_GETFD);
    if (flags < 0 || fcntl(owner->metadata, F_SETFD,
                           flags & ~FD_CLOEXEC) < 0)
        return -1;
    owner->old_flags = flags;
    size_t activated = 0;
    for (; activated < owner->child_count; ++activated) {
        if (fcntl(owner->child_caps[activated], F_SETFD,
                  owner->child_flags[activated] & ~FD_CLOEXEC) < 0)
            break;
    }
    if (activated != owner->child_count) {
        int saved = errno;
        bool rollback_failed = false;
        while (activated != 0) {
            --activated;
            if (fcntl(owner->child_caps[activated], F_SETFD,
                      owner->child_flags[activated]) < 0)
                rollback_failed = true;
        }
        if (fcntl(owner->metadata, F_SETFD, flags) < 0)
            rollback_failed = true;
        owner->poisoned = rollback_failed;
        errno = rollback_failed ? EIO : saved;
        return -1;
    }
    owner->active = true;
    return 0;
}

int sparc64_exec_state_export_deactivate(sparc64_exec_state_export_t *owner)
{
    if (owner == NULL || owner->poisoned) {
        errno = EIO;
        return -1;
    }
    if (owner->active) {
        bool failed = false;
        for (size_t i = 0; i < owner->child_count; ++i)
            if (fcntl(owner->child_caps[i], F_SETFD,
                      owner->child_flags[i]) < 0)
                failed = true;
        if (fcntl(owner->metadata, F_SETFD, owner->old_flags) < 0)
            failed = true;
        if (failed) {
            owner->poisoned = true;
            errno = EIO;
            return -1;
        }
    }
    owner->active = false;
    return 0;
}

int sparc64_exec_state_import(int owned_fd, sparc64_exec_state_t *out)
{
    if (out == NULL) {
        if (owned_fd >= 3)
            (void)close(owned_fd);
        errno = EINVAL;
        return -1;
    }
    memset(out, 0, sizeof(*out));
    if (owned_fd < 3) {
        errno = EINVAL;
        return -1;
    }
    unsigned char *data = NULL;
    sparc64_exec_state_t staged = {0};
    int result = -1;
    int flags = fcntl(owned_fd, F_GETFD);
    if (flags < 0 || fcntl(owned_fd, F_SETFD, flags | FD_CLOEXEC) < 0)
        goto done;
    struct stat before, after;
    if (!private_metadata(owned_fd, &before) ||
        before.st_size < (off_t)EXEC_RECORD_HEADER ||
        (uint64_t)before.st_size > EXEC_RECORD_MAX) {
        errno = EINVAL;
        goto done;
    }
    size_t length = (size_t)before.st_size;
    data = malloc(length);
    if (data == NULL)
        goto done;
    if (read_all(owned_fd, data, length) != 0)
        goto done;
    if (!private_metadata(owned_fd, &after) ||
        !same_record_stat(&before, &after)) {
        errno = EINVAL;
        goto done;
    }
    if (!decode(data, length, &staged))
        goto done;
    result = 0;
done: {
        int saved = errno;
        free(data);
        if (close(owned_fd) != 0 && result == 0) {
            saved = errno;
            result = -1;
        }
        if (result == 0)
            *out = staged;
        else
            sparc64_exec_state_destroy(&staged);
        errno = saved;
        return result;
    }
}

