/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#include "file_split.h"


static bool fifo_identity(int directory_fd, const char *path,
                          sparc64_linux_fifo_identity_t *identity)
{
#if defined(__linux__)
    struct statx status;
    if (statx(directory_fd, path,
              path[0] == '\0' ? AT_EMPTY_PATH : AT_SYMLINK_NOFOLLOW,
              STATX_TYPE | STATX_INO | STATX_BTIME, &status) != 0 ||
        (status.stx_mask & (STATX_TYPE | STATX_INO | STATX_BTIME)) !=
            (STATX_TYPE | STATX_INO | STATX_BTIME) ||
        status.stx_btime.tv_nsec >= 1000000000u ||
        !S_ISFIFO(status.stx_mode))
        return false;
    *identity = (sparc64_linux_fifo_identity_t){
        .device_major = status.stx_dev_major,
        .device_minor = status.stx_dev_minor,
        .inode = status.stx_ino,
        .birth_seconds = status.stx_btime.tv_sec,
        .birth_nanoseconds = status.stx_btime.tv_nsec
    };
#else
    struct stat status;
    int result = path[0] == '\0' ? fstat(directory_fd, &status) :
                 fstatat(directory_fd, path, &status, AT_SYMLINK_NOFOLLOW);
    if (result != 0 || !S_ISFIFO(status.st_mode))
        return false;
    *identity = (sparc64_linux_fifo_identity_t){
        .device_major = (uint32_t)((uint64_t)status.st_dev >> 32),
        .device_minor = (uint32_t)status.st_dev,
        .inode = (uint64_t)status.st_ino,
        .birth_seconds = status.st_birthtimespec.tv_sec,
        .birth_nanoseconds = (uint32_t)status.st_birthtimespec.tv_nsec
    };
#endif
    return true;
}

bool sparc64_linux_file_reserve_fifo(sparc64_linux_file_t *files)
{
    if (files == NULL) { errno = EINVAL; return false; }
    if (files->created_fifo_count < files->created_fifo_capacity)
        return true;
    size_t grown = files->created_fifo_capacity == 0 ? 8 :
                   files->created_fifo_capacity * 2;
    if (grown < files->created_fifo_capacity ||
        grown > SIZE_MAX / sizeof(*files->created_fifos)) {
        errno = ENOMEM;
        return false;
    }
    void *storage = realloc(files->created_fifos,
                            grown * sizeof(*files->created_fifos));
    if (storage == NULL)
        return false;
    files->created_fifos = storage;
    files->created_fifo_capacity = grown;
    return true;
}

void sparc64_linux_file_record_fifo(sparc64_linux_file_t *files, int directory_fd,
                               const char *leaf)
{
    if (files == NULL || leaf == NULL ||
        files->created_fifo_count >= files->created_fifo_capacity)
        return;
    sparc64_linux_fifo_identity_t identity;
    if (fifo_identity(directory_fd, leaf, &identity))
        files->created_fifos[files->created_fifo_count++] = identity;
}

static bool created_fifo_fd(sparc64_linux_file_t *files, int descriptor)
{
    if (files->created_fifo_count == 0)
        return false;
    sparc64_linux_fifo_identity_t opened;
    if (!fifo_identity(descriptor, "", &opened))
        return false;
    for (size_t i = 0; i < files->created_fifo_count; ++i) {
        const sparc64_linux_fifo_identity_t *saved = &files->created_fifos[i];
        if (opened.device_major == saved->device_major &&
            opened.device_minor == saved->device_minor &&
            opened.inode == saved->inode &&
            opened.birth_seconds == saved->birth_seconds &&
            opened.birth_nanoseconds == saved->birth_nanoseconds)
            return true;
    }
    return false;
}

uint64_t failure(unsigned int linux_errno)
{
    return UINT64_C(0) - linux_errno;
}

uint64_t host_failure(int host_errno)
{
    return failure(sparc64_linux_errno(host_errno == 0 ? EIO : host_errno));
}

/* Preserve the borrowed open description when a configured canonical callback
 * falls back to the ordinary nonregular-file route. Reacquiring by guest FD
 * after unborrow could select a close/reuse replacement. */
int duplicate_borrowed_fd(const sparc64_fd_borrow_t *borrowed)
{
    int duplicate = fcntl(borrowed->host_fd, F_DUPFD_CLOEXEC, 3);
    return duplicate;
}

int64_t signed_word(uint64_t word)
{
    return word <= (uint64_t)INT64_MAX ? (int64_t)word :
           -1 - (int64_t)(UINT64_MAX - word);
}

/* Preflight all possible mapped targets before native O_TRUNC chooses an inode.
 * No allocation/epoch failure is allowed after that irreversible side effect. */
static bool truncate_capacity(sparc64_space_t *space)
{
    for (size_t i = 0; i < space->count; ++i) {
        const sparc64_backing_t *backing = space->pages[i].backing;
        if (backing->file == NULL)
            continue;
        if (space->generation == UINT64_MAX) {
            space->fault_address = space->pages[i].address;
            space->fault_reason = SPARC64_FAULT_INTERNAL;
            space->internal_failure = true;
            return false;
        }
        for (size_t j = 0; j < SPARC64_PAGE_GRANULES; ++j)
            if (backing->epochs[j] == UINT64_MAX) {
                space->fault_address = space->pages[i].address +
                                       (uint64_t)j * SPARC64_RESERVATION_GRANULE;
                space->fault_reason = SPARC64_FAULT_INTERNAL;
                space->internal_failure = true;
                return false;
            }
    }
    return true;
}

static int open_truncate_adapter(int descriptor, int *native_errno,
                                 void *opaque)
{
    open_truncate_context_t *context = opaque;
    int reported = -1;
    int outcome = context->io->truncate(descriptor, 0, &reported,
                                       context->io->truncate_context);
    if (outcome != 0 || reported < 0 || reported >= 4096) {
        context->files->space->internal_failure = true;
        context->files->space->fault_reason = SPARC64_FAULT_INTERNAL;
        return -1;
    }
    context->confirmed = true;
    *native_errno = reported;
    return 0;
}

static uint64_t open_truncate_result(open_truncate_context_t *context,
                                     uint32_t reserved_guest_fd,
                                     uint64_t result)
{
    if (context->confirmed && context->io->open_truncate_result != NULL &&
        context->io->open_truncate_result(reserved_guest_fd, result,
            context->io->open_truncate_result_context) != 0) {
        context->files->space->internal_failure = true;
        context->files->space->fault_reason = SPARC64_FAULT_INTERNAL;
        return failure(5);
    }
    return result;
}

static bool file_init(sparc64_linux_file_t *files, sparc64_space_t *space,
                       const char *sysroot, sparc64_fd_initial_t **initial)
{
    if (files == NULL || space == NULL) {
        errno = EINVAL;
        return false;
    }
    memset(files, 0, sizeof(*files));
    files->space = space;
    files->creator_pid = getpid();
    if (initial == NULL && sparc64_fd_table_init(&files->descriptors) != 0)
        return false;
    sparc64_file_registry_init(&files->backings, space);
    files->active_backings = &files->backings;
    if (sparc64_path_resolver_init(&files->paths) != 0) {
        int saved = errno;
        sparc64_linux_file_destroy(files);
        errno = saved;
        return false;
    }
    if (sysroot != NULL) {
        /* Canonicalize once, before guest cwd changes can affect a relative
         * sysroot. This does not prevent symlink traversal inside that view. */
        files->sysroot = realpath(sysroot, NULL);
        if (files->sysroot == NULL) {
            int saved = errno;
            sparc64_linux_file_destroy(files);
            errno = saved;
            return false;
        }
    }
    int initialized = initial != NULL ?
        sparc64_fd_table_init_initial(&files->descriptors, initial) :
        0;
    if (initialized != 0) {
        int saved = errno;
        sparc64_linux_file_destroy(files);
        errno = saved;
        return false;
    }
    return true;
}

bool sparc64_linux_file_init(sparc64_linux_file_t *files, sparc64_space_t *space, const char *sysroot)
{
    return file_init(files, space, sysroot, NULL);
}

bool sparc64_linux_file_init_initial(sparc64_linux_file_t *files, sparc64_space_t *space,
                                 const char *sysroot, sparc64_fd_initial_t **initial)
{
    if (initial == NULL || *initial == NULL) { errno = EINVAL; return false; }
    return file_init(files, space, sysroot, initial);
}

void sparc64_linux_file_destroy(sparc64_linux_file_t *files)
{
    if (files == NULL)
        return;
    sparc64_fd_table_destroy(&files->descriptors);
    if (!files->backings_borrowed)
        sparc64_file_registry_destroy(&files->backings);
    sparc64_path_resolver_destroy(&files->paths);
    free(files->created_fifos);
    free(files->sysroot);
    memset(files, 0, sizeof(*files));
}

int sparc64_linux_file_fork_child_resolver_rebase(sparc64_linux_file_t *files)
{
    if (files == NULL || files->creator_pid == getpid()) {
        errno = EPERM;
        return -1;
    }
    sparc64_path_resolver_destroy(&files->paths);
    if (sparc64_path_resolver_init(&files->paths) != 0)
        return -1;
    files->creator_pid = getpid();
    return 0;
}

int sparc64_linux_file_bind_child_image(sparc64_linux_file_t *files, sparc64_space_t *space,
                                   sparc64_file_registry_t *registry)
{
    if (files == NULL || space == NULL || registry == NULL ||
        files->creator_pid != getpid() ||
        registry->space != space) {
        errno = EINVAL;
        return -1;
    }
    /* The child-start owner has already restored policy. The old registry
     * may be destroyed or freed; never inspect files->active_backings here. */
    files->space = space;
    files->active_backings = registry;
    files->backings_borrowed = true;
    return 0;
}

uint64_t sparc64_linux_file_mmap(sparc64_linux_file_t *files, sparc64_linux_memory_t *memory,
                           const uint64_t arguments[6])
{
    /* riscv_sys_mmap rejects unaligned byte offsets before fd lookup. */
    if (arguments[5] % SPARC64_PAGE_SIZE != 0)
        return failure(22);
    if ((arguments[3] & UINT64_C(0x20)) != 0)
        return sparc64_linux_mmap(memory, arguments[0], arguments[1], arguments[2],
                             arguments[3], arguments[4], arguments[5]);
    if ((arguments[3] & 3) != 2)
        return failure((arguments[3] & 3) == 0 ? 22 : 95);
    int lease = sparc64_fd_acquire(&files->descriptors, (uint32_t)arguments[4]);
    if (lease < 0)
        return host_failure(errno);
    sparc64_file_source_t *source = sparc64_file_source_acquire(files->active_backings, lease);
    if (source == NULL)
        return host_failure(errno);
    uint64_t result = sparc64_linux_mmap_source(memory, arguments[0], arguments[1],
                                          arguments[2], arguments[3], source, arguments[5]);
    source->release(source);
    return result;
}

uint64_t open_file(sparc64_linux_file_t *files,
                          const sparc64_linux_file_io_t *io,
                          const uint64_t arguments[6])
{
    char path[4096], resolved[8192];
    if (sparc64_linux_copy_path(files->space, arguments[1], path) != 0)
        return host_failure(errno);
    if (path[0] == '\0')
        return failure(2);
    int flags;
    bool cloexec;
    if (sparc64_linux_open_flags((uint32_t)arguments[2], &flags, &cloexec) != 0)
        return host_failure(errno);
    if (sparc64_linux_path_join(files->sysroot, path, resolved) != 0)
        return host_failure(errno);
    int guest = sparc64_fd_reserve(&files->descriptors);
    if (guest < 0)
        return host_failure(errno);
    bool canonical_truncate = io != NULL && io->truncate != NULL;
    if ((flags & O_TRUNC) != 0 && !canonical_truncate &&
        (!truncate_capacity(files->space) ||
         !sparc64_file_registry_prepare_truncate(files->active_backings))) {
        (void)sparc64_fd_cancel(&files->descriptors, (unsigned int)guest);
        return failure(12);
    }
    uint32_t directory = (uint32_t)arguments[0];
    int lease = -1, native_directory = AT_FDCWD;
    if (path[0] != '/' && directory != G_AT_FDCWD) {
        lease = sparc64_fd_acquire(&files->descriptors, directory);
        if (lease < 0) {
            int saved = errno;
            (void)sparc64_fd_cancel(&files->descriptors, (unsigned int)guest);
            return host_failure(saved);
        }
        native_directory = lease;
    }
    sparc64_path_open_result_t opened_result = {0};
    open_truncate_context_t truncate_context = {.files = files, .io = io};
    int opened = canonical_truncate ?
        sparc64_path_open_guest_with_truncate(&files->paths, native_directory,
                                         resolved, flags,
                                         (mode_t)(arguments[3] & UINT64_C(07777)),
                                         &opened_result, open_truncate_adapter,
                                         &truncate_context) :
        sparc64_path_open_guest(&files->paths, native_directory, resolved, flags,
                           (mode_t)(arguments[3] & UINT64_C(07777)),
                           &opened_result);
    int saved = errno;
    if (lease >= 0)
        (void)sparc64_fd_release(lease);
    if (opened < 0) {
        (void)sparc64_fd_cancel(&files->descriptors, (unsigned int)guest);
        return open_truncate_result(&truncate_context, (uint32_t)guest,
                                     host_failure(saved));
    }
    if ((flags & O_TRUNC) != 0 && !canonical_truncate) {
        /* Unknown providers can alias any source. Observe each retained FD's
         * own size; the global preflight ran before the irreversible open. */
        if (!sparc64_file_registry_observe_resize(files->active_backings)) {
            (void)close(opened);
            (void)sparc64_fd_cancel(&files->descriptors, (unsigned int)guest);
            return failure(5);
        }
    }
    uint32_t hidden = ~(uint32_t)arguments[2] & UINT32_C(0x30000);
    bool created_fifo = created_fifo_fd(files, opened);
#ifdef O_PATH
    if ((flags & O_PATH) != 0)
        created_fifo = false;
#endif
    bool fifo_writer = (flags & O_ACCMODE) != O_RDONLY &&
                       !opened_result.logical_read_only;
    int committed = created_fifo ?
        sparc64_fd_commit_managed_fifo(&files->descriptors, (unsigned int)guest,
                                   opened, cloexec, hidden,
                                   opened_result.logical_read_only,
                                   fifo_writer) :
        sparc64_fd_commit_with_access(&files->descriptors, (unsigned int)guest,
                                  opened, cloexec, hidden,
                                  opened_result.logical_read_only);
    uint64_t result = committed < 0 ? host_failure(errno) : (uint64_t)guest;
    return open_truncate_result(&truncate_context, (uint32_t)guest, result);
}

/* Guest threads share FS state (CLONE_FS), and the family guard serializes
 * this change with every translated relative path walk. Open through the
 * private-inode resolver first: chdir must not enter a runtime-owned directory
 * or follow a pathname replacement after the checked open. The native cwd is
 * already the relative-path base used by file, metadata and exec dispatch. */
uint64_t change_directory(sparc64_linux_file_t *files, uint64_t address)
{
    char path[SPARC64_LINUX_PATH_MAX], resolved[SPARC64_LINUX_HOST_PATH_MAX];
    if (sparc64_linux_copy_path(files->space, address, path) != 0)
        return host_failure(errno);
    if (path[0] == '\0')
        return failure(2);
    if (sparc64_linux_path_join(files->sysroot, path, resolved) != 0)
        return host_failure(errno);
    /* A Linux chdir requires search permission, not read permission. O_PATH
     * retains the exact checked directory without adding a read requirement.
     * Hosts without a certified O_PATH directory descriptor use the older
     * readable-directory route until that standard ABI is available. */
    int flags = O_RDONLY | O_DIRECTORY | O_CLOEXEC;
#ifdef O_PATH
    if (files->paths.native_path_supported)
        flags = O_PATH | O_DIRECTORY | O_CLOEXEC;
#endif
    int directory = sparc64_path_open(&files->paths, AT_FDCWD, resolved, flags, 0);
    if (directory < 0)
        return host_failure(errno);
    int changed = fchdir(directory), saved = errno;
    (void)close(directory);
    return changed < 0 ? host_failure(saved) : 0;
}

bool path_descriptor(int flags)
{
#ifdef O_PATH
    return (flags & O_PATH) != 0;
#else
    (void)flags;
    return false;
#endif
}

ssize_t managed_write(int native_fd, const void *bytes, size_t size, void *opaque)
{
    managed_write_t *context = opaque;
    sparc64_file_mutation_t *mutation = NULL;
    if (sparc64_file_mutation_begin(context->files->active_backings,
                                 native_fd, &mutation) != 0)
        return -1;
    uint64_t offset = context->positioned ? (uint64_t)context->position : 0;
    int flags = fcntl(native_fd, F_GETFL);
    if (flags < 0)
        goto failed;
    off_t native_position = (off_t)context->position;
    if (sparc64_file_mutation_needs_position(mutation) ||
        (context->positioned && (flags & O_APPEND) != 0)) {
        if ((flags & O_APPEND) != 0) {
            struct stat status;
            if (fstat(native_fd, &status) < 0)
                goto failed;
            if (status.st_size < 0) {
                errno = EIO;
                goto failed;
            }
            if (S_ISREG(status.st_mode)) {
                offset = (uint64_t)status.st_size;
                /* Linux pwrite honors O_APPEND; Darwin's underlying pwrite
                 * ignores it. The serialized file owner pins this EOF. */
                native_position = (off_t)offset;
            }
        } else if (!context->positioned) {
            off_t current = lseek(native_fd, 0, SEEK_CUR);
            if (current < 0)
                goto failed;
            offset = (uint64_t)current;
        }
    }
    if (!sparc64_file_mutation_prepare_write(mutation, offset, size)) {
        errno = ENOMEM;
        goto failed;
    }
    ssize_t completed = context->positioned ?
        pwrite(native_fd, bytes, size, native_position) :
        context->writer != NULL ?
        context->writer(native_fd, bytes, size, context->writer_context) :
        write(native_fd, bytes, size);
    int saved = errno;
    if (completed > 0)
        sparc64_file_mutation_commit_write(mutation, offset, (uint64_t)completed);
    sparc64_file_mutation_destroy(&mutation);
    errno = saved;
    return completed;
failed: {
    int saved = errno;
    sparc64_file_mutation_destroy(&mutation);
    errno = saved;
    return -1;
    }
}

uint64_t transfer(sparc64_linux_file_t *files, const sparc64_linux_file_io_t *io,
                          const uint64_t arguments[6],
                          bool writing, bool positioned)
{
    int64_t position = signed_word(arguments[3]);
    /* Linux v6.18 ksys_pread64/pwrite64 reject negative position before fdget. */
    if (positioned && position < 0)
        return failure(22);
    uint32_t hidden_flags;
    bool logical_read_only;
    bool callback_pwrite = writing && positioned && io->pwrite != NULL;
    bool canonical_candidate = writing && !positioned &&
                               io->canonical_write_request != NULL;
    sparc64_fd_borrow_t borrowed = {.host_fd = -1};
    bool borrowed_live = false;
    int lease;
    if (callback_pwrite || canonical_candidate) {
        if (sparc64_fd_borrow(&files->descriptors, (uint32_t)arguments[0],
                          &borrowed) != 0)
            return host_failure(errno);
        borrowed_live = true;
        lease = borrowed.host_fd;
        hidden_flags = borrowed.hidden_status_flags;
        logical_read_only = borrowed.logical_read_only;
    } else {
        lease = sparc64_fd_acquire_mode(&files->descriptors, (uint32_t)arguments[0],
                                    &hidden_flags, &logical_read_only);
        if (lease < 0)
            return host_failure(errno);
    }
    sparc64_owned_io_flight_t *owned = NULL;
    bool lease_transferred = false;
    uint64_t result;
    int flags = fcntl(lease, F_GETFL);
    if (flags < 0) {
        result = host_failure(errno);
        goto done;
    }
    if (path_descriptor(flags)) {
        result = failure(9);
        goto done;
    }
    if (callback_pwrite) {
        struct stat status;
        if (fstat(lease, &status) < 0) {
            result = host_failure(errno);
            goto done;
        }
        if (!S_ISREG(status.st_mode)) {
            /* The canonical pwrite callback owns regular-file mutation
             * accounting. Keep other seekable descriptors on the native
             * route, using a duplicate of this exact open description after
             * dropping the table borrow. */
            int duplicate = duplicate_borrowed_fd(&borrowed);
            if (duplicate < 0) {
                result = host_failure(errno);
                goto done;
            }
            if (sparc64_fd_unborrow(&borrowed) != 0) {
                int saved = errno;
                (void)close(duplicate);
                result = host_failure(saved);
                goto done;
            }
            borrowed_live = false;
            lease = duplicate;
            callback_pwrite = false;
        }
    }
    bool callback_canonical = false;
    if (canonical_candidate) {
        struct stat status;
        if (fstat(lease, &status) < 0) {
            result = host_failure(errno);
            goto done;
        }
        if (S_ISREG(status.st_mode)) {
            callback_canonical = true;
        } else {
            int duplicate = duplicate_borrowed_fd(&borrowed);
            if (duplicate < 0) {
                result = host_failure(errno);
                goto done;
            }
            if (sparc64_fd_unborrow(&borrowed) != 0) {
                int saved = errno;
                (void)close(duplicate);
                result = host_failure(saved);
                goto done;
            }
            borrowed_live = false;
            lease = duplicate;
        }
    }
    /* ksys_pread64/pwrite64 check FMODE_PREAD/PWRITE before vfs_* checks
     * access mode or user pointers. Querying the offset never consumes data. */
    if (positioned && lseek(lease, 0, SEEK_CUR) < 0 && errno == ESPIPE) {
        result = failure(29);
        goto done;
    }
    if (writing ? logical_read_only || (flags & O_ACCMODE) == O_RDONLY :
                  (flags & O_ACCMODE) == O_WRONLY) {
        result = failure(9);
        goto done;
    }
    if (writing && !positioned &&
        !callback_canonical &&
        (io->write_releases_guard || io->write_request != NULL)) {
        struct stat status;
        if (io->write == NULL && io->write_request == NULL) {
            result = failure(95);
            goto done;
        }
        if (fstat(lease, &status) < 0) {
            result = host_failure(errno);
            goto done;
        }
        if (!S_ISFIFO(status.st_mode)) {
            result = failure(95);
            goto done;
        }
    }
    uint64_t address = arguments[1], requested = arguments[2];
    /* vfs_read/write apply access_ok to the original count before MAX_RW_COUNT.
     * Numeric validity does not mean the range is mapped or permitted. */
    if (address > files->space->limit || requested > files->space->limit - address) {
        result = failure(14);
        goto done;
    }
    uint64_t count = requested > MAX_RW_COUNT ? MAX_RW_COUNT : requested;
    if (writing && !positioned &&
        !callback_canonical &&
        (io->write != NULL || io->write_request != NULL) && io->max_write != 0 &&
        count > io->max_write) {
        result = failure(95);
        goto done;
    }
    if (callback_canonical && count > io->max_canonical_write) {
        result = failure(95);
        goto done;
    }
    /* The callback cap applies to the complete Linux-capped count before
     * touching guest payload memory. After a later copy-in fault, Linux may
     * still apply the valid prefix once; never fragment or fall back. */
    if (callback_pwrite && count > io->max_pwrite) {
        result = failure(95);
        goto done;
    }
    /* Owned pipe callbacks need the original logical size: truncating to a
     * staging prefix changes blocking completion and Linux's remainder merge.
     * The immutable buffer remains owned until the callback reacquires the
     * family guard. Other current I/O keeps its bounded short-write path. */
    bool full_write = writing && !positioned &&
                      (io->write != NULL || io->write_request != NULL ||
                       callback_canonical) &&
                      (io->full_write || io->write_request != NULL);
    if (callback_canonical)
        full_write = true;
    size_t amount = callback_pwrite || callback_canonical || full_write || count < IO_STAGE ?
                    (size_t)count : IO_STAGE;
    if (!writing) {
        struct stat status;
        if (fstat(lease, &status) < 0) {
            result = host_failure(errno);
            goto done;
        }
        /* File-level errors precede actual user-copy faults. Numeric access_ok
         * above still applies even when no bytes will be copied. Do not use
         * st_size as an EOF oracle: pseudo files can report a synthetic size. */
        if (S_ISDIR(status.st_mode)) {
            result = failure(21);
            goto done;
        }
    }
    unsigned char *staging = malloc(amount == 0 ? 1 : amount);
    if (staging == NULL) {
        result = failure(12);
        goto done;
    }
    size_t prepared = 0;
    while (prepared < amount) {
        uint64_t cursor = address + prepared;
        size_t part = (size_t)(SPARC64_PAGE_SIZE - (cursor & (SPARC64_PAGE_SIZE - 1)));
        if (part > amount - prepared)
            part = amount - prepared;
        /* Read syscall probing checks WRITE without mutating the destination.
         * Both copyout plans pin views before the native call; only the owned
         * I/O plan permits intervening token owners to change guest state. */
        if (!sparc64_space_read(files->space, cursor, staging + prepared, part,
                            writing ? SPARC64_MEM_READ : SPARC64_MEM_WRITE)) {
            if (sparc64_fault_is_runtime(files->space->fault_reason)) {
                free(staging);
                result = failure(12);
                goto done;
            }
            break;
        }
        prepared += part;
    }
    if (prepared == 0 && amount != 0 &&
        !(writing && !positioned && io->write_request != NULL &&
          !callback_canonical)) {
        /* A regular file at EOF can return zero without
         * touching even an unmapped destination. A zero-byte native probe is
         * insufficient: an ordinary nonempty file would also return zero.
         * Peek one byte with pread, which cannot consume the shared offset. */
        if (!writing) {
            struct stat status;
            off_t offset = positioned ? (off_t)position : lseek(lease, 0, SEEK_CUR);
            if (offset >= 0 && fstat(lease, &status) == 0 && S_ISREG(status.st_mode)) {
                ssize_t peeked = pread(lease, staging, 1, offset);
                if (peeked <= 0) {
                    int saved = errno;
                    free(staging);
                    result = peeked == 0 ? 0 : host_failure(saved);
                    goto done;
                }
            }
        }
        free(staging);
        result = failure(14);
        goto done;
    }
    sparc64_copyout_t *copyout = NULL;
    sparc64_io_copyout_t *io_copyout = NULL;
    bool rebasing = !writing && !positioned && io->read != NULL &&
                    io->read_releases_guard;
    if (!writing && prepared != 0) {
        if (rebasing)
            io_copyout = sparc64_space_io_copyout_prepare(files->space, address, prepared);
        else
            copyout = sparc64_space_copyout_prepare(files->space, address, prepared);
        if (copyout == NULL && io_copyout == NULL) {
            free(staging);
            result = failure(sparc64_fault_is_runtime(files->space->fault_reason) ? 12 : 14);
            goto done;
        }
    }
    bool releasing = rebasing || (writing && !positioned &&
                                  !callback_canonical &&
                                  io->write_releases_guard);
    if (releasing && io->owned_io != NULL) {
        if (io->flight_slot == NULL || *io->flight_slot != NULL) {
            sparc64_space_copyout_discard(copyout);
            sparc64_space_io_copyout_discard(io_copyout);
            free(staging);
            result = failure(22);
            goto done;
        }
        if (sparc64_owned_io_begin(io->owned_io, lease, staging, copyout,
                              io_copyout, &owned) != 0) {
            sparc64_space_copyout_discard(copyout);
            sparc64_space_io_copyout_discard(io_copyout);
            free(staging);
            result = failure(12);
            goto done;
        }
        lease_transferred = true;
        *io->flight_slot = owned;
    }
    ssize_t completed;
    if (writing) {
        managed_write_t context = {
            .files = files,
            .positioned = positioned,
            .position = position,
            .writer = positioned ? NULL : io->write,
            .writer_context = positioned ? NULL : io->write_context
        };
        if (callback_pwrite) {
            completed = io->pwrite(lease, staging, prepared,
                                   (uint64_t)position, io->pwrite_context);
        } else if (callback_canonical) {
            const sparc64_linux_write_request_t request = {
                .bytes = staging, .valid_size = prepared,
                .logical_size = (size_t)count
            };
            completed = io->canonical_write_request(
                lease, &request, io->canonical_write_request_context);
        } else if (!positioned && io->write_request != NULL) {
            const sparc64_linux_write_request_t request = {
                .bytes = staging, .valid_size = prepared,
                .logical_size = (size_t)count
            };
            completed = io->write_request(lease, &request,
                                          io->write_request_context);
        } else {
            completed = managed_write(lease, staging, prepared, &context);
        }
    }
    else
        completed = positioned ? pread(lease, staging, prepared, (off_t)position) :
                    io->read != NULL ?
                    io->read(lease, staging, prepared, io->read_context) :
                    read(lease, staging, prepared);
    int saved = errno;
    if (completed < 0)
        result = host_failure(saved);
    else if ((size_t)completed > prepared)
        result = failure(5);
    else if (!writing && completed != 0) {
        size_t committed = 0;
        bool copied = rebasing ?
            sparc64_space_io_copyout_commit(io_copyout, staging, (size_t)completed,
                                       &committed) :
            sparc64_space_copyout_commit(copyout, staging, (size_t)completed);
        if (copied)
            result = (uint64_t)completed;
        else if (sparc64_fault_is_runtime(files->space->fault_reason))
            result = failure(12); /* Runtime observes sticky INTERNAL. */
        else
            result = committed != 0 ? (uint64_t)committed : failure(14);
    } else
        result = (uint64_t)completed;
    if (owned != NULL) {
        *io->flight_slot = NULL;
        sparc64_owned_io_finish(&owned);
    } else {
        sparc64_space_copyout_discard(copyout);
        sparc64_space_io_copyout_discard(io_copyout);
        free(staging);
    }
done:
    if (!lease_transferred) {
        if (borrowed_live)
            (void)sparc64_fd_unborrow(&borrowed);
        else
            (void)sparc64_fd_release(lease);
    }
    return result;
}
