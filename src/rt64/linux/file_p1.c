/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#include "file_split.h"


static uint64_t get_status(sparc64_linux_file_t *files, const uint64_t arguments[6])
{
    int lease = sparc64_fd_acquire(&files->descriptors, (uint32_t)arguments[0]);
    if (lease < 0)
        return host_failure(errno);
    struct stat status;
    int result = fstat(lease, &status), saved = errno;
    (void)sparc64_fd_release(lease);
    if (result < 0)
        return host_failure(saved);
    unsigned char encoded[128];
    if (sparc64_codec_stat64(encoded, &status) != 0)
        return host_failure(errno);
    /* Match read copyout classification; the runtime still treats INTERNAL
     * as fatal after dispatch rather than committing this result to a guest. */
    return sparc64_space_write(files->space, arguments[1], encoded, sizeof(encoded)) ?
           0 : failure(sparc64_fault_is_runtime(files->space->fault_reason) ? 12 : 14);
}

static uint64_t seek_file(sparc64_linux_file_t *files, const uint64_t arguments[6])
{
    sparc64_fd_borrow_t borrowed = {0};
    if (sparc64_fd_borrow(&files->descriptors, (uint32_t)arguments[0], &borrowed) != 0)
        return host_failure(errno);
    int whence;
    switch ((uint32_t)arguments[2]) {
    case 0: whence = SEEK_SET; break;
    case 1: whence = SEEK_CUR; break;
    case 2: whence = SEEK_END; break;
    default: (void)sparc64_fd_unborrow(&borrowed); return failure(22);
    }
    off_t offset = lseek(borrowed.host_fd, (off_t)signed_word(arguments[1]), whence);
    int saved = errno;
    (void)sparc64_fd_unborrow(&borrowed);
    return offset < 0 ? host_failure(saved) : (uint64_t)offset;
}

static uint64_t control_file(sparc64_linux_file_t *files, const uint64_t arguments[6])
{
    unsigned int fd = (uint32_t)arguments[0], command = (uint32_t)arguments[1];
    uint64_t argument = arguments[2];
    if (command == 0 || command == 1030) { /* F_DUPFD[_CLOEXEC] */
        /* Kernel validates the descriptor before checking signed int minimum. */
        if (sparc64_fd_get_cloexec(&files->descriptors, fd) < 0)
            return host_failure(errno);
        if ((uint32_t)argument > INT_MAX)
            return failure(22);
        int duplicated = sparc64_fd_dup(&files->descriptors, fd, (uint32_t)argument,
                                    command == 1030);
        return duplicated < 0 ? host_failure(errno) : (uint64_t)duplicated;
    }
    if (command == 1) { /* F_GETFD */
        int flag = sparc64_fd_get_cloexec(&files->descriptors, fd);
        return flag < 0 ? host_failure(errno) : (uint64_t)flag;
    }
    if (command == 2) { /* F_SETFD ignores bits other than FD_CLOEXEC. */
        return sparc64_fd_set_cloexec(&files->descriptors, fd, (argument & 1) != 0) < 0 ?
               host_failure(errno) : 0;
    }
    uint32_t hidden_flags;
    bool logical_read_only;
    int lease = sparc64_fd_acquire_mode(&files->descriptors, fd, &hidden_flags,
                                    &logical_read_only);
    if (lease < 0)
        return host_failure(errno);
    uint64_t result;
    int previous = fcntl(lease, F_GETFL);
    if (previous < 0)
        result = host_failure(errno);
    else if (path_descriptor(previous) && command != 3)
        result = failure(9);
    else if (command == 3) { /* F_GETFL */
        result = sparc64_linux_getfl(previous) & ~hidden_flags;
        if (logical_read_only)
            result &= ~UINT64_C(3);
    } else if (command == 4) { /* F_SETFL, append/nonblocking current subset. */
        if ((argument & (UINT64_C(0x2000) | UINT64_C(0x4000) | UINT64_C(0x40000))) != 0)
            result = failure(95);
        else {
            int flags = previous & ~(O_APPEND | O_NONBLOCK);
            if ((argument & UINT64_C(0x400)) != 0) flags |= O_APPEND;
            if ((argument & UINT64_C(0x800)) != 0) flags |= O_NONBLOCK;
            result = fcntl(lease, F_SETFL, flags) < 0 ? host_failure(errno) : 0;
        }
    } else
        result = failure(95); /* No process record-lock claim from FD leases. */
    (void)sparc64_fd_release(lease);
    return result;
}

static ssize_t canonical_writev_request(int descriptor,
                                        const sparc64_linux_write_request_t *request,
                                        void *opaque)
{
    canonical_writev_context_t *context = opaque;
    if (request->logical_size != 0 && request->valid_size == 0) {
        errno = EFAULT;
        return -1;
    }
    return context->callback(descriptor, request, context->context);
}

static uint64_t write_vectors(sparc64_linux_file_t *files,
                              const sparc64_linux_file_io_t *io,
                              const uint64_t arguments[6])
{
    uint32_t hidden_flags;
    bool logical_read_only;
    sparc64_fd_borrow_t borrowed = {.host_fd = -1};
    bool borrowed_live = false;
    bool canonical_candidate = io->canonical_write_request != NULL;
    int lease;
    if (canonical_candidate) {
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
    if (logical_read_only) {
        if (borrowed_live)
            (void)sparc64_fd_unborrow(&borrowed);
        else
            (void)sparc64_fd_release(lease);
        return failure(9);
    }
    bool callback_canonical = false;
    if (canonical_candidate) {
        int flags = fcntl(lease, F_GETFL);
        if (flags < 0) {
            int saved = errno;
            (void)sparc64_fd_unborrow(&borrowed);
            return host_failure(saved);
        }
        if (path_descriptor(flags) || (flags & O_ACCMODE) == O_RDONLY) {
            (void)sparc64_fd_unborrow(&borrowed);
            return failure(9);
        }
        struct stat status;
        if (fstat(lease, &status) < 0) {
            int saved = errno;
            (void)sparc64_fd_unborrow(&borrowed);
            return host_failure(saved);
        }
        if (S_ISREG(status.st_mode)) {
            callback_canonical = true;
        } else {
            int duplicate = duplicate_borrowed_fd(&borrowed);
            if (duplicate < 0) {
                int saved = errno;
                (void)sparc64_fd_unborrow(&borrowed);
                return host_failure(saved);
            }
            if (sparc64_fd_unborrow(&borrowed) != 0) {
                int saved = errno;
                (void)close(duplicate);
                borrowed_live = false;
                return host_failure(saved);
            }
            borrowed_live = false;
            lease = duplicate;
        }
    }
    if (callback_canonical) {
        canonical_writev_context_t context = {
            .callback = io->canonical_write_request,
            .context = io->canonical_write_request_context
        };
        uint64_t result = sparc64_linux_writev_fd_with_request_limit(
            files->space, lease, arguments[1], arguments[2], NULL, NULL,
            canonical_writev_request, &context,
            io->max_canonical_write, true);
        int saved = errno;
        (void)sparc64_fd_unborrow(&borrowed);
        errno = saved;
        return result;
    }
    if (io->write_releases_guard || io->write_request != NULL) {
        struct stat status;
        if (io->write == NULL && io->write_request == NULL) {
            (void)sparc64_fd_release(lease);
            return failure(95);
        }
        if (fstat(lease, &status) < 0) {
            int saved = errno;
            (void)sparc64_fd_release(lease);
            return host_failure(saved);
        }
        if (!S_ISFIFO(status.st_mode)) {
            (void)sparc64_fd_release(lease);
            return failure(95);
        }
    }
    managed_write_t context = {
        .files = files,
        .writer = io->write,
        .writer_context = io->write_context
    };
    size_t maximum = (io->write != NULL || io->write_request != NULL) &&
                     io->max_write != 0 ? io->max_write : SIZE_MAX;
    bool owned = io->write_releases_guard && io->owned_io != NULL;
    if (owned && (io->flight_slot == NULL || *io->flight_slot != NULL)) {
        (void)sparc64_fd_release(lease);
        return failure(5);
    }
    uint64_t result = owned ? sparc64_linux_writev_fd_with_request_limit_owned(
        files->space, lease, arguments[1], arguments[2], managed_write,
        &context, io->write_request, io->write_request_context,
        maximum, io->full_write, io->owned_io, io->flight_slot) :
        sparc64_linux_writev_fd_with_request_limit(
        files->space, lease, arguments[1], arguments[2], managed_write,
        &context, io->write_request, io->write_request_context,
        maximum, io->full_write);
    if (owned && *io->flight_slot != NULL)
        sparc64_owned_io_finish(io->flight_slot);
    else
        (void)sparc64_fd_release(lease);
    return result;
}

static uint64_t resize_file(sparc64_linux_file_t *files,
                            const sparc64_linux_file_io_t *io,
                            const uint64_t arguments[6])
{
    int64_t length = signed_word(arguments[1]);
    if (length < 0)
        return failure(22);
    uint32_t hidden_flags;
    bool logical_read_only;
    bool callback_truncate = io->truncate != NULL;
    sparc64_fd_borrow_t borrowed = {.host_fd = -1};
    int lease;
    if (callback_truncate) {
        if (sparc64_fd_borrow(&files->descriptors, (uint32_t)arguments[0],
                          &borrowed) != 0)
            return host_failure(errno);
        lease = borrowed.host_fd;
        logical_read_only = borrowed.logical_read_only;
    } else {
        lease = sparc64_fd_acquire_mode(&files->descriptors,
                                   (uint32_t)arguments[0], &hidden_flags,
                                   &logical_read_only);
    }
    if (lease < 0)
        return host_failure(errno);
    uint64_t result;
    int flags = fcntl(lease, F_GETFL);
    if (flags < 0) {
        result = host_failure(errno);
        goto done;
    }
    if (path_descriptor(flags) || logical_read_only ||
        (flags & O_ACCMODE) == O_RDONLY) {
        result = failure(path_descriptor(flags) ? 9 : 22);
        goto done;
    }
    if (callback_truncate) {
        struct stat status;
        if (fstat(lease, &status) != 0) {
            result = host_failure(errno);
            goto done;
        }
        if (!S_ISREG(status.st_mode)) {
            result = failure(22);
            goto done;
        }
        int native_errno = -1;
        int disposition = io->truncate(lease, (uint64_t)length,
                                        &native_errno, io->truncate_context);
        if (disposition != 0 || native_errno < 0 || native_errno >= 4096) {
            files->space->internal_failure = true;
            files->space->fault_reason = SPARC64_FAULT_INTERNAL;
            result = failure(5);
        } else {
            result = native_errno == 0 ? 0 : host_failure(native_errno);
        }
        goto done;
    }
    sparc64_file_mutation_t *mutation = NULL;
    if (sparc64_file_mutation_begin(files->active_backings, lease, &mutation) != 0) {
        result = host_failure(errno);
        goto done;
    }
    if (!sparc64_file_mutation_prepare_resize(mutation, (uint64_t)length))
        result = failure(12);
    else if (ftruncate(lease, (off_t)length) < 0)
        result = host_failure(errno);
    else {
        result = sparc64_file_mutation_commit_resize(mutation, (uint64_t)length) ?
                 0 : failure(5);
    }
    sparc64_file_mutation_destroy(&mutation);
done:
    if (callback_truncate)
        (void)sparc64_fd_unborrow(&borrowed);
    else
        (void)sparc64_fd_release(lease);
    return result;
}

static uint64_t ioctl_file(sparc64_linux_file_t *files, const uint64_t arguments[6])
{
    int lease = sparc64_fd_acquire(&files->descriptors, (uint32_t)arguments[0]);
    if (lease < 0)
        return host_failure(errno);
    uint64_t result = failure(25); /* Unsupported ioctl requests: ENOTTY. */
    int flags = fcntl(lease, F_GETFL);
    if (flags < 0)
        result = host_failure(errno);
    else if (path_descriptor(flags))
        result = failure(9);
    else if ((uint32_t)arguments[1] == UINT32_C(0x5413)) { /* TIOCGWINSZ */
        struct winsize size;
        if (ioctl(lease, TIOCGWINSZ, &size) < 0)
            result = host_failure(errno);
        else {
            const unsigned int values[4] = {size.ws_row, size.ws_col, size.ws_xpixel, size.ws_ypixel};
            unsigned char encoded[8];
            for (size_t i = 0; i < 4; ++i) {
                encoded[i * 2] = (unsigned char)values[i];
                encoded[i * 2 + 1] = (unsigned char)(values[i] >> 8);
            }
            result = sparc64_space_write(files->space, arguments[2], encoded, sizeof(encoded)) ?
                     0 : failure(sparc64_fault_is_runtime(files->space->fault_reason) ?
                                 12 : 14);
        }
    }
    (void)sparc64_fd_release(lease);
    return result;
}

bool sparc64_linux_file_dispatch(sparc64_linux_file_t *files, uint64_t number,
                            const uint64_t arguments[6], uint64_t *result)
{
    return sparc64_linux_file_dispatch_io(files, NULL, number, arguments, result);
}

bool sparc64_linux_file_dispatch_io(sparc64_linux_file_t *files,
                               const sparc64_linux_file_io_t *io, uint64_t number,
                               const uint64_t arguments[6], uint64_t *result)
{
    if (files == NULL || arguments == NULL || result == NULL)
        return false;
    const sparc64_linux_file_io_t selected = io != NULL ? *io : (sparc64_linux_file_io_t){
        .read = files->read,
        .read_context = files->read_context,
        .read_releases_guard = files->read_releases_guard,
        .poll = files->poll,
        .poll_context = files->poll_context
    };
    if (sparc64_linux_metadata_dispatch(files, number, arguments, result))
        return true;
    if (sparc64_linux_directory_dispatch(files, number, arguments, result))
        return true;
    if (sparc64_linux_pipe_dispatch(files, number, arguments, result))
        return true;
    if (sparc64_linux_poll_dispatch_io(files, &selected, number, arguments, result))
        return true;
    if (sparc64_linux_socket_dispatch(files, number, arguments, result))
        return true;
    switch (number) {
    case 23: {
        int value = sparc64_fd_dup(&files->descriptors, (uint32_t)arguments[0], 0, false);
        *result = value < 0 ? host_failure(errno) : (uint64_t)value;
        break;
    }
    case 24: {
        uint32_t flags = (uint32_t)arguments[2];
        if ((flags & ~UINT32_C(0x80000)) != 0)
            *result = failure(22);
        else {
            int value = sparc64_fd_dup3(&files->descriptors, (uint32_t)arguments[0],
                                   (uint32_t)arguments[1], flags != 0);
            *result = value < 0 ? host_failure(errno) : (uint64_t)value;
        }
        break;
    }
    case 25: *result = control_file(files, arguments); break;
    case 29: *result = ioctl_file(files, arguments); break;
    case 46: *result = resize_file(files, &selected, arguments); break;
    case 49: *result = change_directory(files, arguments[0]); break;
    case 56: *result = open_file(files, &selected, arguments); break;
    case 57: *result = sparc64_fd_close(&files->descriptors, (uint32_t)arguments[0]) < 0 ?
                       host_failure(errno) : 0; break;
    case 62: *result = seek_file(files, arguments); break;
    case 63: *result = transfer(files, &selected, arguments, false, false); break;
    case 64: *result = transfer(files, &selected, arguments, true, false); break;
    case 66: *result = write_vectors(files, &selected, arguments); break;
    case 67: *result = transfer(files, &selected, arguments, false, true); break;
    case 68: *result = transfer(files, &selected, arguments, true, true); break;
    case 80: *result = get_status(files, arguments); break;
    default: return false;
    }
    return true;
}
