/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L
#include "linux/io.h"
#include "linux/error.h"
#include "runtime/owned_io.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <unistd.h>

#define SPARC64_LINUX_IOV_MAX 1024u
#define SPARC64_LINUX_MAX_RW_COUNT UINT64_C(0x7ffff000)
#define SPARC64_LINUX_WRITEV_STAGE ((size_t)65536)

typedef struct {
    uint64_t base;
    uint64_t length;
} guest_iovec_t;

static uint64_t error_result(int error)
{
    return UINT64_C(0) - sparc64_linux_errno(error);
}

static uint64_t load_le64(const unsigned char *bytes)
{
    uint64_t value = 0;
    for (unsigned int i = 0; i < 8; ++i)
        value |= (uint64_t)bytes[i] << (i * 8);
    return value;
}

static ssize_t host_write(int fd, const void *bytes, size_t size, void *context)
{
    (void)context;
    return write(fd, bytes, size);
}

static uint64_t write_vectors(sparc64_space_t *space, int fd,
                               uint64_t iov_address, uint64_t iov_count,
                               sparc64_linux_write_fn writer, void *context,
                               sparc64_linux_write_request_fn request,
                               void *request_context,
                               size_t maximum, bool full_stage,
                               sparc64_owned_io_registry_t *registry,
                               sparc64_owned_io_flight_t **flight_slot)
{
    if (space == NULL || (writer == NULL && request == NULL))
        return error_result(EINVAL);
    /* Linux's vlen is unsigned long at the syscall boundary but import_iovec
     * narrows it to unsigned nr_segs before enforcing IOV_MAX. */
    iov_count = (uint32_t)iov_count;
    if (iov_count > SPARC64_LINUX_IOV_MAX)
        return error_result(EINVAL);
    if (iov_count == 0)
        return 0;

    guest_iovec_t vectors[SPARC64_LINUX_IOV_MAX];
    for (uint64_t i = 0; i < iov_count; ++i) {
        uint64_t offset = i * UINT64_C(16);
        if (iov_address > UINT64_MAX - offset)
            return error_result(EFAULT);
        unsigned char header[16];
        if (!sparc64_space_read(space, iov_address + offset, header, sizeof(header),
                           SPARC64_MEM_READ))
            return error_result(sparc64_fault_is_runtime(space->fault_reason) ?
                                ENOMEM : EFAULT);
        vectors[i].base = load_le64(header);
        vectors[i].length = load_le64(header + 8);
        if (vectors[i].length > (uint64_t)INT64_MAX)
            return error_result(EINVAL);
    }

    uint64_t total = 0;
    if (iov_count == 1) {
        if (vectors[0].length > SPARC64_LINUX_MAX_RW_COUNT)
            vectors[0].length = SPARC64_LINUX_MAX_RW_COUNT;
        if (vectors[0].base > space->limit ||
            vectors[0].length > space->limit - vectors[0].base)
            return error_result(EFAULT);
        total = vectors[0].length;
    } else {
        for (uint64_t i = 0; i < iov_count; ++i) {
            if (vectors[i].base > space->limit ||
                vectors[i].length > space->limit - vectors[i].base)
                return error_result(EFAULT);
            if (total < SPARC64_LINUX_MAX_RW_COUNT) {
                uint64_t remaining = SPARC64_LINUX_MAX_RW_COUNT - total;
                total += vectors[i].length < remaining ? vectors[i].length : remaining;
            }
        }
    }
    if (total == 0)
        return 0;
    if (total > maximum)
        return error_result(EOPNOTSUPP);

    sparc64_owned_io_flight_t *owned = NULL;
    if (registry != NULL) {
        if (flight_slot == NULL || *flight_slot != NULL) {
            errno = EINVAL;
            return error_result(EIO);
        }
        if (sparc64_owned_io_begin(registry, fd, NULL, NULL, NULL, &owned) != 0)
            return error_result(errno == ENOMEM ? ENOMEM : EIO);
        *flight_slot = owned;
    }

    size_t staging_size = full_stage || request != NULL ||
                          total < SPARC64_LINUX_WRITEV_STAGE ?
                          (size_t)total : SPARC64_LINUX_WRITEV_STAGE;
    unsigned char *staging = malloc(staging_size);
    if (staging == NULL)
        return error_result(ENOMEM);
    if (owned != NULL && sparc64_owned_io_adopt_staging(owned, staging) != 0) {
        free(staging);
        return error_result(EIO);
    }

    size_t staged = 0;
    bool faulted = false;
    for (uint64_t i = 0; i < iov_count && staged < staging_size; ++i) {
        uint64_t copied = 0;
        while (copied < vectors[i].length && staged < staging_size) {
            if (vectors[i].base > UINT64_MAX - copied) {
                faulted = true;
                break;
            }
            uint64_t address = vectors[i].base + copied;
            size_t amount = staging_size - staged;
            uint64_t vector_remaining = vectors[i].length - copied;
            if ((uint64_t)amount > vector_remaining)
                amount = (size_t)vector_remaining;
            size_t page_remaining =
                (size_t)(SPARC64_PAGE_SIZE - (address & (SPARC64_PAGE_SIZE - 1)));
            if (amount > page_remaining)
                amount = page_remaining;
            if (!sparc64_space_read(space, address, staging + staged, amount,
                               SPARC64_MEM_READ)) {
                if (sparc64_fault_is_runtime(space->fault_reason)) {
                    if (owned == NULL)
                        free(staging);
                    return error_result(ENOMEM);
                }
                faulted = true;
                break;
            }
            copied += (uint64_t)amount;
            staged += amount;
        }
        if (faulted)
            break;
    }
    if (request == NULL && faulted && staged == 0) {
        if (owned == NULL)
            free(staging);
        return error_result(EFAULT);
    }

    errno = 0;
    const sparc64_linux_write_request_t captured = {
        .bytes = staging, .valid_size = staged, .logical_size = (size_t)total
    };
    ssize_t written = request != NULL ?
        request(fd, &captured, request_context) :
        writer(fd, staging, staged, context);
    int write_error = errno;
    if (owned == NULL)
        free(staging);
    if (written < 0)
        return error_result(write_error == 0 ? EIO : write_error);
    if ((size_t)written > staged)
        return error_result(EIO);
    return (uint64_t)written;
}

uint64_t sparc64_linux_writev(sparc64_space_t *space, uint64_t fd,
                         uint64_t iov_address, uint64_t iov_count)
{
    fd = (uint32_t)fd;
    if (fd != 1 && fd != 2)
        return error_result(EBADF);
    return sparc64_linux_writev_fd(space, (int)fd, iov_address, iov_count);
}

uint64_t sparc64_linux_writev_fd(sparc64_space_t *space, int native_fd,
                            uint64_t iov_address, uint64_t iov_count)
{
    return sparc64_linux_writev_fd_with_writer(space, native_fd, iov_address, iov_count,
                                           host_write, NULL);
}

uint64_t sparc64_linux_writev_fd_with_writer(sparc64_space_t *space, int native_fd,
                                        uint64_t iov_address, uint64_t iov_count,
                                        sparc64_linux_write_fn writer, void *context)
{
    return sparc64_linux_writev_fd_with_writer_limit(space, native_fd, iov_address,
                                                 iov_count, writer, context,
                                                 SIZE_MAX, false);
}

uint64_t sparc64_linux_writev_fd_with_writer_limit(sparc64_space_t *space, int native_fd,
                                               uint64_t iov_address,
                                               uint64_t iov_count,
                                               sparc64_linux_write_fn writer,
                                               void *context, size_t maximum,
                                               bool full_stage)
{
    int flags = fcntl(native_fd, F_GETFL);
    if (flags < 0)
        return error_result(errno == 0 ? EBADF : errno);
    if ((flags & O_ACCMODE) == O_RDONLY)
        return error_result(EBADF);
#ifdef O_PATH
    if ((flags & O_PATH) != 0)
        return error_result(EBADF);
#endif
    return write_vectors(space, native_fd, iov_address, iov_count, writer,
                          context, NULL, NULL, maximum, full_stage, NULL, NULL);
}

uint64_t sparc64_linux_writev_fd_with_request_limit(sparc64_space_t *space, int native_fd,
                                                uint64_t iov_address,
                                                uint64_t iov_count,
                                                sparc64_linux_write_fn writer,
                                                void *writer_context,
                                                sparc64_linux_write_request_fn request,
                                                void *request_context,
                                                size_t maximum, bool full_stage)
{
    int flags = fcntl(native_fd, F_GETFL);
    if (flags < 0)
        return error_result(errno == 0 ? EBADF : errno);
    if ((flags & O_ACCMODE) == O_RDONLY)
        return error_result(EBADF);
#ifdef O_PATH
    if ((flags & O_PATH) != 0)
        return error_result(EBADF);
#endif
    return write_vectors(space, native_fd, iov_address, iov_count, writer,
                          writer_context, request, request_context,
                          maximum, full_stage, NULL, NULL);
}

uint64_t sparc64_linux_writev_fd_with_request_limit_owned(
    sparc64_space_t *space, int native_fd, uint64_t iov_address, uint64_t iov_count,
    sparc64_linux_write_fn writer, void *writer_context,
    sparc64_linux_write_request_fn request, void *request_context,
    size_t maximum, bool full_stage,
    sparc64_owned_io_registry_t *registry, sparc64_owned_io_flight_t **flight_slot)
{
    int flags = fcntl(native_fd, F_GETFL);
    if (flags < 0)
        return error_result(errno == 0 ? EBADF : errno);
    if ((flags & O_ACCMODE) == O_RDONLY)
        return error_result(EBADF);
#ifdef O_PATH
    if ((flags & O_PATH) != 0)
        return error_result(EBADF);
#endif
    return write_vectors(space, native_fd, iov_address, iov_count, writer,
                          writer_context, request, request_context,
                          maximum, full_stage, registry, flight_slot);
}

uint64_t sparc64_linux_writev_with_writer(sparc64_space_t *space, uint64_t fd,
                                     uint64_t iov_address, uint64_t iov_count,
                                     sparc64_linux_write_fn writer, void *context)
{
    fd = (uint32_t)fd;
    if (fd != 1 && fd != 2)
        return error_result(EBADF);
    return write_vectors(space, (int)fd, iov_address, iov_count, writer,
                          context, NULL, NULL, SIZE_MAX, false, NULL, NULL);
}
