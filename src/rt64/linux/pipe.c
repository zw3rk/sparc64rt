/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L
#include "linux/pipe.h"
#include "linux/error.h"

#include <errno.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>

#define G_O_NONBLOCK UINT32_C(0x800)
#define G_O_CLOEXEC UINT32_C(0x80000)
#define G_O_DIRECT UINT32_C(0x4000)
#define G_O_NOTIFICATION_PIPE UINT32_C(0x80)

static uint64_t failure(unsigned int error)
{
    return UINT64_C(0) - error;
}

static int native_pipe(int descriptors[2], bool nonblocking)
{
#if defined(__linux__)
    return pipe2(descriptors, O_CLOEXEC | (nonblocking ? O_NONBLOCK : 0));
#else
    if (pipe(descriptors) < 0)
        return -1;
    for (size_t i = 0; i < 2; ++i) {
        if (fcntl(descriptors[i], F_SETFD, FD_CLOEXEC) < 0)
            goto failed;
        if (nonblocking) {
            int flags = fcntl(descriptors[i], F_GETFL);
            if (flags < 0 || fcntl(descriptors[i], F_SETFL, flags | O_NONBLOCK) < 0)
                goto failed;
        }
    }
    return 0;
failed: {
    int saved = errno;
    (void)close(descriptors[0]);
    (void)close(descriptors[1]);
    errno = saved;
    return -1;
    }
#endif
}

static unsigned int copy_descriptors(sparc64_space_t *space, uint64_t address,
                                     const unsigned char encoded[8])
{
    /* Linux copy_to_user checks the whole numeric range before a partial
     * mapped-page copy. A later page fault may leave a prefix of the pair. */
    if (address >= space->limit || UINT64_C(8) > space->limit - address)
        return 14;
    size_t prefix = 0;
    while (prefix < 8) {
        size_t amount = (size_t)(SPARC64_PAGE_SIZE - (address + prefix) % SPARC64_PAGE_SIZE);
        if (amount > 8 - prefix)
            amount = 8 - prefix;
        if (!sparc64_space_prepare_write(space, address + prefix, amount)) {
            if (sparc64_fault_is_runtime(space->fault_reason))
                return 12;
            break;
        }
        prefix += amount;
    }
    if (prefix != 0 && !sparc64_space_write(space, address, encoded, prefix))
        return sparc64_fault_is_runtime(space->fault_reason) ? 12 : 14;
    return prefix == 8 ? 0 : 14;
}

static uint64_t create_pipe(sparc64_linux_file_t *files, const uint64_t args[6])
{
    /* pipe2 takes int flags: high register bits are discarded. */
    uint32_t flags = (uint32_t)args[1];
    const uint32_t ordinary = G_O_NONBLOCK | G_O_CLOEXEC;
    const uint32_t other_modes = G_O_DIRECT | G_O_NOTIFICATION_PIPE;
    if ((flags & ~(ordinary | other_modes)) != 0)
        return failure(22);
    if ((flags & other_modes) != 0)
        return failure(95); /* Packet and notification pipes are not supported. */
    int read_guest = sparc64_fd_reserve(&files->descriptors);
    if (read_guest < 0)
        return failure(sparc64_linux_errno(errno));
    int write_guest = sparc64_fd_reserve(&files->descriptors);
    if (write_guest < 0) {
        int saved = errno;
        (void)sparc64_fd_cancel(&files->descriptors, (unsigned int)read_guest);
        return failure(sparc64_linux_errno(saved));
    }
    int descriptors[2];
    if (native_pipe(descriptors, (flags & G_O_NONBLOCK) != 0) < 0) {
        int saved = errno;
        (void)sparc64_fd_cancel(&files->descriptors, (unsigned int)read_guest);
        (void)sparc64_fd_cancel(&files->descriptors, (unsigned int)write_guest);
        return failure(sparc64_linux_errno(saved));
    }
    unsigned char encoded[8];
    for (unsigned int i = 0; i < 4; ++i) {
        encoded[i] = (unsigned char)((uint32_t)read_guest >> (i * 8));
        encoded[i + 4] = (unsigned char)((uint32_t)write_guest >> (i * 8));
    }
    unsigned int error = copy_descriptors(files->space, args[0], encoded);
    if (error != 0) {
        (void)close(descriptors[0]);
        (void)close(descriptors[1]);
        (void)sparc64_fd_cancel(&files->descriptors, (unsigned int)read_guest);
        (void)sparc64_fd_cancel(&files->descriptors, (unsigned int)write_guest);
        return failure(error);
    }
    bool cloexec = (flags & G_O_CLOEXEC) != 0;
    if (sparc64_fd_commit_pipe_reader(&files->descriptors, (unsigned int)read_guest,
                                 descriptors[0], cloexec) < 0) {
        int saved = errno;
        (void)close(descriptors[1]);
        (void)sparc64_fd_cancel(&files->descriptors, (unsigned int)write_guest);
        return failure(sparc64_linux_errno(saved));
    }
    if (sparc64_fd_commit_pipe_writer(&files->descriptors, (unsigned int)write_guest,
                                 descriptors[1], cloexec) < 0) {
        int saved = errno;
        (void)sparc64_fd_close(&files->descriptors, (unsigned int)read_guest);
        return failure(sparc64_linux_errno(saved));
    }
    return 0;
}

static uint64_t bytes_available(sparc64_linux_file_t *files, const uint64_t args[6])
{
    int lease = sparc64_fd_acquire(&files->descriptors, (uint32_t)args[0]);
    if (lease < 0)
        return failure(sparc64_linux_errno(errno));
    int available = 0;
    int queried = ioctl(lease, FIONREAD, &available);
    int saved = errno;
    uint64_t result;
    if (queried < 0)
        result = failure(sparc64_linux_errno(saved));
    else if (available < 0)
        result = failure(5);
    else {
        unsigned char encoded[4];
        for (unsigned int i = 0; i < sizeof(encoded); ++i)
            encoded[i] = (unsigned char)((uint32_t)available >> (i * 8));
        result = sparc64_space_write(files->space, args[2], encoded, sizeof(encoded)) ?
                 0 : failure(sparc64_fault_is_runtime(files->space->fault_reason) ? 12 : 14);
    }
    (void)sparc64_fd_release(lease);
    return result;
}

bool sparc64_linux_pipe_dispatch(sparc64_linux_file_t *files, uint64_t number,
                            const uint64_t arguments[6], uint64_t *result)
{
    if (files == NULL || arguments == NULL || result == NULL)
        return false;
    if (number == 59) {
        *result = create_pipe(files, arguments);
        return true;
    }
    /* An owned pipe FIONREAD is a nonblocking metadata snapshot. Other ioctls
     * and descriptor classes retain the general file dispatch contract. */
    if (number == 29 && (uint32_t)arguments[1] == UINT32_C(0x541b) &&
        (sparc64_fd_is_pipe_endpoint(&files->descriptors, (uint32_t)arguments[0]) == 1 ||
         sparc64_fd_is_managed_fifo_endpoint(&files->descriptors,
                                        (uint32_t)arguments[0]) == 1)) {
        *result = bytes_available(files, arguments);
        return true;
    }
    return false;
}
