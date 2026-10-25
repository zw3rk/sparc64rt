/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#define _GNU_SOURCE 1
#define _DARWIN_C_SOURCE 1
#define _POSIX_C_SOURCE 200809L
#include "runtime/inode_pins.h"

#include <errno.h>
#include <fcntl.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

#ifdef SPARC64_INODE_PINS_TESTING
/* Tests install only while single-threaded and before native fork. */
static sparc64_inode_pins_test_hook_t test_hook;
static void *test_context;
void sparc64_inode_pins_test_set_hook(sparc64_inode_pins_test_hook_t hook, void *context)
{
    test_hook = hook;
    test_context = context;
}
#define TEST_POINT(point) do { if (test_hook != NULL) \
    test_hook((point), test_context); } while (0)
#else
#define TEST_POINT(point) ((void)0)
#endif

static bool empty(const sparc64_inode_pins_t *pins)
{
    return pins != NULL && pins->sender == -1 && pins->receiver == -1;
}

static void close_pair(int sender, int receiver)
{
    if (sender >= 0)
        (void)close(sender);
    if (receiver >= 0 && receiver != sender)
        (void)close(receiver);
}

static int normalize(int *fd)
{
    if (*fd < 3) {
        int replacement = fcntl(*fd, F_DUPFD_CLOEXEC, 3);
        if (replacement < 0)
            return -1;
        (void)close(*fd);
        *fd = replacement;
        return 0;
    }
    int flags = fcntl(*fd, F_GETFD);
    return flags < 0 ? -1 : fcntl(*fd, F_SETFD, flags | FD_CLOEXEC);
}

static bool datagram_socket(int fd)
{
    int type = 0;
    socklen_t length = sizeof(type);
    struct sockaddr_storage address;
    socklen_t address_length = sizeof(address);
    return getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &length) == 0 &&
           length == sizeof(type) && type == SOCK_DGRAM &&
           getpeername(fd, (struct sockaddr *)&address, &address_length) == 0 &&
           address_length >= offsetof(struct sockaddr, sa_data) &&
           address.ss_family == AF_UNIX;
}

int sparc64_inode_pins_adopt(sparc64_inode_pins_t *out, int sender, int receiver)
{
    int error = EINVAL;
    if (!empty(out) || sender < 0 || receiver < 0 || sender == receiver)
        goto failed;
    if (!datagram_socket(sender) || !datagram_socket(receiver)) {
        error = EPROTOTYPE;
        goto failed;
    }
    if (normalize(&sender) != 0 || normalize(&receiver) != 0) {
        error = errno;
        goto failed;
    }
#ifdef SO_NOSIGPIPE
    int enabled = 1;
    if (setsockopt(sender, SOL_SOCKET, SO_NOSIGPIPE, &enabled, sizeof(enabled)) != 0) {
        error = errno;
        goto failed;
    }
#endif
    *out = (sparc64_inode_pins_t){.sender = sender, .receiver = receiver};
    return 0;

failed:
    close_pair(sender, receiver);
    errno = error;
    return -1;
}

int sparc64_inode_pins_create(sparc64_inode_pins_t *out)
{
    if (!empty(out)) {
        errno = EINVAL;
        return -1;
    }
    int pair[2];
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, pair) != 0)
        return -1;
    return sparc64_inode_pins_adopt(out, pair[0], pair[1]);
}

void sparc64_inode_pins_close(sparc64_inode_pins_t *pins)
{
    if (pins == NULL)
        return;
    int error = errno;
    close_pair(pins->sender, pins->receiver);
    *pins = (sparc64_inode_pins_t)SPARC64_INODE_PINS_INITIALIZER;
    errno = error;
}

int sparc64_inode_pins_keep(const sparc64_inode_pins_t *pins, int source_fd,
                       uint64_t *attempts)
{
    if (pins == NULL || pins->sender < 3 || pins->receiver < 3 ||
        pins->sender == pins->receiver || attempts == NULL || source_fd < 0) {
        errno = EINVAL;
        return -1;
    }
    struct stat status;
    if (fstat(source_fd, &status) != 0)
        return -1;
    if (!S_ISREG(status.st_mode)) {
        errno = EINVAL;
        return -1;
    }
    if (*attempts >= SPARC64_INODE_PINS_MAX_ATTEMPTS) {
        errno = ENOSPC;
        return -1;
    }
    /* The family guard provides exclusion; publish the nonrefundable charge
     * before a kernel reference can outlive this producer. */
    ++*attempts;
    atomic_thread_fence(memory_order_release);
    TEST_POINT(SPARC64_INODE_PINS_CHARGED);
    unsigned char byte = 0;
    struct iovec vector = {.iov_base = &byte, .iov_len = 1};
    union {
        struct cmsghdr alignment;
        unsigned char bytes[CMSG_SPACE(sizeof(int))];
    } ancillary;
    memset(&ancillary, 0, sizeof(ancillary));
    struct msghdr message = {.msg_iov = &vector, .msg_iovlen = 1,
        .msg_control = ancillary.bytes, .msg_controllen = sizeof(ancillary.bytes)};
    struct cmsghdr *header = CMSG_FIRSTHDR(&message);
    if (header == NULL) {
        errno = EIO;
        return -1;
    }
    header->cmsg_level = SOL_SOCKET;
    header->cmsg_type = SCM_RIGHTS;
    header->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(header), &source_fd, sizeof(source_fd));
    ssize_t amount = sendmsg(pins->sender, &message, MSG_DONTWAIT | MSG_NOSIGNAL);
    if (amount != 1) {
        if (amount >= 0)
            errno = EIO;
        return -1;
    }
    TEST_POINT(SPARC64_INODE_PINS_ENQUEUED);
    return 0;
}
