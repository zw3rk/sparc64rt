/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#define _GNU_SOURCE 1
#include "runtime/vfork_completion.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <unistd.h>

static int private_fd(int owned)
{
    int normalized = fcntl(owned, F_DUPFD_CLOEXEC, 3);
    int saved = errno;
    (void)close(owned);
    errno = saved;
    return normalized;
}

int sparc64_vfork_completion_pair(int *out_reader, int *out_writer)
{
    if (out_reader == NULL || out_writer == NULL || out_reader == out_writer ||
        *out_reader != -1 || *out_writer != -1) {
        errno = EINVAL;
        return -1;
    }
    int pair[2];
#ifdef __linux__
    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC,
                   0, pair) != 0)
        return -1;
#else
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, pair) != 0)
        return -1;
#endif
    int reader = private_fd(pair[0]);
    if (reader < 0) {
        int saved = errno;
        (void)close(pair[1]);
        errno = saved;
        return -1;
    }
    int writer = private_fd(pair[1]);
    if (writer < 0) {
        int saved = errno;
        (void)close(reader);
        errno = saved;
        return -1;
    }
#ifndef __linux__
    int read_flags = fcntl(reader, F_GETFL);
    int write_flags = fcntl(writer, F_GETFL);
    if (read_flags < 0 || write_flags < 0 ||
        fcntl(reader, F_SETFL, read_flags | O_NONBLOCK) != 0 ||
        fcntl(writer, F_SETFL, write_flags | O_NONBLOCK) != 0 ||
        setsockopt(writer, SOL_SOCKET, SO_NOSIGPIPE,
                   &(int){1}, sizeof(int)) != 0) {
        int saved = errno;
        (void)close(reader);
        (void)close(writer);
        errno = saved;
        return -1;
    }
#endif
    *out_reader = reader;
    *out_writer = writer;
    return 0;
}

int sparc64_vfork_completion_wait_service(int reader, bool wait_exec, bool *completed,
                                     sparc64_vfork_wait_service_fn service,
                                     void *context)
{
    if (reader < 3 || completed == NULL) {
        errno = EINVAL;
        return -1;
    }
    bool joined = false;
    for (;;) {
        if (service != NULL) {
            int serviced = service(context);
            if (serviced < 0)
                return -1;
            if (serviced > 0) {
                *completed = false;
                return 0;
            }
        }
        unsigned char byte;
        ssize_t received = recv(reader, &byte, 1, MSG_DONTWAIT);
        if (received == 1) {
            if (!joined && byte == 'J') {
                joined = true;
                if (!wait_exec) {
                    *completed = true;
                    return 0;
                }
                continue;
            }
            if (!joined || byte != 'E' || !wait_exec) {
                errno = EPROTO;
                return -1;
            }
            *completed = true;
            return 0;
        }
        if (received == 0) {
            *completed = false;
            return 0;
        }
        if (errno == EINTR)
            continue;
        if (errno != EAGAIN && errno != EWOULDBLOCK)
            return -1;
        struct pollfd ready = {.fd = reader, .events = POLLIN | POLLHUP};
        /* The native stop carrier can remain blocked after fork's native
         * phase. A service-enabled waiter therefore checks scheduler hooks
         * at a bounded cadence; this is not a child-completion deadline. */
        int observed = poll(&ready, 1, service != NULL ? 20 : -1);
        if (observed < 0 && errno == EINTR)
            continue;
        if (observed < 0)
            return -1;
        if ((ready.revents & POLLNVAL) != 0) {
            errno = EBADF;
            return -1;
        }
    }
}

int sparc64_vfork_completion_wait(int reader, bool wait_exec, bool *completed)
{
    return sparc64_vfork_completion_wait_service(reader, wait_exec, completed,
                                             NULL, NULL);
}

int sparc64_vfork_completion_adopt(int writer)
{
    struct stat status;
    int kind = 0;
    socklen_t length = sizeof(kind);
    if (writer < 3) {
        errno = EINVAL;
        return -1;
    }
    int access = fcntl(writer, F_GETFL);
    if (access < 0 || fstat(writer, &status) != 0 ||
        getsockopt(writer, SOL_SOCKET, SO_TYPE, &kind, &length) != 0)
        return -1;
    if ((access & O_NONBLOCK) == 0 || !S_ISSOCK(status.st_mode) ||
        length != sizeof(kind) || kind != SOCK_STREAM) {
        errno = EINVAL;
        return -1;
    }
    return fcntl(writer, F_SETFD, FD_CLOEXEC);
}

int sparc64_vfork_completion_signal(int writer)
{
    if (writer < 3) {
        errno = EINVAL;
        return -1;
    }
    static const unsigned char complete = 'E';
    ssize_t sent;
    do {
#ifdef __linux__
        sent = send(writer, &complete, 1, MSG_DONTWAIT | MSG_NOSIGNAL);
#else
        sent = send(writer, &complete, 1, MSG_DONTWAIT);
#endif
    } while (sent < 0 && errno == EINTR);
    if (sent == 1 || (sent < 0 && errno == EPIPE))
        return 0;
    if (sent == 0)
        errno = EIO;
    return -1;
}

int sparc64_vfork_completion_join(int writer)
{
    if (writer < 3) {
        errno = EINVAL;
        return -1;
    }
    static const unsigned char joined = 'J';
    ssize_t sent;
    do {
#ifdef __linux__
        sent = send(writer, &joined, 1, MSG_DONTWAIT | MSG_NOSIGNAL);
#else
        sent = send(writer, &joined, 1, MSG_DONTWAIT);
#endif
    } while (sent < 0 && errno == EINTR);
    if (sent == 1 || (sent < 0 && errno == EPIPE))
        return 0;
    if (sent == 0)
        errno = EIO;
    return -1;
}
