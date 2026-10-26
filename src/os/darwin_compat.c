/*
 * src/os/darwin_compat.c -- macOS portability shims (Lane S1)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Implements the helpers declared in os/darwin_compat.h. Linux builds
 * keep their native calls (this TU compiles to nothing there); the
 * Darwin standalone link routes the Linux-only pipe2(2) use through
 * rt_darwin_pipe2. No guest behavior changes: same fds, same flags,
 * same -EINVAL domain as the native call.
 */

#include "os/darwin_compat.h"

#if defined(__APPLE__)

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

int rt_darwin_pipe2(int fds[2], int flags)
{
    if (fds == NULL) {
        return -EINVAL;
    }
    if ((flags & ~(O_CLOEXEC | O_NONBLOCK)) != 0) {
        return -EINVAL;
    }
    if (pipe(fds) != 0) {
        return -errno;
    }
    if ((flags & O_CLOEXEC) != 0) {
        (void)fcntl(fds[0], F_SETFD, FD_CLOEXEC);
        (void)fcntl(fds[1], F_SETFD, FD_CLOEXEC);
    }
    if ((flags & O_NONBLOCK) != 0) {
        (void)fcntl(fds[0], F_SETFL, O_NONBLOCK);
        (void)fcntl(fds[1], F_SETFL, O_NONBLOCK);
    }
    return 0;
}

#else /* not macOS: no symbols, keeps -pedantic quiet */

typedef int rt_darwin_compat_unused_t;

#endif /* defined(__APPLE__) */
