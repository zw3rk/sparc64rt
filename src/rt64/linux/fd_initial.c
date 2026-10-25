/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#define _POSIX_C_SOURCE 200809L
#include "linux/fd_initial.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

int sparc64_fd_census_read(sparc64_fd_census_t *out)
{
    if (out == NULL) { errno = EINVAL; return -1; }
    for (unsigned int i = 0; i < SPARC64_FD_TABLE_LIMIT; ++i) {
        int flags;
        do { flags = fcntl((int)i, F_GETFD); }
        while (flags < 0 && errno == EINTR);
        if (flags < 0 && errno != EBADF)
            return -1;
        out->flags[i] = flags;
    }
    return 0;
}

static bool admitted(const sparc64_fd_census_t *census, unsigned int fd,
                       int image_fd, int diagnostic_fd)
{
    return census->flags[fd] >= 0 &&
           (census->flags[fd] & FD_CLOEXEC) == 0 &&
           (int)fd != image_fd && (int)fd != diagnostic_fd;
}

int sparc64_fd_initial_capture(const sparc64_fd_census_t *census, int image_fd,
                           int diagnostic_fd, sparc64_fd_initial_t **out)
{
    if (census == NULL || out == NULL || *out != NULL ||
        (image_fd >= 0 && image_fd == diagnostic_fd)) {
        errno = EINVAL;
        return -1;
    }
    *out = NULL;
    sparc64_fd_initial_t *owner = malloc(sizeof(*owner));
    if (owner == NULL)
        return -1;
    for (unsigned int i = 0; i < SPARC64_FD_TABLE_LIMIT; ++i)
        owner->descriptors[i] = -1;
    unsigned int changed_through = 3;
    /* Relocate lows first, while every admitted original still pins its own
     * number. Newly allocated caps cannot accidentally enter this census. */
    for (unsigned int i = 0; i < 3; ++i) {
        if (!admitted(census, i, image_fd, diagnostic_fd))
            continue;
        int fd = fcntl((int)i, F_DUPFD_CLOEXEC, 3);
        if (fd < 0)
            goto failed;
        owner->descriptors[i] = fd;
    }
    for (unsigned int i = 3; i < SPARC64_FD_TABLE_LIMIT; ++i) {
        if (!admitted(census, i, image_fd, diagnostic_fd))
            continue;
        if (fcntl((int)i, F_SETFD, census->flags[i] | FD_CLOEXEC) != 0)
            goto failed;
        changed_through = i + 1;
    }
    /* All fallible preparation completed. Consume exact original low caps;
     * never retry close and risk closing a subsequently reused descriptor. */
    for (unsigned int i = 0; i < 3; ++i)
        if (admitted(census, i, image_fd, diagnostic_fd) && close((int)i) != 0)
            _exit(125);
    for (unsigned int i = 3; i < SPARC64_FD_TABLE_LIMIT; ++i)
        if (admitted(census, i, image_fd, diagnostic_fd))
            owner->descriptors[i] = (int)i;
    *out = owner;
    return 0;
failed:;
    int saved = errno;
    for (unsigned int i = 3; i < changed_through; ++i)
        if (admitted(census, i, image_fd, diagnostic_fd) &&
            fcntl((int)i, F_SETFD, census->flags[i]) != 0)
            _exit(125);
    /* Only relocated low caps are owned before commit. */
    sparc64_fd_initial_destroy(&owner);
    errno = saved;
    return -1;
}

void sparc64_fd_initial_destroy(sparc64_fd_initial_t **owned)
{
    if (owned == NULL || *owned == NULL)
        return;
    int saved = errno;
    sparc64_fd_initial_t *owner = *owned;
    for (unsigned int i = 0; i < SPARC64_FD_TABLE_LIMIT; ++i)
        if (owner->descriptors[i] >= 3)
            (void)close(owner->descriptors[i]);
    free(owner);
    *owned = NULL;
    errno = saved;
}
