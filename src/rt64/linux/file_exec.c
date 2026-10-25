/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L
#define _XOPEN_SOURCE 700
#if defined(__APPLE__)
#define _DARWIN_C_SOURCE 1
#endif
#include "linux/file_exec.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int validate_fifo_identities(const sparc64_linux_fifo_identity_t *identities,
                                    size_t count)
{
    if (count > SIZE_MAX / sizeof(*identities)) {
        errno = EOVERFLOW;
        return -1;
    }
    if (count != 0 && identities == NULL) {
        errno = EINVAL;
        return -1;
    }
    for (size_t i = 0; i < count; ++i) {
        if (identities[i].inode == 0 ||
            identities[i].birth_nanoseconds >= UINT32_C(1000000000)) {
            errno = EINVAL;
            return -1;
        }
        for (size_t j = 0; j < i; ++j) {
            if (identities[i].device_major == identities[j].device_major &&
                identities[i].device_minor == identities[j].device_minor &&
                identities[i].inode == identities[j].inode &&
                identities[i].birth_seconds == identities[j].birth_seconds &&
                identities[i].birth_nanoseconds == identities[j].birth_nanoseconds) {
                errno = EINVAL;
                return -1;
            }
        }
    }
    return 0;
}

int sparc64_linux_file_exec_init(sparc64_linux_file_t *files, sparc64_space_t *space,
                            int owned_metadata, int *owned_descriptors,
                            size_t descriptor_count,
                            const sparc64_linux_fifo_identity_t *fifo_identities,
                            size_t fifo_count, const char *absolute_sysroot)
{
    if (files == NULL || space == NULL || files->descriptors.initialized ||
        descriptor_count > SPARC64_FD_TABLE_LIMIT ||
        (descriptor_count != 0 && owned_descriptors == NULL) ||
        absolute_sysroot == NULL || absolute_sysroot[0] != '/') {
        errno = EINVAL;
        return -1;
    }
    if (validate_fifo_identities(fifo_identities, fifo_count) != 0)
        return -1;

    /* No native opens are permitted before the descriptor handoff: resolver
     * setup may otherwise occupy an intentionally absent guest standard FD. */
    memset(files, 0, sizeof(*files));
    files->space = space;
    files->creator_pid = getpid();
    if (sparc64_fd_handoff_receive(owned_metadata, owned_descriptors,
                              descriptor_count, &files->descriptors) != 0)
        goto fail;

    sparc64_file_registry_init(&files->backings, space);
    files->active_backings = &files->backings;
    if (sparc64_path_resolver_init(&files->paths) != 0)
        goto fail;
    files->sysroot = realpath(absolute_sysroot, NULL);
    if (files->sysroot == NULL)
        goto fail;

    if (fifo_count != 0) {
        files->created_fifos = malloc(fifo_count * sizeof(*files->created_fifos));
        if (files->created_fifos == NULL)
            goto fail;
        memcpy(files->created_fifos, fifo_identities,
               fifo_count * sizeof(*files->created_fifos));
        files->created_fifo_count = fifo_count;
        files->created_fifo_capacity = fifo_count;
    }
    return 0;

fail: {
        int saved = errno;
        sparc64_linux_file_destroy(files);
        errno = saved;
        return -1;
    }
}
