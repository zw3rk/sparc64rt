/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#include "runtime/owned_io.h"

#include <errno.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>
#ifdef SPARC64_RUNTIME_TEST_EXEC_SUSPENDED_IO
#include <fcntl.h>
#include <sys/stat.h>
#endif

struct sparc64_owned_io_flight {
    sparc64_owned_io_registry_t *registry;
    sparc64_owned_io_flight_t *next;
    int lease;
    struct pollfd *poll_descriptors;
    size_t poll_count;
    void *staging;
    sparc64_copyout_t *copyout;
    sparc64_io_copyout_t *io_copyout;
    void *mapping;
    size_t mapping_length;
};

void sparc64_owned_io_registry_init(sparc64_owned_io_registry_t *registry)
{
    if (registry != NULL)
        *registry = (sparc64_owned_io_registry_t){.creator_pid = getpid()};
}

bool sparc64_owned_io_registry_empty(const sparc64_owned_io_registry_t *registry)
{
    return registry != NULL && registry->creator_pid == getpid() &&
           registry->head == NULL;
}

#ifdef SPARC64_RUNTIME_TEST_EXEC_SUSPENDED_IO
int sparc64_owned_io_test_reads(const sparc64_owned_io_registry_t *registry,
                           uint32_t *count, sparc64_owned_io_test_read_t *first)
{
    if (registry == NULL || count == NULL || first == NULL ||
        registry->creator_pid != getpid()) {
        errno = EINVAL;
        return -1;
    }
    *count = 0;
    *first = (sparc64_owned_io_test_read_t){.lease = -1};
    for (const sparc64_owned_io_flight_t *flight = registry->head; flight != NULL;
         flight = flight->next) {
        struct stat status;
        int flags = fcntl(flight->lease, F_GETFD);
        if (flight->registry != registry || flight->lease < 3 || flags < 0 ||
            (flags & FD_CLOEXEC) == 0 || flight->staging == NULL ||
            flight->io_copyout == NULL || flight->copyout != NULL ||
            fstat(flight->lease, &status) != 0 || !S_ISFIFO(status.st_mode)) {
            errno = EIO;
            return -1;
        }
        if (*count == UINT32_MAX) {
            errno = EOVERFLOW;
            return -1;
        }
        if (*count == 0)
            *first = (sparc64_owned_io_test_read_t){
                .flight = (uintptr_t)flight, .staging = (uintptr_t)flight->staging,
                .copyout = (uintptr_t)flight->io_copyout,
                .mapping = (uintptr_t)flight->mapping,
                .mapping_length = flight->mapping_length, .lease = flight->lease,
                .device = status.st_dev, .inode = status.st_ino
            };
        ++*count;
    }
    return 0;
}
#endif

int sparc64_owned_io_begin(sparc64_owned_io_registry_t *registry, int lease,
                      void *staging, sparc64_copyout_t *copyout,
                      sparc64_io_copyout_t *io_copyout,
                      sparc64_owned_io_flight_t **out)
{
    if (out != NULL)
        *out = NULL;
    if (registry == NULL || out == NULL || lease < 3 ||
        registry->creator_pid != getpid() ||
        (copyout != NULL && io_copyout != NULL)) {
        errno = EINVAL;
        return -1;
    }
    sparc64_owned_io_flight_t *flight = calloc(1, sizeof(*flight));
    if (flight == NULL)
        return -1;
    flight->registry = registry;
    flight->lease = lease;
    flight->staging = staging;
    flight->copyout = copyout;
    flight->io_copyout = io_copyout;
    flight->next = registry->head;
    registry->head = flight;
    *out = flight;
    return 0;
}

int sparc64_owned_io_adopt_staging(sparc64_owned_io_flight_t *flight, void *staging)
{
    if (flight == NULL || staging == NULL || flight->staging != NULL ||
        flight->registry->creator_pid != getpid()) {
        errno = EINVAL;
        return -1;
    }
    flight->staging = staging;
    return 0;
}

int sparc64_owned_io_begin_poll(sparc64_owned_io_registry_t *registry,
                           struct pollfd *descriptors, size_t count,
                           void *staging, sparc64_owned_io_flight_t **out)
{
    if (out != NULL)
        *out = NULL;
    if (registry == NULL || out == NULL ||
        registry->creator_pid != getpid() ||
        (count != 0 && descriptors == NULL) ||
        (count == 0 && descriptors != NULL) ||
        count > SIZE_MAX / sizeof(*descriptors)) {
        errno = EINVAL;
        return -1;
    }
    for (size_t i = 0; i < count; ++i)
        if (descriptors[i].fd != -1 && descriptors[i].fd < 3) {
            errno = EINVAL;
            return -1;
        }
    sparc64_owned_io_flight_t *flight = calloc(1, sizeof(*flight));
    if (flight == NULL)
        return -1;
    flight->registry = registry;
    flight->lease = -1;
    flight->poll_descriptors = descriptors;
    flight->poll_count = count;
    flight->staging = staging;
    flight->next = registry->head;
    registry->head = flight;
    *out = flight;
    return 0;
}

int sparc64_owned_io_adopt_mapping(sparc64_owned_io_flight_t *flight,
                              void *mapping, size_t length)
{
    if (flight == NULL || mapping == NULL || mapping == MAP_FAILED ||
        length == 0 || flight->mapping != NULL ||
        flight->registry->creator_pid != getpid()) {
        errno = EINVAL;
        return -1;
    }
    flight->mapping = mapping;
    flight->mapping_length = length;
    return 0;
}

static void release_flight(sparc64_owned_io_flight_t *flight)
{
    sparc64_space_copyout_discard(flight->copyout);
    sparc64_space_io_copyout_discard(flight->io_copyout);
    if (flight->mapping != NULL &&
        munmap(flight->mapping, flight->mapping_length) != 0)
        _exit(125);
    free(flight->staging);
    if (flight->lease >= 0 && close(flight->lease) != 0)
        _exit(125);
    for (size_t i = 0; i < flight->poll_count; ++i)
        if (flight->poll_descriptors[i].fd >= 0 &&
            close(flight->poll_descriptors[i].fd) != 0)
            _exit(125);
    free(flight->poll_descriptors);
    free(flight);
}

void sparc64_owned_io_finish(sparc64_owned_io_flight_t **owned)
{
    if (owned == NULL || *owned == NULL)
        _exit(125);
    sparc64_owned_io_flight_t *flight = *owned;
    sparc64_owned_io_registry_t *registry = flight->registry;
    if (registry->creator_pid != getpid())
        _exit(125);
    sparc64_owned_io_flight_t **link = &registry->head;
    while (*link != NULL && *link != flight)
        link = &(*link)->next;
    if (*link != flight)
        _exit(125);
    *link = flight->next;
    *owned = NULL;
    release_flight(flight);
}

int sparc64_owned_io_abandon_child(sparc64_owned_io_registry_t *registry)
{
    if (registry == NULL || registry->creator_pid == 0 ||
        registry->creator_pid == getpid()) {
        errno = EPERM;
        return -1;
    }
    sparc64_owned_io_flight_t *flight = registry->head;
    registry->head = NULL;
    registry->creator_pid = getpid();
    while (flight != NULL) {
        sparc64_owned_io_flight_t *next = flight->next;
        release_flight(flight);
        flight = next;
    }
    return 0;
}
