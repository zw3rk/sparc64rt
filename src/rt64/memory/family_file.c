/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#define _GNU_SOURCE 1
#define _POSIX_C_SOURCE 200809L
#include "memory/family_file.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

_Static_assert(sizeof(off_t) == 8, "managed file refresh requires 64-bit offsets");

typedef struct {
    sparc64_file_source_t source;
    sparc64_family_backing_t *backing;
    uint64_t source_id;
    size_t references;
    int fd;
} family_file_t;

static family_file_t *file_object(sparc64_file_source_t *source)
{
    return (family_file_t *)source;
}

static void retain(sparc64_file_source_t *source)
{
    family_file_t *file = file_object(source);
    if (file->references == SIZE_MAX)
        abort();
    ++file->references;
}

static void release(sparc64_file_source_t *source)
{
    family_file_t *file = file_object(source);
    assert(file->references != 0);
    if (--file->references == 0) {
        (void)close(file->fd);
        free(file);
    }
}

static bool failed(sparc64_space_t *space, uint64_t address, sparc64_fault_reason_t reason)
{
    space->fault_address = address;
    space->fault_reason = reason;
    if (reason == SPARC64_FAULT_INTERNAL)
        space->internal_failure = true;
    return false;
}

static bool has_notifications(const sparc64_family_page_state_t *state)
{
    static const uint64_t zero[4] = {0};
    return memcmp(state->notified, zero, sizeof(zero)) != 0;
}

static bool file_state(const sparc64_family_page_state_t *state)
{
    return state->private_cow <= 1 && state->reserved == 0 &&
           (state->private_cow == 0 || !has_notifications(state));
}

static bool file_size(int fd, uint64_t *size)
{
    struct stat status;
    int result;
    do {
        result = fstat(fd, &status);
    } while (result < 0 && errno == EINTR);
    if (result < 0)
        return false;
    if (!S_ISREG(status.st_mode) || status.st_size < 0) {
        errno = ENODEV;
        return false;
    }
    *size = (uint64_t)status.st_size;
    return true;
}

static bool beyond_eof(uint64_t offset, uint64_t size)
{
    /* No ceil(size/page) overflow, including size0. */
    return offset >= size &&
           (size % SPARC64_PAGE_SIZE == 0 || offset > size - size % SPARC64_PAGE_SIZE);
}

static bool refresh(sparc64_file_source_t *source, sparc64_backing_t *view, uint64_t address)
{
    family_file_t *file = file_object(source);
    sparc64_space_t *space = source->space;
    sparc64_family_page_state_t target;
    if (view->file != source || view->bus_fault ||
        sparc64_family_backing_snapshot(file->backing, view->payload, &target) != 0 ||
        !file_state(&target))
        return failed(space, address, SPARC64_FAULT_INTERNAL);
    /* Legacy file refresh/COW code must never run on this managed mirror. */
    uint64_t size;
    if (!file_size(file->fd, &size) || beyond_eof(view->file_offset, size))
        return failed(space, address, SPARC64_FAULT_BUS);
    /* These flags are local projections, never canonical authority. The
     * trusted producer has completed its native write before consumers may
     * run. Notification bits represent reservation epochs already charged by
     * that producer; a failed read must leave every canonical bit intact. */
    view->private_cow = target.private_cow != 0;
    memset(view->file_notified, 0, sizeof(view->file_notified));
    if (view->private_cow)
        return true;
    unsigned char bytes[4096] = {0};
    uint64_t available = size - view->file_offset;
    size_t wanted = available < SPARC64_PAGE_SIZE ? (size_t)available : (size_t)SPARC64_PAGE_SIZE;
    size_t received = 0;
    while (received < wanted) {
        /* An accessible offset is below nonnegative st_size (signed off_t).
         * The checked map also ensures the complete page offset cannot wrap. */
        ssize_t amount = pread(file->fd, bytes + received, wanted - received,
                               (off_t)(view->file_offset + received));
        if (amount < 0) {
            if (errno == EINTR)
                continue;
            return failed(space, address, SPARC64_FAULT_BUS);
        }
        if (amount == 0)
            break;
        received += (size_t)amount;
    }
    if (!file_size(file->fd, &size) || beyond_eof(view->file_offset, size))
        return failed(space, address, SPARC64_FAULT_BUS);
    if (size - view->file_offset < SPARC64_PAGE_SIZE)
        memset(bytes + (size_t)(size - view->file_offset), 0,
                (size_t)SPARC64_PAGE_SIZE - (size_t)(size - view->file_offset));
    bool changed = memcmp(target.bytes, bytes, sizeof(bytes)) != 0;
    if (!changed && !has_notifications(&target))
        return true;
    if (space->generation == UINT64_MAX || target.content_generation == UINT64_MAX)
        return failed(space, address, SPARC64_FAULT_INTERNAL);
    for (size_t i = 0; i < SPARC64_PAGE_GRANULES; ++i) {
        size_t offset = i * SPARC64_RESERVATION_GRANULE;
        bool notified = (target.notified[i / 64u] & (UINT64_C(1) << (i % 64u))) != 0;
        if (!notified &&
            memcmp(target.bytes + offset, bytes + offset, SPARC64_RESERVATION_GRANULE) != 0) {
            if (target.epochs[i] == UINT64_MAX)
                return failed(space, address, SPARC64_FAULT_INTERNAL);
            ++target.epochs[i];
        }
    }
    memcpy(target.bytes, bytes, sizeof(bytes));
    memset(target.notified, 0, sizeof(target.notified));
    ++target.content_generation;
    if (sparc64_family_backing_commit_file_refresh(file->backing, view->payload, &target) != 0)
        return failed(space, address, SPARC64_FAULT_INTERNAL);
    ++space->generation;
    return true;
}

bool sparc64_family_file_cow(sparc64_file_source_t *source, uint64_t address)
{
    if (source == NULL || source->retain != retain || source->release != release ||
        source->refresh != refresh || source->space == NULL) {
        errno = EINVAL;
        return false;
    }
    sparc64_space_t *space = source->space;
    uint64_t base = address & ~(SPARC64_PAGE_SIZE - 1u);
    size_t first = 0, end = space->count;
    while (first < end) {
        size_t middle = first + (end - first) / 2u;
        if (space->pages[middle].address < base)
            first = middle + 1u;
        else
            end = middle;
    }
    if (first == space->count || space->pages[first].address != base ||
        space->pages[first].backing->file != source)
        return failed(space, address, SPARC64_FAULT_UNMAPPED);
    /* Explicit one-page metadata transition for trusted native callers.
     * Ordinary managed byte stores batch their first COW with bytes/epochs
     * in the generic write transaction instead of calling this separately. */
    unsigned char ignored;
    if (!sparc64_space_read(space, address, &ignored, 1, SPARC64_MEM_WRITE))
        return false;
    sparc64_backing_t *view = space->pages[first].backing;
    family_file_t *file = file_object(source);
    sparc64_family_page_state_t target;
    if (sparc64_family_backing_snapshot(file->backing, view->payload, &target) != 0 ||
        !file_state(&target))
        return failed(space, address, SPARC64_FAULT_INTERNAL);
    if (target.private_cow != 0)
        return true;
    if (space->generation == UINT64_MAX || target.content_generation == UINT64_MAX)
        return failed(space, address, SPARC64_FAULT_INTERNAL);
    for (size_t i = 0; i < SPARC64_PAGE_GRANULES; ++i) {
        if (target.epochs[i] == UINT64_MAX)
            return failed(space, address, SPARC64_FAULT_INTERNAL);
        ++target.epochs[i];
    }
    target.private_cow = 1;
    memset(target.notified, 0, sizeof(target.notified));
    ++target.content_generation;
    if (sparc64_family_backing_commit_state(file->backing, view->payload, &target) != 0)
        return failed(space, address, SPARC64_FAULT_INTERNAL);
    view->private_cow = true;
    memset(view->file_notified, 0, sizeof(view->file_notified));
    ++space->generation;
    return true;
}

int sparc64_family_file_source_create(sparc64_file_source_t **out,
                                  sparc64_family_backing_t *backing, sparc64_space_t *space,
                                  uint64_t source_id, int owned_fd)
{
    int error = EINVAL;
    if (owned_fd < 0) {
        errno = EBADF;
        return -1;
    }
    if (out == NULL || *out != NULL || backing == NULL || space == NULL || source_id == 0 ||
        space->managed.context != backing)
        goto failed;
    uint64_t size;
    if (!file_size(owned_fd, &size)) {
        error = errno == 0 ? ENODEV : errno;
        goto failed;
    }
    int flags = fcntl(owned_fd, F_GETFL);
    if (flags < 0) {
        error = errno;
        goto failed;
    }
#ifdef O_PATH
    if ((flags & O_PATH) != 0) {
        error = EBADF;
        goto failed;
    }
#endif
    if ((flags & O_ACCMODE) == O_WRONLY) {
        error = EACCES;
        goto failed;
    }
    if (owned_fd < 3) {
        int duplicate = fcntl(owned_fd, F_DUPFD_CLOEXEC, 3);
        error = errno;
        (void)close(owned_fd);
        owned_fd = duplicate;
        if (owned_fd < 0) {
            errno = error;
            return -1;
        }
    } else if (fcntl(owned_fd, F_SETFD, FD_CLOEXEC) < 0) {
        error = errno;
        goto failed;
    }
    family_file_t *file = calloc(1, sizeof(*file));
    if (file == NULL) {
        error = ENOMEM;
        goto failed;
    }
    file->source = (sparc64_file_source_t){space, retain, release, refresh};
    file->backing = backing;
    file->source_id = source_id;
    file->references = 1;
    file->fd = owned_fd;
    *out = &file->source;
    return 0;
failed:
    (void)close(owned_fd);
    errno = error;
    return -1;
}

int sparc64_family_file_source_describe(sparc64_file_source_t *source,
                                    sparc64_family_guard_t *guard,
                                    sparc64_file_identity_policy_t policy,
                                    sparc64_family_file_description_t *out)
{
    if (source == NULL || out == NULL || source->retain != retain ||
        source->release != release || source->refresh != refresh ||
        !sparc64_file_identity_policy_valid(policy)) {
        errno = EINVAL; return -1;
    }
    family_file_t *file = file_object(source);
    if (!sparc64_family_backing_guard_matches(file->backing, guard)) {
        errno = EINVAL; return -1;
    }
    sparc64_family_file_description_t fresh = {.source_id = file->source_id};
    if (!file_size(file->fd, &fresh.size) ||
        sparc64_file_identity_query(file->fd, policy, &fresh.identity) != 0)
        return -1;
    *out = fresh;
    return 0;
}

static bool map_source(sparc64_file_source_t *source, sparc64_space_t *space,
                         bool staging, uint64_t guest_page,
                         unsigned int permissions, sparc64_family_page_key_t key,
                         uint64_t offset)
{
    if (source == NULL || source->retain != retain || source->release != release ||
        source->refresh != refresh || source->space == NULL) {
        errno = EINVAL;
        return false;
    }
    if (space == NULL || source->space->managed.context != file_object(source)->backing) {
        errno = EINVAL;
        return false;
    }
    if ((permissions & ~(unsigned int)7) != 0 ||
        offset % SPARC64_PAGE_SIZE != 0 || offset > UINT64_MAX - SPARC64_PAGE_SIZE) {
        errno = EOPNOTSUPP;
        return failed(space, guest_page, SPARC64_FAULT_RANGE);
    }
    return staging ?
        sparc64_family_backing_stage_file(file_object(source)->backing, space,
                                       guest_page, permissions, key, source, offset) :
        sparc64_family_backing_map_file(file_object(source)->backing, space,
                                    guest_page, permissions, key, source, offset);
}

bool sparc64_family_file_map(sparc64_file_source_t *source, uint64_t guest_page,
                         unsigned int permissions, sparc64_family_page_key_t key,
                         uint64_t offset)
{
    return map_source(source, source == NULL ? NULL : source->space, false,
                        guest_page, permissions, key, offset);
}

bool sparc64_family_file_stage(sparc64_file_source_t *source, sparc64_space_t *stage,
                           uint64_t guest_page, unsigned int permissions,
                           sparc64_family_page_key_t key, uint64_t offset)
{
    return map_source(source, stage, true, guest_page, permissions, key, offset);
}
