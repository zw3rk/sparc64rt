/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#define _POSIX_C_SOURCE 200809L
#include "linux/fd_handoff.h"
#include "linux/fd_snapshot_internal.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define HANDOFF_HEADER 40u
#define HANDOFF_RECORD 16u
#define HANDOFF_MAX (HANDOFF_HEADER + 2u * SPARC64_FD_TABLE_LIMIT * HANDOFF_RECORD)

struct sparc64_fd_handoff {
    sparc64_fd_snapshot_t *snapshot;
    sparc64_path_registration_t *registration;
    int metadata;
    int old_flags[SPARC64_FD_TABLE_LIMIT + 1u];
    size_t changed;
    bool active, poisoned;
};

static uint32_t get32(const unsigned char *p)
{
    uint32_t value = 0;
    for (unsigned int i = 0; i < 4; ++i)
        value |= (uint32_t)p[i] << (8u * i);
    return value;
}

static uint64_t get64(const unsigned char *p)
{
    uint64_t value = 0;
    for (unsigned int i = 0; i < 8; ++i)
        value |= (uint64_t)p[i] << (8u * i);
    return value;
}

static void put32(unsigned char *p, uint32_t value)
{
    for (unsigned int i = 0; i < 4; ++i)
        p[i] = (unsigned char)(value >> (8u * i));
}

static void put64(unsigned char *p, uint64_t value)
{
    for (unsigned int i = 0; i < 8; ++i)
        p[i] = (unsigned char)(value >> (8u * i));
}

static void filter_cloexec(sparc64_fd_snapshot_t *snapshot)
{
    uint32_t remap[SPARC64_FD_TABLE_LIMIT];
    for (size_t i = 0; i < SPARC64_FD_TABLE_LIMIT; ++i)
        remap[i] = UINT32_MAX;
    uint32_t entries = 0;
    for (uint32_t i = 0; i < snapshot->entry_count; ++i) {
        sparc64_fd_snapshot_entry_t entry = snapshot->entries[i];
        if (entry.guest_cloexec != 0)
            continue;
        snapshot->entries[entries++] = entry;
        remap[entry.description_index] = 0;
    }
    uint32_t descriptions = 0;
    for (uint32_t i = 0; i < snapshot->description_count; ++i) {
        if (remap[i] == UINT32_MAX) {
            (void)close(snapshot->leases[i]);
        } else {
            remap[i] = descriptions;
            snapshot->descriptions[descriptions] = snapshot->descriptions[i];
            snapshot->leases[descriptions++] = snapshot->leases[i];
        }
    }
    for (uint32_t i = 0; i < entries; ++i)
        snapshot->entries[i].description_index =
            remap[snapshot->entries[i].description_index];
    snapshot->entry_count = entries;
    snapshot->description_count = descriptions;
}

static unsigned char *encode(const sparc64_fd_snapshot_t *snapshot, size_t *length)
{
    *length = HANDOFF_HEADER + HANDOFF_RECORD *
              (size_t)(snapshot->entry_count + snapshot->description_count);
    unsigned char *data = calloc(1, *length);
    if (data == NULL)
        return NULL;
    memcpy(data, "RVFDEX01", 8);
    put32(data + 8, 1);
    put32(data + 12, HANDOFF_HEADER);
    put32(data + 16, (uint32_t)*length);
    put32(data + 20, snapshot->entry_count);
    put32(data + 24, snapshot->description_count);
    put64(data + 32, snapshot->next_description_id);
    unsigned char *p = data + HANDOFF_HEADER;
    for (uint32_t i = 0; i < snapshot->entry_count; ++i, p += HANDOFF_RECORD) {
        const sparc64_fd_snapshot_entry_t *entry = &snapshot->entries[i];
        put32(p, entry->guest_fd);
        put32(p + 4, entry->description_index);
        put32(p + 8, entry->hidden_status_flags);
        p[12] = entry->guest_cloexec;
    }
    for (uint32_t i = 0; i < snapshot->description_count; ++i, p += HANDOFF_RECORD) {
        const sparc64_fd_snapshot_description_t *description = &snapshot->descriptions[i];
        put64(p, description->id);
        p[8] = description->logical_read_only;
        p[9] = description->pipe_writer;
        p[10] = description->pipe_endpoint;
        p[11] = description->fifo_writer;
        p[12] = description->fifo_endpoint;
    }
    return data;
}

static bool private_metadata(int fd, struct stat *status)
{
    return fd >= 3 && fstat(fd, status) == 0 && S_ISREG(status->st_mode) &&
           status->st_uid == geteuid() && status->st_nlink == 0 &&
           (status->st_mode & 07777) == 0600;
}

int sparc64_fd_handoff_create(sparc64_fd_table_t *table, sparc64_path_resolver_t *resolver,
                          sparc64_fd_handoff_t **out)
{
    if (out == NULL) {
        errno = EINVAL;
        return -1;
    }
    *out = NULL;
    if (resolver == NULL || !resolver->initialized) {
        errno = EINVAL;
        return -1;
    }
    sparc64_fd_handoff_t *owner = calloc(1, sizeof(*owner));
    if (owner == NULL)
        return -1;
    owner->metadata = -1;
    if (sparc64_fd_snapshot_create(table, &owner->snapshot) != 0)
        goto fail;
    filter_cloexec(owner->snapshot);
    char path[] = "/tmp/sparc64rt-fd-handoff-XXXXXX";
    int fd = mkstemp(path);
    if (fd < 0)
        goto fail;
    int saved = errno;
    int unlinked = unlink(path);
    if (unlinked != 0) {
        saved = errno;
        (void)close(fd);
        errno = saved;
        goto fail;
    }
    owner->metadata = fcntl(fd, F_DUPFD_CLOEXEC, 3);
    saved = errno;
    (void)close(fd);
    errno = saved;
    if (owner->metadata < 0)
        goto fail;
    if (fchmod(owner->metadata, 0600) != 0)
        goto fail;
    struct stat status;
    if (!private_metadata(owner->metadata, &status)) {
        errno = EINVAL;
        goto fail;
    }
    if (sparc64_path_protect_temporary(resolver, status.st_dev, status.st_ino,
                                  &owner->registration) != 0)
        goto fail;
    size_t length;
    unsigned char *data = encode(owner->snapshot, &length);
    if (data == NULL)
        goto fail;
    size_t done = 0;
    while (done < length) {
        ssize_t count = write(owner->metadata, data + done, length - done);
        if (count < 0 && errno == EINTR)
            continue;
        if (count <= 0) {
            saved = count == 0 ? EIO : errno;
            free(data);
            errno = saved;
            goto fail;
        }
        done += (size_t)count;
    }
    free(data);
    *out = owner;
    return 0;
fail: {
        int failure = errno;
        sparc64_fd_handoff_destroy(&owner);
        errno = failure;
        return -1;
    }
}

int sparc64_fd_handoff_metadata(const sparc64_fd_handoff_t *handoff)
{
    return handoff == NULL ? -1 : handoff->metadata;
}

size_t sparc64_fd_handoff_descriptors(const sparc64_fd_handoff_t *handoff,
                                 int output[SPARC64_FD_TABLE_LIMIT])
{
    if (handoff == NULL || output == NULL)
        return 0;
    size_t count = handoff->snapshot->description_count;
    for (size_t i = 0; i < count; ++i)
        output[i] = handoff->snapshot->leases[i];
    return count;
}

static int native_descriptor(const sparc64_fd_handoff_t *handoff, size_t index)
{
    return index == handoff->snapshot->description_count ? handoff->metadata :
           handoff->snapshot->leases[index];
}

int sparc64_fd_handoff_deactivate(sparc64_fd_handoff_t *handoff)
{
    if (handoff == NULL || handoff->poisoned) {
        errno = EIO;
        return -1;
    }
    int failure = 0;
    for (size_t i = 0; i < handoff->changed; ++i)
        if (fcntl(native_descriptor(handoff, i), F_SETFD,
                   handoff->old_flags[i]) < 0 && failure == 0)
            failure = errno;
    if (failure != 0) {
        handoff->poisoned = true;
        errno = failure;
        return -1;
    }
    handoff->changed = 0;
    handoff->active = false;
    return 0;
}

int sparc64_fd_handoff_activate(sparc64_fd_handoff_t *handoff)
{
    if (handoff == NULL || handoff->poisoned || handoff->active) {
        errno = handoff != NULL && handoff->active ? EALREADY : EINVAL;
        return -1;
    }
    size_t count = handoff->snapshot->description_count + 1u;
    for (size_t i = 0; i < count; ++i) {
        int fd = native_descriptor(handoff, i);
        int flags = fcntl(fd, F_GETFD);
        if (flags < 0 || fcntl(fd, F_SETFD, flags & ~FD_CLOEXEC) < 0) {
            int failure = errno;
            if (sparc64_fd_handoff_deactivate(handoff) == 0)
                errno = failure;
            return -1;
        }
        handoff->old_flags[i] = flags;
        ++handoff->changed;
    }
    handoff->active = true;
    return 0;
}

void sparc64_fd_handoff_destroy(sparc64_fd_handoff_t **handoff)
{
    if (handoff == NULL || *handoff == NULL)
        return;
    int saved = errno;
    sparc64_fd_handoff_t *owner = *handoff;
    sparc64_fd_snapshot_destroy(owner->snapshot);
    sparc64_path_retire_temporary(&owner->registration);
    if (owner->metadata >= 3)
        (void)close(owner->metadata);
    free(owner);
    *handoff = NULL;
    errno = saved;
}

static void close_received(int metadata, int *fds, size_t count)
{
    for (size_t i = 0; i < count; ++i) {
        bool duplicate = fds[i] == metadata;
        for (size_t j = 0; j < i; ++j)
            if (fds[j] == fds[i])
                duplicate = true;
        if (!duplicate && fds[i] >= 3)
            (void)close(fds[i]);
    }
    if (metadata >= 3)
        (void)close(metadata);
    for (size_t i = 0; i < count; ++i)
        fds[i] = -1;
}

static int decode(const unsigned char *data, size_t length, int *fds,
                   size_t count, sparc64_fd_table_t *destination)
{
    if (length < HANDOFF_HEADER || memcmp(data, "RVFDEX01", 8) != 0 ||
        get32(data + 8) != 1 || get32(data + 12) != HANDOFF_HEADER ||
        get32(data + 16) != length || get32(data + 28) != 0) {
        errno = EINVAL;
        return -1;
    }
    uint32_t entries = get32(data + 20), descriptions = get32(data + 24);
    if (entries > SPARC64_FD_TABLE_LIMIT || descriptions > entries ||
        descriptions != count || length != HANDOFF_HEADER +
        HANDOFF_RECORD * (size_t)(entries + descriptions)) {
        errno = EINVAL;
        return -1;
    }
    sparc64_fd_snapshot_t snapshot = {
        .version = SPARC64_FD_SNAPSHOT_VERSION, .entry_count = entries,
        .description_count = descriptions,
        .next_description_id = get64(data + 32), .leases = fds
    };
    snapshot.entries = calloc(entries == 0 ? 1 : entries, sizeof(*snapshot.entries));
    snapshot.descriptions = calloc(descriptions == 0 ? 1 : descriptions,
                                    sizeof(*snapshot.descriptions));
    if (snapshot.entries == NULL || snapshot.descriptions == NULL) {
        int failure = errno;
        free(snapshot.entries);
        free(snapshot.descriptions);
        errno = failure;
        return -1;
    }
    const unsigned char *p = data + HANDOFF_HEADER;
    bool invalid = false;
    for (uint32_t i = 0; i < entries; ++i, p += HANDOFF_RECORD) {
        snapshot.entries[i] = (sparc64_fd_snapshot_entry_t){
            .guest_fd = get32(p), .description_index = get32(p + 4),
            .hidden_status_flags = get32(p + 8), .guest_cloexec = p[12],
            .reserved = {p[13], p[14], p[15]}
        };
        if (p[12] != 0) /* Exec cannot retain a guest CLOEXEC entry. */
            invalid = true;
    }
    for (uint32_t i = 0; i < descriptions; ++i, p += HANDOFF_RECORD)
        snapshot.descriptions[i] = (sparc64_fd_snapshot_description_t){
            .id = get64(p), .logical_read_only = p[8], .pipe_writer = p[9],
            .pipe_endpoint = p[10], .fifo_writer = p[11], .fifo_endpoint = p[12],
            .reserved = {p[13], p[14], p[15]}
        };
    int result = -1;
    if (invalid)
        errno = EINVAL;
    else
        result = sparc64_fd_snapshot_restore(&snapshot, destination);
    int failure = errno;
    free(snapshot.entries);
    free(snapshot.descriptions);
    errno = failure;
    return result;
}

int sparc64_fd_handoff_receive(int owned_metadata, int *owned_descriptors,
                           size_t count, sparc64_fd_table_t *destination)
{
    if (count > SPARC64_FD_TABLE_LIMIT || (count != 0 && owned_descriptors == NULL)) {
        errno = EINVAL;
        return -1;
    }
    int failure = EINVAL, result = -1;
    unsigned char *data = NULL;
    if (destination == NULL || destination->initialized || owned_metadata < 3)
        goto done;
    for (size_t i = 0; i < count; ++i) {
        if (owned_descriptors[i] < 3 || owned_descriptors[i] == owned_metadata)
            goto done;
        for (size_t j = 0; j < i; ++j)
            if (owned_descriptors[j] == owned_descriptors[i])
                goto done;
    }
    for (size_t i = 0; i <= count; ++i) {
        int fd = i == count ? owned_metadata : owned_descriptors[i];
        int flags = fcntl(fd, F_GETFD);
        if (flags < 0 || fcntl(fd, F_SETFD, flags | FD_CLOEXEC) < 0) {
            failure = errno;
            goto done;
        }
    }
    struct stat status;
    if (!private_metadata(owned_metadata, &status) ||
        status.st_size < HANDOFF_HEADER || status.st_size > HANDOFF_MAX)
        goto done;
    for (size_t i = 0; i < count; ++i) {
        struct stat descriptor_status;
        if (fstat(owned_descriptors[i], &descriptor_status) != 0) {
            failure = errno;
            goto done;
        }
        if (descriptor_status.st_dev == status.st_dev &&
            descriptor_status.st_ino == status.st_ino)
            goto done; /* Metadata aliases must never become guest files. */
    }
    size_t length = (size_t)status.st_size;
    data = malloc(length);
    if (data == NULL) {
        failure = errno;
        goto done;
    }
    size_t offset = 0;
    while (offset < length) {
        ssize_t got = pread(owned_metadata, data + offset, length - offset,
                             (off_t)offset);
        if (got < 0 && errno == EINTR)
            continue;
        if (got <= 0) {
            failure = got == 0 ? EINVAL : errno;
            goto done;
        }
        offset += (size_t)got;
    }
    result = decode(data, length, owned_descriptors, count, destination);
    failure = errno;
done:
    free(data);
    close_received(owned_metadata, owned_descriptors, count);
    errno = failure;
    return result;
}
