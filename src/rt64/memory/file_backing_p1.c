/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#include "file_backing_split.h"


static bool observe_mutation(sparc64_file_mutation_t *mutation);

sparc64_file_source_t *sparc64_file_source_acquire(sparc64_file_registry_t *registry, int owned_fd)
{
    return acquire(registry, owned_fd, NULL);
}

void sparc64_file_source_prepared_discard(sparc64_file_prepared_t **prepared)
{
    if (prepared == NULL || *prepared == NULL)
        return;
    int saved = errno;
    (void)close((*prepared)->file.fd);
    free(*prepared);
    *prepared = NULL;
    errno = saved;
}

int sparc64_file_source_prepare(int owned_fd, sparc64_file_identity_policy_t policy,
                            sparc64_file_prepared_t **out)
{
    if (out == NULL || *out != NULL ||
        !sparc64_file_identity_policy_valid(policy)) {
        if (owned_fd >= 0)
            (void)close(owned_fd);
        errno = EINVAL;
        return -1;
    }
    if (owned_fd < 0) {
        errno = EBADF;
        return -1;
    }
    struct stat status;
    if (fstat(owned_fd, &status) != 0)
        goto failed;
    int flags = fcntl(owned_fd, F_GETFL);
    if (flags < 0)
        goto failed;
#ifdef O_PATH
    if ((flags & O_PATH) != 0) {
        errno = EBADF;
        goto failed;
    }
#endif
    if (!S_ISREG(status.st_mode) || status.st_size < 0) {
        errno = ENODEV;
        goto failed;
    }
    if ((flags & O_ACCMODE) == O_WRONLY) {
        errno = EACCES;
        goto failed;
    }
    sparc64_file_identity_t identity = {0};
    if (sparc64_file_identity_query(owned_fd, policy, &identity) != 0)
        goto failed;
    if (owned_fd < 3) {
        int duplicate = fcntl(owned_fd, F_DUPFD_CLOEXEC, 3);
        int saved = errno;
        (void)close(owned_fd);
        owned_fd = duplicate;
        if (owned_fd < 0) {
            errno = saved;
            return -1;
        }
    } else if (fcntl(owned_fd, F_SETFD, FD_CLOEXEC) < 0)
        goto failed;
    sparc64_file_prepared_t *prepared = calloc(1, sizeof(*prepared));
    if (prepared == NULL)
        goto failed;
    prepared->file.fd = owned_fd;
    prepared->file.identity = identity;
    prepared->file.observed_size = (uint64_t)status.st_size;
    prepared->policy = policy;
    *out = prepared;
    return 0;
failed: {
    int saved = errno;
    (void)close(owned_fd);
    errno = saved;
    return -1;
}
}

sparc64_file_source_t *sparc64_file_source_admit(sparc64_file_registry_t *registry,
                                       sparc64_file_prepared_t **prepared)
{
    if (registry == NULL || registry->space == NULL || prepared == NULL ||
        *prepared == NULL || registry->identity_policy != (*prepared)->policy) {
        errno = EINVAL;
        return NULL;
    }
    sparc64_file_object_t *file = &(*prepared)->file;
    sparc64_file_object_t *existing = lookup(registry, &file->identity);
    if (existing != NULL) {
        retain(&existing->source);
        sparc64_file_source_prepared_discard(prepared);
        return &existing->source;
    }
    file->source = (sparc64_file_source_t){registry->space, retain, release, refresh};
    file->registry = registry;
    file->next = registry->head;
    file->references = 1;
    registry->head = file;
    *prepared = NULL;
    return &file->source;
}

sparc64_file_source_t *sparc64_file_source_find(sparc64_file_registry_t *registry, int native_fd)
{
    if (registry == NULL || registry->space == NULL) {
        errno = EINVAL;
        return NULL;
    }
    struct stat status;
    if (fstat(native_fd, &status) < 0)
        return NULL;
    sparc64_file_identity_t identity;
    if (sparc64_file_identity_query(native_fd, registry->identity_policy, &identity) != 0)
        return NULL;
    sparc64_file_object_t *file = lookup(registry, &identity);
    if (file == NULL) {
        errno = 0;
        return NULL;
    }
    if (status.st_size < 0 || !observe_size(&file->source, (uint64_t)status.st_size, 0)) {
        errno = EIO;
        return NULL;
    }
    retain(&file->source);
    return &file->source;
}

sparc64_file_source_t *sparc64_file_source_clone_into(sparc64_file_registry_t *child,
                                            sparc64_file_source_t *parent)
{
    if (child == NULL || child->space == NULL || parent == NULL ||
        parent->retain != retain || parent->release != release ||
        parent->refresh != refresh || parent->space == NULL ||
        child->space == parent->space) {
        errno = EINVAL;
        return NULL;
    }
    sparc64_file_object_t *original = object(parent);
    if (original->registry != NULL &&
        sparc64_file_registry_set_identity_policy(child,
            original->registry->identity_policy) != 0)
        return NULL;
    int duplicated = fcntl(original->fd, F_DUPFD_CLOEXEC, 3);
    if (duplicated < 0)
        return NULL;
    sparc64_file_source_t *copy = acquire(child, duplicated, &original->identity);
    if (copy != NULL) {
        /* A fork inherits the observer's current truncation baseline. A later
         * refresh may update either registry independently. */
        sparc64_file_object_t *cloned = object(copy);
        if (cloned->references == 1)
            cloned->observed_size = original->observed_size;
    }
    return copy;
}

int sparc64_file_source_identity(sparc64_file_source_t *source,
                              sparc64_file_identity_t *out, int *borrowed_fd)
{
    if (source == NULL || out == NULL || borrowed_fd == NULL ||
        source->retain != retain || source->release != release ||
        source->refresh != refresh || source->space == NULL) {
        errno = EINVAL;
        return -1;
    }
    sparc64_file_object_t *file = object(source);
    *out = file->identity;
    *borrowed_fd = file->fd;
    return 0;
}

static size_t write_range(const sparc64_backing_t *backing, uint64_t offset, uint64_t size,
                           size_t *first)
{
    uint64_t end = offset + size;
    uint64_t page_end = backing->file_offset + SPARC64_PAGE_SIZE;
    if (size == 0 || offset >= page_end || backing->file_offset >= end)
        return 0;
    uint64_t start = offset > backing->file_offset ? offset : backing->file_offset;
    if (end > page_end)
        end = page_end;
    *first = (size_t)(start - backing->file_offset);
    return (size_t)(end - start);
}

bool sparc64_file_prepare_write(sparc64_file_source_t *source, uint64_t offset, uint64_t size)
{
    if (size > UINT64_MAX - offset)
        return false;
    if (source == NULL || size == 0)
        return true;
    sparc64_space_t *space = source->space;
    bool changing = false;
    for (size_t i = 0; i < space->count; ++i) {
        sparc64_backing_t *backing = space->pages[i].backing;
        if (backing->file == source && !backing->private_cow) {
            size_t first = 0, count = write_range(backing, offset, size, &first);
            if (count != 0) {
                changing = true;
                if (!epoch_capacity(backing, first, count))
                    return sparc64_file_backing_fail(source, space->pages[i].address, SPARC64_FAULT_INTERNAL);
            }
        }
    }
    return !changing || space->generation != UINT64_MAX ||
           sparc64_file_backing_fail(source, 0, SPARC64_FAULT_INTERNAL);
}

void sparc64_file_commit_write(sparc64_file_source_t *source, uint64_t offset, uint64_t size)
{
    if (source == NULL || size == 0)
        return;
    assert(sparc64_file_prepare_write(source, offset, size));
    sparc64_space_t *space = source->space;
    bool advanced = false;
    for (size_t i = 0; i < space->count; ++i) {
        sparc64_backing_t *backing = space->pages[i].backing;
        if (backing->file == source && !backing->private_cow) {
            size_t first = 0, count = write_range(backing, offset, size, &first);
            if (count != 0) {
                if (!advanced) {
                    ++space->generation;
                    advanced = true;
                }
                advance_epochs(backing, first, count);
                size_t last = (first + count - 1) / SPARC64_RESERVATION_GRANULE;
                for (size_t j = first / SPARC64_RESERVATION_GRANULE; j <= last; ++j)
                    backing->file_notified[j / 64] |= UINT64_C(1) << (j % 64);
            }
        }
    }
}

static bool candidate(const sparc64_file_object_t *file, const sparc64_file_identity_t *writer)
{
    return !sparc64_file_identity_valid(writer) ||
           !sparc64_file_identity_valid(&file->identity) ||
           sparc64_file_identity_equal(&file->identity, writer);
}

static int writer_identity(sparc64_file_registry_t *registry, int fd,
                             sparc64_file_identity_t *identity, bool *regular)
{
    *regular = false;
    if (registry == NULL || registry->space == NULL) {
        errno = EINVAL;
        return -1;
    }
    struct stat status;
    int result;
    do { result = fstat(fd, &status); } while (result != 0 && errno == EINTR);
    if (result != 0)
        return -1;
    if (!S_ISREG(status.st_mode))
        return 0;
    *regular = true;
    return sparc64_file_identity_query(fd, registry->identity_policy, identity);
}

int sparc64_file_mutation_begin(sparc64_file_registry_t *registry, int native_fd,
                             sparc64_file_mutation_t **out)
{
    if (out == NULL) {
        errno = EINVAL;
        return -1;
    }
    *out = NULL;
    sparc64_file_identity_t writer = {0};
    bool regular;
    if (writer_identity(registry, native_fd, &writer, &regular) != 0)
        return -1;
    if (!regular)
        return 0;
    size_t count = 0;
    for (sparc64_file_object_t *file = registry->head; file != NULL; file = file->next)
        if (candidate(file, &writer)) {
            if (count == (SIZE_MAX - sizeof(sparc64_file_mutation_t)) /
                             sizeof(mutation_entry_t) || file->references == SIZE_MAX) {
                errno = ENOMEM;
                return -1;
            }
            ++count;
        }
    if (count == 0)
        return 0;
    sparc64_file_mutation_t *mutation = calloc(1, sizeof(*mutation) +
                                              count * sizeof(mutation_entry_t));
    if (mutation == NULL)
        return -1;
    mutation->space = registry->space;
    for (sparc64_file_object_t *file = registry->head; file != NULL; file = file->next)
        if (candidate(file, &writer)) {
            retain(&file->source);
            mutation->entries[mutation->count++] = (mutation_entry_t){
                .source = &file->source,
                .wide = !sparc64_file_identity_valid(&writer) ||
                         !sparc64_file_identity_valid(&file->identity)};
        }
    if (!observe_mutation(mutation)) {
        sparc64_file_mutation_destroy(&mutation);
        errno = EIO;
        return -1;
    }
    *out = mutation;
    return 0;
}

bool sparc64_file_mutation_needs_position(const sparc64_file_mutation_t *mutation)
{
    if (mutation != NULL)
        for (size_t i = 0; i < mutation->count; ++i)
            if (!mutation->entries[i].wide)
                return true;
    return false;
}

static bool changes_write(sparc64_file_source_t *source, uint64_t offset, uint64_t size)
{
    for (size_t i = 0; i < source->space->count; ++i) {
        sparc64_backing_t *backing = source->space->pages[i].backing;
        size_t first = 0;
        if (backing->file == source && !backing->private_cow &&
            write_range(backing, offset, size, &first) != 0)
            return true;
    }
    return false;
}

static bool changes_resize(sparc64_file_source_t *source, uint64_t size)
{
    if (size >= object(source)->observed_size)
        return false;
    for (size_t i = 0; i < source->space->count; ++i) {
        sparc64_backing_t *backing = source->space->pages[i].backing;
        if (backing->file == source && resize_start(backing, size) < SPARC64_PAGE_SIZE)
            return true;
    }
    return false;
}

static bool generation_capacity(sparc64_space_t *space, uint64_t needed)
{
    if (needed <= UINT64_MAX - space->generation)
        return true;
    space->internal_failure = true;
    space->fault_reason = SPARC64_FAULT_INTERNAL;
    space->fault_address = 0;
    return false;
}

static bool observe_mutation(sparc64_file_mutation_t *mutation)
{
    uint64_t needed = 0;
    for (size_t i = 0; i < mutation->count; ++i) {
        mutation_entry_t *entry = &mutation->entries[i];
        struct stat status;
        if (measured_stat(object(entry->source), &status) != 0 || status.st_size < 0)
            return sparc64_file_backing_fail(entry->source, 0, SPARC64_FAULT_INTERNAL);
        entry->after_size = (uint64_t)status.st_size;
        if (!sparc64_file_prepare_resize(entry->source, entry->after_size))
            return false;
        if (changes_resize(entry->source, entry->after_size))
            ++needed;
    }
    if (!generation_capacity(mutation->space, needed))
        return false;
    for (size_t i = 0; i < mutation->count; ++i)
        sparc64_file_commit_resize(mutation->entries[i].source,
                                 mutation->entries[i].after_size);
    return true;
}

bool sparc64_file_mutation_prepare_write(sparc64_file_mutation_t *mutation,
                                      uint64_t offset, uint64_t maximum_size)
{
    if (maximum_size > UINT64_MAX - offset)
        return false;
    if (mutation == NULL)
        return true;
    uint64_t needed = 0;
    for (size_t i = 0; maximum_size != 0 && i < mutation->count; ++i) {
        mutation_entry_t *entry = &mutation->entries[i];
        uint64_t start = entry->wide ? 0 : offset;
        uint64_t length = entry->wide ? UINT64_MAX : maximum_size;
        if (!sparc64_file_prepare_write(entry->source, start, length))
            return false;
        if (changes_write(entry->source, start, length))
            ++needed;
    }
    if (!generation_capacity(mutation->space, needed))
        return false;
    mutation->offset = offset;
    mutation->size = maximum_size;
    mutation->prepared = 1;
    return true;
}

void sparc64_file_mutation_commit_write(sparc64_file_mutation_t *mutation,
                                     uint64_t offset, uint64_t actual_size)
{
    if (mutation == NULL)
        return;
    assert(mutation->prepared == 1 && mutation->offset == offset &&
           actual_size <= mutation->size);
    for (size_t i = 0; actual_size != 0 && i < mutation->count; ++i) {
        mutation_entry_t *entry = &mutation->entries[i];
        sparc64_file_commit_write(entry->source, entry->wide ? 0 : offset,
                                entry->wide ? UINT64_MAX : actual_size);
    }
    mutation->prepared = 0;
}

bool sparc64_file_mutation_prepare_resize(sparc64_file_mutation_t *mutation, uint64_t size)
{
    if (mutation == NULL)
        return true;
    uint64_t needed = 0;
    for (size_t i = 0; i < mutation->count; ++i) {
        mutation_entry_t *entry = &mutation->entries[i];
        uint64_t worst_size = entry->wide ? 0 : size;
        if (!sparc64_file_prepare_resize(entry->source, worst_size))
            return false;
        if (changes_resize(entry->source, worst_size))
            ++needed;
    }
    if (!generation_capacity(mutation->space, needed))
        return false;
    mutation->size = size;
    mutation->prepared = 2;
    return true;
}

bool sparc64_file_mutation_commit_resize(sparc64_file_mutation_t *mutation, uint64_t size)
{
    if (mutation == NULL)
        return true;
    assert(mutation->prepared == 2 && mutation->size == size);
    /* All possible native observations complete before publishing any local
     * resize state. Failure after native truncation is infrastructure-fatal;
     * returning guest execution with stale COW state would be incorrect. */
    for (size_t i = 0; i < mutation->count; ++i) {
        mutation_entry_t *entry = &mutation->entries[i];
        entry->after_size = size;
        if (entry->wide) {
            struct stat status;
            if (measured_stat(object(entry->source), &status) != 0 || status.st_size < 0)
                return sparc64_file_backing_fail(entry->source, 0, SPARC64_FAULT_INTERNAL);
            entry->after_size = (uint64_t)status.st_size;
        }
    }
    for (size_t i = 0; i < mutation->count; ++i)
        sparc64_file_commit_resize(mutation->entries[i].source,
                                 mutation->entries[i].after_size);
    mutation->prepared = 0;
    return true;
}

void sparc64_file_mutation_destroy(sparc64_file_mutation_t **owned)
{
    if (owned == NULL || *owned == NULL)
        return;
    int saved = errno;
    sparc64_file_mutation_t *mutation = *owned;
    for (size_t i = 0; i < mutation->count; ++i)
        release(mutation->entries[i].source);
    free(mutation);
    *owned = NULL;
    errno = saved;
}

bool sparc64_file_registry_prepare_truncate(sparc64_file_registry_t *registry)
{
    if (registry == NULL || registry->space == NULL)
        return false;
    uint64_t needed = 0;
    for (sparc64_file_object_t *file = registry->head; file != NULL; file = file->next) {
        if (!sparc64_file_prepare_resize(&file->source, 0))
            return false;
        if (changes_resize(&file->source, 0))
            ++needed;
    }
    return generation_capacity(registry->space, needed);
}

bool sparc64_file_registry_observe_resize(sparc64_file_registry_t *registry)
{
    if (registry == NULL || registry->space == NULL)
        return false;
    for (sparc64_file_object_t *file = registry->head; file != NULL; file = file->next) {
        struct stat status;
        if (measured_stat(file, &status) != 0 || status.st_size < 0)
            return sparc64_file_backing_fail(&file->source, 0, SPARC64_FAULT_INTERNAL);
        if (!observe_size(&file->source, (uint64_t)status.st_size, 0))
            return false;
    }
    return true;
}
