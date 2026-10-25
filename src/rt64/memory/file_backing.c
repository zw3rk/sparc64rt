/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#include "file_backing_split.h"


sparc64_file_object_t *object(sparc64_file_source_t *source)
{
    return (sparc64_file_object_t *)source; /* source is the first member. */
}

void sparc64_file_registry_init(sparc64_file_registry_t *registry, sparc64_space_t *space)
{
    *registry = (sparc64_file_registry_t){.space = space};
}

int sparc64_file_registry_set_identity_policy(sparc64_file_registry_t *registry,
                                          sparc64_file_identity_policy_t policy)
{
    if (registry == NULL || registry->space == NULL ||
        !sparc64_file_identity_policy_valid(policy)) {
        errno = EINVAL;
        return -1;
    }
    if (registry->head != NULL && registry->identity_policy != policy) {
        errno = EBUSY;
        return -1;
    }
    registry->identity_policy = policy;
    return 0;
}

void sparc64_file_registry_destroy(sparc64_file_registry_t *registry)
{
    if (registry == NULL)
        return;
    for (sparc64_file_object_t *file = registry->head; file != NULL; file = file->next)
        file->registry = NULL;
    *registry = (sparc64_file_registry_t){0};
}

void retain(sparc64_file_source_t *source)
{
    sparc64_file_object_t *file = object(source);
    if (file->references == SIZE_MAX)
        abort();
    ++file->references;
}

void release(sparc64_file_source_t *source)
{
    sparc64_file_object_t *file = object(source);
    assert(file->references != 0);
    if (--file->references != 0)
        return;
    if (file->registry != NULL) {
        sparc64_file_object_t **link = &file->registry->head;
        while (*link != NULL && *link != file)
            link = &(*link)->next;
        assert(*link == file);
        *link = file->next;
    }
    (void)close(file->fd);
    free(file);
}

bool sparc64_file_backing_fail(sparc64_file_source_t *source, uint64_t address, sparc64_fault_reason_t reason)
{
    source->space->fault_address = address;
    source->space->fault_reason = reason;
    if (reason == SPARC64_FAULT_INTERNAL)
        source->space->internal_failure = true;
    return false;
}

bool epoch_capacity(const sparc64_backing_t *backing, size_t first, size_t length)
{
    if (length == 0)
        return true;
    size_t last = (first + length - 1) / SPARC64_RESERVATION_GRANULE;
    for (size_t i = first / SPARC64_RESERVATION_GRANULE; i <= last; ++i)
        if (backing->epochs[i] == UINT64_MAX)
            return false;
    return true;
}

void advance_epochs(sparc64_backing_t *backing, size_t first, size_t length)
{
    if (length == 0)
        return;
    size_t last = (first + length - 1) / SPARC64_RESERVATION_GRANULE;
    for (size_t i = first / SPARC64_RESERVATION_GRANULE; i <= last; ++i)
        ++backing->epochs[i];
}

/* A partial last COW page survives truncate, including private bytes beyond
 * new EOF. A full page at/above ceil(EOF/page) loses COW ownership. */
size_t resize_start(const sparc64_backing_t *backing, uint64_t size)
{
    if (backing->file_offset >= size) {
        if (backing->file_offset != (size & ~(SPARC64_PAGE_SIZE - 1)) ||
            size % SPARC64_PAGE_SIZE == 0)
            return 0;
    }
    if (backing->private_cow || backing->file_offset >= size ||
        size - backing->file_offset >= SPARC64_PAGE_SIZE)
        return (size_t)SPARC64_PAGE_SIZE;
    return (size_t)(size - backing->file_offset);
}

bool sparc64_file_prepare_resize(sparc64_file_source_t *source, uint64_t size)
{
    if (source == NULL || size >= object(source)->observed_size)
        return true;
    sparc64_space_t *space = source->space;
    bool changing = false;
    for (size_t i = 0; i < space->count; ++i) {
        sparc64_backing_t *backing = space->pages[i].backing;
        if (backing->file == source) {
            size_t start = resize_start(backing, size);
            if (start < SPARC64_PAGE_SIZE) {
                changing = true;
                if (!epoch_capacity(backing, start, (size_t)SPARC64_PAGE_SIZE - start))
                    return sparc64_file_backing_fail(source, space->pages[i].address, SPARC64_FAULT_INTERNAL);
            }
        }
    }
    return !changing || space->generation != UINT64_MAX ||
           sparc64_file_backing_fail(source, 0, SPARC64_FAULT_INTERNAL);
}

void sparc64_file_commit_resize(sparc64_file_source_t *source, uint64_t size)
{
    if (source == NULL)
        return;
    assert(sparc64_file_prepare_resize(source, size));
    sparc64_file_object_t *file = object(source);
    if (size < file->observed_size) {
        sparc64_space_t *space = source->space;
        bool advanced = false;
        for (size_t i = 0; i < space->count; ++i) {
            sparc64_backing_t *backing = space->pages[i].backing;
            if (backing->file != source)
                continue;
            size_t start = resize_start(backing, size);
            if (start < SPARC64_PAGE_SIZE) {
                if (!advanced) {
                    ++space->generation;
                    advanced = true;
                }
                advance_epochs(backing, start, (size_t)SPARC64_PAGE_SIZE - start);
                memset(backing->bytes + start, 0, (size_t)SPARC64_PAGE_SIZE - start);
                if (start == 0)
                    backing->private_cow = false;
                if (start == 0)
                    memset(backing->file_notified, 0, sizeof(backing->file_notified));
            }
        }
    }
    /* Update only after every alias has discarded full-page COW state. */
    file->observed_size = size;
}

bool observe_size(sparc64_file_source_t *source, uint64_t size, uint64_t address)
{
    if (!sparc64_file_prepare_resize(source, size))
        return sparc64_file_backing_fail(source, address, SPARC64_FAULT_INTERNAL);
    sparc64_file_commit_resize(source, size);
    return true;
}

int measured_stat(sparc64_file_object_t *file, struct stat *status)
{
    sparc64_measure_observer_t *measure = file->source.space->measure;
    sparc64_measure_stamp_t stamp = sparc64_measure_begin(measure, SPARC64_MEASURE_FILE_STAT);
    /* Native signal capture may interrupt refresh without a guest memory fault. */
    int result;
    do {
        result = fstat(file->fd, status);
    } while (result < 0 && errno == EINTR);
    sparc64_measure_end(measure, SPARC64_MEASURE_FILE_STAT, stamp);
    return result;
}

static ssize_t measured_read(sparc64_file_object_t *file, void *bytes, size_t size,
                              off_t offset)
{
    sparc64_measure_observer_t *measure = file->source.space->measure;
    sparc64_measure_stamp_t stamp = sparc64_measure_begin(measure, SPARC64_MEASURE_FILE_READ);
    ssize_t result = pread(file->fd, bytes, size, offset);
    sparc64_measure_end(measure, SPARC64_MEASURE_FILE_READ, stamp);
    return result;
}

static bool publish_refresh_bytes(sparc64_file_source_t *source, sparc64_backing_t *backing,
                                  uint64_t address, const unsigned char bytes[SPARC64_PAGE_SIZE])
{
    bool changed = memcmp(backing->bytes, bytes, (size_t)SPARC64_PAGE_SIZE) != 0;
    if (changed) {
        bool new_invalidation = false;
        for (size_t i = 0; i < SPARC64_PAGE_GRANULES; ++i) {
            bool notified = (backing->file_notified[i / 64] & (UINT64_C(1) << (i % 64))) != 0;
            if (memcmp(backing->bytes + i * SPARC64_RESERVATION_GRANULE,
                        bytes + i * SPARC64_RESERVATION_GRANULE, SPARC64_RESERVATION_GRANULE) != 0 &&
                !notified) {
                new_invalidation = true;
                if (backing->epochs[i] == UINT64_MAX)
                    return sparc64_file_backing_fail(source, address, SPARC64_FAULT_INTERNAL);
            }
        }
        if (new_invalidation) {
            if (source->space->generation == UINT64_MAX)
                return sparc64_file_backing_fail(source, address, SPARC64_FAULT_INTERNAL);
            ++source->space->generation;
        }
        for (size_t i = 0; i < SPARC64_PAGE_GRANULES; ++i) {
            bool notified = (backing->file_notified[i / 64] & (UINT64_C(1) << (i % 64))) != 0;
            if (memcmp(backing->bytes + i * SPARC64_RESERVATION_GRANULE,
                        bytes + i * SPARC64_RESERVATION_GRANULE, SPARC64_RESERVATION_GRANULE) != 0 && !notified)
                ++backing->epochs[i];
        }
        memcpy(backing->bytes, bytes, (size_t)SPARC64_PAGE_SIZE);
    }
    memset(backing->file_notified, 0, sizeof(backing->file_notified));
    return true;
}

static bool refresh_bytes(sparc64_file_source_t *source, sparc64_backing_t *backing, uint64_t address)
{
    sparc64_file_object_t *file = object(source);
    struct stat status;
    if (measured_stat(file, &status) < 0 || status.st_size < 0)
        return sparc64_file_backing_fail(source, address, SPARC64_FAULT_BUS);
    uint64_t size = (uint64_t)status.st_size;
    if (!observe_size(source, size, address))
        return false;
    /* Avoid rounding overflow and signed off_t overflow for beyond-EOF pages. */
    if (backing->file_offset >= size &&
        (size % SPARC64_PAGE_SIZE == 0 || backing->file_offset > size - size % SPARC64_PAGE_SIZE))
        return sparc64_file_backing_fail(source, address, SPARC64_FAULT_BUS);
    if (backing->private_cow)
        return true;
    unsigned char bytes[4096] = {0};
    uint64_t available = size - backing->file_offset;
    size_t wanted = available < SPARC64_PAGE_SIZE ? (size_t)available : (size_t)SPARC64_PAGE_SIZE;
    size_t received = 0;
    while (received < wanted) {
        ssize_t amount = measured_read(file, bytes + received, wanted - received,
                               (off_t)(backing->file_offset + received));
        if (amount < 0) {
            if (errno == EINTR)
                continue; /* No guest bytes published; safe memory-fault retry. */
            return sparc64_file_backing_fail(source, address, SPARC64_FAULT_BUS);
        }
        if (amount == 0)
            break;
        received += (size_t)amount;
    }
    if (measured_stat(file, &status) < 0 || status.st_size < 0)
        return sparc64_file_backing_fail(source, address, SPARC64_FAULT_BUS);
    if (!observe_size(source, (uint64_t)status.st_size, address))
        return false;
    size = (uint64_t)status.st_size;
    if (backing->file_offset >= size &&
        (size % SPARC64_PAGE_SIZE == 0 || backing->file_offset > size - size % SPARC64_PAGE_SIZE))
        return sparc64_file_backing_fail(source, address, SPARC64_FAULT_BUS);
    if (size - backing->file_offset < SPARC64_PAGE_SIZE)
        memset(bytes + (size_t)(size - backing->file_offset), 0,
                (size_t)SPARC64_PAGE_SIZE - (size_t)(size - backing->file_offset));
    return publish_refresh_bytes(source, backing, address, bytes);
}

bool refresh(sparc64_file_source_t *source, sparc64_backing_t *backing, uint64_t address)
{
    sparc64_measure_observer_t *measure = source->space->measure;
    sparc64_measure_stamp_t stamp = sparc64_measure_begin(measure, SPARC64_MEASURE_FILE_REFRESH);
    bool result = refresh_bytes(source, backing, address);
    sparc64_measure_end(measure, SPARC64_MEASURE_FILE_REFRESH, stamp);
    return result;
}

static sparc64_refresh_result_t refresh_fault(sparc64_space_t *space, uint64_t address,
                                         sparc64_fault_reason_t reason)
{
    space->fault_address = address;
    space->fault_reason = reason;
    if (reason == SPARC64_FAULT_INTERNAL)
        space->internal_failure = true;
    return SPARC64_REFRESH_FAULT;
}

/* This entry is guarded. The ticket retains the exact backing, but the
 * detached sampler sees only copied scalar metadata, its FD number and its
 * private byte buffer. The active scheduler I/O flight forbids fork while
 * that retained source exists solely on the worker's C stack. */
sparc64_file_refresh_ticket_t *sparc64_file_refresh_ticket_capture(sparc64_space_t *space,
    const sparc64_page_t *page, uint64_t fault_address, unsigned int permissions)
{
    sparc64_backing_t *backing = page->backing;
    if (backing->file == NULL || backing->file->refresh != refresh)
        return NULL;
    sparc64_file_refresh_ticket_t *ticket = calloc(1, sizeof(*ticket));
    if (ticket == NULL)
        return NULL;
    if (!sparc64_backing_retain(backing)) {
        free(ticket);
        return NULL;
    }
    sparc64_file_object_t *file = object(backing->file);
    ticket->backing = backing;
    ticket->space = space;
    ticket->source = backing->file;
    ticket->payload = backing->payload;
    ticket->fd = file->fd;
    ticket->address = page->address;
    ticket->fault_address = fault_address;
    ticket->binding = page->binding_base;
    ticket->generation = space->generation;
    ticket->offset = backing->file_offset;
    ticket->observed_size = file->observed_size;
    ticket->permissions = permissions;
    ticket->private_cow = backing->private_cow;
    memcpy(ticket->notified, backing->file_notified, sizeof(ticket->notified));
    memcpy(ticket->epochs, backing->epochs, sizeof(ticket->epochs));
    return ticket;
}

sparc64_refresh_result_t sparc64_space_refresh_capture(sparc64_space_t *space,
    uint64_t address, unsigned int permissions, sparc64_file_refresh_ticket_t **out)
{
    if (out == NULL || space == NULL)
        return SPARC64_REFRESH_FAULT;
    *out = NULL;
    space->fault_reason = SPARC64_FAULT_NONE;
    if (address < SPARC64_PAGE_SIZE || address >= space->limit)
        return refresh_fault(space, address, SPARC64_FAULT_RANGE);
    uint64_t base = address & ~(SPARC64_PAGE_SIZE - 1);
    size_t left = 0, right = space->count;
    while (left < right) {
        size_t middle = left + (right - left) / 2;
        if (space->pages[middle].address < base)
            left = middle + 1;
        else
            right = middle;
    }
    if (left == space->count || space->pages[left].address != base)
        return refresh_fault(space, address, SPARC64_FAULT_UNMAPPED);
    const sparc64_page_t *page = &space->pages[left];
    if ((page->permissions & permissions) != permissions)
        return refresh_fault(space, address, SPARC64_FAULT_PERMISSION);
    if (space->managed.commitv != NULL &&
        !space->managed.check_guard(space->managed.context))
        return refresh_fault(space, address, SPARC64_FAULT_INTERNAL);
    if (page->backing->bus_fault)
        return refresh_fault(space, address, SPARC64_FAULT_BUS);
    if (page->backing->file == NULL)
        return SPARC64_REFRESH_READY;
    *out = sparc64_file_refresh_ticket_capture(space, page, address, permissions);
    if (*out == NULL)
        return refresh_fault(space, address, SPARC64_FAULT_INTERNAL);
    return SPARC64_REFRESH_SAMPLE;
}

void sparc64_file_refresh_sample(sparc64_file_refresh_ticket_t *ticket)
{
    if (ticket == NULL || ticket->sampled)
        return;
    /* Copy the FD while guarded capture owns its source. No registry, space,
     * backing, observer or guest pointer is consulted in this phase. */
    int fd = ticket->fd;
    struct stat status;
    ticket->sampled = true;
    if (fstat(fd, &status) < 0) {
        ticket->native_interrupted = errno == EINTR;
        ticket->native_failed = !ticket->native_interrupted;
        return;
    }
    if (status.st_size < 0) {
        ticket->native_failed = true;
        return;
    }
    ticket->first_size = (uint64_t)status.st_size;
    if (ticket->private_cow)
        return;
    if (ticket->offset < ticket->first_size) {
        uint64_t available = ticket->first_size - ticket->offset;
        size_t wanted = available < SPARC64_PAGE_SIZE ? (size_t)available : SPARC64_PAGE_SIZE;
        size_t received = 0;
        while (received < wanted) {
            ssize_t amount = pread(fd, ticket->bytes + received, wanted - received,
                                   (off_t)(ticket->offset + received));
            if (amount < 0) {
                ticket->native_interrupted = errno == EINTR;
                ticket->native_failed = !ticket->native_interrupted;
                return;
            }
            if (amount == 0)
                break;
            received += (size_t)amount;
        }
    }
    if (fstat(fd, &status) < 0) {
        ticket->native_interrupted = errno == EINTR;
        ticket->native_failed = !ticket->native_interrupted;
        return;
    }
    if (status.st_size < 0) {
        ticket->native_failed = true;
        return;
    }
    ticket->last_size = (uint64_t)status.st_size;
}

static bool file_page_bus(uint64_t offset, uint64_t size)
{
    return offset >= size &&
        (size % SPARC64_PAGE_SIZE == 0 || offset > size - size % SPARC64_PAGE_SIZE);
}

/* Value-only relookup. Call for every entry in a batch before its first
 * publication, then again before each subsequent publication: an earlier
 * resize may change another alias's epochs or COW state. */
static bool refresh_ticket_current(sparc64_space_t *space,
                                   const sparc64_file_refresh_ticket_t *ticket)
{
    uint64_t base = ticket->address;
    size_t left = 0, right = space->count;
    while (left < right) {
        size_t middle = left + (right - left) / 2;
        if (space->pages[middle].address < base)
            left = middle + 1;
        else
            right = middle;
    }
    if (left == space->count || space->pages[left].address != base ||
        space->pages[left].binding_base != ticket->binding ||
        space->pages[left].backing != ticket->backing ||
        space->generation != ticket->generation ||
        (space->pages[left].permissions & ticket->permissions) != ticket->permissions)
        return false;
    const sparc64_backing_t *backing = ticket->backing;
    sparc64_file_source_t *source = backing->file;
    return source != NULL && source == ticket->source &&
        backing->payload == ticket->payload && source->space == space &&
        backing->file_offset == ticket->offset &&
        backing->private_cow == ticket->private_cow &&
        object(source)->observed_size == ticket->observed_size &&
        memcmp(backing->epochs, ticket->epochs, sizeof(ticket->epochs)) == 0 &&
        memcmp(backing->file_notified, ticket->notified,
               sizeof(ticket->notified)) == 0;
}

sparc64_refresh_result_t sparc64_file_refresh_ticket_apply(sparc64_space_t *space,
    sparc64_file_refresh_ticket_t *ticket)
{
    if (space == NULL || ticket == NULL || !ticket->sampled ||
        ticket->space != space)
        return SPARC64_REFRESH_FAULT;
    if (space->managed.commitv != NULL &&
        !space->managed.check_guard(space->managed.context))
        return refresh_fault(space, ticket->fault_address, SPARC64_FAULT_INTERNAL);
    if (!refresh_ticket_current(space, ticket))
        return SPARC64_REFRESH_STALE;
    sparc64_backing_t *backing = ticket->backing;
    sparc64_file_source_t *source = backing->file;
    if (ticket->native_interrupted)
        return SPARC64_REFRESH_STALE;
    if (ticket->native_failed)
        return refresh_fault(space, ticket->fault_address, SPARC64_FAULT_BUS);
    if (!observe_size(source, ticket->first_size, ticket->fault_address))
        return SPARC64_REFRESH_FAULT;
    if (file_page_bus(ticket->offset, ticket->first_size))
        return refresh_fault(space, ticket->fault_address, SPARC64_FAULT_BUS);
    if (ticket->private_cow && backing->private_cow)
        return SPARC64_REFRESH_READY;
    if (ticket->private_cow)
        return SPARC64_REFRESH_STALE; /* Resize discarded COW after the first stat. */
    if (!observe_size(source, ticket->last_size, ticket->fault_address))
        return SPARC64_REFRESH_FAULT;
    if (file_page_bus(ticket->offset, ticket->last_size))
        return refresh_fault(space, ticket->fault_address, SPARC64_FAULT_BUS);
    if (ticket->last_size - ticket->offset < SPARC64_PAGE_SIZE)
        memset(ticket->bytes + (size_t)(ticket->last_size - ticket->offset), 0,
               SPARC64_PAGE_SIZE - (size_t)(ticket->last_size - ticket->offset));
    return publish_refresh_bytes(source, backing, ticket->fault_address, ticket->bytes) ?
           SPARC64_REFRESH_READY : SPARC64_REFRESH_FAULT;
}

sparc64_refresh_result_t sparc64_space_refresh_apply(sparc64_space_t *space,
    sparc64_file_refresh_ticket_t *ticket)
{
    return sparc64_file_refresh_ticket_apply(space, ticket);
}

void sparc64_file_refresh_ticket_discard(sparc64_file_refresh_ticket_t **ticket)
{
    if (ticket == NULL || *ticket == NULL)
        return;
    sparc64_backing_release((*ticket)->backing);
    free(*ticket);
    *ticket = NULL;
}

static bool refresh_scope_check(void *opaque, sparc64_space_t *space,
    const sparc64_page_t *page, uint64_t address, unsigned int permissions)
{
    sparc64_file_refresh_scope_t *scope = opaque;
    if (scope == NULL || !scope->entered || scope->space != space ||
        page->backing->file == NULL || page->backing->file->refresh != refresh)
        return refresh_fault(space, address, SPARC64_FAULT_INTERNAL) == SPARC64_REFRESH_READY;
    uint64_t base = page->address;
    for (size_t i = 0; i < scope->count; ++i) {
        sparc64_refresh_need_t *need = &scope->needs[i];
        if (need->address != base || need->permissions != permissions)
            continue;
        if (need->proved)
            return true;
        if (need->ticket != NULL && need->ticket->sampled) {
            need->ticket->fault_address = address;
            sparc64_refresh_result_t result = sparc64_file_refresh_ticket_apply(space,
                                                                       need->ticket);
            if (result == SPARC64_REFRESH_READY) {
                need->proved = true;
                sparc64_file_refresh_ticket_discard(&need->ticket);
                return true;
            }
            if (result == SPARC64_REFRESH_FAULT)
                return false;
        }
        return refresh_fault(space, address, SPARC64_FAULT_RETRY) == SPARC64_REFRESH_READY;
    }
    if (scope->count == SPARC64_REFRESH_SCOPE_MAX) {
        scope->overflowed = true;
        return refresh_fault(space, address, SPARC64_FAULT_RETRY) == SPARC64_REFRESH_READY;
    }
    scope->needs[scope->count++] = (sparc64_refresh_need_t){
        .address = base, .permissions = permissions, .alias_of = SIZE_MAX
    };
    return refresh_fault(space, address, SPARC64_FAULT_RETRY) == SPARC64_REFRESH_READY;
}

sparc64_file_refresh_scope_t *sparc64_file_refresh_scope_create(sparc64_space_t *space)
{
    if (space == NULL)
        return NULL;
    sparc64_file_refresh_scope_t *scope = calloc(1, sizeof(*scope));
    if (scope != NULL)
        scope->space = space;
    return scope;
}

bool sparc64_file_refresh_scope_enter(sparc64_file_refresh_scope_t *scope)
{
    if (scope == NULL || scope->entered || scope->space->refresh_check != NULL)
        return false;
    scope->space->refresh_context = scope;
    scope->space->refresh_check = refresh_scope_check;
    scope->entered = true;
    return true;
}

void sparc64_file_refresh_scope_leave(sparc64_file_refresh_scope_t *scope)
{
    if (scope == NULL || !scope->entered)
        return;
    assert(scope->space->refresh_context == scope &&
           scope->space->refresh_check == refresh_scope_check);
    scope->space->refresh_check = NULL;
    scope->space->refresh_context = NULL;
    scope->entered = false;
    /* Only a captured batch may cross the guard boundary. A READY proof and
     * its native sample cannot authorize a later engine attempt. */
    if (!scope->pending_sample)
        for (size_t i = 0; i < scope->count; ++i) {
            sparc64_file_refresh_ticket_discard(&scope->needs[i].ticket);
            scope->needs[i].proved = false;
            scope->needs[i].alias_of = SIZE_MAX;
        }
}

sparc64_refresh_result_t sparc64_file_refresh_scope_capture(sparc64_file_refresh_scope_t *scope)
{
    if (scope == NULL || !scope->entered)
        return SPARC64_REFRESH_FAULT;
    scope->pending_sample = false;
    sparc64_space_t *space = scope->space;
    for (size_t i = 0; i < scope->count; ++i) {
        sparc64_refresh_need_t *need = &scope->needs[i];
        sparc64_file_refresh_ticket_discard(&need->ticket);
        need->proved = false;
        need->alias_of = SIZE_MAX;
        sparc64_refresh_result_t result = sparc64_space_refresh_capture(space,
            need->address, need->permissions, &need->ticket);
        if (result == SPARC64_REFRESH_READY) {
            /* No file ticket is needed now. Do not prove this address: a
             * sibling may install a new file mapping before guarded resume. */
            continue;
        }
        if (result == SPARC64_REFRESH_FAULT) {
            if (sparc64_fault_is_runtime(space->fault_reason))
                return SPARC64_REFRESH_FAULT;
            /* An old requirement may have been unmapped or protected while
             * we were outside the guard. Let the actual retried instruction
             * report its own fault, at its current byte address. */
            space->fault_reason = SPARC64_FAULT_NONE;
            continue;
        }
        for (size_t j = 0; j < i; ++j)
            if (scope->needs[j].ticket != NULL &&
                scope->needs[j].ticket->backing == need->ticket->backing) {
                need->alias_of = j;
                break;
            }
    }
    scope->pending_sample = true;
    return SPARC64_REFRESH_SAMPLE;
}

void sparc64_file_refresh_scope_sample(sparc64_file_refresh_scope_t *scope)
{
    if (scope == NULL || scope->entered || !scope->pending_sample)
        return;
    for (size_t i = 0; i < scope->count; ++i) {
        sparc64_refresh_need_t *need = &scope->needs[i];
        if (need->ticket == NULL)
            continue;
        if (need->alias_of == SIZE_MAX) {
            sparc64_file_refresh_sample(need->ticket);
        } else {
            sparc64_file_refresh_ticket_t *owner = scope->needs[need->alias_of].ticket;
            if (owner == NULL || !owner->sampled)
                continue;
            need->ticket->sampled = true;
            need->ticket->native_failed = owner->native_failed;
            need->ticket->native_interrupted = owner->native_interrupted;
            need->ticket->first_size = owner->first_size;
            need->ticket->last_size = owner->last_size;
            memcpy(need->ticket->bytes, owner->bytes, sizeof(owner->bytes));
        }
    }
}

sparc64_refresh_result_t sparc64_file_refresh_scope_resume(sparc64_file_refresh_scope_t *scope)
{
    if (scope == NULL || !scope->entered || !scope->pending_sample)
        return SPARC64_REFRESH_FAULT;
    scope->pending_sample = false;
    sparc64_space_t *space = scope->space;
    /* No sample is allowed to publish until every mapped requirement still
     * names its exact captured page, source, payload, permissions and epochs. */
    for (size_t i = 0; i < scope->count; ++i) {
        sparc64_file_refresh_ticket_t *ticket = scope->needs[i].ticket;
        if (ticket != NULL && (!ticket->sampled ||
                               !refresh_ticket_current(space, ticket)))
            return SPARC64_REFRESH_STALE;
    }
    for (size_t i = 0; i < scope->count; ++i) {
        sparc64_refresh_need_t *need = &scope->needs[i];
        sparc64_file_refresh_ticket_t *ticket = need->ticket;
        if (ticket == NULL || need->alias_of != SIZE_MAX)
            continue;
        /* BUS is deferred until an actual checked access. A JIT lookahead
         * must fall back without faulting a preceding executable prefix. */
        if (ticket->native_failed || ticket->native_interrupted ||
            file_page_bus(ticket->offset, ticket->first_size) ||
            (!ticket->private_cow &&
             file_page_bus(ticket->offset, ticket->last_size)))
            continue;
        sparc64_refresh_result_t result = sparc64_file_refresh_ticket_apply(space, ticket);
        if (result != SPARC64_REFRESH_READY)
            return result;
        need->proved = true;
        for (size_t j = i + 1; j < scope->count; ++j)
            if (scope->needs[j].alias_of == i)
                scope->needs[j].proved = true;
    }
    return SPARC64_REFRESH_READY;
}

void sparc64_file_refresh_scope_reset(sparc64_file_refresh_scope_t *scope)
{
    if (scope == NULL)
        return;
    assert(scope->entered && !scope->pending_sample);
    for (size_t i = 0; i < scope->count; ++i)
        sparc64_file_refresh_ticket_discard(&scope->needs[i].ticket);
    memset(scope->needs, 0, sizeof(scope->needs));
    scope->count = 0;
    scope->overflowed = false;
}

bool sparc64_file_refresh_scope_overflowed(const sparc64_file_refresh_scope_t *scope)
{
    return scope != NULL && scope->overflowed;
}

void sparc64_file_refresh_scope_destroy(sparc64_file_refresh_scope_t **scope)
{
    if (scope == NULL || *scope == NULL)
        return;
    sparc64_file_refresh_scope_leave(*scope);
    for (size_t i = 0; i < (*scope)->count; ++i)
        sparc64_file_refresh_ticket_discard(&(*scope)->needs[i].ticket);
    free(*scope);
    *scope = NULL;
}

sparc64_file_object_t *lookup(const sparc64_file_registry_t *registry,
                                 const sparc64_file_identity_t *identity)
{
    for (sparc64_file_object_t *file = registry->head; file != NULL; file = file->next)
        if (sparc64_file_identity_equal(&file->identity, identity))
            return file;
    return NULL;
}

sparc64_file_source_t *acquire(sparc64_file_registry_t *registry, int owned_fd,
                                  const sparc64_file_identity_t *proven)
{
    if (owned_fd < 0) {
        errno = EBADF;
        return NULL;
    }
    int error = EINVAL;
    if (registry == NULL || registry->space == NULL)
        goto failed;
    struct stat status;
    if (fstat(owned_fd, &status) < 0) {
        error = errno;
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
    if (!S_ISREG(status.st_mode) || status.st_size < 0) {
        error = ENODEV;
        goto failed;
    }
    if ((flags & O_ACCMODE) == O_WRONLY) {
        error = EACCES;
        goto failed;
    }
    sparc64_file_identity_t identity = {0};
    if (proven != NULL)
        identity = *proven; /* Exact local clone provenance, not dev/ino. */
    else if (sparc64_file_identity_query(owned_fd, registry->identity_policy,
                                     &identity) != 0) {
        error = errno;
        goto failed;
    }
    sparc64_file_object_t *existing = lookup(registry, &identity);
    if (existing != NULL) {
        retain(&existing->source);
        (void)close(owned_fd);
        return &existing->source;
    }
    if (owned_fd < 3) {
        int private_fd = fcntl(owned_fd, F_DUPFD_CLOEXEC, 3);
        error = errno;
        (void)close(owned_fd);
        owned_fd = private_fd;
        if (owned_fd < 0) {
            errno = error;
            return NULL;
        }
    } else if (fcntl(owned_fd, F_SETFD, FD_CLOEXEC) < 0) {
        error = errno;
        goto failed;
    }
    sparc64_file_object_t *file = calloc(1, sizeof(*file));
    if (file == NULL) {
        error = ENOMEM;
        goto failed;
    }
    file->source = (sparc64_file_source_t){registry->space, retain, release, refresh};
    file->registry = registry;
    file->next = registry->head;
    file->fd = owned_fd;
    file->identity = identity;
    file->references = 1;
    file->observed_size = (uint64_t)status.st_size;
    registry->head = file;
    return &file->source;
failed:
    (void)close(owned_fd);
    errno = error;
    return NULL;
}
