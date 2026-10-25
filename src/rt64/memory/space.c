/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#include "space_split.h"


static void heap_payload_dispose(sparc64_page_payload_t *payload)
{
    free(payload); /* payload is the first member of heap_payload_t. */
}

static sparc64_page_payload_t *heap_payload_create(void *context)
{
    (void)context;
    heap_payload_t *heap = calloc(1, sizeof(*heap));
    if (heap == NULL)
        return NULL;
    heap->payload = (sparc64_page_payload_t){
        .bytes = heap->bytes, .epochs = heap->epochs,
        .references = 1, .dispose = heap_payload_dispose
    };
    return &heap->payload;
}

static bool payload_retain(sparc64_page_payload_t *payload)
{
    if (payload->references == SIZE_MAX)
        return false;
    ++payload->references;
    return true;
}

static void payload_release(sparc64_page_payload_t *payload)
{
    assert(payload != NULL && payload->references != 0);
    if (--payload->references == 0)
        payload->dispose(payload);
}

static sparc64_backing_t *create_backing(sparc64_space_t *space, bool file_private,
                                    sparc64_fault_reason_t *reason)
{
    sparc64_page_factory_t factory = file_private ?
        (sparc64_page_factory_t){heap_payload_create, NULL} : space->page_factory;
    sparc64_page_payload_t *payload = factory.create(factory.context);
    if (payload == NULL) {
        /* Only the built-in heap factory has a defined NULL=allocation failure
         * contract. A custom factory may have failed after external effects. */
        *reason = factory.create == heap_payload_create ?
                  SPARC64_FAULT_RESOURCE : SPARC64_FAULT_INTERNAL;
        return NULL;
    }
    if (payload->bytes == NULL || payload->epochs == NULL ||
        payload->references != 1 || payload->dispose == NULL) {
        if (payload->dispose != NULL)
            payload->dispose(payload);
        *reason = SPARC64_FAULT_INTERNAL;
        return NULL;
    }
    payload->backend = !file_private && space->managed.commitv != NULL ?
                       SPARC64_PAYLOAD_MANAGED : SPARC64_PAYLOAD_HEAP;
    sparc64_backing_t *backing = calloc(1, sizeof(*backing));
    if (backing == NULL) {
        payload_release(payload);
        *reason = SPARC64_FAULT_RESOURCE;
        return NULL;
    }
    backing->bytes = payload->bytes;
    backing->epochs = payload->epochs;
    backing->payload = payload;
    backing->references = 1;
    return backing;
}

static sparc64_backing_t *alias_backing(sparc64_backing_t *source,
                                    sparc64_fault_reason_t *reason)
{
    if (source->bus_fault) {
        sparc64_backing_t *fault = calloc(1, sizeof(*fault));
        if (fault == NULL) { *reason = SPARC64_FAULT_RESOURCE; return NULL; }
        fault->bus_fault = true; fault->references = 1;
        return fault;
    }
    if (!payload_retain(source->payload)) {
        *reason = SPARC64_FAULT_INTERNAL;
        return NULL;
    }
    sparc64_backing_t *alias = calloc(1, sizeof(*alias));
    if (alias == NULL) {
        payload_release(source->payload);
        *reason = SPARC64_FAULT_RESOURCE;
        return NULL;
    }
    alias->bytes = source->payload->bytes;
    alias->epochs = source->payload->epochs;
    alias->payload = source->payload;
    alias->references = 1;
    return alias;
}

bool fail(sparc64_space_t *space, uint64_t address, sparc64_fault_reason_t reason)
{
    space->fault_address = address;
    space->fault_reason = reason;
    if (reason == SPARC64_FAULT_INTERNAL)
        space->internal_failure = true;
    return false;
}

bool managed_guard(sparc64_space_t *space, uint64_t address)
{
    if (space->managed.commitv == NULL)
        return true;
    sparc64_measure_stamp_t stamp = sparc64_measure_begin(space->measure,
                                                SPARC64_MEASURE_MANAGED_GUARD);
    bool held = space->managed.check_guard(space->managed.context);
    sparc64_measure_end(space->measure, SPARC64_MEASURE_MANAGED_GUARD, stamp);
    return held || fail(space, address, SPARC64_FAULT_INTERNAL);
}

void sparc64_space_init(sparc64_space_t *space, unsigned int xlen)
{
    if (space == NULL)
        return;
    memset(space, 0, sizeof(*space));
    space->limit = xlen == 32 ? (UINT64_C(1) << 32) : (UINT64_C(1) << 47);
    space->generation = 1;
    space->next_binding = 1;
    space->page_factory = (sparc64_page_factory_t){heap_payload_create, NULL};
}

bool sparc64_space_set_page_factory(sparc64_space_t *space, sparc64_page_factory_t factory)
{
    if (space == NULL || space->count != 0 || factory.create == NULL ||
        space->managed.commitv != NULL)
        return false;
    space->page_factory = factory;
    return true;
}

bool sparc64_space_set_managed_factory(sparc64_space_t *space, sparc64_page_factory_t factory,
                                  sparc64_managed_page_ops_t managed)
{
    if (space == NULL || space->count != 0 || factory.create == NULL ||
        managed.check_guard == NULL || managed.refresh == NULL ||
        managed.check_write == NULL || managed.commitv == NULL)
        return false;
    space->page_factory = factory;
    space->managed = managed;
    return true;
}

bool sparc64_backing_retain(sparc64_backing_t *backing)
{
    if (backing == NULL || backing->references == SIZE_MAX)
        return false;
    ++backing->references;
    return true;
}

void sparc64_backing_release(sparc64_backing_t *backing)
{
    if (backing == NULL)
        return;
    assert(backing->references != 0);
    if (--backing->references != 0)
        return;
    if (backing->file != NULL)
        backing->file->release(backing->file);
    if (!backing->bus_fault)
        payload_release(backing->payload);
    free(backing);
}

void sparc64_space_destroy(sparc64_space_t *space)
{
    if (space == NULL)
        return;
    for (size_t i = 0; i < space->count; ++i)
        sparc64_backing_release(space->pages[i].backing);
    free(space->pages);
    free(space->epoch_scratch);
    memset(space, 0, sizeof(*space));
}

size_t page_position(const sparc64_space_t *space, uint64_t address)
{
    size_t left = 0, right = space->count;
    while (left < right) {
        size_t middle = left + (right - left) / 2;
        if (space->pages[middle].address < address)
            left = middle + 1;
        else
            right = middle;
    }
    return left;
}

static bool valid_range(sparc64_space_t *space, uint64_t address, uint64_t size)
{
    if (size == 0)
        return true;
    if (address < SPARC64_PAGE_SIZE || address >= space->limit)
        return fail(space, address, SPARC64_FAULT_RANGE);
    if (size > space->limit - address)
        return fail(space, space->limit, SPARC64_FAULT_RANGE);
    return true;
}

static bool mapping_range(sparc64_space_t *space, uint64_t address, uint64_t size,
                           unsigned int permissions)
{
    space->fault_reason = SPARC64_FAULT_NONE;
    if (size == 0 || address % SPARC64_PAGE_SIZE != 0 || size % SPARC64_PAGE_SIZE != 0 ||
        (permissions & ~(unsigned int)7) != 0)
        return fail(space, address, SPARC64_FAULT_RANGE);
    if (!valid_range(space, address, size))
        return false;
    return true;
}

static bool map_pages(sparc64_space_t *space, uint64_t address, uint64_t size,
                      unsigned int permissions, enum map_mode mode,
                      sparc64_file_source_t *source, uint64_t file_offset, bool bus_fault)
{
    if (space == NULL || !mapping_range(space, address, size, permissions))
        return false;
    if (!managed_guard(space, address))
        return false;
    if (source != NULL && (source->space != space || source->retain == NULL ||
                          source->release == NULL || source->refresh == NULL ||
                          file_offset % SPARC64_PAGE_SIZE != 0 || size > UINT64_MAX - file_offset))
        return fail(space, address, SPARC64_FAULT_RANGE);
    uint64_t page_count = size / SPARC64_PAGE_SIZE;
    if (page_count > SPARC64_R1_MAX_PAGES)
        return fail(space, address, SPARC64_FAULT_RESOURCE);
    size_t first = page_position(space, address);
    size_t last = page_position(space, address + size);
    if (mode == MAP_EXCLUSIVE && first != last)
        return fail(space, space->pages[first].address, SPARC64_FAULT_RANGE);
    size_t count = space->count - (last - first) + (size_t)page_count;
    if (count > SPARC64_R1_MAX_PAGES)
        return fail(space, address, SPARC64_FAULT_RESOURCE);
    if (page_count > (UINT64_MAX - space->next_binding) / SPARC64_PAGE_GRANULES)
        return fail(space, address, SPARC64_FAULT_INTERNAL);
    if (space->generation == UINT64_MAX)
        return fail(space, address, SPARC64_FAULT_INTERNAL);
    /* Prepare a complete replacement registry without modifying live objects.
     * Track only new allocations so failed merges never free reused backing. */
    sparc64_page_t *pages = malloc(count * sizeof(*pages));
    sparc64_backing_t **created = malloc((size_t)page_count * sizeof(*created));
    if (pages == NULL || created == NULL) {
        free(pages);
        free(created);
        return fail(space, address, SPARC64_FAULT_RESOURCE);
    }
    if (first != 0)
        memcpy(pages, space->pages, first * sizeof(*pages));
    size_t old = first, allocated = 0;
    uint64_t binding = space->next_binding;
    for (size_t i = 0; i < (size_t)page_count; ++i) {
        uint64_t at = address + (uint64_t)i * SPARC64_PAGE_SIZE;
        bool present = old < last && space->pages[old].address == at;
        sparc64_backing_t *backing;
        unsigned int access = permissions;
        if (mode == MAP_MERGE && present) {
            backing = space->pages[old].backing;
            access |= space->pages[old].permissions;
        } else {
            sparc64_fault_reason_t reason = SPARC64_FAULT_INTERNAL;
            if (bus_fault) {
                backing = calloc(1, sizeof(*backing));
                if (backing != NULL) {
                    backing->bus_fault = true; backing->references = 1;
                } else {
                    reason = SPARC64_FAULT_RESOURCE;
                }
            } else {
                backing = create_backing(space, source != NULL, &reason);
            }
            if (backing == NULL) {
                for (size_t j = 0; j < allocated; ++j)
                    sparc64_backing_release(created[j]);
                free(created);
                free(pages);
                return fail(space, at, reason);
            }
            if (source != NULL) {
                source->retain(source);
                backing->file = source;
                backing->file_offset = file_offset + (uint64_t)i * SPARC64_PAGE_SIZE;
            }
            created[allocated++] = backing;
        }
        pages[first + i] = (sparc64_page_t){at, access, backing, binding};
        binding += SPARC64_PAGE_GRANULES;
        if (present)
            ++old;
    }
    if (last != space->count)
        memcpy(pages + first + (size_t)page_count, space->pages + last,
                (space->count - last) * sizeof(*pages));
    /* Invalidate before replacing bytes/ownership. No guest instruction or
     * blocking operation can observe the middle of this single-thread commit. */
    ++space->generation;
    if (source != NULL)
        space->has_file_pages = true;
    if (mode == MAP_REPLACE)
        for (size_t i = first; i < last; ++i)
            sparc64_backing_release(space->pages[i].backing);
    free(space->pages);
    free(created);
    space->pages = pages;
    space->count = count;
    space->capacity = count;
    space->next_binding = binding;
    return true;
}

bool sparc64_space_map(sparc64_space_t *space, uint64_t address, uint64_t size,
                  unsigned int permissions, bool merge)
{
    return map_pages(space, address, size, permissions,
                     merge ? MAP_MERGE : MAP_EXCLUSIVE, NULL, 0, false);
}

bool sparc64_space_map_bus(sparc64_space_t *space, uint64_t address, uint64_t size,
                      unsigned int permissions, bool replace)
{
    return map_pages(space, address, size, permissions,
                     replace ? MAP_REPLACE : MAP_EXCLUSIVE, NULL, 0, true);
}

bool sparc64_space_replace(sparc64_space_t *space, uint64_t address, uint64_t size,
                      unsigned int permissions)
{
    return map_pages(space, address, size, permissions, MAP_REPLACE, NULL, 0, false);
}

bool sparc64_space_map_file(sparc64_space_t *space, uint64_t address, uint64_t size,
                       unsigned int permissions, bool replace,
                       sparc64_file_source_t *source, uint64_t file_offset)
{
    if (source == NULL)
        return false;
    return map_pages(space, address, size, permissions,
                     replace ? MAP_REPLACE : MAP_EXCLUSIVE, source, file_offset, false);
}

static bool map_managed_payload(sparc64_space_t *space, uint64_t address,
                                 unsigned int permissions,
                                 sparc64_page_payload_t *payload,
                                 sparc64_file_source_t *source, uint64_t offset,
                                 bool staging)
{
    if (space == NULL || !mapping_range(space, address, SPARC64_PAGE_SIZE, permissions))
        return false;
    if (!managed_guard(space, address))
        return false;
    if (space->managed.commitv == NULL || payload == NULL ||
        payload->backend != SPARC64_PAYLOAD_MANAGED || payload->bytes == NULL ||
        payload->epochs == NULL || payload->dispose == NULL)
        return fail(space, address, SPARC64_FAULT_INTERNAL);
    if (source != NULL && (source->space == NULL ||
        (source->space != space && (!staging ||
         source->space->managed.context != space->managed.context ||
         source->space->limit != space->limit)) || source->retain == NULL ||
        source->release == NULL || source->refresh == NULL ||
        offset % SPARC64_PAGE_SIZE != 0 || offset > UINT64_MAX - SPARC64_PAGE_SIZE))
        return fail(space, address, SPARC64_FAULT_RANGE);
    size_t first = page_position(space, address);
    if (first < space->count && space->pages[first].address == address)
        return fail(space, address, SPARC64_FAULT_RANGE);
    if (space->count == SPARC64_R1_MAX_PAGES)
        return fail(space, address, SPARC64_FAULT_RESOURCE);
    if (space->generation == UINT64_MAX ||
        space->next_binding > UINT64_MAX - SPARC64_PAGE_GRANULES ||
        payload->references == SIZE_MAX)
        return fail(space, address, SPARC64_FAULT_INTERNAL);
    sparc64_page_t *pages = malloc((space->count + 1) * sizeof(*pages));
    sparc64_backing_t *view = calloc(1, sizeof(*view));
    if (pages == NULL || view == NULL) {
        free(pages);
        free(view);
        return fail(space, address, SPARC64_FAULT_RESOURCE);
    }
    if (first != 0)
        memcpy(pages, space->pages, first * sizeof(*pages));
    if (first != space->count)
        memcpy(pages + first + 1, space->pages + first,
               (space->count - first) * sizeof(*pages));
    ++payload->references;
    *view = (sparc64_backing_t){.bytes = payload->bytes, .epochs = payload->epochs,
                           .payload = payload, .references = 1,
                           .file = source, .file_offset = offset};
    if (source != NULL)
        source->retain(source);
    pages[first] = (sparc64_page_t){address, permissions, view, space->next_binding};
    ++space->generation;
    space->next_binding += SPARC64_PAGE_GRANULES;
    ++space->count;
    space->capacity = space->count;
    free(space->pages);
    space->pages = pages;
    if (source != NULL)
        space->has_file_pages = true;
    return true;
}

bool sparc64_space_map_shared_payload(sparc64_space_t *space, uint64_t address,
                                 unsigned int permissions, sparc64_page_payload_t *payload)
{
    return map_managed_payload(space, address, permissions, payload, NULL, 0, false);
}

bool sparc64_space_map_managed_file_payload(sparc64_space_t *space, uint64_t address,
                                        unsigned int permissions,
                                        sparc64_page_payload_t *payload,
                                        sparc64_file_source_t *source, uint64_t offset)
{
    if (source == NULL)
        return false;
    return map_managed_payload(space, address, permissions, payload, source, offset, false);
}

bool sparc64_space_stage_managed_file_payload(sparc64_space_t *space, uint64_t address,
                                          unsigned int permissions,
                                          sparc64_page_payload_t *payload,
                                          sparc64_file_source_t *source, uint64_t offset)
{
    if (source == NULL)
        return false;
    return map_managed_payload(space, address, permissions, payload, source, offset, true);
}

bool sparc64_space_alias(sparc64_space_t *space, uint64_t source, uint64_t destination,
                    uint64_t size, unsigned int permissions)
{
    if (space == NULL || !mapping_range(space, source, size, permissions) ||
        !mapping_range(space, destination, size, permissions))
        return false;
    if (!managed_guard(space, source))
        return false;
    uint64_t page_count = size / SPARC64_PAGE_SIZE;
    if (page_count > SPARC64_R1_MAX_PAGES)
        return fail(space, destination, SPARC64_FAULT_RESOURCE);
    size_t count = (size_t)page_count;
    size_t source_first = page_position(space, source);
    for (size_t i = 0; i < count; ++i) {
        uint64_t at = source + (uint64_t)i * SPARC64_PAGE_SIZE;
        if (source_first + i >= space->count ||
            space->pages[source_first + i].address != at)
            return fail(space, at, SPARC64_FAULT_UNMAPPED);
        if (space->pages[source_first + i].backing->file != NULL)
            return fail(space, at, SPARC64_FAULT_RANGE);
    }
    size_t first = page_position(space, destination);
    size_t last = page_position(space, destination + size);
    if (first != last)
        return fail(space, space->pages[first].address, SPARC64_FAULT_RANGE);
    if (count > SPARC64_R1_MAX_PAGES - space->count)
        return fail(space, destination, SPARC64_FAULT_RESOURCE);
    if (count > (UINT64_MAX - space->next_binding) / SPARC64_PAGE_GRANULES ||
        space->generation == UINT64_MAX)
        return fail(space, destination, SPARC64_FAULT_INTERNAL);
    sparc64_page_t *pages = malloc((space->count + count) * sizeof(*pages));
    if (pages == NULL)
        return fail(space, destination, SPARC64_FAULT_RESOURCE);
    if (first != 0)
        memcpy(pages, space->pages, first * sizeof(*pages));
    if (first != space->count)
        memcpy(pages + first + count, space->pages + first,
               (space->count - first) * sizeof(*pages));
    uint64_t binding = space->next_binding;
    for (size_t i = 0; i < count; ++i) {
        sparc64_fault_reason_t reason = SPARC64_FAULT_INTERNAL;
        sparc64_backing_t *backing = alias_backing(
            space->pages[source_first + i].backing, &reason);
        if (backing == NULL) {
            for (size_t j = 0; j < i; ++j)
                sparc64_backing_release(pages[first + j].backing);
            free(pages);
            return fail(space, destination + (uint64_t)i * SPARC64_PAGE_SIZE,
                        reason);
        }
        pages[first + i] = (sparc64_page_t){destination + (uint64_t)i * SPARC64_PAGE_SIZE,
                                      permissions, backing, binding};
        binding += SPARC64_PAGE_GRANULES;
    }
    ++space->generation;
    free(space->pages);
    space->pages = pages;
    space->count += count;
    space->capacity = space->count;
    space->next_binding = binding;
    return true;
}

bool sparc64_space_unmap(sparc64_space_t *space, uint64_t address, uint64_t size)
{
    if (space == NULL || !mapping_range(space, address, size, 0))
        return false;
    if (!managed_guard(space, address))
        return false;
    size_t first = page_position(space, address);
    size_t last = page_position(space, address + size);
    if (first == last)
        return true;
    if (space->generation == UINT64_MAX)
        return fail(space, address, SPARC64_FAULT_INTERNAL);
    ++space->generation;
    for (size_t i = first; i < last; ++i)
        sparc64_backing_release(space->pages[i].backing);
    memmove(space->pages + first, space->pages + last,
            (space->count - last) * sizeof(*space->pages));
    space->count -= last - first;
    return true;
}

bool sparc64_space_protect(sparc64_space_t *space, uint64_t address, uint64_t size,
                      unsigned int permissions)
{
    if (space == NULL || !mapping_range(space, address, size, permissions))
        return false;
    if (!managed_guard(space, address))
        return false;
    uint64_t page_count = size / SPARC64_PAGE_SIZE;
    size_t first = page_position(space, address);
    size_t last = page_position(space, address + size);
    if ((uint64_t)(last - first) != page_count)
        return fail(space, address, SPARC64_FAULT_UNMAPPED);
    if (space->generation == UINT64_MAX ||
        page_count > (UINT64_MAX - space->next_binding) / SPARC64_PAGE_GRANULES)
        return fail(space, address, SPARC64_FAULT_INTERNAL);
    ++space->generation;
    for (size_t i = first; i < last; ++i) {
        space->pages[i].permissions = permissions;
        space->pages[i].binding_base = space->next_binding;
        space->next_binding += SPARC64_PAGE_GRANULES;
    }
    return true;
}

bool sparc64_space_find_hole(const sparc64_space_t *space, uint64_t start, uint64_t size,
                        uint64_t *address)
{
    if (space == NULL || address == NULL || size == 0 ||
        size % SPARC64_PAGE_SIZE != 0 || start < SPARC64_PAGE_SIZE ||
        start > UINT64_MAX - (SPARC64_PAGE_SIZE - 1))
        return false;
    uint64_t candidate = (start + SPARC64_PAGE_SIZE - 1) & ~(SPARC64_PAGE_SIZE - 1);
    size_t first = page_position(space, candidate);
    for (size_t i = first; i < space->count; ++i) {
        if (candidate >= space->limit || size > space->limit - candidate)
            return false;
        if (space->pages[i].address - candidate >= size) {
            *address = candidate;
            return true;
        }
        candidate = space->pages[i].address + SPARC64_PAGE_SIZE;
    }
    if (candidate >= space->limit || size > space->limit - candidate)
        return false;
    *address = candidate;
    return true;
}

static int compare_pages(const void *left, const void *right)
{
    const sparc64_page_t *a = left, *b = right;
    return a->address < b->address ? -1 : a->address != b->address;
}

bool sparc64_space_remap(sparc64_space_t *space, uint64_t source, uint64_t old_size,
                    uint64_t destination, uint64_t new_size,
                    unsigned int permissions)
{
    if (space == NULL || !mapping_range(space, source, old_size, permissions) ||
        !mapping_range(space, destination, new_size, permissions))
        return false;
    if (!managed_guard(space, source))
        return false;
    uint64_t old_end = source + old_size, new_end = destination + new_size;
    if (source != destination && source < new_end && destination < old_end)
        return fail(space, destination, SPARC64_FAULT_RANGE);
    size_t first = page_position(space, source), last = page_position(space, old_end);
    if ((uint64_t)(last - first) != old_size / SPARC64_PAGE_SIZE)
        return fail(space, source, SPARC64_FAULT_UNMAPPED);
    sparc64_backing_t *original = space->pages[first].backing;
    if (original->file != NULL && new_size > UINT64_MAX - original->file_offset)
        return fail(space, source, SPARC64_FAULT_RANGE);
    uint64_t new_count = new_size / SPARC64_PAGE_SIZE;
    if (new_count > SPARC64_R1_MAX_PAGES)
        return fail(space, destination, SPARC64_FAULT_RESOURCE);
    if (space->generation == UINT64_MAX ||
        new_count > (UINT64_MAX - space->next_binding) / SPARC64_PAGE_GRANULES)
        return fail(space, destination, SPARC64_FAULT_INTERNAL);
    size_t retained = 0;
    for (size_t i = 0; i < space->count; ++i) {
        uint64_t at = space->pages[i].address;
        if (!(at >= source && at < old_end) && !(at >= destination && at < new_end))
            ++retained;
    }
    if (new_count > SPARC64_R1_MAX_PAGES - retained)
        return fail(space, destination, SPARC64_FAULT_RESOURCE);
    size_t count = retained + (size_t)new_count;
    sparc64_page_t *pages = malloc(count * sizeof(*pages));
    if (pages == NULL)
        return fail(space, destination, SPARC64_FAULT_RESOURCE);
    size_t at_new = 0;
    for (size_t i = 0; i < space->count; ++i) {
        uint64_t at = space->pages[i].address;
        if (!(at >= source && at < old_end) && !(at >= destination && at < new_end))
            pages[at_new++] = space->pages[i];
    }
    size_t reused = last - first;
    if (reused > (size_t)new_count)
        reused = (size_t)new_count;
    uint64_t binding = space->next_binding;
    size_t created = 0;
    for (size_t i = 0; i < (size_t)new_count; ++i) {
        sparc64_fault_reason_t reason = SPARC64_FAULT_INTERNAL;
        sparc64_backing_t *backing = i < reused ? space->pages[first + i].backing :
                                          create_backing(space, original->file != NULL,
                                                         &reason);
        if (backing == NULL) {
            for (size_t j = 0; j < created; ++j)
                sparc64_backing_release(pages[retained + reused + j].backing);
            free(pages);
            return fail(space, destination, reason);
        }
        if (i >= reused) {
            if (original->file != NULL) {
                original->file->retain(original->file);
                backing->file = original->file;
                backing->file_offset = original->file_offset + (uint64_t)i * SPARC64_PAGE_SIZE;
            }
            ++created;
        }
        pages[at_new++] = (sparc64_page_t){destination + (uint64_t)i * SPARC64_PAGE_SIZE,
                                    permissions, backing, binding};
        binding += SPARC64_PAGE_GRANULES;
    }
    qsort(pages, count, sizeof(*pages), compare_pages);
    ++space->generation;
    for (size_t i = 0; i < space->count; ++i) {
        uint64_t at = space->pages[i].address;
        bool moved = i >= first && i - first < reused;
        if (!moved && ((at >= source && at < old_end) ||
                       (at >= destination && at < new_end)))
            sparc64_backing_release(space->pages[i].backing);
    }
    free(space->pages);
    space->pages = pages;
    space->count = count;
    space->capacity = count;
    space->next_binding = binding;
    return true;
}

bool validate_access(sparc64_space_t *space, uint64_t address, size_t size,
                            unsigned int permissions)
{
    space->fault_reason = SPARC64_FAULT_NONE;
    if (!valid_range(space, address, (uint64_t)size))
        return false;
    uint64_t start = address;
    size_t remaining = size;
    while (remaining != 0) {
        uint64_t base = address & ~(SPARC64_PAGE_SIZE - 1);
        size_t position = page_position(space, base);
        if (position == space->count || space->pages[position].address != base)
            return fail(space, address, SPARC64_FAULT_UNMAPPED);
        if ((space->pages[position].permissions & permissions) != permissions)
            return fail(space, address, SPARC64_FAULT_PERMISSION);
        size_t amount = (size_t)(SPARC64_PAGE_SIZE - (address - base));
        if (amount > remaining)
            amount = remaining;
        address += amount;
        remaining -= amount;
    }
    /* Permission/range checks finish before filesystem reads. Refresh also
     * precedes LR/SC's direct backing access and reservation-token sampling. */
    if (size != 0 && !managed_guard(space, start))
        return false;
    address = start;
    remaining = size;
    while (remaining != 0) {
        uint64_t base = address & ~(SPARC64_PAGE_SIZE - 1);
        sparc64_backing_t *backing = space->pages[page_position(space, base)].backing;
        if (backing->bus_fault)
            return fail(space, address, SPARC64_FAULT_BUS);
        if (backing->payload->backend != SPARC64_PAYLOAD_HEAP &&
            backing->payload->backend != SPARC64_PAYLOAD_MANAGED)
            return fail(space, address, SPARC64_FAULT_INTERNAL);
        if (backing->payload->backend == SPARC64_PAYLOAD_MANAGED) {
            if (space->managed.commitv == NULL)
                return fail(space, address, SPARC64_FAULT_INTERNAL);
            bool changed = false;
            sparc64_measure_stamp_t refresh_stamp = sparc64_measure_begin(space->measure,
                                                                 SPARC64_MEASURE_FILE_REFRESH);
            bool refreshed = space->managed.refresh(space->managed.context,
                                                     backing->payload,
                                                     space->generation != UINT64_MAX,
                                                     &changed, space->measure);
            sparc64_measure_end(space->measure, SPARC64_MEASURE_FILE_REFRESH, refresh_stamp);
            if (!refreshed)
                return fail(space, address, SPARC64_FAULT_INTERNAL);
            if (changed)
                ++space->generation;
        }
        bool refreshed = true;
        if (backing->file != NULL)
            refreshed = space->refresh_check != NULL ?
                space->refresh_check(space->refresh_context, space,
                    &space->pages[page_position(space, base)], address, permissions) :
                backing->file->refresh(backing->file, backing, address);
        if (!refreshed) {
            switch (space->fault_reason) {
            case SPARC64_FAULT_RANGE:
            case SPARC64_FAULT_UNMAPPED:
            case SPARC64_FAULT_PERMISSION:
            case SPARC64_FAULT_BUS:
            case SPARC64_FAULT_RESOURCE:
            case SPARC64_FAULT_RETRY:
                break;
            case SPARC64_FAULT_INTERNAL:
                space->internal_failure = true;
                break;
            case SPARC64_FAULT_NONE:
            default:
                return fail(space, address, SPARC64_FAULT_INTERNAL);
            }
            return false;
        }
        size_t amount = (size_t)(SPARC64_PAGE_SIZE - (address - base));
        if (amount > remaining)
            amount = remaining;
        address += amount;
        remaining -= amount;
    }
    return true;
}

bool sparc64_space_read(sparc64_space_t *space, uint64_t address, void *bytes,
                   size_t size, unsigned int permissions)
{
    if (space == NULL)
        return false;
    if (bytes == NULL && size != 0)
        return fail(space, address, SPARC64_FAULT_INTERNAL);
    if (!validate_access(space, address, size, permissions))
        return false;
    unsigned char *out = bytes;
    while (size != 0) {
        uint64_t base = address & ~(SPARC64_PAGE_SIZE - 1);
        size_t position = page_position(space, base);
        size_t offset = (size_t)(address - base);
        size_t amount = (size_t)SPARC64_PAGE_SIZE - offset;
        if (amount > size)
            amount = size;
        memcpy(out, space->pages[position].backing->bytes + offset, amount);
        address += amount;
        out += amount;
        size -= amount;
    }
    return true;
}

bool first_managed_file_write(const sparc64_backing_t *view)
{
    return view->file != NULL && view->payload->backend == SPARC64_PAYLOAD_MANAGED &&
        view->payload->canonical_private_cow != NULL &&
        *view->payload->canonical_private_cow == 0;
}

int compare_epoch_touches(const void *left, const void *right)
{
    const epoch_touch_t *a = left, *b = right;
    uintptr_t a_key = (uintptr_t)a->payload, b_key = (uintptr_t)b->payload;
    if (a_key != b_key)
        return a_key < b_key ? -1 : 1;
    return a->address < b->address ? -1 : a->address != b->address;
}
