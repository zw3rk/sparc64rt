/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#include "space_split.h"


/* Aliased VAs may touch one physical granule more than once in one write.
 * Count every hit before committing any epoch/byte mutation. In a managed
 * space the retained, payload-sorted touches also reserve the batch plan
 * before a caller can consume native input. */
static bool shared_epoch_capacity(sparc64_space_t *space, uint64_t address, size_t size)
{
    uint64_t last = address + (uint64_t)size - 1;
    size_t page_count = (size_t)(last / SPARC64_PAGE_SIZE - address / SPARC64_PAGE_SIZE + 1);
    bool new_scratch = page_count > space->epoch_scratch_capacity;
    epoch_touch_t *touches = new_scratch ? malloc(page_count * sizeof(*touches)) :
                                           space->epoch_scratch;
    if (touches == NULL)
        return fail(space, address, SPARC64_FAULT_RESOURCE);
    uint64_t cursor = address;
    size_t remaining = size, used = 0;
    while (remaining != 0) {
        uint64_t base = cursor & ~(SPARC64_PAGE_SIZE - 1);
        sparc64_backing_t *backing = space->pages[page_position(space, base)].backing;
        size_t offset = (size_t)(cursor - base);
        size_t amount = (size_t)SPARC64_PAGE_SIZE - offset;
        if (amount > remaining)
            amount = remaining;
        touches[used++] = (epoch_touch_t){
            .payload = backing->payload, .view = backing, .address = cursor,
            .first = offset / SPARC64_RESERVATION_GRANULE,
            .last = (offset + amount - 1) / SPARC64_RESERVATION_GRANULE,
            .amount = amount
        };
        remaining -= amount;
        cursor += amount;
    }
    qsort(touches, used, sizeof(*touches), compare_epoch_touches);
    size_t first = 0;
    while (first < used) {
        sparc64_page_payload_t *payload = touches[first].payload;
        uint32_t counts[SPARC64_PAGE_GRANULES] = {0};
        size_t end = first;
        bool cow = false;
        while (end < used && touches[end].payload == payload) {
            cow = cow || first_managed_file_write(touches[end].view);
            ++end;
        }
        if (cow)
            for (size_t i = 0; i < SPARC64_PAGE_GRANULES; ++i) {
                counts[i] = 1;
                if (payload->epochs[i] == UINT64_MAX) {
                    uint64_t fault = touches[first].address;
                    if (new_scratch)
                        free(touches);
                    return fail(space, fault, SPARC64_FAULT_INTERNAL);
                }
            }
        end = first;
        while (end < used && touches[end].payload == payload) {
            for (size_t granule = touches[end].first;
                 granule <= touches[end].last; ++granule) {
                ++counts[granule];
                if (payload->epochs[granule] > UINT64_MAX - counts[granule]) {
                    uint64_t fault = touches[end].address;
                    if (new_scratch)
                        free(touches);
                    return fail(space, fault, SPARC64_FAULT_INTERNAL);
                }
            }
            ++end;
        }
        first = end;
    }
    if (new_scratch) {
        free(space->epoch_scratch);
        space->epoch_scratch = touches;
        space->epoch_scratch_capacity = page_count;
    }
    return true;
}

static bool prepare_write(sparc64_space_t *space, uint64_t address,
                           size_t size, unsigned int permissions)
{
    if (space == NULL)
        return false;
    if (!validate_access(space, address, size, permissions))
        return false;
    /* Validate epoch capacity before invalidating anything. All writes use
     * this path, so ABA and sub-word interference cannot escape reservations. */
    uint64_t cursor = address;
    size_t remaining = size;
    bool touches_shared = false;
    size_t touched_pages = 0;
    while (remaining != 0) {
        uint64_t base = cursor & ~(SPARC64_PAGE_SIZE - 1);
        sparc64_page_t *page = &space->pages[page_position(space, base)];
        size_t offset = (size_t)(cursor - base);
        size_t amount = (size_t)SPARC64_PAGE_SIZE - offset;
        if (amount > remaining)
            amount = remaining;
        ++touched_pages;
        if (page->backing->payload->backend == SPARC64_PAYLOAD_MANAGED) {
            sparc64_page_payload_t *payload = page->backing->payload;
            bool file = page->backing->file != NULL;
            errno = 0;
            if (space->managed.commitv == NULL ||
                !space->managed.check_write(space->managed.context, payload, file, true))
                return fail(space, cursor, errno == ENOMEM ? SPARC64_FAULT_RESOURCE : SPARC64_FAULT_INTERNAL);
            if (file && (payload->canonical_private_cow == NULL ||
                *payload->canonical_private_cow > 1))
                return fail(space, cursor, SPARC64_FAULT_INTERNAL);
        }
        if (page->backing->payload->references > 1)
            touches_shared = true;
        size_t last = (offset + amount - 1) / SPARC64_RESERVATION_GRANULE;
        for (size_t i = offset / SPARC64_RESERVATION_GRANULE; i <= last; ++i)
            if (page->backing->epochs[i] == UINT64_MAX)
                return fail(space, cursor, SPARC64_FAULT_INTERNAL);
        remaining -= amount;
        cursor += amount;
    }
    if (size != 0 && space->generation == UINT64_MAX)
        return fail(space, address, SPARC64_FAULT_INTERNAL);
    if ((space->managed.commitv != NULL ||
         (touches_shared && touched_pages > 1)) && size != 0 &&
        !shared_epoch_capacity(space, address, size))
        return false;
    return true;
}

bool sparc64_space_prepare_write(sparc64_space_t *space, uint64_t address, size_t size)
{
    return prepare_write(space, address, size, SPARC64_MEM_WRITE);
}

bool sparc64_space_cow_file_page(sparc64_space_t *space, uint64_t address)
{
    if (space == NULL || !validate_access(space, address, 1, SPARC64_MEM_WRITE))
        return false;
    uint64_t base = address & ~(SPARC64_PAGE_SIZE - 1);
    sparc64_backing_t *backing = space->pages[page_position(space, base)].backing;
    if (backing->file == NULL || backing->private_cow)
        return true;
    if (backing->payload->backend != SPARC64_PAYLOAD_HEAP || space->generation == UINT64_MAX)
        return fail(space, address, SPARC64_FAULT_INTERNAL);
    for (size_t i = 0; i < SPARC64_PAGE_GRANULES; ++i)
        if (backing->epochs[i] == UINT64_MAX)
            return fail(space, address, SPARC64_FAULT_INTERNAL);
    /* A COW copy is already present in the private heap view. Invalidate
     * reservations conservatively without changing the logical mapping:
     * released I/O completion must still recognize this destination binding. */
    ++space->generation;
    for (size_t i = 0; i < SPARC64_PAGE_GRANULES; ++i)
        ++backing->epochs[i];
    backing->private_cow = true;
    return true;
}

sparc64_copyout_t *sparc64_space_copyout_prepare(sparc64_space_t *space, uint64_t address,
                                       size_t maximum)
{
    if (space == NULL || !sparc64_space_prepare_write(space, address, maximum))
        return NULL;
    size_t count = 0;
    if (maximum != 0) {
        uint64_t last = address + (uint64_t)maximum - 1;
        count = (size_t)(last / SPARC64_PAGE_SIZE - address / SPARC64_PAGE_SIZE + 1);
    }
    if (count > (SIZE_MAX - sizeof(sparc64_copyout_t)) / sizeof(copyout_page_t)) {
        (void)fail(space, address, SPARC64_FAULT_RESOURCE);
        return NULL;
    }
    sparc64_copyout_t *copyout = malloc(sizeof(*copyout) + count * sizeof(copyout->pages[0]));
    if (copyout == NULL) {
        (void)fail(space, address, SPARC64_FAULT_RESOURCE);
        return NULL;
    }
    *copyout = (sparc64_copyout_t){
        .space = space, .address = address, .generation = space->generation,
        .maximum = maximum
    };
    if (count != 0 && space->managed.commitv != NULL) {
        copyout->touches = malloc(count * sizeof(*copyout->touches));
        if (copyout->touches == NULL) {
            (void)fail(space, address, SPARC64_FAULT_RESOURCE);
            sparc64_space_copyout_discard(copyout);
            return NULL;
        }
        memcpy(copyout->touches, space->epoch_scratch,
               count * sizeof(*copyout->touches));
    }
    for (size_t i = 0; i < count; ++i) {
        uint64_t base = (address & ~(SPARC64_PAGE_SIZE - 1)) + (uint64_t)i * SPARC64_PAGE_SIZE;
        sparc64_page_t *page = &space->pages[page_position(space, base)];
        if (!sparc64_backing_retain(page->backing)) {
            (void)fail(space, base, SPARC64_FAULT_INTERNAL);
            sparc64_space_copyout_discard(copyout);
            return NULL;
        }
        copyout->pages[i] = (copyout_page_t){
            .address = base, .binding_base = page->binding_base,
            .permissions = page->permissions, .backing = page->backing
        };
        ++copyout->count;
    }
    return copyout;
}

void sparc64_space_copyout_discard(sparc64_copyout_t *copyout)
{
    if (copyout == NULL)
        return;
    for (size_t i = 0; i < copyout->count; ++i)
        sparc64_backing_release(copyout->pages[i].backing);
    free(copyout->touches);
    free(copyout);
}

sparc64_io_copyout_t *sparc64_space_io_copyout_prepare(sparc64_space_t *space, uint64_t address,
                                            size_t maximum)
{
    sparc64_copyout_t *pinned = sparc64_space_copyout_prepare(space, address, maximum);
    if (pinned == NULL)
        return NULL;
    if (pinned->count > (SIZE_MAX - sizeof(sparc64_io_copyout_t)) / sizeof(epoch_touch_t)) {
        (void)fail(space, address, SPARC64_FAULT_RESOURCE);
        sparc64_space_copyout_discard(pinned);
        return NULL;
    }
    sparc64_io_copyout_t *copyout = malloc(sizeof(*copyout) +
                                     pinned->count * sizeof(copyout->touches[0]));
    if (copyout == NULL) {
        (void)fail(space, address, SPARC64_FAULT_RESOURCE);
        sparc64_space_copyout_discard(pinned);
        return NULL;
    }
    copyout->pinned = pinned;
    copyout->consumed = false;
    uint64_t cursor = address;
    size_t remaining = maximum;
    for (size_t i = 0; i < pinned->count; ++i) {
        size_t offset = (size_t)(cursor & (SPARC64_PAGE_SIZE - 1));
        size_t amount = (size_t)SPARC64_PAGE_SIZE - offset;
        if (amount > remaining)
            amount = remaining;
        copyout->touches[i] = (epoch_touch_t){
            .payload = pinned->pages[i].backing->payload,
            .view = pinned->pages[i].backing, .address = cursor,
            .first = offset / SPARC64_RESERVATION_GRANULE,
            .last = (offset + amount - 1) / SPARC64_RESERVATION_GRANULE,
            .amount = amount
        };
        cursor += amount;
        remaining -= amount;
    }
    qsort(copyout->touches, pinned->count, sizeof(copyout->touches[0]),
           compare_epoch_touches);
    return copyout;
}

void sparc64_space_io_copyout_discard(sparc64_io_copyout_t *copyout)
{
    if (copyout != NULL) {
        sparc64_space_copyout_discard(copyout->pinned);
        free(copyout);
    }
}

/* The sorted plan is immutable while unlocked. Recheck counter capacity from
 * the refreshed, current payloads without touching shared scratch or allocating.
 * Multiple aliases of one granule consume one epoch for each VA hit. */
static bool io_copyout_capacity(sparc64_io_copyout_t *copyout, size_t prefix)
{
    sparc64_copyout_t *pinned = copyout->pinned;
    sparc64_space_t *space = pinned->space;
    if (space->generation == UINT64_MAX)
        return fail(space, pinned->address, SPARC64_FAULT_INTERNAL);
    uint64_t end = pinned->address + (uint64_t)prefix;
    size_t next = 0;
    while (next < pinned->count) {
        sparc64_page_payload_t *payload = copyout->touches[next].payload;
        uint32_t counts[SPARC64_PAGE_GRANULES] = {0};
        bool touched = false, cow = false, file = false;
        while (next < pinned->count && copyout->touches[next].payload == payload) {
            const epoch_touch_t *hit = &copyout->touches[next++];
            if (hit->address >= end)
                continue;
            touched = true;
            file = file || hit->view->file != NULL;
            cow = cow || first_managed_file_write(hit->view);
            size_t amount = hit->amount;
            if ((uint64_t)amount > end - hit->address)
                amount = (size_t)(end - hit->address);
            size_t offset = (size_t)(hit->address & (SPARC64_PAGE_SIZE - 1));
            size_t last = (offset + amount - 1) / SPARC64_RESERVATION_GRANULE;
            for (size_t granule = hit->first; granule <= last; ++granule) {
                ++counts[granule];
                if (payload->epochs[granule] > UINT64_MAX - counts[granule])
                    return fail(space, hit->address, SPARC64_FAULT_INTERNAL);
            }
        }
        if (cow)
            for (size_t i = 0; i < SPARC64_PAGE_GRANULES; ++i)
                if (payload->epochs[i] == UINT64_MAX ||
                    payload->epochs[i] > UINT64_MAX - counts[i] - 1u)
                    return fail(space, pinned->address, SPARC64_FAULT_INTERNAL);
        if (touched && payload->backend == SPARC64_PAYLOAD_MANAGED &&
            !space->managed.check_write(space->managed.context, payload, file, false))
            return fail(space, pinned->address, SPARC64_FAULT_INTERNAL);
    }
    return true;
}

/* The preparation scratch is sorted by payload, then guest VA. Thus every
 * alias contributes in guest-address order and each managed payload is
 * committed once. Normal I/O uses the installed backend: input may already
 * have been consumed, so it cannot allocate, refresh or discover new capacity
 * failure here. Only the four-byte transaction supplies an explicit callback,
 * which may fail before committing its external state. */
static bool write_managed_bytes(sparc64_space_t *space, uint64_t address,
                                const unsigned char *bytes, size_t size,
                                const epoch_touch_t *touches, size_t count,
                                bool *published, sparc64_space_word_commit_fn commit,
                                void *context, bool *commit_called)
{
    uint64_t end = address + (uint64_t)size;
    size_t next = 0;
    while (next < count) {
        sparc64_managed_page_update_t updates[2] = {0};
        size_t staged = 0;
        while (next < count && staged < 2) {
            size_t first = next;
            sparc64_page_payload_t *payload = touches[first].payload;
            do {
                ++next;
            } while (next < count && touches[next].payload == payload);
            if (payload->backend != SPARC64_PAYLOAD_MANAGED)
                continue;
            bool used = false;
            for (size_t i = first; i < next; ++i)
                if (touches[i].address < end)
                    used = true;
            if (!used)
                continue;
            sparc64_managed_page_update_t *update = &updates[staged++];
            update->payload = payload;
            memcpy(update->bytes, payload->bytes, SPARC64_PAGE_SIZE);
            memcpy(update->epochs, payload->epochs,
                   SPARC64_PAGE_GRANULES * sizeof(uint64_t));
            for (size_t i = first; i < next; ++i)
                if (touches[i].address < end && first_managed_file_write(touches[i].view))
                    update->make_private_cow = true;
            if (update->make_private_cow)
                for (size_t i = 0; i < SPARC64_PAGE_GRANULES; ++i)
                    ++update->epochs[i];
            for (size_t i = first; i < next; ++i) {
                const epoch_touch_t *hit = &touches[i];
                if (hit->address >= end)
                    continue;
                size_t amount = hit->amount;
                if ((uint64_t)amount > end - hit->address)
                    amount = (size_t)(end - hit->address);
                size_t offset = (size_t)(hit->address & (SPARC64_PAGE_SIZE - 1));
                size_t last = (offset + amount - 1) / SPARC64_RESERVATION_GRANULE;
                for (size_t granule = offset / SPARC64_RESERVATION_GRANULE;
                     granule <= last; ++granule)
                    ++update->epochs[granule];
                memcpy(update->bytes + offset,
                       bytes + (size_t)(hit->address - address), amount);
            }
        }
        if (staged == 0)
            continue;
        bool success;
        if (commit != NULL) {
            if (*commit_called)
                return fail(space, address, SPARC64_FAULT_INTERNAL);
            *commit_called = true;
            errno = 0;
            success = commit(context, updates, staged);
        } else
            success = space->managed.commitv(space->managed.context, updates, staged);
        if (!success)
            return fail(space, address, commit != NULL && errno == ENOMEM ?
                        SPARC64_FAULT_RESOURCE : SPARC64_FAULT_INTERNAL);
        if (!*published) {
            ++space->generation;
            *published = true;
        }
    }
    return true;
}

static bool write_prepared_bytes(sparc64_space_t *space, uint64_t address,
                                  const void *bytes, size_t size,
                                  const epoch_touch_t *touches,
                                  size_t touch_count,
                                  sparc64_space_word_commit_fn commit, void *context)
{
    bool published = false;
    bool commit_called = false;
    if (space->managed.commitv != NULL && size != 0 &&
        !write_managed_bytes(space, address, bytes, size, touches,
                             touch_count, &published, commit, context,
                             &commit_called))
        return false;
    /* A private/file-COW word still has external waiter rows to commit.
     * The remaining heap mutation is infallible and stays under the guard. */
    if (commit != NULL && !commit_called) {
        errno = 0;
        if (!commit(context, NULL, 0))
            return fail(space, address, errno == ENOMEM ?
                        SPARC64_FAULT_RESOURCE : SPARC64_FAULT_INTERNAL);
    }
    uint64_t cursor = address;
    size_t remaining = size;
    while (remaining != 0) {
        uint64_t base = cursor & ~(SPARC64_PAGE_SIZE - 1);
        sparc64_backing_t *backing = space->pages[page_position(space, base)].backing;
        size_t offset = (size_t)(cursor - base);
        size_t amount = (size_t)SPARC64_PAGE_SIZE - offset;
        if (amount > remaining)
            amount = remaining;
        if (backing->payload->backend == SPARC64_PAYLOAD_HEAP) {
            if (!published) {
                ++space->generation;
                published = true;
            }
            size_t last = (offset + amount - 1) / SPARC64_RESERVATION_GRANULE;
            for (size_t i = offset / SPARC64_RESERVATION_GRANULE; i <= last; ++i)
                ++backing->epochs[i];
        }
        cursor += amount;
        remaining -= amount;
    }
    const unsigned char *in = bytes;
    while (size != 0) {
        uint64_t base = address & ~(SPARC64_PAGE_SIZE - 1);
        size_t position = page_position(space, base);
        size_t offset = (size_t)(address - base);
        size_t amount = (size_t)SPARC64_PAGE_SIZE - offset;
        if (amount > size)
            amount = size;
        sparc64_backing_t *backing = space->pages[position].backing;
        if (backing->file != NULL && backing->payload->backend == SPARC64_PAYLOAD_MANAGED)
            backing->private_cow = *backing->payload->canonical_private_cow != 0;
        if (backing->payload->backend == SPARC64_PAYLOAD_HEAP) {
            if (backing->file != NULL)
                backing->private_cow = true;
            memcpy(backing->bytes + offset, in, amount);
        }
        address += amount;
        in += amount;
        size -= amount;
    }
    return true;
}

bool sparc64_space_io_copyout_commit(sparc64_io_copyout_t *copyout, const void *bytes,
                                 size_t actual, size_t *committed)
{
    if (committed != NULL)
        *committed = 0;
    if (copyout == NULL)
        return false;
    sparc64_copyout_t *pinned = copyout->pinned;
    sparc64_space_t *space = pinned->space;
    if (copyout->consumed)
        return fail(space, pinned->address, SPARC64_FAULT_INTERNAL);
    copyout->consumed = true;
    if (committed == NULL)
        return fail(space, pinned->address, SPARC64_FAULT_INTERNAL);
    if (actual > pinned->maximum || (actual != 0 && bytes == NULL))
        return fail(space, pinned->address, SPARC64_FAULT_INTERNAL);
    if (actual == 0)
        return true;
    space->fault_reason = SPARC64_FAULT_NONE;
    if (!managed_guard(space, pinned->address))
        return false;
    size_t prefix = 0;
    for (size_t i = 0; prefix < actual; ++i) {
        const copyout_page_t *saved = &pinned->pages[i];
        uint64_t cursor = pinned->address + (uint64_t)prefix;
        size_t position = page_position(space, saved->address);
        if (position == space->count ||
            space->pages[position].address != saved->address) {
            (void)fail(space, cursor, SPARC64_FAULT_UNMAPPED);
            break;
        }
        const sparc64_page_t *current = &space->pages[position];
        if (current->backing != saved->backing ||
            current->binding_base != saved->binding_base) {
            (void)fail(space, cursor, SPARC64_FAULT_UNMAPPED);
            break;
        }
        if ((current->permissions & SPARC64_MEM_WRITE) == 0) {
            (void)fail(space, cursor, SPARC64_FAULT_PERMISSION);
            break;
        }
        size_t amount = (size_t)(SPARC64_PAGE_SIZE - (cursor & (SPARC64_PAGE_SIZE - 1)));
        if (amount > actual - prefix)
            amount = actual - prefix;
        if (!validate_access(space, cursor, amount, SPARC64_MEM_WRITE)) {
            if (sparc64_fault_is_runtime(space->fault_reason))
                return false;
            break;
        }
        prefix += amount;
    }
    if (prefix == 0)
        return false;
    sparc64_fault_reason_t reason = space->fault_reason;
    uint64_t fault = space->fault_address;
    if (!io_copyout_capacity(copyout, prefix) ||
        !write_prepared_bytes(space, pinned->address, bytes, prefix,
                              copyout->touches, pinned->count, NULL, NULL))
        return false;
    *committed = prefix;
    if (prefix != actual) {
        space->fault_reason = reason;
        space->fault_address = fault;
    }
    return prefix == actual;
}

bool sparc64_space_copyout_commit(sparc64_copyout_t *copyout, const void *bytes,
                              size_t actual)
{
    if (copyout == NULL)
        return false;
    sparc64_space_t *space = copyout->space;
    if (copyout->consumed)
        return fail(space, copyout->address, SPARC64_FAULT_INTERNAL);
    copyout->consumed = true;
    if (actual > copyout->maximum || (actual != 0 && bytes == NULL))
        return fail(space, copyout->address, SPARC64_FAULT_INTERNAL);
    if (actual == 0)
        return true;
    if (space->generation != copyout->generation ||
        !managed_guard(space, copyout->address))
        return fail(space, copyout->address, SPARC64_FAULT_INTERNAL);
    for (size_t i = 0; i < copyout->count; ++i) {
        copyout_page_t *saved = &copyout->pages[i];
        size_t position = page_position(space, saved->address);
        if (position == space->count)
            return fail(space, saved->address, SPARC64_FAULT_INTERNAL);
        sparc64_page_t *page = &space->pages[position];
        if (page->address != saved->address || page->backing != saved->backing ||
            page->binding_base != saved->binding_base ||
            page->permissions != saved->permissions)
            return fail(space, saved->address, SPARC64_FAULT_INTERNAL);
    }
    return write_prepared_bytes(space, copyout->address, bytes, actual,
                                copyout->touches, copyout->count, NULL, NULL);
}

static bool write_bytes(sparc64_space_t *space, uint64_t address, const void *bytes,
                         size_t size, unsigned int permissions)
{
    if (space == NULL)
        return false;
    if (bytes == NULL && size != 0)
        return fail(space, address, SPARC64_FAULT_INTERNAL);
    if (!prepare_write(space, address, size, permissions))
        return false;
    size_t count = 0;
    if (size != 0) {
        uint64_t last = address + (uint64_t)size - 1;
        count = (size_t)(last / SPARC64_PAGE_SIZE - address / SPARC64_PAGE_SIZE + 1);
    }
    return write_prepared_bytes(space, address, bytes, size,
                                space->managed.commitv == NULL ? NULL :
                                space->epoch_scratch, count, NULL, NULL);
}

bool sparc64_space_write_word_commit(sparc64_space_t *space, uint64_t address,
                                const unsigned char bytes[4],
                                sparc64_space_word_commit_fn commit, void *context)
{
    if (space == NULL)
        return false;
    if (bytes == NULL || commit == NULL)
        return fail(space, address, SPARC64_FAULT_INTERNAL);
    if (!prepare_write(space, address, 4, SPARC64_MEM_WRITE))
        return false;
    size_t count = (size_t)((address + 3) / SPARC64_PAGE_SIZE -
                            address / SPARC64_PAGE_SIZE + 1);
    return write_prepared_bytes(space, address, bytes, 4,
                                space->managed.commitv == NULL ? NULL :
                                space->epoch_scratch, count, commit, context);
}

bool sparc64_space_write(sparc64_space_t *space, uint64_t address, const void *bytes,
                    size_t size)
{
    return write_bytes(space, address, bytes, size, SPARC64_MEM_WRITE);
}

bool sparc64_space_write_initial(sparc64_space_t *space, uint64_t address,
                            const void *bytes, size_t size)
{
    return write_bytes(space, address, bytes, size, 0);
}

bool sparc64_space_atomic(sparc64_space_t *space, const sparc64_atomic_request_t *request,
                      sparc64_atomic_result_t *result)
{
    if (space == NULL || request == NULL || result == NULL)
        return false;
    memset(result, 0, sizeof(*result));
    if ((request->width != 4 && request->width != 8) ||
        (request->address & (request->width - 1u)) != 0 ||
        request->op < SPARC64_ATOMIC_LR || request->op > SPARC64_ATOMIC_MAXU)
        return fail(space, request->address, SPARC64_FAULT_INTERNAL);
    unsigned int permission = request->op == SPARC64_ATOMIC_LR ? SPARC64_MEM_READ :
                              request->op == SPARC64_ATOMIC_SC ? SPARC64_MEM_WRITE :
                              SPARC64_MEM_READ | SPARC64_MEM_WRITE;
    if (!validate_access(space, request->address, request->width, permission))
        return false;
    uint64_t base = request->address & ~(SPARC64_PAGE_SIZE - 1);
    sparc64_page_t *page = &space->pages[page_position(space, base)];
    size_t offset = (size_t)(request->address - base);
    size_t granule = offset / SPARC64_RESERVATION_GRANULE;
    sparc64_reservation_token_t current = {page->binding_base + granule,
                                      page->backing->epochs[granule]};
    if (request->op == SPARC64_ATOMIC_SC &&
        (!request->reservation_valid ||
         request->reservation.binding_id != current.binding_id ||
         request->reservation.write_epoch != current.write_epoch))
        return true;
    uint64_t old = 0;
    for (unsigned int i = 0; i < request->width; ++i)
        old |= (uint64_t)page->backing->bytes[offset + i] << (i * 8);
    if (request->op == SPARC64_ATOMIC_LR) {
        result->old_value = old;
        result->reservation = current;
        return true;
    }
    uint64_t mask = request->width == 4 ? UINT32_MAX : UINT64_MAX;
    uint64_t sign = UINT64_C(1) << (request->width * 8 - 1);
    uint64_t value = request->value & mask, replacement = value;
    switch (request->op) {
    case SPARC64_ATOMIC_SC: case SPARC64_ATOMIC_SWAP: break;
    case SPARC64_ATOMIC_ADD: replacement = (old + value) & mask; break;
    case SPARC64_ATOMIC_XOR: replacement = old ^ value; break;
    case SPARC64_ATOMIC_AND: replacement = old & value; break;
    case SPARC64_ATOMIC_OR: replacement = old | value; break;
    case SPARC64_ATOMIC_MIN: replacement = (old ^ sign) < (value ^ sign) ? old : value; break;
    case SPARC64_ATOMIC_MAX: replacement = (old ^ sign) > (value ^ sign) ? old : value; break;
    case SPARC64_ATOMIC_MINU: replacement = old < value ? old : value; break;
    case SPARC64_ATOMIC_MAXU: replacement = old > value ? old : value; break;
    case SPARC64_ATOMIC_LR: return false; /* handled above */
    }
    unsigned char bytes[8];
    for (unsigned int i = 0; i < request->width; ++i)
        bytes[i] = (unsigned char)(replacement >> (i * 8));
    if (!sparc64_space_write(space, request->address, bytes, request->width))
        return false;
    result->old_value = old;
    result->sc_success = request->op == SPARC64_ATOMIC_SC;
    return true;
}
