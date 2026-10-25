/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#include "runtime/family_shmem.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

enum { SHMEM_HEADER = 64, SHMEM_RECORD = 16, SHMEM_SCHEMA = 1 };
static const unsigned char shmem_magic[8] = {'R', 'V', 'R', 'T', 'S', 'H', 'M', 0};

static void shmem_put(unsigned char *bytes, uint64_t value, size_t size)
{
    for (size_t i = 0; i < size; ++i)
        bytes[i] = (unsigned char)(value >> (i * 8u));
}

static uint64_t shmem_get(const unsigned char *bytes, size_t size)
{
    uint64_t value = 0;
    for (size_t i = 0; i < size; ++i)
        value |= (uint64_t)bytes[i] << (i * 8u);
    return value;
}

static bool shmem_zero(const unsigned char *bytes, size_t size)
{
    for (size_t i = 0; i < size; ++i)
        if (bytes[i] != 0)
            return false;
    return true;
}

static bool shmem_extent(uint64_t extent, size_t count, size_t *length, uint32_t *slots)
{
    if (extent == 0 || extent % SPARC64_FAMILY_PAGE_SIZE != 0 || count == 0 ||
        count > SPARC64_FAMILY_SHMEM_MAX_PAGES || extent / SPARC64_FAMILY_PAGE_SIZE != count)
        return false;
    size_t bytes = SHMEM_HEADER + count * SHMEM_RECORD;
    size_t pages = (bytes + SPARC64_FAMILY_PAGE_SIZE - 1u) / SPARC64_FAMILY_PAGE_SIZE;
    if (pages > SPARC64_FAMILY_OBJECT_MAX_SLOTS)
        return false;
    *length = bytes; *slots = (uint32_t)pages;
    return true;
}

static int shmem_key_compare(const void *a, const void *b)
{
    const sparc64_family_page_key_t *x = a, *y = b;
    if (x->object_id != y->object_id)
        return (x->object_id > y->object_id) - (x->object_id < y->object_id);
    return (x->page_index > y->page_index) - (x->page_index < y->page_index);
}

static int shmem_validate_keys(sparc64_family_guard_t *guard,
                                 const sparc64_family_shmem_state_t *state)
{
    sparc64_family_page_key_t *keys = malloc(state->page_count * sizeof(*keys));
    if (keys == NULL)
        return -1;
    memcpy(keys, state->pages, state->page_count * sizeof(*keys));
    qsort(keys, state->page_count, sizeof(*keys), shmem_key_compare);
    sparc64_family_object_t *object = NULL;
    uint64_t id = 0;
    int result = -1, saved = EINVAL;
    for (size_t i = 0; i < state->page_count; ++i) {
        if (keys[i].object_id == 0 || (i != 0 && shmem_key_compare(&keys[i - 1u], &keys[i]) == 0))
            goto done;
        if (keys[i].object_id != id) {
            sparc64_family_object_close(object); object = NULL;
            if (sparc64_family_object_open(guard, keys[i].object_id, &object) != 0) {
                saved = errno; goto done;
            }
            id = keys[i].object_id;
        }
        if (keys[i].page_index >= sparc64_family_object_count(object))
            goto done;
    }
    result = 0;
done:
    sparc64_family_object_close(object); free(keys);
    if (result != 0)
        errno = saved;
    return result;
}

void sparc64_family_shmem_state_destroy(sparc64_family_shmem_state_t *state)
{
    if (state != NULL) {
        free(state->pages); *state = (sparc64_family_shmem_state_t){0};
    }
}

int sparc64_family_shmem_create(sparc64_family_guard_t *guard,
                             const sparc64_family_shmem_state_t *state,
                             sparc64_family_shmem_t *out)
{
    size_t length;
    uint32_t slots;
    if (out == NULL || state == NULL || state->pages == NULL ||
        !shmem_extent(state->extent, state->page_count, &length, &slots)) {
        errno = EINVAL; return -1;
    }
    if (shmem_validate_keys(guard, state) != 0)
        return -1;
    unsigned char *bytes = calloc(slots, SPARC64_FAMILY_PAGE_SIZE);
    if (bytes == NULL)
        return -1;
    sparc64_family_object_t *object = NULL;
    int result = -1, saved = 0;
    if (sparc64_family_object_create(guard, slots, &object) != 0) { saved = errno; goto done; }
    uint64_t id = sparc64_family_object_id(object);
    memcpy(bytes, shmem_magic, sizeof(shmem_magic));
    shmem_put(bytes + 8, SHMEM_SCHEMA, 4); shmem_put(bytes + 12, SHMEM_HEADER, 4);
    shmem_put(bytes + 16, id, 8); shmem_put(bytes + 24, state->extent, 8);
    shmem_put(bytes + 32, state->page_count, 8); shmem_put(bytes + 40, length, 8);
    shmem_put(bytes + 48, slots, 8);
    for (size_t i = 0; i < state->page_count; ++i) {
        unsigned char *record = bytes + SHMEM_HEADER + i * SHMEM_RECORD;
        shmem_put(record, state->pages[i].object_id, 8);
        shmem_put(record + 8, state->pages[i].page_index, 4);
    }
    for (uint32_t i = 0; i < slots; ++i) {
        sparc64_family_page_state_t page;
        if (sparc64_family_object_snapshot(guard, object, i, &page) != 0) { saved = errno; goto done; }
        if (page.content_generation == UINT64_MAX) { saved = EOVERFLOW; goto done; }
        for (size_t j = 0; j < SPARC64_FAMILY_EPOCHS; ++j) {
            if (page.epochs[j] == UINT64_MAX) { saved = EOVERFLOW; goto done; }
            ++page.epochs[j];
        }
        ++page.content_generation;
        memcpy(page.bytes, bytes + (size_t)i * SPARC64_FAMILY_PAGE_SIZE, SPARC64_FAMILY_PAGE_SIZE);
        if (sparc64_family_object_commit(guard, object, i, &page) != 0) { saved = errno; goto done; }
    }
    *out = (sparc64_family_shmem_t){id}; result = 0;
done:
    sparc64_family_object_close(object); free(bytes);
    if (result != 0)
        errno = saved;
    return result;
}

int sparc64_family_shmem_read(sparc64_family_guard_t *guard, sparc64_family_shmem_t shmem,
                           sparc64_family_shmem_state_t *out)
{
    if (out == NULL || shmem.object_id == 0) { errno = EINVAL; return -1; }
    sparc64_family_object_t *object = NULL;
    if (sparc64_family_object_open(guard, shmem.object_id, &object) != 0)
        return -1;
    int result = -1, saved = EIO;
    sparc64_family_page_state_t first;
    sparc64_family_shmem_state_t state = {0};
    if (sparc64_family_object_snapshot(guard, object, 0, &first) != 0) { saved = errno; goto done; }
    uint64_t count = shmem_get(first.bytes + 32, 8);
    size_t length;
    uint32_t slots;
    if (memcmp(first.bytes, shmem_magic, sizeof(shmem_magic)) != 0 ||
        shmem_get(first.bytes + 8, 4) != SHMEM_SCHEMA ||
        shmem_get(first.bytes + 12, 4) != SHMEM_HEADER ||
        shmem_get(first.bytes + 16, 8) != shmem.object_id ||
        count > SPARC64_FAMILY_SHMEM_MAX_PAGES ||
        !shmem_extent(shmem_get(first.bytes + 24, 8), (size_t)count, &length, &slots) ||
        shmem_get(first.bytes + 40, 8) != length || shmem_get(first.bytes + 48, 8) != slots ||
        !shmem_zero(first.bytes + 56, 8) || sparc64_family_object_count(object) != slots)
        goto done;
    state.extent = shmem_get(first.bytes + 24, 8); state.page_count = (size_t)count;
    state.pages = calloc(state.page_count, sizeof(*state.pages));
    if (state.pages == NULL) { saved = errno; goto done; }
    for (uint32_t i = 0; i < slots; ++i) {
        sparc64_family_page_state_t page;
        if (i == 0)
            page = first;
        else if (sparc64_family_object_snapshot(guard, object, i, &page) != 0) {
            saved = errno; goto done;
        }
        size_t start = i == 0 ? SHMEM_HEADER : 0;
        size_t base = (size_t)i * SPARC64_FAMILY_PAGE_SIZE;
        for (size_t at = start; at < SPARC64_FAMILY_PAGE_SIZE; at += SHMEM_RECORD) {
            if (base + at >= length) {
                if (!shmem_zero(page.bytes + at, SPARC64_FAMILY_PAGE_SIZE - at))
                    goto done;
                break;
            }
            size_t index = (base + at - SHMEM_HEADER) / SHMEM_RECORD;
            if (!shmem_zero(page.bytes + at + 12, 4))
                goto done;
            state.pages[index] = (sparc64_family_page_key_t){shmem_get(page.bytes + at, 8),
                (uint32_t)shmem_get(page.bytes + at + 8, 4)};
        }
    }
    if (shmem_validate_keys(guard, &state) != 0) {
        saved = errno == ENOMEM ? ENOMEM : EIO; goto done;
    }
    sparc64_family_shmem_state_destroy(out); *out = state;
    state = (sparc64_family_shmem_state_t){0}; result = 0;
done:
    sparc64_family_shmem_state_destroy(&state); sparc64_family_object_close(object);
    if (result != 0)
        errno = saved;
    return result;
}
