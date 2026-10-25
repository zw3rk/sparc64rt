/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#include "runtime/family_mm.h"
#include "runtime/family_wait.h"
#include "runtime/family_file_index.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

enum { HEADER_BYTES = 144, VMA_BYTES = 48, PAGE_BYTES = 48,
       MEMBER_BYTES = 16, SHARED_BYTES = 16, FILE_ASSOC_BYTES = 32,
       SCHEMA_VERSION = 4 };

typedef struct {
    sparc64_family_mm_t mm;
    uint64_t snapshot, length;
    sparc64_family_mm_state_t state;
} mm_header_t;

static void put_word(unsigned char *bytes, uint64_t value, size_t size)
{
    for (size_t i = 0; i < size; ++i)
        bytes[i] = (unsigned char)(value >> (i * 8u));
}

static uint64_t get_word(const unsigned char *bytes, size_t size)
{
    uint64_t value = 0;
    for (size_t i = 0; i < size; ++i)
        value |= (uint64_t)bytes[i] << (i * 8u);
    return value;
}

static bool all_zero(const unsigned char *bytes, size_t size)
{
    for (size_t i = 0; i < size; ++i)
        if (bytes[i] != 0)
            return false;
    return true;
}

static bool extent(const sparc64_family_mm_state_t *state, size_t *length,
                     uint32_t *slots)
{
    if (state->vma_count > SPARC64_FAMILY_MM_MAX_RECORDS ||
        state->page_count > SPARC64_FAMILY_MM_MAX_RECORDS ||
        state->member_count > SPARC64_FAMILY_MM_MAX_RECORDS ||
        state->shared_source_count > SPARC64_FAMILY_MM_MAX_RECORDS ||
        state->file_assoc_count > SPARC64_FAMILY_MM_MAX_RECORDS)
        return false;
    /* Counts are bounded before multiplication; valid even on 32-bit hosts. */
    size_t bytes = HEADER_BYTES + state->vma_count * VMA_BYTES +
                   state->page_count * PAGE_BYTES + state->member_count * MEMBER_BYTES +
                   state->shared_source_count * SHARED_BYTES +
                   state->file_assoc_count * FILE_ASSOC_BYTES;
    size_t count = (bytes + SPARC64_FAMILY_PAGE_SIZE - 1u) / SPARC64_FAMILY_PAGE_SIZE;
    if (count == 0 || count > SPARC64_FAMILY_OBJECT_MAX_SLOTS)
        return false;
    *length = bytes;
    *slots = (uint32_t)count;
    return true;
}

static int compare_mapping_id(const void *a, const void *b)
{
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
    return (x > y) - (x < y);
}

static int compare_key(const void *a, const void *b)
{
    const sparc64_family_page_key_t *x = a, *y = b;
    if (x->object_id != y->object_id)
        return (x->object_id > y->object_id) - (x->object_id < y->object_id);
    return (x->page_index > y->page_index) - (x->page_index < y->page_index);
}

int sparc64_family_mm_shared_append(sparc64_family_mm_state_t *state, uint64_t backing_id,
                                 sparc64_family_shmem_t manifest)
{
    if (state == NULL || backing_id == 0 || backing_id >= state->next_vma_id ||
        manifest.object_id == 0 || state->shared_source_count >= SPARC64_FAMILY_MM_MAX_RECORDS ||
        (state->shared_source_count != 0 && (state->shared_sources == NULL ||
         state->shared_sources[state->shared_source_count - 1u].backing_id >= backing_id))) {
        errno = EINVAL; return -1;
    }
    size_t count = state->shared_source_count;
    sparc64_family_mm_shared_source_t *sources = malloc((count + 1u) * sizeof(*sources));
    if (sources == NULL)
        return -1;
    if (count != 0)
        memcpy(sources, state->shared_sources, count * sizeof(*sources));
    sources[count] = (sparc64_family_mm_shared_source_t){backing_id, manifest};
    free(state->shared_sources); state->shared_sources = sources;
    state->shared_source_count = count + 1u;
    return 0;
}

int sparc64_family_mm_file_assoc_insert(sparc64_family_mm_state_t *state,
                                    sparc64_family_mm_file_assoc_t association)
{
    if (state == NULL || association.key.object_id == 0 ||
        association.key.page_index >= SPARC64_FAMILY_OBJECT_MAX_SLOTS ||
        association.source_id == 0 ||
        association.file_offset % SPARC64_FAMILY_PAGE_SIZE != 0 ||
        association.file_offset > INT64_MAX ||
        state->file_assoc_count > SPARC64_FAMILY_MM_MAX_RECORDS ||
        (state->file_assoc_count != 0 && state->file_assocs == NULL)) {
        errno = EINVAL; return -1;
    }
    size_t at = 0;
    while (at < state->file_assoc_count &&
           compare_key(&state->file_assocs[at].key, &association.key) < 0)
        ++at;
    if (at < state->file_assoc_count &&
        compare_key(&state->file_assocs[at].key, &association.key) == 0) {
        if (state->file_assocs[at].source_id == association.source_id &&
            state->file_assocs[at].file_offset == association.file_offset)
            return 0;
        errno = EEXIST; return -1;
    }
    if (state->file_assoc_count == SPARC64_FAMILY_MM_MAX_RECORDS) {
        errno = ENOSPC; return -1;
    }
    size_t count = state->file_assoc_count;
    sparc64_family_mm_file_assoc_t *rows = malloc((count + 1u) * sizeof(*rows));
    if (rows == NULL)
        return -1;
    if (at != 0)
        memcpy(rows, state->file_assocs, at * sizeof(*rows));
    rows[at] = association;
    if (at != count)
        memcpy(rows + at + 1u, state->file_assocs + at,
               (count - at) * sizeof(*rows));
    free(state->file_assocs);
    state->file_assocs = rows;
    state->file_assoc_count = count + 1u;
    return 0;
}

static const sparc64_family_mm_file_assoc_t *file_assoc_find(
    const sparc64_family_mm_state_t *state, sparc64_family_page_key_t key)
{
    size_t left = 0, right = state->file_assoc_count;
    while (left < right) {
        size_t middle = left + (right - left) / 2u;
        int order = compare_key(&state->file_assocs[middle].key, &key);
        if (order < 0) left = middle + 1u;
        else right = middle;
    }
    return left < state->file_assoc_count &&
        compare_key(&state->file_assocs[left].key, &key) == 0 ?
        &state->file_assocs[left] : NULL;
}

static int validate_shared(sparc64_family_guard_t *guard, const sparc64_family_mm_state_t *state)
{
    for (size_t i = 0; i < state->shared_source_count; ++i) {
        const sparc64_family_mm_shared_source_t *source = &state->shared_sources[i];
        if (source->backing_id == 0 || source->backing_id == state->brk_id ||
            source->backing_id >= state->next_vma_id ||
            source->manifest.object_id == 0 || (i != 0 &&
            state->shared_sources[i - 1u].backing_id >= source->backing_id)) {
            errno = EINVAL; return -1;
        }
        sparc64_family_shmem_state_t manifest = {0};
        if (sparc64_family_shmem_read(guard, source->manifest, &manifest) != 0)
            return -1;
        for (size_t page = 0; page < manifest.page_count; ++page)
            if (file_assoc_find(state, manifest.pages[page]) != NULL) {
                sparc64_family_shmem_state_destroy(&manifest);
                errno = EINVAL; return -1;
            }
        size_t page_at = 0;
        bool valid = true;
        for (size_t j = 0; valid && j < state->vma_count; ++j) {
            const sparc64_vma_t *vma = &state->vmas[j];
            size_t count = (size_t)((vma->end - vma->start) / SPARC64_FAMILY_PAGE_SIZE);
            if (vma->backing_id == source->backing_id) {
                if (vma->kind != SPARC64_VMA_ANONYMOUS_SHARED) {
                    valid = false; break;
                }
                for (size_t k = 0; k < count; ++k) {
                    const sparc64_family_mm_page_t *page = &state->pages[page_at + k];
                    uint64_t offset = vma->offset + (uint64_t)k * SPARC64_FAMILY_PAGE_SIZE;
                    if (offset >= manifest.extent ? page->kind != SPARC64_MM_BUS :
                        (page->kind != SPARC64_MM_DATA || compare_key(&page->key,
                         &manifest.pages[offset / SPARC64_FAMILY_PAGE_SIZE]) != 0)) {
                        valid = false; break;
                    }
                }
            }
            page_at += count;
        }
        sparc64_family_shmem_state_destroy(&manifest);
        if (!valid) { errno = EINVAL; return -1; }
    }
    for (size_t i = 0; i < state->vma_count; ++i) {
        if (state->vmas[i].kind != SPARC64_VMA_ANONYMOUS_SHARED)
            continue;
        bool found = false;
        for (size_t j = 0; j < state->shared_source_count; ++j)
            if (state->shared_sources[j].backing_id == state->vmas[i].backing_id) {
                found = true; break;
            }
        if (!found) { errno = EINVAL; return -1; }
    }
    return 0;
}

static const sparc64_family_file_index_assoc_t *global_association(
    const sparc64_family_file_index_state_t *index, sparc64_family_page_key_t key)
{
    size_t left = 0, right = index->association_count;
    while (left < right) {
        size_t middle = left + (right - left) / 2u;
        if (compare_key(&index->associations[middle].key, &key) < 0) left = middle + 1u;
        else right = middle;
    }
    return left < index->association_count &&
        compare_key(&index->associations[left].key, &key) == 0 ? &index->associations[left] : NULL;
}

/* All entry points, including unchanged-revision reads, consult family-wide
 * origins. A local MM snapshot cannot authorize an old file key as anonymous. */
static int validate_global(sparc64_family_guard_t *guard, const sparc64_family_mm_state_t *state)
{
    uint64_t root = sparc64_family_file_index_object(guard);
    if (root == 0) {
        if (errno == EOPNOTSUPP && state->file_assoc_count == 0)
            return 0;
        return -1;
    }
    sparc64_family_file_index_state_t index = {0};
    if (sparc64_family_file_index_read(guard, root, &index) != 0)
        return -1;
    int result = -1;
    for (size_t i = 0; i < state->file_assoc_count; ++i) {
        const sparc64_family_mm_file_assoc_t *local = &state->file_assocs[i];
        const sparc64_family_file_index_assoc_t *global = global_association(&index, local->key);
        if (global == NULL || global->source_id != local->source_id ||
            global->file_offset != local->file_offset) { errno = EINVAL; goto done; }
    }
    for (size_t i = 0; i < state->page_count; ++i) {
        const sparc64_family_mm_page_t *page = &state->pages[i];
        if (page->kind == SPARC64_MM_DATA && file_assoc_find(state, page->key) == NULL &&
            global_association(&index, page->key) != NULL) { errno = EINVAL; goto done; }
    }
    for (size_t i = 0; i < state->shared_source_count; ++i) {
        sparc64_family_shmem_state_t manifest = {0};
        if (sparc64_family_shmem_read(guard, state->shared_sources[i].manifest, &manifest) != 0)
            goto done;
        bool valid = true;
        for (size_t j = 0; j < manifest.page_count; ++j)
            if (global_association(&index, manifest.pages[j]) != NULL) { valid = false; break; }
        sparc64_family_shmem_state_destroy(&manifest);
        if (!valid) { errno = EINVAL; goto done; }
    }
    result = 0;
done: {
        int saved = errno;
        sparc64_family_file_index_state_destroy(&index);
        errno = saved;
        return result;
    }
}

static int validate(sparc64_family_guard_t *guard, const sparc64_family_mm_state_t *state)
{
    size_t length;
    uint32_t slots;
    if (state == NULL || !extent(state, &length, &slots) ||
        (state->vma_count != 0 && state->vmas == NULL) ||
        (state->page_count != 0 && state->pages == NULL) ||
        (state->member_count != 0 && state->members == NULL) ||
        (state->shared_source_count != 0 && state->shared_sources == NULL) ||
        (state->file_assoc_count != 0 && state->file_assocs == NULL) ||
        state->limit < SPARC64_FAMILY_PAGE_SIZE || state->limit > (UINT64_C(1) << 47) ||
        state->limit % SPARC64_FAMILY_PAGE_SIZE != 0 ||
        state->minimum_break >= state->limit || state->current_break < state->minimum_break ||
        state->current_break >= state->limit || state->brk_id == 0 ||
        state->brk_id >= state->next_vma_id || state->next_mapping_id == 0) {
        errno = EINVAL;
        return -1;
    }
    size_t page_count = 0;
    for (size_t i = 0; i < state->file_assoc_count; ++i) {
        const sparc64_family_mm_file_assoc_t *association = &state->file_assocs[i];
        if (association->key.object_id == 0 ||
            association->key.page_index >= SPARC64_FAMILY_OBJECT_MAX_SLOTS ||
            association->source_id == 0 ||
            association->file_offset % SPARC64_FAMILY_PAGE_SIZE != 0 ||
            association->file_offset > INT64_MAX ||
            (i != 0 && compare_key(&state->file_assocs[i - 1u].key,
                                   &association->key) >= 0))
            goto invalid;
    }
    for (size_t i = 0; i < state->vma_count; ++i) {
        const sparc64_vma_t *vma = &state->vmas[i];
        if (vma->kind != SPARC64_VMA_INITIAL && vma->kind != SPARC64_VMA_ANONYMOUS &&
            vma->kind != SPARC64_VMA_BRK && vma->kind != SPARC64_VMA_ANONYMOUS_SHARED &&
            vma->kind != SPARC64_VMA_FILE_PRIVATE)
            goto invalid;
        if (vma->start < SPARC64_FAMILY_PAGE_SIZE || vma->start >= vma->end ||
            vma->end > state->limit || vma->start % SPARC64_FAMILY_PAGE_SIZE != 0 ||
            vma->end % SPARC64_FAMILY_PAGE_SIZE != 0 ||
            (i != 0 && state->vmas[i - 1u].end > vma->start) ||
            vma->backing_id == 0 || vma->backing_id >= state->next_vma_id ||
            vma->offset % SPARC64_FAMILY_PAGE_SIZE != 0 ||
            vma->offset > UINT64_MAX - (vma->end - vma->start) ||
            (vma->may_permissions & ~7u) != 0 ||
            (vma->permissions & ~vma->may_permissions) != 0)
            goto invalid;
        uint64_t count = (vma->end - vma->start) / SPARC64_FAMILY_PAGE_SIZE;
        if (count > state->page_count - page_count)
            goto invalid;
        uint64_t file_source_id = 0;
        for (uint64_t j = 0; j < count; ++j) {
            const sparc64_family_mm_page_t *page = &state->pages[page_count++];
            unsigned int permissions = vma->permissions |
                ((vma->permissions & SPARC64_MEM_WRITE) != 0 ? SPARC64_MEM_READ : 0u);
            if (page->address != vma->start + j * SPARC64_FAMILY_PAGE_SIZE ||
                page->mapping_id == 0 || page->mapping_id >= state->next_mapping_id ||
                page->mapping_generation == 0 ||
                (page->kind != SPARC64_MM_DATA && page->kind != SPARC64_MM_BUS) ||
                (page->kind == SPARC64_MM_DATA && (page->key.object_id == 0 ||
                 page->key.page_index >= SPARC64_FAMILY_OBJECT_MAX_SLOTS)) ||
                (page->kind == SPARC64_MM_BUS && (vma->kind != SPARC64_VMA_ANONYMOUS_SHARED ||
                 page->key.object_id != 0 || page->key.page_index != 0)) ||
                page->permissions != permissions)
                goto invalid;
            const sparc64_family_mm_file_assoc_t *association =
                page->kind == SPARC64_MM_DATA ? file_assoc_find(state, page->key) : NULL;
            if (vma->kind == SPARC64_VMA_FILE_PRIVATE) {
                if (association == NULL ||
                    association->file_offset !=
                    vma->offset + j * SPARC64_FAMILY_PAGE_SIZE)
                    goto invalid;
                if (file_source_id != 0 &&
                    file_source_id != association->source_id)
                    goto invalid;
                file_source_id = association->source_id;
            } else if (association != NULL) {
                goto invalid;
            }
        }
        if (file_source_id != 0) {
            size_t prior_page = 0;
            for (size_t previous = 0; previous < i; ++previous) {
                const sparc64_vma_t *earlier = &state->vmas[previous];
                if (earlier->kind == SPARC64_VMA_FILE_PRIVATE &&
                    earlier->backing_id == vma->backing_id) {
                    const sparc64_family_mm_file_assoc_t *first = file_assoc_find(
                        state, state->pages[prior_page].key);
                    if (first == NULL || first->source_id != file_source_id)
                        goto invalid;
                }
                prior_page += (size_t)((earlier->end - earlier->start) /
                                       SPARC64_FAMILY_PAGE_SIZE);
            }
        }
    }
    if (page_count != state->page_count)
        goto invalid;
    for (size_t i = 0; i < state->member_count; ++i) {
        const sparc64_family_mm_member_t *member = &state->members[i];
        if (member->owner_incarnation == 0 || member->task_id == 0)
            goto invalid;
        if (i != 0) {
            const sparc64_family_mm_member_t *previous = &state->members[i - 1u];
            if (previous->owner_incarnation > member->owner_incarnation ||
                (previous->owner_incarnation == member->owner_incarnation &&
                 previous->task_id >= member->task_id))
                goto invalid;
        }
    }
    if (validate_shared(guard, state) != 0 || validate_global(guard, state) != 0)
        return -1;
    if (state->page_count == 0 && state->file_assoc_count == 0)
        return 0;
    uint64_t *mapping_ids = state->page_count == 0 ? NULL :
        malloc(state->page_count * sizeof(*mapping_ids));
    sparc64_family_page_key_t *keys = malloc(
        (state->page_count + state->file_assoc_count) * sizeof(*keys));
    if ((state->page_count != 0 && mapping_ids == NULL) || keys == NULL) {
        free(mapping_ids); free(keys);
        errno = ENOMEM;
        return -1;
    }
    size_t key_count = 0;
    for (size_t i = 0; i < state->page_count; ++i) {
        mapping_ids[i] = state->pages[i].mapping_id;
        if (state->pages[i].kind == SPARC64_MM_DATA)
            keys[key_count++] = state->pages[i].key;
    }
    for (size_t i = 0; i < state->file_assoc_count; ++i)
        keys[key_count++] = state->file_assocs[i].key;
    if (state->page_count > 1)
        qsort(mapping_ids, state->page_count, sizeof(*mapping_ids), compare_mapping_id);
    for (size_t i = 1; i < state->page_count; ++i) {
        if (mapping_ids[i - 1u] == mapping_ids[i]) {
            free(mapping_ids); free(keys);
            goto invalid;
        }
    }
    free(mapping_ids);
    qsort(keys, key_count, sizeof(*keys), compare_key);
    sparc64_family_object_t *object = NULL;
    uint64_t object_id = 0;
    int result = 0;
    for (size_t i = 0; i < key_count; ++i) {
        if (keys[i].object_id != object_id) {
            sparc64_family_object_close(object);
            object = NULL;
            if (sparc64_family_object_open(guard, keys[i].object_id, &object) != 0) {
                result = -1;
                break;
            }
            object_id = keys[i].object_id;
        }
        if (keys[i].page_index >= sparc64_family_object_count(object)) {
            errno = EINVAL;
            result = -1;
            break;
        }
    }
    int saved = errno;
    sparc64_family_object_close(object);
    free(keys);
    errno = saved;
    return result;
invalid:
    errno = EINVAL;
    return -1;
}

void sparc64_family_mm_state_destroy(sparc64_family_mm_state_t *state)
{
    if (state == NULL)
        return;
    free(state->vmas); free(state->pages); free(state->members);
    free(state->shared_sources); free(state->file_assocs);
    memset(state, 0, sizeof(*state));
}

static void encode_header(unsigned char *bytes, bool root, const mm_header_t *header)
{
    memcpy(bytes, root ? "RVMMR004" : "RVMMS004", 8);
    put_word(bytes + 8, SCHEMA_VERSION, 4);
    put_word(bytes + 12, HEADER_BYTES, 4);
    const uint64_t words[16] = {
        header->mm.mm_id, header->mm.root_object, header->state.revision,
        header->snapshot, header->length, header->state.vma_count,
        header->state.page_count, header->state.member_count,
        header->state.limit, header->state.minimum_break, header->state.current_break,
        header->state.brk_id, header->state.next_vma_id, header->state.next_mapping_id,
        header->state.shared_source_count, header->state.file_assoc_count
    };
    for (size_t i = 0; i < 16; ++i)
        put_word(bytes + 16u + i * 8u, words[i], 8);
}

static bool decode_header(const unsigned char *bytes, sparc64_family_mm_t mm,
                            mm_header_t *header)
{
    if (memcmp(bytes, "RVMMR004", 8) != 0 ||
        get_word(bytes + 8, 4) != SCHEMA_VERSION ||
        get_word(bytes + 12, 4) != HEADER_BYTES ||
        mm.mm_id == 0 || mm.root_object == 0 ||
        get_word(bytes + 16, 8) != mm.mm_id ||
        get_word(bytes + 24, 8) != mm.root_object)
        return false;
    *header = (mm_header_t){.mm = mm};
    header->state.revision = get_word(bytes + 32, 8);
    header->snapshot = get_word(bytes + 40, 8);
    header->length = get_word(bytes + 48, 8);
    uint64_t counts[3] = {get_word(bytes + 56, 8), get_word(bytes + 64, 8),
                          get_word(bytes + 72, 8)};
    for (size_t i = 0; i < 3; ++i)
        if (counts[i] > SPARC64_FAMILY_MM_MAX_RECORDS)
            return false;
    header->state.vma_count = (size_t)counts[0];
    header->state.page_count = (size_t)counts[1];
    header->state.member_count = (size_t)counts[2];
    header->state.limit = get_word(bytes + 80, 8);
    header->state.minimum_break = get_word(bytes + 88, 8);
    header->state.current_break = get_word(bytes + 96, 8);
    header->state.brk_id = get_word(bytes + 104, 8);
    header->state.next_vma_id = get_word(bytes + 112, 8);
    header->state.next_mapping_id = get_word(bytes + 120, 8);
    uint64_t shared_count = get_word(bytes + 128, 8);
    if (shared_count > SPARC64_FAMILY_MM_MAX_RECORDS)
        return false;
    header->state.shared_source_count = (size_t)shared_count;
    uint64_t file_count = get_word(bytes + 136, 8);
    if (file_count > SPARC64_FAMILY_MM_MAX_RECORDS)
        return false;
    header->state.file_assoc_count = (size_t)file_count;
    size_t length;
    uint32_t slots;
    return header->state.revision != 0 && header->snapshot != 0 &&
           header->snapshot != mm.root_object &&
           extent(&header->state, &length, &slots) && length == header->length;
}

static int read_root(sparc64_family_guard_t *guard, sparc64_family_mm_t mm,
                       sparc64_family_object_t **object, sparc64_family_page_state_t *page,
                       mm_header_t *header)
{
    if (mm.mm_id == 0 || mm.root_object == 0) {
        errno = EINVAL;
        return -1;
    }
    if (sparc64_family_object_open(guard, mm.root_object, object) != 0)
        return -1;
    if (sparc64_family_object_count(*object) != 1 ||
        sparc64_family_object_snapshot(guard, *object, 0, page) != 0 ||
        !decode_header(page->bytes, mm, header) ||
        !all_zero(page->bytes + HEADER_BYTES, SPARC64_FAMILY_PAGE_SIZE - HEADER_BYTES)) {
        sparc64_family_object_close(*object); *object = NULL;
        errno = EIO;
        return -1;
    }
    return 0;
}

static int write_slot(sparc64_family_guard_t *guard, sparc64_family_object_t *object,
                        uint32_t index, const unsigned char *bytes)
{
    sparc64_family_page_state_t page;
    if (sparc64_family_object_snapshot(guard, object, index, &page) != 0)
        return -1;
    if (page.content_generation == UINT64_MAX) {
        errno = EOVERFLOW;
        return -1;
    }
    for (size_t i = 0; i < SPARC64_FAMILY_EPOCHS; ++i) {
        if (page.epochs[i] == UINT64_MAX) {
            errno = EOVERFLOW;
            return -1;
        }
        ++page.epochs[i];
    }
    ++page.content_generation;
    memcpy(page.bytes, bytes, SPARC64_FAMILY_PAGE_SIZE);
    return sparc64_family_object_commit(guard, object, index, &page);
}

static int publish(sparc64_family_guard_t *guard, sparc64_family_mm_t mm,
                     sparc64_family_object_t *root, sparc64_family_mm_state_t *state)
{
    size_t length;
    uint32_t slots;
    if (!extent(state, &length, &slots) || state->revision == UINT64_MAX) {
        errno = EOVERFLOW;
        return -1;
    }
    size_t allocation = (size_t)slots * SPARC64_FAMILY_PAGE_SIZE;
    unsigned char *bytes = calloc(1, allocation);
    if (bytes == NULL)
        return -1;
    sparc64_family_object_t *snapshot = NULL;
    if (sparc64_family_object_create(guard, slots, &snapshot) != 0) {
        free(bytes);
        return -1;
    }
    mm_header_t header = {.mm = mm, .snapshot = sparc64_family_object_id(snapshot),
                           .length = length, .state = *state};
    ++header.state.revision;
    encode_header(bytes, false, &header);
    size_t offset = HEADER_BYTES;
    for (size_t i = 0; i < state->vma_count; ++i, offset += VMA_BYTES) {
        const sparc64_vma_t *vma = &state->vmas[i];
        put_word(bytes + offset, vma->start, 8);
        put_word(bytes + offset + 8, vma->end, 8);
        put_word(bytes + offset + 16, vma->backing_id, 8);
        put_word(bytes + offset + 24, vma->offset, 8);
        put_word(bytes + offset + 32, vma->permissions, 4);
        put_word(bytes + offset + 36, vma->may_permissions, 4);
        put_word(bytes + offset + 40, (uint32_t)vma->kind, 4);
    }
    for (size_t i = 0; i < state->page_count; ++i, offset += PAGE_BYTES) {
        const sparc64_family_mm_page_t *page = &state->pages[i];
        put_word(bytes + offset, page->address, 8);
        put_word(bytes + offset + 8, page->mapping_id, 8);
        put_word(bytes + offset + 16, page->mapping_generation, 8);
        put_word(bytes + offset + 24, page->key.object_id, 8);
        put_word(bytes + offset + 32, page->key.page_index, 8);
        put_word(bytes + offset + 40, page->permissions, 4);
        put_word(bytes + offset + 44, (uint32_t)page->kind, 4);
    }
    for (size_t i = 0; i < state->member_count; ++i, offset += MEMBER_BYTES) {
        put_word(bytes + offset, state->members[i].owner_incarnation, 8);
        put_word(bytes + offset + 8, state->members[i].task_id, 8);
    }
    for (size_t i = 0; i < state->shared_source_count; ++i, offset += SHARED_BYTES) {
        put_word(bytes + offset, state->shared_sources[i].backing_id, 8);
        put_word(bytes + offset + 8, state->shared_sources[i].manifest.object_id, 8);
    }
    for (size_t i = 0; i < state->file_assoc_count; ++i, offset += FILE_ASSOC_BYTES) {
        const sparc64_family_mm_file_assoc_t *association = &state->file_assocs[i];
        put_word(bytes + offset, association->key.object_id, 8);
        put_word(bytes + offset + 8, association->key.page_index, 8);
        put_word(bytes + offset + 16, association->source_id, 8);
        put_word(bytes + offset + 24, association->file_offset, 8);
    }
    int result = 0;
    for (uint32_t i = 0; i < slots; ++i) {
        if (write_slot(guard, snapshot, i, bytes + (size_t)i * SPARC64_FAMILY_PAGE_SIZE) != 0) {
            result = -1;
            break;
        }
    }
    if (result == 0) {
        unsigned char root_bytes[SPARC64_FAMILY_PAGE_SIZE] = {0};
        encode_header(root_bytes, true, &header);
        result = write_slot(guard, root, 0, root_bytes);
        if (result == 0)
            state->revision = header.state.revision;
    }
    int saved = errno;
    sparc64_family_object_close(snapshot);
    free(bytes);
    errno = saved;
    return result;
}

typedef struct {
    uint64_t mapping_id;
    size_t index;
} mapping_id_record_t;

static int compare_mapping_id_record(const void *a, const void *b)
{
    const mapping_id_record_t *x = a, *y = b;
    return (x->mapping_id > y->mapping_id) - (x->mapping_id < y->mapping_id);
}

static int validate_transition(const sparc64_family_mm_state_t *old,
                                 const sparc64_family_mm_state_t *next)
{
    if (old->limit != next->limit || old->minimum_break != next->minimum_break ||
        old->brk_id != next->brk_id || old->next_vma_id > next->next_vma_id ||
        old->next_mapping_id > next->next_mapping_id ||
        old->shared_source_count > next->shared_source_count ||
        old->file_assoc_count > next->file_assoc_count) {
        errno = EINVAL;
        return -1;
    }
    for (size_t i = 0; i < next->shared_source_count; ++i) {
        const sparc64_family_mm_shared_source_t *source = &next->shared_sources[i];
        if (i < old->shared_source_count ?
            (source->backing_id != old->shared_sources[i].backing_id ||
             source->manifest.object_id != old->shared_sources[i].manifest.object_id) :
            source->backing_id < old->next_vma_id) {
            errno = EINVAL; return -1;
        }
    }
    size_t next_assoc = 0;
    for (size_t i = 0; i < old->file_assoc_count; ++i) {
        const sparc64_family_mm_file_assoc_t *former = &old->file_assocs[i];
        while (next_assoc < next->file_assoc_count &&
               compare_key(&next->file_assocs[next_assoc].key,
                           &former->key) < 0)
            ++next_assoc;
        if (next_assoc == next->file_assoc_count ||
            compare_key(&next->file_assocs[next_assoc].key,
                        &former->key) != 0 ||
            next->file_assocs[next_assoc].source_id != former->source_id ||
            next->file_assocs[next_assoc].file_offset != former->file_offset) {
            errno = EINVAL; return -1;
        }
    }
    for (size_t i = 0; i < next->file_assoc_count; ++i) {
        const sparc64_family_mm_file_assoc_t *association = &next->file_assocs[i];
        if (file_assoc_find(old, association->key) != NULL)
            continue;
        for (size_t page = 0; page < old->page_count; ++page)
            if (old->pages[page].kind == SPARC64_MM_DATA &&
                compare_key(&old->pages[page].key, &association->key) == 0) {
                errno = EINVAL; return -1;
            }
    }
    mapping_id_record_t *records = old->page_count == 0 ? NULL :
        malloc(old->page_count * sizeof(*records));
    if (old->page_count != 0 && records == NULL)
        return -1;
    for (size_t i = 0; i < old->page_count; ++i)
        records[i] = (mapping_id_record_t){old->pages[i].mapping_id, i};
    if (old->page_count > 1)
        qsort(records, old->page_count, sizeof(*records), compare_mapping_id_record);
    bool valid = true;
    for (size_t i = 0; valid && i < next->page_count; ++i) {
        const sparc64_family_mm_page_t *page = &next->pages[i];
        if (page->mapping_id >= old->next_mapping_id)
            continue;
        size_t left = 0, right = old->page_count;
        while (left < right) {
            size_t middle = left + (right - left) / 2;
            if (records[middle].mapping_id < page->mapping_id)
                left = middle + 1;
            else
                right = middle;
        }
        if (left == old->page_count || records[left].mapping_id != page->mapping_id) {
            valid = false;
            break;
        }
        const sparc64_family_mm_page_t *previous = &old->pages[records[left].index];
        bool changed = previous->key.object_id != page->key.object_id ||
            previous->key.page_index != page->key.page_index ||
            previous->permissions != page->permissions || previous->kind != page->kind;
        valid = previous->address == page->address &&
            page->mapping_generation >= previous->mapping_generation &&
            (!changed || page->mapping_generation > previous->mapping_generation);
    }
    free(records);
    if (!valid)
        errno = EINVAL;
    return valid ? 0 : -1;
}

int sparc64_family_mm_create(sparc64_family_guard_t *guard, sparc64_family_mm_state_t *state,
                         sparc64_family_mm_t *out)
{
    if (guard == NULL || !sparc64_family_guard_matches(guard, guard->family) ||
        state == NULL || state->revision != 0 || out == NULL ||
        out->mm_id != 0 || out->root_object != 0) {
        errno = EINVAL;
        return -1;
    }
    if (validate(guard, state) != 0)
        return -1;
    sparc64_family_mm_t mm = {0};
    if (sparc64_family_mm_id(guard, &mm.mm_id) != 0)
        return -1;
    sparc64_family_object_t *root = NULL;
    if (sparc64_family_object_create(guard, 1, &root) != 0)
        return -1;
    mm.root_object = sparc64_family_object_id(root);
    int result = publish(guard, mm, root, state);
    int saved = errno;
    sparc64_family_object_close(root);
    if (result == 0)
        *out = mm;
    errno = saved;
    return result;
}

int sparc64_family_mm_commit(sparc64_family_guard_t *guard, sparc64_family_mm_t mm,
                         sparc64_family_mm_state_t *state)
{
    if (state == NULL) { errno = EINVAL; return -1; }
    sparc64_family_object_t *root = NULL;
    sparc64_family_page_state_t page;
    mm_header_t header;
    if (read_root(guard, mm, &root, &page, &header) != 0)
        return -1;
    int result = -1;
    if (state->revision != header.state.revision)
        errno = EAGAIN;
    else if (validate(guard, state) == 0) {
        sparc64_family_mm_state_t old = {0};
        if (sparc64_family_mm_read(guard, mm, &old) == 0 &&
            validate_transition(&old, state) == 0)
            result = publish(guard, mm, root, state);
        sparc64_family_mm_state_destroy(&old);
    }
    int saved = errno;
    sparc64_family_object_close(root);
    errno = saved;
    return result;
}

int sparc64_family_mm_read(sparc64_family_guard_t *guard, sparc64_family_mm_t mm,
                       sparc64_family_mm_state_t *out)
{
    if (out == NULL) { errno = EINVAL; return -1; }
    sparc64_family_object_t *root = NULL, *snapshot = NULL;
    sparc64_family_page_state_t page;
    mm_header_t header;
    if (read_root(guard, mm, &root, &page, &header) != 0)
        return -1;
    sparc64_family_object_close(root);
    sparc64_family_mm_state_t fresh = header.state;
    size_t length;
    uint32_t slots;
    if (!extent(&fresh, &length, &slots)) { errno = EIO; return -1; }
    if (sparc64_family_object_open(guard, header.snapshot, &snapshot) != 0) {
        if (errno != ENOMEM)
            errno = EIO;
        return -1;
    }
    if (sparc64_family_object_count(snapshot) != slots) {
        sparc64_family_object_close(snapshot); errno = EIO; return -1;
    }
    size_t allocation = (size_t)slots * SPARC64_FAMILY_PAGE_SIZE;
    unsigned char *bytes = malloc(allocation);
    if (bytes == NULL) { sparc64_family_object_close(snapshot); return -1; }
    int result = -1;
    for (uint32_t i = 0; i < slots; ++i) {
        if (sparc64_family_object_snapshot(guard, snapshot, i, &page) != 0)
            goto done;
        memcpy(bytes + (size_t)i * SPARC64_FAMILY_PAGE_SIZE, page.bytes, SPARC64_FAMILY_PAGE_SIZE);
    }
    unsigned char expected[HEADER_BYTES] = {0};
    encode_header(expected, false, &header);
    if (memcmp(bytes, expected, HEADER_BYTES) != 0 ||
        !all_zero(bytes + length, allocation - length)) {
        errno = EIO;
        goto done;
    }
    fresh.vmas = fresh.vma_count == 0 ? NULL : calloc(fresh.vma_count, sizeof(*fresh.vmas));
    fresh.pages = fresh.page_count == 0 ? NULL : calloc(fresh.page_count, sizeof(*fresh.pages));
    fresh.members = fresh.member_count == 0 ? NULL : calloc(fresh.member_count, sizeof(*fresh.members));
    fresh.shared_sources = fresh.shared_source_count == 0 ? NULL :
        calloc(fresh.shared_source_count, sizeof(*fresh.shared_sources));
    fresh.file_assocs = fresh.file_assoc_count == 0 ? NULL :
        calloc(fresh.file_assoc_count, sizeof(*fresh.file_assocs));
    if ((fresh.vma_count != 0 && fresh.vmas == NULL) ||
        (fresh.page_count != 0 && fresh.pages == NULL) ||
        (fresh.member_count != 0 && fresh.members == NULL) ||
        (fresh.shared_source_count != 0 && fresh.shared_sources == NULL) ||
        (fresh.file_assoc_count != 0 && fresh.file_assocs == NULL)) {
        errno = ENOMEM;
        goto done;
    }
    size_t offset = HEADER_BYTES;
    for (size_t i = 0; i < fresh.vma_count; ++i, offset += VMA_BYTES) {
        sparc64_vma_t *vma = &fresh.vmas[i];
        vma->start = get_word(bytes + offset, 8);
        vma->end = get_word(bytes + offset + 8, 8);
        vma->backing_id = get_word(bytes + offset + 16, 8);
        vma->offset = get_word(bytes + offset + 24, 8);
        vma->permissions = (unsigned int)get_word(bytes + offset + 32, 4);
        vma->may_permissions = (unsigned int)get_word(bytes + offset + 36, 4);
        uint64_t kind = get_word(bytes + offset + 40, 4);
        if (kind > SPARC64_VMA_ANONYMOUS_SHARED || !all_zero(bytes + offset + 44, 4)) {
            errno = EIO; goto done;
        }
        vma->kind = (sparc64_vma_kind_t)kind;
    }
    for (size_t i = 0; i < fresh.page_count; ++i, offset += PAGE_BYTES) {
        sparc64_family_mm_page_t *record = &fresh.pages[i];
        record->address = get_word(bytes + offset, 8);
        record->mapping_id = get_word(bytes + offset + 8, 8);
        record->mapping_generation = get_word(bytes + offset + 16, 8);
        record->key.object_id = get_word(bytes + offset + 24, 8);
        record->key.page_index = get_word(bytes + offset + 32, 8);
        record->permissions = (unsigned int)get_word(bytes + offset + 40, 4);
        uint64_t kind = get_word(bytes + offset + 44, 4);
        if (kind > SPARC64_MM_BUS) { errno = EIO; goto done; }
        record->kind = (sparc64_family_mm_page_kind_t)kind;
    }
    for (size_t i = 0; i < fresh.member_count; ++i, offset += MEMBER_BYTES) {
        fresh.members[i].owner_incarnation = get_word(bytes + offset, 8);
        fresh.members[i].task_id = get_word(bytes + offset + 8, 8);
    }
    for (size_t i = 0; i < fresh.shared_source_count; ++i, offset += SHARED_BYTES) {
        fresh.shared_sources[i].backing_id = get_word(bytes + offset, 8);
        fresh.shared_sources[i].manifest.object_id = get_word(bytes + offset + 8, 8);
    }
    for (size_t i = 0; i < fresh.file_assoc_count; ++i, offset += FILE_ASSOC_BYTES) {
        sparc64_family_mm_file_assoc_t *association = &fresh.file_assocs[i];
        association->key.object_id = get_word(bytes + offset, 8);
        association->key.page_index = get_word(bytes + offset + 8, 8);
        association->source_id = get_word(bytes + offset + 16, 8);
        association->file_offset = get_word(bytes + offset + 24, 8);
    }
    if (validate(guard, &fresh) != 0) {
        if (errno != ENOMEM)
            errno = EIO;
        goto done;
    }
    sparc64_family_mm_state_destroy(out);
    *out = fresh;
    memset(&fresh, 0, sizeof(fresh));
    result = 0;
done:;
    int saved = errno;
    sparc64_family_mm_state_destroy(&fresh);
    sparc64_family_object_close(snapshot);
    free(bytes);
    errno = saved;
    return result;
}
