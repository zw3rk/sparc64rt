/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#include "memory/mm_fork.h"
#include "runtime/family_file_index.h"
#include "runtime/mm_view_internal.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct sparc64_mm_fork_image {
    sparc64_family_mm_t mm;
    sparc64_family_identity_t family;
    uint64_t parent_incarnation;
    pid_t parent_pid;
};

typedef struct {
    sparc64_family_page_key_t old_key, new_key;
    uint64_t source_id, file_offset;
} private_key_t;

static int key_order(sparc64_family_page_key_t a, sparc64_family_page_key_t b)
{
    if (a.object_id != b.object_id)
        return (a.object_id > b.object_id) - (a.object_id < b.object_id);
    return (a.page_index > b.page_index) - (a.page_index < b.page_index);
}

static int private_order(const void *left, const void *right)
{
    const private_key_t *a = left, *b = right;
    return key_order(a->old_key, b->old_key);
}

static int association_order(const void *left, const void *right)
{
    const sparc64_family_file_index_assoc_t *a = left, *b = right;
    return key_order(a->key, b->key);
}

static private_key_t *private_find(private_key_t *keys, size_t count,
                                    sparc64_family_page_key_t key)
{
    size_t lo = 0, hi = count;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2u;
        if (key_order(keys[mid].old_key, key) < 0) lo = mid + 1u;
        else hi = mid;
    }
    return lo < count && key_order(keys[lo].old_key, key) == 0 ? &keys[lo] : NULL;
}

static const sparc64_family_mm_file_assoc_t *old_file_assoc(
    const sparc64_family_mm_state_t *state, sparc64_family_page_key_t key)
{
    size_t lo = 0, hi = state->file_assoc_count;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2u;
        if (key_order(state->file_assocs[mid].key, key) < 0) lo = mid + 1u;
        else hi = mid;
    }
    return lo < state->file_assoc_count &&
           key_order(state->file_assocs[lo].key, key) == 0 ?
           &state->file_assocs[lo] : NULL;
}

static int copy_child_metadata(const sparc64_family_mm_state_t *parent,
                                sparc64_family_mm_state_t *child)
{
    *child = (sparc64_family_mm_state_t){.limit = parent->limit,
        .minimum_break = parent->minimum_break,
        .current_break = parent->current_break, .brk_id = parent->brk_id,
        .next_vma_id = parent->next_vma_id,
        .next_mapping_id = parent->next_mapping_id};
    if (parent->vma_count != 0) {
        child->vmas = malloc(parent->vma_count * sizeof(*child->vmas));
        if (child->vmas == NULL) return -1;
        memcpy(child->vmas, parent->vmas, parent->vma_count * sizeof(*child->vmas));
        child->vma_count = parent->vma_count;
    }
    if (parent->page_count != 0) {
        child->pages = malloc(parent->page_count * sizeof(*child->pages));
        if (child->pages == NULL) return -1;
        memcpy(child->pages, parent->pages, parent->page_count * sizeof(*child->pages));
        child->page_count = parent->page_count;
    }
    if (parent->shared_source_count != 0) {
        child->shared_sources = malloc(parent->shared_source_count *
                                       sizeof(*child->shared_sources));
        if (child->shared_sources == NULL) return -1;
        memcpy(child->shared_sources, parent->shared_sources,
               parent->shared_source_count * sizeof(*child->shared_sources));
        child->shared_source_count = parent->shared_source_count;
    }
    /* The new root is deliberately unadmitted until the post-fork guard exists.
     * Retained file associations are reconstructed for its fresh live keys. */
    return 0;
}

static int private_pages(const sparc64_family_mm_state_t *parent,
                          bool *private_page, private_key_t *keys,
                          size_t *key_count)
{
    size_t page_at = 0, count = 0;
    for (size_t i = 0; i < parent->vma_count; ++i) {
        const sparc64_vma_t *vma = &parent->vmas[i];
        if (vma->kind != SPARC64_VMA_INITIAL && vma->kind != SPARC64_VMA_ANONYMOUS &&
            vma->kind != SPARC64_VMA_BRK && vma->kind != SPARC64_VMA_FILE_PRIVATE &&
            vma->kind != SPARC64_VMA_ANONYMOUS_SHARED) {
            errno = EOPNOTSUPP; return -1;
        }
        uint64_t pages = (vma->end - vma->start) / SPARC64_PAGE_SIZE;
        if (pages > parent->page_count - page_at) { errno = EIO; return -1; }
        for (uint64_t j = 0; j < pages; ++j, ++page_at) {
            const sparc64_family_mm_page_t *page = &parent->pages[page_at];
            bool shared = vma->kind == SPARC64_VMA_ANONYMOUS_SHARED;
            if (page->address != vma->start + j * SPARC64_PAGE_SIZE ||
                (page->kind == SPARC64_MM_BUS && !shared)) {
                errno = EIO; return -1;
            }
            if (shared || page->kind == SPARC64_MM_BUS)
                continue;
            private_page[page_at] = true;
            keys[count++].old_key = page->key;
        }
    }
    if (page_at != parent->page_count) { errno = EIO; return -1; }
    qsort(keys, count, sizeof(*keys), private_order);
    size_t distinct = 0;
    for (size_t i = 0; i < count; ++i) {
        if (distinct != 0 && key_order(keys[distinct - 1u].old_key,
                                        keys[i].old_key) == 0)
            continue;
        keys[distinct++] = keys[i];
    }
    *key_count = distinct;
    return 0;
}

static int clone_state(sparc64_mm_view_t *parent, sparc64_family_guard_t *guard,
                        private_key_t *entry)
{
    sparc64_family_object_t *source = NULL;
    if (entry->old_key.page_index > UINT32_MAX ||
        sparc64_family_object_open(guard, entry->old_key.object_id, &source) != 0)
        return -1;
    sparc64_family_page_state_t exact;
    int result = sparc64_family_object_snapshot(guard, source,
                                           (uint32_t)entry->old_key.page_index, &exact);
    int saved = errno;
    sparc64_family_object_close(source);
    if (result != 0) { errno = saved; return -1; }

    sparc64_space_t stage;
    sparc64_space_init(&stage, parent->space->limit <= UINT64_C(1) << 32 ? 32u : 64u);
    if (!sparc64_family_backing_install(parent->backing, &stage) ||
        !sparc64_family_backing_stage_anonymous(parent->backing, &stage,
                                            SPARC64_PAGE_SIZE, SPARC64_PAGE_SIZE,
                                            SPARC64_MEM_READ | SPARC64_MEM_WRITE)) {
        saved = stage.fault_reason == SPARC64_FAULT_RESOURCE ? ENOMEM : EIO;
        sparc64_space_destroy(&stage); errno = saved; return -1;
    }
    sparc64_page_payload_t *payload = stage.pages[0].backing->payload;
    if (!sparc64_family_backing_key(parent->backing, payload, &entry->new_key) ||
        sparc64_family_backing_commit_state(parent->backing, payload, &exact) != 0) {
        saved = errno == 0 ? EIO : errno;
        sparc64_space_destroy(&stage); errno = saved; return -1;
    }
    sparc64_space_destroy(&stage);
    return 0;
}

static int admit_new_origins(sparc64_family_guard_t *guard,
                              const private_key_t *keys, size_t count)
{
    size_t added = 0;
    for (size_t i = 0; i < count; ++i)
        if (keys[i].source_id != 0) ++added;
    if (added == 0) return 0;
    uint64_t root = sparc64_family_file_index_object(guard);
    if (root == 0) { errno = EIO; return -1; }
    sparc64_family_file_index_state_t index = {0};
    if (sparc64_family_file_index_read(guard, root, &index) != 0)
        return -1;
    int result = -1;
    if (added > SPARC64_FAMILY_FILE_INDEX_MAX_ASSOCIATIONS - index.association_count) {
        errno = ENOSPC; goto done;
    }
    sparc64_family_file_index_assoc_t *rows = realloc(index.associations,
        (index.association_count + added) * sizeof(*rows));
    if (rows == NULL) goto done;
    index.associations = rows;
    for (size_t i = 0; i < count; ++i) {
        if (keys[i].source_id == 0) continue;
        index.associations[index.association_count++] =
            (sparc64_family_file_index_assoc_t){keys[i].new_key,
                keys[i].source_id, keys[i].file_offset};
    }
    qsort(index.associations, index.association_count,
          sizeof(*index.associations), association_order);
    result = sparc64_family_file_index_commit(guard, root, &index);
done: {
        int saved = errno;
        sparc64_family_file_index_state_destroy(&index);
        errno = saved;
        return result;
    }
}

int sparc64_mm_fork_prepare(sparc64_mm_view_t *parent, sparc64_family_guard_t *parent_guard,
                       sparc64_mm_fork_image_t **out)
{
    if (parent == NULL || parent_guard == NULL || out == NULL || *out != NULL ||
        parent->space == NULL || parent->space->internal_failure ||
        !sparc64_family_backing_guard_matches(parent->backing, parent_guard)) {
        errno = EINVAL; return -1;
    }
    sparc64_family_identity_t identity;
    if (sparc64_family_identity(parent_guard, &identity) != 0)
        return -1;
    sparc64_family_mm_state_t old = {0}, child = {0};
    if (sparc64_family_mm_read(parent_guard, parent->mm, &old) != 0)
        return -1;
    if (old.revision != parent->applied.revision) {
        sparc64_family_mm_state_destroy(&old);
        errno = EAGAIN;
        return -1;
    }
    int result = -1;
    bool *private_page = NULL;
    private_key_t *keys = NULL;
    size_t key_count = 0;
    sparc64_mm_fork_image_t *image = NULL;
    if (copy_child_metadata(&old, &child) != 0)
        goto done;
    private_page = calloc(old.page_count == 0 ? 1u : old.page_count,
                           sizeof(*private_page));
    keys = calloc(old.page_count == 0 ? 1u : old.page_count,
                   sizeof(*keys));
    image = calloc(1, sizeof(*image));
    if (private_page == NULL || keys == NULL || image == NULL)
        goto done;
    if (private_pages(&old, private_page, keys, &key_count) != 0)
        goto done;
    for (size_t i = 0; i < key_count; ++i) {
        const sparc64_family_mm_file_assoc_t *assoc = old_file_assoc(&old, keys[i].old_key);
        if (assoc != NULL) {
            keys[i].source_id = assoc->source_id;
            keys[i].file_offset = assoc->file_offset;
        }
        if (clone_state(parent, parent_guard, &keys[i]) != 0)
            goto done;
        if (assoc != NULL && sparc64_family_mm_file_assoc_insert(&child,
                (sparc64_family_mm_file_assoc_t){keys[i].new_key,
                    assoc->source_id, assoc->file_offset}) != 0)
            goto done;
    }
    for (size_t i = 0; i < child.page_count; ++i) {
        if (!private_page[i]) continue;
        private_key_t *entry = private_find(keys, key_count, old.pages[i].key);
        if (entry == NULL) { errno = EIO; goto done; }
        child.pages[i].key = entry->new_key;
    }
    if (admit_new_origins(parent_guard, keys, key_count) != 0 ||
        sparc64_family_mm_create(parent_guard, &child, &image->mm) != 0)
        goto done;
    image->family = identity;
    image->parent_incarnation = parent_guard->incarnation;
    image->parent_pid = getpid();
    *out = image;
    image = NULL;
    result = 0;
done: {
        int saved = errno;
        free(image); free(keys); free(private_page);
        sparc64_family_mm_state_destroy(&child);
        sparc64_family_mm_state_destroy(&old);
        errno = saved;
        return result;
    }
}

static bool same_identity(sparc64_family_identity_t a, sparc64_family_identity_t b)
{
    return a.control_device == b.control_device &&
           a.control_inode == b.control_inode &&
           a.directory_device == b.directory_device &&
           a.directory_inode == b.directory_inode;
}

int sparc64_mm_fork_child_adopt(sparc64_mm_fork_image_t **owned,
                            sparc64_family_guard_t *child_guard,
                            sparc64_family_backing_t *child_backing,
                            sparc64_space_t *empty_space,
                            sparc64_linux_memory_t *empty_memory,
                            sparc64_file_identity_policy_t identity_policy,
                            uint64_t child_task_id, sparc64_mm_view_t **out)
{
    if (owned == NULL || *owned == NULL || child_guard == NULL ||
        child_backing == NULL || empty_space == NULL || empty_memory == NULL ||
        out == NULL || *out != NULL || child_task_id == 0 ||
        getpid() == (*owned)->parent_pid ||
        child_guard->incarnation == (*owned)->parent_incarnation ||
        !sparc64_family_backing_guard_matches(child_backing, child_guard)) {
        errno = EINVAL; return -1;
    }
    sparc64_family_identity_t identity;
    if (sparc64_family_identity(child_guard, &identity) != 0 ||
        !same_identity(identity, (*owned)->family)) {
        errno = EXDEV; return -1;
    }
    sparc64_mm_view_t *view = NULL;
    if (sparc64_mm_view_create(&view, (*owned)->mm, child_backing,
                           empty_space, empty_memory) != 0)
        return -1;
    if (sparc64_mm_view_bind_family_sources(view, child_guard, identity_policy) != 0) {
        int saved = errno;
        sparc64_mm_view_destroy(&view);
        errno = saved; return -1;
    }
    sparc64_family_mm_state_t state = {0};
    if (sparc64_family_mm_read(child_guard, (*owned)->mm, &state) != 0) {
        int saved = errno;
        sparc64_mm_view_destroy(&view);
        errno = saved; return -1;
    }
    if (state.member_count != 0) {
        sparc64_family_mm_state_destroy(&state);
        sparc64_mm_view_destroy(&view);
        errno = EBUSY; return -1;
    }
    state.members = calloc(1, sizeof(*state.members));
    if (state.members == NULL) {
        sparc64_family_mm_state_destroy(&state);
        sparc64_mm_view_destroy(&view);
        return -1;
    }
    state.member_count = 1;
    state.members[0] = (sparc64_family_mm_member_t){child_guard->incarnation, child_task_id};
    sparc64_mm_view_plan_t plan = {0};
    if (sparc64_mm_view_plan_prepare(view, &state, &plan) != 0) {
        int saved = errno;
        sparc64_mm_view_plan_discard(&plan);
        sparc64_family_mm_state_destroy(&state);
        sparc64_mm_view_destroy(&view);
        errno = saved; return -1;
    }
    int committed = sparc64_family_mm_commit(child_guard, (*owned)->mm, &plan.state);
    int saved = errno;
    sparc64_family_mm_state_destroy(&state);
    if (committed != 0) {
        sparc64_mm_view_plan_discard(&plan);
        sparc64_mm_view_destroy(&view);
        errno = saved; return -2;
    }
    sparc64_mm_view_plan_apply(view, &plan);
    sparc64_mm_view_plan_discard(&plan);
    sparc64_mm_fork_image_destroy(owned);
    *out = view;
    return 0;
}

void sparc64_mm_fork_image_destroy(sparc64_mm_fork_image_t **owned)
{
    if (owned == NULL || *owned == NULL) return;
    free(*owned);
    *owned = NULL;
}
