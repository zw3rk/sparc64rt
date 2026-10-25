/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#include "runtime/process_memory.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

struct sparc64_process_memory {
    sparc64_space_t space;
    sparc64_linux_memory_t vmas;
    sparc64_file_registry_t files;
    sparc64_family_backing_t *backing;
    sparc64_family_identity_t identity;
    struct shared_page *shared;
    size_t shared_count;
    bool committed;
};

typedef struct shared_page {
    uint64_t address;
    unsigned int permissions;
    sparc64_family_page_key_t key;
} shared_page_t;

#ifdef SPARC64_PROCESS_MEMORY_TEST_CHILD
void sparc64_process_memory_test_corrupt_shared_key(sparc64_process_memory_t *prepared)
{
    if (prepared == NULL || prepared->shared_count == 0)
        abort();
    prepared->shared[0].key.object_id = UINT64_MAX;
}
#endif

typedef struct {
    const sparc64_page_payload_t *parent;
    uint64_t first_child_address;
} private_pair_t;

typedef struct {
    sparc64_file_source_t *parent;
    sparc64_file_source_t *child;
} file_pair_t;

static void release_file_pairs(file_pair_t *pairs, size_t count)
{
    for (size_t i = 0; i < count; ++i)
        pairs[i].child->release(pairs[i].child);
    free(pairs);
}

static const sparc64_vma_t *covering_vma(const sparc64_linux_memory_t *memory,
                                    uint64_t page, size_t *cursor)
{
    while (*cursor < memory->count && memory->vmas[*cursor].end <= page)
        ++*cursor;
    if (*cursor == memory->count || memory->vmas[*cursor].start > page ||
        memory->vmas[*cursor].end - page < SPARC64_PAGE_SIZE)
        return NULL;
    return &memory->vmas[*cursor];
}

static int failed_space(sparc64_space_t *space)
{
    errno = space->fault_reason == SPARC64_FAULT_RESOURCE ? ENOMEM : EIO;
    return -1;
}

static int parent_page_state(sparc64_family_backing_t *backing,
                             sparc64_family_guard_t *guard,
                             const sparc64_page_payload_t *payload,
                             unsigned char bytes[SPARC64_PAGE_SIZE],
                             uint64_t epochs[SPARC64_PAGE_GRANULES])
{
    if (payload->backend == SPARC64_PAYLOAD_HEAP) {
        memcpy(bytes, payload->bytes, SPARC64_PAGE_SIZE);
        memcpy(epochs, payload->epochs, SPARC64_PAGE_GRANULES * sizeof(*epochs));
        return 0;
    }
    sparc64_family_page_key_t key;
    if (payload->backend != SPARC64_PAYLOAD_MANAGED ||
        !sparc64_family_backing_key(backing, (sparc64_page_payload_t *)payload, &key) ||
        key.page_index > UINT32_MAX) {
        errno = EIO;
        return -1;
    }
    sparc64_family_object_t *object = NULL;
    if (sparc64_family_object_open(guard, key.object_id, &object) != 0)
        return -1;
    sparc64_family_page_state_t state;
    int result = sparc64_family_object_snapshot(guard, object,
                                           (uint32_t)key.page_index, &state);
    int saved = errno;
    sparc64_family_object_close(object);
    if (result != 0) {
        errno = saved;
        return -1;
    }
    memcpy(bytes, state.bytes, SPARC64_PAGE_SIZE);
    memcpy(epochs, state.epochs, sizeof(state.epochs));
    return 0;
}

static int clone_private_page(sparc64_process_memory_t *child,
                              const sparc64_page_t *page, private_pair_t *pairs,
                              size_t *pair_count, file_pair_t *files,
                              size_t *file_count, sparc64_family_backing_t *parent_backing,
                              sparc64_family_guard_t *guard)
{
    sparc64_backing_t *original = page->backing;
    if (original->file == NULL) {
        for (size_t i = 0; i < *pair_count; ++i)
            if (pairs[i].parent == original->payload) {
                if (!sparc64_space_alias(&child->space, pairs[i].first_child_address,
                                    page->address, SPARC64_PAGE_SIZE, page->permissions))
                    return failed_space(&child->space);
                child->space.pages[child->space.count - 1].backing->private_cow =
                    original->private_cow;
                return 0;
            }
        if (!sparc64_space_map(&child->space, page->address, SPARC64_PAGE_SIZE,
                          page->permissions, false))
            return failed_space(&child->space);
    } else {
        if (original->file->space == NULL) {
            errno = EIO;
            return -1;
        }
        sparc64_file_source_t *source = NULL;
        for (size_t i = 0; i < *file_count; ++i)
            if (files[i].parent == original->file) {
                source = files[i].child;
                break;
            }
        if (source == NULL) {
            source = sparc64_file_source_clone_into(&child->files, original->file);
            if (source == NULL)
                return -1;
            files[(*file_count)++] = (file_pair_t){original->file, source};
        }
        bool mapped = sparc64_space_map_file(&child->space, page->address,
                                         SPARC64_PAGE_SIZE, page->permissions, false,
                                         source, original->file_offset);
        if (!mapped)
            return failed_space(&child->space);
    }
    sparc64_backing_t *view = child->space.pages[child->space.count - 1].backing;
    if (parent_page_state(parent_backing, guard, original->payload,
                          view->bytes, view->epochs) != 0)
        return -1;
    view->private_cow = original->private_cow;
    memcpy(view->file_notified, original->file_notified,
           sizeof(view->file_notified));
    if (original->file == NULL)
        pairs[(*pair_count)++] = (private_pair_t){original->payload, page->address};
    return 0;
}

void sparc64_process_memory_discard(sparc64_process_memory_t **owned)
{
    if (owned == NULL || *owned == NULL)
        return;
    sparc64_process_memory_t *child = *owned;
    sparc64_linux_memory_destroy(&child->vmas);
    sparc64_space_destroy(&child->space);
    sparc64_file_registry_destroy(&child->files);
    if (child->backing != NULL) {
        sparc64_family_backing_unbind(child->backing);
        if (sparc64_family_backing_destroy(child->backing) != 0)
            abort(); /* An escaped child payload would make teardown unsafe. */
    }
    free(child->shared);
    free(child);
    *owned = NULL;
}

int sparc64_process_memory_create_canonical_empty(sparc64_process_memory_t **out,
    sparc64_family_t *child_family, sparc64_family_guard_t *child_guard,
    uint64_t limit, uint32_t slots_per_object,
    sparc64_file_identity_policy_t identity_policy)
{
    if (out == NULL || *out != NULL || child_family == NULL ||
        !sparc64_family_guard_matches(child_guard, child_family) ||
        limit < SPARC64_PAGE_SIZE || limit % SPARC64_PAGE_SIZE != 0 ||
        slots_per_object == 0 || slots_per_object > SPARC64_FAMILY_OBJECT_MAX_SLOTS ||
        !sparc64_file_identity_policy_valid(identity_policy)) {
        errno = EINVAL;
        return -1;
    }
    sparc64_process_memory_t *child = calloc(1, sizeof(*child));
    if (child == NULL)
        return -1;
    sparc64_space_init(&child->space, limit <= (UINT64_C(1) << 32) ? 32 : 64);
    child->space.limit = limit;
    child->vmas.space = &child->space;
    sparc64_file_registry_init(&child->files, &child->space);
    if (sparc64_file_registry_set_identity_policy(&child->files, identity_policy) != 0 ||
        sparc64_family_backing_create(&child->backing, child_family,
                                  slots_per_object) != 0 ||
        sparc64_family_backing_bind(child->backing, child_guard) != 0 ||
        !sparc64_family_backing_install(child->backing, &child->space)) {
        int saved = errno == 0 ? EIO : errno;
        sparc64_process_memory_discard(&child);
        errno = saved;
        return -1;
    }
    child->committed = true;
    *out = child;
    return 0;
}

int sparc64_process_memory_prepare(sparc64_process_memory_t **out,
                              const sparc64_linux_memory_t *parent,
                              sparc64_family_backing_t *parent_backing,
                              sparc64_family_t *family, sparc64_family_guard_t *guard)
{
    if (out == NULL) {
        errno = EINVAL;
        return -1;
    }
    *out = NULL;
    if (parent == NULL || parent->space == NULL || parent_backing == NULL ||
        family == NULL || !sparc64_family_guard_matches(guard, family) ||
        parent->space->page_factory.context != parent_backing ||
        parent->space->managed.commitv == NULL ||
        !sparc64_family_backing_guard_matches(parent_backing, guard) ||
        parent->space->internal_failure ||
        (parent->count != 0 && parent->vmas == NULL)) {
        errno = EINVAL;
        return -1;
    }
    sparc64_process_memory_t *child = calloc(1, sizeof(*child));
    if (child == NULL)
        return -1;
    sparc64_space_init(&child->space, parent->space->limit <= (UINT64_C(1) << 32) ? 32 : 64);
    child->space.limit = parent->space->limit;
    /* An inherited LR token cannot accidentally name a child mapping. */
    child->space.next_binding = parent->space->next_binding;
    if (sparc64_family_identity(guard, &child->identity) != 0)
        goto failed;
    sparc64_file_registry_init(&child->files, &child->space);
    child->vmas.space = &child->space;
    if (parent->count > SIZE_MAX / sizeof(*child->vmas.vmas)) {
        errno = ENOMEM;
        goto failed;
    }
    child->vmas.vmas = malloc((parent->count == 0 ? 1 : parent->count) *
                               sizeof(*child->vmas.vmas));
    if (child->vmas.vmas == NULL)
        goto failed;
    if (parent->count != 0)
        memcpy(child->vmas.vmas, parent->vmas,
               parent->count * sizeof(*child->vmas.vmas));
    child->vmas.count = parent->count;
    child->vmas.next_id = parent->next_id;
    child->vmas.brk_id = parent->brk_id;
    child->vmas.minimum_break = parent->minimum_break;
    child->vmas.current_break = parent->current_break;
    if (parent->space->count > SIZE_MAX / sizeof(private_pair_t) ||
        parent->space->count > SIZE_MAX / sizeof(file_pair_t) ||
        parent->space->count > SIZE_MAX / sizeof(shared_page_t)) {
        errno = ENOMEM;
        goto failed;
    }
    private_pair_t *pairs = calloc(parent->space->count == 0 ? 1 : parent->space->count,
                                    sizeof(*pairs));
    if (pairs == NULL)
        goto failed;
    file_pair_t *file_pairs = calloc(parent->space->count == 0 ? 1 :
                                      parent->space->count, sizeof(*file_pairs));
    if (file_pairs == NULL) {
        free(pairs);
        goto failed;
    }
    child->shared = calloc(parent->space->count == 0 ? 1 : parent->space->count,
                            sizeof(*child->shared));
    if (child->shared == NULL) {
        free(pairs);
        free(file_pairs);
        goto failed;
    }
    size_t pair_count = 0, file_count = 0, cursor = 0;
    for (size_t i = 0; i < parent->space->count; ++i) {
        const sparc64_page_t *page = &parent->space->pages[i];
        const sparc64_vma_t *vma = covering_vma(parent, page->address, &cursor);
        if (vma == NULL || page->backing == NULL ||
            page->backing->payload == NULL ||
            page->backing->bytes != page->backing->payload->bytes ||
            page->backing->epochs != page->backing->payload->epochs) {
            errno = EIO;
            free(pairs);
            release_file_pairs(file_pairs, file_count);
            goto failed;
        }
        if (vma->kind == SPARC64_VMA_ANONYMOUS_SHARED) {
            sparc64_family_page_key_t key;
            if (page->backing->file != NULL ||
                !sparc64_family_backing_key(parent_backing,
                                        page->backing->payload, &key))
                errno = EIO;
            else {
                child->shared[child->shared_count++] =
                    (shared_page_t){page->address, page->permissions, key};
                continue;
            }
            free(pairs);
            release_file_pairs(file_pairs, file_count);
            goto failed;
        }
        if (clone_private_page(child, page, pairs, &pair_count, file_pairs, &file_count,
                               parent_backing, guard) != 0) {
            free(pairs);
            release_file_pairs(file_pairs, file_count);
            goto failed;
        }
    }
    free(pairs);
    release_file_pairs(file_pairs, file_count);
    *out = child;
    return 0;
failed: {
        int saved = errno;
        sparc64_process_memory_discard(&child);
        errno = saved;
        return -1;
    }
}

int sparc64_process_memory_commit(sparc64_process_memory_t *prepared,
                              sparc64_family_t *child_family,
                              sparc64_family_guard_t *child_guard,
                              uint32_t slots_per_object)
{
    if (prepared == NULL || prepared->committed || prepared->backing != NULL ||
        !sparc64_family_guard_matches(child_guard, child_family)) {
        errno = EINVAL;
        return -1;
    }
    sparc64_family_identity_t identity;
    if (sparc64_family_identity(child_guard, &identity) != 0)
        return -1;
    if (identity.control_device != prepared->identity.control_device ||
        identity.control_inode != prepared->identity.control_inode ||
        identity.directory_device != prepared->identity.directory_device ||
        identity.directory_inode != prepared->identity.directory_inode) {
        errno = EXDEV;
        return -1;
    }
    if (sparc64_family_backing_create(&prepared->backing, child_family,
                                  slots_per_object) != 0)
        return -1;
    if (sparc64_family_backing_bind(prepared->backing, child_guard) != 0)
        return -1;
    if (!sparc64_family_backing_adopt(prepared->backing, &prepared->space)) {
        (void)failed_space(&prepared->space);
        return -1;
    }
    for (size_t i = 0; i < prepared->shared_count; ++i) {
        shared_page_t *page = &prepared->shared[i];
        if (!sparc64_family_backing_map_shared(prepared->backing, &prepared->space,
                                          page->address, page->permissions,
                                          page->key)) {
            (void)failed_space(&prepared->space);
            return -1;
        }
    }
    sparc64_family_backing_unbind(prepared->backing);
    prepared->committed = true;
    return 0;
}

int sparc64_process_memory_bind(sparc64_process_memory_t *committed,
                           sparc64_family_guard_t *child_guard)
{
    if (committed == NULL || !committed->committed) {
        errno = EINVAL;
        return -1;
    }
    return sparc64_family_backing_bind(committed->backing, child_guard);
}

int sparc64_process_memory_set_file_identity_policy(sparc64_process_memory_t *prepared,
                                                sparc64_file_identity_policy_t policy)
{
    if (prepared == NULL || prepared->committed) {
        errno = EINVAL;
        return -1;
    }
    return sparc64_file_registry_set_identity_policy(&prepared->files, policy);
}

void sparc64_process_memory_unbind(sparc64_process_memory_t *owner)
{
    if (owner != NULL)
        sparc64_family_backing_unbind(owner->backing);
}

sparc64_space_t *sparc64_process_memory_space(sparc64_process_memory_t *owner)
{
    return owner == NULL || !owner->committed ? NULL : &owner->space;
}

sparc64_linux_memory_t *sparc64_process_memory_vmas(sparc64_process_memory_t *owner)
{
    return owner == NULL || !owner->committed ? NULL : &owner->vmas;
}

sparc64_file_registry_t *sparc64_process_memory_files(sparc64_process_memory_t *owner)
{
    return owner == NULL || !owner->committed ? NULL : &owner->files;
}

sparc64_family_backing_t *sparc64_process_memory_backing(sparc64_process_memory_t *owner)
{
    return owner == NULL || !owner->committed ? NULL : owner->backing;
}
