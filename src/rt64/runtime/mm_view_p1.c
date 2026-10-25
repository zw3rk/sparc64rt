/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#include "mm_view_split.h"


/* Only this fresh-file mapping transaction may admit origins. Refresh and
 * generic plan preparation must reject missing authority, never create it. */
int sparc64_mm_view_plan_admit_files(sparc64_mm_view_t *view, sparc64_family_guard_t *guard,
                              sparc64_mm_view_plan_t *plan, const sparc64_space_t *fresh)
{
    uint64_t root = sparc64_family_file_index_object(guard);
    if (root == 0)
        return -1;
    sparc64_family_file_index_state_t index = {0};
    if (sparc64_family_file_index_read(guard, root, &index) != 0)
        return -1;
    int result = -1;
    size_t added = 0, sources = 0;
    for (size_t i = 0; i < plan->state.file_assoc_count; ++i) {
        const sparc64_family_mm_file_assoc_t *a = &plan->state.file_assocs[i];
        size_t at = origin_position(&index, a->key);
        if (at < index.association_count && same_key(index.associations[at].key, a->key)) {
            if (index.associations[at].source_id != a->source_id ||
                index.associations[at].file_offset != a->file_offset) { errno = EINVAL; goto done; }
        } else {
            if (!transaction_key(view, fresh, a->key)) { errno = EINVAL; goto done; }
            ++added;
        }
    }
    if (added == 0) { result = 0; goto done; }
    for (size_t i = 0; i < plan->file_source_count; ++i) {
        size_t at = source_position(&index, plan->file_sources[i].id);
        if (at == index.source_count || index.sources[at].source_id != plan->file_sources[i].id)
            ++sources;
    }
    if (added > SPARC64_FAMILY_FILE_INDEX_MAX_ASSOCIATIONS - index.association_count ||
        sources > SPARC64_FAMILY_FILE_INDEX_MAX_SOURCES - index.source_count) {
        errno = ENOSPC; goto done;
    }
    if (sources != 0) {
        sparc64_family_file_index_source_t *rows = realloc(index.sources,
            (index.source_count + sources) * sizeof(*rows));
        if (rows == NULL) goto done;
        index.sources = rows;
    }
    sparc64_family_file_index_assoc_t *rows = realloc(index.associations,
        (index.association_count + added) * sizeof(*rows));
    if (rows == NULL) goto done;
    index.associations = rows;
    for (size_t i = 0; i < plan->file_source_count; ++i) {
        const sparc64_mm_file_cache_entry_t *entry = &plan->file_sources[i];
        size_t at = source_position(&index, entry->id);
        if (at < index.source_count && index.sources[at].source_id == entry->id)
            continue; /* Never overwrite global proof, size or mutation history. */
        sparc64_family_file_description_t description;
        if (sparc64_family_file_source_describe(entry->source, guard, view->file_identity_policy,
                                              &description) != 0)
            goto done;
        if (description.source_id != entry->id) { errno = EIO; goto done; }
        memmove(index.sources + at + 1u, index.sources + at,
                   (index.source_count - at) * sizeof(*index.sources));
        index.sources[at] = (sparc64_family_file_index_source_t){.source_id = entry->id,
            .identity = description.identity, .reconciled_size = description.size};
        ++index.source_count;
    }
    for (size_t i = 0; i < plan->state.file_assoc_count; ++i) {
        const sparc64_family_mm_file_assoc_t *a = &plan->state.file_assocs[i];
        size_t at = origin_position(&index, a->key);
        if (at < index.association_count && same_key(index.associations[at].key, a->key))
            continue;
        memmove(index.associations + at + 1u, index.associations + at,
                   (index.association_count - at) * sizeof(*index.associations));
        index.associations[at] = (sparc64_family_file_index_assoc_t){a->key, a->source_id, a->file_offset};
        ++index.association_count;
    }
    result = sparc64_family_file_index_commit(guard, root, &index);
done: {
        int saved = errno;
        sparc64_family_file_index_state_destroy(&index);
        errno = saved;
        return result;
    }
}

int sparc64_mm_view_map_file_private(sparc64_mm_view_t *view, sparc64_family_guard_t *guard,
                                  uint64_t address, uint64_t length,
                                  unsigned int permissions, unsigned int may_permissions,
                                  uint64_t source_id,
                                  uint64_t file_offset)
{
    if (view == NULL || guard == NULL || length == 0 ||
        length % SPARC64_PAGE_SIZE != 0 || address < SPARC64_PAGE_SIZE ||
        address % SPARC64_PAGE_SIZE != 0 || address >= view->space->limit ||
        length > view->space->limit - address || source_id == 0 ||
        file_offset % SPARC64_PAGE_SIZE != 0 ||
        file_offset > INT64_MAX ||
        file_offset > INT64_MAX - (length - SPARC64_PAGE_SIZE) ||
        (may_permissions & ~(SPARC64_MEM_READ | SPARC64_MEM_WRITE | SPARC64_MEM_EXEC)) != 0 ||
        (permissions & ~may_permissions) != 0) {
        errno = EINVAL; return -1;
    }
    if (sparc64_mm_view_refresh(view, guard) != 0)
        return -1;
    for (size_t i = 0; i < view->applied.vma_count; ++i) {
        const sparc64_vma_t *vma = &view->applied.vmas[i];
        if (vma->start < address + length && vma->end > address) {
            errno = EEXIST; return -1;
        }
    }
    size_t added = (size_t)(length / SPARC64_PAGE_SIZE);
    if (added > SPARC64_FAMILY_MM_MAX_RECORDS - view->applied.page_count ||
        added > SPARC64_FAMILY_MM_MAX_RECORDS - view->applied.file_assoc_count ||
        view->applied.vma_count == SPARC64_FAMILY_MM_MAX_RECORDS) {
        errno = ENOMEM; return -1;
    }
    if (view->applied.revision == UINT64_MAX ||
        view->applied.next_vma_id == UINT64_MAX ||
        added > UINT64_MAX - view->applied.next_mapping_id ||
        added > (UINT64_MAX - view->space->next_binding) / SPARC64_PAGE_GRANULES) {
        errno = EOVERFLOW; return -1;
    }
    sparc64_family_mm_state_t state = {0};
    sparc64_space_t fresh;
    sparc64_mm_view_plan_t plan = {0};
    sparc64_space_init(&fresh, view->space->limit <= (UINT64_C(1) << 32) ? 32 : 64);
    fresh.limit = view->space->limit;
    int result = -1, saved = 0;
    if (sparc64_family_mm_read(guard, view->mm, &state) != 0) {
        saved = errno; goto done;
    }
    if (!sparc64_family_backing_install(view->backing, &fresh)) {
        saved = EIO; goto done;
    }
    if (!sparc64_family_backing_stage_anonymous(view->backing, &fresh,
                                            address, length, permissions)) {
        saved = space_error(&fresh); goto done;
    }
    sparc64_vma_t vma = {address, address + length, state.next_vma_id++,
                    file_offset, permissions, may_permissions, SPARC64_VMA_FILE_PRIVATE};
    if (sparc64_mm_view_state_insert(view, &state, &fresh, vma) != 0) {
        saved = errno; goto done;
    }
    for (size_t i = 0; i < fresh.count; ++i) {
        sparc64_family_page_key_t key;
        if (!sparc64_family_backing_key(view->backing, fresh.pages[i].backing->payload,
                                   &key)) {
            saved = EIO; goto done;
        }
        sparc64_family_mm_file_assoc_t assoc = {key, source_id,
                                            file_offset + i * SPARC64_PAGE_SIZE};
        if (sparc64_family_mm_file_assoc_insert(&state, assoc) != 0) {
            saved = errno; goto done;
        }
    }
    if (sparc64_mm_view_plan_prepare(view, &state, &plan) != 0 ||
        sparc64_mm_view_plan_admit_files(view, guard, &plan, &fresh) != 0 ||
        sparc64_family_mm_commit(guard, view->mm, &plan.state) != 0) {
        saved = errno; goto done;
    }
    sparc64_mm_view_plan_apply(view, &plan);
    result = 0;
done:
    sparc64_mm_view_plan_discard(&plan);
    sparc64_space_destroy(&fresh);
    sparc64_family_mm_state_destroy(&state);
    if (result != 0)
        errno = saved;
    return result;
}

int sparc64_mm_view_map_file_readonly(sparc64_mm_view_t *view, sparc64_family_guard_t *guard,
                                  uint64_t address, uint64_t length,
                                  unsigned int permissions, uint64_t source_id,
                                  uint64_t file_offset)
{
    if ((permissions & ~(SPARC64_MEM_READ | SPARC64_MEM_EXEC)) != 0) {
        errno = EINVAL;
        return -1;
    }
    return sparc64_mm_view_map_file_private(view, guard, address, length, permissions,
                                        permissions, source_id, file_offset);
}

static int stage_shared_source(sparc64_mm_view_t *view, sparc64_family_guard_t *guard,
                                 sparc64_family_mm_state_t *state, sparc64_space_t *fresh,
                                 uint64_t backing_id)
{
    sparc64_family_page_key_t *keys = malloc(fresh->count * sizeof(*keys));
    if (keys == NULL)
        return -1;
    int result = -1, saved = 0;
    for (size_t i = 0; i < fresh->count; ++i) {
        if (!sparc64_family_backing_key(view->backing, fresh->pages[i].backing->payload, &keys[i])) {
            saved = EIO; goto done;
        }
    }
    sparc64_family_shmem_state_t source = {fresh->count * SPARC64_PAGE_SIZE, keys, fresh->count};
    sparc64_family_shmem_t manifest = {0};
    if (sparc64_family_shmem_create(guard, &source, &manifest) != 0 ||
        sparc64_family_mm_shared_append(state, backing_id, manifest) != 0) {
        saved = errno; goto done;
    }
    result = 0;
done:
    free(keys);
    if (result != 0)
        errno = saved;
    return result;
}

static int mmap_pages(sparc64_mm_view_t *view, sparc64_family_guard_t *guard,
                           uint64_t address, uint64_t length, uint64_t protection,
                           uint64_t flags, uint64_t offset, int file_fd,
                           uint64_t *guest_result)
{
    if (guest_result == NULL) { errno = EINVAL; return -1; }
    if (sparc64_mm_view_refresh(view, guard) != 0)
        return -1;
    const uint64_t map_shared = 1, map_private = 2, map_fixed = 0x10,
        map_anon = 0x20, map_noreplace = 0x100000;
    /* Match the existing eager anonymous memory policy's ignored legacy and
     * population hints. Locked/huge/grow-down and unknown features are not here. */
    const uint64_t allowed = map_shared | map_private | map_fixed | map_anon |
        map_noreplace | UINT64_C(0x800) | UINT64_C(0x1000) | UINT64_C(0x4000) |
        UINT64_C(0x8000) | UINT64_C(0x10000) | UINT64_C(0x20000);
    unsigned int failure = 0;
    if (length == 0 || offset % SPARC64_PAGE_SIZE != 0 || (protection & ~UINT64_C(7)) != 0)
        failure = 22;
    else if (length > UINT64_MAX - (SPARC64_PAGE_SIZE - 1))
        failure = 12;
    uint64_t size = failure == 0 ?
        (length + SPARC64_PAGE_SIZE - 1) & ~(SPARC64_PAGE_SIZE - 1) : 0;
    uint64_t limit = view->space->limit;
    if (failure == 0 && size > limit)
        failure = 12;
    if (failure == 0 && (flags & 3) == 0)
        failure = 22;
    else if (failure == 0 && ((flags & 3) == 3 ||
             ((flags & map_anon) != 0) != (file_fd < 0) ||
             (file_fd >= 0 && (flags & 3) != map_private) || (flags & ~allowed) != 0))
        failure = 95;
    if (failure != 0) { *guest_result = UINT64_C(0) - failure; return 0; }
    bool fixed = (flags & (map_fixed | map_noreplace)) != 0;
    if (fixed) {
        if (address % SPARC64_PAGE_SIZE != 0)
            failure = 22;
        else if (address < SPARC64_PAGE_SIZE || address >= limit || size > limit - address)
            failure = address < SPARC64_PAGE_SIZE ? 1u : 12u;
        else if ((flags & map_noreplace) != 0) {
            for (size_t i = 0; i < view->applied.vma_count; ++i) {
                if (view->applied.vmas[i].start >= address + size)
                    break;
                if (view->applied.vmas[i].end > address) { failure = 17; break; }
            }
        }
    } else {
        address &= ~(SPARC64_PAGE_SIZE - 1);
        uint64_t found = 0;
        bool hint = address >= SPARC64_PAGE_SIZE && address < limit && size <= limit - address &&
            sparc64_space_find_hole(view->space, address, size, &found) && found == address;
        if (!hint) {
            uint64_t preferred = UINT64_C(0x4000000000);
            uint64_t start = preferred < limit ? preferred : SPARC64_PAGE_SIZE;
            if (!sparc64_space_find_hole(view->space, start, size, &address) &&
                !sparc64_space_find_hole(view->space, SPARC64_PAGE_SIZE, size, &address))
                failure = 12;
        }
    }
    if (failure != 0) { *guest_result = UINT64_C(0) - failure; return 0; }
    /* Linux checks regular-file offset bounds after placement/NOREPLACE,
     * including the rounded final page. Anonymous offsets are ignored. */
    if (file_fd >= 0 && (size > INT64_MAX || offset > (uint64_t)INT64_MAX - size)) {
        *guest_result = UINT64_C(0) - 75; return 0;
    }
    size_t removed = 0;
    for (size_t i = 0; i < view->applied.page_count; ++i)
        if (view->applied.pages[i].address >= address && view->applied.pages[i].address < address + size)
            ++removed;
    uint64_t added = size / SPARC64_PAGE_SIZE;
    if (added > SPARC64_FAMILY_MM_MAX_RECORDS - (view->applied.page_count - removed)) {
        *guest_result = UINT64_C(0) - 12; return 0;
    }
    /* Unmapping does not revoke immutable origin history. */
    if (file_fd >= 0 && added > SPARC64_FAMILY_MM_MAX_RECORDS - view->applied.file_assoc_count) {
        *guest_result = UINT64_C(0) - 12; return 0;
    }
    if ((flags & 3) == map_shared &&
        view->applied.shared_source_count == SPARC64_FAMILY_MM_MAX_RECORDS) {
        *guest_result = UINT64_C(0) - 12; return 0;
    }
    if (view->applied.revision == UINT64_MAX || view->applied.next_vma_id == UINT64_MAX ||
        added > UINT64_MAX - view->applied.next_mapping_id ||
        view->space->generation == UINT64_MAX ||
        added > (UINT64_MAX - view->space->next_binding) / SPARC64_PAGE_GRANULES) {
        errno = EOVERFLOW; return -1;
    }
    uint64_t source_id = 0;
    if (file_fd >= 0) {
        struct stat status;
        int native_flags = fcntl(file_fd, F_GETFL);
        if (native_flags < 0 || fstat(file_fd, &status) != 0)
            return -1; /* The caller still pins this exact native description. */
        if ((native_flags & O_ACCMODE) == O_WRONLY) {
            *guest_result = UINT64_C(0) - 13; return 0;
        }
        if (!S_ISREG(status.st_mode) || status.st_size < 0) {
            *guest_result = UINT64_C(0) - 19; return 0;
        }
        if (sparc64_family_file_target_check(guard, file_fd) != 0) {
            if (errno == EACCES) {
                *guest_result = UINT64_C(0) - 13; return 0;
            }
            return -1;
        }
    }
    if (file_fd >= 0 && sparc64_family_source_register(guard, file_fd, &source_id) != 0) {
        /* ENOSPC is the bounded service/catalog budget. An uncertain service
         * protocol failure must never become an ordinary guest retry. */
        if (errno == ENOSPC || errno == ENOMEM) {
            *guest_result = UINT64_C(0) - 12; return 0;
        }
        return -1;
    }
    sparc64_family_mm_state_t state = {0};
    if (sparc64_family_mm_read(guard, view->mm, &state) != 0)
        return -1;
    sparc64_space_t fresh;
    sparc64_space_init(&fresh, limit <= (UINT64_C(1) << 32) ? 32 : 64);
    fresh.limit = limit;
    sparc64_mm_view_plan_t plan = {0};
    int result = -1, saved = 0;
    unsigned int effective = (unsigned int)protection |
        ((protection & SPARC64_MEM_WRITE) != 0 ? SPARC64_MEM_READ : 0u);
    if (!sparc64_family_backing_install(view->backing, &fresh)) {
        saved = EIO; goto done;
    }
    if (!sparc64_family_backing_stage_anonymous(view->backing, &fresh, address, size, effective)) {
        saved = space_error(&fresh); goto done;
    }
    sparc64_vma_t added_vma = {address, address + size, state.next_vma_id++, 0,
        (unsigned int)protection, 7,
        file_fd >= 0 ? SPARC64_VMA_FILE_PRIVATE :
        (flags & 3) == map_shared ? SPARC64_VMA_ANONYMOUS_SHARED : SPARC64_VMA_ANONYMOUS};
    if (file_fd >= 0)
        added_vma.offset = offset;
    if ((added_vma.kind == SPARC64_VMA_ANONYMOUS_SHARED &&
         stage_shared_source(view, guard, &state, &fresh, added_vma.backing_id) != 0) ||
        sparc64_mm_view_state_insert(view, &state, &fresh, added_vma) != 0) {
        saved = errno; goto done;
    }
    if (file_fd >= 0) {
        for (size_t i = 0; i < fresh.count; ++i) {
            sparc64_family_page_key_t key;
            if (!sparc64_family_backing_key(view->backing, fresh.pages[i].backing->payload, &key)) {
                saved = EIO; goto done;
            }
            sparc64_family_mm_file_assoc_t assoc = {key, source_id, offset + i * SPARC64_PAGE_SIZE};
            if (sparc64_family_mm_file_assoc_insert(&state, assoc) != 0) {
                saved = errno; goto done;
            }
        }
    }
    if (sparc64_mm_view_plan_prepare(view, &state, &plan) != 0 ||
        (file_fd >= 0 && sparc64_mm_view_plan_admit_files(view, guard, &plan, &fresh) != 0) ||
        sparc64_family_mm_commit(guard, view->mm, &plan.state) != 0) {
        saved = errno; goto done;
    }
    sparc64_mm_view_plan_apply(view, &plan);
    *guest_result = address;
    result = 0;
done:
    sparc64_mm_view_plan_discard(&plan);
    sparc64_space_destroy(&fresh);
    sparc64_family_mm_state_destroy(&state);
    if (result != 0)
        errno = saved;
    return result;
}

int sparc64_mm_view_mmap_anon(sparc64_mm_view_t *view, sparc64_family_guard_t *guard,
                           uint64_t address, uint64_t length, uint64_t protection,
                           uint64_t flags, uint64_t offset, uint64_t *guest_result)
{
    return mmap_pages(view, guard, address, length, protection, flags, offset, -1, guest_result);
}

int sparc64_mm_view_mmap_file_private_fd(sparc64_mm_view_t *view, sparc64_family_guard_t *guard,
    uint64_t address, uint64_t length, uint64_t protection, uint64_t flags,
    int borrowed_readable_fd, uint64_t offset, uint64_t *guest_result)
{
    if (borrowed_readable_fd < 0) { errno = EINVAL; return -1; }
    return mmap_pages(view, guard, address, length, protection, flags, offset,
                         borrowed_readable_fd, guest_result);
}

static bool overlaps(const sparc64_family_mm_state_t *state, uint64_t start, uint64_t end)
{
    for (size_t i = 0; i < state->vma_count && state->vmas[i].start < end; ++i)
        if (state->vmas[i].end > start)
            return true;
    return false;
}

int sparc64_mm_view_brk(sparc64_mm_view_t *view, sparc64_family_guard_t *guard,
                     uint64_t address, uint64_t *guest_result)
{
    if (guest_result == NULL) { errno = EINVAL; return -1; }
    if (sparc64_mm_view_refresh(view, guard) != 0)
        return -1;
    uint64_t previous = view->applied.current_break, minimum = view->applied.minimum_break;
    uint64_t limit = view->space->limit;
    if (address == previous || address < minimum || address >= limit || previous == 0) {
        *guest_result = previous; return 0;
    }
    uint64_t old_end = (previous + SPARC64_PAGE_SIZE - 1) & ~(SPARC64_PAGE_SIZE - 1);
    uint64_t new_end = (address + SPARC64_PAGE_SIZE - 1) & ~(SPARC64_PAGE_SIZE - 1);
    bool growing = new_end > old_end;
    if ((new_end < old_end && !overlaps(&view->applied, new_end, old_end)) ||
        (growing && (new_end > limit - SPARC64_PAGE_SIZE ||
                     overlaps(&view->applied, old_end, new_end + SPARC64_PAGE_SIZE)))) {
        *guest_result = previous; return 0;
    }
    uint64_t added = growing ? (new_end - old_end) / SPARC64_PAGE_SIZE : 0;
    if (added > SPARC64_FAMILY_MM_MAX_RECORDS - view->applied.page_count) {
        *guest_result = previous; return 0;
    }
    if (view->applied.revision == UINT64_MAX ||
        (new_end != old_end && view->space->generation == UINT64_MAX) ||
        (growing && (added > UINT64_MAX - view->applied.next_mapping_id ||
                     added > (UINT64_MAX - view->space->next_binding) / SPARC64_PAGE_GRANULES))) {
        errno = EOVERFLOW; return -1;
    }
    sparc64_family_mm_state_t state = {0};
    if (sparc64_family_mm_read(guard, view->mm, &state) != 0)
        return -1;
    sparc64_space_t fresh;
    sparc64_space_init(&fresh, limit <= (UINT64_C(1) << 32) ? 32 : 64);
    fresh.limit = limit;
    sparc64_mm_view_plan_t plan = {0};
    int result = -1, saved = 0;
    if (growing) {
        uint64_t anchor = (minimum + SPARC64_PAGE_SIZE - 1) & ~(SPARC64_PAGE_SIZE - 1);
        sparc64_vma_t vma = {old_end, new_end, state.brk_id, old_end - anchor, 3, 7, SPARC64_VMA_BRK};
        if (!sparc64_family_backing_install(view->backing, &fresh)) { saved = EIO; goto done; }
        if (!sparc64_family_backing_stage_anonymous(view->backing, &fresh, old_end, new_end - old_end, 3)) {
            saved = space_error(&fresh); goto done;
        }
        if (sparc64_mm_view_state_insert(view, &state, &fresh, vma) != 0) { saved = errno; goto done; }
    } else if (new_end < old_end && sparc64_mm_view_state_unmap(&state, new_end, old_end) != 0) {
        saved = errno; goto done;
    }
    state.current_break = address;
    if (sparc64_mm_view_plan_prepare(view, &state, &plan) != 0 ||
        sparc64_family_mm_commit(guard, view->mm, &plan.state) != 0) {
        saved = errno; goto done;
    }
    sparc64_mm_view_plan_apply(view, &plan);
    *guest_result = address;
    result = 0;
done:
    sparc64_mm_view_plan_discard(&plan);
    sparc64_space_destroy(&fresh);
    sparc64_family_mm_state_destroy(&state);
    if (result != 0)
        errno = saved;
    return result;
}

uint64_t sparc64_mm_view_revision(const sparc64_mm_view_t *view)
{
    return view == NULL ? 0 : view->applied.revision;
}

void sparc64_mm_view_destroy(sparc64_mm_view_t **owned)
{
    if (owned == NULL || *owned == NULL)
        return;
    sparc64_mm_view_t *view = *owned;
    for (size_t i = 0; i < view->file_source_count; ++i)
        view->file_sources[i].source->release(view->file_sources[i].source);
    free(view->file_sources);
    sparc64_file_caps_client_close(&view->file_client);
    sparc64_family_mm_state_destroy(&view->applied);
    free(view->local_bindings); free(view); *owned = NULL;
}
