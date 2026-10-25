/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#include "runtime/mm_view_internal.h"

#include <errno.h>

static int remap_space_error(const sparc64_space_t *space)
{
    return space->fault_reason == SPARC64_FAULT_RESOURCE ? ENOMEM : EIO;
}

static size_t count_pages(const sparc64_family_mm_state_t *state, uint64_t start, uint64_t end)
{
    size_t count = 0;
    for (size_t i = 0; i < state->page_count; ++i)
        if (state->pages[i].address >= start && state->pages[i].address < end)
            ++count;
    return count;
}

static bool range_hole(const sparc64_family_mm_state_t *state, uint64_t start, uint64_t end)
{
    for (size_t i = 0; i < state->vma_count && state->vmas[i].start < end; ++i)
        if (state->vmas[i].end > start)
            return false;
    return true;
}

static void empty_candidate(sparc64_space_t *space, uint64_t limit)
{
    sparc64_space_init(space, limit <= (UINT64_C(1) << 32) ? 32 : 64);
    space->limit = limit;
}

/* Import only mapped source rows; the caller selected a contiguous VMA slice.
 * Canonical IDs are assigned by state_insert, never copied from these local
 * candidate bindings. No bytes need copying through guest permissions. */
static int import_slice(sparc64_mm_view_t *view, sparc64_space_t *candidate,
                          uint64_t start, uint64_t end, uint64_t destination)
{
    for (size_t i = 0; i < view->applied.page_count; ++i) {
        const sparc64_family_mm_page_t *page = &view->applied.pages[i];
        if (page->address < start || page->address >= end)
            continue;
        uint64_t address = destination + (page->address - start);
        bool mapped = page->kind == SPARC64_MM_BUS ?
            sparc64_space_map_bus(candidate, address, SPARC64_PAGE_SIZE, page->permissions, false) :
            sparc64_family_backing_map_shared(view->backing, candidate,
                address, page->permissions, page->key);
        if (!mapped) {
            errno = remap_space_error(candidate); return -1;
        }
    }
    return 0;
}

/* Shared tails are views of the immutable original source. Shrink/regrow
 * must recover its existing nonzero bytes and epochs; beyond-extent views
 * exist but fault BUS. Private tails alone allocate fresh zero payloads. */
static int append_tail(sparc64_mm_view_t *view, sparc64_family_guard_t *guard,
                          sparc64_family_mm_state_t *state, sparc64_space_t *origins,
                          sparc64_space_t *candidate, sparc64_vma_t source,
                          uint64_t offset, uint64_t address, uint64_t length)
{
    unsigned int effective = source.permissions |
        ((source.permissions & SPARC64_MEM_WRITE) != 0 ? SPARC64_MEM_READ : 0u);
    if (source.kind == SPARC64_VMA_ANONYMOUS_SHARED) {
        sparc64_family_shmem_t handle = {0};
        for (size_t i = 0; i < view->applied.shared_source_count; ++i)
            if (view->applied.shared_sources[i].backing_id == source.backing_id) {
                handle = view->applied.shared_sources[i].manifest; break;
            }
        if (handle.object_id == 0 || length > UINT64_MAX - offset) {
            errno = EIO; return -1;
        }
        sparc64_family_shmem_state_t manifest = {0};
        if (sparc64_family_shmem_read(guard, handle, &manifest) != 0)
            return -1;
        int saved = 0;
        for (uint64_t i = 0; i < length; i += SPARC64_PAGE_SIZE) {
            uint64_t original_offset = offset + i;
            bool mapped = original_offset >= manifest.extent ?
                sparc64_space_map_bus(candidate, address + i, SPARC64_PAGE_SIZE, effective, false) :
                sparc64_family_backing_map_shared(view->backing, candidate, address + i,
                    effective, manifest.pages[original_offset / SPARC64_PAGE_SIZE]);
            if (!mapped) { saved = remap_space_error(candidate); break; }
        }
        sparc64_family_shmem_state_destroy(&manifest);
        if (saved != 0) { errno = saved; return -1; }
        return 0;
    }
    uint64_t file_source = 0;
    if (source.kind == SPARC64_VMA_FILE_PRIVATE) {
        /* A split VMA's start still has an exact page-origin association;
         * never derive a source from pathname, inode alone, or local FD. */
        for (size_t i = 0; i < view->applied.page_count; ++i) {
            const sparc64_family_mm_page_t *page = &view->applied.pages[i];
            if (page->address != source.start)
                continue;
            for (size_t j = 0; j < view->applied.file_assoc_count; ++j) {
                const sparc64_family_mm_file_assoc_t *assoc = &view->applied.file_assocs[j];
                if (assoc->key.object_id == page->key.object_id &&
                    assoc->key.page_index == page->key.page_index &&
                    assoc->file_offset == source.offset) {
                    file_source = assoc->source_id; break;
                }
            }
            break;
        }
        if (file_source == 0) { errno = EIO; return -1; }
    }
    sparc64_space_t tail;
    empty_candidate(&tail, candidate->limit);
    int result = -1, saved = 0;
    if (!sparc64_family_backing_install(view->backing, &tail)) { saved = EIO; goto done; }
    if (!sparc64_family_backing_stage_anonymous(view->backing, &tail, address, length, effective)) {
        saved = remap_space_error(&tail); goto done;
    }
    for (size_t i = 0; i < tail.count; ++i) {
        sparc64_family_page_key_t key;
        if (!sparc64_family_backing_key(view->backing, tail.pages[i].backing->payload, &key)) {
            saved = EIO; goto done;
        }
        if (!sparc64_family_backing_map_shared(view->backing, candidate, tail.pages[i].address,
                                            effective, key)) {
            saved = remap_space_error(candidate); goto done;
        }
        if (file_source != 0) {
            sparc64_family_mm_file_assoc_t assoc = {key, file_source, offset + i * SPARC64_PAGE_SIZE};
            if (!sparc64_family_backing_map_shared(view->backing, origins, tail.pages[i].address,
                                                effective, key)) {
                saved = remap_space_error(origins); goto done;
            }
            if (sparc64_family_mm_file_assoc_insert(state, assoc) != 0) {
                saved = errno; goto done;
            }
        }
    }
    result = 0;
done:
    sparc64_space_destroy(&tail);
    if (result != 0)
        errno = saved;
    return result;
}

static int move_slice(sparc64_mm_view_t *view, sparc64_family_guard_t *guard,
                        sparc64_family_mm_state_t *state, sparc64_space_t *origins, sparc64_vma_t source,
                        uint64_t start, uint64_t old_end,
                        uint64_t new_end, uint64_t destination)
{
    sparc64_space_t candidate;
    empty_candidate(&candidate, state->limit);
    int result = -1, saved = 0;
    if (!sparc64_family_backing_install(view->backing, &candidate)) { saved = EIO; goto done; }
    if (import_slice(view, &candidate, start, old_end, destination) != 0) {
        saved = errno; goto done;
    }
    if (new_end > old_end && append_tail(view, guard, state, origins, &candidate, source,
            source.offset + (old_end - source.start), destination + (old_end - start),
            new_end - old_end) != 0) {
        saved = errno; goto done;
    }
    source.offset += start - source.start;
    source.start = destination; source.end = destination + (new_end - start);
    if (sparc64_mm_view_state_insert(view, state, &candidate, source) != 0) {
        saved = errno; goto done;
    }
    result = 0;
done:
    sparc64_space_destroy(&candidate);
    if (result != 0)
        errno = saved;
    return result;
}

/* Linux removes a fixed destination before these later deterministic errors.
 * Use the ordinary guarded transaction, retaining exact early-validation and
 * fatal/uncertain-publication classifications. Never retry the whole remap. */
static int fixed_failure(sparc64_mm_view_t *view, sparc64_family_guard_t *guard,
                            uint64_t destination, uint64_t length,
                            unsigned int failure, uint64_t *guest_result)
{
    uint64_t unmap_result = 0;
    if (sparc64_mm_view_munmap(view, guard, destination, length, &unmap_result) != 0)
        return -1;
    *guest_result = unmap_result != 0 ? unmap_result : UINT64_C(0) - failure;
    return 0;
}

int sparc64_mm_view_mremap(sparc64_mm_view_t *view, sparc64_family_guard_t *guard,
                        uint64_t address, uint64_t old_length, uint64_t new_length,
                        uint64_t flags, uint64_t destination, uint64_t *guest_result)
{
    if (guest_result == NULL) { errno = EINVAL; return -1; }
    if (sparc64_mm_view_refresh(view, guard) != 0)
        return -1;
    unsigned int failure = 0;
    if ((flags & ~UINT64_C(7)) != 0 || address % SPARC64_PAGE_SIZE != 0 ||
        ((flags & 6) != 0 && (flags & 1) == 0) || new_length == 0 ||
        old_length > UINT64_MAX - (SPARC64_PAGE_SIZE - 1) ||
        new_length > UINT64_MAX - (SPARC64_PAGE_SIZE - 1))
        failure = 22;
    if (failure != 0) { *guest_result = UINT64_C(0) - failure; return 0; }
    uint64_t old_size = (old_length + SPARC64_PAGE_SIZE - 1) & ~(SPARC64_PAGE_SIZE - 1);
    uint64_t new_size = (new_length + SPARC64_PAGE_SIZE - 1) & ~(SPARC64_PAGE_SIZE - 1);
    uint64_t limit = view->space->limit;
    if (new_size > limit || ((flags & 4) != 0 && old_size != new_size)) {
        *guest_result = UINT64_C(0) - 22; return 0;
    }
    bool fixed = (flags & 2) != 0;
    if ((flags & 6) != 0 && (destination % SPARC64_PAGE_SIZE != 0 ||
                   destination > limit - new_size ||
                   (destination >= address ? destination - address < old_size :
                                              address - destination < new_size))) {
        *guest_result = UINT64_C(0) - 22; return 0;
    }
    if ((flags & 4) != 0) {
        *guest_result = UINT64_C(0) - 95; return 0; /* Needs its own backing/fault policy. */
    }
    if (fixed && destination < SPARC64_PAGE_SIZE) {
        *guest_result = UINT64_C(0) - 22; return 0;
    }
    if (address < SPARC64_PAGE_SIZE || address >= limit) {
        *guest_result = UINT64_C(0) - 14; return 0;
    }
    size_t at = 0;
    while (at < view->applied.vma_count && view->applied.vmas[at].end <= address)
        ++at;
    if (at == view->applied.vma_count || view->applied.vmas[at].start > address) {
        *guest_result = UINT64_C(0) - 14; return 0;
    }
    sparc64_vma_t source = view->applied.vmas[at];
    bool duplicate = old_size == 0;
    if (duplicate && source.kind != SPARC64_VMA_ANONYMOUS_SHARED) {
        *guest_result = UINT64_C(0) - 22; return 0;
    }
    if (!fixed && new_size <= old_size) {
        uint64_t result = 0;
        if (new_size < old_size) {
            if (new_size > limit - address) {
                *guest_result = UINT64_C(0) - 22; return 0;
            }
            if (sparc64_mm_view_munmap(view, guard, address + new_size,
                                    old_size - new_size, &result) != 0)
                return -1;
        }
        *guest_result = result == 0 ? address : result;
        return 0;
    }
    bool multi = fixed && new_size == old_size;
    uint64_t retained = new_size < old_size ? new_size : old_size;
    if (!multi && retained > source.end - address) {
        *guest_result = UINT64_C(0) - 14; return 0;
    }
    if (!multi && (new_size > UINT64_MAX - source.offset ||
                  address - source.start > UINT64_MAX - source.offset - new_size)) {
        *guest_result = UINT64_C(0) - 22; return 0;
    }
    if (!multi && source.kind == SPARC64_VMA_FILE_PRIVATE &&
        (new_size > INT64_MAX || source.offset > (uint64_t)INT64_MAX - new_size ||
         address - source.start > (uint64_t)INT64_MAX - new_size - source.offset)) {
        /* The retained source service uses signed native file positions. */
        *guest_result = UINT64_C(0) - 95; return 0;
    }
    if (fixed && duplicate && destination == address)
        return fixed_failure(view, guard, destination, new_size, 14, guest_result);
    /* Keep true integer wrap distinct from a nonwrapping range above the
     * supported VA limit. The latter reaches Linux's destructive shrink step. */
    if (old_size > UINT64_MAX - address) {
        *guest_result = UINT64_C(0) - (new_size < old_size ? 22u : 14u); return 0;
    }
    if (!multi && old_size > limit - address) {
        if (fixed && new_size < old_size)
            return fixed_failure(view, guard, destination, new_size, 22, guest_result);
        *guest_result = UINT64_C(0) - (new_size < old_size ? 22u : 14u); return 0;
    }
    bool inplace = false;
    if (!fixed) {
        if (new_size <= limit - address && address + old_size == source.end &&
            range_hole(&view->applied, source.end, address + new_size)) {
            destination = address; inplace = true;
        } else if ((flags & 1) == 0) {
            *guest_result = UINT64_C(0) - 12; return 0;
        } else if (!sparc64_space_find_hole(view->space, UINT64_C(0x4000000000), new_size, &destination) &&
                   !sparc64_space_find_hole(view->space, SPARC64_PAGE_SIZE, new_size, &destination)) {
            *guest_result = UINT64_C(0) - 12; return 0;
        }
    }
    size_t removed = 0, inserted = 0;
    if (inplace) {
        inserted = (size_t)((new_size - old_size) / SPARC64_PAGE_SIZE);
    } else {
        removed = count_pages(&view->applied, address, address + old_size);
        if (multi) {
            for (size_t i = at; i < view->applied.vma_count &&
                               view->applied.vmas[i].start < address + old_size; ++i) {
                const sparc64_vma_t *vma = &view->applied.vmas[i];
                uint64_t start = vma->start > address ? vma->start : address;
                uint64_t end = vma->end < address + old_size ? vma->end : address + old_size;
                inserted += (size_t)((end - start) / SPARC64_PAGE_SIZE);
                removed += count_pages(&view->applied, destination + (start - address),
                                         destination + (end - address));
            }
        } else {
            if (new_size / SPARC64_PAGE_SIZE > SPARC64_FAMILY_MM_MAX_RECORDS) {
                *guest_result = UINT64_C(0) - 12; return 0;
            }
            inserted = (size_t)(new_size / SPARC64_PAGE_SIZE);
            removed += count_pages(&view->applied, destination, destination + new_size);
        }
    }
    if (inserted > SPARC64_FAMILY_MM_MAX_RECORDS - (view->applied.page_count - removed)) {
        *guest_result = UINT64_C(0) - 12; return 0;
    }
    uint64_t file_added = source.kind == SPARC64_VMA_FILE_PRIVATE && new_size > old_size ?
        (new_size - old_size) / SPARC64_PAGE_SIZE : 0;
    if (file_added > SPARC64_FAMILY_MM_MAX_RECORDS - view->applied.file_assoc_count) {
        *guest_result = UINT64_C(0) - 12; return 0;
    }
    if (view->applied.revision == UINT64_MAX || view->space->generation == UINT64_MAX ||
        inserted > UINT64_MAX - view->applied.next_mapping_id ||
        inserted > (UINT64_MAX - view->space->next_binding) / SPARC64_PAGE_GRANULES) {
        errno = EOVERFLOW; return -1;
    }
    sparc64_family_mm_state_t state = {0};
    if (sparc64_family_mm_read(guard, view->mm, &state) != 0)
        return -1;
    sparc64_mm_view_plan_t plan = {0};
    sparc64_space_t origins;
    empty_candidate(&origins, limit);
    int result = -1, saved = 0;
    if (!sparc64_family_backing_install(view->backing, &origins)) { saved = EIO; goto done; }
    if (inplace) {
        sparc64_space_t tail;
        empty_candidate(&tail, limit);
        bool ready = sparc64_family_backing_install(view->backing, &tail);
        if (ready && append_tail(view, guard, &state, &origins, &tail, source,
                source.offset + (source.end - source.start), source.end,
                new_size - old_size) != 0) {
            saved = errno; ready = false;
        } else if (!ready) {
            saved = EIO;
        }
        sparc64_vma_t added = source;
        added.offset += source.end - source.start;
        added.start = source.end; added.end = address + new_size;
        if (ready && sparc64_mm_view_state_insert(view, &state, &tail, added) != 0) {
            saved = errno; ready = false;
        }
        sparc64_space_destroy(&tail);
        if (!ready)
            goto done;
    } else {
        if (!duplicate && sparc64_mm_view_state_unmap(&state, address, address + old_size) != 0) {
            saved = errno; goto done;
        }
        if (multi) {
            for (size_t i = at; i < view->applied.vma_count &&
                               view->applied.vmas[i].start < address + old_size; ++i) {
                sparc64_vma_t vma = view->applied.vmas[i];
                uint64_t start = vma.start > address ? vma.start : address;
                uint64_t end = vma.end < address + old_size ? vma.end : address + old_size;
                if (move_slice(view, guard, &state, &origins, vma, start, end, end,
                                  destination + (start - address)) != 0) {
                    saved = errno; goto done;
                }
            }
        } else if (move_slice(view, guard, &state, &origins, source, address, address + retained,
                                address + new_size, destination) != 0) {
            saved = errno; goto done;
        }
    }
    if (sparc64_mm_view_plan_prepare(view, &state, &plan) != 0 ||
        (origins.count != 0 && sparc64_mm_view_plan_admit_files(view, guard, &plan, &origins) != 0) ||
        sparc64_family_mm_commit(guard, view->mm, &plan.state) != 0) {
        saved = errno; goto done;
    }
    sparc64_mm_view_plan_apply(view, &plan);
    *guest_result = destination; result = 0;
done:
    sparc64_mm_view_plan_discard(&plan); sparc64_family_mm_state_destroy(&state);
    sparc64_space_destroy(&origins);
    if (result != 0)
        errno = saved;
    return result;
}
