/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#include "runtime/exec_tid.h"
#include "runtime/family_file_index.h"
#include "runtime/family_wait.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

enum { EXEC_TID_MAX = 4096, EXEC_TID_BYTES = 4 };

static const sparc64_page_t *find_page(const sparc64_space_t *space, uint64_t address)
{
    uint64_t page = address & ~(SPARC64_PAGE_SIZE - 1);
    size_t low = 0, high = space->count;
    while (low < high) {
        size_t middle = low + (high - low) / 2;
        if (space->pages[middle].address < page)
            low = middle + 1;
        else
            high = middle;
    }
    return low < space->count && space->pages[low].address == page ?
           &space->pages[low] : NULL;
}

static const sparc64_vma_t *vma_at(const sparc64_linux_memory_t *memory, uint64_t address)
{
    for (size_t i = 0; i < memory->count; ++i) {
        const sparc64_vma_t *vma = &memory->vmas[i];
        if (vma->start <= address && address < vma->end)
            return vma;
    }
    return NULL;
}

typedef struct {
    sparc64_family_page_key_t key;
    uint16_t writes;
    uint16_t touched[SPARC64_FAMILY_EPOCHS];
} clear_capacity_t;

static int file_origins_read(sparc64_family_guard_t *guard,
                             sparc64_family_file_index_state_t *index)
{
    uint64_t root = sparc64_family_file_index_object(guard);
    if (root == 0) {
        if (errno == EOPNOTSUPP)
            return 0; /* An ordinary family has no file origins. */
        errno = EIO;
        return -1;
    }
    return sparc64_family_file_index_read(guard, root, index);
}

static bool file_origin(const sparc64_family_file_index_state_t *index,
                        sparc64_family_page_key_t key)
{
    size_t left = 0, right = index->association_count;
    while (left < right) {
        size_t middle = left + (right - left) / 2u;
        sparc64_family_page_key_t candidate = index->associations[middle].key;
        if (candidate.object_id < key.object_id ||
            (candidate.object_id == key.object_id &&
             candidate.page_index < key.page_index))
            left = middle + 1u;
        else
            right = middle;
    }
    return left < index->association_count &&
           index->associations[left].key.object_id == key.object_id &&
           index->associations[left].key.page_index == key.page_index;
}

static bool clean_file_state(const sparc64_family_page_state_t *state)
{
    if (state->private_cow > 1 || state->reserved != 0)
        return false;
    for (size_t i = 0; i < 4; ++i)
        if (state->notified[i] != 0)
            return false;
    return true;
}

static int check_capacity(sparc64_family_guard_t *guard,
                          const sparc64_exec_tid_clear_t *intents, size_t count)
{
    sparc64_family_file_index_state_t index = {0};
    if (file_origins_read(guard, &index) != 0)
        return -1;
    clear_capacity_t *capacity = calloc(count * 2u, sizeof(*capacity));
    if (capacity == NULL) {
        sparc64_family_file_index_state_destroy(&index);
        return -1;
    }
    size_t used = 0;
    for (size_t i = 0; i < count; ++i) {
        const sparc64_exec_tid_clear_t *intent = &intents[i];
        for (uint32_t s = 0; s < intent->segment_count; ++s) {
            sparc64_family_page_key_t key = intent->keys[s];
            size_t at = 0;
            while (at < used && (capacity[at].key.object_id != key.object_id ||
                   capacity[at].key.page_index != key.page_index))
                ++at;
            if (at == used)
                capacity[used++].key = key;
            bool earlier_key = s != 0 &&
                intent->keys[0].object_id == key.object_id &&
                intent->keys[0].page_index == key.page_index;
            if (!earlier_key)
                ++capacity[at].writes;
            uint32_t first = intent->offsets[s] / 16u;
            uint32_t last = (intent->offsets[s] + intent->lengths[s] - 1u) / 16u;
            for (uint32_t epoch = first; epoch <= last; ++epoch) {
                uint32_t prior_first = intent->offsets[0] / 16u;
                uint32_t prior_last = (intent->offsets[0] + intent->lengths[0] - 1u) / 16u;
                if (!earlier_key || epoch < prior_first || epoch > prior_last)
                    ++capacity[at].touched[epoch];
            }
        }
    }
    int failure = 0;
    for (size_t i = 0; i < used; ++i) {
        sparc64_family_object_t *object = NULL;
        sparc64_family_page_state_t current;
        if (sparc64_family_object_open(guard, capacity[i].key.object_id, &object) != 0 ||
            sparc64_family_object_snapshot(guard, object,
                (uint32_t)capacity[i].key.page_index, &current) != 0) {
            failure = errno;
        } else if (current.content_generation > UINT64_MAX - capacity[i].writes) {
            failure = EOVERFLOW;
        } else {
            bool file = file_origin(&index, capacity[i].key);
            uint64_t first_cow = file && current.private_cow == 0 ? 1u : 0u;
            if ((file && !clean_file_state(&current)) ||
                (!file && current.private_cow != 0))
                failure = EIO;
            for (size_t epoch = 0; failure == 0 && epoch < SPARC64_FAMILY_EPOCHS;
                 ++epoch) {
                uint64_t charge = capacity[i].touched[epoch] + first_cow;
                if (current.epochs[epoch] > UINT64_MAX - charge) {
                    failure = EOVERFLOW;
                    break;
                }
            }
        }
        if (object != NULL)
            sparc64_family_object_close(object);
        if (failure != 0)
            break;
    }
    free(capacity);
    sparc64_family_file_index_state_destroy(&index);
    if (failure != 0) {
        errno = failure;
        return -1;
    }
    return 0;
}

static int capture(sparc64_family_guard_t *guard, sparc64_space_t *space,
                        const sparc64_linux_memory_t *memory,
                        sparc64_family_backing_t *backing,
                        const uint64_t *addresses, size_t address_count,
                        const sparc64_exec_tid_request_t *requests,
                        sparc64_exec_tid_clear_t **out, size_t *out_count,
                        bool same_mm)
{
    if (out != NULL)
        *out = NULL;
    if (out_count != NULL)
        *out_count = 0;
    if (guard == NULL || space == NULL || memory == NULL || memory->space != space ||
        backing == NULL || out == NULL || out_count == NULL ||
        (address_count != 0 && (addresses == NULL) == (requests == NULL)) ||
        space->page_factory.context != backing ||
        !sparc64_family_backing_guard_matches(backing, guard)) {
        errno = EINVAL;
        return -1;
    }
    if (address_count > EXEC_TID_MAX) {
        errno = E2BIG;
        return -1;
    }
    size_t caller_roles = 0;
    for (size_t i = 0; requests != NULL && i < address_count; ++i)
        if (requests[i].role > SPARC64_EXEC_TID_CALLER_IF_LIVE_PEER ||
            (requests[i].role == SPARC64_EXEC_TID_CALLER_IF_LIVE_PEER &&
             (!same_mm || ++caller_roles > 1))) {
            errno = EINVAL;
            return -1;
        }
    sparc64_exec_tid_clear_t *intents = address_count == 0 ? NULL :
        calloc(address_count, sizeof(*intents));
    if (address_count != 0 && intents == NULL)
        return -1;
    size_t used = 0;
    for (size_t i = 0; i < address_count; ++i) {
        uint64_t address = requests == NULL ? addresses[i] : requests[i].address;
        sparc64_exec_tid_role_t role = requests == NULL ? SPARC64_EXEC_TID_SIBLING :
                                               requests[i].role;
        if (address == 0)
            continue;
        /* Checked preflight refreshes clean file bytes under the frozen
         * guard, but does not establish COW. Replay does that transaction
         * only after native exec and its exact caller eligibility check. */
        if (!sparc64_space_prepare_write(space, address, EXEC_TID_BYTES)) {
            if (space->internal_failure || sparc64_fault_is_runtime(space->fault_reason)) {
                free(intents);
                errno = space->fault_reason == SPARC64_FAULT_RESOURCE ? ENOMEM : EIO;
                return -1;
            }
            continue; /* mm_release ignores an inaccessible user TID word. */
        }
        sparc64_exec_tid_clear_t intent = {0};
        intent.role = role;
        uint32_t remaining = EXEC_TID_BYTES;
        uint64_t current = address;
        while (remaining != 0) {
            uint32_t offset = (uint32_t)(current & (SPARC64_PAGE_SIZE - 1));
            uint32_t length = (uint32_t)(SPARC64_PAGE_SIZE - offset);
            if (length > remaining)
                length = remaining;
            const sparc64_vma_t *vma = vma_at(memory, current);
            if (vma != NULL && (same_mm ||
                vma->kind == SPARC64_VMA_ANONYMOUS_SHARED)) {
                const sparc64_page_t *page = find_page(space, current);
                sparc64_family_page_key_t key;
                if (page == NULL || page->backing == NULL ||
                    page->backing->payload == NULL ||
                    !sparc64_family_backing_key(backing, page->backing->payload, &key) ||
                    key.page_index > UINT32_MAX) {
                    free(intents);
                    errno = EIO;
                    return -1;
                }
                uint32_t segment = intent.segment_count++;
                intent.keys[segment] = key;
                intent.offsets[segment] = offset;
                intent.lengths[segment] = length;
            }
            current += length;
            remaining -= length;
        }
        if (intent.segment_count != 0) {
            if (same_mm && intent.segment_count == 1 &&
                intent.lengths[0] == EXEC_TID_BYTES && (address & 3u) == 0) {
                const sparc64_vma_t *vma = vma_at(memory, address);
                if (vma != NULL && vma->kind != SPARC64_VMA_ANONYMOUS_SHARED)
                    intent.mm_shared_wake_address = address;
            }
            intents[used++] = intent;
        }
    }
    if (used == 0) {
        free(intents);
        intents = NULL;
    } else if (check_capacity(guard, intents, used) != 0) {
        free(intents);
        return -1;
    }
    *out = intents;
    *out_count = used;
    return 0;
}

int sparc64_exec_tid_capture(sparc64_family_guard_t *guard, sparc64_space_t *space,
                        const sparc64_linux_memory_t *memory,
                        sparc64_family_backing_t *backing,
                        const uint64_t *addresses, size_t address_count,
                        sparc64_exec_tid_clear_t **out, size_t *out_count)
{
    return capture(guard, space, memory, backing, addresses, address_count,
                   NULL, out, out_count, false);
}

int sparc64_exec_tid_capture_same_mm(sparc64_family_guard_t *guard, sparc64_space_t *space,
                        const sparc64_linux_memory_t *memory,
                        sparc64_family_backing_t *backing,
                        const uint64_t *addresses, size_t address_count,
                        sparc64_exec_tid_clear_t **out, size_t *out_count)
{
    return capture(guard, space, memory, backing, addresses, address_count,
                   NULL, out, out_count, true);
}

int sparc64_exec_tid_capture_tagged(sparc64_family_guard_t *guard, sparc64_space_t *space,
                        const sparc64_linux_memory_t *memory,
                        sparc64_family_backing_t *backing,
                        const sparc64_exec_tid_request_t *requests, size_t count,
                        bool same_mm,
                        sparc64_exec_tid_clear_t **out, size_t *out_count)
{
    return capture(guard, space, memory, backing, NULL, count,
                   requests, out, out_count, same_mm);
}

static int live_foreign_old_mm_peer(sparc64_family_guard_t *guard,
                                    sparc64_family_mm_t old_mm, bool *live)
{
    sparc64_family_mm_state_t state = {0};
    if (old_mm.mm_id == 0 || old_mm.root_object == 0 || live == NULL ||
        sparc64_family_mm_read(guard, old_mm, &state) != 0) {
        errno = EIO; /* An imported conditional store needs an exact root. */
        return -1;
    }
    bool local_member = false;
    *live = false;
    for (size_t i = 0; i < state.member_count; ++i) {
        uint64_t owner = state.members[i].owner_incarnation;
        if (owner == guard->incarnation) {
            local_member = true;
            continue;
        }
        bool alive = false;
        if (sparc64_family_owner_alive(guard, owner, &alive) != 0) {
            sparc64_family_mm_state_destroy(&state);
            errno = EIO;
            return -1;
        }
        *live = *live || alive;
    }
    sparc64_family_mm_state_destroy(&state);
    if (!local_member) {
        errno = EIO;
        return -1;
    }
    return 0;
}

static int replay(sparc64_family_guard_t *guard, sparc64_family_mm_t old_mm,
                  const sparc64_exec_tid_clear_t *intents, size_t count)
{
    if (guard == NULL || old_mm.mm_id == 0 ||
        (count != 0 && intents == NULL) || count > EXEC_TID_MAX) {
        errno = EINVAL;
        return -1;
    }
    size_t callers = 0;
    for (size_t i = 0; i < count; ++i) {
        const sparc64_exec_tid_clear_t *intent = &intents[i];
        if (intent->role > SPARC64_EXEC_TID_CALLER_IF_LIVE_PEER ||
            intent->segment_count == 0 || intent->segment_count > 2 ||
            (intent->mm_shared_wake_address != 0 &&
             (intent->segment_count != 1 || intent->lengths[0] != 4 ||
              (intent->mm_shared_wake_address & 3u) != 0 ||
              (intent->mm_shared_wake_address & (SPARC64_PAGE_SIZE - 1u)) !=
                  intent->offsets[0])) ||
            (intent->role == SPARC64_EXEC_TID_CALLER_IF_LIVE_PEER &&
             (++callers > 1 || old_mm.root_object == 0))) {
            errno = EINVAL;
            return -1;
        }
        for (uint32_t segment = 0; segment < intent->segment_count; ++segment)
            if (intent->keys[segment].object_id == 0 ||
                intent->keys[segment].page_index > UINT32_MAX ||
                intent->lengths[segment] == 0 ||
                intent->lengths[segment] > EXEC_TID_BYTES ||
                intent->offsets[segment] >
                    SPARC64_FAMILY_PAGE_SIZE - intent->lengths[segment]) {
                errno = EINVAL;
                return -1;
            }
        uint32_t total = intent->lengths[0];
        if (intent->segment_count == 2)
            total += intent->lengths[1];
        if (total > EXEC_TID_BYTES ||
            (intent->segment_count == 1 &&
             (intent->keys[1].object_id != 0 ||
              intent->keys[1].page_index != 0 ||
              intent->offsets[1] != 0 || intent->lengths[1] != 0)) ||
            (intent->segment_count == 2 &&
             intent->keys[0].object_id == intent->keys[1].object_id &&
             intent->keys[0].page_index == intent->keys[1].page_index &&
             intent->offsets[0] < intent->offsets[1] + intent->lengths[1] &&
             intent->offsets[1] < intent->offsets[0] + intent->lengths[0])) {
            errno = EINVAL;
            return -1;
        }
    }
    sparc64_family_file_index_state_t index = {0};
    if (file_origins_read(guard, &index) != 0)
        return -1;
    for (size_t i = 0; i < count; ++i) {
        const sparc64_exec_tid_clear_t *intent = &intents[i];
        if (intent->role == SPARC64_EXEC_TID_CALLER_IF_LIVE_PEER) {
            bool live = false;
            /* This is the caller store's mm_users read-before-put_user
             * linearization. Native peer death may race after this sample,
             * as on Linux; never reuse the earlier freeze-time result. */
            if (live_foreign_old_mm_peer(guard, old_mm, &live) != 0) {
                sparc64_family_file_index_state_destroy(&index);
                return -1;
            }
            if (!live)
                continue;
        }
        sparc64_family_object_t *objects[2] = {NULL, NULL};
        sparc64_family_page_key_t keys[2] = {{0, 0}, {0, 0}};
        sparc64_family_page_state_t targets[2];
        bool touched[2][SPARC64_FAMILY_EPOCHS] = {{false}};
        bool first_cow[2] = {false, false};
        size_t unique = 0;
        int failure = 0;
        for (uint32_t segment = 0; segment < intent->segment_count; ++segment) {
            sparc64_family_page_key_t key = intent->keys[segment];
            uint32_t offset = intent->offsets[segment];
            uint32_t length = intent->lengths[segment];
            size_t target = 0;
            while (target < unique && (keys[target].object_id != key.object_id ||
                   keys[target].page_index != key.page_index))
                ++target;
            if (target == unique) {
                if (sparc64_family_object_open(guard, key.object_id,
                                          &objects[unique]) != 0 ||
                    sparc64_family_object_snapshot(guard, objects[unique],
                                               (uint32_t)key.page_index,
                                               &targets[unique]) != 0) {
                    failure = errno;
                    if (objects[unique] != NULL)
                        ++unique;
                    break;
                }
                bool file = file_origin(&index, key);
                if ((file && !clean_file_state(&targets[unique])) ||
                    (!file && targets[unique].private_cow != 0)) {
                    failure = EIO;
                    ++unique;
                    break;
                }
                first_cow[unique] = file && targets[unique].private_cow == 0;
                keys[unique++] = key;
            }
            memset(targets[target].bytes + offset, 0, length);
            for (uint32_t byte = offset; byte < offset + length; ++byte)
                touched[target][byte / 16u] = true;
        }
        sparc64_family_object_update_t updates[2];
        for (size_t page = 0; failure == 0 && page < unique; ++page) {
            if (targets[page].content_generation == UINT64_MAX) {
                failure = EOVERFLOW;
                break;
            }
            ++targets[page].content_generation;
            for (size_t epoch = 0; epoch < SPARC64_FAMILY_EPOCHS; ++epoch) {
                uint64_t charge = (first_cow[page] ? 1u : 0u) +
                                  (touched[page][epoch] ? 1u : 0u);
                if (targets[page].epochs[epoch] > UINT64_MAX - charge) {
                    failure = EOVERFLOW;
                    break;
                }
                targets[page].epochs[epoch] += charge;
            }
            if (failure != 0)
                break;
            if (first_cow[page])
                targets[page].private_cow = 1;
            updates[page] = (sparc64_family_object_update_t){objects[page],
                (uint32_t)keys[page].page_index, &targets[page]};
        }
        sparc64_family_wait_table_t table = {0};
        if (failure == 0 && (sparc64_family_wait_table_read(guard, &table) != 0 ||
                             sparc64_family_wait_table_sweep(guard, &table) != 0))
            failure = errno;
        /* Only a complete aligned shared word has a Linux futex key. A
         * partial shared fragment still receives its best-effort zero bytes. */
        if (failure == 0 && intent->segment_count == 1 &&
            intent->lengths[0] == 4 && (intent->offsets[0] & 3u) == 0) {
            uint64_t offset = intent->keys[0].page_index * SPARC64_FAMILY_PAGE_SIZE +
                              intent->offsets[0];
            for (size_t row = 0; row < table.count; ++row) {
                sparc64_family_wait_row_t *wait = &table.rows[row];
                bool matching_object = intent->mm_shared_wake_address == 0 &&
                    wait->key.kind == SPARC64_FAMILY_WAIT_OBJECT &&
                    wait->key.identity == intent->keys[0].object_id &&
                    wait->key.offset == offset;
                bool matching_mm = intent->mm_shared_wake_address != 0 &&
                    wait->key.kind == SPARC64_FAMILY_WAIT_MM_SHARED &&
                    wait->key.identity == old_mm.mm_id &&
                    wait->key.offset == intent->mm_shared_wake_address;
                if (wait->state == SPARC64_FAMILY_WAITING &&
                    (matching_object || matching_mm)) {
                    wait->state = SPARC64_FAMILY_WOKEN;
                    break;
                }
            }
        }
        if (failure == 0 &&
            sparc64_family_wait_table_commit(guard, &table, updates, unique) != 0)
            failure = errno;
        sparc64_family_wait_table_destroy(&table);
        for (size_t page = 0; page < unique; ++page)
            sparc64_family_object_close(objects[page]);
        if (failure != 0) {
            sparc64_family_file_index_state_destroy(&index);
            errno = failure;
            return -1;
        }
    }
    sparc64_family_file_index_state_destroy(&index);
    return 0;
}

int sparc64_exec_tid_replay(sparc64_family_guard_t *guard, uint64_t old_mm_id,
                       const sparc64_exec_tid_clear_t *intents, size_t count)
{
    return replay(guard, (sparc64_family_mm_t){.mm_id = old_mm_id}, intents, count);
}

int sparc64_exec_tid_replay_old_mm(sparc64_family_guard_t *guard, sparc64_family_mm_t old_mm,
                       const sparc64_exec_tid_clear_t *intents, size_t count)
{
    return replay(guard, old_mm, intents, count);
}
