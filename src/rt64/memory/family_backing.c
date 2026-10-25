/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#include "memory/family_backing.h"
#include "runtime/family_file_index.h"

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

typedef struct family_object_node {
    sparc64_family_object_t *object;
    uint32_t next_slot;
    bool local;
    struct family_object_node *next;
} family_object_node_t;

typedef struct family_payload family_payload_t;

typedef struct {
    uint64_t content_generation;
    uint64_t epochs[SPARC64_FAMILY_EPOCHS];
    uint64_t notified[4];
    uint32_t private_cow;
    uint32_t reserved;
} family_refresh_metadata_t;

struct sparc64_family_backing {
    sparc64_family_t *family;
    sparc64_family_guard_t *guard;
    uint32_t slots_per_object;
    uint32_t bootstrap_slots;
    family_object_node_t *objects;
    family_payload_t *payloads; /* Weak key index; disposal unlinks entries. */
    size_t live_payloads;
};

struct family_payload {
    sparc64_page_payload_t payload;
    sparc64_family_backing_t *owner;
    sparc64_family_object_t *object;
    uint32_t page_index;
    sparc64_family_page_state_t mirror;
    family_refresh_metadata_t refresh_metadata;
    sparc64_family_refresh_stamp_t refresh_stamp;
    bool refresh_metadata_valid;
    bool refresh_stamp_valid;
    enum { WRITE_ORIGIN_UNKNOWN, WRITE_ORIGIN_ANON, WRITE_ORIGIN_FILE } write_origin;
    family_payload_t *next;
};

static bool guard_matches(const sparc64_family_backing_t *backing)
{
    return backing != NULL &&
           sparc64_family_guard_matches(backing->guard, backing->family);
}

static bool managed_check_guard(void *context)
{
    return guard_matches(context);
}

static void family_payload_dispose(sparc64_page_payload_t *payload);

static family_payload_t *checked_payload(sparc64_family_backing_t *backing,
                                         sparc64_page_payload_t *payload)
{
    if (backing == NULL || payload == NULL ||
        payload->dispose != family_payload_dispose)
        return NULL;
    family_payload_t *managed = (family_payload_t *)payload;
    return managed->owner == backing && &managed->payload == payload ? managed : NULL;
}

static bool refresh_metadata_matches(const family_payload_t *managed)
{
    const family_refresh_metadata_t *proof = &managed->refresh_metadata;
    return managed->refresh_metadata_valid &&
        proof->content_generation == managed->mirror.content_generation &&
        proof->private_cow == managed->mirror.private_cow &&
        proof->reserved == managed->mirror.reserved &&
        memcmp(proof->notified, managed->mirror.notified,
               sizeof(proof->notified)) == 0 &&
        memcmp(proof->epochs, managed->mirror.epochs,
               sizeof(proof->epochs)) == 0;
}

static void refresh_metadata_save(family_payload_t *managed)
{
    family_refresh_metadata_t *proof = &managed->refresh_metadata;
    proof->content_generation = managed->mirror.content_generation;
    proof->private_cow = managed->mirror.private_cow;
    proof->reserved = managed->mirror.reserved;
    memcpy(proof->notified, managed->mirror.notified, sizeof(proof->notified));
    memcpy(proof->epochs, managed->mirror.epochs, sizeof(proof->epochs));
    managed->refresh_metadata_valid = true;
}

static void family_payload_dispose(sparc64_page_payload_t *payload)
{
    family_payload_t *managed = (family_payload_t *)payload;
    sparc64_family_backing_t *backing = managed->owner;
    family_payload_t **entry = &backing->payloads;
    while (*entry != NULL && *entry != managed)
        entry = &(*entry)->next;
    if (*entry == managed)
        *entry = managed->next;
    --backing->live_payloads;
    free(managed);
}

static sparc64_page_payload_t *payload_for_slot(sparc64_family_backing_t *backing,
                                           sparc64_family_object_t *object,
                                           uint32_t slot,
                                           sparc64_fault_reason_t *reason)
{
    if (!guard_matches(backing) || backing->live_payloads == SIZE_MAX) {
        if (reason != NULL)
            *reason = SPARC64_FAULT_INTERNAL;
        return NULL;
    }
    family_payload_t *managed = calloc(1, sizeof(*managed));
    if (managed == NULL) {
        if (reason != NULL)
            *reason = SPARC64_FAULT_RESOURCE;
        return NULL;
    }
    managed->owner = backing;
    managed->object = object;
    managed->page_index = slot;
    if (sparc64_family_object_snapshot(backing->guard, object, slot,
                                  &managed->mirror) != 0) {
        free(managed);
        if (reason != NULL)
            *reason = SPARC64_FAULT_INTERNAL;
        return NULL;
    }
    /* The first managed refresh must still validate canonical metadata before
     * it can seed a reusable stamp. */
    managed->payload = (sparc64_page_payload_t){
        .bytes = managed->mirror.bytes,
        .epochs = managed->mirror.epochs,
        .references = 1,
        .dispose = family_payload_dispose,
        .backend = SPARC64_PAYLOAD_MANAGED,
        .canonical_private_cow = &managed->mirror.private_cow
    };
    managed->next = backing->payloads;
    backing->payloads = managed;
    ++backing->live_payloads;
    return &managed->payload;
}

static sparc64_page_payload_t *family_payload_allocate(sparc64_family_backing_t *backing,
                                                   sparc64_fault_reason_t *reason)
{
    if (reason != NULL)
        *reason = SPARC64_FAULT_INTERNAL;
    if (!guard_matches(backing))
        return NULL;
    family_object_node_t *node = backing->objects;
    while (node != NULL && (!node->local ||
                            node->next_slot >= sparc64_family_object_count(node->object)))
        node = node->next;
    if (node == NULL) {
        family_object_node_t *new_node = calloc(1, sizeof(*new_node));
        if (new_node == NULL) {
            if (reason != NULL)
                *reason = SPARC64_FAULT_RESOURCE;
            return NULL;
        }
        uint32_t slots = backing->bootstrap_slots != 0 ?
                         backing->bootstrap_slots : backing->slots_per_object;
        if (sparc64_family_object_create(backing->guard, slots,
                                    &new_node->object) != 0) {
            free(new_node);
            return NULL;
        }
        new_node->local = true;
        new_node->next = backing->objects;
        backing->objects = new_node;
        node = new_node;
    }
    sparc64_page_payload_t *payload = payload_for_slot(backing, node->object,
                                                   node->next_slot, reason);
    if (payload == NULL)
        return NULL;
    ++node->next_slot;
    return payload;
}

static sparc64_page_payload_t *family_payload_create(void *context)
{
    return family_payload_allocate(context, NULL);
}

typedef struct {
    sparc64_family_backing_t *backing;
    sparc64_fault_reason_t failure;
    bool failed;
} staged_factory_t;

static sparc64_page_payload_t *staged_payload_create(void *context)
{
    staged_factory_t *factory = context;
    sparc64_page_payload_t *payload = family_payload_allocate(factory->backing, &factory->failure);
    if (payload == NULL)
        factory->failed = true;
    return payload;
}

bool sparc64_family_backing_stage_anonymous(sparc64_family_backing_t *backing,
                                        sparc64_space_t *space, uint64_t address,
                                        uint64_t size, unsigned int permissions)
{
    if (space == NULL)
        return false;
    if (!guard_matches(backing) || space->internal_failure ||
        space->count != 0 || space->pages != NULL ||
        space->page_factory.create != family_payload_create ||
        space->page_factory.context != backing || space->managed.context != backing) {
        space->fault_address = address; space->fault_reason = SPARC64_FAULT_INTERNAL;
        return false;
    }
    /* Only an unpublished empty candidate uses this stack-owned factory.
     * The live managed callbacks/context are untouched. Generic factories
     * retain space.c's conservative NULL=internal-failure contract. */
    sparc64_page_factory_t original = space->page_factory;
    staged_factory_t factory = {backing, SPARC64_FAULT_INTERNAL, false};
    space->page_factory = (sparc64_page_factory_t){staged_payload_create, &factory};
    bool result = sparc64_space_map(space, address, size, permissions, false);
    space->page_factory = original;
    if (!result && space->fault_reason == SPARC64_FAULT_INTERNAL && factory.failed &&
        factory.failure == SPARC64_FAULT_RESOURCE) {
        space->fault_reason = SPARC64_FAULT_RESOURCE;
        space->internal_failure = false;
        errno = ENOMEM;
    }
    return result;
}

static bool managed_refresh(void *context, sparc64_page_payload_t *payload,
                            bool can_publish, bool *changed,
                            sparc64_measure_observer_t *measure)
{
    sparc64_family_backing_t *backing = context;
    family_payload_t *managed = checked_payload(backing, payload);
    if (backing == NULL || managed == NULL || changed == NULL)
        return false;
    sparc64_family_refresh_stamp_t observation;
    bool reusable = false;
    sparc64_measure_stamp_t check_stamp = sparc64_measure_begin(
        measure, SPARC64_MEASURE_FAMILY_REFRESH_CHECK);
    if (sparc64_family_refresh_observation_observed(backing->guard, backing->family,
                                               &observation, &reusable,
                                               measure) != 0) {
        sparc64_measure_end(measure, SPARC64_MEASURE_FAMILY_REFRESH_CHECK, check_stamp);
        return false;
    }
    bool stamp_matches = reusable && managed->refresh_stamp_valid &&
        managed->refresh_stamp.acquisition == observation.acquisition &&
        managed->refresh_stamp.mutation == observation.mutation &&
        refresh_metadata_matches(managed);
    sparc64_measure_end(measure, SPARC64_MEASURE_FAMILY_REFRESH_CHECK, check_stamp);
    if (stamp_matches) {
        sparc64_measure_stamp_t hit_stamp = sparc64_measure_begin(
            measure, SPARC64_MEASURE_FAMILY_REFRESH_HIT);
        *changed = false;
        sparc64_measure_end(measure, SPARC64_MEASURE_FAMILY_REFRESH_HIT, hit_stamp);
        return true;
    }
    sparc64_family_page_state_t current;
    sparc64_measure_stamp_t snapshot_stamp = sparc64_measure_begin(measure, SPARC64_MEASURE_FAMILY_SNAPSHOT);
    int snapshot = sparc64_family_object_snapshot_for_observed(backing->guard,
        backing->family, managed->object, managed->page_index, &current, measure);
    sparc64_measure_end(measure, SPARC64_MEASURE_FAMILY_SNAPSHOT, snapshot_stamp);
    if (snapshot != 0)
        return false;
    if (current.private_cow > 1 || current.reserved != 0) {
        errno = EIO;
        return false;
    }
    sparc64_measure_stamp_t compare_stamp = sparc64_measure_begin(measure, SPARC64_MEASURE_FAMILY_COMPARE);
    *changed = current.content_generation != managed->mirror.content_generation ||
               current.private_cow != managed->mirror.private_cow ||
               current.reserved != managed->mirror.reserved ||
               memcmp(current.notified, managed->mirror.notified,
                      sizeof(current.notified)) != 0 ||
               memcmp(current.epochs, managed->mirror.epochs,
                      sizeof(current.epochs)) != 0 ||
               memcmp(current.bytes, managed->mirror.bytes,
                      sizeof(current.bytes)) != 0;
    sparc64_measure_end(measure, SPARC64_MEASURE_FAMILY_COMPARE, compare_stamp);
    if (*changed && !can_publish)
        return false;
    if (*changed)
        memcpy(&managed->mirror, &current, sizeof(current));
    if (sparc64_family_refresh_observation_observed(backing->guard, backing->family,
                                               &observation, &reusable,
                                               measure) != 0)
        return false;
    managed->refresh_stamp_valid = reusable;
    if (reusable) {
        refresh_metadata_save(managed);
        managed->refresh_stamp = observation;
    }
    return true;
}

static bool origin_matches(sparc64_family_backing_t *backing, family_payload_t *managed,
                             bool expected_file, bool allow_resolve)
{
    if (managed->write_origin == WRITE_ORIGIN_UNKNOWN) {
        if (!allow_resolve) { errno = EIO; return false; }
        bool file = false;
        uint64_t root = sparc64_family_file_index_object(backing->guard);
        if (root == 0 && errno != EOPNOTSUPP)
            return false;
        if (root != 0) {
            sparc64_family_file_index_state_t index = {0};
            if (sparc64_family_file_index_read(backing->guard, root, &index) != 0)
                return false;
            uint64_t object = sparc64_family_object_id(managed->object);
            for (size_t i = 0; i < index.association_count; ++i)
                if (index.associations[i].key.object_id == object &&
                    index.associations[i].key.page_index == managed->page_index) {
                    file = true;
                    break;
                }
            sparc64_family_file_index_state_destroy(&index);
        }
        if (file != expected_file) { errno = EIO; return false; }
        /* Only guarded write preflight resolves this cache. Fresh FILE keys
         * are initially staged as anonymous but are not written before their
         * global admission. Trusted admission never retrofits a used ANON key,
         * and retains FILE origins forever. This relies on that admission
         * contract; the raw index codec does not authenticate ANON history. */
        managed->write_origin = file ? WRITE_ORIGIN_FILE : WRITE_ORIGIN_ANON;
    }
    if ((managed->write_origin == WRITE_ORIGIN_FILE) != expected_file) {
        errno = EIO; return false;
    }
    if (expected_file && (managed->mirror.private_cow > 1 ||
        managed->mirror.reserved != 0 || managed->mirror.notified[0] != 0 ||
        managed->mirror.notified[1] != 0 || managed->mirror.notified[2] != 0 ||
        managed->mirror.notified[3] != 0)) {
        errno = EIO; return false;
    }
    return true;
}

static bool managed_check_write(void *context, sparc64_page_payload_t *payload,
                                  bool expected_file, bool allow_resolve)
{
    sparc64_family_backing_t *backing = context;
    family_payload_t *managed = checked_payload(backing, payload);
    return guard_matches(backing) && managed != NULL &&
           managed->mirror.content_generation != UINT64_MAX &&
           origin_matches(backing, managed, expected_file, allow_resolve);
}

static bool commit_updates(sparc64_family_backing_t *backing,
                            const sparc64_managed_page_update_t *updates,
                            size_t count, sparc64_family_wait_table_t *table)
{
    if (!guard_matches(backing) || (count != 0 && updates == NULL) ||
        (count == 0 && table == NULL) || count > 2) {
        errno = EIO;
        return false;
    }
    sparc64_family_page_state_t targets[2];
    sparc64_family_object_update_t commits[2];
    family_payload_t *managed[2] = {NULL, NULL};
    for (size_t i = 0; i < count; ++i) {
        managed[i] = checked_payload(backing, updates[i].payload);
        if (managed[i] == NULL || managed[i]->mirror.content_generation == UINT64_MAX) {
            errno = EIO;
            return false;
        }
        bool file = managed[i]->write_origin == WRITE_ORIGIN_FILE;
        if (managed[i]->write_origin == WRITE_ORIGIN_UNKNOWN ||
            !origin_matches(backing, managed[i], file, false) ||
            (updates[i].make_private_cow &&
             (!file || managed[i]->mirror.private_cow != 0)) ||
            (file && managed[i]->mirror.private_cow == 0 &&
             !updates[i].make_private_cow)) {
            errno = EIO;
            return false;
        }
        targets[i] = managed[i]->mirror;
        memcpy(targets[i].bytes, updates[i].bytes, sizeof(targets[i].bytes));
        memcpy(targets[i].epochs, updates[i].epochs, sizeof(targets[i].epochs));
        if (updates[i].make_private_cow)
            targets[i].private_cow = 1;
        ++targets[i].content_generation;
        commits[i] = (sparc64_family_object_update_t){
            managed[i]->object, managed[i]->page_index, &targets[i]
        };
    }
    int result = table == NULL ?
        sparc64_family_object_commitv(backing->guard, commits, count) :
        sparc64_family_wait_table_commit(backing->guard, table,
                                     count == 0 ? NULL : commits, count);
    if (result != 0) {
        /* Replay allocates too. ENOMEM after COMMITTED poisons the family:
         * it is an irreversible runtime failure, never a guest retry. */
        if (table != NULL && (errno != ENOMEM || !guard_matches(backing)))
            errno = EIO;
        return false;
    }
    for (size_t i = 0; i < count; ++i)
        managed[i]->mirror = targets[i];
    return true;
}

static bool managed_commitv(void *context,
                            const sparc64_managed_page_update_t *updates,
                            size_t count)
{
    return commit_updates(context, updates, count, NULL);
}

bool sparc64_family_backing_commit_wait(sparc64_family_backing_t *backing,
                                    sparc64_family_wait_table_t *table,
                                    const sparc64_managed_page_update_t *updates,
                                    size_t count)
{
    if (table == NULL) {
        errno = EIO;
        return false;
    }
    return commit_updates(backing, updates, count, table);
}

static sparc64_managed_page_ops_t managed_ops(sparc64_family_backing_t *backing)
{
    return (sparc64_managed_page_ops_t){
        managed_check_guard, managed_refresh, managed_check_write,
        managed_commitv, backing
    };
}

int sparc64_family_backing_create(sparc64_family_backing_t **out, sparc64_family_t *family,
                             uint32_t slots_per_object)
{
    if (out == NULL || family == NULL || slots_per_object == 0 ||
        slots_per_object > SPARC64_FAMILY_OBJECT_MAX_SLOTS) {
        errno = EINVAL;
        return -1;
    }
    *out = NULL;
    sparc64_family_backing_t *backing = calloc(1, sizeof(*backing));
    if (backing == NULL)
        return -1;
    backing->family = family;
    backing->slots_per_object = slots_per_object;
    *out = backing;
    return 0;
}

int sparc64_family_backing_bind(sparc64_family_backing_t *backing,
                           sparc64_family_guard_t *guard)
{
    if (backing == NULL || backing->guard != NULL ||
        !sparc64_family_guard_matches(guard, backing->family)) {
        errno = EINVAL;
        return -1;
    }
    backing->guard = guard;
    return 0;
}

bool sparc64_family_backing_guard_matches(const sparc64_family_backing_t *backing,
                                      const sparc64_family_guard_t *guard)
{
    return backing != NULL && backing->guard == guard && guard_matches(backing);
}

int sparc64_family_backing_file_intern(sparc64_family_backing_t *backing,
                                   const sparc64_file_identity_t *identity, int fd,
                                   uint64_t *file_id)
{
    if (!guard_matches(backing)) {
        errno = EIO;
        return -1;
    }
    int result = sparc64_family_file_intern(backing->guard, identity, fd, file_id);
    if (result != 0 && !guard_matches(backing))
        errno = EIO;
    return result;
}

void sparc64_family_backing_unbind(sparc64_family_backing_t *backing)
{
    if (backing != NULL)
        backing->guard = NULL;
}

bool sparc64_family_backing_install(sparc64_family_backing_t *backing, sparc64_space_t *space)
{
    if (backing == NULL || space == NULL)
        return false;
    sparc64_page_factory_t factory = {family_payload_create, backing};
    return sparc64_space_set_managed_factory(space, factory, managed_ops(backing));
}

typedef struct {
    sparc64_page_payload_t *old_payload, *new_payload;
    size_t views;
} adoption_pair_t;

static int compare_adoption_pairs(const void *left, const void *right)
{
    const adoption_pair_t *a = left, *b = right;
    uintptr_t a_key = (uintptr_t)a->old_payload;
    uintptr_t b_key = (uintptr_t)b->old_payload;
    return a_key < b_key ? -1 : a_key != b_key;
}

static bool adoption_fail(sparc64_space_t *space, uint64_t address,
                          sparc64_fault_reason_t reason)
{
    space->fault_address = address;
    space->fault_reason = reason;
    if (reason == SPARC64_FAULT_INTERNAL)
        space->internal_failure = true;
    return false;
}

static void release_staged_payload(sparc64_page_payload_t *payload)
{
    if (payload != NULL && --payload->references == 0)
        payload->dispose(payload);
}

static bool valid_initial_epochs(const sparc64_page_payload_t *payload)
{
    static const unsigned char zeros[SPARC64_RESERVATION_GRANULE] = {0};
    for (size_t i = 0; i < SPARC64_PAGE_GRANULES; ++i)
        if (payload->epochs[i] == 0 &&
            memcmp(payload->bytes + i * SPARC64_RESERVATION_GRANULE,
                   zeros, sizeof(zeros)) != 0)
            return false;
    return true;
}

bool sparc64_family_backing_adopt(sparc64_family_backing_t *backing, sparc64_space_t *space)
{
    if (space == NULL)
        return false;
    space->fault_reason = SPARC64_FAULT_NONE;
    if (!guard_matches(backing) || space->managed.commitv != NULL ||
        space->internal_failure)
        return adoption_fail(space, 0, SPARC64_FAULT_INTERNAL);
    if (space->count == 0)
        return sparc64_family_backing_install(backing, space);
    uint64_t first_address = space->pages[0].address;
    if (space->generation == UINT64_MAX ||
        space->count > (UINT64_MAX - space->next_binding) / SPARC64_PAGE_GRANULES)
        return adoption_fail(space, first_address, SPARC64_FAULT_INTERNAL);
    adoption_pair_t *pairs = malloc(space->count * sizeof(*pairs));
    sparc64_page_t *pages = malloc(space->count * sizeof(*pages));
    if (pairs == NULL || pages == NULL) {
        free(pairs);
        free(pages);
        return adoption_fail(space, first_address, SPARC64_FAULT_RESOURCE);
    }
    size_t anonymous = 0;
    for (size_t i = 0; i < space->count; ++i) {
        sparc64_backing_t *view = space->pages[i].backing;
        if (view == NULL || view->payload == NULL || view->references != 1 ||
            view->bytes != view->payload->bytes ||
            view->epochs != view->payload->epochs ||
            view->payload->backend != SPARC64_PAYLOAD_HEAP) {
            free(pairs);
            free(pages);
            return adoption_fail(space, space->pages[i].address,
                                 SPARC64_FAULT_INTERNAL);
        }
        if (view->file == NULL)
            pairs[anonymous++] = (adoption_pair_t){.old_payload = view->payload};
    }
    qsort(pairs, anonymous, sizeof(*pairs), compare_adoption_pairs);
    size_t unique = 0;
    for (size_t i = 0; i < anonymous; ++i) {
        if (unique == 0 || pairs[i].old_payload != pairs[unique - 1].old_payload)
            pairs[unique++] = pairs[i];
        ++pairs[unique - 1].views;
    }
    for (size_t i = 0; i < unique; ++i) {
        if (pairs[i].old_payload->references != pairs[i].views ||
            !valid_initial_epochs(pairs[i].old_payload)) {
            free(pairs);
            free(pages);
            return adoption_fail(space, first_address, SPARC64_FAULT_INTERNAL);
        }
    }
    /* A hard-zero initial image can otherwise consume one SysV identifier per
     * 64 pages before it executes a guest instruction. Pack its already
     * validated anonymous payloads into one bounded object. The 480-slot cap
     * keeps this object's full extent below the 4 MiB host SysV limit; later
     * allocations retain the configured ordinary 64-slot object size. */
    if (sparc64_family_zero_backing(backing->family) &&
        unique > backing->slots_per_object && unique <= 480u)
        backing->bootstrap_slots = (uint32_t)unique;
    size_t created = 0, built = 0;
    sparc64_fault_reason_t reason = SPARC64_FAULT_INTERNAL;
    uint64_t fault_address = first_address;
    for (size_t i = 0; i < unique; ++i) {
        sparc64_page_payload_t *payload = family_payload_create(backing);
        if (payload == NULL)
            goto rollback;
        pairs[i].new_payload = payload;
        ++created;
        if (payload->backend != SPARC64_PAYLOAD_MANAGED)
            goto rollback;
    }
    uint64_t binding = space->next_binding;
    for (size_t i = 0; i < space->count; ++i) {
        sparc64_page_t old = space->pages[i];
        sparc64_backing_t *view = old.backing;
        if (view->file == NULL) {
            adoption_pair_t key = {.old_payload = view->payload};
            adoption_pair_t *pair = bsearch(&key, pairs, unique,
                                             sizeof(*pairs), compare_adoption_pairs);
            if (pair == NULL || pair->new_payload->references == SIZE_MAX) {
                fault_address = old.address;
                goto rollback;
            }
            sparc64_backing_t *replacement = calloc(1, sizeof(*replacement));
            if (replacement == NULL) {
                reason = SPARC64_FAULT_RESOURCE;
                fault_address = old.address;
                goto rollback;
            }
            ++pair->new_payload->references;
            replacement->payload = pair->new_payload;
            replacement->bytes = pair->new_payload->bytes;
            replacement->epochs = pair->new_payload->epochs;
            replacement->references = 1;
            replacement->private_cow = view->private_cow;
            memcpy(replacement->file_notified, view->file_notified,
                   sizeof(replacement->file_notified));
            view = replacement;
        }
        pages[i] = (sparc64_page_t){old.address, old.permissions, view, binding};
        ++built;
        binding += SPARC64_PAGE_GRANULES;
    }
    /* All local allocations and source invariants are settled. Seed private
     * packed slots under the guard; none is reachable through guest mappings
     * until every batch has committed. Failed slots remain family-owned files
     * until quiescent cleanup, while the old image remains authoritative. */
    for (size_t i = 0; i < unique; ++i)
        if (!managed_check_write(backing, pairs[i].new_payload, false, true))
            goto rollback;
    for (size_t i = 0; i < unique; i += 2) {
        sparc64_managed_page_update_t updates[2] = {0};
        size_t count = unique - i < 2 ? unique - i : 2;
        for (size_t j = 0; j < count; ++j) {
            updates[j].payload = pairs[i + j].new_payload;
            memcpy(updates[j].bytes, pairs[i + j].old_payload->bytes,
                   SPARC64_PAGE_SIZE);
            memcpy(updates[j].epochs, pairs[i + j].old_payload->epochs,
                   SPARC64_PAGE_GRANULES * sizeof(uint64_t));
        }
        if (!managed_commitv(backing, updates, count))
            goto rollback;
    }
    sparc64_page_t *old_pages = space->pages;
    space->pages = pages;
    space->page_factory = (sparc64_page_factory_t){family_payload_create, backing};
    space->managed = managed_ops(backing);
    space->next_binding = binding;
    ++space->generation;
    free(space->epoch_scratch);
    space->epoch_scratch = NULL;
    space->epoch_scratch_capacity = 0;
    for (size_t i = 0; i < space->count; ++i)
        if (old_pages[i].backing != pages[i].backing)
            sparc64_backing_release(old_pages[i].backing);
    free(old_pages);
    for (size_t i = 0; i < created; ++i)
        release_staged_payload(pairs[i].new_payload);
    backing->bootstrap_slots = 0;
    free(pairs);
    return true;

rollback:
    for (size_t i = 0; i < built; ++i)
        if (pages[i].backing != space->pages[i].backing)
            sparc64_backing_release(pages[i].backing);
    for (size_t i = 0; i < created; ++i)
        release_staged_payload(pairs[i].new_payload);
    backing->bootstrap_slots = 0;
    free(pages);
    free(pairs);
    return adoption_fail(space, fault_address, reason);
}

bool sparc64_family_backing_key(sparc64_family_backing_t *backing,
                           sparc64_page_payload_t *payload,
                           sparc64_family_page_key_t *out)
{
    family_payload_t *managed = checked_payload(backing, payload);
    if (managed == NULL || out == NULL)
        return false;
    *out = (sparc64_family_page_key_t){
        sparc64_family_object_id(managed->object), managed->page_index
    };
    return true;
}

static bool map_existing(sparc64_family_backing_t *backing,
                                  sparc64_space_t *space, uint64_t guest_page,
                                  unsigned int permissions,
                                  sparc64_family_page_key_t key,
                                  sparc64_file_source_t *source, uint64_t offset,
                                  bool staging)
{
    if (space == NULL)
        return false;
    if (backing == NULL || !guard_matches(backing) ||
        space->page_factory.create != family_payload_create ||
        space->page_factory.context != backing ||
        space->managed.context != backing)
        return adoption_fail(space, guest_page, SPARC64_FAULT_INTERNAL);
    if (key.object_id == 0 || key.page_index >= SPARC64_FAMILY_OBJECT_MAX_SLOTS)
        return adoption_fail(space, guest_page, SPARC64_FAULT_RANGE);

    family_object_node_t *node = backing->objects;
    while (node != NULL && sparc64_family_object_id(node->object) != key.object_id)
        node = node->next;
    bool new_node = node == NULL;
    if (new_node) {
        node = calloc(1, sizeof(*node));
        if (node == NULL)
            return adoption_fail(space, guest_page, SPARC64_FAULT_RESOURCE);
        if (sparc64_family_object_open(backing->guard, key.object_id,
                                  &node->object) != 0) {
            int saved = errno;
            free(node);
            sparc64_fault_reason_t reason = saved == ENOENT || saved == EINVAL ?
                                       SPARC64_FAULT_RANGE :
                                       saved == ENOMEM || saved == EMFILE ||
                                       saved == ENFILE ? SPARC64_FAULT_RESOURCE :
                                       SPARC64_FAULT_INTERNAL;
            return adoption_fail(space, guest_page, reason);
        }
    }
    if (key.page_index >= sparc64_family_object_count(node->object)) {
        if (new_node) {
            sparc64_family_object_close(node->object);
            free(node);
        }
        return adoption_fail(space, guest_page, SPARC64_FAULT_RANGE);
    }
    family_payload_t *canonical = backing->payloads;
    while (canonical != NULL &&
           (canonical->object != node->object ||
            canonical->page_index != key.page_index))
        canonical = canonical->next;
    sparc64_fault_reason_t reason = SPARC64_FAULT_INTERNAL;
    sparc64_page_payload_t *payload = canonical == NULL ?
        payload_for_slot(backing, node->object, (uint32_t)key.page_index,
                         &reason) :
        &canonical->payload;
    if (payload == NULL) {
        if (new_node) {
            sparc64_family_object_close(node->object);
            free(node);
        }
        return adoption_fail(space, guest_page, reason);
    }
    bool mapped = source == NULL ?
        sparc64_space_map_shared_payload(space, guest_page, permissions, payload) :
        staging ? sparc64_space_stage_managed_file_payload(space, guest_page,
                    permissions, payload, source, offset) :
        sparc64_space_map_managed_file_payload(space, guest_page, permissions, payload,
                                           source, offset);
    if (canonical == NULL)
        release_staged_payload(payload);
    if (!mapped) {
        if (new_node) {
            sparc64_family_object_close(node->object);
            free(node);
        }
        return false;
    }
    if (new_node) {
        node->next = backing->objects;
        backing->objects = node;
    } else if (canonical == NULL && node->local &&
               key.page_index >= node->next_slot) {
        /* Never allocate another local payload over imported live state. */
        node->next_slot = backing->slots_per_object;
    }
    return true;
}

bool sparc64_family_backing_map_shared(sparc64_family_backing_t *backing,
                                  sparc64_space_t *space, uint64_t guest_page,
                                  unsigned int permissions, sparc64_family_page_key_t key)
{
    return map_existing(backing, space, guest_page, permissions, key, NULL, 0, false);
}

bool sparc64_family_backing_map_file(sparc64_family_backing_t *backing,
                                sparc64_space_t *space, uint64_t guest_page,
                                unsigned int permissions, sparc64_family_page_key_t key,
                                sparc64_file_source_t *source, uint64_t offset)
{
    if (source == NULL)
        return false;
    return map_existing(backing, space, guest_page, permissions, key, source, offset, false);
}

bool sparc64_family_backing_stage_file(sparc64_family_backing_t *backing,
                                  sparc64_space_t *space, uint64_t guest_page,
                                  unsigned int permissions, sparc64_family_page_key_t key,
                                  sparc64_file_source_t *source, uint64_t offset)
{
    if (source == NULL || source->space == NULL ||
        source->space->managed.context != backing)
        return false;
    return map_existing(backing, space, guest_page, permissions, key, source, offset, true);
}

int sparc64_family_backing_snapshot(sparc64_family_backing_t *backing,
                                sparc64_page_payload_t *payload,
                                sparc64_family_page_state_t *out)
{
    family_payload_t *managed = checked_payload(backing, payload);
    if (!guard_matches(backing) || managed == NULL || out == NULL) {
        errno = EIO;
        return -1;
    }
    return sparc64_family_object_snapshot(backing->guard, managed->object,
                                      managed->page_index, out);
}

static int commit_full_state(sparc64_family_backing_t *backing,
                               sparc64_page_payload_t *payload,
                               const sparc64_family_page_state_t *target,
                               bool file_refresh)
{
    family_payload_t *managed = checked_payload(backing, payload);
    if (!guard_matches(backing) || managed == NULL || target == NULL) {
        errno = EIO;
        return -1;
    }
    int result = file_refresh ?
        sparc64_family_object_commit_file_refresh(backing->guard, managed->object,
                                                managed->page_index, target) :
        sparc64_family_object_commit(backing->guard, managed->object,
                                  managed->page_index, target);
    if (result != 0)
        return -1;
    managed->mirror = *target;
    return 0;
}

int sparc64_family_backing_commit_state(sparc64_family_backing_t *backing,
                                    sparc64_page_payload_t *payload,
                                    const sparc64_family_page_state_t *target)
{
    return commit_full_state(backing, payload, target, false);
}

int sparc64_family_backing_commit_file_refresh(sparc64_family_backing_t *backing,
                                           sparc64_page_payload_t *payload,
                                           const sparc64_family_page_state_t *target)
{
    return commit_full_state(backing, payload, target, true);
}

int sparc64_family_backing_destroy(sparc64_family_backing_t *backing)
{
    if (backing == NULL)
        return 0;
    if (backing->live_payloads != 0 || backing->guard != NULL) {
        errno = EBUSY;
        return -1;
    }
    family_object_node_t *node = backing->objects;
    while (node != NULL) {
        family_object_node_t *next = node->next;
        sparc64_family_object_close(node->object);
        free(node);
        node = next;
    }
    free(backing);
    return 0;
}
