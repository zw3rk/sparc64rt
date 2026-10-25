/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SPARC64RT_RUNTIME_FAMILY_MM_H
#define SPARC64RT_RUNTIME_FAMILY_MM_H

#include "linux/memory.h"
#include "runtime/family.h"
#include "runtime/family_shmem.h"

#define SPARC64_FAMILY_MM_MAX_RECORDS 65536u

/* Explicit capabilities/identities, never native pointers or guest addresses
 * interpreted as translator pointers. Both words must match the stored root. */
typedef struct {
    uint64_t mm_id;
    uint64_t root_object;
} sparc64_family_mm_t;

typedef enum { SPARC64_MM_DATA, SPARC64_MM_BUS } sparc64_family_mm_page_kind_t;

typedef struct {
    uint64_t address, mapping_id, mapping_generation;
    sparc64_family_page_key_t key;
    unsigned int permissions;
    /* BUS has a zero key and no payload; its original shared-backing offset
     * must be beyond the immutable manifest extent. DATA must match its key. */
    sparc64_family_mm_page_kind_t kind;
} sparc64_family_mm_page_t;

/* Canonical mapping IDs are opaque IDs allocated one per view. They are NOT
 * sparc64_page_t.binding_base or sparc64_space_t.next_binding values (those reserve
 * SPARC64_PAGE_GRANULES local LR/SC identities). Reconciliation must allocate a
 * fresh local binding range whenever mapping_id OR mapping_generation changes;
 * retain a pinned local view only while both remain unchanged. Never import
 * these IDs directly as local reservation/copyout bindings. */

typedef struct {
    uint64_t owner_incarnation, task_id;
} sparc64_family_mm_member_t;

/* Retained immutable association, including after its last mapped view. The
 * local backing ID is never the global manifest object ID. */
typedef struct {
    uint64_t backing_id;
    sparc64_family_shmem_t manifest;
} sparc64_family_mm_shared_source_t;

/* A managed key's immutable clean-file provenance. Rows remain after the last
 * VMA using the key is removed. Source IDs name retained capabilities in one
 * trusted family service, never inode equivalence or native paths. */
typedef struct {
    sparc64_family_page_key_t key;
    uint64_t source_id;
    uint64_t file_offset;
} sparc64_family_mm_file_assoc_t;

/* Owned local snapshot, not a wire representation. Arrays are ordered by
 * address and (incarnation,task_id), respectively. Aliases retain distinct
 * mapping IDs/permissions but the SAME managed key. Mapping generations describe
 * views; current bytes/epochs remain authoritative in the managed payload and
 * may change without publishing a new MM revision. Dead members remain valid
 * records until a lifecycle transaction removes them. */
typedef struct {
    sparc64_vma_t *vmas;
    sparc64_family_mm_page_t *pages;
    sparc64_family_mm_member_t *members;
    size_t vma_count, page_count, member_count;
    uint64_t revision, limit, minimum_break, current_break;
    uint64_t brk_id, next_vma_id, next_mapping_id;
    sparc64_family_mm_shared_source_t *shared_sources;
    size_t shared_source_count;
    sparc64_family_mm_file_assoc_t *file_assocs;
    size_t file_assoc_count;
} sparc64_family_mm_state_t;

void sparc64_family_mm_state_destroy(sparc64_family_mm_state_t *state);
/* Append staged metadata only; publication validates the manifest and exact
 * per-offset keys. Rows are sorted by monotonically allocated local backing ID.
 * Failure leaves state unchanged. This does not publish or admit guest tasks. */
int sparc64_family_mm_shared_append(sparc64_family_mm_state_t *state, uint64_t backing_id,
                                 sparc64_family_shmem_t manifest);
/* Insert a new key association in sorted order. An existing identical row is
 * idempotent; conflicting source/offset is rejected. This stages metadata
 * only: callers must fetch source_id and publish the fresh key's matching
 * family-wide file-index origin before publishing the next MM revision.
 * Every read/create/commit checks all retained rows against that authority. */
int sparc64_family_mm_file_assoc_insert(sparc64_family_mm_state_t *state,
                                    sparc64_family_mm_file_assoc_t association);
/* All calls require one uninterrupted current family guard. Creation accepts
 * revision0 and publishes revision1; commit compares the caller's revision
 * before staging and publishes exactly its successor. A stale writer returns
 * EAGAIN. Only success changes the supplied revision or output handle. */
int sparc64_family_mm_create(sparc64_family_guard_t *guard, sparc64_family_mm_state_t *state,
                         sparc64_family_mm_t *out);
/* Read accepts {0} or a prior owned snapshot and replaces it only on success.
 * MM limit/minimum brk/brk identity are immutable; counters never decrease.
 * Removed mapping IDs cannot be reused. Changed kinds/keys/permissions require a new
 * mapping ID or a strictly newer mapping generation at the original address. */
int sparc64_family_mm_read(sparc64_family_guard_t *guard, sparc64_family_mm_t mm,
                       sparc64_family_mm_state_t *out);
int sparc64_family_mm_commit(sparc64_family_guard_t *guard, sparc64_family_mm_t mm,
                         sparc64_family_mm_state_t *state);

/* Canonical INITIAL/ANONYMOUS/BRK/ANONYMOUS_SHARED metadata and READ/EXEC-only
 * FILE_PRIVATE associations. Every source-enabled MM consults the family-wide
 * index, including unchanged-revision reads and retained inactive rows/manifest
 * keys. File origins require prior exact capability fetch and fresh-key global
 * admission; ordinary anonymous families cannot publish file associations.
 * Writable file/COW/notification input remains unsupported. No guest CLONE_VM
 * support is implied. Referenced
 * keys must already belong to the caller's managed data inventory; this API
 * checks existence/slot bounds, not authorization of untrusted guest records.
 * Immutable snapshots are staged separately; one existing family redo update
 * publishes the root. Prepublication failure leaves the active root and data
 * untouched (IDs/unreachable staging objects may remain). EIO may indicate
 * interrupted redo/recovery and must follow the caller's fatal/recovery policy.
 * Old snapshots remain until family cleanup; reclamation is not implemented. */

#endif
