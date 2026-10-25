/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SPARC64RT_RUNTIME_MM_VIEW_INTERNAL_H
#define SPARC64RT_RUNTIME_MM_VIEW_INTERNAL_H

#include "runtime/mm_view.h"

typedef struct {
    uint64_t id;
    sparc64_file_source_t *source;
} sparc64_mm_file_cache_entry_t;

/* Private transaction machinery shared by canonical mapping operations.
 * Call only under the backing's exact uninterrupted guard, after refresh. */
struct sparc64_mm_view {
    sparc64_family_mm_t mm;
    sparc64_family_backing_t *backing;
    sparc64_space_t *space;
    sparc64_linux_memory_t *memory;
    sparc64_family_mm_state_t applied;
    uint64_t *local_bindings;
    sparc64_file_caps_client_t file_client;
    sparc64_file_identity_policy_t file_identity_policy;
    sparc64_mm_file_cache_entry_t *file_sources;
    size_t file_source_count;
};

typedef struct {
    sparc64_space_t space;
    sparc64_family_mm_state_t state;
    sparc64_vma_t *vmas;
    uint64_t *bindings;
    sparc64_mm_file_cache_entry_t *file_sources;
    size_t file_source_count, old_file_source_count;
    bool metadata_only;
} sparc64_mm_view_plan_t;

/* Prepare borrows state on failure, consumes its arrays on success. Apply
 * consumes a successfully prepared/published plan without allocation/failure.
 * Discard is valid for a zero plan or any partially prepared owned plan. */
int sparc64_mm_view_plan_prepare(sparc64_mm_view_t *view, sparc64_family_mm_state_t *state,
                              sparc64_mm_view_plan_t *plan);
void sparc64_mm_view_plan_apply(sparc64_mm_view_t *view, sparc64_mm_view_plan_t *plan);
void sparc64_mm_view_plan_discard(sparc64_mm_view_plan_t *plan);
/* Admit only origins backed by this transaction's newly allocated payloads.
 * Global immutable origins may survive a later failed MM commit; never admit
 * origins from refresh or generic plan preparation. */
int sparc64_mm_view_plan_admit_files(sparc64_mm_view_t *view, sparc64_family_guard_t *guard,
    sparc64_mm_view_plan_t *plan, const sparc64_space_t *fresh);

/* Pure staged metadata edits, never live mappings. Insert requires a sorted
 * guarded candidate of exactly the inserted pages and preflighted mapping-ID
 * budget. It assigns fresh IDs, retains keys and does not consume VMA IDs. */
int sparc64_mm_view_state_unmap(sparc64_family_mm_state_t *state, uint64_t start, uint64_t end);
int sparc64_mm_view_state_insert(sparc64_mm_view_t *view, sparc64_family_mm_state_t *state,
                              sparc64_space_t *fresh, sparc64_vma_t added);

#endif
