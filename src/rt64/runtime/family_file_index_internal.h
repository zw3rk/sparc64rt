/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SPARC64RT_RUNTIME_FAMILY_FILE_INDEX_INTERNAL_H
#define SPARC64RT_RUNTIME_FAMILY_FILE_INDEX_INTERNAL_H

#include "runtime/family_file_index.h"

/* Private recovery protocol, never guest input. Pending operations freeze the
 * complete source/key snapshot until final source-history publication. Both
 * immutable intent/observation records bind to snapshot_object and revision. */
enum { SPARC64_FILE_IDLE, SPARC64_FILE_STAGED, SPARC64_FILE_RECONCILE };
typedef struct {
    uint64_t snapshot_object, revision;
    uint64_t intent_object, observed_object, cursor;
    uint32_t phase;
} sparc64_family_file_cursor_t;

int sparc64_family_file_index_cursor_read(sparc64_family_guard_t *guard,
                                      sparc64_family_file_cursor_t *out);
/* Check all anchor updates (including final publish) before native mutation.
 * The caller holds the uninterrupted guard and stages complete immutable
 * records before advancing. Counter checks do not themselves reserve IDs. */
int sparc64_family_file_index_cursor_reserve(sparc64_family_guard_t *guard,
                                         uint64_t updates);
/* Allocate the exact complete final snapshot extent before native mutation.
 * Finalization reuses these slots without consuming IDs on recovery retries. */
int sparc64_family_file_index_reserve_snapshot(sparc64_family_guard_t *guard,
                                           uint64_t *out_object);
/* STAGED -> RECONCILE publishes the full immutable outcome first. A reconcile
 * step increments cursor by exactly one; when payload changes it shares the
 * anchor's absolute-state redo. No metadata key may be used as payload. */
int sparc64_family_file_index_cursor_advance(sparc64_family_guard_t *guard,
                                         const sparc64_family_file_cursor_t *expected,
                                         const sparc64_family_file_cursor_t *next,
                                         const sparc64_family_object_update_t *payload);
/* Caller validates completion against immutable inventory count. Atomically
 * publish updated source sizes/sequences and clear every pending anchor word;
 * compare the exact cursor/base snapshot before publishing the new snapshot. */
int sparc64_family_file_index_finish(sparc64_family_guard_t *guard,
                                 const sparc64_family_file_cursor_t *expected,
                                 uint64_t reserved_snapshot,
                                 sparc64_family_file_index_state_t *state);

#endif
