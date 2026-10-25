/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SPARC64RT_RUNTIME_FAMILY_SHMEM_H
#define SPARC64RT_RUNTIME_FAMILY_SHMEM_H

#include "runtime/family_wait.h"

#define SPARC64_FAMILY_SHMEM_MAX_PAGES 65536u

/* Family-scoped immutable manifest identity, distinct from an MM's local
 * VMA backing_id. MM records retain this association after the final VMA disappears.
 * The manifest holds original DATA only; beyond-extent BUS belongs to MM views. */
typedef struct { uint64_t object_id; } sparc64_family_shmem_t;

typedef struct {
    uint64_t extent;
    sparc64_family_page_key_t *pages;
    size_t page_count;
} sparc64_family_shmem_state_t;

void sparc64_family_shmem_state_destroy(sparc64_family_shmem_state_t *state);
/* Hold the exact current family guard. An anonymous manifest has a positive
 * page-aligned immutable original extent and one distinct existing data key per
 * original offset. Complete every metadata slot before returning the handle.
 * Failure preserves *out; unreachable staging objects/IDs may remain until
 * family cleanup. Uncertain redo EIO requires fatal/recovery policy. Trusted
 * internal keys only: existence/slot checks do not authorize guest records. */
int sparc64_family_shmem_create(sparc64_family_guard_t *guard,
                             const sparc64_family_shmem_state_t *state,
                             sparc64_family_shmem_t *out);
/* Read a complete validated snapshot; *out is zero or a prior owned snapshot.
 * Bounds, identity, schema, distinct keys, padding and existing data slots are
 * checked before replacing it. The durable manifest and data remain owned by
 * the family even when no process-local snapshot or mapped view is retained. */
int sparc64_family_shmem_read(sparc64_family_guard_t *guard, sparc64_family_shmem_t shmem,
                           sparc64_family_shmem_state_t *out);

#endif
