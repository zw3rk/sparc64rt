/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SPARC64RT_RUNTIME_FAMILY_FILE_RESIZE_RECORD_H
#define SPARC64RT_RUNTIME_FAMILY_FILE_RESIZE_RECORD_H

#include "memory/file_identity.h"
#include "runtime/family.h"

#include <stddef.h>
#include <stdint.h>

typedef enum {
    SPARC64_FILE_RESIZE_INTENT = 1,
    SPARC64_FILE_RESIZE_OBSERVATION = 2
} sparc64_family_file_resize_kind_t;

typedef enum {
    /* Zero preserves the meaning of schema1 records and existing callers. */
    SPARC64_FILE_MUTATION_TRUNCATE = 0,
    SPARC64_FILE_MUTATION_PWRITE = 1,
    SPARC64_FILE_MUTATION_WRITE = 2,
    SPARC64_FILE_MUTATION_APPEND_PWRITE = 3
} sparc64_family_file_mutation_kind_t;

typedef struct {
    uint64_t source_id;
    uint64_t after_size;
} sparc64_family_file_resize_size_t;

typedef struct {
    uint64_t self_object;
    uint64_t anchor_object;
    uint64_t operation_id;
    uint64_t base_snapshot;
    uint64_t base_revision;
    uint64_t target_length;
    uint64_t observation_object;
    uint64_t final_snapshot_object;
    uint32_t source_count;
    uint32_t association_count;
    sparc64_file_identity_policy_t identity_policy;
    sparc64_file_identity_t target_identity;
    sparc64_family_file_resize_kind_t kind;
    uint32_t native_errno;
    /* Schema2 separates mutation operands. TRUNCATE uses target_length and
     * leaves these counts/offset zero. Write kinds use a frozen offset/count,
     * target_length0 and at most SPARC64_FILE_CAPS_MAX_WRITE_BYTES immutable
     * service-owned bytes. WRITE's offset is its preflight cursor/append EOF;
     * APPEND_PWRITE stores the frozen EOF, never the ignored caller position.
     * Intent result_count is0;
     * an observation records the exact nonnegative native result, or0 with a
     * native errno. A native failure is distinct from a zero-byte success. */
    sparc64_family_file_mutation_kind_t mutation_kind;
    uint64_t write_offset, write_count, result_count;
    /* Schema3 only: immutable syscall recipient and process-owned limits.
     * The observation records an actual service event, never an errno guess.
     * Legacy records leave both flags and every caller field zero. Recovery
     * reconciles memory without delivering to its current worker. */
    bool attributed;
    bool generated_sigxfsz;
    sparc64_file_caps_call_context_t caller;
    /* Owned only for observations; exactly source_count strictly ordered rows. */
    sparc64_family_file_resize_size_t *sizes;
} sparc64_family_file_resize_record_t;

void sparc64_family_file_resize_record_destroy(sparc64_family_file_resize_record_t *record);

/* Intent occupies one slot. Observation occupies enough slots for the fixed
 * 512-byte header followed by one 16-byte source-size row per source. */
int sparc64_family_file_resize_record_slots(sparc64_family_file_resize_kind_t kind,
                                        uint32_t source_count,
                                        uint32_t *out_slots);

/* Stage only into an object reserved by the caller before mutation. This never
 * allocates family objects or consumes object IDs. A repeat is accepted only
 * when the reserved slots are virgin or match the exact already-staged image. */
int sparc64_family_file_resize_record_stage(sparc64_family_guard_t *guard,
                                        uint64_t reserved_object,
                                        const sparc64_family_file_resize_record_t *record);

/* Initialize out to {0}, or pass an earlier owned result. Read replaces it
 * only after all slots and records validate; failure preserves it unchanged. */
int sparc64_family_file_resize_record_read(sparc64_family_guard_t *guard,
                                       uint64_t object_id,
                                       sparc64_family_file_resize_record_t *out);

#endif
