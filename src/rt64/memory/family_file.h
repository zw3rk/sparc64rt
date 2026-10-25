/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SPARC64RT_MEMORY_FAMILY_FILE_H
#define SPARC64RT_MEMORY_FAMILY_FILE_H

#include "memory/family_backing.h"
#include "memory/file_identity.h"

typedef struct {
    uint64_t source_id, size;
    sparc64_file_identity_t identity;
} sparc64_family_file_description_t;

/* Query only this managed source's exact retained FD under its bound guard.
 * No native FD escapes or is duplicated/closed. Output changes only on success;
 * unknown identity is valid and remains conservative. */
int sparc64_family_file_source_describe(sparc64_file_source_t *source,
                                    sparc64_family_guard_t *guard,
                                    sparc64_file_identity_policy_t policy,
                                    sparc64_family_file_description_t *out);

/* Internal managed-file component, not guest-MM/futex admission. Consume the
 * exact retained readable ordinary FD on every outcome; source_id is a trusted
 * nonzero family capability ID, never inode equivalence or pathname discovery.
 * backing/space outlive every source/view. Source objects do not coalesce FDs.
 * Initialize *out=NULL; success returns one source reference. Failure consumes
 * owned_fd and leaves *out unchanged, including a rejected nonempty output. */
int sparc64_family_file_source_create(sparc64_file_source_t **out,
                                  sparc64_family_backing_t *backing, sparc64_space_t *space,
                                  uint64_t source_id, int owned_fd);
/* Caller holds the backing's bound guard. Trusted canonical provenance must
 * associate key with exactly this source_id and offset for its entire lifetime,
 * including every peer cache. A bare key cannot establish that association.
 * Ordinary READ/WRITE/EXEC permissions are admitted by the trusted native
 * component. Generic managed writes authorize global origin and batch their
 * first COW with bytes/epochs; canonical reads project the private bytes.
 * Clean refresh consumes canonical notification bits after the trusted
 * producer has completed native mutation. Prepaid granules do not advance
 * twice; clearing even a same-byte notification advances content generation.
 * COW payloads with notification bits reject. Recoverable source mutation,
 * legacy futex classification and guest CLI/fork admission remain separate.
 * Import into a vacant page is atomic; access refreshes canonical bytes/epochs
 * before exposing data, and dynamic EOF faults BUS until a later file grow. */
bool sparc64_family_file_map(sparc64_file_source_t *source, uint64_t guest_page,
                         unsigned int permissions, sparc64_family_page_key_t key,
                         uint64_t offset);
/* Explicit canonical same-byte COW transition, not byte-write admission.
 * Caller holds the exact guard, source owns this mapped view, and the page has
 * write permission (e.g. set by an internal preparation plan). Refresh first;
 * commit COW+all-granule epochs+CG together, then project local flags. Keep
 * bindings unchanged. Already-COW is a no-op. No source native mutation may
 * occur between this operation and later reads until canonical source-write/
 * truncate notification exists, including shrink-regrow between accesses. */
bool sparc64_family_file_cow(sparc64_file_source_t *source, uint64_t address);
/* Same guarded private import into an unpublished candidate, while source
 * stays bound to the stable final space. Both spaces must use the same backing
 * and VA limit. Never read/access the candidate before moving its registry to
 * source->space. Failure/discard releases staged views without rebinding any
 * source, including sources shared with retained old I/O views. */
bool sparc64_family_file_stage(sparc64_file_source_t *source, sparc64_space_t *stage,
                           uint64_t guest_page, unsigned int permissions,
                           sparc64_family_page_key_t key, uint64_t offset);

#endif
