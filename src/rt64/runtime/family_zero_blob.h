/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SPARC64RT_FAMILY_ZERO_BLOB_H
#define SPARC64RT_FAMILY_ZERO_BLOB_H

#include <stddef.h>
#include <stdint.h>

#define SPARC64_FAMILY_ZERO_BLOB_CHUNK_SIZE 1024u
#define SPARC64_FAMILY_ZERO_BLOB_MAX_CHUNKS 8u
#define SPARC64_FAMILY_ZERO_BLOB_MAX_SIZE \
    (SPARC64_FAMILY_ZERO_BLOB_CHUNK_SIZE * SPARC64_FAMILY_ZERO_BLOB_MAX_CHUNKS)

/* Standalone Linux storage primitive, not yet a family control/journal backend.
 * The caller owns a private, exact directory FD and must serialize a blob ID's
 * publication under its family guard. IDs are immutable and never replaced.
 * All files remain zero length; their content is stored in bounded xattrs.
 * Returns 0 on durable publication, -1 before publication, -2 if durability
 * after the atomic rename is uncertain. A failed prepublication may leave
 * unreachable orphan files; recovery must never treat them as published.
 */
int sparc64_family_zero_blob_publish(int directory_fd, uint64_t id,
                                const uint8_t *bytes, size_t size);

/* On failure, out and *out_size remain unchanged. A published manifest is
 * accepted only after all metadata, chunk sizes, and SHA-256 validate.
 */
int sparc64_family_zero_blob_read(int directory_fd, uint64_t id,
                             uint8_t *out, size_t capacity,
                             size_t *out_size);

#endif
