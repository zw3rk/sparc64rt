/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Minimal FIPS 180-4 SHA-256 for AOT cache records. The digest API in
 * aot/digest.h keeps its shape; only the hash provider is local so the
 * Phase 0 tree builds without a vendored TLS library. Wire digests are
 * standard SHA-256 and stay compatible with any provider.
 */
#ifndef SPARC64RT_RT64_AOT_SHA256_H
#define SPARC64RT_RT64_AOT_SHA256_H

#include <stddef.h>
#include <stdint.h>

#define SPARC64_SHA256_BYTES 32u
#define SPARC64_SHA256_BLOCK_BYTES 64u

typedef struct {
    uint32_t h[8];
    uint64_t total;
    uint8_t block[SPARC64_SHA256_BLOCK_BYTES];
    size_t buffered;
} sparc64_sha256_t;

void sparc64_sha256_init(sparc64_sha256_t *ctx);
void sparc64_sha256_update(sparc64_sha256_t *ctx, const uint8_t *bytes,
                         size_t size);
void sparc64_sha256_finish(sparc64_sha256_t *ctx,
                         uint8_t out[SPARC64_SHA256_BYTES]);

#endif
