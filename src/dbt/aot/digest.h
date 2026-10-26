/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SPARC64RT_AOT_DIGEST_H
#define SPARC64RT_AOT_DIGEST_H
#include <stddef.h>
#include <stdint.h>
#define SPARC64_AOT_SHA256_BYTES 32u
#define SPARC64_AOT_SHA256_MAX_SPANS 64u
typedef struct sparc64_aot_span {
    const uint8_t *bytes;
    size_t size;
} sparc64_aot_span_t;
/* Local FIPS 180-4 SHA-256 (aot/sha256.h), with a fresh context per call.
 * NULL bytes are allowed only for an empty span. Output remains unchanged
 * on failure. */
int sparc64_aot_sha256(const uint8_t *bytes, size_t size,
                   uint8_t out[SPARC64_AOT_SHA256_BYTES]);
int sparc64_aot_sha256_spans(const sparc64_aot_span_t *spans, size_t count,
                         uint8_t out[SPARC64_AOT_SHA256_BYTES]);
#endif
