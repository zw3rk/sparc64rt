/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SPARC64RT_RUNTIME_IMAGE_EXPECTATION_H
#define SPARC64RT_RUNTIME_IMAGE_EXPECTATION_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint8_t sha256[32];
    uint64_t size;
} sparc64_image_expectation_t;

/* Parse HEX64:DECIMAL_SIZE; size has 1..20 decimal digits, is positive and fits
 * uint64_t. Output remains unchanged on failure. This is a launch consistency check,
 * not authentication of an untrusted launcher or an executable cache. */
bool sparc64_image_expectation_parse(const char *text, sparc64_image_expectation_t *out);

/* Check already-owned immutable bytes using the established SHA-256 library.
 * Mismatch sets ENOEXEC; hashing failure sets EIO. No source FD is consulted. */
bool sparc64_image_expectation_match(const sparc64_image_expectation_t *expected,
                                 const uint8_t *bytes, size_t size);

#endif
