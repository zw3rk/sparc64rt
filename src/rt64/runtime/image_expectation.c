/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#include "runtime/image_expectation.h"
#include "aot/digest.h"

#include <errno.h>
#include <string.h>

static int hex_digit(unsigned char c)
{
    if (c >= '0' && c <= '9') return (int)(c - '0');
    if (c >= 'a' && c <= 'f') return (int)(c - 'a') + 10;
    if (c >= 'A' && c <= 'F') return (int)(c - 'A') + 10;
    return -1;
}

bool sparc64_image_expectation_parse(const char *text, sparc64_image_expectation_t *out)
{
    sparc64_image_expectation_t parsed = {0};
    if (text == NULL || out == NULL)
        goto invalid;
    for (size_t i = 0; i < 64; ++i) {
        int digit = hex_digit((unsigned char)text[i]);
        if (digit < 0)
            goto invalid;
        parsed.sha256[i / 2] |= (uint8_t)((unsigned int)digit <<
                                         ((i & 1u) == 0 ? 4u : 0u));
    }
    if (text[64] != ':' || text[65] == '\0')
        goto invalid;
    for (size_t i = 65;; ++i) {
        unsigned char c = (unsigned char)text[i];
        if (c == '\0')
            break;
        if (i >= 85 || c < '0' || c > '9')
            goto invalid;
        uint64_t digit = (uint64_t)(c - '0');
        if (parsed.size > (UINT64_MAX - digit) / 10u)
            goto invalid;
        parsed.size = parsed.size * 10u + digit;
    }
    if (parsed.size == 0)
        goto invalid;
    *out = parsed;
    return true;
invalid:
    errno = EINVAL;
    return false;
}

bool sparc64_image_expectation_match(const sparc64_image_expectation_t *expected,
                                 const uint8_t *bytes, size_t size)
{
    if (expected == NULL || bytes == NULL || expected->size != (uint64_t)size) {
        errno = ENOEXEC;
        return false;
    }
    uint8_t digest[SPARC64_AOT_SHA256_BYTES];
    if (sparc64_aot_sha256(bytes, size, digest) != 0) {
        errno = EIO;
        return false;
    }
    if (memcmp(digest, expected->sha256, sizeof(digest)) != 0) {
        errno = ENOEXEC;
        return false;
    }
    return true;
}
