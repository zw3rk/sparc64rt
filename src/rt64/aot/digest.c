/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#include "aot/digest.h"
#include "aot/sha256.h"
#include <errno.h>
#include <string.h>

int sparc64_aot_sha256_spans(const sparc64_aot_span_t *spans, size_t count,
                         uint8_t out[SPARC64_AOT_SHA256_BYTES])
{
    if (out == NULL || count > SPARC64_AOT_SHA256_MAX_SPANS ||
        (count != 0 && spans == NULL)) {
        errno = EINVAL;
        return -1;
    }
    for (size_t i = 0; i < count; ++i)
        if (spans[i].size != 0 && spans[i].bytes == NULL) {
            errno = EINVAL;
            return -1;
        }
    sparc64_sha256_t context;
    uint8_t result[SPARC64_AOT_SHA256_BYTES];
    sparc64_sha256_init(&context);
    for (size_t i = 0; i < count; ++i)
        if (spans[i].size != 0)
            sparc64_sha256_update(&context, spans[i].bytes, spans[i].size);
    sparc64_sha256_finish(&context, result);
    memcpy(out, result, sizeof(result));
    return 0;
}

int sparc64_aot_sha256(const uint8_t *bytes, size_t size,
                   uint8_t out[SPARC64_AOT_SHA256_BYTES])
{
    const sparc64_aot_span_t span = {bytes, size};
    return sparc64_aot_sha256_spans(&span, 1, out);
}
