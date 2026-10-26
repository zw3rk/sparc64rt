/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#include "dbt/aot/sha256.h"

#include <string.h>

static const uint32_t k[64] = {
    UINT32_C(0x428a2f98), UINT32_C(0x71374491), UINT32_C(0xb5c0fbcf),
    UINT32_C(0xe9b5dba5), UINT32_C(0x3956c25b), UINT32_C(0x59f111f1),
    UINT32_C(0x923f82a4), UINT32_C(0xab1c5ed5), UINT32_C(0xd807aa98),
    UINT32_C(0x12835b01), UINT32_C(0x243185be), UINT32_C(0x550c7dc3),
    UINT32_C(0x72be5d74), UINT32_C(0x80deb1fe), UINT32_C(0x9bdc06a7),
    UINT32_C(0xc19bf174), UINT32_C(0xe49b69c1), UINT32_C(0xefbe4786),
    UINT32_C(0x0fc19dc6), UINT32_C(0x240ca1cc), UINT32_C(0x2de92c6f),
    UINT32_C(0x4a7484aa), UINT32_C(0x5cb0a9dc), UINT32_C(0x76f988da),
    UINT32_C(0x983e5152), UINT32_C(0xa831c66d), UINT32_C(0xb00327c8),
    UINT32_C(0xbf597fc7), UINT32_C(0xc6e00bf3), UINT32_C(0xd5a79147),
    UINT32_C(0x06ca6351), UINT32_C(0x14292967), UINT32_C(0x27b70a85),
    UINT32_C(0x2e1b2138), UINT32_C(0x4d2c6dfc), UINT32_C(0x53380d13),
    UINT32_C(0x650a7354), UINT32_C(0x766a0abb), UINT32_C(0x81c2c92e),
    UINT32_C(0x92722c85), UINT32_C(0xa2bfe8a1), UINT32_C(0xa81a664b),
    UINT32_C(0xc24b8b70), UINT32_C(0xc76c51a3), UINT32_C(0xd192e819),
    UINT32_C(0xd6990624), UINT32_C(0xf40e3585), UINT32_C(0x106aa070),
    UINT32_C(0x19a4c116), UINT32_C(0x1e376c08), UINT32_C(0x2748774c),
    UINT32_C(0x34b0bcb5), UINT32_C(0x391c0cb3), UINT32_C(0x4ed8aa4a),
    UINT32_C(0x5b9cca4f), UINT32_C(0x682e6ff3), UINT32_C(0x748f82ee),
    UINT32_C(0x78a5636f), UINT32_C(0x84c87814), UINT32_C(0x8cc70208),
    UINT32_C(0x90befffa), UINT32_C(0xa4506ceb), UINT32_C(0xbef9a3f7),
    UINT32_C(0xc67178f2)
};

static uint32_t rotr(uint32_t x, unsigned n)
{
    return (x >> n) | (x << (32u - n));
}

static void compress(sparc64_sha256_t *ctx, const uint8_t *block)
{
    uint32_t w[64];
    for (unsigned i = 0; i < 16; ++i)
        w[i] = ((uint32_t)block[4 * i] << 24) |
               ((uint32_t)block[4 * i + 1] << 16) |
               ((uint32_t)block[4 * i + 2] << 8) |
               (uint32_t)block[4 * i + 3];
    for (unsigned i = 16; i < 64; ++i) {
        uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^
                      (w[i - 15] >> 3);
        uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^
                      (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    uint32_t a = ctx->h[0];
    uint32_t b = ctx->h[1];
    uint32_t c = ctx->h[2];
    uint32_t d = ctx->h[3];
    uint32_t e = ctx->h[4];
    uint32_t f = ctx->h[5];
    uint32_t g = ctx->h[6];
    uint32_t h = ctx->h[7];
    for (unsigned i = 0; i < 64; ++i) {
        uint32_t s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        uint32_t ch = (e & f) ^ (~e & g);
        uint32_t t1 = h + s1 + ch + k[i] + w[i];
        uint32_t s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t t2 = s0 + maj;
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }
    ctx->h[0] += a;
    ctx->h[1] += b;
    ctx->h[2] += c;
    ctx->h[3] += d;
    ctx->h[4] += e;
    ctx->h[5] += f;
    ctx->h[6] += g;
    ctx->h[7] += h;
}

void sparc64_sha256_init(sparc64_sha256_t *ctx)
{
    ctx->h[0] = UINT32_C(0x6a09e667);
    ctx->h[1] = UINT32_C(0xbb67ae85);
    ctx->h[2] = UINT32_C(0x3c6ef372);
    ctx->h[3] = UINT32_C(0xa54ff53a);
    ctx->h[4] = UINT32_C(0x510e527f);
    ctx->h[5] = UINT32_C(0x9b05688c);
    ctx->h[6] = UINT32_C(0x1f83d9ab);
    ctx->h[7] = UINT32_C(0x5be0cd19);
    ctx->total = 0;
    ctx->buffered = 0;
}

void sparc64_sha256_update(sparc64_sha256_t *ctx, const uint8_t *bytes,
                         size_t size)
{
    if (bytes == NULL || size == 0)
        return;
    ctx->total += (uint64_t)size;
    while (size != 0) {
        size_t room = SPARC64_SHA256_BLOCK_BYTES - ctx->buffered;
        size_t take = size < room ? size : room;
        memcpy(ctx->block + ctx->buffered, bytes, take);
        ctx->buffered += take;
        bytes += take;
        size -= take;
        if (ctx->buffered == SPARC64_SHA256_BLOCK_BYTES) {
            compress(ctx, ctx->block);
            ctx->buffered = 0;
        }
    }
}

void sparc64_sha256_finish(sparc64_sha256_t *ctx,
                         uint8_t out[SPARC64_SHA256_BYTES])
{
    uint64_t bits = ctx->total * 8u;
    uint8_t pad = 0x80;
    uint8_t zero = 0x00;
    sparc64_sha256_update(ctx, &pad, 1);
    while (ctx->buffered != 56)
        sparc64_sha256_update(ctx, &zero, 1);
    uint8_t tail[8];
    for (unsigned i = 0; i < 8; ++i)
        tail[i] = (uint8_t)(bits >> (56u - 8u * i));
    size_t saved = ctx->buffered;
    memcpy(ctx->block + saved, tail, sizeof(tail));
    compress(ctx, ctx->block);
    ctx->buffered = 0;
    for (unsigned i = 0; i < 8; ++i) {
        out[4 * i] = (uint8_t)(ctx->h[i] >> 24);
        out[4 * i + 1] = (uint8_t)(ctx->h[i] >> 16);
        out[4 * i + 2] = (uint8_t)(ctx->h[i] >> 8);
        out[4 * i + 3] = (uint8_t)ctx->h[i];
    }
}
