/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#include "aot/relocate.h"
#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

static uint32_t get_word(const uint8_t *p)
{
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 |
        (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}
static void put_word(uint8_t *p, uint32_t word)
{
    p[0] = (uint8_t)word; p[1] = (uint8_t)(word >> 8);
    p[2] = (uint8_t)(word >> 16); p[3] = (uint8_t)(word >> 24);
}
static bool mov64_valid(const uint8_t *p)
{
    unsigned rd = get_word(p) & 31u;
    if (rd == 31u)
        return false;
    for (unsigned half = 0; half < 4; ++half) {
        uint32_t expected = (half == 0 ? UINT32_C(0xd2800000) :
                                         UINT32_C(0xf2800000)) |
                            (uint32_t)half << 21 | rd;
        if ((get_word(p + half * 4u) & UINT32_C(0xffe0001f)) != expected)
            return false;
    }
    return true;
}
static bool guest_value(uint64_t base, uint64_t target, int64_t addend,
                         uint64_t *out)
{
    if (target > UINT64_MAX - base)
        return false;
    uint64_t value = base + target;
    if (addend < 0) {
        uint64_t amount = UINT64_C(0) - (uint64_t)addend;
        if (value < amount)
            return false;
        value -= amount;
    } else {
        uint64_t amount = (uint64_t)addend;
        if (amount > UINT64_MAX - value)
            return false;
        value += amount;
    }
    *out = value;
    return true;
}
sparc64_aot_relocate_result_t sparc64_aot_relocate_guest(const sparc64_aot_block_view_t *block,
                                               uint64_t guest_image_base,
                                               sparc64_aot_relocated_t *out)
{
    if (block == NULL || out == NULL || out->bytes != NULL || out->size != 0 ||
        block->a64_text == NULL || block->a64_size == 0 ||
        block->a64_size > SPARC64_AOT_MAX_BLOCK_TEXT_BYTES ||
        (block->a64_size & 3u) != 0 ||
        block->relocation_count > SPARC64_AOT_MAX_RELOCS_PER_BLOCK ||
        (block->relocation_count != 0 && block->relocations == NULL)) {
        errno = EINVAL;
        return SPARC64_AOT_RELOCATE_ERROR;
    }
    uint64_t values[SPARC64_AOT_MAX_RELOCS_PER_BLOCK];
    uint32_t offsets[SPARC64_AOT_MAX_RELOCS_PER_BLOCK];
    for (uint16_t i = 0; i < block->relocation_count; ++i) {
        sparc64_aot_relocation_t r;
        if (sparc64_aot_view_relocation(block, i, &r) != 0)
            return SPARC64_AOT_RELOCATE_ERROR;
        if (r.kind != SPARC64_AOT_RELOC_GUEST_RELATIVE)
            return SPARC64_AOT_RELOCATE_DECLINE;
        if (r.width != 16 || (r.patch_offset & 3u) != 0 ||
            r.patch_offset > block->a64_size ||
            block->a64_size - r.patch_offset < 16 ||
            !mov64_valid(block->a64_text + r.patch_offset)) {
            errno = EINVAL;
            return SPARC64_AOT_RELOCATE_ERROR;
        }
        for (uint16_t j = 0; j < i; ++j)
            if (r.patch_offset < offsets[j] + 16u &&
                offsets[j] < r.patch_offset + 16u) {
                errno = EINVAL;
                return SPARC64_AOT_RELOCATE_ERROR;
            }
        if (!guest_value(guest_image_base, r.target, r.addend, &values[i]))
            return SPARC64_AOT_RELOCATE_DECLINE;
        offsets[i] = r.patch_offset;
    }
    uint8_t *bytes = malloc(block->a64_size);
    if (bytes == NULL)
        return SPARC64_AOT_RELOCATE_ERROR;
    memcpy(bytes, block->a64_text, block->a64_size);
    for (uint16_t i = 0; i < block->relocation_count; ++i)
        for (unsigned half = 0; half < 4; ++half) {
            uint8_t *site = bytes + offsets[i] + half * 4u;
            uint32_t word = get_word(site) & ~UINT32_C(0x001fffe0);
            word |= (uint32_t)((values[i] >> (half * 16u)) & UINT64_C(0xffff)) << 5;
            put_word(site, word);
        }
    out->bytes = bytes;
    out->size = block->a64_size;
    return SPARC64_AOT_RELOCATE_OK;
}
void sparc64_aot_relocated_destroy(sparc64_aot_relocated_t *out)
{
    if (out != NULL) {
        free(out->bytes);
        memset(out, 0, sizeof(*out));
    }
}
