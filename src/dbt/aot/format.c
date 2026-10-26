/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#include "dbt/aot/format.h"

#include <errno.h>
#include <stdbool.h>
#include <string.h>

static const uint8_t format_magic[8] = {'R', 'V', 'R', 'T', 'C', 'A', 'C', 'H'};

_Static_assert((size_t)SPARC64_AOT_MAX_RELOCS_PER_BLOCK <=
                   SIZE_MAX / SPARC64_AOT_RELOCATION_BYTES,
               "per-block relocation byte count must fit in size_t");

static uint16_t get16(const uint8_t *p)
{
    return (uint16_t)p[0] | (uint16_t)((uint16_t)p[1] << 8);
}

static uint32_t get32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint64_t get64(const uint8_t *p)
{
    return (uint64_t)get32(p) | ((uint64_t)get32(p + 4) << 32);
}

static int64_t get_i64(const uint8_t *p)
{
    uint64_t v = get64(p);
    if (v <= INT64_MAX)
        return (int64_t)v;
    return -1 - (int64_t)(UINT64_MAX - v);
}

static void put16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
}

static void put32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

static void put64(uint8_t *p, uint64_t v)
{
    put32(p, (uint32_t)v);
    put32(p + 4, (uint32_t)(v >> 32));
}

static bool add_size(size_t a, size_t b, size_t *out)
{
    if (b > SIZE_MAX - a)
        return false;
    *out = a + b;
    return true;
}

static bool abi_valid(uint8_t xlen, uint8_t abi)
{
    if (xlen == 32)
        return abi == SPARC64_AOT_ABI_ILP32 || abi == SPARC64_AOT_ABI_ILP32D;
    if (xlen == 64)
        return abi == SPARC64_AOT_ABI_LP64 || abi == SPARC64_AOT_ABI_LP64D;
    return false;
}

static bool page_size_valid(uint32_t page_size)
{
    return page_size >= 4096u && page_size <= 65536u &&
           (page_size & (page_size - 1u)) == 0;
}

static bool a64_host_page_size_valid(uint32_t page_size)
{
    return page_size == 4096u || page_size == 16384u || page_size == 65536u;
}

static bool relocation_fields_valid(const sparc64_aot_relocation_t *reloc,
                                    uint32_t a64_size, uint32_t block_count)
{
    uint8_t required_width;
    switch (reloc->kind) {
    case SPARC64_AOT_RELOC_HELPER_ID:
    case SPARC64_AOT_RELOC_GUEST_RELATIVE:
        required_width = 16;
        break;
    case SPARC64_AOT_RELOC_BLOCK_RELATIVE:
        required_width = 4;
        break;
    default:
        return false;
    }
    if (reloc->width != required_width)
        return false;
    if ((reloc->patch_offset & 3u) != 0 ||
        reloc->patch_offset > a64_size ||
        reloc->width > a64_size - reloc->patch_offset)
        return false;
    switch (reloc->kind) {
    case SPARC64_AOT_RELOC_HELPER_ID:
        return reloc->target != 0 && reloc->target <= UINT32_MAX;
    case SPARC64_AOT_RELOC_GUEST_RELATIVE:
        return true;
    case SPARC64_AOT_RELOC_BLOCK_RELATIVE:
        return (uint32_t)reloc->target < block_count;
    default:
        return false;
    }
}

static bool wire_relocation_valid(const uint8_t *p, uint32_t a64_size,
                                  uint32_t block_count)
{
    sparc64_aot_relocation_t reloc;
    if (p[3] != 0)
        return false;
    reloc.kind = get16(p);
    reloc.width = p[2];
    reloc.patch_offset = get32(p + 4);
    reloc.target = get64(p + 8);
    reloc.addend = get_i64(p + 16);
    if (!relocation_fields_valid(&reloc, a64_size, block_count))
        return false;
    if (reloc.kind == SPARC64_AOT_RELOC_BLOCK_RELATIVE &&
        ((uint32_t)(reloc.target >> 32) >= SPARC64_AOT_MAX_BLOCK_TEXT_BYTES ||
         ((uint32_t)(reloc.target >> 32) & 3u) != 0))
        return false;
    return true;
}

static bool source_block_valid(const sparc64_aot_block_t *block,
                               uint32_t block_count)
{
    if (block->source_bytes == NULL || block->a64_text == NULL ||
        (block->relocation_count != 0 && block->relocations == NULL) ||
        block->source_size == 0 ||
        block->source_size > SPARC64_AOT_MAX_SOURCE_BYTES || block->a64_size == 0 ||
        block->a64_size > SPARC64_AOT_MAX_BLOCK_TEXT_BYTES ||
        block->relocation_count > SPARC64_AOT_MAX_RELOCS_PER_BLOCK)
        return false;
    if (block->source_offset > UINT64_MAX - block->source_size)
        return false;
    if ((block->source_offset & 1u) != 0)
        return false;
    for (uint16_t i = 0; i < block->relocation_count; ++i) {
        const sparc64_aot_relocation_t *reloc = &block->relocations[i];
        if (!relocation_fields_valid(reloc, block->a64_size, block_count))
            return false;
        if (reloc->kind == SPARC64_AOT_RELOC_BLOCK_RELATIVE &&
            ((uint32_t)(reloc->target >> 32) >= SPARC64_AOT_MAX_BLOCK_TEXT_BYTES ||
             ((uint32_t)(reloc->target >> 32) & 3u) != 0))
            return false;
        for (uint16_t j = 0; j < i; ++j) {
            const sparc64_aot_relocation_t *prior = &block->relocations[j];
            uint32_t end = reloc->patch_offset + reloc->width;
            uint32_t prior_end = prior->patch_offset + prior->width;
            if (reloc->patch_offset < prior_end && prior->patch_offset < end)
                return false;
        }
    }
    return true;
}

static bool image_valid(const sparc64_aot_image_t *image, size_t header_bytes,
                         size_t *encoded_size)
{
    size_t total = header_bytes;
    uint64_t previous_start = 0;
    uint32_t relocation_total = 0;

    if (image == NULL || encoded_size == NULL || image->blocks == NULL ||
        image->block_count == 0 || image->block_count > SPARC64_AOT_MAX_BLOCKS ||
        !abi_valid(image->xlen, image->abi) ||
        !page_size_valid(image->guest_page_size) ||
        !a64_host_page_size_valid(image->a64_host_page_size) ||
        image->memory_model != SPARC64_AOT_MEMORY_SPARSE_CHECKED)
        return false;

    for (uint32_t i = 0; i < image->block_count; ++i) {
        const sparc64_aot_block_t *block = &image->blocks[i];
        size_t block_bytes = SPARC64_AOT_BLOCK_HEADER_BYTES;
        size_t reloc_bytes;
        if (!source_block_valid(block, image->block_count) ||
            (block->source_size & 1u) != 0 || (block->a64_size & 3u) != 0 ||
            (i != 0 && block->source_offset <= previous_start))
            return false;
        for (uint16_t j = 0; j < block->relocation_count; ++j) {
            const sparc64_aot_relocation_t *reloc = &block->relocations[j];
            if (reloc->kind == SPARC64_AOT_RELOC_BLOCK_RELATIVE) {
                uint32_t target_index = (uint32_t)reloc->target;
                uint32_t target_offset = (uint32_t)(reloc->target >> 32);
                if (target_index >= image->block_count ||
                    target_offset >= image->blocks[target_index].a64_size)
                    return false;
            }
        }
        previous_start = block->source_offset;
        if (block->relocation_count > SPARC64_AOT_MAX_RELOCS - relocation_total)
            return false;
        relocation_total += block->relocation_count;
        reloc_bytes = (size_t)block->relocation_count * SPARC64_AOT_RELOCATION_BYTES;
        if (!add_size(block_bytes, block->source_size, &block_bytes) ||
            !add_size(block_bytes, block->a64_size, &block_bytes) ||
            !add_size(block_bytes, reloc_bytes, &block_bytes) ||
            !add_size(total, block_bytes, &total) || total > SPARC64_AOT_MAX_FILE_BYTES)
            return false;
    }
    *encoded_size = total;
    return true;
}

int sparc64_aot_encoded_size_v2(const sparc64_aot_image_t *image, size_t *size)
{
    size_t candidate = 0;
    if (size == NULL || !image_valid(image, SPARC64_AOT_HEADER_V2_BYTES, &candidate)) {
        errno = EINVAL;
        return -1;
    }
    *size = candidate;
    return 0;
}

static void encode_relocation(uint8_t *p, const sparc64_aot_relocation_t *reloc)
{
    put16(p, reloc->kind);
    p[2] = reloc->width;
    p[3] = 0;
    put32(p + 4, reloc->patch_offset);
    put64(p + 8, reloc->target);
    put64(p + 16, (uint64_t)reloc->addend);
}

static int encode(const sparc64_aot_image_t *image, uint16_t version,
                   const uint8_t *record_digest, uint8_t *destination,
                   size_t capacity, size_t *written)
{
    size_t total = 0;
    size_t cursor;
    uint16_t header_bytes = version == SPARC64_AOT_FORMAT_V2 ?
        SPARC64_AOT_HEADER_V2_BYTES : SPARC64_AOT_HEADER_BYTES;
    if (written == NULL || destination == NULL ||
        (version == SPARC64_AOT_FORMAT_V2 && record_digest == NULL) ||
        !image_valid(image, header_bytes, &total)) {
        errno = EINVAL;
        return -1;
    }
    if (capacity < total) {
        errno = ENOSPC;
        return -1;
    }

    memcpy(destination, format_magic, sizeof(format_magic));
    put16(destination + 8, version);
    put16(destination + 10, header_bytes);
    put32(destination + 12, (uint32_t)total);
    put32(destination + 16, 0);
    put32(destination + 20, image->block_count);
    destination[24] = image->xlen;
    destination[25] = image->abi;
    put16(destination + 26, 0);
    put64(destination + 28, image->guest_extensions);
    put64(destination + 36, image->a64_host_requirements);
    put32(destination + 44, image->guest_page_size);
    put32(destination + 48, image->memory_model);
    put32(destination + 52, image->a64_host_page_size);
    put64(destination + 56, 0);
    memcpy(destination + 64, image->input_digest, SPARC64_AOT_DIGEST_BYTES);
    memcpy(destination + 96, image->runtime_digest, SPARC64_AOT_DIGEST_BYTES);
    memcpy(destination + 128, image->emitter_digest, SPARC64_AOT_DIGEST_BYTES);
    memcpy(destination + 160, image->profile_digest, SPARC64_AOT_DIGEST_BYTES);
    if (version == SPARC64_AOT_FORMAT_V2)
        memcpy(destination + SPARC64_AOT_RECORD_DIGEST_OFFSET, record_digest,
               SPARC64_AOT_DIGEST_BYTES);
    cursor = header_bytes;
    for (uint32_t i = 0; i < image->block_count; ++i) {
        const sparc64_aot_block_t *block = &image->blocks[i];
        put64(destination + cursor, block->source_offset);
        put32(destination + cursor + 8, block->source_size);
        put32(destination + cursor + 12, block->a64_size);
        put16(destination + cursor + 16, block->relocation_count);
        put16(destination + cursor + 18, 0);
        put32(destination + cursor + 20, 0);
        cursor += SPARC64_AOT_BLOCK_HEADER_BYTES;
        memcpy(destination + cursor, block->source_bytes, block->source_size);
        cursor += block->source_size;
        memcpy(destination + cursor, block->a64_text, block->a64_size);
        cursor += block->a64_size;
        for (uint16_t j = 0; j < block->relocation_count; ++j) {
            encode_relocation(destination + cursor, &block->relocations[j]);
            cursor += SPARC64_AOT_RELOCATION_BYTES;
        }
    }
    *written = total;
    return 0;
}

int sparc64_aot_encode(const sparc64_aot_image_t *image, uint8_t *destination,
                  size_t capacity, size_t *written)
{
    return encode(image, SPARC64_AOT_FORMAT_VERSION, NULL, destination, capacity, written);
}

int sparc64_aot_encode_v2(const sparc64_aot_image_t *image,
                      const uint8_t record_digest[SPARC64_AOT_DIGEST_BYTES],
                      uint8_t *destination, size_t capacity, size_t *written)
{
    return encode(image, SPARC64_AOT_FORMAT_V2, record_digest, destination, capacity, written);
}

static bool parse_block_at(const uint8_t *encoded, size_t encoded_size,
                           size_t cursor, sparc64_aot_block_view_t *out,
                           size_t *record_offset, size_t *next_offset)
{
    size_t end;
    size_t relocation_bytes;
    uint32_t source_size;
    uint32_t text_size;
    uint16_t relocation_count;
    if (cursor > encoded_size || encoded_size - cursor < SPARC64_AOT_BLOCK_HEADER_BYTES)
        return false;
    source_size = get32(encoded + cursor + 8);
    text_size = get32(encoded + cursor + 12);
    relocation_count = get16(encoded + cursor + 16);
    relocation_bytes = (size_t)relocation_count * SPARC64_AOT_RELOCATION_BYTES;
    end = cursor + SPARC64_AOT_BLOCK_HEADER_BYTES;
    if (!add_size(end, source_size, &end) || !add_size(end, text_size, &end) ||
        !add_size(end, relocation_bytes, &end) || end > encoded_size)
        return false;
    if (out != NULL) {
        out->source_offset = get64(encoded + cursor);
        out->source_size = source_size;
        out->a64_size = text_size;
        out->relocation_count = relocation_count;
        out->source_bytes = encoded + cursor + SPARC64_AOT_BLOCK_HEADER_BYTES;
        out->a64_text = out->source_bytes + source_size;
        out->relocations = out->a64_text + text_size;
    }
    if (record_offset != NULL)
        *record_offset = cursor;
    *next_offset = end;
    return true;
}

int sparc64_aot_decode(const uint8_t *encoded, size_t encoded_size,
                  sparc64_aot_view_t *out)
{
    sparc64_aot_view_t candidate;
    uint32_t text_sizes[SPARC64_AOT_MAX_BLOCKS];
    size_t cursor;
    uint64_t previous_start = 0;
    uint32_t relocation_total = 0;

    if (encoded == NULL || out == NULL || encoded_size < SPARC64_AOT_HEADER_BYTES ||
        encoded_size > SPARC64_AOT_MAX_FILE_BYTES ||
        memcmp(encoded, format_magic, sizeof(format_magic)) != 0 ||
        !((get16(encoded + 8) == SPARC64_AOT_FORMAT_VERSION &&
           get16(encoded + 10) == SPARC64_AOT_HEADER_BYTES) ||
          (get16(encoded + 8) == SPARC64_AOT_FORMAT_V2 &&
           get16(encoded + 10) == SPARC64_AOT_HEADER_V2_BYTES &&
           encoded_size >= SPARC64_AOT_HEADER_V2_BYTES)) ||
        get32(encoded + 12) != encoded_size || get32(encoded + 16) != 0 ||
        get16(encoded + 26) != 0 || get64(encoded + 56) != 0) {
        errno = EINVAL;
        return -1;
    }
    memset(&candidate, 0, sizeof(candidate));
    candidate.encoded = encoded;
    candidate.encoded_size = encoded_size;
    candidate.format_version = get16(encoded + 8);
    candidate.header_bytes = get16(encoded + 10);
    if (candidate.format_version == SPARC64_AOT_FORMAT_V2)
        memcpy(candidate.record_digest, encoded + SPARC64_AOT_RECORD_DIGEST_OFFSET,
               SPARC64_AOT_DIGEST_BYTES);
    candidate.block_count = get32(encoded + 20);
    candidate.xlen = encoded[24];
    candidate.abi = encoded[25];
    candidate.guest_extensions = get64(encoded + 28);
    candidate.a64_host_requirements = get64(encoded + 36);
    candidate.guest_page_size = get32(encoded + 44);
    candidate.memory_model = get32(encoded + 48);
    candidate.a64_host_page_size = get32(encoded + 52);
    memcpy(candidate.input_digest, encoded + 64, SPARC64_AOT_DIGEST_BYTES);
    memcpy(candidate.runtime_digest, encoded + 96, SPARC64_AOT_DIGEST_BYTES);
    memcpy(candidate.emitter_digest, encoded + 128, SPARC64_AOT_DIGEST_BYTES);
    memcpy(candidate.profile_digest, encoded + 160, SPARC64_AOT_DIGEST_BYTES);
    if (candidate.block_count == 0 || candidate.block_count > SPARC64_AOT_MAX_BLOCKS ||
        !abi_valid(candidate.xlen, candidate.abi) ||
        !page_size_valid(candidate.guest_page_size) ||
        !a64_host_page_size_valid(candidate.a64_host_page_size) ||
        candidate.memory_model != SPARC64_AOT_MEMORY_SPARSE_CHECKED) {
        errno = EINVAL;
        return -1;
    }

    cursor = candidate.header_bytes;
    for (uint32_t i = 0; i < candidate.block_count; ++i) {
        sparc64_aot_block_view_t block;
        size_t record_offset;
        size_t next_offset;
        if (!parse_block_at(encoded, encoded_size, cursor, &block,
                            &record_offset, &next_offset) ||
            get16(encoded + record_offset + 18) != 0 ||
            get32(encoded + record_offset + 20) != 0 ||
            block.source_size == 0 || block.source_size > SPARC64_AOT_MAX_SOURCE_BYTES ||
            block.a64_size == 0 || block.a64_size > SPARC64_AOT_MAX_BLOCK_TEXT_BYTES ||
            block.relocation_count > SPARC64_AOT_MAX_RELOCS_PER_BLOCK ||
            block.source_offset > UINT64_MAX - block.source_size) {
            errno = EINVAL;
            return -1;
        }
        if ((block.source_size & 1u) != 0 || (block.a64_size & 3u) != 0 ||
            (block.source_offset & 1u) != 0 ||
            (i != 0 && block.source_offset <= previous_start) ||
            block.relocation_count > SPARC64_AOT_MAX_RELOCS - relocation_total) {
            errno = EINVAL;
            return -1;
        }
        previous_start = block.source_offset;
        text_sizes[i] = block.a64_size;
        relocation_total += block.relocation_count;
        for (uint16_t j = 0; j < block.relocation_count; ++j) {
            const uint8_t *reloc = block.relocations +
                                   (size_t)j * SPARC64_AOT_RELOCATION_BYTES;
            if (!wire_relocation_valid(reloc, block.a64_size,
                                       candidate.block_count)) {
                errno = EINVAL;
                return -1;
            }
            for (uint16_t k = 0; k < j; ++k) {
                const uint8_t *prior = block.relocations +
                                       (size_t)k * SPARC64_AOT_RELOCATION_BYTES;
                uint32_t patch = get32(reloc + 4);
                uint32_t prior_patch = get32(prior + 4);
                uint32_t end = patch + reloc[2];
                uint32_t prior_end = prior_patch + prior[2];
                if (patch < prior_end && prior_patch < end) {
                    errno = EINVAL;
                    return -1;
                }
            }
        }
        cursor = next_offset;
    }
    if (cursor != encoded_size) {
        errno = EINVAL;
        return -1;
    }

    cursor = candidate.header_bytes;
    for (uint32_t i = 0; i < candidate.block_count; ++i) {
        sparc64_aot_block_view_t block;
        size_t next_offset;
        if (!parse_block_at(encoded, encoded_size, cursor, &block, NULL,
                            &next_offset)) {
            errno = EINVAL;
            return -1;
        }
        for (uint16_t j = 0; j < block.relocation_count; ++j) {
            const uint8_t *reloc = block.relocations +
                                   (size_t)j * SPARC64_AOT_RELOCATION_BYTES;
            if (get16(reloc) == SPARC64_AOT_RELOC_BLOCK_RELATIVE) {
                uint32_t target_index = (uint32_t)get64(reloc + 8);
                uint32_t target_offset = (uint32_t)(get64(reloc + 8) >> 32);
                if (target_index >= candidate.block_count ||
                    target_offset >= text_sizes[target_index]) {
                    errno = EINVAL;
                    return -1;
                }
            }
        }
        cursor = next_offset;
    }
    *out = candidate;
    return 0;
}

int sparc64_aot_view_block(const sparc64_aot_view_t *view, uint32_t index,
                      sparc64_aot_block_view_t *out)
{
    sparc64_aot_block_view_t candidate;
    size_t cursor;
    if (view == NULL || out == NULL || view->encoded == NULL ||
        index >= view->block_count ||
        !((view->format_version == SPARC64_AOT_FORMAT_VERSION &&
           view->header_bytes == SPARC64_AOT_HEADER_BYTES) ||
          (view->format_version == SPARC64_AOT_FORMAT_V2 &&
           view->header_bytes == SPARC64_AOT_HEADER_V2_BYTES))) {
        errno = EINVAL;
        return -1;
    }
    cursor = view->header_bytes;
    for (uint32_t i = 0; i <= index; ++i) {
        size_t next_offset;
        if (!parse_block_at(view->encoded, view->encoded_size, cursor,
                            &candidate, NULL, &next_offset)) {
            errno = EINVAL;
            return -1;
        }
        cursor = next_offset;
    }
    *out = candidate;
    return 0;
}

int sparc64_aot_view_relocation(const sparc64_aot_block_view_t *block, uint16_t index,
                           sparc64_aot_relocation_t *out)
{
    sparc64_aot_relocation_t candidate;
    const uint8_t *p;
    if (block == NULL || out == NULL || block->relocations == NULL ||
        index >= block->relocation_count) {
        errno = EINVAL;
        return -1;
    }
    p = block->relocations + (size_t)index * SPARC64_AOT_RELOCATION_BYTES;
    candidate.kind = get16(p);
    candidate.width = p[2];
    candidate.patch_offset = get32(p + 4);
    candidate.target = get64(p + 8);
    candidate.addend = get_i64(p + 16);
    *out = candidate;
    return 0;
}
