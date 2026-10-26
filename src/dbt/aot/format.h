/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SPARC64RT_AOT_FORMAT_H
#define SPARC64RT_AOT_FORMAT_H

#include <stddef.h>
#include <stdint.h>

#include "dbt/mem_sites.h"

/* This module only encodes and structurally validates bytes. A decoded view is
 * not trusted input and MUST NOT be executed or published RX. A later owner
 * must verify cache ownership, all opaque digests/profile values, live guest
 * bytes/generations, relocation semantics, and private staging before use.
 */
#define SPARC64_AOT_FORMAT_VERSION 1u
#define SPARC64_AOT_HEADER_BYTES 192u
#define SPARC64_AOT_FORMAT_V2 2u
#define SPARC64_AOT_HEADER_V2_BYTES 224u
/* V3 keeps the V2 224-byte header (record digest included) and appends
 * a per-block Soft-TLB site table after the relocations: site_count
 * (u16) lives in the block header bytes formerly reserved as zero at
 * offset 18, followed by site_count x 24-byte site records. Decoders
 * that only know V1/V2 keep rejecting the nonzero reserved field. */
#define SPARC64_AOT_FORMAT_V3 3u
#define SPARC64_AOT_HEADER_V3_BYTES SPARC64_AOT_HEADER_V2_BYTES
#define SPARC64_AOT_RECORD_DIGEST_OFFSET 192u
#define SPARC64_AOT_BLOCK_HEADER_BYTES 24u
#define SPARC64_AOT_RELOCATION_BYTES 24u
#define SPARC64_AOT_DIGEST_BYTES 32u
#define SPARC64_AOT_MAX_FILE_BYTES (16u * 1024u * 1024u)
#define SPARC64_AOT_MAX_BLOCKS 4096u
#define SPARC64_AOT_MAX_SOURCE_BYTES 128u
#define SPARC64_AOT_MAX_BLOCK_TEXT_BYTES (64u * 1024u)
#define SPARC64_AOT_MAX_RELOCS_PER_BLOCK 256u
#define SPARC64_AOT_MAX_RELOCS 65536u

typedef enum sparc64_aot_abi {
    SPARC64_AOT_ABI_ILP32 = 1,
    SPARC64_AOT_ABI_ILP32D = 2,
    SPARC64_AOT_ABI_LP64 = 3,
    SPARC64_AOT_ABI_LP64D = 4
} sparc64_aot_abi_t;

typedef enum sparc64_aot_memory_model {
    SPARC64_AOT_MEMORY_SPARSE_CHECKED = 1
} sparc64_aot_memory_model_t;

typedef enum sparc64_aot_relocation_kind {
    SPARC64_AOT_RELOC_HELPER_ID = 1,
    SPARC64_AOT_RELOC_GUEST_RELATIVE = 2,
    SPARC64_AOT_RELOC_BLOCK_RELATIVE = 3
} sparc64_aot_relocation_kind_t;

typedef struct sparc64_aot_relocation {
    uint16_t kind;
    uint8_t width;       /* helper/guest MOV64: 16; block B26: 4 */
    uint32_t patch_offset;
    /* Helper ID or guest-VA-relative input offset; block target packs block
     * index in low32 and target A64 byte offset in high32. No host pointers. */
    uint64_t target;
    /* The format checks the raw block target's alignment/bounds, but leaves
     * addend arithmetic, B26 range and opcode-template checks to the future
     * applicator. */
    int64_t addend;
} sparc64_aot_relocation_t;

/* Source offsets and guest-relative targets are input-image guest-VA offsets,
 * not file offsets. ELF mapping and live load bias remain applicator work. */

typedef struct sparc64_aot_block {
    uint64_t source_offset;
    const uint8_t *source_bytes;
    uint32_t source_size;
    const uint8_t *a64_text;
    uint32_t a64_size;
    const sparc64_aot_relocation_t *relocations;
    uint16_t relocation_count;
    /* V3 only: Soft-TLB recovery records for this block's memory sites
     * (must be empty for V1/V2 images). */
    const sparc64_mem_site_t *sites;
    uint16_t site_count;
} sparc64_aot_block_t;

typedef struct sparc64_aot_image {
    uint8_t input_digest[SPARC64_AOT_DIGEST_BYTES];
    uint8_t runtime_digest[SPARC64_AOT_DIGEST_BYTES];
    uint8_t emitter_digest[SPARC64_AOT_DIGEST_BYTES];
    uint8_t profile_digest[SPARC64_AOT_DIGEST_BYTES];
    uint64_t guest_extensions;
    uint64_t a64_host_requirements;
    uint32_t guest_page_size;
    uint32_t a64_host_page_size;
    uint32_t memory_model;
    uint8_t xlen;
    uint8_t abi;
    uint32_t block_count;
    const sparc64_aot_block_t *blocks;
} sparc64_aot_image_t;

/* Borrowed spans point into encoded bytes; callers must keep the entire input
 * alive and unchanged while using the view. This view conveys no authority.
 */
typedef struct sparc64_aot_block_view {
    uint64_t source_offset;
    const uint8_t *source_bytes;
    uint32_t source_size;
    const uint8_t *a64_text;
    uint32_t a64_size;
    const uint8_t *relocations; /* fixed-width LE records, may be NULL if empty */
    uint16_t relocation_count;
    const uint8_t *sites; /* fixed-width LE site records (V3 only), NULL if empty */
    uint16_t site_count;
} sparc64_aot_block_view_t;

typedef struct sparc64_aot_view {
    const uint8_t *encoded;
    size_t encoded_size;
    uint16_t format_version;
    uint16_t header_bytes;
    uint8_t record_digest[SPARC64_AOT_DIGEST_BYTES];
    uint8_t input_digest[SPARC64_AOT_DIGEST_BYTES];
    uint8_t runtime_digest[SPARC64_AOT_DIGEST_BYTES];
    uint8_t emitter_digest[SPARC64_AOT_DIGEST_BYTES];
    uint8_t profile_digest[SPARC64_AOT_DIGEST_BYTES];
    uint64_t guest_extensions;
    uint64_t a64_host_requirements;
    uint32_t guest_page_size;
    uint32_t a64_host_page_size;
    uint32_t memory_model;
    uint8_t xlen;
    uint8_t abi;
    uint32_t block_count;
} sparc64_aot_view_t;

/* All integer wire fields are little-endian. Encoder input spans must not
 * overlap destination. On failure these functions return -1 with errno set
 * and leave `written`/`out` unchanged. */
int sparc64_aot_encode(const sparc64_aot_image_t *image, uint8_t *destination,
                  size_t capacity, size_t *written);
/* V2 extends the header with an opaque whole-record digest. The codec does
 * not compute or validate it; even v2 decode success conveys no authority.
 * V1 encoding and decoding remain available for structural tooling only. */
int sparc64_aot_encode_v2(const sparc64_aot_image_t *image,
                      const uint8_t record_digest[SPARC64_AOT_DIGEST_BYTES],
                      uint8_t *destination, size_t capacity, size_t *written);
/* Validate the same image contract as encode_v2 and return its exact size
 * without allocating or writing a record. On failure *size is unchanged. */
int sparc64_aot_encoded_size_v2(const sparc64_aot_image_t *image, size_t *size);
int sparc64_aot_decode(const uint8_t *encoded, size_t encoded_size,
                  sparc64_aot_view_t *out);
int sparc64_aot_view_block(const sparc64_aot_view_t *view, uint32_t index,
                      sparc64_aot_block_view_t *out);
int sparc64_aot_view_relocation(const sparc64_aot_block_view_t *block, uint16_t index,
                           sparc64_aot_relocation_t *out);
int sparc64_aot_encode_v3(const sparc64_aot_image_t *image,
    const uint8_t record_digest[SPARC64_AOT_DIGEST_BYTES],
    uint8_t *destination, size_t capacity, size_t *written);
/* Size of the V3 encoding without writing it. */
int sparc64_aot_encoded_size_v3(const sparc64_aot_image_t *image,
    size_t *size);
/* Decode one V3 site record into *out (validates wire values).
 * Fails for V1/V2 views or out-of-range index. */
int sparc64_aot_view_site(const sparc64_aot_block_view_t *block,
    uint16_t index, sparc64_mem_site_t *out);

#endif
