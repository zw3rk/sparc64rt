/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SPARC64RT_AOT_RELOCATE_H
#define SPARC64RT_AOT_RELOCATE_H
#include "aot/format.h"
#include <stddef.h>
#include <stdint.h>

typedef struct sparc64_aot_relocated {
    uint8_t *bytes;
    size_t size;
} sparc64_aot_relocated_t;

typedef enum sparc64_aot_relocate_result {
    SPARC64_AOT_RELOCATE_ERROR = -1,
    SPARC64_AOT_RELOCATE_DECLINE = 0,
    SPARC64_AOT_RELOCATE_OK = 1
} sparc64_aot_relocate_result_t;

/* Apply only GUEST_RELATIVE MOV64 relocations to a malloc-owned RW copy.
 * Input must be a stable block view from sparc64_aot_decode/view_block, with its
 * borrowed storage retained. All sites, nonoverlap, 64-bit MOVZ/MOVK opcode,
 * destination and halfword sequence are checked before allocation/mutation.
 * Guest image base + target + signed addend must not wrap: wrapping guest
 * arithmetic remains eligible for ordinary JIT, but declines this export.
 * HELPER/B26 and future kinds deliberately DECLINE. No mapping, publication,
 * live guest permission proof or host execution is performed. A caller still
 * needs trusted snapshot/profile/live-source validation before activation.
 * Empty output (NULL bytes,size0) is required. Output and input stay unchanged
 * on ERROR/DECLINE; success owns only an ordinary byte buffer. */
sparc64_aot_relocate_result_t sparc64_aot_relocate_guest(const sparc64_aot_block_view_t *block,
                                               uint64_t guest_image_base,
                                               sparc64_aot_relocated_t *out);
void sparc64_aot_relocated_destroy(sparc64_aot_relocated_t *out);
#endif
