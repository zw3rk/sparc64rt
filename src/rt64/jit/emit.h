/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SPARC64RT_JIT_EMIT_H
#define SPARC64RT_JIT_EMIT_H

#include <stdint.h>

/* A64 data-processing and unsigned-offset load/store encoders. All callers
 * validate register numbers and immediate widths before calling these. */
static inline uint32_t sparc64_a64_movz(unsigned rd, unsigned halfword,
                                   uint16_t immediate)
{
    return UINT32_C(0xd2800000) | (halfword << 21) |
           ((uint32_t)immediate << 5) | rd;
}

static inline uint32_t sparc64_a64_movk(unsigned rd, unsigned halfword,
                                   uint16_t immediate)
{
    return UINT32_C(0xf2800000) | (halfword << 21) |
           ((uint32_t)immediate << 5) | rd;
}

static inline uint32_t sparc64_a64_ldr(unsigned rt, unsigned rn,
                                  unsigned byte_offset)
{
    return UINT32_C(0xf9400000) | ((byte_offset / 8u) << 10) |
           (rn << 5) | rt;
}

static inline uint32_t sparc64_a64_str(unsigned rt, unsigned rn,
                                  unsigned byte_offset)
{
    return UINT32_C(0xf9000000) | ((byte_offset / 8u) << 10) |
           (rn << 5) | rt;
}

static inline uint32_t sparc64_a64_mov_reg(unsigned rd, unsigned rn)
{
    return UINT32_C(0xaa0003e0) | (rn << 16) | rd;
}

static inline uint32_t sparc64_a64_add_imm(unsigned rd, unsigned rn,
                                      unsigned immediate)
{
    return UINT32_C(0x91000000) | (immediate << 10) | (rn << 5) | rd;
}

static inline uint32_t sparc64_a64_sub_imm(unsigned rd, unsigned rn,
                                      unsigned immediate)
{
    return UINT32_C(0xd1000000) | (immediate << 10) | (rn << 5) | rd;
}

static inline uint32_t sparc64_a64_alu_reg(uint32_t base, unsigned rd,
                                      unsigned rn, unsigned rm)
{
    return base | (rm << 16) | (rn << 5) | rd;
}

#endif
