/*
 * src/dbt/emit_mem.c — 7-instruction BE Soft-TLB emitter (Lane M3)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Implements emit_mem.h over the emit_priv.h word encoders. Every
 * opcode below is field-composed with the layout quoted next to it;
 * the M3 verification probe (see lane notes) cross-checks each word
 * against clang-assembled reference mnemonics.
 */

#include "dbt/emit_mem.h"

#include "dbt/emit_priv.h"
#include "dbt/mem_sites.h"

/* No-edge sentinel: matches SPARC64_DBT_NOPOS ((size_t)-1). */
#define MEM_NO_EDGE ((size_t)-1)

/* ---- local word encoders (field-composed, no x18) ------------------ */

/* ADD Xd, Xn, Xm, LSL #sh (shifted register, 64-bit). */
static void enc_add_lsl(sparc64_dbt_buf_t *b, unsigned rd, unsigned rn,
    unsigned rm, unsigned sh)
{
    sb_word(b, UINT32_C(0x8b000000) | ((rm & 31U) << 16) |
        ((sh & 63U) << 10) | ((rn & 31U) << 5) | (rd & 31U));
}

/* LDP Xt1, Xt2, [Xn, #imm] / STP Xt1, Xt2, [Xn, #imm], 64-bit
 * (signed offset, imm8 is the byte offset, a multiple of 8). */
static void enc_ldp(sparc64_dbt_buf_t *b, bool is_load, unsigned rt,
    unsigned rt2, unsigned rn, int32_t imm8)
{
    uint32_t base = is_load ? UINT32_C(0xa9400000) :
        UINT32_C(0xa9000000);
    uint32_t imm7 = (uint32_t)((imm8 >> 3) & 0x7f);
    if ((imm8 & 7) != 0) {
        b->overflow = true;
        return;
    }
    sb_word(b, base | (imm7 << 15) |
        ((rt2 & 31U) << 10) | ((rn & 31U) << 5) | (rt & 31U));
}

/* Rotate right (64-bit). */
static uint64_t ror64(uint64_t v, unsigned r)
{
    r &= 63U;
    if (r == 0U) {
        return v;
    }
    return (v >> r) | (v << (64U - r));
}

/* Encode a 64-bit logical-immediate mask as N/immr/imms. Covers every
 * single-run mask (including runs that wrap bit 63), which is all the
 * Soft-TLB alignment masks need. Brute force is tiny and obviously
 * right: len in 1..63, rot in 0..63. */
static bool enc_mask_fields(uint64_t v, unsigned *n, unsigned *immr,
    unsigned *imms)
{
    unsigned len;
    unsigned rot;
    if (v == UINT64_C(0) || v == ~UINT64_C(0)) {
        return false;
    }
    for (len = 1U; len < 64U; len++) {
        uint64_t ones = (UINT64_C(1) << len) - UINT64_C(1);
        for (rot = 0U; rot < 64U; rot++) {
            if (ror64(ones, rot) == v) {
                *n = 1U;
                *immr = rot;
                *imms = len - 1U;
                return true;
            }
        }
    }
    return false;
}

/* AND Xd, Xn, #mask (64-bit logical immediate). */
static bool enc_and_imm(sparc64_dbt_buf_t *b, unsigned rd, unsigned rn,
    uint64_t mask)
{
    unsigned n;
    unsigned immr;
    unsigned imms;
    if (!enc_mask_fields(mask, &n, &immr, &imms)) {
        b->overflow = true;
        return false;
    }
    sb_word(b, UINT32_C(0x92000000) | ((n & 1U) << 22) |
        ((immr & 63U) << 16) | ((imms & 63U) << 10) |
        ((rn & 31U) << 5) | (rd & 31U));
    return true;
}

/* LDR/STR (register offset, LSL #0): word = size:V:111:00:opc:1....
 * size: 8B->3, 4B->2, 2B->1, 1B->0. opc: load->1, store->0. */
static void enc_ldst_reg(sparc64_dbt_buf_t *b, bool is_load,
    unsigned size_bits, unsigned rt, unsigned rn, unsigned rm)
{
    uint32_t size;
    uint32_t opc;
    switch (size_bits) {
    case 8U: size = 3U; break;
    case 4U: size = 2U; break;
    case 2U: size = 1U; break;
    default: size = 0U; break;
    }
    opc = is_load ? 1U : 0U;
    sb_word(b, (size << 30) | (UINT32_C(7) << 27) | (opc << 22) |
        (UINT32_C(1) << 21) | ((rm & 31U) << 16) |
        (UINT32_C(3) << 13) | (UINT32_C(2) << 10) |
        ((rn & 31U) << 5) | (rt & 31U));
}

/* LDRSB/LDRSH (register offset, 8/16-bit signed into 64 bits).
 * size: 2B->1, 1B->0; opc is 2 (signed, 64-bit destination). opc 3
 * would be the 32-bit-destination forms. Verified against clang. */
static void enc_ldrsh_reg(sparc64_dbt_buf_t *b, unsigned size_bits,
    unsigned rt, unsigned rn, unsigned rm)
{
    uint32_t size = (size_bits == 2U) ? 1U : 0U;
    sb_word(b, (size << 30) | (UINT32_C(7) << 27) |
        (UINT32_C(2) << 22) | (UINT32_C(1) << 21) |
        ((rm & 31U) << 16) | (UINT32_C(3) << 13) |
        (UINT32_C(2) << 10) | ((rn & 31U) << 5) | (rt & 31U));
}

/* REV Wd (32-bit byte-reverse), REV Xd (64-bit), REV16 Wd. The 32-bit
 * forms live at 0x5AC00xxx (not the 0x1AC00xxx SDIV/UDIV space);
 * verified word-for-word against the assembler. */
static void enc_rev(sparc64_dbt_buf_t *b, bool to64, bool is16,
    unsigned rd, unsigned rn)
{
    uint32_t base;
    if (to64) {
        base = UINT32_C(0xdac00c00);
    } else if (is16) {
        base = UINT32_C(0x5ac00400);
    } else {
        base = UINT32_C(0x5ac00800);
    }
    sb_word(b, base | ((rn & 31U) << 5) | (rd & 31U));
}

/* SXTH/SXTW into 64 bits: SBFM64 #0, #15/#31. */
static void enc_sxt(sparc64_dbt_buf_t *b, bool is32, unsigned rd,
    unsigned rn)
{
    uint32_t imms = is32 ? 31U : 15U;
    sb_word(b, UINT32_C(0x93400000) | (imms << 10) |
        ((rn & 31U) << 5) | (rd & 31U));
}

/* BR Xn. */
static void enc_br(sparc64_dbt_buf_t *b, unsigned rn)
{
    sb_word(b, UINT32_C(0xd61f0000) | ((rn & 31U) << 5));
}

/* ---- mask table -----------------------------------------------------
 * Step-4 mask keeps the low alignment bits and clears the tag bits:
 * (gva & mask) == read_tag iff VPN matches and gva is N-aligned. */

static uint64_t mem_align_mask(unsigned width)
{
    switch (width) {
    case 1U: return UINT64_C(0xfffffffffffff000);
    case 2U: return UINT64_C(0xfffffffffffff001);
    case 4U: return UINT64_C(0xfffffffffffff003);
    case 8U: return UINT64_C(0xfffffffffffff007);
    case 16U: return UINT64_C(0xfffffffffffff00f);
    default: return UINT64_C(0);
    }
}

/* ---- fast-path emitters ---------------------------------------------
 * Fixed scratch: x1 = gva (in), x2/x3 = TLB pair, x4 = tag delta
 * (reused for the swapped store value), x0 = value/dst. */

/* Emit the shared 6-word check; returns false on bad width/overflow. */
static bool mem_emit_check(sparc64_dbt_buf_t *b, bool is_store,
    unsigned width)
{
    uint64_t mask = mem_align_mask(width);
    if (mask == UINT64_C(0)) {
        return false;
    }
    sb_ubfm(b, true, 2U, 1U, 12U, 23U); /* 1. index */
    enc_add_lsl(b, 2U, 20U, 2U, 5U); /* 2. &tlb[index] */
    if (is_store) {
        enc_ldp(b, true, 3U, 2U, 2U, 8); /* 3. addend, write_tag */
    } else {
        enc_ldp(b, true, 2U, 3U, 2U, 0); /* 3. read_tag, addend */
    }
    if (!enc_and_imm(b, 4U, 1U, mask)) { /* 4. tag + align test */
        return false;
    }
    sb_sub_reg(b, true, false, 4U, 4U, 2U); /* 5. diff */
    return true;
}

size_t sparc64_mem_emit_fast(struct sparc64_dbt_buf *b, bool is_store,
    unsigned width, bool is_signed, unsigned vd,
    sparc64_mem_site_t *site)
{
    size_t miss;
    if (b == NULL || site == NULL || vd > 31U) {
        return MEM_NO_EDGE;
    }
    if (width != 1U && width != 2U && width != 4U && width != 8U &&
        width != 16U) {
        return MEM_NO_EDGE;
    }
    site->seq_start_offset = (uint16_t)((size_t)b->count * 4U);
    if (!mem_emit_check(b, is_store, width)) {
        return MEM_NO_EDGE;
    }
    miss = sb_cbz_placeholder(b, true, true, 4U); /* 6. miss? */
    if (miss == SPARC64_DBT_NOPOS) {
        return MEM_NO_EDGE;
    }
    site->host_insn_offset = (uint16_t)((size_t)b->count * 4U);
    if (!is_store) {
        switch (width) {
        case 1U:
            if (is_signed) {
                enc_ldrsh_reg(b, 1U, vd, 1U, 3U);
            } else {
                enc_ldst_reg(b, true, 1U, vd, 1U, 3U);
            }
            break;
        case 2U:
            enc_ldst_reg(b, true, 2U, vd, 1U, 3U);
            enc_rev(b, false, true, vd, vd);
            if (is_signed) {
                enc_sxt(b, false, vd, vd);
            }
            break;
        case 4U:
            enc_ldst_reg(b, true, 4U, vd, 1U, 3U);
            enc_rev(b, false, false, vd, vd);
            if (is_signed) {
                enc_sxt(b, true, vd, vd);
            }
            break;
        case 8U:
            enc_ldst_reg(b, true, 8U, vd, 1U, 3U);
            enc_rev(b, true, false, vd, vd);
            break;
        default: /* 16U quad: low half to vd, high half to x4. */
            enc_add_lsl(b, 2U, 1U, 3U, 0U);
            enc_ldp(b, true, vd, 4U, 2U, 0);
            enc_rev(b, true, false, vd, vd);
            enc_rev(b, true, false, 4U, 4U);
            break;
        }
    } else {
        switch (width) {
        case 1U:
            enc_ldst_reg(b, false, 1U, 0U, 1U, 3U);
            break;
        case 2U:
            enc_rev(b, false, true, 4U, 0U);
            enc_ldst_reg(b, false, 2U, 4U, 1U, 3U);
            break;
        case 4U:
            enc_rev(b, false, false, 4U, 0U);
            enc_ldst_reg(b, false, 4U, 4U, 1U, 3U);
            break;
        case 8U:
            enc_rev(b, true, false, 4U, 0U);
            enc_ldst_reg(b, false, 8U, 4U, 1U, 3U);
            break;
        default: /* 16U quad: low half in x0, high half in x5. */
            enc_add_lsl(b, 2U, 1U, 3U, 0U);
            enc_rev(b, true, false, 4U, 0U);
            enc_rev(b, true, false, 5U, 5U);
            enc_ldp(b, false, 4U, 5U, 2U, 0);
            break;
        }
    }
    if (b->overflow) {
        return MEM_NO_EDGE;
    }
    site->cont_insn_offset = (uint16_t)((size_t)b->count * 4U);
    return miss;
}

size_t sparc64_mem_emit_atomic_edge(struct sparc64_dbt_buf *b)
{
    size_t miss;
    if (b == NULL) {
        return MEM_NO_EDGE;
    }
    /* cbz wzr: never falls through, always takes the stub edge; the
     * patch kind matches the fast-path cbnz so the tail treats every
     * edge uniformly. */
    miss = sb_cbz_placeholder(b, true, false, 31U);
    if (miss == SPARC64_DBT_NOPOS) {
        return MEM_NO_EDGE;
    }
    return miss;
}

/* Shared per-block miss trampoline. Entry: x1 = gva, x0 = value
 * (stores), w4 = site index. Preserves the CCR cached in NZCV across
 * the C slow path, then resumes at the helper's address or exits for
 * dispatcher replay. x30 (the trampoline return) is spilled across
 * the BLR; x29 is untouched. */
static bool mem_emit_common(struct sparc64_dbt_buf *b,
    const sparc64_mem_block_t *blk, size_t *b_patches, uint32_t n)
{
    size_t common;
    size_t miss_cbz;
    uint32_t i;
    if (blk == NULL) {
        return false;
    }
    common = b->count;
    sb_mrs_nzcv(b, 5U);
    sb_push64(b, 5U);
    sb_push64(b, 30U);
    sb_mov_reg(b, true, 2U, 0U); /* val */
    sb_mov_reg(b, true, 0U, 19U); /* ctx */
    sb_mov_imm64(b, 3U, (uint64_t)(uintptr_t)blk);
    sb_mov_imm64(b, 6U, (uint64_t)(uintptr_t)&sparc64_mem_miss);
    sb_blr(b, 6U); /* x0 = resume address or NULL */
    sb_pop64(b, 30U);
    sb_pop64(b, 5U);
    miss_cbz = sb_cbz_placeholder(b, true, false, 0U);
    if (miss_cbz == SPARC64_DBT_NOPOS) {
        return false;
    }
    sb_msr_nzcv(b, 5U);
    enc_br(b, 0U);
    sb_patch_cb(b, miss_cbz, b->count);
    /* Fault: replay through the dispatcher (interp is precise). */
    sb_ldst_imm(b, true, true, 15U, 19U,
        (uint32_t)SPARC64_CTX_EXIT_DEST_OFFSET);
    sb_ldst_imm(b, true, false, 16U, 19U,
        (uint32_t)SPARC64_CTX_EXIT_REASON_OFFSET);
    sb_msr_nzcv(b, 5U);
    sb_ret(b);
    if (b->overflow) {
        return false;
    }
    for (i = 0U; i < n; i++) {
        sb_patch_b(b, b_patches[i], common);
    }
    return true;
}

bool sparc64_mem_emit_tail(struct sparc64_dbt_buf *b,
    const sparc64_mem_block_t *blk, const size_t *edges, uint32_t n)
{
    size_t *b_patches;
    uint32_t i;
    /* VLA-free scratch: blocks hold at most 64 sites (one per insn);
     * refuse larger tables instead of growing the stack frame. */
    size_t patches[SPARC64_DBT_MAX_SITES_PER_BLOCK];
    if (b == NULL || blk == NULL || edges == NULL || n == 0U ||
        n > SPARC64_DBT_MAX_SITES_PER_BLOCK ||
        blk->n_sites != n) {
        return false;
    }
    b_patches = patches;
    for (i = 0U; i < n; i++) {
        size_t stub;
        if (edges[i] == MEM_NO_EDGE) {
            return false;
        }
        stub = b->count;
        sb_patch_cb(b, edges[i], stub);
        sb_movz(b, false, 4U, 0U, (uint16_t)i);
        b_patches[i] = sb_b_placeholder(b);
        if (b->overflow) {
            return false;
        }
        (void)stub;
    }
    return mem_emit_common(b, blk, b_patches, n);
}
