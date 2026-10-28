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

#include <string.h>

#include "dbt/emit_priv.h"
#include "dbt/mem_sites.h"
#include "interp/interp.h"

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

/* Fixed 4-word movz/movk materialization (unlike the variable-length
 * sb_mov_imm64) so the block-record address baked by the tail can be
 * patched after the record slot is carved. Never touches x18. */
static size_t mem_mov_imm64_fixed(sparc64_dbt_buf_t *b, unsigned rd,
    uint64_t v)
{
    size_t at = b->count;
    unsigned hw;
    sb_word(b, UINT32_C(0xd2800000) | ((0U & 3U) << 21) |
        ((((uint32_t)(v & UINT64_C(0xffff))) << 5) | (rd & 31U)));
    for (hw = 1U; hw < 4U; hw++) {
        uint32_t half = (uint32_t)((v >> (hw * 16U)) & UINT64_C(0xffff));
        sb_word(b, UINT32_C(0xf2800000) | ((hw & 3U) << 21) |
            (half << 5) | (rd & 31U));
    }
    return at;
}

/* Rewrite the 4 words at a mem_mov_imm64_fixed site in place. */
static void mem_patch_imm64(sparc64_dbt_buf_t *b, size_t at, unsigned rd,
    uint64_t v)
{
    unsigned hw;
    if (b == NULL || at == SPARC64_DBT_NOPOS || at + 4U > b->count) {
        if (b != NULL) {
            b->overflow = true;
        }
        return;
    }
    b->words[at] = UINT32_C(0xd2800000) | ((0U & 3U) << 21) |
        ((((uint32_t)(v & UINT64_C(0xffff))) << 5) | (rd & 31U));
    for (hw = 1U; hw < 4U; hw++) {
        uint32_t half = (uint32_t)((v >> (hw * 16U)) & UINT64_C(0xffff));
        b->words[at + (size_t)hw] = UINT32_C(0xf2800000) |
            ((hw & 3U) << 21) | (half << 5) | (rd & 31U);
    }
}

/* Shared per-block miss trampoline. Entry: x1 = gva, x0 = value
 * (stores), w4 = site index. Preserves the CCR cached in NZCV across
 * the C slow path, then resumes at the helper's address or exits for
 * dispatcher replay. x30 (the trampoline return) is spilled across
 * the BLR; x29 is untouched. The x3 record address is a fixed-width
 * placeholder until the tail carves the record and patches it. */
static bool mem_emit_common(struct sparc64_dbt_buf *b,
    const sparc64_mem_block_t *blk, size_t *b_patches, uint32_t n,
    size_t *blk_patch_out)
{
    size_t common;
    size_t miss_cbz;
    size_t blk_patch;
    uint32_t i;
    if (blk == NULL || blk_patch_out == NULL) {
        return false;
    }
    common = b->count;
    sb_mrs_nzcv(b, 5U);
    sb_push64(b, 5U);
    sb_push64(b, 30U);
    sb_mov_reg(b, true, 2U, 0U); /* val */
    sb_mov_reg(b, true, 0U, 19U); /* ctx */
    blk_patch = mem_mov_imm64_fixed(b, 3U, UINT64_C(0));
    if (blk_patch == SPARC64_DBT_NOPOS) {
        return false;
    }
    *blk_patch_out = blk_patch;
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
    size_t blk_patch = SPARC64_DBT_NOPOS;
    uint32_t i;
    uint32_t j;
    uint64_t base;
    uint64_t slot_addr;
    size_t slot_off;
    size_t need;
    sparc64_mem_block_t *slot;
    /* VLA-free scratch: blocks hold at most 64 sites (one per insn);
     * refuse larger tables instead of growing the stack frame. */
    size_t patches[SPARC64_DBT_MAX_SITES_PER_BLOCK];
    if (b == NULL || blk == NULL || edges == NULL || n == 0U ||
        n > SPARC64_DBT_MAX_SITES_PER_BLOCK ||
        blk->n_sites != n || b->words == NULL) {
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
    if (!mem_emit_common(b, blk, b_patches, n, &blk_patch)) {
        return false;
    }
    /* Carve the record from the same buffer at the next 8-byte boundary
     * past the emitted code: the slot address is absolute (the arena
     * base may sit 4-misaligned after a code-only commit), and the
     * tail size rounds up to 8 so the next block keeps 4-byte code
     * alignment. Lifetime follows the block: recycle and retranslate
     * drop the code and the record together. */
    base = (uint64_t)(uintptr_t)b->words;
    slot_addr = (base + (uint64_t)b->count * 4U + UINT64_C(7)) &
        ~(uint64_t)UINT64_C(7);
    need = ((uint64_t)sizeof(*slot) +
        (uint64_t)n * (uint64_t)sizeof(slot->sites[0]) +
        UINT64_C(7)) & ~(uint64_t)UINT64_C(7);
    if (slot_addr + need > base + (uint64_t)b->capacity * 4U) {
        b->overflow = true;
        return false;
    }
    slot_off = (size_t)((slot_addr - base) / 4U);
    slot = (sparc64_mem_block_t *)(void *)&b->words[slot_off];
    slot->mem = blk->mem;
    slot->mc = blk->mc;
    slot->guest_pc_base = blk->guest_pc_base;
    slot->rx_base = base;
    slot->n_sites = n;
    for (j = 0U; j < n; j++) {
        slot->sites[j] = blk->sites[j];
    }
    mem_patch_imm64(b, blk_patch, 3U, slot_addr);
    b->count = (size_t)((slot_addr + need - base) / 4U);
    return !b->overflow;
}

/* ---- integer-emitter fast-path sites (Lane A1) ----------------------
 * Per-block accumulator plus the single-access plain-ASI wiring used
 * by e_emit_mem. Register plan: x1 = gva in, x0 = store value in,
 * x9 (ES0) = load destination out; the fast path owns x2-x4. Only
 * adds/movs/ldrs/strs run before the check, so host NZCV (which
 * caches guest CCR) is never disturbed. */

/* Map a decoded integer access onto the fast path. Twin-word (LDD/STD),
 * alternate-ASI (*A), FSR, and atomic forms decline: the caller falls
 * back to the checked helper, which replays them bit-identically. */
static bool mem_classify_site(const sparc64_dec_t *d, bool *is_store,
    unsigned *width, bool *is_signed)
{
    if (d == NULL || is_store == NULL || width == NULL ||
        is_signed == NULL) {
        return false;
    }
    if (d->asi != 0U || d->regasi != 0U) {
        return false;
    }
    switch (d->op3) {
    case SPARC64_OP3_LDUW:
        *is_store = false;
        *width = 4U;
        *is_signed = false;
        return true;
    case SPARC64_OP3_LDUB:
        *is_store = false;
        *width = 1U;
        *is_signed = false;
        return true;
    case SPARC64_OP3_LDUH:
        *is_store = false;
        *width = 2U;
        *is_signed = false;
        return true;
    case SPARC64_OP3_LDSW:
        *is_store = false;
        *width = 4U;
        *is_signed = true;
        return true;
    case SPARC64_OP3_LDSB:
        *is_store = false;
        *width = 1U;
        *is_signed = true;
        return true;
    case SPARC64_OP3_LDSH:
        *is_store = false;
        *width = 2U;
        *is_signed = true;
        return true;
    case SPARC64_OP3_LDX:
        *is_store = false;
        *width = 8U;
        *is_signed = false;
        return true;
    case SPARC64_OP3_STW:
        *is_store = true;
        *width = 4U;
        *is_signed = false;
        return true;
    case SPARC64_OP3_STB:
        *is_store = true;
        *width = 1U;
        *is_signed = false;
        return true;
    case SPARC64_OP3_STH:
        *is_store = true;
        *width = 2U;
        *is_signed = false;
        return true;
    case SPARC64_OP3_STX:
        *is_store = true;
        *width = 8U;
        *is_signed = false;
        return true;
    case SPARC64_OP3_LDF:
        *is_store = false;
        *width = 4U;
        *is_signed = false;
        return true;
    case SPARC64_OP3_LDDF:
        *is_store = false;
        *width = 8U;
        *is_signed = false;
        return true;
    case SPARC64_OP3_STF:
        *is_store = true;
        *width = 4U;
        *is_signed = false;
        return true;
    case SPARC64_OP3_STDF:
        *is_store = true;
        *width = 8U;
        *is_signed = false;
        return true;
    default:
        return false;
    }
}

/* Per-block accumulator: reset by block_begin, appended by emit_site,
 * consumed by block_end. Bounds match the tail's 64-site static
 * scratch, so no heap lives across sites. */
static sparc64_mem_site_t
    acc_sites[SPARC64_DBT_MAX_SITES_PER_BLOCK];
static size_t acc_edges[SPARC64_DBT_MAX_SITES_PER_BLOCK];
static uint64_t acc_base;
static uint32_t acc_n;

bool sparc64_mem_emit_site(struct sparc64_dbt_buf *b,
    const sparc64_dec_t *d, uint64_t fault_pc, bool in_delay)
{
    bool is_store = false;
    unsigned width = 0U;
    bool is_signed = false;
    bool is_fp;
    uint32_t fp_off;
    size_t miss;
    uint32_t idx;
    if (b == NULL || d == NULL) {
        return false;
    }
    if (!mem_classify_site(d, &is_store, &width, &is_signed)) {
        return false;
    }
    if (acc_n >= SPARC64_DBT_MAX_SITES_PER_BLOCK) {
        return false;
    }
    is_fp = (d->op3 == (uint8_t)SPARC64_OP3_LDF ||
        d->op3 == (uint8_t)SPARC64_OP3_LDDF ||
        d->op3 == (uint8_t)SPARC64_OP3_STF ||
        d->op3 == (uint8_t)SPARC64_OP3_STDF);
    if (width == 4U) {
        fp_off = 0x140U + (((uint32_t)d->rd ^ 1U) & 31U) * 4U;
    } else {
        uint32_t pair = (((uint32_t)d->rd & 1U) != 0U)
            ? (16U + ((uint32_t)d->rd >> 1U))
            : ((uint32_t)d->rd >> 1U);
        fp_off = 0x140U + (pair & 31U) * 8U;
    }
    if (is_store) {
        if (is_fp) {
            sb_ldst_imm(b, true, width == 8U, 0U, ECTX, fp_off);
        } else {
            e_ld64(b, 0U, d->rd);
        }
    }
    e_ld64(b, 1U, d->rs1);
    e_src2(b, ES1, d);
    sb_add_reg(b, true, false, 1U, 1U, ES1);
    idx = acc_n;
    miss = sparc64_mem_emit_fast(b, is_store, width, is_signed, ES0,
        &acc_sites[idx]);
    if (miss == MEM_NO_EDGE) {
        return false;
    }
    acc_edges[idx] = miss;
    acc_sites[idx].guest_pc_delta = (uint16_t)(fault_pc - acc_base);
    acc_sites[idx].npc_delta = 0;
    acc_sites[idx].insn_word = d->raw;
    acc_sites[idx].sp_rollback_delta = 0;
    acc_sites[idx].npc_mode = (uint8_t)SPARC64_NPC_SEQUENTIAL;
    acc_sites[idx].width = (uint8_t)width;
    acc_sites[idx].flags = (uint8_t)((is_store ?
        (unsigned)SPARC64_MEM_F_STORE : 0U) |
        (in_delay ? (unsigned)SPARC64_MEM_F_IN_DELAY_SLOT : 0U) |
        (unsigned)SPARC64_MEM_F_BE);
    acc_sites[idx].val_or_dst_reg = (uint8_t)(d->rd & 31U);
    acc_sites[idx].addr_base_reg = (uint8_t)(d->rs1 & 31U);
    acc_sites[idx].reserved = 0U;
    acc_n = idx + 1U;
    if (!is_store) {
        if (is_fp) {
            sb_ldst_imm(b, false, width == 8U, ES0, ECTX, fp_off);
        } else {
            e_st64(b, d->rd, ES0);
        }
        /* Resume past the writeback: the miss path lands here with
         * ctx->r[rd] already updated by the interpreter replay. */
        acc_sites[idx].cont_insn_offset =
            (uint16_t)((size_t)b->count * 4U);
    }
    return !b->overflow;
}

void sparc64_mem_block_begin(uint64_t guest_base)
{
    acc_base = guest_base;
    acc_n = 0U;
}

bool sparc64_mem_block_end(struct sparc64_dbt_buf *b,
    const sparc64_mem_ops_t *mem, void *mc)
{
    sparc64_mem_block_t *tmp;
    bool ok;
    if (b == NULL) {
        return false;
    }
    if (acc_n == 0U) {
        return true;
    }
    if (mem == NULL || acc_n > SPARC64_DBT_MAX_SITES_PER_BLOCK ||
        b->words == NULL) {
        return false;
    }
    tmp = sparc64_mem_block_alloc(mem, mc, acc_base,
        (uint64_t)(uintptr_t)b->words, acc_n);
    if (tmp == NULL) {
        return false;
    }
    (void)memcpy(tmp->sites, acc_sites,
        (size_t)acc_n * sizeof(acc_sites[0]));
    ok = sparc64_mem_emit_tail(b, tmp, acc_edges, acc_n);
    sparc64_mem_block_free(tmp);
    acc_n = 0U;
    return ok;
}
