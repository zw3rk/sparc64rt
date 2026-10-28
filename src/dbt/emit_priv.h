/*
 * src/dbt/emit_priv.h — A64 code buffer, encoders, translator helpers (L2c)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Lane L2c owns this file (Phase 2 card). It holds the minimal AArch64
 * code buffer plus the integer instruction encoders used by emit_int.c
 * (adapted from ../sparc32rt/src/dbt/emit_priv.h and the A64 patterns in
 * ../sparc32rt/src/rt32/a64_emit.h), and the translator-local runtime
 * helpers invoked from JIT-emitted code via BLR.
 *
 * Helpers run in the translator process and cover exactly the operations
 * whose state or checks cannot be expressed inline: guest loads/stores/
 * atomics (alignment + ASI + big-endian + mem callbacks, via the shared
 * interp backend so parity holds by construction), SAVE/RESTORE (shared
 * interp window file), and 64-bit population count. Every helper touches
 * guest memory only through the sparc64_mem_ops_t callbacks captured in
 * the emit context. All helpers return SPARC64_EXIT_NONE on success and
 * SPARC64_EXIT_UNDEF when the dispatcher must replay the faulting
 * instruction with the interpreter (replay recomputes identical traps).
 *
 * Register discipline for emitted code (see emit_int.h): x19 holds the
 * sparc64_ctx_t pointer, x9-x14 are scratch, x15 carries the exit/resume
 * guest PC, w16 the exit reason. x18 is never used.
 */

#ifndef SPARC64RT_DBT_EMIT_PRIV_H
#define SPARC64RT_DBT_EMIT_PRIV_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "core/cpu.h"
#include "interp/interp.h"

/* Code buffer filled by the emitter; words storage is allocated and owned
 * by L2b, which also flips the pages W^X and clears the I-cache. */
typedef struct sparc64_dbt_buf {
    uint32_t *words;
    size_t count;
    size_t capacity;
    bool overflow;
    bool is_call;
    bool fp_fast_checked;
    bool fpsr_dirty;
} sparc64_dbt_buf_t;

/* No-instruction sentinel for reserve failure. */
#define SPARC64_DBT_NOPOS ((size_t)(-1))

static inline void sb_word(sparc64_dbt_buf_t *b, uint32_t w)
{
    if (b->count >= b->capacity) {
        b->overflow = true;
        return;
    }
    b->words[b->count++] = w;
}

/* Reserve one word for later patching; returns its index or NOPOS. */
static inline size_t sb_reserve(sparc64_dbt_buf_t *b, uint32_t placeholder)
{
    size_t at = b->count;
    if (b->count >= b->capacity) {
        b->overflow = true;
        return SPARC64_DBT_NOPOS;
    }
    b->words[b->count++] = placeholder;
    return at;
}

static inline void sb_patch(sparc64_dbt_buf_t *b, size_t at, uint32_t w)
{
    if (at == SPARC64_DBT_NOPOS || at >= b->count) {
        b->overflow = true;
        return;
    }
    b->words[at] = w;
}

/* ---- move-wide immediate ---------------------------------------------- */

static inline void sb_movz(sparc64_dbt_buf_t *b, bool sf, unsigned rd,
    unsigned hw, uint16_t imm)
{
    uint32_t base = sf ? UINT32_C(0xd2800000) : UINT32_C(0x52800000);
    sb_word(b, base | ((uint32_t)(hw & 3U) << 21) |
        ((uint32_t)imm << 5) | (rd & 31U));
}

static inline void sb_movk(sparc64_dbt_buf_t *b, bool sf, unsigned rd,
    unsigned hw, uint16_t imm)
{
    uint32_t base = sf ? UINT32_C(0xf2800000) : UINT32_C(0x72800000);
    sb_word(b, base | ((uint32_t)(hw & 3U) << 21) |
        ((uint32_t)imm << 5) | (rd & 31U));
}

/* Materialize any 32-bit constant (movz, plus movk when high bits set). */
static inline void sb_mov_imm32(sparc64_dbt_buf_t *b, unsigned rd,
    uint32_t v)
{
    sb_movz(b, false, rd, 0U, (uint16_t)(v & 0xffffU));
    if ((v >> 16) != 0U) {
        sb_movk(b, false, rd, 1U, (uint16_t)((v >> 16) & 0xffffU));
    }
}

/* Materialize any 64-bit constant (movz plus movk for nonzero halves). */
static inline void sb_mov_imm64(sparc64_dbt_buf_t *b, unsigned rd,
    uint64_t v)
{
    sb_movz(b, true, rd, 0U, (uint16_t)(v & 0xffffULL));
    if (((v >> 16) & 0xffffULL) != 0ULL) {
        sb_movk(b, true, rd, 1U, (uint16_t)((v >> 16) & 0xffffULL));
    }
    if (((v >> 32) & 0xffffULL) != 0ULL) {
        sb_movk(b, true, rd, 2U, (uint16_t)((v >> 32) & 0xffffULL));
    }
    if (((v >> 48) & 0xffffULL) != 0ULL) {
        sb_movk(b, true, rd, 3U, (uint16_t)((v >> 48) & 0xffffULL));
    }
}

/* ---- register moves ---------------------------------------------------- */

static inline void sb_mov_reg(sparc64_dbt_buf_t *b, bool sf, unsigned rd,
    unsigned rm)
{
    uint32_t base = sf ? UINT32_C(0xaa000000) : UINT32_C(0x2a000000);
    sb_word(b, base | ((rm & 31U) << 16) | (31U << 5) | (rd & 31U));
}

static inline void sb_mov_zr(sparc64_dbt_buf_t *b, bool sf, unsigned rd)
{
    sb_mov_reg(b, sf, rd, 31U);
}

/* ---- loads and stores (unsigned immediate offset) ---------------------- */

static inline void sb_ldst_imm(sparc64_dbt_buf_t *b, bool is_load, bool sf,
    unsigned rt, unsigned rn, uint32_t byte_off)
{
    uint32_t base;
    uint32_t unit = sf ? 8U : 4U;
    if ((byte_off % unit) != 0U || (byte_off / unit) > 4095U) {
        b->overflow = true;
        return;
    }
    if (sf) {
        base = is_load ? UINT32_C(0xf9400000) : UINT32_C(0xf9000000);
    } else {
        base = is_load ? UINT32_C(0xb9400000) : UINT32_C(0xb9000000);
    }
    sb_word(b, base | ((byte_off / unit) << 10) | ((rn & 31U) << 5) |
        (rt & 31U));
}

/* ---- data processing (register) ---------------------------------------- */

static inline void sb_alu_reg(sparc64_dbt_buf_t *b, uint32_t base, bool sf,
    bool set_flags, unsigned rd, unsigned rn, unsigned rm)
{
    uint32_t op = base | ((set_flags ? 1U : 0U) << 29);
    (void)sf;
    sb_word(b, op | ((rm & 31U) << 16) | ((rn & 31U) << 5) | (rd & 31U));
}

static inline void sb_add_reg(sparc64_dbt_buf_t *b, bool sf, bool set_flags,
    unsigned rd, unsigned rn, unsigned rm)
{
    sb_alu_reg(b, sf ? UINT32_C(0x8b000000) : UINT32_C(0x0b000000), sf,
        set_flags, rd, rn, rm);
}

static inline void sb_sub_reg(sparc64_dbt_buf_t *b, bool sf, bool set_flags,
    unsigned rd, unsigned rn, unsigned rm)
{
    sb_alu_reg(b, sf ? UINT32_C(0xcb000000) : UINT32_C(0x4b000000), sf,
        set_flags, rd, rn, rm);
}

static inline void sb_adc(sparc64_dbt_buf_t *b, bool set_flags, unsigned rd,
    unsigned rn, unsigned rm)
{
    sb_alu_reg(b, UINT32_C(0x9a000000), true, set_flags, rd, rn, rm);
}

static inline void sb_sbc(sparc64_dbt_buf_t *b, bool set_flags, unsigned rd,
    unsigned rn, unsigned rm)
{
    sb_alu_reg(b, UINT32_C(0xda000000), true, set_flags, rd, rn, rm);
}

static inline void sb_logic_reg(sparc64_dbt_buf_t *b, uint32_t base,
    unsigned rd, unsigned rn, unsigned rm)
{
    sb_word(b, base | ((rm & 31U) << 16) | ((rn & 31U) << 5) |
        (rd & 31U));
}

static inline void sb_orr_reg(sparc64_dbt_buf_t *b, bool sf, unsigned rd,
    unsigned rn, unsigned rm)
{
    sb_logic_reg(b, sf ? UINT32_C(0xaa000000) : UINT32_C(0x2a000000), rd,
        rn, rm);
}

static inline void sb_eor_reg(sparc64_dbt_buf_t *b, bool sf, unsigned rd,
    unsigned rn, unsigned rm)
{
    sb_logic_reg(b, sf ? UINT32_C(0xca000000) : UINT32_C(0x4a000000), rd,
        rn, rm);
}

static inline void sb_bic_reg(sparc64_dbt_buf_t *b, bool sf, unsigned rd,
    unsigned rn, unsigned rm)
{
    sb_logic_reg(b, sf ? UINT32_C(0x8a200000) : UINT32_C(0x0a200000), rd,
        rn, rm);
}

static inline void sb_orn_reg(sparc64_dbt_buf_t *b, bool sf, unsigned rd,
    unsigned rn, unsigned rm)
{
    sb_logic_reg(b, sf ? UINT32_C(0xaa200000) : UINT32_C(0x2a200000), rd,
        rn, rm);
}

/* ANDS (tst when rd is xzr). */
static inline void sb_ands_reg(sparc64_dbt_buf_t *b, bool sf, unsigned rd,
    unsigned rn, unsigned rm)
{
    sb_logic_reg(b, sf ? UINT32_C(0xea000000) : UINT32_C(0x6a000000), rd,
        rn, rm);
}

/* ANDS wzr, wRn, #3 (low-two-bit test for tagged ops). */
static inline void sb_tst_mask3_32(sparc64_dbt_buf_t *b, unsigned rn)
{
    sb_word(b, UINT32_C(0x72000000) | (1U << 10) | ((rn & 31U) << 5) |
        31U);
}

/* ---- add/sub immediate, compares --------------------------------------- */

static inline void sb_add_imm12(sparc64_dbt_buf_t *b, unsigned rd,
    unsigned rn, uint16_t imm12)
{
    sb_word(b, UINT32_C(0x91000000) | ((uint32_t)(imm12 & 0xfffU) << 10) |
        ((rn & 31U) << 5) | (rd & 31U));
}

/* SUBS xzr, xRn, #imm (64-bit compare against an immediate). */
static inline void sb_cmp_imm(sparc64_dbt_buf_t *b, bool sf, unsigned rn,
    uint16_t imm12)
{
    uint32_t base = sf ? UINT32_C(0xf1000000) : UINT32_C(0x71000000);
    sb_word(b, base | ((uint32_t)(imm12 & 0xfffU) << 10) |
        ((rn & 31U) << 5) | 31U);
}

/* SUBS wzr, wzr, wRm: host carry becomes NOT rm (borrow seed for SBC). */
static inline void sb_subs_zr_zr_rm(sparc64_dbt_buf_t *b, unsigned rm)
{
    sb_word(b, UINT32_C(0x6b000000) | ((rm & 31U) << 16) | (31U << 5) |
        31U);
}

/* SUBS xzr, xRn, xRm (64-bit register compare). */
static inline void sb_cmp_reg(sparc64_dbt_buf_t *b, unsigned rn,
    unsigned rm)
{
    sb_word(b, UINT32_C(0xeb000000) | ((rm & 31U) << 16) |
        ((rn & 31U) << 5) | 31U);
}

/* ---- bitfield moves ----------------------------------------------------- */

static inline void sb_ubfm(sparc64_dbt_buf_t *b, bool sf, unsigned rd,
    unsigned rn, unsigned immr, unsigned imms)
{
    uint32_t base = sf ? UINT32_C(0xd3400000) : UINT32_C(0x53000000);
    sb_word(b, base | ((immr & 63U) << 16) | ((imms & 63U) << 10) |
        ((rn & 31U) << 5) | (rd & 31U));
}

static inline void sb_sbfm64(sparc64_dbt_buf_t *b, unsigned rd, unsigned rn,
    unsigned immr, unsigned imms)
{
    sb_word(b, UINT32_C(0x93400000) | ((immr & 63U) << 16) |
        ((imms & 63U) << 10) | ((rn & 31U) << 5) | (rd & 31U));
}

/* Complex integer ALU through the reference backend: MUL/DIV/POPC,
 * tagged ops, and the multiply-step/divide-cc forms (Y threading, tag
 * traps, divide-by-zero, saturation). Packing: rs2_imm carries the rs2
 * index (register form) or the low 32 bits of the sign-extended
 * immediate. Returns SPARC64_EXIT_NONE or SPARC64_EXIT_UNDEF. */
static inline uint32_t s64_rt_alu(sparc64_ctx_t *ctx, uint32_t op3,
    uint32_t rs1, uint32_t rs2_imm, uint32_t is_imm, uint32_t rd,
    uint64_t pc)
{
    sparc64_dec_t d;
    sparc64_step_result_t r;
    d.raw = 0U;
    d.cls = SPARC64_ICLS_ALU;
    d.op = 2U;
    d.op3 = (uint8_t)(op3 & 0x3fU);
    d.rd = (uint8_t)(rd & 31U);
    d.rs1 = (uint8_t)(rs1 & 31U);
    d.rs2 = (uint8_t)(rs2_imm & 31U);
    d.cond = 0U;
    d.cc = 0U;
    d.asi = 0U;
    d.annul = 0U;
    d.pred = 0U;
    d.is_imm = (uint8_t)(is_imm & 1U);
    d.xbit = 0U;
    d.imm = (int64_t)(int32_t)(rs2_imm & 0xffffffffU);
    d.disp = 0;
    d.opf = 0U;
    d.uimm = 0U;
    r = sparc64_exec_alu(ctx, pc, &d);
    if (r.kind == SPARC64_STEP_CONTINUE) {
        return SPARC64_EXIT_NONE;
    }
    return SPARC64_EXIT_UNDEF;
}

/* ---- shifts (register count), multiply, divide -------------------------- */

static inline void sb_shift_reg(sparc64_dbt_buf_t *b, uint32_t base,
    bool sf, unsigned rd, unsigned rn, unsigned rm)
{
    uint32_t op = sf ? base : (base - UINT32_C(0x80000000));
    sb_word(b, op | ((rm & 31U) << 16) | ((rn & 31U) << 5) | (rd & 31U));
}

static inline void sb_lslv(sparc64_dbt_buf_t *b, bool sf, unsigned rd,
    unsigned rn, unsigned rm)
{
    sb_shift_reg(b, UINT32_C(0x9ac02000), sf, rd, rn, rm);
}

static inline void sb_lsrv(sparc64_dbt_buf_t *b, bool sf, unsigned rd,
    unsigned rn, unsigned rm)
{
    sb_shift_reg(b, UINT32_C(0x9ac02400), sf, rd, rn, rm);
}

static inline void sb_asrv(sparc64_dbt_buf_t *b, bool sf, unsigned rd,
    unsigned rn, unsigned rm)
{
    sb_shift_reg(b, UINT32_C(0x9ac02800), sf, rd, rn, rm);
}

static inline void sb_mul(sparc64_dbt_buf_t *b, unsigned rd, unsigned rn,
    unsigned rm)
{
    sb_word(b, UINT32_C(0x9b007c00) | ((rm & 31U) << 16) |
        ((rn & 31U) << 5) | (rd & 31U));
}

static inline void sb_udiv(sparc64_dbt_buf_t *b, unsigned rd, unsigned rn,
    unsigned rm)
{
    sb_word(b, UINT32_C(0x9ac00800) | ((rm & 31U) << 16) |
        ((rn & 31U) << 5) | (rd & 31U));
}

static inline void sb_sdiv(sparc64_dbt_buf_t *b, unsigned rd, unsigned rn,
    unsigned rm)
{
    sb_word(b, UINT32_C(0x9ac00c00) | ((rm & 31U) << 16) |
        ((rn & 31U) << 5) | (rd & 31U));
}

/* ---- flags access ------------------------------------------------------- */

static inline void sb_mrs_nzcv(sparc64_dbt_buf_t *b, unsigned rt)
{
    sb_word(b, UINT32_C(0xd53b4200) | (rt & 31U));
}

static inline void sb_msr_nzcv(sparc64_dbt_buf_t *b, unsigned rt)
{
    sb_word(b, UINT32_C(0xd51b4200) | (rt & 31U));
}

/* CSET wRd, cond (zero-extending boolean from host flags). */
static inline void sb_cset(sparc64_dbt_buf_t *b, unsigned rd,
    unsigned cond)
{
    sb_word(b, UINT32_C(0x1a9f07e0) |
        (((cond ^ 1U) & 15U) << 12) | (rd & 31U));
}

/* ---- branches, calls, returns ------------------------------------------- */

static inline size_t sb_cbz_placeholder(sparc64_dbt_buf_t *b, bool sf,
    bool nonzero, unsigned rt)
{
    uint32_t base;
    if (sf) {
        base = nonzero ? UINT32_C(0xb5000000) : UINT32_C(0xb4000000);
    } else {
        base = nonzero ? UINT32_C(0x35000000) : UINT32_C(0x34000000);
    }
    return sb_reserve(b, base | (rt & 31U));
}

static inline void sb_patch_cb(sparc64_dbt_buf_t *b, size_t at,
    size_t target)
{
    uint32_t w;
    int64_t delta;
    if (at == SPARC64_DBT_NOPOS || at >= b->count) {
        b->overflow = true;
        return;
    }
    /* at/target are word indices; the branch offset is delta words. */
    delta = (int64_t)target - (int64_t)at;
    if (delta < -(1L << 18) || delta >= (1L << 18)) {
        b->overflow = true;
        return;
    }
    w = b->words[at];
    w |= (uint32_t)(((uint64_t)(delta & 0x7ffffLL)) << 5);
    sb_patch(b, at, w);
}

static inline size_t sb_b_cond_placeholder(sparc64_dbt_buf_t *b,
    unsigned cond)
{
    return sb_reserve(b, UINT32_C(0x54000000) | (cond & 15U));
}

static inline void sb_patch_b_cond(sparc64_dbt_buf_t *b, size_t at,
    unsigned cond, size_t target)
{
    int64_t delta;
    if (at == SPARC64_DBT_NOPOS || at >= b->count) {
        b->overflow = true;
        return;
    }
    /* at/target are word indices; the branch offset is delta words. */
    delta = (int64_t)target - (int64_t)at;
    if (delta < -(1L << 18) || delta >= (1L << 18)) {
        b->overflow = true;
        return;
    }
    sb_patch(b, at, UINT32_C(0x54000000) |
        (uint32_t)(((uint64_t)(delta & 0x7ffffLL)) << 5) |
        (cond & 15U));
}

static inline size_t sb_b_placeholder(sparc64_dbt_buf_t *b)
{
    return sb_reserve(b, UINT32_C(0x14000000));
}

static inline void sb_patch_b(sparc64_dbt_buf_t *b, size_t at,
    size_t target)
{
    int64_t delta;
    if (at == SPARC64_DBT_NOPOS || at >= b->count) {
        b->overflow = true;
        return;
    }
    /* at/target are word indices; the branch offset is delta words. */
    delta = (int64_t)target - (int64_t)at;
    if (delta < -(1L << 25) || delta >= (1L << 25)) {
        b->overflow = true;
        return;
    }
    sb_patch(b, at, UINT32_C(0x14000000) |
        (uint32_t)((uint64_t)(delta & 0x3ffffffLL)));
}

static inline void sb_blr(sparc64_dbt_buf_t *b, unsigned rn)
{
    sb_word(b, UINT32_C(0xd63f0000) | ((rn & 31U) << 5));
}

static inline void sb_ret(sparc64_dbt_buf_t *b)
{
    sb_word(b, UINT32_C(0xd65f03c0));
}

static inline void sb_str_x30_pre(sparc64_dbt_buf_t *b)
{
    sb_word(b, UINT32_C(0xf81f0ffe));
}

static inline void sb_ldr_x30_post(sparc64_dbt_buf_t *b)
{
    sb_word(b, UINT32_C(0xf84107fe));
}

/* Parameterized 16-byte host-stack spill across helper calls and delay
 * slots (same encodings as the x30 pair above; sp stays 16B-aligned).
 * H3: lets JMPL snapshot a register-indirect target before a delay
 * slot that may rotate windows or reuse the scratch set. */
static inline void sb_push64(sparc64_dbt_buf_t *b, unsigned rt)
{
    sb_word(b, UINT32_C(0xf81f0fe0) | (rt & 31U));
}

static inline void sb_pop64(sparc64_dbt_buf_t *b, unsigned rt)
{
    sb_word(b, UINT32_C(0xf84107e0) | (rt & 31U));
}

/* ---- translator-local runtime helpers ------------------------------------
 * Static so only the including emitter (emit_int.c) emits references;
 * JIT code resolves their addresses at emit time via BLR. All helpers
 * return SPARC64_EXIT_NONE on success, SPARC64_EXIT_UNDEF when the
 * dispatcher must replay the faulting instruction with the interpreter.
 * Guest memory is touched only through the mem callbacks.
 */

static inline uint64_t s64_rt_popc(uint64_t v)
{
    uint64_t n = UINT64_C(0);
    while (v != UINT64_C(0)) {
        n += v & UINT64_C(1);
        v >>= 1;
    }
    return n;
}

/* Memory op: packA carries op3 | rd<<8 | rs1<<16 | rs2<<24 | is_imm<<29,
 * raw is the instruction word (trap tval), packB carries the low 32 bits
 * of the sign-extended immediate plus the ASI at bits 32..39. */
static inline uint32_t s64_rt_mem(sparc64_ctx_t *ctx,
    const sparc64_mem_ops_t *mem, void *mc, uint64_t pc, uint32_t pack_a,
    uint32_t raw, uint64_t pack_b)
{
    sparc64_dec_t d;
    sparc64_step_result_t r;
    d.raw = raw;
    d.cls = SPARC64_ICLS_ILLEGAL;
    d.op = 3U;
    d.op3 = (uint8_t)(pack_a & 0x3fU);
    d.rd = (uint8_t)((pack_a >> 8) & 31U);
    d.rs1 = (uint8_t)((pack_a >> 16) & 31U);
    d.rs2 = (uint8_t)((pack_a >> 24) & 31U);
    d.cond = 0U;
    d.cc = 0U;
    d.asi = (uint8_t)((pack_b >> 32) & 0xffU);
    d.annul = 0U;
    d.pred = 0U;
    d.is_imm = (uint8_t)((pack_a >> 29) & 1U);
    d.xbit = 0U;
    d.imm = (int64_t)(int32_t)(pack_b & 0xffffffffULL);
    d.disp = 0;
    d.opf = 0U;
    d.uimm = 0U;
    switch (d.op3) {
    case SPARC64_OP3_LDUW:
    case SPARC64_OP3_LDUB:
    case SPARC64_OP3_LDUH:
    case SPARC64_OP3_LDD:
    case SPARC64_OP3_LDSW:
    case SPARC64_OP3_LDSB:
    case SPARC64_OP3_LDSH:
    case SPARC64_OP3_LDX:
    case SPARC64_OP3_LDA:
    case SPARC64_OP3_LDUBA:
    case SPARC64_OP3_LDUHA:
    case SPARC64_OP3_LDDA:
    case SPARC64_OP3_LDSWA:
    case SPARC64_OP3_LDSBA:
    case SPARC64_OP3_LDSHA:
    case SPARC64_OP3_LDXA:
    case SPARC64_OP3_LDFSR:
        d.cls = SPARC64_ICLS_LOAD;
        r = sparc64_exec_load(ctx, mem, mc, pc, &d);
        break;
    case SPARC64_OP3_STW:
    case SPARC64_OP3_STB:
    case SPARC64_OP3_STH:
    case SPARC64_OP3_STD:
    case SPARC64_OP3_STX:
    case SPARC64_OP3_STA:
    case SPARC64_OP3_STBA:
    case SPARC64_OP3_STHA:
    case SPARC64_OP3_STDA:
    case SPARC64_OP3_STXA:
    case SPARC64_OP3_STFSR:
        d.cls = SPARC64_ICLS_STORE;
        r = sparc64_exec_store(ctx, mem, mc, pc, &d);
        break;
    case SPARC64_OP3_LDSTUB:
    case SPARC64_OP3_LDSTUBA:
        d.cls = SPARC64_ICLS_LDSTUB;
        r = sparc64_exec_atomic(ctx, mem, mc, pc, &d);
        break;
    case SPARC64_OP3_SWAP:
    case SPARC64_OP3_SWAPA:
        d.cls = SPARC64_ICLS_SWAP;
        r = sparc64_exec_atomic(ctx, mem, mc, pc, &d);
        break;
    default:
        d.cls = SPARC64_ICLS_ATOMIC;
        r = sparc64_exec_atomic(ctx, mem, mc, pc, &d);
        break;
    }
    if (r.kind == SPARC64_STEP_CONTINUE) {
        return SPARC64_EXIT_NONE;
    }
    return SPARC64_EXIT_UNDEF;
}

/* Window op: rd_save carries rd | save<<8; sum is the SAVE/RESTORE operand.
 * The shared interp window file performs spill/fill through mem. */
static inline uint32_t s64_rt_win(sparc64_ctx_t *ctx,
    const sparc64_mem_ops_t *mem, void *mc, uint64_t sum, uint32_t rd_save,
    uint64_t pc)
{
    sparc64_step_result_t res;
    unsigned rd = rd_save & 31U;
    bool is_save = ((rd_save >> 8) & 1U) != 0U;
    if (is_save) {
        if (!sparc64_win_save(ctx, mem, mc, sum, rd, &res, pc)) {
            return SPARC64_EXIT_UNDEF;
        }
    } else {
        if (!sparc64_win_restore(ctx, mem, mc, sum, rd, &res, pc)) {
            return SPARC64_EXIT_UNDEF;
        }
    }
    return SPARC64_EXIT_NONE;
}

/* ---- emitter state + mechanical layer ----------------------------------
 * Scratch registers, ctx offsets, operand loaders, flag/nibble
 * builders, exits, and helper-call sequences shared by the
 * per-class emitters in emit_int.c. x18 is never used.
 */

/* Scratch allocation inside one emitted instruction. */
#define ECTX 19u /* ctx pointer (set by L2b block prologue) */
#define ES0 9u
#define ES1 10u
#define ES2 11u
#define ES3 12u
#define ES4 13u
#define ES5 14u
#define EPC 15u /* exit guest PC */
#define ERSN 16u /* exit reason */

/* Guest ctx field offsets without a cpu.h macro. */
#define E_OFF_Y 0x110U
#define E_OFF_GSR 0x128U
#define E_OFF_FPRS 0x130U
#define E_OFF_ASI 0x138U
#define E_OFF_EXIT_ARG 0x274U

/* Per-instruction emit context (filled by L2b, consumed by this unit). */
typedef struct sparc64_emit_ctx {
    sparc64_dbt_buf_t *buf;      /* Code buffer; owned and managed by L2b. */
    uint64_t pc;                 /* Guest address of the insn being emitted. */
    uint64_t fault_pc;           /* Guest PC reported in x15 on fault exits. */
    const sparc64_dec_t *delay;  /* CTI delay-slot insn, or NULL. */
    const sparc64_mem_ops_t *mem; /* Guest memory callbacks (never NULL
                                   * for LOAD/STORE/atomics/SAVE/RESTORE). */
    void *mc;                    /* Callback context for mem. */
} sparc64_emit_ctx_t;

/* ---- tiny emit utilities ---------------------------------------------- */

/* Load guest register rs into xdst (r0 reads as 0 via xzr). */
static inline void e_ld64(sparc64_dbt_buf_t *b, unsigned xdst, unsigned rs)
{
    if ((rs & 31U) == 0U) {
        sb_mov_zr(b, true, xdst);
        return;
    }
    sb_ldst_imm(b, true, true, xdst, ECTX, (rs & 31U) * 8U);
}

/* Store xsrc to guest register rd (writes to r0 are dropped). */
static inline void e_st64(sparc64_dbt_buf_t *b, unsigned rd, unsigned xsrc)
{
    if ((rd & 31U) == 0U) {
        return;
    }
    sb_ldst_imm(b, false, true, xsrc, ECTX, (rd & 31U) * 8U);
}

/* Second ALU operand (sign-extended simm13 or register) into xdst. */
static inline void e_src2(sparc64_dbt_buf_t *b, unsigned xdst,
    const sparc64_dec_t *d)
{
    if (d->is_imm != 0U) {
        sb_mov_imm64(b, xdst, (uint64_t)d->imm);
    } else {
        e_ld64(b, xdst, d->rs2);
    }
}

/* 32-bit logical shift left by an immediate (ubfm alias). */
static inline void e_lsl_imm32(sparc64_dbt_buf_t *b, unsigned rd, unsigned rn,
    unsigned sh)
{
    sb_ubfm(b, false, rd, rn, (32U - sh) & 31U, (31U - sh) & 31U);
}


/* Build an NZCV word in wF from the 4-bit guest nibble in wN and load
 * it into the host flags. Clobbers wT; the three registers must be
 * distinct (wF is written before the last nibble bit is read). N, Z, V
 * map straight across, but the nibble C bit is a borrow (1 iff a<b)
 * while AArch64 C is a carry, so bit 0 is inverted into NZCV bit 29.
 * The e_a64_cond table matches this carry convention. */
static inline void e_nib_to_flags(sparc64_dbt_buf_t *b, unsigned wF, unsigned wN,
    unsigned wT)
{
    sb_ubfm(b, false, wT, wN, 3U, 3U);
    e_lsl_imm32(b, wF, wT, 31U);
    sb_ubfm(b, false, wT, wN, 2U, 2U);
    e_lsl_imm32(b, wT, wT, 30U);
    sb_orr_reg(b, false, wF, wF, wT);
    sb_ubfm(b, false, wT, wN, 1U, 1U);
    e_lsl_imm32(b, wT, wT, 28U);
    sb_orr_reg(b, false, wF, wF, wT);
    sb_ubfm(b, false, wT, wN, 0U, 0U);
    sb_cmp_imm(b, false, wT, 0U);
    sb_cset(b, wT, 0U);
    e_lsl_imm32(b, wT, wT, 29U);
    sb_orr_reg(b, false, wF, wF, wT);
    sb_msr_nzcv(b, wF);
}

/* Capture the host NZCV set by the previous flags-setting op into the
 * guest nibble layout (N=3,Z=2,V=1,C=0) in wI. Clobbers xT. SPARC C is
 * the borrow (E02): for SUB the host carry is inverted, so the C bit is
 * taken directly from the CC condition (1 iff borrow) instead. */
static inline void e_host_to_nibble(sparc64_dbt_buf_t *b, unsigned wI,
    unsigned xT, bool is_sub)
{
    sb_mrs_nzcv(b, xT);
    sb_ubfm(b, false, wI, xT, 31U, 31U);
    e_lsl_imm32(b, wI, wI, 3U);
    sb_ubfm(b, false, xT, xT, 30U, 30U);
    e_lsl_imm32(b, xT, xT, 2U);
    sb_orr_reg(b, false, wI, wI, xT);
    sb_mrs_nzcv(b, xT);
    sb_ubfm(b, false, xT, xT, 28U, 28U);
    e_lsl_imm32(b, xT, xT, 1U);
    sb_orr_reg(b, false, wI, wI, xT);
    if (is_sub) {
        sb_cset(b, xT, 3U);
    } else {
        sb_mrs_nzcv(b, xT);
        sb_ubfm(b, false, xT, xT, 29U, 29U);
    }
    sb_orr_reg(b, false, wI, wI, xT);
}

/* Commit icc (wI) and xcc (wX) nibbles into ctx->ccr, preserving the
 * upper bits. Clobbers xC. */
static inline void e_merge_cc(sparc64_dbt_buf_t *b, unsigned wI, unsigned wX,
    unsigned xC)
{
    sb_ldst_imm(b, true, true, xC, ECTX, SPARC64_CTX_CCR_OFFSET);
    sb_ubfm(b, true, xC, xC, 8U, 63U);
    sb_ubfm(b, true, xC, xC, 56U, 55U);
    e_lsl_imm32(b, wX, wX, 4U);
    sb_orr_reg(b, true, xC, xC, wX);
    sb_orr_reg(b, true, xC, xC, wI);
    sb_ldst_imm(b, false, true, xC, ECTX, SPARC64_CTX_CCR_OFFSET);
}


/* ---- exits ------------------------------------------------------------ */

/* Leave the fragment: x15 = guest PC, w16 = reason, ret. */
static inline void e_exit_imm(sparc64_dbt_buf_t *b, uint64_t pc, uint32_t reason)
{
    sb_mov_imm64(b, EPC, pc);
    sb_mov_imm32(b, ERSN, reason);
    sb_ret(b);
}

/* Leave the fragment with the reason already in w0 (helper fault path):
 * x15 = fault_pc, w16 = w0, ret. */
static inline void e_exit_reason_reg(sparc64_dbt_buf_t *b, uint64_t fault_pc)
{
    sb_mov_imm64(b, EPC, fault_pc);
    sb_mov_reg(b, true, ERSN, 0U);
    sb_ret(b);
}

/* Inline fault exit at the current position (traps replayed via interp):
 * x15 = fault_pc, w16 = EXIT_UNDEF, ret. */
static inline void e_fault_here(sparc64_dbt_buf_t *b, uint64_t fault_pc)
{
    sb_mov_imm64(b, EPC, fault_pc);
    sb_mov_imm32(b, ERSN, SPARC64_EXIT_UNDEF);
    sb_ret(b);
}

/* Resolve a faultable-call patch: on w0 != 0 exit with the helper's
 * reason at fault_pc; the success path skips over that exit. */

/* ---- helper calls ------------------------------------------------------ */

/* BLR to a translator-local helper; x0-x7 must already hold its args.
 * Returns the cbnz patch index for the fault path (w0 != 0). */
static inline size_t e_call_faultable(sparc64_dbt_buf_t *b, uint64_t addr)
{
    size_t p;
    sb_str_x30_pre(b);
    sb_mov_imm64(b, ES2, addr);
    sb_blr(b, ES2);
    sb_ldr_x30_post(b);
    p = sb_cbz_placeholder(b, false, true, 0U);
    return p;
}

static inline void e_resolve_fault(sparc64_emit_ctx_t *ec, size_t p)
{
    size_t p_end = sb_b_placeholder(ec->buf);
    sb_patch_cb(ec->buf, p, ec->buf->count);
    e_exit_reason_reg(ec->buf, ec->fault_pc);
    sb_patch_b(ec->buf, p_end, ec->buf->count);
}

/* Set up x0 = ctx for a helper call. */
static inline void e_arg_ctx(sparc64_dbt_buf_t *b)
{
    sb_mov_reg(b, true, 0U, ECTX);
}

/* Memory/backend call: x0=ctx x1=mem x2=mc x3=pc x4=packA x5=raw
 * x6=packB, then BLR s64_rt_mem with the UNDEF fault path. */
static inline size_t e_call_mem(sparc64_emit_ctx_t *ec, const sparc64_dec_t *d)
{
    sparc64_dbt_buf_t *b = ec->buf;
    uint32_t pack_a = (d->op3 & 0x3fU) | ((d->rd & 31U) << 8) |
        ((d->rs1 & 31U) << 16) | ((d->rs2 & 31U) << 24) |
        ((d->is_imm & 1U) << 29);
    uint64_t pack_b = ((uint64_t)(uint32_t)d->imm) |
        ((uint64_t)d->asi << 32);
    e_arg_ctx(b);
    sb_mov_imm64(b, 1U, (uint64_t)(uintptr_t)ec->mem);
    sb_mov_imm64(b, 2U, (uint64_t)(uintptr_t)ec->mc);
    sb_mov_imm64(b, 3U, ec->pc);
    sb_mov_imm32(b, 4U, pack_a);
    sb_mov_imm32(b, 5U, d->raw);
    sb_mov_imm64(b, 6U, pack_b);
    return e_call_faultable(b, (uint64_t)(uintptr_t)&s64_rt_mem);
}

/* Window call: x0=ctx x1=mem x2=mc x3=sum x4=rd|save<<8 x5=pc.
 * The SAVE/RESTORE sum arrives in ES0. */
static inline size_t e_call_win(sparc64_emit_ctx_t *ec, unsigned rd,
    bool is_save)
{
    sparc64_dbt_buf_t *b = ec->buf;
    e_arg_ctx(b);
    sb_mov_imm64(b, 1U, (uint64_t)(uintptr_t)ec->mem);
    sb_mov_imm64(b, 2U, (uint64_t)(uintptr_t)ec->mc);
    sb_mov_reg(b, true, 3U, ES0);
    sb_mov_imm32(b, 4U, (rd & 31U) | (is_save ? 0x100U : 0U));
    sb_mov_imm64(b, 5U, ec->pc);
    return e_call_faultable(b, (uint64_t)(uintptr_t)&s64_rt_win);
}

/* Seed the host carry from the icc.C bit in wM (0/1) for ADC: C = bit. */
static inline void e_seed_carry_add(sparc64_dbt_buf_t *b, unsigned wM)
{
    sb_cmp_imm(b, false, wM, 1U);
}

/* Seed the host carry from the icc.C bit in wM (0/1) for SBC: C = !bit. */
static inline void e_seed_carry_sub(sparc64_dbt_buf_t *b, unsigned wM)
{
    sb_subs_zr_zr_rm(b, wM);
}

/* Load icc.C (bit 0 of ccr) into wM as 0/1. */
static inline void e_load_carry(sparc64_dbt_buf_t *b, unsigned wM)
{
    sb_ldst_imm(b, true, true, wM, ECTX, SPARC64_CTX_CCR_OFFSET);
    sb_ubfm(b, false, wM, wM, 0U, 0U);
}

#endif /* SPARC64RT_DBT_EMIT_PRIV_H */
