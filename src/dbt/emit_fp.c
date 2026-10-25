/*
 * src/dbt/emit_fp.c — AArch64 FP/NEON instruction emitter (Phase 3, L3b)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Lowers the Phase 3 FP subset to scalar AArch64 FP (contract in
 * emit_fp.h, x19 = ctx, never x18). Lowered: FPOP1 single/double arith
 * (FADD/FSUB/FMUL/FDIV) + FSQRT + moves/neg/abs, F{S,D}TO{I,X} +
 * F{I,X}TO{S,D} + FSTOD/FDTOS, plain FP loads/stores (LDF/STF/LDDF/
 * STDF), all with the specified FSR.RD == 0 guard where rounding
 * matters. Everything else (quad, FSMULD/FDMULQ, VIS/FALIGNDATA, block
 * ASIs, FCMP*, FMOVcc/FMOVr, LDFSR, FBR) returns false for pristine
 * interpreter fallback.
 *
 * FPOP operand fields (GAS+objdump ground truth): binary arith reads
 * rs1 (bits 18:14, decoded) + rs2 (bits 4:0, re-read from raw: the
 * classifier leaves d->rs2 zero for FPOP); all unary FPOP1 ops (FSQRT,
 * moves, neg/abs, FP-source conversions) read the rs2 field;
 * integer-source conversions read the integer register named by rs2;
 * F{S,D}TO{I,X} write the integer register named by rd. AArch64 scalar
 * FP words below were verified word-for-word with the cross-assembler.
 */

#include "dbt/emit_fp.h"

#include <stdint.h>

#include "dbt/emit_priv.h"

/* AArch64 scalar FP bases (Rd/Rn/Rm zero; OR the register fields in).
 * Verified with aarch64-unknown-linux-musl-gcc -c + objdump. */
#define FP_FADD_S UINT32_C(0x1e202800)
#define FP_FSUB_S UINT32_C(0x1e203800)
#define FP_FMUL_S UINT32_C(0x1e200800)
#define FP_FDIV_S UINT32_C(0x1e201800)
#define FP_FADD_D UINT32_C(0x1e602800)
#define FP_FSUB_D UINT32_C(0x1e603800)
#define FP_FMUL_D UINT32_C(0x1e600800)
#define FP_FDIV_D UINT32_C(0x1e601800)
#define FP_FSQRT_S UINT32_C(0x1e21c000)
#define FP_FSQRT_D UINT32_C(0x1e61c000)
#define FP_FMOV_S UINT32_C(0x1e204000)
#define FP_FMOV_D UINT32_C(0x1e604000)
#define FP_FNEG_S UINT32_C(0x1e214000)
#define FP_FNEG_D UINT32_C(0x1e614000)
#define FP_FABS_S UINT32_C(0x1e20c000)
#define FP_FABS_D UINT32_C(0x1e60c000)
#define FP_FCVTNS_W_S UINT32_C(0x1e200000)
#define FP_FCVTNS_X_S UINT32_C(0x9e200000)
#define FP_FCVTNS_W_D UINT32_C(0x1e600000)
#define FP_FCVTNS_X_D UINT32_C(0x9e600000)
#define FP_SCVTF_S_W UINT32_C(0x1e220000)
#define FP_SCVTF_D_W UINT32_C(0x1e620000)
#define FP_SCVTF_S_X UINT32_C(0x9e220000)
#define FP_SCVTF_D_X UINT32_C(0x9e620000)
#define FP_FCVT_D_S UINT32_C(0x1e22c000)
#define FP_FCVT_S_D UINT32_C(0x1e624000)
#define FP_FMOV_X_D UINT32_C(0x9e660000)

/* Guest FP file base (ctx + 0x140); FSR at ctx + 0x120. */
#define FP_FILE_OFF 0x140U
#define FP_FSR_OFF 0x120U

/* Scalar FP data-processing with two sources: base | Rd | Rn<<5 | Rm<<16
 * (FADD/FSUB/FMUL/FDIV). Single-source ops (FSQRT/FMOV/FNEG/FABS/FCVT*)
 * use the same layout with the Rm field zero in the base. */
static inline void fp_alu(sparc64_dbt_buf_t *b, uint32_t base, unsigned vd,
    unsigned vn, unsigned vm)
{
    sb_word(b, base | (vd & 31U) | ((vn & 31U) << 5) |
        ((vm & 31U) << 16));
}

/* LDR St,[x19,#off] / STR St,[x19,#off]: single f[idx]. */
static inline void fp_ld_s(sparc64_dbt_buf_t *b, unsigned vt, unsigned idx)
{
    uint32_t off = FP_FILE_OFF + (idx & 31U) * 4U;
    sb_word(b, UINT32_C(0xbd400000) | (vt & 31U) | (19U << 5) |
        ((off / 4U) << 10));
}

static inline void fp_st_s(sparc64_dbt_buf_t *b, unsigned vt, unsigned idx)
{
    uint32_t off = FP_FILE_OFF + (idx & 31U) * 4U;
    sb_word(b, UINT32_C(0xbd000000) | (vt & 31U) | (19U << 5) |
        ((off / 4U) << 10));
}

/* LDR Dt,[x19,#off] / STR Dt,[x19,#off]: double d[di]. */
static inline void fp_ld_d(sparc64_dbt_buf_t *b, unsigned vt, unsigned di)
{
    uint32_t off = FP_FILE_OFF + (di & 31U) * 8U;
    sb_word(b, UINT32_C(0xfd400000) | (vt & 31U) | (19U << 5) |
        ((off / 8U) << 10));
}

static inline void fp_st_d(sparc64_dbt_buf_t *b, unsigned vt, unsigned di)
{
    uint32_t off = FP_FILE_OFF + (di & 31U) * 8U;
    sb_word(b, UINT32_C(0xfd000000) | (vt & 31U) | (19U << 5) |
        ((off / 8U) << 10));
}

/* Rounding guard prologue: FSR.RD (bits 31:30) must be 0
 * (round-to-nearest, the host FPCR default); nonzero exits UNDEF so the
 * dispatcher replays the instruction with the reference interpreter. */
static bool fp_guard_rd0(sparc64_emit_ctx_t *ec)
{
    sparc64_dbt_buf_t *b = ec->buf;
    size_t p_ok;
    sb_ldst_imm(b, true, true, ES3, ECTX, FP_FSR_OFF);
    sb_ubfm(b, true, ES3, ES3, 30U, 31U);
    p_ok = sb_cbz_placeholder(b, true, false, ES3);
    if (p_ok == SPARC64_DBT_NOPOS) {
        return false;
    }
    e_fault_here(b, ec->fault_pc);
    sb_patch_cb(b, p_ok, b->count);
    return !b->overflow;
}

/* Binary arith (FADD/FSUB/FMUL/FDIV, single or double). */
static bool fp_emit_arith(sparc64_emit_ctx_t *ec, uint32_t base,
    const sparc64_dec_t *d, bool is_double)
{
    sparc64_dbt_buf_t *b = ec->buf;
    unsigned rs1 = d->rs1 & 31U;
    unsigned rs2 = d->raw & 31U;
    unsigned rd = d->rd & 31U;
    if (!fp_guard_rd0(ec)) {
        return false;
    }
    if (is_double) {
        fp_ld_d(b, 0U, (rs1 >> 1U) & 31U);
        fp_ld_d(b, 1U, (rs2 >> 1U) & 31U);
        fp_alu(b, base, 2U, 0U, 1U);
        fp_st_d(b, 2U, (rd >> 1U) & 31U);
    } else {
        fp_ld_s(b, 0U, rs1);
        fp_ld_s(b, 1U, rs2);
        fp_alu(b, base, 2U, 0U, 1U);
        fp_st_s(b, 2U, rd);
    }
    return !b->overflow;
}

/* FSQRT (single or double); the source is the rs2 field (ground truth:
 * `fsqrts %f6, %f7` encodes rs1 = 0, rs2 = 6). */
static bool fp_emit_sqrt(sparc64_emit_ctx_t *ec, uint32_t base,
    const sparc64_dec_t *d, bool is_double)
{
    sparc64_dbt_buf_t *b = ec->buf;
    unsigned rs2 = d->raw & 31U;
    unsigned rd = d->rd & 31U;
    if (!fp_guard_rd0(ec)) {
        return false;
    }
    if (is_double) {
        fp_ld_d(b, 0U, (rs2 >> 1U) & 31U);
        fp_alu(b, base, 1U, 0U, 0U);
        fp_st_d(b, 1U, (rd >> 1U) & 31U);
    } else {
        fp_ld_s(b, 0U, rs2);
        fp_alu(b, base, 1U, 0U, 0U);
        fp_st_s(b, 1U, rd);
    }
    return !b->overflow;
}

/* FMOV (single or double); the source is rs2. Moves need no guard. */
static bool fp_emit_mov(sparc64_emit_ctx_t *ec, const sparc64_dec_t *d,
    bool is_double)
{
    sparc64_dbt_buf_t *b = ec->buf;
    unsigned rs2 = d->raw & 31U;
    unsigned rd = d->rd & 31U;
    if (is_double) {
        fp_ld_d(b, 0U, (rs2 >> 1U) & 31U);
        fp_st_d(b, 0U, (rd >> 1U) & 31U);
    } else {
        fp_ld_s(b, 0U, rs2);
        fp_st_s(b, 0U, rd);
    }
    return !b->overflow;
}

/* FNEG/FABS (single or double); the source is rs2. No guard. */
static bool fp_emit_unary(sparc64_emit_ctx_t *ec, uint32_t base,
    const sparc64_dec_t *d, bool is_double)
{
    sparc64_dbt_buf_t *b = ec->buf;
    unsigned rs2 = d->raw & 31U;
    unsigned rd = d->rd & 31U;
    if (is_double) {
        fp_ld_d(b, 0U, (rs2 >> 1U) & 31U);
        fp_alu(b, base, 1U, 0U, 0U);
        fp_st_d(b, 1U, (rd >> 1U) & 31U);
    } else {
        fp_ld_s(b, 0U, rs2);
        fp_alu(b, base, 1U, 0U, 0U);
        fp_st_s(b, 1U, rd);
    }
    return !b->overflow;
}

/* F{S,D}TO{I,X}: FP source, integer rd (sign-extended 32-bit results,
 * matching the oracle's `ld`-style sign extension). SPARC conversions
 * round per FSR.RD, so this uses FCVTNS (host FPCR rounding, reset RN
 * and untouched anywhere in tree) under the RD == 0 guard prologue;
 * a fixed toward-zero FCVTZS would be wrong for RD = RN. */
static bool fp_emit_f2i(sparc64_emit_ctx_t *ec, uint32_t base,
    const sparc64_dec_t *d, bool from_double, bool to_64)
{
    sparc64_dbt_buf_t *b = ec->buf;
    unsigned rs2 = d->raw & 31U;
    if (!fp_guard_rd0(ec)) {
        return false;
    }
    if (from_double) {
        fp_ld_d(b, 0U, (rs2 >> 1U) & 31U);
    } else {
        fp_ld_s(b, 0U, rs2);
    }
    fp_alu(b, base, ES1, 0U, 0U);
    if (!to_64) {
        sb_sbfm64(b, ES1, ES1, 0U, 31U);
    }
    e_st64(b, d->rd & 31U, ES1);
    return !b->overflow;
}

/* FITOS/FITOD: 32-bit integer rs2 source, FP rd. (FXTOS/FXTOD take
 * their 64-bit source from a double FP register: fp_emit_x2f.) */
static bool fp_emit_i2f(sparc64_emit_ctx_t *ec, uint32_t base,
    const sparc64_dec_t *d, bool to_double)
{
    sparc64_dbt_buf_t *b = ec->buf;
    unsigned rs2 = d->raw & 31U;
    unsigned rd = d->rd & 31U;
    if (!fp_guard_rd0(ec)) {
        return false;
    }
    e_ld64(b, ES0, rs2);
    fp_alu(b, base, 0U, ES0, 0U);
    if (to_double) {
        fp_st_d(b, 0U, (rd >> 1U) & 31U);
    } else {
        fp_st_s(b, 0U, rd);
    }
    return !b->overflow;
}

/* FXTOS/FXTOD: the 64-bit integer source lives in double d[(rs2>>1)&31]
 * (FP file), moved to an integer register before SCVTF. */
static bool fp_emit_x2f(sparc64_emit_ctx_t *ec, uint32_t base,
    const sparc64_dec_t *d, bool to_double)
{
    sparc64_dbt_buf_t *b = ec->buf;
    unsigned rs2 = d->raw & 31U;
    unsigned rd = d->rd & 31U;
    if (!fp_guard_rd0(ec)) {
        return false;
    }
    fp_ld_d(b, 0U, (rs2 >> 1U) & 31U);
    fp_alu(b, FP_FMOV_X_D, ES0, 0U, 0U);
    fp_alu(b, base, 0U, ES0, 0U);
    if (to_double) {
        fp_st_d(b, 0U, (rd >> 1U) & 31U);
    } else {
        fp_st_s(b, 0U, rd);
    }
    return !b->overflow;
}

/* FSTOD/FDTOS: FP-to-FP conversion. */
static bool fp_emit_f2f(sparc64_emit_ctx_t *ec, uint32_t base,
    const sparc64_dec_t *d, bool from_double)
{
    sparc64_dbt_buf_t *b = ec->buf;
    unsigned rs2 = d->raw & 31U;
    unsigned rd = d->rd & 31U;
    if (!fp_guard_rd0(ec)) {
        return false;
    }
    if (from_double) {
        fp_ld_d(b, 0U, (rs2 >> 1U) & 31U);
        fp_alu(b, base, 1U, 0U, 0U);
        fp_st_s(b, 1U, rd);
    } else {
        fp_ld_s(b, 0U, rs2);
        fp_alu(b, base, 1U, 0U, 0U);
        fp_st_d(b, 1U, (rd >> 1U) & 31U);
    }
    return !b->overflow;
}

/* FP loads/stores run the reference FPU kernel through a faultable
 * helper call (alignment + ASI + big-endian + mem callbacks, parity by
 * construction); any fault exits UNDEF for interpreter replay. */
static uint32_t s64_rt_fpmem(sparc64_ctx_t *ctx,
    const sparc64_mem_ops_t *mem, void *mc, uint64_t pc, uint32_t raw)
{
    sparc64_dec_t d;
    sparc64_step_result_t r;
    sparc64_classify_word(raw, &d);
    if (d.cls != (uint8_t)SPARC64_ICLS_FPU) {
        return SPARC64_EXIT_UNDEF;
    }
    r = sparc64_exec_fpu(ctx, mem, mc, pc, &d);
    if (r.kind == SPARC64_STEP_CONTINUE) {
        return SPARC64_EXIT_NONE;
    }
    return SPARC64_EXIT_UNDEF;
}

static bool fp_emit_mem(sparc64_emit_ctx_t *ec, const sparc64_dec_t *d)
{
    sparc64_dbt_buf_t *b = ec->buf;
    size_t p_fault;
    if (ec->mem == NULL) {
        return false;
    }
    e_arg_ctx(b);
    sb_mov_imm64(b, 1U, (uint64_t)(uintptr_t)ec->mem);
    sb_mov_imm64(b, 2U, (uint64_t)(uintptr_t)ec->mc);
    sb_mov_imm64(b, 3U, ec->pc);
    sb_mov_imm32(b, 4U, d->raw);
    p_fault = e_call_faultable(b, (uint64_t)(uintptr_t)&s64_rt_fpmem);
    if (p_fault == SPARC64_DBT_NOPOS) {
        return false;
    }
    e_resolve_fault(ec, p_fault);
    return !b->overflow;
}

/* FPOP1 dispatch on the 9-bit opf (ground-truth values above). */
static bool fp_emit_fpop1(sparc64_emit_ctx_t *ec, const sparc64_dec_t *d)
{
    switch (d->opf) {
    case 0x41U:
        return fp_emit_arith(ec, FP_FADD_S, d, false);
    case 0x42U:
        return fp_emit_arith(ec, FP_FADD_D, d, true);
    case 0x45U:
        return fp_emit_arith(ec, FP_FSUB_S, d, false);
    case 0x46U:
        return fp_emit_arith(ec, FP_FSUB_D, d, true);
    case 0x49U:
        return fp_emit_arith(ec, FP_FMUL_S, d, false);
    case 0x4AU:
        return fp_emit_arith(ec, FP_FMUL_D, d, true);
    case 0x4DU:
        return fp_emit_arith(ec, FP_FDIV_S, d, false);
    case 0x4EU:
        return fp_emit_arith(ec, FP_FDIV_D, d, true);
    case 0x29U:
        return fp_emit_sqrt(ec, FP_FSQRT_S, d, false);
    case 0x2AU:
        return fp_emit_sqrt(ec, FP_FSQRT_D, d, true);
    case 0x01U:
        return fp_emit_mov(ec, d, false);
    case 0x02U:
        return fp_emit_mov(ec, d, true);
    case 0x05U:
        return fp_emit_unary(ec, FP_FNEG_S, d, false);
    case 0x06U:
        return fp_emit_unary(ec, FP_FNEG_D, d, true);
    case 0x09U:
        return fp_emit_unary(ec, FP_FABS_S, d, false);
    case 0x0AU:
        return fp_emit_unary(ec, FP_FABS_D, d, true);
    case 0xD1U:
        return fp_emit_f2i(ec, FP_FCVTNS_W_S, d, false, false);
    case 0xD2U:
        return fp_emit_f2i(ec, FP_FCVTNS_W_D, d, true, false);
    case 0x81U:
        return fp_emit_f2i(ec, FP_FCVTNS_X_S, d, false, true);
    case 0x82U:
        return fp_emit_f2i(ec, FP_FCVTNS_X_D, d, true, true);
    case 0xC4U:
        return fp_emit_i2f(ec, FP_SCVTF_S_W, d, false);
    case 0xC8U:
        return fp_emit_i2f(ec, FP_SCVTF_D_W, d, true);
    case 0x84U:
        return fp_emit_x2f(ec, FP_SCVTF_S_X, d, false);
    case 0x88U:
        return fp_emit_x2f(ec, FP_SCVTF_D_X, d, true);
    case 0xC9U:
        return fp_emit_f2f(ec, FP_FCVT_D_S, d, false);
    case 0xC6U:
        return fp_emit_f2f(ec, FP_FCVT_S_D, d, true);
    default:
        break;
    }
    return false;
}

static bool fp_emit_one(sparc64_emit_ctx_t *ec, const sparc64_dec_t *d)
{
    if (d->op == 2U && d->op3 == (uint8_t)SPARC64_OP3_FPOP1) {
        return fp_emit_fpop1(ec, d);
    }
    if (d->op == 3U &&
        (d->op3 == (uint8_t)SPARC64_OP3_LDF ||
            d->op3 == (uint8_t)SPARC64_OP3_LDDF ||
            d->op3 == (uint8_t)SPARC64_OP3_STF ||
            d->op3 == (uint8_t)SPARC64_OP3_STDF)) {
        return fp_emit_mem(ec, d);
    }
    return false;
}

bool sparc64_emit_fp(sparc64_emit_ctx_t *ec, const sparc64_dec_t *d)
{
    bool ok;
    if (ec == NULL || ec->buf == NULL || d == NULL) {
        return false;
    }
    ok = fp_emit_one(ec, d);
    if (ec->buf->overflow) {
        return false;
    }
    return ok;
}
