/*
 * src/dbt/emit_fpcmp.c — Lane P5 FCMP/FCMPE + FMOVcc + FBfcc lowering.
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Unordered compares set fcc 3 (NV on SNaN/FCMPE*); ordered compares map
 * host NZCV; FMOVcc copies on fp_cctest; FBfcc branches on fcc with an
 * int-then-FP delay slot. Shared FP accessors live in dbt/emit_fp.h.
 */

#include "dbt/emit_fp.h"

#include <stdint.h>

#include "dbt/emit_int.h"
#include "dbt/emit_priv.h"

/* Lane P5: FP condition taken-mask over fcc values 0..3, indexed by
 * the 4-bit FP condition (mirrors interp fp_cctest). */
static const uint32_t fp_taken_mask[16] = {
    0x0U, 0xEU, 0x6U, 0xAU, 0x2U, 0xCU, 0x4U, 0x8U,
    0xFU, 0x1U, 0x9U, 0x5U, 0xDU, 0x3U, 0xBU, 0x7U
};

/* Load fcc[idx] and reduce (cond, fcc) to taken 0/1 in ES4. */
static void fp_taken_compute(sparc64_dbt_buf_t *b, unsigned cond,
    unsigned idx)
{
    sb_ldst_imm(b, true, false, ES3, ECTX, 0x240U + (idx & 3U) * 4U);
    sb_mov_imm32(b, ES4, fp_taken_mask[cond & 15U]);
    sb_lsrv(b, false, ES4, ES4, ES3);
    sb_ubfm(b, false, ES4, ES4, 0U, 0U);
}

/* Commit fcc (in wES4, 0..3) and NV (in wES5, 0 or 0x10) for one
 * compare: fcc[idx] and the FSR fcc field update, cexc overwritten,
 * aexc sticky, UNDEF on a real (TEM & NV) trap. FSR fcc shifts: idx0
 * at bit 10, idx1..3 at bits 32/34/36. */
static bool fp_fcc_nv_commit(sparc64_emit_ctx_t *ec, unsigned idx)
{
    sparc64_dbt_buf_t *b = ec->buf;
    size_t p_notrap;
    unsigned sh;
    switch (idx & 3U) {
    case 0U: sh = 10U; break;
    case 1U: sh = 32U; break;
    case 2U: sh = 34U; break;
    default: sh = 36U; break;
    }
    sb_ldst_imm(b, false, false, ES4, ECTX, 0x240U + (idx & 3U) * 4U);
    sb_ldst_imm(b, true, true, ES3, ECTX, FP_FSR_OFF);
    sb_ubfm(b, false, ES0, ES3, 23U, 27U);
    sb_ands_reg(b, false, 31U, ES0, ES5);
    p_notrap = sb_b_cond_placeholder(b, 0U);
    if (p_notrap == SPARC64_DBT_NOPOS) {
        return false;
    }
    e_fault_here(b, ec->fault_pc);
    sb_patch_b_cond(b, p_notrap, 0U, b->count);
    sb_ldst_imm(b, true, true, ES3, ECTX, FP_FSR_OFF);
    sb_mov_imm64(b, ES0, (UINT64_C(3) << sh) | UINT64_C(0x1F));
    sb_bic_reg(b, true, ES3, ES3, ES0);
    sb_orr_reg(b, true, ES3, ES3, ES5);
    sb_ubfm(b, true, ES0, ES5, 59U, 58U);
    sb_orr_reg(b, true, ES3, ES3, ES0);
    sb_ubfm(b, true, ES0, ES4, 64U - sh, 63U - sh);
    sb_orr_reg(b, true, ES3, ES3, ES0);
    sb_ldst_imm(b, false, true, ES3, ECTX, FP_FSR_OFF);
    return !b->overflow;
}

/* FCMP/FCMPE s+d (opfs 0x51/0x52/0x55/0x56): unordered when either
 * operand is NaN (fcc 3, NV on SNaN or when cmpe is set), else an
 * ordered host-NZCV compare (V->3, Z->0, N->1 else 2). NV/TEM trap and
 * fcc/aexc commit go through fp_fcc_nv_commit. No rounding involved,
 * so no RD guard is needed. */
bool fp_emit_cmp(sparc64_emit_ctx_t *ec, bool is_double,
    unsigned cmpe, unsigned idx, unsigned rs1, unsigned rs2)
{
    sparc64_dbt_buf_t *b = ec->buf;
    size_t p_a_nan;
    size_t p_b_nan;
    size_t p_ord;
    size_t p_done;
    /* Lane P13-5: FCMP clobbers host NZCV. */
    b->nzcv_state = SPARC64_NZCV_NONE;
    if (is_double) {
        fp_ld_d(b, 0U, rs1);
        fp_ld_d(b, 1U, rs2);
    } else {
        fp_ld_s(b, 0U, rs1);
        fp_ld_s(b, 1U, rs2);
    }
    fp_alu(b, is_double ? FP_FCMP_D : FP_FCMP_S, 0U, 0U, 0U);
    p_a_nan = sb_b_cond_placeholder(b, 6U);
    if (p_a_nan == SPARC64_DBT_NOPOS) {
        return false;
    }
    fp_alu(b, is_double ? FP_FCMP_D : FP_FCMP_S, 0U, 1U, 1U);
    p_b_nan = sb_b_cond_placeholder(b, 6U);
    if (p_b_nan == SPARC64_DBT_NOPOS) {
        return false;
    }
    p_ord = sb_b_placeholder(b);
    if (p_ord == SPARC64_DBT_NOPOS) {
        return false;
    }
    /* L_a: a is NaN. ES3 = snan_a = !quiet(a). */
    sb_patch_b_cond(b, p_a_nan, 6U, b->count);
    if (is_double) {
        fp_ld_d(b, 0U, rs1);
        sb_mov_imm64(b, ES0, UINT64_C(0x0008000000000000));
    } else {
        fp_ld_s(b, 0U, rs1);
        sb_mov_imm32(b, ES0, 0x00400000U);
    }
    fp_alu(b, is_double ? FP_FMOV_D_X : FP_FMOV_W_S, ES1, 0U, 0U);
    sb_ands_reg(b, is_double, 31U, ES1, ES0);
    sb_cset(b, ES3, 0U);
    /* b unknown: ES1 = snan_b = isnan(b) && !quiet(b). */
    fp_alu(b, is_double ? FP_FCMP_D : FP_FCMP_S, 0U, 1U, 1U);
    sb_cset(b, ES1, 6U);
    if (is_double) {
        fp_ld_d(b, 0U, rs2);
        sb_mov_imm64(b, ES0, UINT64_C(0x0008000000000000));
    } else {
        fp_ld_s(b, 0U, rs2);
        sb_mov_imm32(b, ES0, 0x00400000U);
    }
    fp_alu(b, is_double ? FP_FMOV_D_X : FP_FMOV_W_S, ES4, 0U, 0U);
    sb_ands_reg(b, is_double, 31U, ES4, ES0);
    sb_cset(b, ES4, 0U);
    sb_logic_reg(b, is_double ? UINT32_C(0x8A000000) :
        UINT32_C(0x0A000000), ES1, ES1, ES4);
    {
        size_t p_un = sb_b_placeholder(b);
        if (p_un == SPARC64_DBT_NOPOS) {
            return false;
        }
        /* L_b: a finite so snan_a = 0; b is NaN so snan_b = !quiet(b). */
        sb_patch_b_cond(b, p_b_nan, 6U, b->count);
        sb_mov_imm32(b, ES3, 0U);
        if (is_double) {
            fp_ld_d(b, 0U, rs2);
            sb_mov_imm64(b, ES0, UINT64_C(0x0008000000000000));
        } else {
            fp_ld_s(b, 0U, rs2);
            sb_mov_imm32(b, ES0, 0x00400000U);
        }
        fp_alu(b, is_double ? FP_FMOV_D_X : FP_FMOV_W_S, ES1, 0U, 0U);
        sb_ands_reg(b, is_double, 31U, ES1, ES0);
        sb_cset(b, ES1, 0U);
        sb_patch_b(b, p_un, b->count);
    }
    /* L_un: nv = (cmpe || snan_a || snan_b) ? 0x10 : 0, fcc = 3. */
    sb_orr_reg(b, false, ES1, ES1, ES3);
    if (cmpe != 0U) {
        sb_mov_imm32(b, ES0, 1U);
        sb_orr_reg(b, false, ES1, ES1, ES0);
    }
    sb_cmp_imm(b, false, ES1, 0U);
    sb_cset(b, ES5, 1U);
    e_lsl_imm32(b, ES5, ES5, 4U);
    sb_mov_imm32(b, ES4, 3U);
    if (!fp_fcc_nv_commit(ec, idx)) {
        return false;
    }
    p_done = sb_b_placeholder(b);
    if (p_done == SPARC64_DBT_NOPOS) {
        return false;
    }
    /* L_ord: ordered compare (V->3, Z->0, N^V->1 else 2). */
    sb_patch_b(b, p_ord, b->count);
    fp_alu(b, is_double ? FP_FCMP_D : FP_FCMP_S, 0U, 0U, 1U);
    sb_mrs_nzcv(b, ES3);
    sb_ubfm(b, false, ES3, ES3, 28U, 31U);
    sb_ubfm(b, false, ES5, ES3, 0U, 0U);
    sb_ubfm(b, false, ES0, ES3, 2U, 2U);
    sb_ubfm(b, false, ES1, ES3, 3U, 3U);
    sb_eor_reg(b, false, ES1, ES1, ES5);
    sb_mov_imm32(b, ES4, 2U);
    {
        size_t p_nlt = sb_cbz_placeholder(b, false, false, ES1);
        size_t p_nz;
        size_t p_nv;
        if (p_nlt == SPARC64_DBT_NOPOS) {
            return false;
        }
        sb_mov_imm32(b, ES4, 1U);
        sb_patch_cb(b, p_nlt, b->count);
        p_nz = sb_cbz_placeholder(b, false, false, ES0);
        if (p_nz == SPARC64_DBT_NOPOS) {
            return false;
        }
        sb_mov_imm32(b, ES4, 0U);
        sb_patch_cb(b, p_nz, b->count);
        p_nv = sb_cbz_placeholder(b, false, false, ES5);
        if (p_nv == SPARC64_DBT_NOPOS) {
            return false;
        }
        sb_mov_imm32(b, ES4, 3U);
        sb_patch_cb(b, p_nv, b->count);
    }
    sb_mov_imm32(b, ES5, 0U);
    if (!fp_fcc_nv_commit(ec, idx)) {
        return false;
    }
    sb_patch_b(b, p_done, b->count);
    return !b->overflow;
}

/* FMOVcc single/double (opf = (fcc<<6)|size, cond in rs1): copies
 * f[rd] = f[rs2] when fp_cctest(cond, fcc[idx]) holds. Operate-class:
 * overwrites cexc with 0 even when skipped; never traps. Quad (size 3)
 * falls back to the interpreter. */
bool fp_emit_movcc(sparc64_emit_ctx_t *ec, const sparc64_dec_t *d)
{
    sparc64_dbt_buf_t *b = ec->buf;
    unsigned opf = d->opf;
    unsigned size = opf & 3U;
    unsigned idx = (opf >> 6) & 3U;
    unsigned cond = d->rs1 & 15U;
    unsigned rs2 = d->raw & 31U;
    unsigned rd = d->rd & 31U;
    size_t p_skip;
    bool is_double;
    if ((opf & UINT32_C(0x13C)) != UINT32_C(0) || size == 0U ||
        size > 2U || d->rs1 > 15U) {
        return false;
    }
    is_double = size == 2U;
    fp_taken_compute(b, cond, idx);
    p_skip = sb_cbz_placeholder(b, false, false, ES4);
    if (p_skip == SPARC64_DBT_NOPOS) {
        return false;
    }
    if (is_double) {
        fp_ld_d(b, 0U, rs2);
        fp_st_d(b, 0U, rd);
    } else {
        fp_ld_s(b, 0U, rs2);
        fp_st_s(b, 0U, rd);
    }
    if (b->overflow) {
        return false;
    }
    sb_patch_cb(b, p_skip, b->count);
    fp_clear_cexc(b);
    return !b->overflow;
}

/* FBfcc delay slot: plain integer/fp single insn, emitted inline.
 * Falls back (false) when neither engine takes it; the caller then
 * abandons the block to the interpreter. */
static bool fbr_emit_delay(sparc64_emit_ctx_t *ec);

static bool fbr_delay_runs(unsigned cond, bool taken, bool annul)
{
    if (taken) {
        return !(annul && cond == 8U);
    }
    return !annul;
}

/* FBfcc: branch on fcc[idx] (fcc index in d->cc). Page-final branches
 * fall back to the interpreter; delay slots emit via int then FP. */
bool sparc64_emit_fbr(sparc64_emit_ctx_t *ec, const sparc64_dec_t *d)
{
    sparc64_dbt_buf_t *b;
    uint64_t target;
    uint64_t fallthrough;
    unsigned cond;
    unsigned idx;
    bool annul;
    size_t p_taken;
    if (ec == NULL || ec->buf == NULL || d == NULL) {
        return false;
    }
    b = ec->buf;
    if ((ec->pc & UINT64_C(0xFFF)) == UINT64_C(0xFFC)) {
        return false;
    }
    if (!sparc64_emit_fp_flush(ec)) {
        return false;
    }
    target = ec->pc + (uint64_t)d->disp;
    fallthrough = ec->pc + 8U;
    cond = d->cond;
    idx = d->cc & 3U;
    annul = d->annul != 0U;
    if (cond == 8U) {
        if (!fbr_delay_runs(cond, true, annul)) {
            e_exit_imm(b, target, SPARC64_EXIT_BRANCH);
            return !b->overflow;
        }
        if (!fbr_emit_delay(ec)) {
            return false;
        }
        if (ec->delay->cls == (uint8_t)SPARC64_ICLS_FPU) {
            if (!sparc64_emit_fp_flush(ec)) {
                return false;
            }
        }
        e_exit_imm(b, target, SPARC64_EXIT_BRANCH);
        return !b->overflow;
    }
    if (cond == 0U) {
        if (!fbr_delay_runs(cond, false, annul)) {
            e_exit_imm(b, fallthrough, SPARC64_EXIT_BRANCH);
            return !b->overflow;
        }
        if (!fbr_emit_delay(ec)) {
            return false;
        }
        if (ec->delay->cls == (uint8_t)SPARC64_ICLS_FPU) {
            if (!sparc64_emit_fp_flush(ec)) {
                return false;
            }
        }
        e_exit_imm(b, fallthrough, SPARC64_EXIT_BRANCH);
        return !b->overflow;
    }
    fp_taken_compute(b, cond, idx);
    p_taken = sb_cbz_placeholder(b, false, true, ES4);
    if (p_taken == SPARC64_DBT_NOPOS) {
        return false;
    }
    {
        sparc64_dbt_cache_snap_t snap;
        /* Lane P13-5: the taken delay copy below must compile against
         * this pre-branch cache state (the two copies execute
         * exclusively). */
        e_cache_snapshot(b, &snap);
        if (fbr_delay_runs(cond, false, annul)) {
            if (!fbr_emit_delay(ec)) {
                return false;
            }
            if (ec->delay->cls == (uint8_t)SPARC64_ICLS_FPU) {
                if (!sparc64_emit_fp_flush(ec)) {
                    return false;
                }
            }
        }
        e_exit_imm(b, fallthrough, SPARC64_EXIT_BRANCH);
        if (b->overflow) {
            return false;
        }
        sb_patch_cb(b, p_taken, b->count);
        e_cache_restore(b, &snap);
    }
    if (fbr_delay_runs(cond, true, annul)) {
        if (!fbr_emit_delay(ec)) {
            return false;
        }
        if (ec->delay->cls == (uint8_t)SPARC64_ICLS_FPU) {
            if (!sparc64_emit_fp_flush(ec)) {
                return false;
            }
        }
    }
    e_exit_imm(b, target, SPARC64_EXIT_BRANCH);
    return !b->overflow;
}

static bool fbr_emit_delay(sparc64_emit_ctx_t *ec)
{
    if (ec == NULL || ec->buf == NULL || ec->delay == NULL) {
        return false;
    }
    if (sparc64_emit_int(ec, ec->delay)) {
        return true;
    }
    if (ec->buf->overflow) {
        return false;
    }
    return sparc64_emit_fp(ec, ec->delay);
}
