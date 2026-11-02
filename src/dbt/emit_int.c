/*
 * src/dbt/emit_int.c — AArch64 integer instruction emitter (Phase 2, L2c)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Integer emitter (--difftest). x19 = ctx, scratch x9-x14, exits
 * carry PC in x15 and reason in w16; never x18. PRIV/FBR/odd
 * encodings fall back; FPU delays lower via emit_fp.h (Lane P5).
 */

#include "dbt/emit_int.h"

#include <stdint.h>

#include "dbt/emit_cond.h"
#include "dbt/emit_fast.h"
#include "dbt/emit_fp.h"
#include "dbt/emit_mem.h"
#include "dbt/emit_priv.h"

static bool e_emit_alu(sparc64_emit_ctx_t *ec, const sparc64_dec_t *d);
static bool e_emit_shift(sparc64_emit_ctx_t *ec, const sparc64_dec_t *d);

/* Branch-width lookahead (Lane P13-5): scan forward from the cc op for
 * the nearest Bicc/BPcc/MOVcc consumer, so the second (live) flag pass
 * matches the width the branch will test. Only transparent insns are
 * skipped: plain ALU/shifts/state ops plus loads/stores/window ops,
 * whose runtime paths either preserve host NZCV (inline fast paths,
 * Soft-TLB miss trampoline) or clear nzcv_state statically (helper
 * fallbacks). Anything else (another cc op, CTI, FPU, fetch failure,
 * scan cap) stops the scan and defaults to icc; soundness never
 * depends on this heuristic, only on the nzcv_state match check. */
static bool e_cc_transparent(const sparc64_dec_t *d)
{
    switch (d->cls) {
    case SPARC64_ICLS_SETHI:
    case SPARC64_ICLS_SHIFT:
    case SPARC64_ICLS_RDASR:
    case SPARC64_ICLS_WRASR:
    case SPARC64_ICLS_MEMBAR:
    case SPARC64_ICLS_FLUSH:
    case SPARC64_ICLS_ALIGN:
    case SPARC64_ICLS_MOVCC:
    case SPARC64_ICLS_MOVR:
    case SPARC64_ICLS_LOAD:
    case SPARC64_ICLS_STORE:
    case SPARC64_ICLS_LDSTUB:
    case SPARC64_ICLS_SWAP:
    case SPARC64_ICLS_ATOMIC:
    case SPARC64_ICLS_SAVE:
    case SPARC64_ICLS_RESTORE:
        return true;
    case SPARC64_ICLS_ALU:
        switch (d->op3) {
        case SPARC64_OP3_ADD:
        case SPARC64_OP3_AND:
        case SPARC64_OP3_OR:
        case SPARC64_OP3_XOR:
        case SPARC64_OP3_SUB:
        case SPARC64_OP3_ANDN:
        case SPARC64_OP3_ORN:
        case SPARC64_OP3_XORN:
            return true;
        default:
            return false;
        }
    default:
        return false;
    }
}

static bool e_cc_lookahead_xcc(sparc64_emit_ctx_t *ec)
{
    uint64_t a;
    unsigned i;
    if (ec == NULL || ec->mem == NULL) {
        return false;
    }
    a = ec->pc + 4U;
    for (i = 0U; i < 16U; i++) {
        sparc64_dec_t d;
        uint32_t raw;
        sparc64_step_result_t res;
        if (!sparc64_fetch_word(ec->mem, ec->mc, a, &raw, &res)) {
            return false;
        }
        sparc64_classify_word(raw, &d);
        if (d.cls == (uint8_t)SPARC64_ICLS_BICC ||
            d.cls == (uint8_t)SPARC64_ICLS_BPCC ||
            (d.cls == (uint8_t)SPARC64_ICLS_MOVCC &&
             (d.cc & 4U) == 0U)) {
            return d.cc == 2U;
        }
        if (!e_cc_transparent(&d)) {
            return false;
        }
        a += 4U;
    }
    return false;
}

/* ---- per-class emitters ---- */

static bool e_emit_sethi(sparc64_emit_ctx_t *ec, const sparc64_dec_t *d)
{
    sparc64_dbt_buf_t *b = ec->buf;
    sb_mov_imm32(b, ES0, d->uimm << 10);
    e_st64(b, d->rd, ES0);
    return !b->overflow;
}

/* Complex ALU via helper s64_rt_alu (Y/cc/traps). */
static size_t e_call_alu(sparc64_emit_ctx_t *ec, const sparc64_dec_t *d)
{
    sparc64_dbt_buf_t *b = ec->buf;
    e_arg_ctx(b);
    sb_mov_imm32(b, 1U, d->op3);
    sb_mov_imm32(b, 2U, d->rs1);
    if (d->is_imm != 0U) {
        sb_mov_imm32(b, 3U, (uint32_t)d->imm);
    } else {
        sb_mov_imm32(b, 3U, d->rs2);
    }
    sb_mov_imm32(b, 4U, d->is_imm);
    sb_mov_imm32(b, 5U, d->rd);
    sb_mov_imm64(b, 6U, ec->pc);
    return e_call_faultable(b, (uint64_t)(uintptr_t)&s64_rt_alu);
}

static bool e_emit_alu_helper(sparc64_emit_ctx_t *ec,
    const sparc64_dec_t *d)
{
    size_t p_fault = e_call_alu(ec, d);
    if (p_fault == SPARC64_DBT_NOPOS) {
        return false;
    }
    e_resolve_fault(ec, p_fault);
    return !ec->buf->overflow;
}

static bool e_emit_alu_simple(sparc64_emit_ctx_t *ec,
    const sparc64_dec_t *d)
{
    sparc64_dbt_buf_t *b = ec->buf;
    unsigned s2 = ES1;
    e_ld64(b, ES0, d->rs1);
    if (d->is_imm != 0U) {
        sb_mov_imm64(b, ES1, (uint64_t)d->imm);
    } else {
        s2 = e_get_gpr(b, d->rs2);
    }
    switch (d->op3) {
    case SPARC64_OP3_ADD:
        sb_add_reg(b, true, false, ES0, ES0, s2);
        break;
    case SPARC64_OP3_AND:
        sb_logic_reg(b, UINT32_C(0x8a000000), ES0, ES0, s2);
        break;
    case SPARC64_OP3_OR:
        sb_orr_reg(b, true, ES0, ES0, s2);
        break;
    case SPARC64_OP3_XOR:
        sb_eor_reg(b, true, ES0, ES0, s2);
        break;
    case SPARC64_OP3_SUB:
        sb_sub_reg(b, true, false, ES0, ES0, s2);
        break;
    case SPARC64_OP3_ANDN:
        sb_bic_reg(b, true, ES0, ES0, s2);
        break;
    case SPARC64_OP3_ORN:
        sb_orn_reg(b, true, ES0, ES0, s2);
        break;
    case SPARC64_OP3_XORN:
        sb_orn_reg(b, true, ES2, 31U, s2);
        sb_eor_reg(b, true, ES0, ES0, ES2);
        break;
    case SPARC64_OP3_ADDX:
        e_load_carry(b, ES2);
        e_seed_carry_add(b, ES2);
        e_ld64(b, ES0, d->rs1);
        e_src2(b, ES1, d);
        sb_adc(b, false, ES0, ES0, ES1);
        b->nzcv_state = SPARC64_NZCV_NONE;
        break;
    case SPARC64_OP3_SUBX:
        e_load_carry(b, ES2);
        e_seed_carry_sub(b, ES2);
        e_ld64(b, ES0, d->rs1);
        e_src2(b, ES1, d);
        sb_sbc(b, false, ES0, ES0, ES1);
        b->nzcv_state = SPARC64_NZCV_NONE;
        break;
    case SPARC64_OP3_MULX:
        sb_mul(b, ES0, ES0, s2);
        break;
    default:
        return false;
    }
    e_st64(b, d->rd, ES0);
    return !b->overflow;
}

/* ADDCC/SUBCC/ADDXCC/SUBXCC (Lane P13-5): source operands stay
 * immutable in ES0/ES1 across both flag passes; the first pass writes
 * ES3 and the second (live) pass writes ES0 for the 64-bit width or
 * xzr for the 32-bit width. Pass order follows the branch lookahead so
 * the live host NZCV matches the width the upcoming Bicc/BPcc/MOVcc
 * tests. CCR commits use only CSET/ORR/STR and the result stores via
 * MOV + STR, none of which touch host NZCV, even when rd aliases
 * rs1/rs2. */
static bool e_emit_addsubcc(sparc64_emit_ctx_t *ec,
    const sparc64_dec_t *d)
{
    sparc64_dbt_buf_t *b = ec->buf;
    bool is_sub = d->op3 == SPARC64_OP3_SUBCC ||
        d->op3 == SPARC64_OP3_SUBXCC;
    bool with_carry = d->op3 == SPARC64_OP3_ADDXCC ||
        d->op3 == SPARC64_OP3_SUBXCC;
    /* With carry the 32-bit pass never sets flags (it runs through the
     * 64-bit SBC/ADC without S, preserving the reseed), so the live
     * host NZCV is always the 64-bit result: keep the original
     * 32-first order and the XCC state. */
    bool xcc_live = with_carry ? true : e_cc_lookahead_xcc(ec);
    if (with_carry) {
        e_load_carry(b, ES2);
    }
    e_ld64(b, ES0, d->rs1);
    e_src2(b, ES1, d);
    if (with_carry) {
        e_load_carry(b, ES2);
        if (is_sub) {
            e_seed_carry_sub(b, ES2);
        } else {
            e_seed_carry_add(b, ES2);
        }
    }
    if (xcc_live) {
        /* 32-bit (icc) pass first into xzr; operands stay intact. */
        if (is_sub) {
            if (with_carry) {
                sb_sbc(b, false, 31U, ES0, ES1);
            } else {
                sb_sub_reg(b, false, true, 31U, ES0, ES1);
            }
        } else {
            if (with_carry) {
                sb_adc(b, false, 31U, ES0, ES1);
            } else {
                sb_add_reg(b, false, true, 31U, ES0, ES1);
            }
        }
        e_host_to_nibble(b, ES4, ES2, is_sub);
    } else {
        /* 64-bit (xcc) pass first into ES3; operands stay intact. The
         * no-carry form must set flags (its nibble is committed
         * next); the with-carry form keeps the original no-S shape
         * but never runs in this order (with_carry forces xcc_live). */
        if (is_sub) {
            if (with_carry) {
                sb_sbc(b, false, ES3, ES0, ES1);
            } else {
                sb_sub_reg(b, true, true, ES3, ES0, ES1);
            }
        } else {
            if (with_carry) {
                sb_adc(b, false, ES3, ES0, ES1);
            } else {
                sb_add_reg(b, true, true, ES3, ES0, ES1);
            }
        }
        e_host_to_nibble(b, ES5, ES2, is_sub);
    }
    if (with_carry) {
        e_load_carry(b, ES2);
        if (is_sub) {
            e_seed_carry_sub(b, ES2);
        } else {
            e_seed_carry_add(b, ES2);
        }
    }
    if (xcc_live) {
        /* 64-bit (xcc) pass second and live; the result survives. */
        if (is_sub) {
            if (with_carry) {
                sb_sbc(b, true, ES0, ES0, ES1);
            } else {
                sb_sub_reg(b, true, true, ES0, ES0, ES1);
            }
        } else {
            if (with_carry) {
                sb_adc(b, true, ES0, ES0, ES1);
            } else {
                sb_add_reg(b, true, true, ES0, ES0, ES1);
            }
        }
        e_host_to_nibble(b, ES5, ES2, is_sub);
        e_merge_cc(b, ES4, ES5, ES2);
        e_set_gpr(b, d->rd, ES0);
        b->nzcv_state = is_sub ? SPARC64_NZCV_SUB_XCC :
            SPARC64_NZCV_ADD_XCC;
    } else {
        /* 32-bit (icc) pass second and live; result discarded. */
        if (is_sub) {
            if (with_carry) {
                sb_sbc(b, false, 31U, ES0, ES1);
            } else {
                sb_sub_reg(b, false, true, 31U, ES0, ES1);
            }
        } else {
            if (with_carry) {
                sb_adc(b, false, 31U, ES0, ES1);
            } else {
                sb_add_reg(b, false, true, 31U, ES0, ES1);
            }
        }
        e_host_to_nibble(b, ES4, ES2, is_sub);
        e_merge_cc(b, ES4, ES5, ES2);
        e_set_gpr(b, d->rd, ES3);
        b->nzcv_state = is_sub ? SPARC64_NZCV_SUB_ICC :
            SPARC64_NZCV_ADD_ICC;
    }
    return !b->overflow;
}

/* Logic-cc N/Z commit (Lane P13-5): TST sets host C = 0, V = 0
 * architecturally, matching the guest logic-cc nibble, so only the N
 * (MI) and Z (EQ) bits need committing: 5 instructions per pass. */
static void e_logic_to_nibble(sparc64_dbt_buf_t *b, unsigned wI,
    unsigned xT)
{
    sb_cset(b, wI, 4U);
    e_lsl_imm32(b, wI, wI, 3U);
    sb_cset(b, xT, 0U);
    e_lsl_imm32(b, xT, xT, 2U);
    sb_orr_reg(b, false, wI, wI, xT);
}

/* Logic cc (Lane P13-5): the 10 V/C computing instructions and the 2
 * flag-clearing ADDs are gone; each TST pass commits only N/Z. Pass
 * order follows the branch lookahead so the live host NZCV matches the
 * upcoming test width. */
static bool e_emit_logiccc(sparc64_emit_ctx_t *ec,
    const sparc64_dec_t *d)
{
    sparc64_dbt_buf_t *b = ec->buf;
    bool xcc_live = e_cc_lookahead_xcc(ec);
    e_ld64(b, ES0, d->rs1);
    e_src2(b, ES1, d);
    switch (d->op3) {
    case SPARC64_OP3_ANDCC:
        sb_logic_reg(b, UINT32_C(0x8a000000), ES0, ES0, ES1);
        break;
    case SPARC64_OP3_ORCC:
        sb_orr_reg(b, true, ES0, ES0, ES1);
        break;
    case SPARC64_OP3_XORCC:
        sb_eor_reg(b, true, ES0, ES0, ES1);
        break;
    case SPARC64_OP3_ANDNCC:
        sb_bic_reg(b, true, ES0, ES0, ES1);
        break;
    case SPARC64_OP3_ORNCC:
        sb_orn_reg(b, true, ES0, ES0, ES1);
        break;
    case SPARC64_OP3_XORNCC:
        sb_orn_reg(b, true, ES2, 31U, ES1);
        sb_eor_reg(b, true, ES0, ES0, ES2);
        break;
    default:
        return false;
    }
    if (xcc_live) {
        sb_ands_reg(b, false, 31U, ES0, ES0);
        e_logic_to_nibble(b, ES4, ES2);
        sb_ands_reg(b, true, 31U, ES0, ES0);
        e_logic_to_nibble(b, ES5, ES2);
    } else {
        sb_ands_reg(b, true, 31U, ES0, ES0);
        e_logic_to_nibble(b, ES5, ES2);
        sb_ands_reg(b, false, 31U, ES0, ES0);
        e_logic_to_nibble(b, ES4, ES2);
    }
    e_merge_cc(b, ES4, ES5, ES2);
    e_set_gpr(b, d->rd, ES0);
    b->nzcv_state = xcc_live ? SPARC64_NZCV_LOGIC_XCC :
        SPARC64_NZCV_LOGIC_ICC;
    return !b->overflow;
}

/* User state reads/writes. */
static bool e_emit_rdasr(sparc64_emit_ctx_t *ec, const sparc64_dec_t *d)
{
    sparc64_dbt_buf_t *b = ec->buf;
    switch (d->rs1) {
    case SPARC64_ASR_Y:
        sb_ldst_imm(b, true, true, ES0, ECTX, E_OFF_Y);
        break;
    case SPARC64_ASR_CCR:
        sb_ldst_imm(b, true, true, ES0, ECTX, SPARC64_CTX_CCR_OFFSET);
        sb_ubfm(b, false, ES0, ES0, 0U, 7U);
        break;
    case SPARC64_ASR_ASI:
        sb_ldst_imm(b, true, false, ES0, ECTX, E_OFF_ASI);
        break;
    case SPARC64_ASR_FPRS:
        sb_ldst_imm(b, true, true, ES0, ECTX, E_OFF_FPRS);
        break;
    case SPARC64_ASR_GSR:
        sb_ldst_imm(b, true, true, ES0, ECTX, E_OFF_GSR);
        break;
    default:
        return false;
    }
    e_st64(b, d->rd, ES0);
    return !b->overflow;
}

static bool e_emit_wrasr(sparc64_emit_ctx_t *ec, const sparc64_dec_t *d)
{
    sparc64_dbt_buf_t *b = ec->buf;
    e_ld64(b, ES0, d->rs1);
    e_src2(b, ES1, d);
    sb_eor_reg(b, true, ES1, ES0, ES1);
    switch (d->rd) {
    case SPARC64_ASR_Y:
        sb_ldst_imm(b, false, true, ES1, ECTX, E_OFF_Y);
        break;
    case SPARC64_ASR_CCR:
        sb_ldst_imm(b, true, true, ES0, ECTX, SPARC64_CTX_CCR_OFFSET);
        sb_ubfm(b, true, ES0, ES0, 8U, 63U);
        sb_ubfm(b, true, ES0, ES0, 56U, 55U);
        sb_ubfm(b, false, ES1, ES1, 0U, 7U);
        sb_orr_reg(b, true, ES0, ES0, ES1);
        sb_ldst_imm(b, false, true, ES0, ECTX, SPARC64_CTX_CCR_OFFSET);
        break;
    case SPARC64_ASR_ASI:
        sb_ldst_imm(b, false, false, ES1, ECTX, E_OFF_ASI);
        break;
    case SPARC64_ASR_FPRS:
        sb_ldst_imm(b, false, true, ES1, ECTX, E_OFF_FPRS);
        break;
    case SPARC64_ASR_GSR:
        sb_ldst_imm(b, false, true, ES1, ECTX, E_OFF_GSR);
        break;
    default:
        return false;
    }
    return !b->overflow;
}

/* ALIGNADDR/ALIGNADDRL. */
static bool e_emit_align(sparc64_emit_ctx_t *ec, const sparc64_dec_t *d)
{
    sparc64_dbt_buf_t *b = ec->buf;
    e_ld64(b, ES0, d->rs1);
    e_src2(b, ES1, d);
    sb_add_reg(b, true, false, ES0, ES0, ES1);
    sb_ldst_imm(b, true, true, ES2, ECTX, E_OFF_GSR);
    sb_ubfm(b, true, ES2, ES2, 3U, 63U);
    sb_ubfm(b, true, ES2, ES2, 61U, 60U);
    sb_ubfm(b, false, ES1, ES0, 0U, 2U);
    sb_orr_reg(b, true, ES2, ES2, ES1);
    sb_ldst_imm(b, false, true, ES2, ECTX, E_OFF_GSR);
    sb_ubfm(b, true, ES0, ES0, 3U, 63U);
    sb_ubfm(b, true, ES0, ES0, 61U, 60U);
    e_st64(b, d->rd, ES0);
    return !b->overflow;
}

/* CALL. */
static bool e_emit_call(sparc64_emit_ctx_t *ec, const sparc64_dec_t *d)
{
    sparc64_dbt_buf_t *b = ec->buf;
    uint64_t target;
    if (!(ec->delay != NULL && sparc64_delay_is_plain(ec->delay))) {
        return false;
    }
    sb_mov_imm64(b, ES0, ec->pc);
    e_st64(b, SPARC64_O7, ES0);
    if (!sparc64_emit_delay(ec)) {
        return false;
    }
    target = ec->pc + (uint64_t)d->disp;
    b->is_call = true;
    e_exit_imm(b, target, SPARC64_EXIT_BRANCH);
    return !b->overflow;
}

static bool e_emit_win(sparc64_emit_ctx_t *ec, const sparc64_dec_t *d,
    bool is_save);

/* JMPL/RETURN. */
static bool e_emit_jmpl_ret(sparc64_emit_ctx_t *ec, const sparc64_dec_t *d,
    bool is_ret)
{
    sparc64_dbt_buf_t *b = ec->buf;
    size_t p_misaligned;
    if (is_ret && (ec->mem == NULL || (ec->delay != NULL &&
            (ec->delay->cls == SPARC64_ICLS_SAVE ||
            ec->delay->cls == SPARC64_ICLS_RESTORE)))) {
        return false;
    }
    if (!(ec->delay != NULL && sparc64_delay_is_plain(ec->delay))) {
        return false;
    }
    e_ld64(b, ES0, d->rs1);
    e_src2(b, ES1, d);
    sb_add_reg(b, true, false, ES0, ES0, ES1);
    /* A1: stash the pre-effect target (dispatcher delay replay). */
    sb_mov_imm64(b, ES2, (uint64_t)(uintptr_t)&sparc64_dbt_cti_target);
    sb_ldst_imm(b, false, true, ES0, ES2, 0U);
    sb_ubfm(b, false, ES1, ES0, 0U, 1U);
    p_misaligned = sb_cbz_placeholder(b, false, true, ES1);
    if (!is_ret) {
        sb_mov_imm64(b, ES1, ec->pc);
        e_st64(b, d->rd, ES1);
    }
    sb_push64(b, ES0);
    if (is_ret && !e_emit_win(ec, &(sparc64_dec_t){ 0 }, false)) {
        return false;
    }
    if (!sparc64_emit_delay(ec)) {
        return false;
    }
    if (!is_ret && d->rd == SPARC64_O7) {
        b->is_call = true;
    }
    sb_pop64(b, ES0);
    sb_mov_reg(b, true, EPC, ES0);
    sb_mov_imm32(b, ERSN, SPARC64_EXIT_BRANCH);
    sb_ret(b);
    sb_patch_cb(b, p_misaligned, b->count);
    e_fault_here(b, ec->fault_pc);
    return !b->overflow;
}

/* Mem via Soft-TLB. */
static bool e_emit_mem(sparc64_emit_ctx_t *ec, const sparc64_dec_t *d)
{
    size_t p_fault;
    if (ec->mem == NULL || !sparc64_mem_emit_site(ec->buf, d,
        ec->fault_pc, ec->delay == d)) {
        if (!sparc64_emit_fp_flush(ec)) {
            return false;
        }
        p_fault = (ec->mem == NULL) ? SPARC64_DBT_NOPOS : e_call_mem(ec, d);
        if (p_fault == SPARC64_DBT_NOPOS) {
            return false;
        }
        e_resolve_fault(ec, p_fault);
    }
    return !ec->buf->overflow;
}

/* SAVE/RESTORE (Lane P5 fast path, helper fallback). */
static bool e_emit_win(sparc64_emit_ctx_t *ec, const sparc64_dec_t *d,
    bool is_save)
{
    sparc64_dbt_buf_t *b = ec->buf;
    size_t p_fault;
    if (ec->mem == NULL) {
        return false;
    }
    if (sparc64_fast_win(ec, d, is_save)) {
        return !b->overflow;
    }
    e_ld64(b, ES0, d->rs1);
    e_src2(b, ES1, d);
    sb_add_reg(b, true, false, ES0, ES0, ES1);
    p_fault = e_call_win(ec, d->rd, is_save);
    if (p_fault == SPARC64_DBT_NOPOS) {
        return false;
    }
    e_resolve_fault(ec, p_fault);
    return !b->overflow;
}

static bool e_emit_one(sparc64_emit_ctx_t *ec, const sparc64_dec_t *d)
{
    switch (d->cls) {
    case SPARC64_ICLS_SETHI:
        return e_emit_sethi(ec, d);
    case SPARC64_ICLS_ALU:
        return e_emit_alu(ec, d);
    case SPARC64_ICLS_SHIFT:
        return e_emit_shift(ec, d);
    case SPARC64_ICLS_MOVCC:
        return sparc64_emit_movcc(ec, d);
    case SPARC64_ICLS_MOVR:
        return sparc64_emit_movr(ec, d);
    case SPARC64_ICLS_RDASR:
        return e_emit_rdasr(ec, d);
    case SPARC64_ICLS_WRASR:
        return e_emit_wrasr(ec, d);
    case SPARC64_ICLS_MEMBAR:
    case SPARC64_ICLS_FLUSH:
        return true;
    case SPARC64_ICLS_ALIGN:
        return e_emit_align(ec, d);
    case SPARC64_ICLS_CALL:
        return e_emit_call(ec, d);
    case SPARC64_ICLS_BICC:
    case SPARC64_ICLS_BPCC:
    case SPARC64_ICLS_BPR:
        return sparc64_emit_branch(ec, d);
    case SPARC64_ICLS_JMPL:
        return e_emit_jmpl_ret(ec, d, false);
    case SPARC64_ICLS_RETURN:
        return e_emit_jmpl_ret(ec, d, true);
    case SPARC64_ICLS_TCC:
        return sparc64_emit_tcc(ec, d);
    case SPARC64_ICLS_SAVE:
        return e_emit_win(ec, d, true);
    case SPARC64_ICLS_RESTORE:
        return e_emit_win(ec, d, false);
    case SPARC64_ICLS_LOAD:
    case SPARC64_ICLS_STORE:
    case SPARC64_ICLS_LDSTUB:
    case SPARC64_ICLS_SWAP:
    case SPARC64_ICLS_ATOMIC:
        return e_emit_mem(ec, d);
    default:
        break;
    }
    /* PRIV/FPU/FBR/ILLEGAL: dispatcher replays via the interpreter. */
    return false;
}

bool sparc64_emit_int(sparc64_emit_ctx_t *ec, const sparc64_dec_t *d)
{
    bool ok;
    if (ec == NULL || ec->buf == NULL || d == NULL) {
        return false;
    }
    ok = e_emit_one(ec, d);
    if (ec->buf->overflow) {
        return false;
    }
    return ok;
}


static bool e_emit_alu(sparc64_emit_ctx_t *ec, const sparc64_dec_t *d)
{
    switch (d->op3) {
    case SPARC64_OP3_ADD:
    case SPARC64_OP3_AND:
    case SPARC64_OP3_OR:
    case SPARC64_OP3_XOR:
    case SPARC64_OP3_SUB:
    case SPARC64_OP3_ANDN:
    case SPARC64_OP3_ORN:
    case SPARC64_OP3_XORN:
    case SPARC64_OP3_ADDX:
    case SPARC64_OP3_SUBX:
    case SPARC64_OP3_MULX:
        return e_emit_alu_simple(ec, d);
    case SPARC64_OP3_UMUL:
    case SPARC64_OP3_SMUL:
    case SPARC64_OP3_UDIVX:
    case SPARC64_OP3_SDIVX:
        if (sparc64_fast_alu(ec, d)) {
            return !ec->buf->overflow;
        }
        return e_emit_alu_helper(ec, d);
    case SPARC64_OP3_UDIV:
    case SPARC64_OP3_SDIV:
    case SPARC64_OP3_POPC:
        return e_emit_alu_helper(ec, d);
    case SPARC64_OP3_ADDCC:
    case SPARC64_OP3_SUBCC:
    case SPARC64_OP3_ADDXCC:
    case SPARC64_OP3_SUBXCC:
        return e_emit_addsubcc(ec, d);
    case SPARC64_OP3_ANDCC:
    case SPARC64_OP3_ORCC:
    case SPARC64_OP3_XORCC:
    case SPARC64_OP3_ANDNCC:
    case SPARC64_OP3_ORNCC:
    case SPARC64_OP3_XORNCC:
        return e_emit_logiccc(ec, d);
    case SPARC64_OP3_UMULCC:
    case SPARC64_OP3_SMULCC:
    case SPARC64_OP3_UDIVCC:
    case SPARC64_OP3_SDIVCC:
    case SPARC64_OP3_TADDCC:
    case SPARC64_OP3_TSUBCC:
    case SPARC64_OP3_TADDCTV:
    case SPARC64_OP3_TSUBCTV:
    case SPARC64_OP3_MULSCC:
        return e_emit_alu_helper(ec, d);
    default:
        return false;
    }
}

/* Shifts. */
static bool e_emit_shift(sparc64_emit_ctx_t *ec, const sparc64_dec_t *d)
{
    sparc64_dbt_buf_t *b = ec->buf;
    unsigned s2 = ES1;
    e_ld64(b, ES0, d->rs1);
    if (d->is_imm != 0U) {
        sb_mov_imm64(b, ES1, ((uint64_t)d->imm) & 0xfffULL);
    } else {
        s2 = e_get_gpr(b, d->rs2);
    }
    if (d->xbit != 0U) {
        sb_ubfm(b, true, ES1, s2, 0U, 5U);
    } else {
        sb_ubfm(b, true, ES1, s2, 0U, 4U);
    }
    if (d->op3 == SPARC64_OP3_SLL) {
        sb_lslv(b, d->xbit != 0U, ES0, ES0, ES1);
    } else if (d->op3 == SPARC64_OP3_SRL) {
        sb_lsrv(b, d->xbit != 0U, ES0, ES0, ES1);
    } else if (d->op3 == SPARC64_OP3_SRA) {
        if (d->xbit != 0U) {
            sb_asrv(b, true, ES0, ES0, ES1);
        } else {
            sb_asrv(b, false, ES0, ES0, ES1);
            sb_sbfm64(b, ES0, ES0, 0U, 31U);
        }
    } else {
        return false;
    }
    e_st64(b, d->rd, ES0);
    return !b->overflow;
}
