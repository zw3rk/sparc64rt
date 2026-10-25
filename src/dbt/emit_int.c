/*
 * src/dbt/emit_int.c — AArch64 integer instruction emitter (Phase 2, L2c)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Integer emitter with interpreter-identical semantics (--difftest).
 * Inline: SETHI, ALU + dual icc/xcc, ADDX/SUBX + cc (carry from icc.C),
 * MULX/UMUL/SMUL, UDIVX/SDIVX/UDIV/SDIV (+cc, divide-by-zero trap,
 * SDIV saturation), POPC (helper), TADD/TSUB (+TV trap), MULSCC,
 * shifts (SLL/SRL full-64, SRA sign-31/63), MOVcc (csel-free branch),
 * MOVr, RDASR/WRASR user state, ALIGNADDR, CALL/Bicc/BPcc/BPr/JMPL/
 * RETURN with delay slots + annul, Tcc (syscall gate). Helpers
 * (emit_priv.h): loads/stores/LDSTUB/SWAP/CASA/CASXA (alignment +
 * ASI + big-endian + mem callbacks via the interp backend),
 * SAVE/RESTORE (shared interp window file). Misaligned multi-byte
 * access faults, never emulates; PRIV/FPU/FBR/odd encodings return
 * false for dispatcher fallback. Contract: x19 = ctx, scratch
 * x9-x14, exits carry PC in x15 and reason in w16; never x18.
 */

#include "dbt/emit_int.h"

#include <stdint.h>

#include "dbt/emit_priv.h"



/* Linux SPARC64 syscall trap number (ta 0x6d; decode.h names it
 * SPARC64_TRAP_SYSCALL_NUM, which lives outside the frozen interp.h). */
#define E_SYSCALL_NUM 0x6dU

static bool e_emit_alu(sparc64_emit_ctx_t *ec, const sparc64_dec_t *d);
static bool e_emit_shift(sparc64_emit_ctx_t *ec, const sparc64_dec_t *d);

/* SPARC cond -> AArch64 cond (V9 numbering matches the shared table). */
static const uint32_t e_a64_cond[16] = {
    14u, /* BN  -> never (folded statically) */
    0u, /* BE   -> EQ */
    13u, /* BLE  -> LE */
    11u, /* BL   -> LT */
    9u, /* BLEU -> LS */
    2u, /* BCS  -> CS */
    4u, /* BNEG -> MI */
    6u, /* BVS  -> VS */
    14u, /* BA   -> AL */
    1u, /* BNE  -> NE */
    12u, /* BG   -> GT */
    10u, /* BGE  -> GE */
    8u, /* BGU  -> HI */
    3u, /* BCC  -> CC */
    5u, /* BPOS -> PL */
    7u /* BVC  -> VC */
};

/* ---- delay slots ---------------------------------------------------------
 * The delay instruction executes unless annulled away; its faults replay
 * through the interpreter at the CTI address (ec->fault_pc already holds
 * the CTI address, so no pc adjustment is needed). A CTI, Tcc, priv,
 * FPU, FBR, or illegal delay slot cannot be inlined: return false for a
 * pristine fallback and let the dispatcher replay via sparc64_step.
 */

static bool e_delay_is_plain(const sparc64_dec_t *d)
{
    switch (d->cls) {
    case SPARC64_ICLS_SETHI:
    case SPARC64_ICLS_ALU:
    case SPARC64_ICLS_SHIFT:
    case SPARC64_ICLS_MOVCC:
    case SPARC64_ICLS_MOVR:
    case SPARC64_ICLS_RDASR:
    case SPARC64_ICLS_WRASR:
    case SPARC64_ICLS_MEMBAR:
    case SPARC64_ICLS_FLUSH:
    case SPARC64_ICLS_ALIGN:
    case SPARC64_ICLS_LOAD:
    case SPARC64_ICLS_STORE:
    case SPARC64_ICLS_LDSTUB:
    case SPARC64_ICLS_SWAP:
    case SPARC64_ICLS_ATOMIC:
    case SPARC64_ICLS_SAVE:
    case SPARC64_ICLS_RESTORE:
        return true;
    default:
        return false;
    }
}

static bool e_emit_one(sparc64_emit_ctx_t *ec, const sparc64_dec_t *d);

static bool e_emit_delay(sparc64_emit_ctx_t *ec)
{
    const sparc64_dec_t *d = ec->delay;
    if (d == NULL || !e_delay_is_plain(d)) {
        return false;
    }
    return e_emit_one(ec, d);
}

/* True when the delay slot runs on this path (interp annul rules). */
static bool e_delay_runs(uint8_t cls, unsigned cond, bool taken,
    bool annul)
{
    if (taken) {
        if (annul && cond == 8U && cls != (uint8_t)SPARC64_ICLS_BPR) {
            return false;
        }
        return true;
    }
    return !annul;
}

/* ---- per-class emitters ------------------------------------------------- */

static bool e_emit_sethi(sparc64_emit_ctx_t *ec, const sparc64_dec_t *d)
{
    sparc64_dbt_buf_t *b = ec->buf;
    sb_mov_imm32(b, ES0, d->uimm << 10);
    e_st64(b, d->rd, ES0);
    return !b->overflow;
}

/* Complex ALU via the translator helper: x0=ctx x1=op3 x2=rs1
 * x3=rs2-or-imm32 x4=is_imm x5=rd x6=pc, then BLR s64_rt_alu with the
 * UNDEF fault path. The reference backend sets Y/cc/traps. */
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
    e_ld64(b, ES0, d->rs1);
    e_src2(b, ES1, d);
    switch (d->op3) {
    case SPARC64_OP3_ADD:
        sb_add_reg(b, true, false, ES0, ES0, ES1);
        break;
    case SPARC64_OP3_AND:
        sb_logic_reg(b, UINT32_C(0x8a000000), ES0, ES0, ES1);
        break;
    case SPARC64_OP3_OR:
        sb_orr_reg(b, true, ES0, ES0, ES1);
        break;
    case SPARC64_OP3_XOR:
        sb_eor_reg(b, true, ES0, ES0, ES1);
        break;
    case SPARC64_OP3_SUB:
        sb_sub_reg(b, true, false, ES0, ES0, ES1);
        break;
    case SPARC64_OP3_ANDN:
        sb_bic_reg(b, true, ES0, ES0, ES1);
        break;
    case SPARC64_OP3_ORN:
        sb_orn_reg(b, true, ES0, ES0, ES1);
        break;
    case SPARC64_OP3_XORN:
        sb_orn_reg(b, true, ES2, 31U, ES1);
        sb_eor_reg(b, true, ES0, ES0, ES2);
        break;
    case SPARC64_OP3_ADDX:
        e_load_carry(b, ES2);
        e_seed_carry_add(b, ES2);
        e_ld64(b, ES0, d->rs1);
        e_src2(b, ES1, d);
        sb_adc(b, false, ES0, ES0, ES1);
        break;
    case SPARC64_OP3_SUBX:
        e_load_carry(b, ES2);
        e_seed_carry_sub(b, ES2);
        e_ld64(b, ES0, d->rs1);
        e_src2(b, ES1, d);
        sb_sbc(b, false, ES0, ES0, ES1);
        break;
    case SPARC64_OP3_MULX:
        sb_mul(b, ES0, ES0, ES1);
        break;
    default:
        return false;
    }
    e_st64(b, d->rd, ES0);
    return !b->overflow;
}




/* ADDCC/SUBCC/ADDXCC/SUBXCC: dual-width carry/borrow with icc from the
 * low 32 bits and xcc from the full 64 bits. */
static bool e_emit_addsubcc(sparc64_emit_ctx_t *ec,
    const sparc64_dec_t *d)
{
    sparc64_dbt_buf_t *b = ec->buf;
    bool is_sub = d->op3 == SPARC64_OP3_SUBCC ||
        d->op3 == SPARC64_OP3_SUBXCC;
    bool with_carry = d->op3 == SPARC64_OP3_ADDXCC ||
        d->op3 == SPARC64_OP3_SUBXCC;
    if (with_carry) {
        e_load_carry(b, ES2);
    }
    e_ld64(b, ES0, d->rs1);
    e_src2(b, ES1, d);
    /* The flag-setting ops below consume the host carry, so the
     * carry is reseeded from icc.C before each width. */
    if (with_carry) {
        if (is_sub) {
            e_seed_carry_sub(b, ES2);
        } else {
            e_seed_carry_add(b, ES2);
        }
    }
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
    e_host_to_nibble(b, ES3, ES2);
    if (with_carry) {
        if (is_sub) {
            e_seed_carry_sub(b, ES2);
        } else {
            e_seed_carry_add(b, ES2);
        }
    }
    if (is_sub) {
        if (with_carry) {
            sb_sbc(b, true, ES0, ES0, ES1);
        } else {
            sb_sub_reg(b, false, true, ES0, ES0, ES1);
        }
    } else {
        if (with_carry) {
            sb_adc(b, true, ES0, ES0, ES1);
        } else {
            sb_add_reg(b, false, true, ES0, ES0, ES1);
        }
    }
    e_host_to_nibble(b, ES4, ES2);
    e_merge_cc(b, ES4, ES3, ES2);
    e_st64(b, d->rd, ES0);
    return !b->overflow;
}

/* Logic cc ops: N/Z from bit 31 / low32-zero (icc) and bit 63 /
 * full-zero (xcc); V and C are clear. */
static bool e_emit_logiccc(sparc64_emit_ctx_t *ec,
    const sparc64_dec_t *d)
{
    sparc64_dbt_buf_t *b = ec->buf;
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
    sb_ands_reg(b, true, 31U, ES0, ES0);
    e_host_to_nibble(b, ES3, ES2);
    sb_ands_reg(b, false, 31U, ES0, ES0);
    e_host_to_nibble(b, ES4, ES2);
    e_merge_cc(b, ES4, ES3, ES2);
    e_st64(b, d->rd, ES0);
    return !b->overflow;
}





/* Integer MOVcc: conditional move selected by the icc/xcc nibble. */
static bool e_emit_movcc(sparc64_emit_ctx_t *ec, const sparc64_dec_t *d)
{
    sparc64_dbt_buf_t *b = ec->buf;
    size_t p_skip;
    if ((d->rd & 31U) == 0U) {
        return true;
    }
    if (d->cond == 8U) {
        e_src2(b, ES0, d);
        e_st64(b, d->rd, ES0);
        return !b->overflow;
    }
    if (d->cond == 0U) {
        return true;
    }
    sb_ldst_imm(b, true, true, ES0, ECTX, SPARC64_CTX_CCR_OFFSET);
    if (d->cc == 2U) {
        sb_ubfm(b, false, ES0, ES0, 4U, 7U);
    } else {
        sb_ubfm(b, false, ES0, ES0, 0U, 3U);
    }
    e_nib_to_flags(b, ES0, ES0, ES1);
    e_src2(b, ES1, d);
    p_skip = sb_b_cond_placeholder(b, e_a64_cond[d->cond & 15U] ^ 1U);
    e_st64(b, d->rd, ES1);
    sb_patch_b_cond(b, p_skip, e_a64_cond[d->cond & 15U] ^ 1U,
        b->count);
    return !b->overflow;
}

/* Integer MOVr: conditional move selected by the full 64-bit register. */
static bool e_emit_movr(sparc64_emit_ctx_t *ec, const sparc64_dec_t *d)
{
    sparc64_dbt_buf_t *b = ec->buf;
    size_t p_store;
    size_t p_done;
    if ((d->rd & 31U) == 0U) {
        return true;
    }
    e_ld64(b, ES0, d->rs1);
    e_src2(b, ES1, d);
    {
        unsigned take_cond = 0U;
        switch (d->cond) {
        case 1U:
            p_store = sb_cbz_placeholder(b, true, false, ES0);
            break;
        case 5U:
            p_store = sb_cbz_placeholder(b, true, true, ES0);
            break;
        case 2U:
            sb_cmp_imm(b, true, ES0, 0U);
            take_cond = 13U;
            p_store = sb_b_cond_placeholder(b, take_cond);
            break;
        case 3U:
            sb_cmp_imm(b, true, ES0, 0U);
            take_cond = 11U;
            p_store = sb_b_cond_placeholder(b, take_cond);
            break;
        case 6U:
            sb_cmp_imm(b, true, ES0, 0U);
            take_cond = 12U;
            p_store = sb_b_cond_placeholder(b, take_cond);
            break;
        case 7U:
            sb_cmp_imm(b, true, ES0, 0U);
            take_cond = 10U;
            p_store = sb_b_cond_placeholder(b, take_cond);
            break;
        default:
            return false;
        }
        if (p_store == SPARC64_DBT_NOPOS) {
            return false;
        }
        p_done = sb_b_placeholder(b);
        if (d->cond == 1U || d->cond == 5U) {
            sb_patch_cb(b, p_store, b->count);
        } else {
            sb_patch_b_cond(b, p_store, take_cond, b->count);
        }
    }
    e_st64(b, d->rd, ES1);
    sb_patch_b(b, p_done, b->count);
    return !b->overflow;
}

/* User state registers: %y/%ccr/%asi/%fprs/%gsr. Other numbers are
 * privileged or illegal and fall back. */
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

/* ALIGNADDR/ALIGNADDRL: rd = sum & ~7, GSR low 3 bits = sum & 7. */
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

/* True when the delay slot can be inlined (validated without
 * emitting, so the caller stays pristine on fallback). */
static bool e_delay_plain(sparc64_emit_ctx_t *ec)
{
    return ec->delay != NULL && e_delay_is_plain(ec->delay);
}

/* CALL: %o7 = pc, delay runs, pc += disp. Pristine fallback when the
 * delay cannot be inlined. The link write precedes the delay, matching
 * the reference model (a delay reading %o7 sees the new value). */
static bool e_emit_call(sparc64_emit_ctx_t *ec, const sparc64_dec_t *d)
{
    sparc64_dbt_buf_t *b = ec->buf;
    uint64_t target;
    if (!e_delay_plain(ec)) {
        return false;
    }
    sb_mov_imm64(b, ES0, ec->pc);
    sb_ldst_imm(b, false, true, ES0, ECTX, SPARC64_O7 * 8U);
    if (!e_emit_delay(ec)) {
        return false;
    }
    target = ec->pc + (uint64_t)d->disp;
    b->is_call = true;
    e_exit_imm(b, target, SPARC64_EXIT_BRANCH);
    return !b->overflow;
}

/* AArch64 condition taken by a BPr rcond (cbz/cbnz/b.cond forms report
 * through the same patch kind the emitter used). */
static unsigned e_bpr_cond(unsigned rcond, bool *is_cb)
{
    *is_cb = (rcond == 1U || rcond == 5U);
    if (rcond == 1U || rcond == 5U) {
        return rcond;
    }
    if (rcond == 2U) {
        return 13U;
    }
    if (rcond == 3U) {
        return 11U;
    }
    if (rcond == 6U) {
        return 12U;
    }
    return 10U;
}

/* Bicc/BPcc/BPr: condition, annul, delay, pc/npc update per the
 * reference model. Pristine fallback when the delay is not plain. */
static bool e_emit_branch(sparc64_emit_ctx_t *ec, const sparc64_dec_t *d)
{
    sparc64_dbt_buf_t *b = ec->buf;
    uint64_t target = ec->pc + (uint64_t)d->disp;
    uint64_t fallthrough = ec->pc + 8U;
    bool annul = d->annul != 0U;
    bool is_bpr = d->cls == (uint8_t)SPARC64_ICLS_BPR;
    size_t p_taken = SPARC64_DBT_NOPOS;
    bool taken_is_cb = false;
    unsigned taken_cond = 0U;
    if (!is_bpr && (d->cond == 8U || d->cond == 0U)) {
        bool taken = d->cond == 8U;
        uint64_t dest = taken ? target : fallthrough;
        if (!e_delay_runs(d->cls, d->cond, taken, annul)) {
            e_exit_imm(b, dest, SPARC64_EXIT_BRANCH);
            return !b->overflow;
        }
        if (!e_delay_plain(ec)) {
            return false;
        }
        if (!e_emit_delay(ec)) {
            return false;
        }
        e_exit_imm(b, dest, SPARC64_EXIT_BRANCH);
        return !b->overflow;
    }
    if (!e_delay_plain(ec)) {
        return false;
    }
    if (is_bpr) {
        if (d->cond != 1U && d->cond != 2U && d->cond != 3U &&
            d->cond != 5U && d->cond != 6U && d->cond != 7U) {
            return false;
        }
        e_ld64(b, ES0, d->rs1);
        if (d->cond == 2U || d->cond == 3U || d->cond == 6U ||
            d->cond == 7U) {
            sb_cmp_imm(b, true, ES0, 0U);
        }
        taken_cond = e_bpr_cond(d->cond, &taken_is_cb);
        if (taken_is_cb) {
            p_taken = sb_cbz_placeholder(b, true, d->cond == 5U,
                ES0);
        } else {
            p_taken = sb_b_cond_placeholder(b, taken_cond);
        }
    } else {
        unsigned shift = 0U;
        if (d->cls == (uint8_t)SPARC64_ICLS_BPCC && d->cc == 2U) {
            shift = 4U;
        }
        sb_ldst_imm(b, true, true, ES0, ECTX, SPARC64_CTX_CCR_OFFSET);
        sb_ubfm(b, false, ES0, ES0, shift, shift + 3U);
        e_nib_to_flags(b, ES0, ES0, ES1);
        taken_cond = e_a64_cond[d->cond & 15U];
        p_taken = sb_b_cond_placeholder(b, taken_cond);
    }
    if (p_taken == SPARC64_DBT_NOPOS) {
        return false;
    }
    if (e_delay_runs(d->cls, d->cond, false, annul)) {
        if (!e_emit_delay(ec)) {
            return false;
        }
    }
    e_exit_imm(b, fallthrough, SPARC64_EXIT_BRANCH);
    if (taken_is_cb) {
        sb_patch_cb(b, p_taken, b->count);
    } else {
        sb_patch_b_cond(b, p_taken, taken_cond, b->count);
    }
    if (e_delay_runs(d->cls, d->cond, true, annul)) {
        if (!e_emit_delay(ec)) {
            return false;
        }
    }
    e_exit_imm(b, target, SPARC64_EXIT_BRANCH);
    return !b->overflow;
}

/* JMPL/RETURN: misaligned targets trap, rd = pc precedes the delay,
 * then the transfer. Pristine fallback when the delay is not plain. */
static bool e_emit_jmpl(sparc64_emit_ctx_t *ec, const sparc64_dec_t *d)
{
    sparc64_dbt_buf_t *b = ec->buf;
    size_t p_misaligned;
    if (!e_delay_plain(ec)) {
        return false;
    }
    e_ld64(b, ES0, d->rs1);
    e_src2(b, ES1, d);
    sb_add_reg(b, true, false, ES0, ES0, ES1);
    sb_ubfm(b, false, ES1, ES0, 0U, 1U);
    p_misaligned = sb_cbz_placeholder(b, false, true, ES1);
    sb_mov_imm64(b, ES1, ec->pc);
    e_st64(b, d->rd, ES1);
    if (!e_emit_delay(ec)) {
        return false;
    }
    if (d->rd == SPARC64_O7) {
        b->is_call = true;
    }
    /* Recompute the target: the delay slot may use the scratch set. */
    e_ld64(b, ES0, d->rs1);
    e_src2(b, ES1, d);
    sb_add_reg(b, true, false, ES0, ES0, ES1);
    sb_mov_reg(b, true, EPC, ES0);
    sb_mov_imm32(b, ERSN, SPARC64_EXIT_BRANCH);
    sb_ret(b);
    sb_patch_cb(b, p_misaligned, b->count);
    e_fault_here(b, ec->fault_pc);
    return !b->overflow;
}

/* Tcc: false conditions fall through; a true 0x6d trap number is the
 * syscall gate (%g1 to exit_arg), any other true trap number replays
 * through the interpreter. */
static bool e_emit_tcc(sparc64_emit_ctx_t *ec, const sparc64_dec_t *d)
{
    sparc64_dbt_buf_t *b = ec->buf;
    size_t p_taken;
    size_t p_syscall;
    if (d->cond == 0U) {
        return true;
    }
    sb_ldst_imm(b, true, true, ES0, ECTX, SPARC64_CTX_CCR_OFFSET);
    if (d->cc == 2U) {
        sb_ubfm(b, false, ES0, ES0, 4U, 7U);
    } else {
        sb_ubfm(b, false, ES0, ES0, 0U, 3U);
    }
    e_nib_to_flags(b, ES0, ES0, ES1);
    if (d->cond == 8U) {
        p_taken = SPARC64_DBT_NOPOS;
    } else {
        p_taken = sb_b_cond_placeholder(b, e_a64_cond[d->cond & 15U]);
        if (p_taken == SPARC64_DBT_NOPOS) {
            return false;
        }
        e_exit_imm(b, ec->pc + 4U, SPARC64_EXIT_BRANCH);
    }
    if (d->is_imm != 0U) {
        sb_mov_imm64(b, ES0, (uint64_t)d->imm);
    } else {
        e_ld64(b, ES0, d->rs1);
        e_src2(b, ES1, d);
        sb_add_reg(b, true, false, ES0, ES0, ES1);
        sb_ubfm(b, true, ES0, ES0, 0U, 6U);
    }
    sb_cmp_imm(b, true, ES0, (uint16_t)E_SYSCALL_NUM);
    p_syscall = sb_b_cond_placeholder(b, 0U);
    e_fault_here(b, ec->fault_pc);
    sb_patch_b_cond(b, p_syscall, 0U, b->count);
    sb_ldst_imm(b, true, true, ES0, ECTX, SPARC64_G1 * 8U);
    sb_ldst_imm(b, false, false, ES0, ECTX, E_OFF_EXIT_ARG);
    e_exit_imm(b, ec->pc, SPARC64_EXIT_SYSCALL);
    if (p_taken != SPARC64_DBT_NOPOS) {
        sb_patch_b_cond(b, p_taken, e_a64_cond[d->cond & 15U],
            b->count);
    }
    return !b->overflow;
}

/* Loads, stores, and atomics funnel through the checked backend:
 * alignment and ASI faults replay through the interpreter. */
static bool e_emit_mem(sparc64_emit_ctx_t *ec, const sparc64_dec_t *d)
{
    size_t p_fault;
    if (ec->mem == NULL) {
        return false;
    }
    p_fault = e_call_mem(ec, d);
    if (p_fault == SPARC64_DBT_NOPOS) {
        return false;
    }
    e_resolve_fault(ec, p_fault);
    return !ec->buf->overflow;
}

/* SAVE/RESTORE funnel through the shared window file. */
static bool e_emit_win(sparc64_emit_ctx_t *ec, const sparc64_dec_t *d,
    bool is_save)
{
    sparc64_dbt_buf_t *b = ec->buf;
    size_t p_fault;
    if (ec->mem == NULL) {
        return false;
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
        return e_emit_movcc(ec, d);
    case SPARC64_ICLS_MOVR:
        return e_emit_movr(ec, d);
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
        return e_emit_branch(ec, d);
    case SPARC64_ICLS_JMPL:
    case SPARC64_ICLS_RETURN:
        return e_emit_jmpl(ec, d);
    case SPARC64_ICLS_TCC:
        return e_emit_tcc(ec, d);
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

/* Shifts: SLL/SRL shift the full 64 bits; SRA sign-extends bit 31
 * (plain) or bit 63 (X forms). Counts mask to 5/6 bits. */
static bool e_emit_shift(sparc64_emit_ctx_t *ec, const sparc64_dec_t *d)
{
    sparc64_dbt_buf_t *b = ec->buf;
    e_ld64(b, ES0, d->rs1);
    if (d->is_imm != 0U) {
        sb_mov_imm64(b, ES1, ((uint64_t)d->imm) & 0xfffULL);
    } else {
        e_ld64(b, ES1, d->rs2);
    }
    if (d->xbit != 0U) {
        sb_ubfm(b, true, ES1, ES1, 0U, 5U);
    } else {
        sb_ubfm(b, true, ES1, ES1, 0U, 4U);
    }
    if (d->op3 == SPARC64_OP3_SLL) {
        sb_lslv(b, true, ES0, ES0, ES1);
    } else if (d->op3 == SPARC64_OP3_SRL) {
        sb_lsrv(b, true, ES0, ES0, ES1);
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
