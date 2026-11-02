/*
 * src/dbt/emit_cond.c — AArch64 condition emitter (Bicc/BPcc/BPr, MOVcc,
 * MOVr, Tcc, delay slots; Lane P13-5 split of emit_int.c)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Moved verbatim from emit_int.c (Phase 2, L2c) so emit_int.c stays
 * under the 900-line discipline. Contract unchanged (see emit_int.h):
 * x19 = ctx, scratch x9-x14, exits carry PC in x15 and reason in w16,
 * never x18. Lane P13-5 adds the live-NZCV fast path: when the block's
 * nzcv_state matches the branch width, Bicc/BPcc/MOVcc skip the
 * 17-instruction CCR-nibble reload + MSR and branch on the live host
 * flags with zero setup instructions.
 */

#include "dbt/emit_cond.h"

#include <stdint.h>

#include "dbt/emit_fp.h"
#include "dbt/emit_int.h"
#include "dbt/emit_mem.h"
#include "dbt/emit_priv.h"

/* SPARC cond -> AArch64 cond (V9 numbering matches the shared table). */
static const uint32_t e_a64_cond[16] = {
    14u, /* BN  -> never (folded statically) */
    0u, /* BE   -> EQ */
    13u, /* BLE  -> LE */
    11u, /* BL   -> LT */
    9u, /* BLEU -> LS */
    3u, /* BCS  -> CC (borrow) */
    4u, /* BNEG -> MI */
    6u, /* BVS  -> VS */
    14u, /* BA   -> AL */
    1u, /* BNE  -> NE */
    12u, /* BG   -> GT */
    10u, /* BGE  -> GE */
    8u, /* BGU  -> HI (carry) */
    2u, /* BCC  -> CS (no borrow) */
    5u, /* BPOS -> PL */
    7u /* BVC  -> VC */
};

/* Live-NZCV fast-path condition (Lane P13-5, Invariant 7): when the
 * block's nzcv_state matches use_xcc, map the SPARC condition onto the
 * live host flags with zero setup instructions. SUBcc carries
 * C = !borrow so all 16 conditions map directly. ADDcc shares the
 * carry convention only for the 10 non-carry conditions; the 4
 * carry-dependent ones (BCS, BCC, BLEU, BGU) fall back to the nibble
 * path. Logic cc leaves guest C = 0, V = 0 (TST sets host C = 0,
 * V = 0): the 8 N/Z conditions map directly, BLEU (C|Z = Z) maps to
 * EQ, BGU (!C&!Z = !Z) maps to NE, and the rest fall back. */
static bool nzcv_fast_cond(sparc64_dbt_buf_t *b, unsigned cond,
    bool use_xcc, unsigned *out)
{
    uint8_t st;
    bool xcc;
    unsigned c;
    if (b == NULL || out == NULL) {
        return false;
    }
    st = b->nzcv_state;
    if (st == SPARC64_NZCV_NONE) {
        return false;
    }
    xcc = (st == SPARC64_NZCV_ADD_XCC) ||
        (st == SPARC64_NZCV_SUB_XCC) ||
        (st == SPARC64_NZCV_LOGIC_XCC);
    if (xcc != use_xcc) {
        return false;
    }
    c = cond & 15U;
    if (st == SPARC64_NZCV_SUB_ICC || st == SPARC64_NZCV_SUB_XCC) {
        *out = e_a64_cond[c];
        return true;
    }
    if (st == SPARC64_NZCV_ADD_ICC || st == SPARC64_NZCV_ADD_XCC) {
        switch (c) {
        case 1U:
        case 2U:
        case 3U:
        case 6U:
        case 7U:
        case 9U:
        case 10U:
        case 11U:
        case 14U:
        case 15U:
            *out = e_a64_cond[c];
            return true;
        default:
            return false;
        }
    }
    switch (c) {
    case 1U:
    case 2U:
    case 3U:
    case 6U:
    case 9U:
    case 10U:
    case 11U:
    case 14U:
        *out = e_a64_cond[c];
        return true;
    case 4U:
        *out = 0U;
        return true;
    case 12U:
        *out = 1U;
        return true;
    default:
        return false;
    }
}

bool sparc64_delay_is_plain(const sparc64_dec_t *d)
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
    case SPARC64_ICLS_FPU:
        return true;
    default:
        return false;
    }
}

bool sparc64_emit_delay(sparc64_emit_ctx_t *ec)
{
    const sparc64_dec_t *d = ec->delay;
    if (d == NULL || !sparc64_delay_is_plain(d)) {
        return false;
    }
    /* Lane P13-5: no blanket cache clear. The GPR/FPR caches are
     * write-through and the callers snapshot them across the two delay
     * copies, so a SAVE/RESTORE delay only drops windowed GPR slots
     * (via sparc64_fast_win) while globals stay cached. */
    if (d->cls == (uint8_t)SPARC64_ICLS_FPU) {
        return sparc64_emit_fp(ec, d);
    }
    return sparc64_emit_int(ec, d);
}

/* Delay runs on this path (interp annul rules). */
bool sparc64_delay_runs(uint8_t cls, unsigned cond, bool taken,
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

/* Delay slot inlines (validated without emitting). */
static bool e_delay_plain(sparc64_emit_ctx_t *ec)
{
    return ec->delay != NULL && sparc64_delay_is_plain(ec->delay);
}

/* Integer MOVcc (%icc/%xcc and %fcc0..%fcc3). */
bool sparc64_emit_movcc(sparc64_emit_ctx_t *ec, const sparc64_dec_t *d)
{
    sparc64_dbt_buf_t *b = ec->buf;
    size_t p_skip;
    unsigned acond;
    if ((d->rd & 31U) == 0U) {
        return true;
    }
    if (d->cond == 8U) {
        e_src2(b, ES0, d);
        e_st64(b, d->rd, ES0);
        b->gpr_cache_valid &=
            (uint8_t)(~(1U << ((((unsigned)d->rd) & 31U) & 7U)));
        return !b->overflow;
    }
    if (d->cond == 0U) {
        return true;
    }
    if ((d->cc & 4U) != 0U) {
        unsigned idx = d->cc & 3U;
        unsigned sh = (idx == 0U) ? 10U : (30U + 2U * idx);
        size_t p_have;
        sb_ldst_imm(b, true, false, ES0, ECTX, 0x240U + idx * 4U);
        sb_ldst_imm(b, true, true, ES2, ECTX, SPARC64_CTX_FSR_OFFSET);
        sb_ubfm(b, true, ES2, ES2, sh, sh + 1U);
        p_have = sb_cbz_placeholder(b, false, true, ES0);
        if (p_have == SPARC64_DBT_NOPOS) {
            return false;
        }
        sb_orr_reg(b, false, ES0, 31U, ES2);
        sb_patch_cb(b, p_have, b->count);
        sb_ubfm(b, false, ES0, ES0, 0U, 1U);
        sb_mov_imm32(b, ES2, sparc64_fp_cond_mask(d->cond));
        sb_lsrv(b, false, ES2, ES2, ES0);
        sb_ubfm(b, false, ES2, ES2, 0U, 0U);
        e_src2(b, ES1, d);
        p_skip = sb_cbz_placeholder(b, false, false, ES2);
        if (p_skip == SPARC64_DBT_NOPOS) {
            return false;
        }
        e_st64(b, d->rd, ES1);
        sb_patch_cb(b, p_skip, b->count);
        b->gpr_cache_valid &=
            (uint8_t)(~(1U << ((((unsigned)d->rd) & 31U) & 7U)));
        return !b->overflow;
    }
    if (nzcv_fast_cond(b, d->cond, d->cc == 2U, &acond)) {
        e_src2(b, ES1, d);
        p_skip = sb_b_cond_placeholder(b, acond ^ 1U);
        if (p_skip == SPARC64_DBT_NOPOS) {
            return false;
        }
        e_st64(b, d->rd, ES1);
        sb_patch_b_cond(b, p_skip, acond ^ 1U, b->count);
        b->gpr_cache_valid &=
            (uint8_t)(~(1U << ((((unsigned)d->rd) & 31U) & 7U)));
        return !b->overflow;
    }
    sb_ldst_imm(b, true, true, ES0, ECTX, SPARC64_CTX_CCR_OFFSET);
    if (d->cc == 2U) {
        sb_ubfm(b, false, ES0, ES0, 4U, 7U);
    } else {
        sb_ubfm(b, false, ES0, ES0, 0U, 3U);
    }
    e_nib_to_flags(b, ES1, ES0, ES2);
    b->nzcv_state = SPARC64_NZCV_NONE;
    e_src2(b, ES1, d);
    p_skip = sb_b_cond_placeholder(b, e_a64_cond[d->cond & 15U] ^ 1U);
    if (p_skip == SPARC64_DBT_NOPOS) {
        return false;
    }
    e_st64(b, d->rd, ES1);
    sb_patch_b_cond(b, p_skip, e_a64_cond[d->cond & 15U] ^ 1U,
        b->count);
    b->gpr_cache_valid &= (uint8_t)(~(1U << ((((unsigned)d->rd) & 31U) & 7U)));
    return !b->overflow;
}

/* Integer MOVr. */
bool sparc64_emit_movr(sparc64_emit_ctx_t *ec, const sparc64_dec_t *d)
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
            b->nzcv_state = SPARC64_NZCV_NONE;
            take_cond = 13U;
            p_store = sb_b_cond_placeholder(b, take_cond);
            break;
        case 3U:
            sb_cmp_imm(b, true, ES0, 0U);
            b->nzcv_state = SPARC64_NZCV_NONE;
            take_cond = 11U;
            p_store = sb_b_cond_placeholder(b, take_cond);
            break;
        case 6U:
            sb_cmp_imm(b, true, ES0, 0U);
            b->nzcv_state = SPARC64_NZCV_NONE;
            take_cond = 12U;
            p_store = sb_b_cond_placeholder(b, take_cond);
            break;
        case 7U:
            sb_cmp_imm(b, true, ES0, 0U);
            b->nzcv_state = SPARC64_NZCV_NONE;
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
        if (p_done == SPARC64_DBT_NOPOS) {
            return false;
        }
        if (d->cond == 1U || d->cond == 5U) {
            sb_patch_cb(b, p_store, b->count);
        } else {
            sb_patch_b_cond(b, p_store, take_cond, b->count);
        }
    }
    e_st64(b, d->rd, ES1);
    sb_patch_b(b, p_done, b->count);
    b->gpr_cache_valid &= (uint8_t)(~(1U << ((((unsigned)d->rd) & 31U) & 7U)));
    return !b->overflow;
}

/* BPr rcond mapping. */
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

/* Bicc/BPcc/BPr. */
bool sparc64_emit_branch(sparc64_emit_ctx_t *ec, const sparc64_dec_t *d)
{
    sparc64_dbt_buf_t *b = ec->buf;
    uint64_t target = ec->pc + (uint64_t)d->disp;
    uint64_t fallthrough = ec->pc + 8U;
    bool annul = d->annul != 0U;
    bool is_bpr = d->cls == (uint8_t)SPARC64_ICLS_BPR;
    size_t p_taken = SPARC64_DBT_NOPOS;
    bool taken_is_cb = false;
    unsigned taken_cond = 0U;
    sparc64_dbt_cache_snap_t snap;
    if (!is_bpr && (d->cond == 8U || d->cond == 0U)) {
        bool taken = d->cond == 8U;
        uint64_t dest = taken ? target : fallthrough;
        if (!sparc64_delay_runs(d->cls, d->cond, taken, annul)) {
            e_exit_imm(b, dest, SPARC64_EXIT_BRANCH);
            return !b->overflow;
        }
        if (!e_delay_plain(ec)) {
            return false;
        }
        if (!sparc64_emit_delay(ec)) {
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
            b->nzcv_state = SPARC64_NZCV_NONE;
        }
        taken_cond = e_bpr_cond(d->cond, &taken_is_cb);
        if (taken_is_cb) {
            p_taken = sb_cbz_placeholder(b, true, d->cond == 5U,
                ES0);
        } else {
            p_taken = sb_b_cond_placeholder(b, taken_cond);
        }
    } else {
        bool use_xcc = false;
        if (d->cls == (uint8_t)SPARC64_ICLS_BPCC && d->cc == 2U) {
            use_xcc = true;
        }
        if (!nzcv_fast_cond(b, d->cond, use_xcc, &taken_cond)) {
            unsigned shift = 0U;
            if (use_xcc) {
                shift = 4U;
            }
            sb_ldst_imm(b, true, true, ES0, ECTX, SPARC64_CTX_CCR_OFFSET);
            sb_ubfm(b, false, ES0, ES0, shift, shift + 3U);
            e_nib_to_flags(b, ES1, ES0, ES2);
            b->nzcv_state = SPARC64_NZCV_NONE;
            taken_cond = e_a64_cond[d->cond & 15U];
        }
        p_taken = sb_b_cond_placeholder(b, taken_cond);
    }
    if (p_taken == SPARC64_DBT_NOPOS) {
        return false;
    }
    /* Snapshot the write-through caches: the taken delay copy below
     * must compile against this pre-branch state, not the state the
     * not-taken copy leaves behind (the two execute exclusively). */
    e_cache_snapshot(b, &snap);
    if (sparc64_delay_runs(d->cls, d->cond, false, annul)) {
        if (!sparc64_emit_delay(ec)) {
            return false;
        }
    }
    e_exit_imm(b, fallthrough, SPARC64_EXIT_BRANCH);
    if (taken_is_cb) {
        sb_patch_cb(b, p_taken, b->count);
    } else {
        sb_patch_b_cond(b, p_taken, taken_cond, b->count);
    }
    e_cache_restore(b, &snap);
    if (sparc64_delay_runs(d->cls, d->cond, true, annul)) {
        if (!sparc64_emit_delay(ec)) {
            return false;
        }
    }
    e_exit_imm(b, target, SPARC64_EXIT_BRANCH);
    return !b->overflow;
}

/* Linux SPARC64 trap base: ta 0x6d syscall, 0x6e setjmp, 0x6f longjmp. */
#define E_SYSCALL_NUM 0x6dU

/* Tcc. */
bool sparc64_emit_tcc(sparc64_emit_ctx_t *ec, const sparc64_dec_t *d)
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
    e_nib_to_flags(b, ES1, ES0, ES2);
    b->nzcv_state = SPARC64_NZCV_NONE;
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
    sb_mov_imm64(b, ES1, (uint64_t)E_SYSCALL_NUM);
    sb_sub_reg(b, true, false, ES0, ES0, ES1);
    sb_cmp_imm(b, true, ES0, 2U);
    p_syscall = sb_b_cond_placeholder(b, 9U);
    e_fault_here(b, ec->fault_pc);
    sb_patch_b_cond(b, p_syscall, 9U, b->count);
    sb_ldst_imm(b, true, true, ES0, ECTX, SPARC64_G1 * 8U);
    sb_ldst_imm(b, false, false, ES0, ECTX, E_OFF_EXIT_ARG);
    e_exit_imm(b, ec->pc, SPARC64_EXIT_SYSCALL);
    if (p_taken != SPARC64_DBT_NOPOS) {
        sb_patch_b_cond(b, p_taken, e_a64_cond[d->cond & 15U],
            b->count);
    }
    return !b->overflow;
}
