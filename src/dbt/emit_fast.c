/*
 * src/dbt/emit_fast.c — Lane P5 inline MUL/DIV + SAVE/RESTORE fast path.
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * UMUL/SMUL lower to UMULL/SMULL with Y = high 32; UDIVX/SDIVX check
 * divide-by-zero (plus the INT64_MIN / -1 saturation) inline and trap
 * via UNDEF exactly like the helper. SAVE/RESTORE with no spill/fill
 * shuffle the shared window file inline (cansave > 0 / canrestore > 0
 * plus the validity gate); every other case funnels through the
 * existing s64_rt_win helper, so semantics match by construction.
 */

#include "dbt/emit_fast.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "core/cpu.h"
#include "dbt/emit_priv.h"

/* Window-file bases (interp_win.c, Lane P5 accessors). */
extern uint64_t *sparc64_win_file_base(void);
extern uint64_t *sparc64_win_sp_base(void);
extern bool *sparc64_win_valid_base(void);

/* LDRB Wt,[Xn] / STRB Wt,[Xn] (zero offset). */
static void f_ldrb(sparc64_dbt_buf_t *b, unsigned wt, unsigned xn)
{
    sb_word(b, UINT32_C(0x39400000) | ((xn & 31U) << 5) | (wt & 31U));
}

static void f_strb(sparc64_dbt_buf_t *b, unsigned wt, unsigned xn)
{
    sb_word(b, UINT32_C(0x39000000) | ((xn & 31U) << 5) | (wt & 31U));
}

/* UMULL/SMULL xD, wN, wM (Ra = xzr): full 64-bit product. */
static void f_mull(sparc64_dbt_buf_t *b, bool is_signed, unsigned xd,
    unsigned wn, unsigned wm)
{
    uint32_t base = is_signed ? UINT32_C(0x9b200000) :
        UINT32_C(0x9ba00000);
    sb_word(b, base | ((wm & 31U) << 16) | (31U << 10) |
        ((wn & 31U) << 5) | (xd & 31U));
}

bool sparc64_fast_alu(sparc64_emit_ctx_t *ec, const sparc64_dec_t *d)
{
    sparc64_dbt_buf_t *b;
    uint32_t op3;
    if (ec == NULL || ec->buf == NULL || d == NULL) {
        return false;
    }
    b = ec->buf;
    op3 = d->op3;
    e_ld64(b, ES0, d->rs1);
    e_src2(b, ES1, d);
    if (op3 == (uint32_t)SPARC64_OP3_UMUL ||
        op3 == (uint32_t)SPARC64_OP3_SMUL) {
        f_mull(b, op3 == (uint32_t)SPARC64_OP3_SMUL, ES2, ES0, ES1);
        sb_ubfm(b, true, ES3, ES2, 32U, 63U);
        sb_ldst_imm(b, false, true, ES3, ECTX, E_OFF_Y);
        e_st64(b, d->rd, ES2);
        return !b->overflow;
    }
    if (op3 == (uint32_t)SPARC64_OP3_UDIVX ||
        op3 == (uint32_t)SPARC64_OP3_SDIVX) {
        size_t p_ok;
        p_ok = sb_cbz_placeholder(b, true, true, ES1);
        if (p_ok == SPARC64_DBT_NOPOS) {
            return false;
        }
        e_fault_here(b, ec->fault_pc);
        sb_patch_cb(b, p_ok, b->count);
        if (op3 == (uint32_t)SPARC64_OP3_SDIVX) {
            size_t p_notmin;
            size_t p_notm1;
            size_t p_done;
            sb_mov_imm64(b, ES2, UINT64_C(0x8000000000000000));
            sb_cmp_reg(b, ES0, ES2);
            p_notmin = sb_b_cond_placeholder(b, 1U);
            if (p_notmin == SPARC64_DBT_NOPOS) {
                return false;
            }
            sb_mov_imm32(b, ES2, 1U);
            sb_add_reg(b, true, true, 31U, ES1, ES2);
            p_notm1 = sb_b_cond_placeholder(b, 1U);
            if (p_notm1 == SPARC64_DBT_NOPOS) {
                return false;
            }
            sb_mov_imm64(b, ES0, UINT64_C(0x8000000000000000));
            p_done = sb_b_placeholder(b);
            if (p_done == SPARC64_DBT_NOPOS) {
                return false;
            }
            sb_patch_b_cond(b, p_notmin, 1U, b->count);
            sb_patch_b_cond(b, p_notm1, 1U, b->count);
            sb_sdiv(b, ES0, ES0, ES1);
            sb_patch_b(b, p_done, b->count);
        } else {
            sb_udiv(b, ES0, ES0, ES1);
        }
        e_st64(b, d->rd, ES0);
        return !b->overflow;
    }
    return false;
}

/* Emitter scratch discipline: ES0 carries the SAVE/RESTORE sum, ES1 the
 * current cwp and ERSN the target window across the shuffle; ES2-ES5
 * and EPC are free temporaries. */

/* Compute winfile window address: xdst = base + (xidx << shift). */
static void f_win_addr(sparc64_dbt_buf_t *b, unsigned xdst, uint64_t base,
    unsigned xidx, unsigned shift)
{
    sb_mov_imm64(b, xdst, base);
    sb_mov_imm32(b, ES5, shift);
    sb_lslv(b, true, ES2, xidx, ES5);
    sb_add_reg(b, true, false, xdst, xdst, ES2);
}

static void f_move4(sparc64_dbt_buf_t *b, unsigned dst_base_reg,
    unsigned dst_first, unsigned src_base_reg, unsigned src_first)
{
    unsigned i;
    for (i = 0U; i < 4U; i++) {
        sb_ldst_imm(b, true, true, ES2 + i, src_base_reg,
            (src_first + i) * 8U);
    }
    for (i = 0U; i < 4U; i++) {
        sb_ldst_imm(b, false, true, ES2 + i, dst_base_reg,
            (dst_first + i) * 8U);
    }
}

bool sparc64_fast_win(sparc64_emit_ctx_t *ec, const sparc64_dec_t *d,
    bool is_save)
{
    sparc64_dbt_buf_t *b;
    size_t p_slow1;
    size_t p_slow2;
    size_t p_end;
    size_t p_fault;
    if (ec == NULL || ec->buf == NULL || d == NULL || ec->mem == NULL) {
        return false;
    }
    b = ec->buf;
    e_ld64(b, ES0, d->rs1);
    e_src2(b, ES1, d);
    sb_add_reg(b, true, false, ES0, ES0, ES1);
    sb_ldst_imm(b, true, false, ES1, ECTX, 0x250U);
    if (is_save) {
        sb_add_imm12(b, ERSN, ES1, 7U);
    } else {
        sb_add_imm12(b, ERSN, ES1, 1U);
    }
    sb_ubfm(b, false, ERSN, ERSN, 0U, 2U);
    if (is_save) {
        sb_ldst_imm(b, true, false, ES3, ECTX, 0x254U);
        p_slow1 = sb_cbz_placeholder(b, false, false, ES3);
        if (p_slow1 == SPARC64_DBT_NOPOS) {
            return false;
        }
        sb_mov_imm64(b, ES4, (uint64_t)(uintptr_t)sparc64_win_valid_base());
        sb_add_reg(b, true, false, ES4, ES4, ERSN);
        f_ldrb(b, ES3, ES4);
        p_slow2 = sb_cbz_placeholder(b, false, true, ES3);
        if (p_slow2 == SPARC64_DBT_NOPOS) {
            return false;
        }
    } else {
        sb_ldst_imm(b, true, false, ES3, ECTX, 0x258U);
        p_slow1 = sb_cbz_placeholder(b, false, false, ES3);
        if (p_slow1 == SPARC64_DBT_NOPOS) {
            return false;
        }
        sb_mov_imm64(b, ES4, (uint64_t)(uintptr_t)sparc64_win_valid_base());
        sb_add_reg(b, true, false, ES4, ES4, ERSN);
        f_ldrb(b, ES3, ES4);
        p_slow2 = sb_cbz_placeholder(b, false, false, ES3);
        if (p_slow2 == SPARC64_DBT_NOPOS) {
            return false;
        }
    }
    if (b->overflow) {
        return false;
    }
    {
        unsigned i;
        /* winfile[cwp] = L/I image. */
        f_win_addr(b, ES4,
            (uint64_t)(uintptr_t)sparc64_win_file_base(), ES1, 7U);
        for (i = 0U; i < 16U; i++) {
            sb_ldst_imm(b, true, true, ES2, ECTX, (16U + i) * 8U);
            sb_ldst_imm(b, false, true, ES2, ES4, i * 8U);
        }
        /* winsp[cwp] = %sp. */
        f_win_addr(b, ES4,
            (uint64_t)(uintptr_t)sparc64_win_sp_base(), ES1, 3U);
        sb_ldst_imm(b, true, true, ES2, ECTX, 14U * 8U);
        sb_ldst_imm(b, false, true, ES2, ES4, 0U);
        /* win_valid[cwp] = save. */
        sb_mov_imm64(b, ES4,
            (uint64_t)(uintptr_t)sparc64_win_valid_base());
        sb_add_reg(b, true, false, ES4, ES4, ES1);
        sb_mov_imm32(b, ES2, is_save ? 1U : 0U);
        f_strb(b, ES2, ES4);
        if (is_save) {
            /* I = old O (two batches, regs stay distinct). */
            f_move4(b, ECTX, 24U, ECTX, 8U);
            f_move4(b, ECTX, 28U, ECTX, 12U);
            /* L = winfile[tgt]. */
            f_win_addr(b, ES4,
                (uint64_t)(uintptr_t)sparc64_win_file_base(), ERSN,
                7U);
            for (i = 0U; i < 8U; i++) {
                sb_ldst_imm(b, true, true, ES2, ES4, i * 8U);
                sb_ldst_imm(b, false, true, ES2, ECTX, (16U + i) * 8U);
            }
            sb_ldst_imm(b, false, false, ERSN, ECTX, 0x250U);
            sb_ldst_imm(b, true, false, ES2, ECTX, 0x254U);
            sb_mov_imm32(b, ES3, 1U);
            sb_sub_reg(b, false, false, ES2, ES2, ES3);
            sb_ldst_imm(b, false, false, ES2, ECTX, 0x254U);
            sb_ldst_imm(b, true, false, ES2, ECTX, 0x258U);
            sb_cmp_imm(b, false, ES2, 7U);
            {
                size_t p_sat = sb_b_cond_placeholder(b, 10U);
                if (p_sat == SPARC64_DBT_NOPOS) {
                    return false;
                }
                sb_add_reg(b, false, false, ES2, ES2, ES3);
                sb_ldst_imm(b, false, false, ES2, ECTX, 0x258U);
                sb_patch_b_cond(b, p_sat, 10U, b->count);
            }
        } else {
            /* O = old I, L/I = winfile[tgt]. */
            f_move4(b, ECTX, 8U, ECTX, 24U);
            f_move4(b, ECTX, 12U, ECTX, 28U);
            f_win_addr(b, ES4,
                (uint64_t)(uintptr_t)sparc64_win_file_base(), ERSN,
                7U);
            for (i = 0U; i < 8U; i++) {
                sb_ldst_imm(b, true, true, ES2, ES4, i * 8U);
                sb_ldst_imm(b, false, true, ES2, ECTX, (16U + i) * 8U);
            }
            for (i = 0U; i < 8U; i++) {
                sb_ldst_imm(b, true, true, ES2, ES4, (8U + i) * 8U);
                sb_ldst_imm(b, false, true, ES2, ECTX, (24U + i) * 8U);
            }
            sb_ldst_imm(b, false, false, ERSN, ECTX, 0x250U);
            sb_ldst_imm(b, true, false, ES2, ECTX, 0x258U);
            sb_mov_imm32(b, ES3, 1U);
            sb_sub_reg(b, false, false, ES2, ES2, ES3);
            sb_ldst_imm(b, false, false, ES2, ECTX, 0x258U);
            sb_ldst_imm(b, true, false, ES2, ECTX, 0x254U);
            sb_cmp_imm(b, false, ES2, 7U);
            {
                size_t p_sat = sb_b_cond_placeholder(b, 10U);
                if (p_sat == SPARC64_DBT_NOPOS) {
                    return false;
                }
                sb_add_reg(b, false, false, ES2, ES2, ES3);
                sb_ldst_imm(b, false, false, ES2, ECTX, 0x254U);
                sb_patch_b_cond(b, p_sat, 10U, b->count);
            }
        }
        if (b->overflow) {
            return false;
        }
        e_st64(b, d->rd, ES0);
        p_end = sb_b_placeholder(b);
        if (p_end == SPARC64_DBT_NOPOS) {
            return false;
        }
        sb_patch_cb(b, p_slow1, b->count);
        sb_patch_cb(b, p_slow2, b->count);
        p_fault = e_call_win(ec, d->rd, is_save);
        if (p_fault == SPARC64_DBT_NOPOS) {
            return false;
        }
        e_resolve_fault(ec, p_fault);
        sb_patch_b(b, p_end, b->count);
    }
    return !b->overflow;
}
