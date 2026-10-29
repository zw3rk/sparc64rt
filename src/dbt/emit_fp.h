/*
 * src/dbt/emit_fp.h — AArch64 FP/NEON emitter interface (Phase 3, L3b)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Lane L3b owns this file (Phase 3 card). It declares the single entry
 * point the DBT dispatcher (L2b, src/dbt/dbt.c) calls for ICLS_FPU
 * instructions; anything this unit refuses (false) keeps the pristine
 * interpreter fallback with zero words emitted.
 *
 * Contract with L2b (mirrors emit_int.h): x19 holds the sparc64_ctx_t
 * pointer on fragment entry (never x18). Guest FP registers live in ctx
 * memory (fp union at 0x140: f[i] at 0x140+i*4, d[i] at 0x140+i*8 with
 * %dN = f-pair 2N/2N+1 so d-index (N>>1)&31; fsr at 0x120, fcc[i] at
 * 0x240+4i). Guest memory is touched only through the sparc64_mem_ops_t
 * callbacks carried in the emit context. Every exit sequence carries the
 * resume/fault guest PC in x15 and the reason in w16 (SPARC64_EXIT_*).
 * Rounding-sensitive lowered ops (arith, sqrt, conversions) emit a
 * runtime FSR.RD == 0 guard prologue and exit SPARC64_EXIT_UNDEF on
 * nonzero (cached blocks stay correct across LDFSR mode changes).
 */

#ifndef SPARC64RT_DBT_EMIT_FP_H
#define SPARC64RT_DBT_EMIT_FP_H

#include <stdbool.h>

#include "interp/interp.h" /* sparc64_dec_t decoded form (classify_word) */
#include "dbt/emit_priv.h" /* sparc64_emit_ctx_t code buffer context */

/* Shared FP file accessors (Lane P5 split: emit_fp.c + emit_fpcmp.c). */
#define FP_FILE_OFF 0x140U
#define FP_FSR_OFF 0x120U
#define FP_FCMP_S UINT32_C(0x1e202000)
#define FP_FCMP_D UINT32_C(0x1e602000)
#define FP_FMOV_X_D UINT32_C(0x9e660000)
#define FP_FMOV_W_S UINT32_C(0x1e260000)
#define FP_FMOV_D_X UINT32_C(0x9e670000)

static inline void fp_alu(sparc64_dbt_buf_t *b, uint32_t base, unsigned vd,
    unsigned vn, unsigned vm)
{
    sb_word(b, base | (vd & 31U) | ((vn & 31U) << 5) |
        ((vm & 31U) << 16));
}

static inline unsigned fp_slot_s(unsigned arch)
{
    return (arch ^ 1U) & 31U;
}

static inline unsigned fp_pair_d(unsigned field)
{
    return ((field & 1U) != 0U) ? (16U + (field >> 1U)) : (field >> 1U);
}

/* Write-through double FPR cache in AAPCS64 callee-saved d8..d15
 * (Lane P13-5, Invariant 1): 8 slots, slot = pair & 7, tagged by the
 * guest double pair. Every double write updates d(8+slot) via FMOV and
 * the ctx fp file in memory, so helpers, faults, and SMC exits stay
 * coherent with zero flush code. FMOV Dd,Dn = 0x1E604000 | Dn<<5 | Dd;
 * single-precision writes invalidate the aliased pair slot. */
static inline void fp_mov_dd(sparc64_dbt_buf_t *b, unsigned dd,
    unsigned dn)
{
    sb_word(b, UINT32_C(0x1e604000) | ((dn & 31U) << 5) |
        (dd & 31U));
}

static inline unsigned fp_d_slot(unsigned pair)
{
    return (pair & 31U) & 7U;
}

/* Invalidate the double slot aliased by single-precision arch reg N
 * (double pair N>>1 shares the same 8 bytes). */
static inline void fp_inv_s_alias(sparc64_dbt_buf_t *b, unsigned arch)
{
    unsigned pair = ((arch & 31U) >> 1) & 31U;
    unsigned slot = fp_d_slot(pair);
    if ((((b->fpr_valid >> slot) & 1U) != 0U) &&
        (b->fpr_tag[slot] == (uint8_t)pair)) {
        b->fpr_valid &= (uint8_t)(~(uint8_t)(1U << slot));
    }
}

/* LDDF/STDF site helpers for emit_mem.c: STDF reads the fp file
 * through the cache (FMOV X0,D(8+slot) on hit, LDR + populate on
 * miss); LDDF populates the cache from the just-loaded x9 value;
 * the miss-stub reload restores d(8+slot) after an interp replay.
 * FMOV Xn,Dn = 0x9E660000 | Dn<<5 | Xn; FMOV Dn,Xn = 0x9E670000 |
 * Xn<<5 | Dn. */
static inline void fp_site_stdf_read(sparc64_dbt_buf_t *b, unsigned pair)
{
    unsigned slot = fp_d_slot(pair);
    uint32_t off = FP_FILE_OFF + (pair & 31U) * 8U;
    if ((((b->fpr_valid >> slot) & 1U) != 0U) &&
        (b->fpr_tag[slot] == (uint8_t)(pair & 31U))) {
        sb_word(b, UINT32_C(0x9e660000) | ((8U + slot) << 5) | 0U);
        return;
    }
    /* Miss: integer LDR X0 (the store path byte-swaps X0), then
     * populate the cache from X0. */
    sb_ldst_imm(b, true, true, 0U, ECTX, off);
    sb_word(b, UINT32_C(0x9e670000) | (0U << 5) | (8U + slot));
    b->fpr_tag[slot] = (uint8_t)(pair & 31U);
    b->fpr_valid |= (uint8_t)(1U << slot);
}

static inline void fp_site_lddf_populate(sparc64_dbt_buf_t *b,
    unsigned pair)
{
    unsigned slot = fp_d_slot(pair);
    sb_word(b, UINT32_C(0x9e670000) | (9U << 5) | (8U + slot));
    b->fpr_tag[slot] = (uint8_t)(pair & 31U);
    b->fpr_valid |= (uint8_t)(1U << slot);
}

static inline void fp_site_lddf_reload(sparc64_dbt_buf_t *b, unsigned pair)
{
    unsigned slot = fp_d_slot(pair);
    uint32_t off = FP_FILE_OFF + (pair & 31U) * 8U;
    sb_word(b, UINT32_C(0xfd400000) | ((8U + slot) & 31U) |
        (19U << 5) | ((off / 8U) << 10));
}

static inline void fp_ld_s(sparc64_dbt_buf_t *b, unsigned vt, unsigned arch)
{
    uint32_t off = FP_FILE_OFF + fp_slot_s(arch) * 4U;
    sb_word(b, UINT32_C(0xbd400000) | (vt & 31U) | (19U << 5) |
        ((off / 4U) << 10));
}

static inline void fp_st_s(sparc64_dbt_buf_t *b, unsigned vt, unsigned arch)
{
    uint32_t off = FP_FILE_OFF + fp_slot_s(arch) * 4U;
    sb_word(b, UINT32_C(0xbd000000) | (vt & 31U) | (19U << 5) |
        ((off / 4U) << 10));
    fp_inv_s_alias(b, arch);
}

static inline void fp_ld_d(sparc64_dbt_buf_t *b, unsigned vt, unsigned field)
{
    uint32_t off = FP_FILE_OFF + fp_pair_d(field) * 8U;
    unsigned pair = fp_pair_d(field);
    unsigned slot = fp_d_slot(pair);
    if ((((b->fpr_valid >> slot) & 1U) != 0U) &&
        (b->fpr_tag[slot] == (uint8_t)pair)) {
        fp_mov_dd(b, vt & 31U, 8U + slot);
        return;
    }
    sb_word(b, UINT32_C(0xfd400000) | (vt & 31U) | (19U << 5) |
        ((off / 8U) << 10));
    fp_mov_dd(b, 8U + slot, vt & 31U);
    b->fpr_tag[slot] = (uint8_t)pair;
    b->fpr_valid |= (uint8_t)(1U << slot);
}

static inline void fp_st_d(sparc64_dbt_buf_t *b, unsigned vt, unsigned field)
{
    uint32_t off = FP_FILE_OFF + fp_pair_d(field) * 8U;
    unsigned pair = fp_pair_d(field);
    unsigned slot = fp_d_slot(pair);
    fp_mov_dd(b, 8U + slot, vt & 31U);
    sb_word(b, UINT32_C(0xfd000000) | (vt & 31U) | (19U << 5) |
        ((off / 8U) << 10));
    b->fpr_tag[slot] = (uint8_t)pair;
    b->fpr_valid |= (uint8_t)(1U << slot);
}

/* Clear guest FSR.cexc (moves never raise); defined in emit_fp.c. */
void fp_clear_cexc(sparc64_dbt_buf_t *b);

/* Commit accumulated host FPSR flags into guest FSR when dirty;
 * defined in emit_fp.c. Clears fpsr_dirty. */
bool sparc64_emit_fp_flush(sparc64_emit_ctx_t *ec);

/* FCMP/FCMPE s+d compare; defined in emit_fpcmp.c. */
bool fp_emit_cmp(sparc64_emit_ctx_t *ec, bool is_double, unsigned cmpe,
    unsigned idx, unsigned rs1, unsigned rs2);

/* FMOVcc s+d conditional move; defined in emit_fpcmp.c. */
bool fp_emit_movcc(sparc64_emit_ctx_t *ec, const sparc64_dec_t *d);

/* Emit one translated guest FPU instruction; returns false when the op
 * must fall back to the interpreter (quad, VIS/FALIGNDATA, block ASIs,
 * FMOVr, LDFSR, everything else). Lowered: FPOP1 arith/sqrt/moves,
 * conversions, FP loads/stores, FCMP/FCMPE s+d, FMOVcc s+d. Never
 * emits any read or write of AArch64 x18. */
bool sparc64_emit_fp(sparc64_emit_ctx_t *ec, const sparc64_dec_t *d);

/* Emit one FBfcc transfer (FBR class); returns false for page-final
 * branches or unemittable delay slots (caller falls back to the
 * interpreter). Never touches x18. */
bool sparc64_emit_fbr(sparc64_emit_ctx_t *ec, const sparc64_dec_t *d);

#endif /* SPARC64RT_DBT_EMIT_FP_H */
