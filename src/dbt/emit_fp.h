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
}

static inline void fp_ld_d(sparc64_dbt_buf_t *b, unsigned vt, unsigned field)
{
    uint32_t off = FP_FILE_OFF + fp_pair_d(field) * 8U;
    sb_word(b, UINT32_C(0xfd400000) | (vt & 31U) | (19U << 5) |
        ((off / 8U) << 10));
}

static inline void fp_st_d(sparc64_dbt_buf_t *b, unsigned vt, unsigned field)
{
    uint32_t off = FP_FILE_OFF + fp_pair_d(field) * 8U;
    sb_word(b, UINT32_C(0xfd000000) | (vt & 31U) | (19U << 5) |
        ((off / 8U) << 10));
}

/* Clear guest FSR.cexc (moves never raise); defined in emit_fp.c. */
void fp_clear_cexc(sparc64_dbt_buf_t *b);

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
