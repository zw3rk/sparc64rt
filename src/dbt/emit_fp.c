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
 * every FPOP1 conversion reads and writes the FP file (integer values
 * transfer through f/d regs; `ld [c5i], %f0` stages the int in an F-reg).
 * Slot mapping mirrors interp (single N in slot N^1, double field v in
 * d[v>>1] / d[16+(v>>1)]) or difftest diverges. AArch64 scalar FP words
 * below were verified word-for-word with the cross-assembler.
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
#define FP_FCVTZS_W_S UINT32_C(0x1e380000)
#define FP_FCVTZS_X_S UINT32_C(0x9e380000)
#define FP_FCVTZS_W_D UINT32_C(0x1e780000)
#define FP_FCVTZS_X_D UINT32_C(0x9e780000)
#define FP_SCVTF_S_W UINT32_C(0x1e220000)
#define FP_SCVTF_D_W UINT32_C(0x1e620000)
#define FP_SCVTF_S_X UINT32_C(0x9e220000)
#define FP_SCVTF_D_X UINT32_C(0x9e620000)
#define FP_FCVT_D_S UINT32_C(0x1e22c000)
#define FP_FCVT_S_D UINT32_C(0x1e624000)
#define FP_FMOV_X_D UINT32_C(0x9e660000)
#define FP_FMOV_W_S UINT32_C(0x1e260000)
#define FP_FMOV_S_W UINT32_C(0x1e270000)
#define FP_FMOV_D_X UINT32_C(0x9e670000)
#define FP_FCMP_S UINT32_C(0x1e202000)
#define FP_FCMP_D UINT32_C(0x1e602000)

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

/* Guest FP slot of single arch f[arch] (slot arch^1) and double
 * field (d[field>>1], upper bank at d[16+(field>>1)] when odd). */
static inline unsigned fp_slot_s(unsigned arch)
{
    return (arch ^ 1U) & 31U;
}

static inline unsigned fp_pair_d(unsigned field)
{
    return ((field & 1U) != 0U) ? (16U + (field >> 1U)) : (field >> 1U);
}

/* LDR St,[x19,#off] / STR St,[x19,#off]: single arch f[arch]. */
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

/* LDR Dt,[x19,#off] / STR Dt,[x19,#off]: double field (even/odd). */
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

/* Rounding guard prologue: FSR.RD (bits 31:30) must be 0
 * (round-to-nearest, the host FPCR default); nonzero exits UNDEF so the
 * dispatcher replays the instruction with the reference interpreter.
 * Also clears host FPSR so fp_sync_fsr observes only this op's flags. */
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
    sb_word(b, UINT32_C(0xd51b443f)); /* msr FPSR, xzr */
    return !b->overflow;
}

static void fp_clear_cexc(sparc64_dbt_buf_t *b)
{
    sb_ldst_imm(b, true, true, ES3, ECTX, FP_FSR_OFF);
    sb_word(b, UINT32_C(0x927be800) | ((ES3 & 31U) << 5) | (ES3 & 31U));
    sb_ldst_imm(b, true, false, ES3, ECTX, FP_FSR_OFF);
}

/* If the host FP op raised any IEEE exception (IOC|DZC|OFC|UFC|IXC in
 * FPSR[4:0]), exit UNDEF before writing the destination register so the
 * interpreter replays the instruction and sets FSR.cexc/aexc/TEM traps
 * identically to the oracle; otherwise clear FSR.cexc (bits 4:0). */
static bool fp_sync_fsr(sparc64_emit_ctx_t *ec)
{
    sparc64_dbt_buf_t *b = ec->buf;
    size_t p_ok;
    sb_word(b, UINT32_C(0xd53b4420) | (ES3 & 31U)); /* mrs ES3, FPSR */
    sb_ubfm(b, true, ES3, ES3, 0U, 4U);
    p_ok = sb_cbz_placeholder(b, true, false, ES3);
    if (p_ok == SPARC64_DBT_NOPOS) {
        return false;
    }
    e_fault_here(b, ec->fault_pc);
    sb_patch_cb(b, p_ok, b->count);
    fp_clear_cexc(b);
    return !b->overflow;
}

/* NaN detour: FCMP Vt,Vt sets V iff Vt is NaN; B.VS exits UNDEF so
 * the interpreter reproduces the oracle's NaN payload, quieting, and
 * NV exactly. Finite results stay native and bit-exact (IEEE); the FSR
 * flags they raise are observed through the interpreter copy. */
static bool fp_nan_check(sparc64_emit_ctx_t *ec, bool is_double,
    unsigned vt)
{
    sparc64_dbt_buf_t *b = ec->buf;
    size_t p_vs;
    size_t p_end;
    fp_alu(b, is_double ? FP_FCMP_D : FP_FCMP_S, 0U, vt, vt);
    p_vs = sb_b_cond_placeholder(b, 6U);
    if (p_vs == SPARC64_DBT_NOPOS) {
        return false;
    }
    p_end = sb_b_placeholder(b);
    if (p_end == SPARC64_DBT_NOPOS) {
        return false;
    }
    sb_patch_b_cond(b, p_vs, 6U, b->count);
    e_fault_here(b, ec->fault_pc);
    sb_patch_b(b, p_end, b->count);
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
        fp_ld_d(b, 0U, rs1);
        fp_ld_d(b, 1U, rs2);
        fp_alu(b, base, 2U, 0U, 1U);
        if (!fp_nan_check(ec, true, 2U) || !fp_sync_fsr(ec)) {
            return false;
        }
        fp_st_d(b, 2U, rd);
    } else {
        fp_ld_s(b, 0U, rs1);
        fp_ld_s(b, 1U, rs2);
        fp_alu(b, base, 2U, 0U, 1U);
        if (!fp_nan_check(ec, false, 2U) || !fp_sync_fsr(ec)) {
            return false;
        }
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
        fp_ld_d(b, 0U, rs2);
        fp_alu(b, base, 1U, 0U, 0U);
        if (!fp_nan_check(ec, true, 1U) || !fp_sync_fsr(ec)) {
            return false;
        }
        fp_st_d(b, 1U, rd);
    } else {
        fp_ld_s(b, 0U, rs2);
        fp_alu(b, base, 1U, 0U, 0U);
        if (!fp_nan_check(ec, false, 1U) || !fp_sync_fsr(ec)) {
            return false;
        }
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
        fp_ld_d(b, 0U, rs2);
        fp_st_d(b, 0U, rd);
    } else {
        fp_ld_s(b, 0U, rs2);
        fp_st_s(b, 0U, rd);
    }
    fp_clear_cexc(b);
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
        fp_ld_d(b, 0U, rs2);
        fp_alu(b, base, 1U, 0U, 0U);
        fp_st_d(b, 1U, rd);
    } else {
        fp_ld_s(b, 0U, rs2);
        fp_alu(b, base, 1U, 0U, 0U);
        fp_st_s(b, 1U, rd);
    }
    fp_clear_cexc(b);
    return !b->overflow;
}

/* F{S,D}TO{I,X}: FP source, FP rd (the integer result bit pattern
 * lands in f[rd]/d[rd]; the test reads it back with st/std). Truncates
 * toward zero like hardware (RD only matters via the guard: conversions
 * that need another mode exit UNDEF for interpreter replay). */
static bool fp_emit_f2i(sparc64_emit_ctx_t *ec, uint32_t base,
    const sparc64_dec_t *d, bool from_double, bool to_64)
{
    sparc64_dbt_buf_t *b = ec->buf;
    unsigned rs2 = d->raw & 31U;
    unsigned rd = d->rd & 31U;
    if (!fp_guard_rd0(ec)) {
        return false;
    }
    if (from_double) {
        fp_ld_d(b, 0U, rs2);
    } else {
        fp_ld_s(b, 0U, rs2);
    }
    if (!fp_nan_check(ec, from_double, 0U)) {
        return false;
    }
    fp_alu(b, base, ES1, 0U, 0U);
    if (!fp_sync_fsr(ec)) {
        return false;
    }
    if (to_64) {
        fp_alu(b, FP_FMOV_D_X, ES1, ES1, 0U);
        fp_st_d(b, ES1, rd);
    } else {
        fp_alu(b, FP_FMOV_S_W, ES1, ES1, 0U);
        fp_st_s(b, ES1, rd);
    }
    return !b->overflow;
}

/* FITOS/FITOD: the 32-bit integer source lives in single f[rs2]
 * (oracle/test: `ld [c5i], %f0` stages it before `fitos %f0, %f2`).
 * (FXTOS/FXTOD take their 64-bit source from a double FP register:
 * fp_emit_x2f.) */
static bool fp_emit_i2f(sparc64_emit_ctx_t *ec, uint32_t base,
    const sparc64_dec_t *d, bool to_double)
{
    sparc64_dbt_buf_t *b = ec->buf;
    unsigned rs2 = d->raw & 31U;
    unsigned rd = d->rd & 31U;
    if (!fp_guard_rd0(ec)) {
        return false;
    }
    fp_ld_s(b, 0U, rs2);
    fp_alu(b, FP_FMOV_W_S, ES0, 0U, 0U);
    fp_alu(b, base, 0U, ES0, 0U);
    if (!fp_sync_fsr(ec)) {
        return false;
    }
    if (to_double) {
        fp_st_d(b, 0U, rd);
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
    fp_ld_d(b, 0U, rs2);
    fp_alu(b, FP_FMOV_X_D, ES0, 0U, 0U);
    fp_alu(b, base, 0U, ES0, 0U);
    if (!fp_sync_fsr(ec)) {
        return false;
    }
    if (to_double) {
        fp_st_d(b, 0U, rd);
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
        fp_ld_d(b, 0U, rs2);
        if (!fp_nan_check(ec, true, 0U)) {
            return false;
        }
        fp_alu(b, base, 1U, 0U, 0U);
        if (!fp_sync_fsr(ec)) {
            return false;
        }
        fp_st_s(b, 1U, rd);
    } else {
        fp_ld_s(b, 0U, rs2);
        if (!fp_nan_check(ec, false, 0U)) {
            return false;
        }
        fp_alu(b, base, 1U, 0U, 0U);
        if (!fp_sync_fsr(ec)) {
            return false;
        }
        fp_st_d(b, 1U, rd);
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
    /* Toward-zero: SPARC float-to-int always truncates (RD only gates
     * which mode may run natively; exceptional inputs trap to the
     * interpreter via the caller's fallback paths). */
    case 0xD1U:
        return fp_emit_f2i(ec, FP_FCVTZS_W_S, d, false, false);
    case 0xD2U:
        return fp_emit_f2i(ec, FP_FCVTZS_W_D, d, true, false);
    case 0x81U:
        return fp_emit_f2i(ec, FP_FCVTZS_X_S, d, false, true);
    case 0x82U:
        return fp_emit_f2i(ec, FP_FCVTZS_X_D, d, true, true);
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
