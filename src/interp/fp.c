/*
 * src/interp/fp.c — Phase 3 complete single/double FPU + VIS interpreter.
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Reference interpreter for the SPEC section 2 FP/SIMD set (this file:
 * moves, compares, conditional moves plus the FPOP/FPOP2/VIS
 * dispatcher). Single/double arithmetic, square root, FSMULD, and
 * FDTOS live in fp_sd.c (explicit integer cores, no host FP
 * environment); quad add/sub/mul in fp_quad.c, quad div/sqrt in
 * fp_qdiv.c, quad move/compare/convert in fp_qconv.c, the remaining
 * S/D conversions in fp_conv.c, and FP loads/stores plus the VIS
 * fill/align data path in fp_ldst.c. Every encoding and behavior
 * below is verified bit-for-bit against the qemu-sparc64 7.2.22 oracle
 * (experiments/E05 plus the L3a behavior probes):
 *
 * FPOP1 (op3 0x34) S/D arith/sqrt (0x41/45/49/4D, 0x42/46/4A/4E,
 * 0x29/0x2A), FSMULD 0x069, and FDTOS 0x0C6 route to fp_sd.c;
 * FMOV 0x01/0x02; FNEG 0x05/0x06; FABS 0x09/0x0A; FITOS 0x0C4;
 * FITOD 0x0C8; FXTOS 0x084; FXTOD 0x088; FSTOI 0x0D1; FDTOI 0x0D2;
 * FSTOX 0x081; FDTOX 0x082; FSTOD 0x0C9 route to fp_conv.c.
 * Quad add/sub/mul/FDMULQ (0x43/47/4B/6E) route to fp_quad.c, quad
 * div/sqrt (0x4F/2B) to fp_qdiv.c, and quad move/compare/convert
 * (0x03/07/0B/CC/8C/D3/83/CD/CE/C7/CB) to fp_qconv.c; anything else
 * traps ILLEGAL.
 *
 * FPOP2 (op3 0x35): FCMPS 0x51, FCMPD 0x52, FCMPES 0x55, FCMPED 0x56
 * (fcc = rd&3); FMOVcc opf = (fcc<<6)|size with the FP condition in the
 * 5-bit rs1 field (N=0 NE=1 L=4 G=6 U=7 A=8 E=9 GE=11 LE=13 O=15, plus
 * LG=2 UL=3 ULE=5 UE=10 UGE=12 ULE=14 which GAS never emits); FMOVr
 * opf = 0x100|size (%icc) / 0x180|size (%xcc) with the integer condition
 * in rs1 (all 16 Bicc numbers, evaluated by sparc64_eval_cond).
 * FCMPQ/FCMPEQ route to fp_qconv.c; anything else traps ILLEGAL.
 *
 * VIS (op3 0x36) routes to fp_ldst.c: FZERO 0x60 (double zero) /
 * 0x61 (single zero), FONE 0x7E (double ones), FALIGNDATA 0x48 with
 * GSR bits 2:0 as the byte offset; ALIGNADDR stays integer-classed
 * (interp_win.c). All other VIS opfs (0x62 fnord, 0x63 fnors,
 * 0x7A fornot1d, ...) trap ILLEGAL.
 *
 * FSR model: cexc bits 4:0 = NV/OF/UF/DZ/NX (bit 4 = NV), aexc bits 9:5
 * same order, fcc0 at 11:10, fcc1..3 at 33:32/35:34/37:36, RD at 31:30
 * (0 nearest, 1 toward-zero, 2 toward-+inf, 3 toward--inf). Operate
 * instructions (arith, sqrt, conversions, compares, and all moves
 * FMOV/FNEG/FABS/FMOVcc/FMOVr incl. skipped conditional moves)
 * overwrite cexc, OR into aexc, and trap ILLEGAL when (TEM & cexc) != 0
 * with TEM = bits 27:23. VIS fill/align (FZERO/FONE/FALIGNDATA) and FP
 * loads/stores never touch FSR. ftt is never written
 * (the oracle leaves it zero even on SNaN compares). LDFSR/STFSR stay
 * integer-modeled in interp_mem.c.
 *
 * NaN rules (oracle-observed): SNaN arithmetic input sets NV and yields
 * the quieted NaN (payload kept); QNaN-only inputs yield the NaN with
 * the larger payload (tie: rs1), quietly; invalid non-NaN results
 * (0/0, inf-inf, inf*0, inf/inf, sqrt of negative) yield all-ones
 * (0x7FFFFFFF / 0x7FFFFFFFFFFFFFFF) with NV. FNEG/FABS/FMOV copy/flip
 * bits raw (SNaN preserved, no flags). FCMP on SNaN sets NV with
 * fcc = 3; on QNaN fcc = 3 quietly. FCMPE* sets NV on any NaN.
 *
 * STQF deliberately duplicates the high double (qemu 7.2 STQF quirk).
 * Double/quad register fields: even = lower pair, odd = upper bank
 * (pair 16+(v>>1)); quad field mod 4 == 0 lower / == 1 upper bank,
 * anything else ILLEGAL. Single field s addresses fp.f[(s) ^ 1U]: the
 * union shares LE bytes (f[2i] = LOW half of d[i]) while SPARC pairs
 * even = HIGH, so the xor keeps every single/double/quad view mutually
 * coherent with the oracle. FMOVcc reads cpu->fcc[] (LDFSR never syncs it;
 * see lane notes if the oracle disagrees on LDFSR/fcc corners).
 *
 * NOTE: the op == 2 classifier leaves d->rs2 == 0 for every FPU form,
 * so all second FP sources are recovered from d->raw here; d->is_imm
 * (opf bit 8) is meaningless for FPOP and ignored.
 */

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "core/cpu.h"
#include "interp/interp.h"

/* Phase 3 cross-file entries (defined in fp_conv.c / fp_quad.c /
 * fp_qdiv.c / fp_qconv.c / fp_ldst.c / fp_sd.c). They are declared here
 * so interp.h stays untouched; every helper stays static. */
sparc64_step_result_t sparc64_fp_conv(sparc64_cpu_t *cpu, uint64_t pc,
    const sparc64_dec_t *d);
sparc64_step_result_t sparc64_fp_sd(sparc64_cpu_t *cpu, uint64_t pc,
    const sparc64_dec_t *d);
sparc64_step_result_t sparc64_fp_quad(sparc64_cpu_t *cpu, uint64_t pc,
    const sparc64_dec_t *d);
sparc64_step_result_t sparc64_fp_qdiv(sparc64_cpu_t *cpu, uint64_t pc,
    const sparc64_dec_t *d);
sparc64_step_result_t sparc64_fp_qconv(sparc64_cpu_t *cpu, uint64_t pc,
    const sparc64_dec_t *d);
sparc64_step_result_t sparc64_fp_vis(sparc64_cpu_t *cpu, uint64_t pc,
    const sparc64_dec_t *d);
sparc64_step_result_t sparc64_fp_ldst(sparc64_ctx_t *cpu,
    const sparc64_mem_ops_t *mem, void *mc, uint64_t pc,
    const sparc64_dec_t *d);

/* Double-pair index: even field addresses the lower f-pair, odd field
 * the upper bank (d32/d34/... have no single view). */
static unsigned fp_pair(unsigned v)
{
    if ((v & 1U) != 0U) {
        return 16U + (v >> 1U);
    }
    return v >> 1U;
}

/* Quad index: field mod 4 == 0 is the lower file, mod 4 == 1 the upper
 * bank (q8..q15 overlay d16..d31). Returns 16 when mod 4 is 2 or 3;
 * callers trap ILLEGAL on that (GAS never emits it). */
static unsigned fp_qidx(unsigned w)
{
    unsigned m = w & 3U;
    if (m == 0U) {
        return w >> 2U;
    }
    if (m == 1U) {
        return 8U + (w >> 2U);
    }
    return 16U;
}

static bool fp_isnan_s(uint32_t u)
{
    return ((u & UINT32_C(0x7F800000)) == UINT32_C(0x7F800000)) &&
        ((u & UINT32_C(0x007FFFFF)) != UINT32_C(0));
}

static bool fp_issnan_s(uint32_t u)
{
    return fp_isnan_s(u) && ((u & UINT32_C(0x00400000)) == UINT32_C(0));
}

static bool fp_isnan_d(uint64_t u)
{
    return ((u & UINT64_C(0x7FF0000000000000)) ==
            UINT64_C(0x7FF0000000000000)) &&
        ((u & UINT64_C(0x000FFFFFFFFFFFFF)) != UINT64_C(0));
}

static bool fp_issnan_d(uint64_t u)
{
    return fp_isnan_d(u) &&
        ((u & UINT64_C(0x0008000000000000)) == UINT64_C(0));
}

/* Commit one operate instruction's flags: cexc overwritten, aexc sticky.
 * A trapped (TEM & cexc) condition takes the generic synchronous-trap
 * path, like ILLEGAL. */
static sparc64_step_result_t fp_commit(sparc64_cpu_t *cpu, uint64_t pc,
    const sparc64_dec_t *d, unsigned fresh)
{
    fresh &= 0x1FU;
    cpu->fsr = (cpu->fsr & ~UINT64_C(0x1F)) | (uint64_t)fresh;
    cpu->fsr |= (uint64_t)fresh << 5;
    if ((((cpu->fsr >> 23) & UINT64_C(0x1F)) & (cpu->fsr & UINT64_C(0x1F))) !=
        UINT64_C(0)) {
        return sparc64_trap(SPARC64_TRAP_ILLEGAL, pc, d->raw);
    }
    return sparc64_step_ok(pc);
}

/* Mirror one compare result into cpu->fcc[] and the FSR fcc fields. */
static void fp_fcc_write(sparc64_cpu_t *cpu, unsigned idx, unsigned v)
{
    static const unsigned shifts[4] = { 10U, 32U, 34U, 36U };
    v &= 3U;
    idx &= 3U;
    cpu->fcc[idx] = (uint32_t)v;
    cpu->fsr = (cpu->fsr & ~((uint64_t)UINT64_C(3) << shifts[idx])) |
        ((uint64_t)v << shifts[idx]);
}

/* Single/double arithmetic, square root, and FSMULD live in fp_sd.c
 * (explicit integer cores); the dispatcher below routes their opfs to
 * sparc64_fp_sd. */
/* Data movement: raw bit copy, sign flip, sign clear. An operate
 * instruction: overwrites cexc (no flags raised), aexc sticky. */
static sparc64_step_result_t fp_move_s(sparc64_cpu_t *cpu, uint64_t pc,
    const sparc64_dec_t *d, unsigned op)
{
    uint32_t a = cpu->fp.f[(d->raw & 31U) ^ 1U];
    if (op == 1U) {
        a ^= UINT32_C(0x80000000);
    } else if (op == 2U) {
        a &= ~UINT32_C(0x80000000);
    }
    cpu->fp.f[(d->rd & 31U) ^ 1U] = a;
    return fp_commit(cpu, pc, d, 0U);
}

static sparc64_step_result_t fp_move_d(sparc64_cpu_t *cpu, uint64_t pc,
    const sparc64_dec_t *d, unsigned op)
{
    uint64_t a = cpu->fp.d[fp_pair(d->raw & 31U)];
    if (op == 1U) {
        a ^= UINT64_C(0x8000000000000000);
    } else if (op == 2U) {
        a &= ~UINT64_C(0x8000000000000000);
    }
    cpu->fp.d[fp_pair(d->rd)] = a;
    return fp_commit(cpu, pc, d, 0U);
}

/* Ordered magnitude compare for finite nonzero operands of equal sign
 * encoding: returns 0 equal, 1 less, 2 greater. */
static unsigned fp_cmp_mag_s(uint32_t a, uint32_t b)
{
    uint32_t ma = a & UINT32_C(0x7FFFFFFF);
    uint32_t mb = b & UINT32_C(0x7FFFFFFF);
    if (ma == mb) {
        return 0U;
    }
    return (ma < mb) ? 1U : 2U;
}

static unsigned fp_cmp_mag_d(uint64_t a, uint64_t b)
{
    uint64_t ma = a & UINT64_C(0x7FFFFFFFFFFFFFFF);
    uint64_t mb = b & UINT64_C(0x7FFFFFFFFFFFFFFF);
    if (ma == mb) {
        return 0U;
    }
    return (ma < mb) ? 1U : 2U;
}

/* FCMP/FCMPE (single): integer bit logic only. unordered -> fcc 3;
 * FCMPE* sets NV on any NaN, FCMP* only on SNaN. */
static sparc64_step_result_t fp_cmp_s(sparc64_cpu_t *cpu, uint64_t pc,
    const sparc64_dec_t *d, unsigned cmpe)
{
    uint32_t a = cpu->fp.f[(d->rs1 & 31U) ^ 1U];
    uint32_t b = cpu->fp.f[(d->raw & 31U) ^ 1U];
    bool an = fp_isnan_s(a);
    bool bn = fp_isnan_s(b);
    bool sa = fp_issnan_s(a);
    bool sb = fp_issnan_s(b);
    unsigned fcc = 3U;
    unsigned nv = 0U;
    if (an || bn) {
        if (cmpe != 0U || sa || sb) {
            nv = 0x10U;
        }
    } else if (((a & UINT32_C(0x7FFFFFFF)) == UINT32_C(0)) &&
        ((b & UINT32_C(0x7FFFFFFF)) == UINT32_C(0))) {
        fcc = 0U;
    } else if (((a ^ b) & UINT32_C(0x80000000)) != UINT32_C(0)) {
        fcc = ((a & UINT32_C(0x80000000)) != UINT32_C(0)) ? 1U : 2U;
    } else {
        unsigned m = fp_cmp_mag_s(a, b);
        if (((a & UINT32_C(0x80000000)) != UINT32_C(0))) {
            fcc = (m == 1U) ? 2U : ((m == 2U) ? 1U : 0U);
        } else {
            fcc = m;
        }
    }
    fp_fcc_write(cpu, d->rd, fcc);
    return fp_commit(cpu, pc, d, nv);
}

/* FCMP/FCMPE (double), same rules as single. */
static sparc64_step_result_t fp_cmp_d(sparc64_cpu_t *cpu, uint64_t pc,
    const sparc64_dec_t *d, unsigned cmpe)
{
    uint64_t a = cpu->fp.d[fp_pair(d->rs1)];
    uint64_t b = cpu->fp.d[fp_pair(d->raw & 31U)];
    bool an = fp_isnan_d(a);
    bool bn = fp_isnan_d(b);
    bool sa = fp_issnan_d(a);
    bool sb = fp_issnan_d(b);
    unsigned fcc = 3U;
    unsigned nv = 0U;
    if (an || bn) {
        if (cmpe != 0U || sa || sb) {
            nv = 0x10U;
        }
    } else if (((a & UINT64_C(0x7FFFFFFFFFFFFFFF)) == UINT64_C(0)) &&
        ((b & UINT64_C(0x7FFFFFFFFFFFFFFF)) == UINT64_C(0))) {
        fcc = 0U;
    } else if (((a ^ b) & UINT64_C(0x8000000000000000)) != UINT64_C(0)) {
        fcc = ((a & UINT64_C(0x8000000000000000)) != UINT64_C(0)) ? 1U : 2U;
    } else {
        unsigned m = fp_cmp_mag_d(a, b);
        if (((a & UINT64_C(0x8000000000000000)) != UINT64_C(0))) {
            fcc = (m == 1U) ? 2U : ((m == 2U) ? 1U : 0U);
        } else {
            fcc = m;
        }
    }
    fp_fcc_write(cpu, d->rd, fcc);
    return fp_commit(cpu, pc, d, nv);
}

/* Floating-point condition test over an fcc value (0 equal, 1 less,
 * 2 greater, 3 unordered). Covers all 16 V9 FP conditions; GAS only
 * emits 10 of them for FMOVcc, the rest are available to hand-encoded
 * words with identical predicates. */
static bool fp_cctest(unsigned cond, unsigned fcc)
{
    switch (cond) {
    case 0U:
        return false;
    case 1U:
        return fcc != 0U;
    case 2U:
        return (fcc == 1U) || (fcc == 2U);
    case 3U:
        return (fcc == 3U) || (fcc == 1U);
    case 4U:
        return fcc == 1U;
    case 5U:
        return fcc != 2U;
    case 6U:
        return fcc == 2U;
    case 7U:
        return fcc == 3U;
    case 8U:
        return true;
    case 9U:
        return fcc == 0U;
    case 10U:
        return (fcc == 3U) || (fcc == 0U);
    case 11U:
        return (fcc == 2U) || (fcc == 0U);
    case 12U:
        return fcc != 1U;
    case 13U:
        return (fcc == 0U) || (fcc == 1U);
    case 14U:
        return (fcc == 3U) || (fcc == 1U) || (fcc == 0U);
    default:
        return fcc != 3U;
    }
}

/* Copy one quad register file slot (16 bytes) without touching FSR. */
static void fp_copy_q(sparc64_cpu_t *cpu, unsigned dst, unsigned src)
{
    unsigned dd = fp_qidx(dst);
    unsigned ds = fp_qidx(src);
    cpu->fp.d[2U * dd] = cpu->fp.d[2U * ds];
    cpu->fp.d[2U * dd + 1U] = cpu->fp.d[2U * ds + 1U];
}

/* FMOVcc: opf = (fcc<<6)|size. The destination keeps its old bits when
 * the condition is false. Never touches FSR. */
static sparc64_step_result_t fp_movcc(sparc64_cpu_t *cpu, uint64_t pc,
    const sparc64_dec_t *d)
{
    unsigned opf = d->opf;
    unsigned size;
    unsigned fcc;
    unsigned cond;
    unsigned rs2;
    if ((opf & UINT32_C(0x13C)) != UINT32_C(0)) {
        return sparc64_trap(SPARC64_TRAP_ILLEGAL, pc, d->raw);
    }
    size = opf & 3U;
    if (size == 0U || size > 3U) {
        return sparc64_trap(SPARC64_TRAP_ILLEGAL, pc, d->raw);
    }
    fcc = (opf >> 6) & 3U;
    cond = d->rs1;
    if (cond > 15U) {
        return sparc64_trap(SPARC64_TRAP_ILLEGAL, pc, d->raw);
    }
    if (!fp_cctest(cond, cpu->fcc[fcc])) {
        return fp_commit(cpu, pc, d, 0U);
    }
    rs2 = d->raw & 31U;
    if (size == 1U) {
        cpu->fp.f[(d->rd & 31U) ^ 1U] = cpu->fp.f[(rs2) ^ 1U];
    } else if (size == 2U) {
        cpu->fp.d[fp_pair(d->rd)] = cpu->fp.d[fp_pair(rs2)];
    } else {
        unsigned qd = fp_qidx(d->rd);
        unsigned qs = fp_qidx(rs2);
        if (qd > 15U || qs > 15U) {
            return sparc64_trap(SPARC64_TRAP_ILLEGAL, pc, d->raw);
        }
        fp_copy_q(cpu, d->rd, rs2);
    }
    return fp_commit(cpu, pc, d, 0U);
}

/* FMOVr: opf = 0x100|size (%icc) or 0x180|size (%xcc); the integer
 * condition tests the selected cc nibble. Operate instruction even when
 * the move is skipped: overwrites cexc, aexc sticky. */
static sparc64_step_result_t fp_movr(sparc64_cpu_t *cpu, uint64_t pc,
    const sparc64_dec_t *d)
{
    unsigned opf = d->opf;
    unsigned size = opf & 3U;
    unsigned cond;
    unsigned nib;
    unsigned rs2;
    if (size == 0U || size > 3U) {
        return sparc64_trap(SPARC64_TRAP_ILLEGAL, pc, d->raw);
    }
    if (opf != (0x100U | size) && opf != (0x180U | size)) {
        return sparc64_trap(SPARC64_TRAP_ILLEGAL, pc, d->raw);
    }
    cond = d->rs1;
    if (cond > 15U) {
        return sparc64_trap(SPARC64_TRAP_ILLEGAL, pc, d->raw);
    }
    nib = ((opf & 0x80U) != 0U) ? sparc64_cc_xcc(cpu) : sparc64_cc_icc(cpu);
    if (!sparc64_eval_cond(cond, nib)) {
        return fp_commit(cpu, pc, d, 0U);
    }
    rs2 = d->raw & 31U;
    if (size == 1U) {
        cpu->fp.f[(d->rd & 31U) ^ 1U] = cpu->fp.f[(rs2) ^ 1U];
    } else if (size == 2U) {
        cpu->fp.d[fp_pair(d->rd)] = cpu->fp.d[fp_pair(rs2)];
    } else {
        unsigned qd = fp_qidx(d->rd);
        unsigned qs = fp_qidx(rs2);
        if (qd > 15U || qs > 15U) {
            return sparc64_trap(SPARC64_TRAP_ILLEGAL, pc, d->raw);
        }
        fp_copy_q(cpu, d->rd, rs2);
    }
    return fp_commit(cpu, pc, d, 0U);
}

sparc64_step_result_t sparc64_exec_fpu(sparc64_ctx_t *cpu,
    const sparc64_mem_ops_t *mem, void *mc, uint64_t pc,
    const sparc64_dec_t *d)
{
    if (d->op3 == SPARC64_OP3_VIS) {
        return sparc64_fp_vis(cpu, pc, d);
    }
    if (d->op3 == SPARC64_OP3_FPOP1) {
        switch (d->opf) {
        case 0x41U:
        case 0x45U:
        case 0x49U:
        case 0x4DU:
        case 0x42U:
        case 0x46U:
        case 0x4AU:
        case 0x4EU:
        case 0x29U:
        case 0x2AU:
        case 0x69U:
        case 0x0C6U:
            return sparc64_fp_sd(cpu, pc, d);
        case 0x01U:
            return fp_move_s(cpu, pc, d, 0U);
        case 0x02U:
            return fp_move_d(cpu, pc, d, 0U);
        case 0x05U:
            return fp_move_s(cpu, pc, d, 1U);
        case 0x06U:
            return fp_move_d(cpu, pc, d, 1U);
        case 0x09U:
            return fp_move_s(cpu, pc, d, 2U);
        case 0x0AU:
            return fp_move_d(cpu, pc, d, 2U);
        case 0x0C4U:
        case 0x0C8U:
        case 0x084U:
        case 0x088U:
        case 0x0D1U:
        case 0x0D2U:
        case 0x081U:
        case 0x082U:
        case 0x0C9U:
            return sparc64_fp_conv(cpu, pc, d);
        case 0x043U:
        case 0x047U:
        case 0x04BU:
        case 0x06EU:
            return sparc64_fp_quad(cpu, pc, d);
        case 0x04FU:
        case 0x02BU:
            return sparc64_fp_qdiv(cpu, pc, d);
        case 0x003U:
        case 0x007U:
        case 0x00BU:
        case 0x0CCU:
        case 0x08CU:
        case 0x0D3U:
        case 0x083U:
        case 0x0CDU:
        case 0x0CEU:
        case 0x0C7U:
        case 0x0CBU:
            return sparc64_fp_qconv(cpu, pc, d);
        default:
            return sparc64_trap(SPARC64_TRAP_ILLEGAL, pc, d->raw);
        }
    }
    if (d->op3 == SPARC64_OP3_FPOP2) {
        unsigned opf;
        switch (d->opf) {
        case 0x51U:
            return fp_cmp_s(cpu, pc, d, 0U);
        case 0x52U:
            return fp_cmp_d(cpu, pc, d, 0U);
        case 0x55U:
            return fp_cmp_s(cpu, pc, d, 1U);
        case 0x56U:
            return fp_cmp_d(cpu, pc, d, 1U);
        case 0x53U:
        case 0x57U:
            return sparc64_fp_qconv(cpu, pc, d);
        default:
            break;
        }
        opf = d->opf;
        if ((opf & UINT32_C(0x13C)) == UINT32_C(0) && (opf & 3U) >= 1U &&
            (opf & 3U) <= 3U && ((opf >> 8) & 1U) == 0U) {
            return fp_movcc(cpu, pc, d);
        }
        if ((opf == (0x100U | (opf & 3U)) ||
                opf == (0x180U | (opf & 3U))) && (opf & 3U) >= 1U &&
            (opf & 3U) <= 3U) {
            return fp_movr(cpu, pc, d);
        }
        return sparc64_trap(SPARC64_TRAP_ILLEGAL, pc, d->raw);
    }
    if (d->op3 == SPARC64_OP3_LDF || d->op3 == SPARC64_OP3_LDDF ||
        d->op3 == SPARC64_OP3_STF || d->op3 == SPARC64_OP3_STDF ||
        d->op3 == SPARC64_OP3_LDTW || d->op3 == SPARC64_OP3_STTW ||
        d->op3 == SPARC64_OP3_LDDA || d->op3 == SPARC64_OP3_STDA ||
        d->op3 == SPARC64_OP3_LDFA || d->op3 == SPARC64_OP3_LDDFA ||
        d->op3 == SPARC64_OP3_STFA || d->op3 == SPARC64_OP3_STDFA) {
        return sparc64_fp_ldst(cpu, mem, mc, pc, d);
    }
    return sparc64_trap(SPARC64_TRAP_ILLEGAL, pc, d->raw);
}
