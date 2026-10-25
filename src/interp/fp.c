/*
 * src/interp/fp.c — RC2 minimal FPU kernel, reference interpreter only.
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Covers exactly the floating-point data movement static glibc startup
 * needs (FZERO, FP moves, FP loads/stores); every other FP/SIMD opcode
 * traps ILLEGAL, loudly, so nothing silently computes a wrong value.
 * No FPU enable check (FPRS/PEF): deferred to Phase 3/4.
 *
 * Phase 3 (lane L3a) owns the complete FPU/SIMD implementation from
 * SPEC.md section 2 (arithmetic, NaN propagation, FCC, rounding, SIMD,
 * NEON emission) and subsumes this file; the DBT treats every FPU class
 * as pristine interpreter fallback, so difftest agrees by construction.
 */

#include <stdint.h>
#include <string.h>

#include "core/cpu.h"
#include "interp/interp.h"

/* Double register index: %dN (N even) overlays %fN/%fN+1. */
static unsigned fp_dreg(unsigned rd)
{
    return (rd >> 1U) & 31U;
}

/* VIS FZERO: %f0-style zero of a single (0x61) or double (0x60) register. */
static sparc64_step_result_t fp_zero(sparc64_cpu_t *cpu, uint64_t pc,
    const sparc64_dec_t *d)
{
    if (d->opf == 0x60U) {
        cpu->fp.d[fp_dreg(d->rd)] = UINT64_C(0);
        return sparc64_step_ok(pc);
    }
    if (d->opf == 0x61U) {
        cpu->fp.f[d->rd & 31U] = UINT32_C(0);
        return sparc64_step_ok(pc);
    }
    return sparc64_trap(SPARC64_TRAP_ILLEGAL, pc, d->raw);
}

static uint64_t fp_dbits(double v)
{
    uint64_t u = UINT64_C(0);
    memcpy(&u, &v, sizeof(u));
    return u;
}

static double fp_f64(uint64_t u)
{
    double v = 0.0;
    memcpy(&v, &u, sizeof(v));
    return v;
}

static uint32_t fp_fbits(float v)
{
    uint32_t u = UINT32_C(0);
    memcpy(&u, &v, sizeof(u));
    return u;
}

static float fp_f32(uint32_t u)
{
    float v = 0.0F;
    memcpy(&v, &u, sizeof(v));
    return v;
}

/* FPOP1 arithmetic (op3 0x34): FADD/FSUB/FMUL/FDIV single (opf low bits
 * 1) and double (2). Host float/double are IEEE-754 binary32/64 evaluated
 * under round-to-nearest, which is exactly the guest FSR default, so the
 * correctly-rounded operations match bit for bit. Quad (3), FMOVcc/FCMP,
 * conversions, and status-flag side effects belong to Phase 3. */
static sparc64_step_result_t fp_arith(sparc64_cpu_t *cpu, uint64_t pc,
    const sparc64_dec_t *d)
{
    if (d->opf == 0x41U || d->opf == 0x45U || d->opf == 0x49U ||
        d->opf == 0x4DU) {
        float a = fp_f32(cpu->fp.f[d->rs1 & 31U]);
        float b = (d->is_imm != 0U) ? (float)d->imm
                                    : fp_f32(cpu->fp.f[d->rs2 & 31U]);
        float r = a;
        if (d->opf == 0x41U) {
            r = a + b;
        } else if (d->opf == 0x45U) {
            r = a - b;
        } else if (d->opf == 0x49U) {
            r = a * b;
        } else {
            r = a / b;
        }
        cpu->fp.f[d->rd & 31U] = fp_fbits(r);
        return sparc64_step_ok(pc);
    }
    if (d->opf == 0x42U || d->opf == 0x46U || d->opf == 0x4AU ||
        d->opf == 0x4EU) {
        double a = fp_f64(cpu->fp.d[fp_dreg(d->rs1)]);
        double b = fp_f64(cpu->fp.d[fp_dreg(d->rs2)]);
        double r = a;
        if (d->opf == 0x42U) {
            r = a + b;
        } else if (d->opf == 0x46U) {
            r = a - b;
        } else if (d->opf == 0x4AU) {
            r = a * b;
        } else {
            r = a / b;
        }
        cpu->fp.d[fp_dreg(d->rd)] = fp_dbits(r);
        return sparc64_step_ok(pc);
    }
    return sparc64_trap(SPARC64_TRAP_ILLEGAL, pc, d->raw);
}

/* FP loads/stores (plain 0x20-0x27 and the 0x30-0x37 alternate group,
 * plus LDDA/STDA): data movement between memory and the FP file. Single
 * forms move 32 bits, double forms 64. Alternate forms resolve the ASI
 * (immediate, or %asi when regasi is set) through the shared checker. */
static sparc64_step_result_t fp_ldst(sparc64_ctx_t *cpu,
    const sparc64_mem_ops_t *mem, void *mc, uint64_t pc,
    const sparc64_dec_t *d)
{
    bool is_load = (d->op3 == SPARC64_OP3_LDF ||
        d->op3 == SPARC64_OP3_LDDF || d->op3 == SPARC64_OP3_LDDA ||
        d->op3 == SPARC64_OP3_LDFA || d->op3 == SPARC64_OP3_LDDFA);
    bool is_double = (d->op3 == SPARC64_OP3_LDDF ||
        d->op3 == SPARC64_OP3_STDF || d->op3 == SPARC64_OP3_LDDA ||
        d->op3 == SPARC64_OP3_STDA || d->op3 == SPARC64_OP3_LDDFA ||
        d->op3 == SPARC64_OP3_STDFA);
    bool alt = (d->op3 == SPARC64_OP3_LDDA ||
        d->op3 == SPARC64_OP3_STDA || d->op3 == SPARC64_OP3_LDFA ||
        d->op3 == SPARC64_OP3_LDDFA || d->op3 == SPARC64_OP3_STFA ||
        d->op3 == SPARC64_OP3_STDFA);
    uint64_t va = sparc64_rreg(cpu, d->rs1) +
        ((d->is_imm != 0U) ? (uint64_t)(int64_t)d->imm
                           : sparc64_rreg(cpu, d->rs2));
    bool little = false;
    sparc64_step_result_t res;
    uint64_t v = UINT64_C(0);
    if (alt) {
        sparc64_dec_t dd = *d;
        if (dd.regasi != 0U) {
            dd.asi = (uint8_t)(cpu->asi & UINT64_C(0xFF));
        }
        if (dd.asi >= 0xF0U && dd.asi <= 0xF7U &&
            (d->op3 == SPARC64_OP3_LDDA ||
                d->op3 == SPARC64_OP3_STDA ||
                d->op3 == SPARC64_OP3_LDDFA ||
                d->op3 == SPARC64_OP3_STDFA)) {
            /* VIS block operation (UltraSPARC ASI 0xF0-0xF7, e.g. glibc
             * memset/memcpy): a 64-byte line across 8 consecutive double
             * FP registers. Cache effects are invisible to linux-user, so
             * plain 8-byte pieces are data-identical to hardware. */
            unsigned base;
            unsigned k;
            if ((va & UINT64_C(63)) != UINT64_C(0)) {
                return sparc64_trap(SPARC64_TRAP_LOAD_ACCESS, pc, va);
            }
            base = (unsigned)fp_dreg(d->rd) & ~7U;
            for (k = 0U; k < 8U; k++) {
                if (is_load) {
                    if (!sparc64_ld_int(mem, mc, va + (uint64_t)(k * 8U),
                            8U, false, false, &v, &res, pc)) {
                        return res;
                    }
                    cpu->fp.d[base + k] = v;
                } else {
                    v = cpu->fp.d[base + k];
                    if (!sparc64_st_int(mem, mc, va + (uint64_t)(k * 8U),
                            8U, false, v, &res, pc)) {
                        return res;
                    }
                }
            }
            return sparc64_step_ok(pc);
        }
        if (!sparc64_asi_check(pc, &dd, &little, &res)) {
            return res;
        }
    }
    if (is_load) {
        if (!sparc64_ld_int(mem, mc, va, is_double ? 8U : 4U, false, little,
                &v, &res, pc)) {
            return res;
        }
        if (is_double) {
            cpu->fp.d[fp_dreg(d->rd)] = v;
        } else {
            cpu->fp.f[d->rd & 31U] = (uint32_t)v;
        }
        return sparc64_step_ok(pc);
    }
    v = is_double ? cpu->fp.d[fp_dreg(d->rd)]
                  : (uint64_t)cpu->fp.f[d->rd & 31U];
    if (!sparc64_st_int(mem, mc, va, is_double ? 8U : 4U, little, v, &res,
            pc)) {
        return res;
    }
    return sparc64_step_ok(pc);
}

sparc64_step_result_t sparc64_exec_fpu(sparc64_ctx_t *cpu,
    const sparc64_mem_ops_t *mem, void *mc, uint64_t pc,
    const sparc64_dec_t *d)
{
    if (d->op3 == SPARC64_OP3_VIS && (d->opf == 0x60U || d->opf == 0x61U)) {
        return fp_zero(cpu, pc, d);
    }
    if (d->op3 == SPARC64_OP3_FPOP1) {
        return fp_arith(cpu, pc, d);
    }
    if (d->op3 == SPARC64_OP3_LDF || d->op3 == SPARC64_OP3_LDDF ||
        d->op3 == SPARC64_OP3_STF || d->op3 == SPARC64_OP3_STDF ||
        d->op3 == SPARC64_OP3_LDDA || d->op3 == SPARC64_OP3_STDA ||
        d->op3 == SPARC64_OP3_LDFA || d->op3 == SPARC64_OP3_LDDFA ||
        d->op3 == SPARC64_OP3_STFA || d->op3 == SPARC64_OP3_STDFA) {
        return fp_ldst(cpu, mem, mc, pc, d);
    }
    return sparc64_trap(SPARC64_TRAP_ILLEGAL, pc, d->raw);
}
