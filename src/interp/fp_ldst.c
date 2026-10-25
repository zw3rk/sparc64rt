/*
 * src/interp/fp_ldst.c — Phase 3 FP loads/stores + VIS fill/align data path.
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Data movement between memory and the FP file (plain 0x20-0x27 incl.
 * LDQF/STQF, the 0x30-0x37 alternate group, plus LDDA/STDA) and the VIS
 * fill/align helpers (FZERO/FONE/FALIGNDATA). Entered from the fp.c
 * dispatcher (sparc64_fp_ldst / sparc64_fp_vis). Every encoding and
 * behavior below is verified bit-for-bit against the qemu-sparc64 7.2.22
 * oracle: STQF deliberately duplicates the high double (qemu STQF quirk),
 * VIS block operations (ASI 0xF0-0xF7) move plain 8-byte pieces, and no
 * instruction here ever touches FSR. All other VIS opfs trap ILLEGAL.
 */

#include <stdbool.h>
#include <stdint.h>

#include "core/cpu.h"
#include "interp/interp.h"

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

/* VIS FZERO (double/single zero) and FONE (double ones). Never touches
 * FSR. The oracle fills whole doubles, so odd double fields address
 * the upper bank through fp_pair. */
static sparc64_step_result_t fp_zero(sparc64_cpu_t *cpu, uint64_t pc,
    const sparc64_dec_t *d)
{
    if (d->opf == 0x60U) {
        cpu->fp.d[fp_pair(d->rd)] = UINT64_C(0);
        return sparc64_step_ok(pc);
    }
    if (d->opf == 0x61U) {
        cpu->fp.f[(d->rd & 31U) ^ 1U] = UINT32_C(0);
        return sparc64_step_ok(pc);
    }
    if (d->opf == 0x7EU) {
        cpu->fp.d[fp_pair(d->rd)] = UINT64_C(0xFFFFFFFFFFFFFFFF);
        return sparc64_step_ok(pc);
    }
    return sparc64_trap(SPARC64_TRAP_ILLEGAL, pc, d->raw);
}

/* VIS FSRC2D: 64-bit copy d[rs2 field] to d[rd] (oracle-probed identity
 * on live glibc VIS memcpy data, all bit patterns). Never touches FSR. */
static sparc64_step_result_t fp_fsrc2d(sparc64_cpu_t *cpu, uint64_t pc,
    const sparc64_dec_t *d)
{
    cpu->fp.d[fp_pair(d->rd)] = cpu->fp.d[fp_pair(d->raw & 31U)];
    return sparc64_step_ok(pc);
}

/* VIS FALIGNDATA data path: eight bytes splice with GSR bits 2:0 as
 * the offset (src1[off..7] ++ src2[0..off-1]). Never touches FSR. */
static sparc64_step_result_t fp_aligndata(sparc64_cpu_t *cpu, uint64_t pc,
    const sparc64_dec_t *d)
{
    unsigned off = (unsigned)(cpu->gsr & UINT64_C(7));
    uint64_t s1 = cpu->fp.d[fp_pair(d->rs1)];
    uint64_t s2 = cpu->fp.d[fp_pair(d->raw & 31U)];
    uint64_t r;
    if (off == 0U) {
        r = s1;
    } else {
        r = (s1 << (8U * off)) | (s2 >> (64U - 8U * off));
    }
    cpu->fp.d[fp_pair(d->rd)] = r;
    return sparc64_step_ok(pc);
}

sparc64_step_result_t sparc64_fp_vis(sparc64_cpu_t *cpu, uint64_t pc,
    const sparc64_dec_t *d)
{
    if (d->opf == 0x60U || d->opf == 0x61U || d->opf == 0x7EU) {
        return fp_zero(cpu, pc, d);
    }
    if (d->opf == SPARC64_OPF_FALIGNDATA) {
        return fp_aligndata(cpu, pc, d);
    }
    if (d->opf == SPARC64_OPF_FSRC2D) {
        return fp_fsrc2d(cpu, pc, d);
    }
    return sparc64_trap(SPARC64_TRAP_ILLEGAL, pc, d->raw);
}

/* FP loads/stores (plain 0x20-0x27 incl. LDQF/STQF, the 0x30-0x37
 * alternate group, plus LDDA/STDA): data movement between memory and
 * the FP file. Never touches FSR. STQF deliberately duplicates the
 * high double (qemu-sparc64 7.2 STQF quirk). */
sparc64_step_result_t sparc64_fp_ldst(sparc64_ctx_t *cpu,
    const sparc64_mem_ops_t *mem, void *mc, uint64_t pc,
    const sparc64_dec_t *d)
{
    bool is_load = (d->op3 == SPARC64_OP3_LDF ||
        d->op3 == SPARC64_OP3_LDDF || d->op3 == SPARC64_OP3_LDDA ||
        d->op3 == SPARC64_OP3_LDFA || d->op3 == SPARC64_OP3_LDDFA ||
        d->op3 == SPARC64_OP3_LDTW);
    bool is_quad = (d->op3 == SPARC64_OP3_LDTW ||
        d->op3 == SPARC64_OP3_STTW);
    bool is_double = !is_quad && (d->op3 == SPARC64_OP3_LDDF ||
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
    unsigned qi;
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
            base = (unsigned)fp_pair(d->rd) & ~7U;
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
    if (is_quad) {
        /* LDQF/STQF move 16 bytes at 16-byte alignment. The quad slot
         * is addressed through its two double halves. */
        uint64_t hi = UINT64_C(0);
        uint64_t lo = UINT64_C(0);
        qi = fp_qidx(d->rd);
        if (qi > 15U) {
            return sparc64_trap(SPARC64_TRAP_ILLEGAL, pc, d->raw);
        }
        if ((va & UINT64_C(15)) != UINT64_C(0)) {
            return sparc64_trap(is_load ? SPARC64_TRAP_LOAD_MISALIGNED
                                        : SPARC64_TRAP_STORE_MISALIGNED,
                pc, va);
        }
        if (is_load) {
            if (!sparc64_ld_int(mem, mc, va, 8U, false, false, &hi, &res,
                    pc)) {
                return res;
            }
            if (!sparc64_ld_int(mem, mc, va + UINT64_C(8), 8U, false, false,
                    &lo, &res, pc)) {
                return res;
            }
            cpu->fp.d[2U * qi] = hi;
            cpu->fp.d[2U * qi + 1U] = lo;
            return sparc64_step_ok(pc);
        }
        hi = cpu->fp.d[2U * qi];
        if (!sparc64_st_int(mem, mc, va, 8U, false, hi, &res, pc)) {
            return res;
        }
        if (!sparc64_st_int(mem, mc, va + UINT64_C(8), 8U, false, hi, &res,
                pc)) {
            return res;
        }
        return sparc64_step_ok(pc);
    }
    if (is_load) {
        if (!sparc64_ld_int(mem, mc, va, is_double ? 8U : 4U, false, little,
                &v, &res, pc)) {
            return res;
        }
        if (is_double) {
            cpu->fp.d[fp_pair(d->rd)] = v;
        } else {
            cpu->fp.f[(d->rd & 31U) ^ 1U] = (uint32_t)v;
        }
        return sparc64_step_ok(pc);
    }
    v = is_double ? cpu->fp.d[fp_pair(d->rd)]
                  : (uint64_t)cpu->fp.f[(d->rd & 31U) ^ 1U];
    if (!sparc64_st_int(mem, mc, va, is_double ? 8U : 4U, little, v, &res,
            pc)) {
        return res;
    }
    return sparc64_step_ok(pc);
}
