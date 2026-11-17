/*
 * src/interp/fp_ldst.c — Phase 3 FP loads/stores + VIS fill/align data path.
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Data movement between memory and the FP file (plain 0x20-0x27 incl.
 * LDQF/STQF and the 0x30-0x37 alternate group; integer LDDA/STDA never
 * reach this file, see below) and the VIS fill/align helpers
 * (FZERO/FONE/FALIGNDATA). Entered from the fp.c dispatcher
 * (sparc64_fp_ldst / sparc64_fp_vis). STQF stores both quad halves in
 * order. VIS block operations (ASI 0xF0-0xF7) move plain 8-byte pieces,
 * and no instruction here ever touches FSR. All other VIS opfs trap
 * ILLEGAL.
 */

#include <stdbool.h>
#include <stdint.h>

#include "core/cpu.h"
#include "interp/fp_commit.h"
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
        sparc64_fp_mark_dirty(cpu, (fp_pair(d->rd) >= 16U) ? 1U : 0U);
        return sparc64_step_ok(pc);
    }
    if (d->opf == 0x61U) {
        cpu->fp.f[(d->rd & 31U) ^ 1U] = UINT32_C(0);
        sparc64_fp_mark_dirty(cpu, 0U);
        return sparc64_step_ok(pc);
    }
    if (d->opf == 0x7EU) {
        cpu->fp.d[fp_pair(d->rd)] = UINT64_C(0xFFFFFFFFFFFFFFFF);
        sparc64_fp_mark_dirty(cpu, (fp_pair(d->rd) >= 16U) ? 1U : 0U);
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
    sparc64_fp_mark_dirty(cpu, (fp_pair(d->rd) >= 16U) ? 1U : 0U);
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
    sparc64_fp_mark_dirty(cpu, (fp_pair(d->rd) >= 16U) ? 1U : 0U);
    return sparc64_step_ok(pc);
}

/* VIS1 logical ops (opf 0x60..0x7F): even opf is the 64-bit double
 * form, odd opf the 32-bit single form. Compilers targeting a VIS1
 * baseline (Debian sparc64) emit these for plain 64-bit integer
 * and/or/xor. Never touches FSR. */
static uint64_t vis_logic(unsigned fn, uint64_t a, uint64_t b)
{
    switch (fn) {
    case 0x0U: return UINT64_C(0);
    case 0x1U: return ~(a | b);
    case 0x2U: return a & ~b;
    case 0x3U: return ~b;
    case 0x4U: return ~a & b;
    case 0x5U: return ~a;
    case 0x6U: return a ^ b;
    case 0x7U: return ~(a & b);
    case 0x8U: return a & b;
    case 0x9U: return ~(a ^ b);
    case 0xAU: return a;
    case 0xBU: return a | ~b;
    case 0xCU: return b;
    case 0xDU: return ~a | b;
    case 0xEU: return a | b;
    default: return ~UINT64_C(0);
    }
}

static sparc64_step_result_t fp_vis_logic(sparc64_cpu_t *cpu, uint64_t pc,
    const sparc64_dec_t *d)
{
    unsigned fn = (d->opf >> 1U) & 0xFU;
    if ((d->opf & 1U) == 0U) {
        cpu->fp.d[fp_pair(d->rd)] = vis_logic(fn,
            cpu->fp.d[fp_pair(d->rs1)], cpu->fp.d[fp_pair(d->raw & 31U)]);
        sparc64_fp_mark_dirty(cpu, (fp_pair(d->rd) >= 16U) ? 1U : 0U);
    } else {
        /* Singles index the host-order halves with ^1 (see fp_zero). */
        uint64_t a = cpu->fp.f[(d->rs1 & 31U) ^ 1U];
        uint64_t b = cpu->fp.f[(d->raw & 31U) ^ 1U];
        cpu->fp.f[(d->rd & 31U) ^ 1U] = (uint32_t)vis_logic(fn, a, b);
        sparc64_fp_mark_dirty(cpu, 0U);
    }
    return sparc64_step_ok(pc);
}

sparc64_step_result_t sparc64_fp_vis(sparc64_cpu_t *cpu, uint64_t pc,
    const sparc64_dec_t *d)
{
    if (d->opf >= 0x62U && d->opf <= 0x7FU && d->opf != 0x7EU &&
        d->opf != 0x7FU) {
        return fp_vis_logic(cpu, pc, d);
    }
    if (d->opf == 0x7FU) {
        cpu->fp.f[(d->rd & 31U) ^ 1U] = UINT32_C(0xFFFFFFFF);
        sparc64_fp_mark_dirty(cpu, 0U);
        return sparc64_step_ok(pc);
    }
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

/* FP loads/stores (plain 0x20-0x27 incl. LDQF/STQF and the 0x30-0x37
 * alternate group, never integer LDDA/STDA): data movement between
 * memory and the FP file. Never touches FSR. */

/* No-fault alternate space: eligible access faults become zero on loads;
 * stores and atomics through these ASIs fault (interp_mem.c parity). */
static bool fp_nofault_asi(uint8_t asi)
{
    return asi == SPARC64_ASI_PNF || asi == SPARC64_ASI_PNFL;
}

static bool fp_eligible_fault(const sparc64_step_result_t *r)
{
    if (r->kind != SPARC64_STEP_TRAP ||
        r->cause != SPARC64_TRAP_LOAD_ACCESS) {
        return false;
    }
    switch (r->memory_reason) {
    case SPARC64_MEM_FAULT_UNMAPPED:
    case SPARC64_MEM_FAULT_PERMISSION:
    case SPARC64_MEM_FAULT_RANGE:
    case SPARC64_MEM_FAULT_BUS:
        return true;
    default:
        return false;
    }
}

/* One staged 4-byte load piece: eligible no-fault failures become zero. */
static bool fp_piece_nofault(const sparc64_mem_ops_t *mem, void *mc,
    uint64_t va, bool little, bool nofault, uint64_t *out,
    sparc64_step_result_t *res, uint64_t pc)
{
    if (sparc64_ld_int(mem, mc, va, 4U, false, little, out, res, pc)) {
        return true;
    }
    if (!nofault || !fp_eligible_fault(res)) {
        return false;
    }
    *out = UINT64_C(0);
    return true;
}
sparc64_step_result_t sparc64_fp_ldst(sparc64_ctx_t *cpu,
    const sparc64_mem_ops_t *mem, void *mc, uint64_t pc,
    const sparc64_dec_t *d)
{
    bool nofault = false;
    bool is_load;
    bool is_quad;
    bool is_double;
    bool alt;
    uint64_t va;
    bool little = false;
    sparc64_step_result_t res;
    uint64_t v = UINT64_C(0);
    unsigned qi;
    /* Integer LDDA/STDA are classified by the decoder, never here. */
    if (d->op3 == SPARC64_OP3_LDDA || d->op3 == SPARC64_OP3_STDA) {
        return sparc64_trap(SPARC64_TRAP_ILLEGAL, pc, d->raw);
    }
    is_load = (d->op3 == SPARC64_OP3_LDF ||
        d->op3 == SPARC64_OP3_LDDF ||
        d->op3 == SPARC64_OP3_LDFA || d->op3 == SPARC64_OP3_LDDFA ||
        d->op3 == SPARC64_OP3_LDTW);
    is_quad = (d->op3 == SPARC64_OP3_LDTW ||
        d->op3 == SPARC64_OP3_STTW);
    is_double = !is_quad && (d->op3 == SPARC64_OP3_LDDF ||
        d->op3 == SPARC64_OP3_STDF || d->op3 == SPARC64_OP3_LDDFA ||
        d->op3 == SPARC64_OP3_STDFA);
    alt = (d->op3 == SPARC64_OP3_LDFA ||
        d->op3 == SPARC64_OP3_LDDFA || d->op3 == SPARC64_OP3_STFA ||
        d->op3 == SPARC64_OP3_STDFA);
    va = sparc64_rreg(cpu, d->rs1) +
        ((d->is_imm != 0U) ? (uint64_t)(int64_t)d->imm
                           : sparc64_rreg(cpu, d->rs2));
    if (alt) {
        sparc64_dec_t dd = *d;
        if (dd.regasi != 0U) {
            dd.asi = (uint8_t)(cpu->asi & UINT64_C(0xFF));
        }
        if (dd.asi >= 0xF0U && dd.asi <= 0xF7U &&
            (d->op3 == SPARC64_OP3_LDDFA ||
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
                    cpu->fprs |= ((base + k) < 16U) ? UINT64_C(0x1)
                                                   : UINT64_C(0x2);
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
        nofault = fp_nofault_asi(dd.asi);
    }
    if (is_quad) {
        /* LDQF/STQF move 16 bytes at word alignment: four staged 4-byte
         * pieces, published only after all succeed. The quad slot is
         * addressed through its two double halves and stays big-endian
         * regardless of ASI. */
        uint64_t p0 = UINT64_C(0);
        uint64_t p1 = UINT64_C(0);
        uint64_t p2 = UINT64_C(0);
        uint64_t p3 = UINT64_C(0);
        uint64_t hi;
        uint64_t lo;
        qi = fp_qidx(d->rd);
        if (qi > 15U) {
            return sparc64_trap(SPARC64_TRAP_ILLEGAL, pc, d->raw);
        }
        if ((va & UINT64_C(3)) != UINT64_C(0)) {
            return sparc64_trap(is_load ? SPARC64_TRAP_LOAD_MISALIGNED
                                        : SPARC64_TRAP_STORE_MISALIGNED,
                pc, va);
        }
        if (!is_load && nofault) {
            return sparc64_trap(SPARC64_TRAP_STORE_ACCESS, pc, va);
        }
        if (is_load) {
            if (!fp_piece_nofault(mem, mc, va, false, nofault, &p0, &res,
                    pc)) {
                return res;
            }
            if (!fp_piece_nofault(mem, mc, va + UINT64_C(4), false, nofault,
                    &p1, &res, pc)) {
                return res;
            }
            if (!fp_piece_nofault(mem, mc, va + UINT64_C(8), false, nofault,
                    &p2, &res, pc)) {
                return res;
            }
            if (!fp_piece_nofault(mem, mc, va + UINT64_C(12), false,
                    nofault, &p3, &res, pc)) {
                return res;
            }
            hi = (p0 << 32) | p1;
            lo = (p2 << 32) | p3;
            cpu->fp.d[2U * qi] = hi;
            cpu->fp.d[2U * qi + 1U] = lo;
            cpu->fprs |= (qi < 8U) ? UINT64_C(0x1) : UINT64_C(0x2);
            return sparc64_step_ok(pc);
        }
        hi = cpu->fp.d[2U * qi];
        lo = cpu->fp.d[2U * qi + 1U];
        if (!sparc64_st_int(mem, mc, va, 4U, false, hi >> 32, &res, pc)) {
            return res;
        }
        if (!sparc64_st_int(mem, mc, va + UINT64_C(4), 4U, false,
                hi & UINT64_C(0xFFFFFFFF), &res, pc)) {
            return res;
        }
        if (!sparc64_st_int(mem, mc, va + UINT64_C(8), 4U, false, lo >> 32,
                &res, pc)) {
            return res;
        }
        if (!sparc64_st_int(mem, mc, va + UINT64_C(12), 4U, false,
                lo & UINT64_C(0xFFFFFFFF), &res, pc)) {
            return res;
        }
        return sparc64_step_ok(pc);
    }
    if (is_load) {
        if ((va & UINT64_C(3)) != UINT64_C(0)) {
            return sparc64_trap(SPARC64_TRAP_LOAD_MISALIGNED, pc, va);
        }
        if (is_double) {
            uint64_t p0 = UINT64_C(0);
            uint64_t p1 = UINT64_C(0);
            if (!fp_piece_nofault(mem, mc, va, little, nofault, &p0, &res,
                    pc)) {
                return res;
            }
            if (!fp_piece_nofault(mem, mc, va + UINT64_C(4), little,
                    nofault, &p1, &res, pc)) {
                return res;
            }
            v = little ? (p0 | (p1 << 32)) : ((p0 << 32) | p1);
            cpu->fp.d[fp_pair(d->rd)] = v;
            cpu->fprs |= (fp_pair(d->rd) < 16U) ? UINT64_C(0x1)
                                               : UINT64_C(0x2);
        } else {
            if (!fp_piece_nofault(mem, mc, va, little, nofault, &v, &res,
                    pc)) {
                return res;
            }
            cpu->fp.f[(d->rd & 31U) ^ 1U] = (uint32_t)v;
            cpu->fprs |= UINT64_C(0x1);
        }
        return sparc64_step_ok(pc);
    }
    if ((va & UINT64_C(3)) != UINT64_C(0)) {
        return sparc64_trap(SPARC64_TRAP_STORE_MISALIGNED, pc, va);
    }
    if (nofault) {
        return sparc64_trap(SPARC64_TRAP_STORE_ACCESS, pc, va);
    }
    v = is_double ? cpu->fp.d[fp_pair(d->rd)]
                  : (uint64_t)cpu->fp.f[(d->rd & 31U) ^ 1U];
    if (is_double) {
        uint64_t p0 = little ? (v & UINT64_C(0xFFFFFFFF)) : (v >> 32);
        uint64_t p1 = little ? (v >> 32) : (v & UINT64_C(0xFFFFFFFF));
        if (!sparc64_st_int(mem, mc, va, 4U, little, p0, &res, pc)) {
            return res;
        }
        if (!sparc64_st_int(mem, mc, va + UINT64_C(4), 4U, little, p1, &res,
                pc)) {
            return res;
        }
    } else if (!sparc64_st_int(mem, mc, va, 4U, little, v, &res, pc)) {
        return res;
    }
    return sparc64_step_ok(pc);
}
