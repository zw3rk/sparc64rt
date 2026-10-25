/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Base integer reference interpreter (Phase 1, L1b): sparc64_decode /
 * sparc64_step / sparc64_step_with_insn over sparc64_mem_ops_t.
 *
 * Encoding authority: SPARC V9 (Oracle M8 / SPARC64 XII), verified against
 * the binutils disassembler and the qemu-sparc64 oracle via the Phase E
 * experiments (E01 stack bias 2047 + 128-byte spill/fill; E02 dual
 * icc/xcc carry + borrow; E03 BPcc/BPr/MOVcc/MOVr/CASA/LE-ASI; E04 signal
 * frame geometry; E05 FPU/VIS markers + ALIGNADDR semantics).
 *
 * Notable model choices:
 * - All operands, addresses, and results are full 64-bit; nothing is
 *   truncated to 32 bits. %g0 reads as 0, writes to %g0 are dropped.
 * - Every *cc ALU op updates both nibbles from its own operand width
 *   (icc from the low 32-bit result, xcc from the full 64-bit result);
 *   SUBcc carry is the borrow (C=1 iff src1 < src2 unsigned, E02).
 *   ADDX/SUBX(+cc) carry in from icc.C (oracle-verified).
 * - Unaligned loads/stores emulate byte-wise and never fault.
 * - Atomics prefer the host-CAS substrate (LR/SC loop for CASA/CASXA,
 *   SWAP op for LDSTUB/SWAP) and fall back to read/compare/write.
 * - ta 0x6d returns SPARC64_STEP_SYSCALL with no register or pc change;
 *   the syscall layer (L1c) applies the dual-carry update and the
 *   pc = npc / npc += 4 advance per SPEC 2.1. Other true Tcc, FPop/FP
 *   markers (Phase 3), and reserved words trap ILLEGAL; privileged state
 *   access traps PRIVILEGED. There is no EXIT_UNDEF step kind; Phase 3
 *   markers surface as TRAP/ILLEGAL with the raw word in tval.
 * - CASA/CASXA follow the E03 i-bit rule (i == 0: 8-bit immediate ASI
 *   from bits 12:5; i == 1: %asi-register form, which the linux-user
 *   oracle faults, so the interpreter reports a load-access trap).
 */

#include "interp/interp.h"

static void sparc64_decode_op2(sparc64_dec_t *d, uint32_t word, unsigned op3,
    unsigned rd, unsigned rs1, unsigned i);
static void sparc64_decode_op3(sparc64_dec_t *d, uint32_t word, unsigned op3,
    unsigned rd, unsigned rs1, unsigned i);
static sparc64_step_result_t exec_single(sparc64_cpu_t *cpu,
    const sparc64_mem_ops_t *mem, void *mc, uint64_t pc, const sparc64_dec_t *d);
static sparc64_step_result_t exec_cti(sparc64_cpu_t *cpu,
    const sparc64_mem_ops_t *mem, void *mc, uint64_t pc, const sparc64_dec_t *d);
static sparc64_step_result_t exec_tcc(sparc64_cpu_t *cpu, uint64_t pc,
    const sparc64_dec_t *d);

/* Bit-field and sign-extension helpers (inclusive hi..lo). */
static unsigned fld(uint32_t w, unsigned hi, unsigned lo)
{
    return (unsigned)((w >> lo) &
        (uint32_t)(((UINT64_C(1) << (hi - lo + 1U)) - UINT64_C(1))));
}

static int64_t sx(uint64_t v, unsigned n)
{
    uint64_t m = UINT64_C(1) << (n - 1U);
    return (int64_t)((v ^ m) - m);
}

/* Bicc/BPcc/Ticc/MOVcc condition over one 4-bit N/Z/V/C nibble
 * (bit 3 N, bit 2 Z, bit 1 V, bit 0 C). */
bool sparc64_eval_cond(unsigned cond, unsigned nibble)
{
    bool n = (nibble & 8U) != 0U;
    bool z = (nibble & 4U) != 0U;
    bool v = (nibble & 2U) != 0U;
    bool c = (nibble & 1U) != 0U;
    switch (cond & 15U) {
    case 0x0U: return false;
    case 0x1U: return z;
    case 0x2U: return z || (n != v);
    case 0x3U: return n != v;
    case 0x4U: return c || z;
    case 0x5U: return c;
    case 0x6U: return n;
    case 0x7U: return v;
    case 0x8U: return true;
    case 0x9U: return !z;
    case 0xAU: return !(z || (n != v));
    case 0xBU: return n == v;
    case 0xCU: return !(c || z);
    case 0xDU: return !c;
    case 0xEU: return !n;
    default: return !v;
    }
}

/* BPr/MOVr register test over the full 64-bit value. rcond skips 4. */
bool sparc64_eval_rcond(unsigned rcond, uint64_t v)
{
    switch (rcond & 15U) {
    case 1U: return v == UINT64_C(0);
    case 2U: return (int64_t)v <= (int64_t)0;
    case 3U: return (int64_t)v < (int64_t)0;
    case 5U: return v != UINT64_C(0);
    case 6U: return (int64_t)v > (int64_t)0;
    case 7U: return (int64_t)v >= (int64_t)0;
    default: return false;
    }
}

static bool rcond_valid(unsigned rcond)
{
    return rcond == 1U || rcond == 2U || rcond == 3U || rcond == 5U ||
        rcond == 6U || rcond == 7U;
}

/* Pure word classifier: fills *out for any raw word. Illegal words yield
 * SPARC64_ICLS_ILLEGAL; execution traps them in step. */
void sparc64_decode_word(uint32_t word, sparc64_dec_t *d)
{
    unsigned op;
    d->raw = word;
    d->cls = SPARC64_ICLS_ILLEGAL;
    d->op = 0U;
    d->op3 = 0U;
    d->rd = 0U;
    d->rs1 = 0U;
    d->rs2 = 0U;
    d->cond = 0U;
    d->cc = 0U;
    d->asi = 0U;
    d->annul = 0U;
    d->pred = 0U;
    d->is_imm = 0U;
    d->xbit = 0U;
    d->imm = 0;
    d->disp = 0;
    d->opf = 0U;
    d->uimm = 0U;
    op = fld(word, 31U, 30U);
    d->op = (uint8_t)op;
    if (op == 1U) {
        d->cls = SPARC64_ICLS_CALL;
        d->disp = (int64_t)sx(word & UINT32_C(0x3FFFFFFF), 30U) << 2;
        return;
    }
    if (op == 0U) {
        unsigned op2 = fld(word, 24U, 22U);
        if (op2 == 1U) {
            unsigned cc = fld(word, 21U, 20U);
            if (cc != 0U && cc != 2U) {
                return;
            }
            d->cls = SPARC64_ICLS_BPCC;
            d->annul = (uint8_t)fld(word, 29U, 29U);
            d->cond = (uint8_t)fld(word, 28U, 25U);
            d->cc = (uint8_t)cc;
            d->pred = (uint8_t)fld(word, 19U, 19U);
            d->disp = (int64_t)sx(fld(word, 18U, 0U), 19U) << 2;
            return;
        }
        if (op2 == 2U) {
            d->cls = SPARC64_ICLS_BICC;
            d->annul = (uint8_t)fld(word, 29U, 29U);
            d->cond = (uint8_t)fld(word, 28U, 25U);
            d->disp = (int64_t)sx(fld(word, 21U, 0U), 22U) << 2;
            return;
        }
        if (op2 == 3U) {
            unsigned rcond = fld(word, 28U, 25U);
            uint32_t d16;
            if (!rcond_valid(rcond)) {
                return;
            }
            d->cls = SPARC64_ICLS_BPR;
            d->annul = (uint8_t)fld(word, 29U, 29U);
            d->cond = (uint8_t)rcond;
            d->pred = (uint8_t)fld(word, 19U, 19U);
            d->rs1 = (uint8_t)fld(word, 18U, 14U);
            d16 = (fld(word, 21U, 20U) << 14) | fld(word, 13U, 0U);
            d->disp = (int64_t)sx(d16, 16U) << 2;
            return;
        }
        if (op2 == 4U) {
            d->cls = SPARC64_ICLS_SETHI;
            d->rd = (uint8_t)fld(word, 29U, 25U);
            d->uimm = fld(word, 21U, 0U);
            return;
        }
        if (op2 == 6U) {
            d->cls = SPARC64_ICLS_FBR;
            d->annul = (uint8_t)fld(word, 29U, 29U);
            d->cond = (uint8_t)fld(word, 28U, 25U);
            d->disp = (int64_t)sx(fld(word, 21U, 0U), 22U) << 2;
            return;
        }
        return;
    }
    if (op == 2U || op == 3U) {
        unsigned op3 = fld(word, 24U, 19U);
        unsigned rd = fld(word, 29U, 25U);
        unsigned rs1 = fld(word, 18U, 14U);
        unsigned i = fld(word, 13U, 13U);
        d->op3 = (uint8_t)op3;
        d->rd = (uint8_t)rd;
        d->rs1 = (uint8_t)rs1;
        d->is_imm = (uint8_t)i;
        if (op == 2U) {
            sparc64_decode_op2(d, word, op3, rd, rs1, i);
            return;
        }
        sparc64_decode_op3(d, word, op3, rd, rs1, i);
        return;
    }
}

/* Format-3 ALU/misc classifier (op == 2). */
static void sparc64_decode_op2(sparc64_dec_t *d, uint32_t word, unsigned op3,
    unsigned rd, unsigned rs1, unsigned i)
{
    /* Integer ALU (dual-width cc), MULX/DIVX/POPC, TADD/TSUB, MULScc. */
    switch (op3) {
    case SPARC64_OP3_ADD:
    case SPARC64_OP3_AND:
    case SPARC64_OP3_OR:
    case SPARC64_OP3_XOR:
    case SPARC64_OP3_SUB:
    case SPARC64_OP3_ANDN:
    case SPARC64_OP3_ORN:
    case SPARC64_OP3_XORN:
    case SPARC64_OP3_ADDX:
    case SPARC64_OP3_MULX:
    case SPARC64_OP3_UMUL:
    case SPARC64_OP3_SMUL:
    case SPARC64_OP3_SUBX:
    case SPARC64_OP3_UDIVX:
    case SPARC64_OP3_UDIV:
    case SPARC64_OP3_SDIV:
    case SPARC64_OP3_ADDCC:
    case SPARC64_OP3_ANDCC:
    case SPARC64_OP3_ORCC:
    case SPARC64_OP3_XORCC:
    case SPARC64_OP3_SUBCC:
    case SPARC64_OP3_ANDNCC:
    case SPARC64_OP3_ORNCC:
    case SPARC64_OP3_XORNCC:
    case SPARC64_OP3_ADDXCC:
    case SPARC64_OP3_UMULCC:
    case SPARC64_OP3_SMULCC:
    case SPARC64_OP3_SUBXCC:
    case SPARC64_OP3_UDIVCC:
    case SPARC64_OP3_SDIVCC:
    case SPARC64_OP3_TADDCC:
    case SPARC64_OP3_TSUBCC:
    case SPARC64_OP3_TADDCTV:
    case SPARC64_OP3_TSUBCTV:
    case SPARC64_OP3_MULSCC:
    case SPARC64_OP3_SDIVX:
    case SPARC64_OP3_POPC:
        if (op3 == SPARC64_OP3_TADDCC && rd == 31U && rs1 == 0U &&
            i == 1U) {
            /* SIR (software-initiated reset) shares the TADDcc opcode. */
            d->cls = SPARC64_ICLS_PRIV;
            return;
        }
        d->cls = SPARC64_ICLS_ALU;
        if (i != 0U) {
            d->imm = (int64_t)sx(fld(word, 12U, 0U), 13U);
        } else {
            d->rs2 = (uint8_t)fld(word, 4U, 0U);
        }
        return;
    case SPARC64_OP3_SLL:
    case SPARC64_OP3_SRL:
    case SPARC64_OP3_SRA:
        d->cls = SPARC64_ICLS_SHIFT;
        d->xbit = (uint8_t)fld(word, 12U, 12U);
        if (i != 0U) {
            d->imm = (int64_t)fld(word, 11U, 0U);
        } else {
            d->rs2 = (uint8_t)fld(word, 4U, 0U);
        }
        return;
    case SPARC64_OP3_MOVCC:
        if (fld(word, 18U, 18U) == 0U) {
            /* MEMBAR shares op3 0x2C; bit 18 selects the integer MOVcc. */
            d->cls = SPARC64_ICLS_MEMBAR;
            return;
        } {
            unsigned cc = fld(word, 12U, 11U);
            if (cc != 0U && cc != 2U) {
                return;
            }
            d->cls = SPARC64_ICLS_MOVCC;
            d->cond = (uint8_t)fld(word, 17U, 14U);
            d->cc = (uint8_t)cc;
            if (i != 0U) {
                d->imm = (int64_t)sx(fld(word, 10U, 0U), 11U);
            } else {
                d->rs2 = (uint8_t)fld(word, 4U, 0U);
            }
            return;
        }
    case SPARC64_OP3_MOVR: {
        unsigned rcond = fld(word, 12U, 10U);
        if (!rcond_valid(rcond)) {
            return;
        }
        d->cls = SPARC64_ICLS_MOVR;
        d->cond = (uint8_t)rcond;
        if (i != 0U) {
            d->imm = (int64_t)sx(fld(word, 9U, 0U), 10U);
        } else {
            d->rs2 = (uint8_t)fld(word, 4U, 0U);
        }
        return;
    }
    case SPARC64_OP3_RDASR:
        if (rs1 == SPARC64_ASR_Y || rs1 == SPARC64_ASR_CCR ||
            rs1 == SPARC64_ASR_ASI || rs1 == SPARC64_ASR_FPRS ||
            rs1 == SPARC64_ASR_GSR) {
            d->cls = SPARC64_ICLS_RDASR;
            return;
        }
        if (rs1 == SPARC64_ASR_TICK || rs1 == SPARC64_ASR_PC ||
            (rs1 >= 20U && rs1 <= 25U)) {
            /* TICK/PC/SOFTINT/TICK_CMPR/STICK are supervisor-only. */
            d->cls = SPARC64_ICLS_PRIV;
            return;
        }
        /* Unassigned ASR numbers trap illegal_instruction. */
        return;
    case SPARC64_OP3_WRASR:
        if (rd == SPARC64_ASR_Y || rd == SPARC64_ASR_CCR ||
            rd == SPARC64_ASR_ASI || rd == SPARC64_ASR_FPRS ||
            rd == SPARC64_ASR_GSR) {
            d->cls = SPARC64_ICLS_WRASR;
            if (i != 0U) {
                d->imm = (int64_t)sx(fld(word, 12U, 0U), 13U);
            } else {
                d->rs2 = (uint8_t)fld(word, 4U, 0U);
            }
            return;
        }
        if (rd == SPARC64_ASR_TICK || rd == SPARC64_ASR_PC ||
            (rd >= 20U && rd <= 25U)) {
            d->cls = SPARC64_ICLS_PRIV;
            return;
        }
        return;
    case SPARC64_OP3_RDPR:
    case SPARC64_OP3_RDHPR:
    case SPARC64_OP3_FLUSHW:
    case SPARC64_OP3_WRPR:
    case SPARC64_OP3_WRHPR:
    case SPARC64_OP3_DONE:
    case SPARC64_OP3_RETRY:
        d->cls = SPARC64_ICLS_PRIV;
        return;
    case SPARC64_OP3_FPOP1:
    case SPARC64_OP3_FPOP2:
        d->cls = SPARC64_ICLS_FPU;
        d->opf = fld(word, 13U, 5U);
        return;
    case SPARC64_OP3_VIS: {
        uint32_t opf = fld(word, 13U, 5U);
        d->opf = opf;
        if (opf == SPARC64_OPF_ALIGNADDR ||
            opf == SPARC64_OPF_ALIGNADDRL) {
            d->cls = SPARC64_ICLS_ALIGN;
            if (i != 0U) {
                d->imm = (int64_t)sx(fld(word, 12U, 0U), 13U);
            } else {
                d->rs2 = (uint8_t)fld(word, 4U, 0U);
            }
            return;
        }
        /* FALIGNDATA and the remaining VIS ops need the FPU file. */
        d->cls = SPARC64_ICLS_FPU;
        return;
    }
    case SPARC64_OP3_JMPL:
        d->cls = SPARC64_ICLS_JMPL;
        if (i != 0U) {
            d->imm = (int64_t)sx(fld(word, 12U, 0U), 13U);
        } else {
            d->rs2 = (uint8_t)fld(word, 4U, 0U);
        }
        return;
    case SPARC64_OP3_RETURN:
        d->cls = SPARC64_ICLS_RETURN;
        if (i != 0U) {
            d->imm = (int64_t)sx(fld(word, 12U, 0U), 13U);
        } else {
            d->rs2 = (uint8_t)fld(word, 4U, 0U);
        }
        return;
    case SPARC64_OP3_TCC: {
        unsigned cc = fld(word, 12U, 11U);
        if (cc != 0U && cc != 2U) {
            return;
        }
        d->cls = SPARC64_ICLS_TCC;
        d->cond = d->rd;
        d->cc = (uint8_t)cc;
        if (i != 0U) {
            if (fld(word, 10U, 7U) != 0U) {
                d->cls = SPARC64_ICLS_ILLEGAL;
                return;
            }
            d->imm = (int64_t)fld(word, 6U, 0U);
        } else {
            d->rs2 = (uint8_t)fld(word, 4U, 0U);
        }
        return;
    }
    case SPARC64_OP3_FLUSH:
        d->cls = SPARC64_ICLS_FLUSH;
        return;
    case SPARC64_OP3_SAVE:
        d->cls = SPARC64_ICLS_SAVE;
        if (i != 0U) {
            d->imm = (int64_t)sx(fld(word, 12U, 0U), 13U);
        } else {
            d->rs2 = (uint8_t)fld(word, 4U, 0U);
        }
        return;
    case SPARC64_OP3_RESTORE:
        d->cls = SPARC64_ICLS_RESTORE;
        if (i != 0U) {
            d->imm = (int64_t)sx(fld(word, 12U, 0U), 13U);
        } else {
            d->rs2 = (uint8_t)fld(word, 4U, 0U);
        }
        return;
    default:
        return;
    }
}

/* Format-3 memory classifier (op == 3). Alternate-space forms carry an
 * 8-bit immediate ASI in bits 12:5 when i == 0 (E03); the i == 1
 * %asi-register form has no linux-user oracle mapping and traps. */
static void sparc64_decode_op3(sparc64_dec_t *d, uint32_t word, unsigned op3,
    unsigned rd, unsigned rs1, unsigned i)
{
    bool alt;
    (void)rd;
    (void)rs1;
    switch (op3) {
    case SPARC64_OP3_LDUW:
    case SPARC64_OP3_LDUB:
    case SPARC64_OP3_LDUH:
    case SPARC64_OP3_LDD:
    case SPARC64_OP3_STW:
    case SPARC64_OP3_STB:
    case SPARC64_OP3_STH:
    case SPARC64_OP3_STD:
    case SPARC64_OP3_LDSW:
    case SPARC64_OP3_LDSB:
    case SPARC64_OP3_LDSH:
    case SPARC64_OP3_LDX:
    case SPARC64_OP3_STX:
    case SPARC64_OP3_LDSTUB:
    case SPARC64_OP3_SWAP:
    case SPARC64_OP3_LDA:
    case SPARC64_OP3_LDUBA:
    case SPARC64_OP3_LDUHA:
    case SPARC64_OP3_LDDA:
    case SPARC64_OP3_STA:
    case SPARC64_OP3_STBA:
    case SPARC64_OP3_STHA:
    case SPARC64_OP3_STDA:
    case SPARC64_OP3_LDSWA:
    case SPARC64_OP3_LDSBA:
    case SPARC64_OP3_LDSHA:
    case SPARC64_OP3_LDXA:
    case SPARC64_OP3_STXA:
    case SPARC64_OP3_LDSTUBA:
    case SPARC64_OP3_SWAPA:
    case SPARC64_OP3_CASA:
    case SPARC64_OP3_CASXA:
        break;
    case SPARC64_OP3_LDFSR:
    case SPARC64_OP3_STFSR:
        /* FSR is integer-modeled; only the F-file forms trap. */
        break;
    case SPARC64_OP3_PREFETCH:
        d->cls = SPARC64_ICLS_FLUSH;
        return;
    default:
        /* Unassigned op3, FP-file loads/stores, ILLTRAP/UNIMP space. */
        if (op3 == SPARC64_OP3_LDF || op3 == SPARC64_OP3_LDTW ||
            op3 == SPARC64_OP3_LDDF || op3 == SPARC64_OP3_STF ||
            op3 == SPARC64_OP3_STTW || op3 == SPARC64_OP3_STDF) {
            d->cls = SPARC64_ICLS_FPU;
        }
        return;
    }
    alt = (op3 >= SPARC64_OP3_LDA && op3 <= SPARC64_OP3_SWAPA) ||
        op3 == SPARC64_OP3_CASA || op3 == SPARC64_OP3_CASXA;
    if ((op3 == SPARC64_OP3_LDD || op3 == SPARC64_OP3_STD ||
            op3 == SPARC64_OP3_LDDA || op3 == SPARC64_OP3_STDA) &&
        (d->rd & 1U) != 0U) {
        /* Twin-word destinations must be even. */
        d->cls = SPARC64_ICLS_ILLEGAL;
        return;
    }
    if (alt) {
        if (i == 0U) {
            d->asi = (uint8_t)fld(word, 12U, 5U);
        } else {
            /* %asi-register form: no oracle mapping, fault like qemu. */
            d->asi = 0xFFU;
        }
    }
    /* Address operand decodes uniformly; alternate i == 1 traps on asi. */
    if (i != 0U) {
        d->imm = (int64_t)sx(fld(word, 12U, 0U), 13U);
    } else {
        d->rs2 = (uint8_t)fld(word, 4U, 0U);
    }
    switch (op3) {
    case SPARC64_OP3_LDUW:
    case SPARC64_OP3_LDUB:
    case SPARC64_OP3_LDUH:
    case SPARC64_OP3_LDD:
    case SPARC64_OP3_LDSW:
    case SPARC64_OP3_LDSB:
    case SPARC64_OP3_LDSH:
    case SPARC64_OP3_LDX:
    case SPARC64_OP3_LDA:
    case SPARC64_OP3_LDUBA:
    case SPARC64_OP3_LDUHA:
    case SPARC64_OP3_LDDA:
    case SPARC64_OP3_LDSWA:
    case SPARC64_OP3_LDSBA:
    case SPARC64_OP3_LDSHA:
    case SPARC64_OP3_LDXA:
    case SPARC64_OP3_LDFSR:
        d->cls = SPARC64_ICLS_LOAD;
        return;
    case SPARC64_OP3_STW:
    case SPARC64_OP3_STB:
    case SPARC64_OP3_STH:
    case SPARC64_OP3_STD:
    case SPARC64_OP3_STA:
    case SPARC64_OP3_STBA:
    case SPARC64_OP3_STHA:
    case SPARC64_OP3_STDA:
    case SPARC64_OP3_STXA:
    case SPARC64_OP3_STFSR:
        d->cls = SPARC64_ICLS_STORE;
        return;
    case SPARC64_OP3_LDSTUB:
    case SPARC64_OP3_LDSTUBA:
        d->cls = SPARC64_ICLS_LDSTUB;
        return;
    case SPARC64_OP3_SWAP:
    case SPARC64_OP3_SWAPA:
        d->cls = SPARC64_ICLS_SWAP;
        return;
    default:
        d->cls = SPARC64_ICLS_ATOMIC;
        return;
    }
}

/* Single non-CTI instruction. Returns CONTINUE (caller advances pc/npc)
 * or a stop result (trap/syscall/fault, pc unchanged). */
static sparc64_step_result_t exec_single(sparc64_cpu_t *cpu,
    const sparc64_mem_ops_t *mem, void *mc, uint64_t pc, const sparc64_dec_t *d)
{
    uint64_t sum;
    sparc64_step_result_t res;
    switch (d->cls) {
    case SPARC64_ICLS_SETHI:
        sparc64_wreg(cpu, d->rd, (uint64_t)d->uimm << 10);
        return sparc64_step_ok(pc);
    case SPARC64_ICLS_ALU:
        return sparc64_exec_alu(cpu, pc, d);
    case SPARC64_ICLS_SHIFT:
        return sparc64_exec_shift(cpu, pc, d);
    case SPARC64_ICLS_MOVCC:
    case SPARC64_ICLS_MOVR:
        return sparc64_exec_mov(cpu, pc, d);
    case SPARC64_ICLS_RDASR:
        return sparc64_exec_rdasr(cpu, pc, d);
    case SPARC64_ICLS_WRASR:
        return sparc64_exec_wrasr(cpu, pc, d);
    case SPARC64_ICLS_MEMBAR:
    case SPARC64_ICLS_FLUSH:
        return sparc64_step_ok(pc);
    case SPARC64_ICLS_ALIGN:
        return sparc64_exec_align(cpu, pc, d);
    case SPARC64_ICLS_LOAD:
        return sparc64_exec_load(cpu, mem, mc, pc, d);
    case SPARC64_ICLS_STORE:
        return sparc64_exec_store(cpu, mem, mc, pc, d);
    case SPARC64_ICLS_LDSTUB:
    case SPARC64_ICLS_SWAP:
    case SPARC64_ICLS_ATOMIC:
        return sparc64_exec_atomic(cpu, mem, mc, pc, d);
    case SPARC64_ICLS_SAVE:
        sum = sparc64_rreg(cpu, d->rs1) +
            ((d->is_imm != 0U) ? (uint64_t)d->imm
                               : sparc64_rreg(cpu, d->rs2));
        if (!sparc64_win_save(cpu, mem, mc, sum, d->rd, &res, pc)) {
            return res;
        }
        return sparc64_step_ok(pc);
    case SPARC64_ICLS_RESTORE:
        sum = sparc64_rreg(cpu, d->rs1) +
            ((d->is_imm != 0U) ? (uint64_t)d->imm
                               : sparc64_rreg(cpu, d->rs2));
        if (!sparc64_win_restore(cpu, mem, mc, sum, d->rd, &res, pc)) {
            return res;
        }
        return sparc64_step_ok(pc);
    case SPARC64_ICLS_PRIV:
        return sparc64_trap(SPARC64_TRAP_PRIVILEGED, pc, d->raw);
    case SPARC64_ICLS_FPU:
    case SPARC64_ICLS_ILLEGAL:
    case SPARC64_ICLS_FBR:
    default:
        /* FBR (Phase 3 owns fcc) and FPU markers trap like EXIT_UNDEF. */
        return sparc64_trap(SPARC64_TRAP_ILLEGAL, pc, d->raw);
    }
}

/* Delay-slot execution: fetches, decodes, and runs the single delay
 * instruction. A nested CTI takes over the transfer (outer cancelled);
 * any stop result propagates with pc/npc unchanged. */
static bool exec_delay(sparc64_cpu_t *cpu, const sparc64_mem_ops_t *mem,
    void *mc, uint64_t delay_pc, sparc64_step_result_t *res)
{
    uint32_t raw;
    sparc64_dec_t dd;
    sparc64_step_result_t r;
    if (!sparc64_fetch_word(mem, mc, delay_pc, &raw, res)) {
        return false;
    }
    sparc64_decode_word(raw, &dd);
    if (dd.cls == (uint8_t)SPARC64_ICLS_CALL ||
        dd.cls == (uint8_t)SPARC64_ICLS_JMPL ||
        dd.cls == (uint8_t)SPARC64_ICLS_RETURN ||
        dd.cls == (uint8_t)SPARC64_ICLS_BICC ||
        dd.cls == (uint8_t)SPARC64_ICLS_BPCC ||
        dd.cls == (uint8_t)SPARC64_ICLS_BPR) {
        *res = exec_cti(cpu, mem, mc, delay_pc, &dd);
        if (res->kind != SPARC64_STEP_CONTINUE) {
            return false;
        }
        return true;
    }
    if (dd.cls == (uint8_t)SPARC64_ICLS_TCC) {
        /* A trap-condition in the delay slot evaluates normally: a false
         * condition is a nop, a true one stops the outer transfer. */
        r = exec_tcc(cpu, delay_pc, &dd);
        if (r.kind != SPARC64_STEP_CONTINUE) {
            *res = r;
            return false;
        }
        return true;
    }
    r = exec_single(cpu, mem, mc, delay_pc, &dd);
    if (r.kind != SPARC64_STEP_CONTINUE) {
        *res = r;
        return false;
    }
    return true;
}

/* Control transfer at pc (cpu->npc == pc + 4): delay slot, annul, and
 * pc/npc update. Returns CONTINUE with pc/npc committed, or a stop
 * result (misaligned target, delay fault) with pc/npc unchanged. */
static sparc64_step_result_t exec_cti(sparc64_cpu_t *cpu,
    const sparc64_mem_ops_t *mem, void *mc, uint64_t pc, const sparc64_dec_t *d)
{
    uint64_t npc = cpu->npc;
    uint64_t target;
    sparc64_step_result_t res;
    bool taken = true;
    if (d->cls == (uint8_t)SPARC64_ICLS_CALL) {
        sparc64_wreg(cpu, SPARC64_O7, pc);
        if (!exec_delay(cpu, mem, mc, npc, &res)) {
            return res;
        }
        cpu->pc = pc + (uint64_t)d->disp; /* mod 2^64 */
        cpu->npc = cpu->pc + 4U;
        return sparc64_step_ok(pc);
    }
    if (d->cls == (uint8_t)SPARC64_ICLS_JMPL ||
        d->cls == (uint8_t)SPARC64_ICLS_RETURN) {
        target = sparc64_rreg(cpu, d->rs1) +
            ((d->is_imm != 0U) ? (uint64_t)d->imm
                               : sparc64_rreg(cpu, d->rs2));
        if ((target & UINT64_C(3)) != UINT64_C(0)) {
            return sparc64_trap(SPARC64_TRAP_ILLEGAL, pc, d->raw);
        }
        sparc64_wreg(cpu, d->rd, pc);
        if (!exec_delay(cpu, mem, mc, npc, &res)) {
            return res;
        }
        cpu->pc = target;
        cpu->npc = target + 4U;
        return sparc64_step_ok(pc);
    }
    /* Branches: condition, target, annul (BA,a always skips, E02). */
    if (d->cls == (uint8_t)SPARC64_ICLS_BICC) {
        taken = sparc64_eval_cond(d->cond, sparc64_cc_icc(cpu));
    } else if (d->cls == (uint8_t)SPARC64_ICLS_BPCC) {
        unsigned nib = (d->cc == 2U) ? sparc64_cc_xcc(cpu)
                                     : sparc64_cc_icc(cpu);
        taken = sparc64_eval_cond(d->cond, nib);
    } else {
        taken = sparc64_eval_rcond(d->cond, sparc64_rreg(cpu, d->rs1));
    }
    target = pc + (uint64_t)d->disp; /* mod 2^64 */
    if (d->annul != 0U) {
        bool skip = taken ? (d->cond == 8U &&
                d->cls != (uint8_t)SPARC64_ICLS_BPR) : true;
        if (skip) {
            if (taken) {
                cpu->pc = target;
                cpu->npc = target + 4U;
            } else {
                cpu->pc = npc + 4U;
                cpu->npc = npc + 8U;
            }
            return sparc64_step_ok(pc);
        }
    }
    if (!exec_delay(cpu, mem, mc, npc, &res)) {
        return res;
    }
    if (taken) {
        cpu->pc = target;
        cpu->npc = target + 4U;
    } else {
        cpu->pc = npc + 4U;
        cpu->npc = npc + 8U;
    }
    return sparc64_step_ok(pc);
}

/* Trap on condition: false advances; true with trap# 0x6d is the syscall
 * gate (no state change, the L1c layer applies carry + pc advance);
 * any other true trap number traps ILLEGAL. */
static sparc64_step_result_t exec_tcc(sparc64_cpu_t *cpu, uint64_t pc,
    const sparc64_dec_t *d)
{
    unsigned nib = (d->cc == 2U) ? sparc64_cc_xcc(cpu) : sparc64_cc_icc(cpu);
    uint64_t trapno;
    if (!sparc64_eval_cond(d->cond, nib)) {
        return sparc64_step_ok(pc);
    }
    trapno = (d->is_imm != 0U) ? (uint64_t)d->imm
                               : (sparc64_rreg(cpu, d->rs1) +
            sparc64_rreg(cpu, d->rs2));
    if ((trapno & UINT64_C(0x7F)) == UINT64_C(0x6D)) {
        sparc64_step_result_t r;
        r.kind = SPARC64_STEP_SYSCALL;
        r.cause = SPARC64_TRAP_ILLEGAL;
        r.pc = pc;
        r.tval = UINT64_C(0);
        r.length = 4U;
        r.memory_reason = SPARC64_MEM_FAULT_NONE;
        return r;
    }
    return sparc64_trap(SPARC64_TRAP_ILLEGAL, pc, d->raw);
}

sparc64_step_result_t sparc64_decode(const sparc64_cpu_t *cpu,
    const sparc64_mem_ops_t *memory, void *context, sparc64_insn_t *instruction)
{
    sparc64_step_result_t res;
    uint32_t raw;
    if (instruction == NULL) {
        res.kind = SPARC64_STEP_INTERNAL;
        res.cause = SPARC64_TRAP_INST_ACCESS;
        res.pc = (cpu != NULL) ? cpu->pc : UINT64_C(0);
        res.tval = res.pc;
        res.length = 4U;
        res.memory_reason = SPARC64_MEM_FAULT_INTERNAL;
        return res;
    }
    if (cpu == NULL) {
        instruction->pc = UINT64_C(0);
        instruction->raw = 0U;
        instruction->length = 0U;
        res.kind = SPARC64_STEP_INTERNAL;
        res.cause = SPARC64_TRAP_INST_ACCESS;
        res.pc = UINT64_C(0);
        res.tval = UINT64_C(0);
        res.length = 4U;
        res.memory_reason = SPARC64_MEM_FAULT_INTERNAL;
        return res;
    }
    if (!sparc64_fetch_word(memory, context, cpu->pc, &raw, &res)) {
        instruction->pc = cpu->pc;
        instruction->raw = 0U;
        instruction->length = 0U;
        return res;
    }
    instruction->pc = cpu->pc;
    instruction->raw = raw;
    instruction->length = 4U;
    return sparc64_step_ok(cpu->pc);
}

sparc64_step_result_t sparc64_step_with_insn(sparc64_cpu_t *cpu,
    const sparc64_mem_ops_t *memory, void *context, sparc64_insn_t *executed)
{
    sparc64_dec_t d;
    sparc64_step_result_t res;
    sparc64_insn_t in;
    uint64_t pc;
    if (cpu == NULL) {
        res.kind = SPARC64_STEP_INTERNAL;
        res.cause = SPARC64_TRAP_INST_ACCESS;
        res.pc = UINT64_C(0);
        res.tval = UINT64_C(0);
        res.length = 4U;
        res.memory_reason = SPARC64_MEM_FAULT_INTERNAL;
        return res;
    }
    cpu->r[0] = UINT64_C(0);
    pc = cpu->pc;
    res = sparc64_decode(cpu, memory, context, &in);
    if (res.kind != SPARC64_STEP_CONTINUE) {
        if (executed != NULL) {
            *executed = in;
        }
        cpu->r[0] = UINT64_C(0);
        return res;
    }
    sparc64_decode_word(in.raw, &d);
    if (executed != NULL) {
        *executed = in;
    }
    switch (d.cls) {
    case SPARC64_ICLS_CALL:
    case SPARC64_ICLS_JMPL:
    case SPARC64_ICLS_RETURN:
    case SPARC64_ICLS_BICC:
    case SPARC64_ICLS_BPCC:
    case SPARC64_ICLS_BPR:
        /* exec_cti commits the final pc/npc itself. */
        res = exec_cti(cpu, memory, context, pc, &d);
        break;
    case SPARC64_ICLS_TCC:
        res = exec_tcc(cpu, pc, &d);
        if (res.kind == SPARC64_STEP_CONTINUE) {
            cpu->pc = cpu->npc;
            cpu->npc += 4U;
        }
        break;
    default:
        res = exec_single(cpu, memory, context, pc, &d);
        if (res.kind == SPARC64_STEP_CONTINUE) {
            cpu->pc = cpu->npc;
            cpu->npc += 4U;
        }
        break;
    }
    cpu->r[0] = UINT64_C(0);
    return res;
}

sparc64_step_result_t sparc64_step(sparc64_cpu_t *cpu,
    const sparc64_mem_ops_t *memory, void *context)
{
    return sparc64_step_with_insn(cpu, memory, context, NULL);
}

