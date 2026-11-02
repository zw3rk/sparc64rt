/*
 * src/interp/decode.c — SPARC V9 unified instruction decoder
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Single source of truth for SPARC V9 instruction classification and
 * field extraction across the interpreter, DBT, and lockstep harness.
 * sparc64_classify_word populates sparc64_dec_t; sparc64_decode_word
 * adapts the same decode into sparc64_decoded_t so no duplicate opcode
 * tables can drift.
 */

#include "interp/decode.h"
#include "interp/interp.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "core/cpu.h"

static void sparc64_decode_op2(sparc64_dec_t *d, uint32_t word, unsigned op3,
    unsigned rd, unsigned rs1, unsigned i);
static void sparc64_decode_op3(sparc64_dec_t *d, uint32_t word, unsigned op3,
    unsigned rd, unsigned rs1, unsigned i);

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

static bool rcond_valid(unsigned rcond)
{
    return rcond == 1U || rcond == 2U || rcond == 3U || rcond == 5U ||
        rcond == 6U || rcond == 7U;
}

/* Pure word classifier: fills *d for any raw word. Illegal words yield
 * SPARC64_ICLS_ILLEGAL; execution traps them in step. */
void sparc64_classify_word(uint32_t word, sparc64_dec_t *d)
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
    d->regasi = 0U;
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
        d->disp = sx(word & UINT32_C(0x3FFFFFFF), 30U) * INT64_C(4);
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
            d->disp = sx(fld(word, 18U, 0U), 19U) * INT64_C(4);
            return;
        }
        if (op2 == 2U) {
            d->cls = SPARC64_ICLS_BICC;
            d->annul = (uint8_t)fld(word, 29U, 29U);
            d->cond = (uint8_t)fld(word, 28U, 25U);
            d->disp = sx(fld(word, 21U, 0U), 22U) * INT64_C(4);
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
            d->disp = sx(d16, 16U) * INT64_C(4);
            return;
        }
        if (op2 == 4U) {
            d->cls = SPARC64_ICLS_SETHI;
            d->rd = (uint8_t)fld(word, 29U, 25U);
            d->uimm = fld(word, 21U, 0U);
            return;
        }
        if (op2 == 5U) {
            /* FBfcc: a(29) cond(28:25) fcc(21:20); bit 19 is the static
             * prediction hint (ignored, like BPcc pred); disp19 is
             * bits 18:0 (oracle-probed). op2 == 6 stays ILLEGAL:
             * qemu-sparc64 kills it, so it never decodes as a branch. */
            d->cls = SPARC64_ICLS_FBR;
            d->annul = (uint8_t)fld(word, 29U, 29U);
            d->cond = (uint8_t)fld(word, 28U, 25U);
            d->cc = (uint8_t)fld(word, 21U, 20U);
            d->pred = (uint8_t)fld(word, 19U, 19U);
            d->disp = sx(fld(word, 18U, 0U), 19U) * INT64_C(4);
            return;
        }
        d->uimm = word & 0x3FFFFFU;
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
            d->imm = sx(fld(word, 12U, 0U), 13U);
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
    case SPARC64_OP3_MOVCC: {
        unsigned cc2 = fld(word, 18U, 18U);
        unsigned cc = fld(word, 12U, 11U);
        /* cc2 == 1 selects integer %icc (cc=0) / %xcc (cc=2);
         * cc2 == 0 selects FP %fcc0..%fcc3 (encoded as 4 | cc). */
        if (cc2 != 0U && cc != 0U && cc != 2U) {
            return;
        }
        d->cls = SPARC64_ICLS_MOVCC;
        d->cond = (uint8_t)fld(word, 17U, 14U);
        d->cc = (uint8_t)((cc2 != 0U) ? cc : (4U | cc));
        if (i != 0U) {
            d->imm = sx(fld(word, 10U, 0U), 11U);
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
            d->imm = sx(fld(word, 9U, 0U), 10U);
        } else {
            d->rs2 = (uint8_t)fld(word, 4U, 0U);
        }
        return;
    }
    case SPARC64_OP3_RDASR:
        if (rs1 == 15U) {
            /* MEMBAR shares the RDASR opcode (ordering hint: nop). */
            d->cls = SPARC64_ICLS_MEMBAR;
            return;
        }
        if (rs1 == SPARC64_ASR_Y || rs1 == SPARC64_ASR_CCR ||
            rs1 == SPARC64_ASR_ASI || rs1 == SPARC64_ASR_PC ||
            rs1 == SPARC64_ASR_FPRS || rs1 == SPARC64_ASR_GSR ||
            rs1 == SPARC64_ASR_TICK) {
            d->cls = SPARC64_ICLS_RDASR;
            return;
        }
        if (rs1 >= 20U && rs1 <= 25U) {
            d->cls = SPARC64_ICLS_PRIV;
            return;
        }
        return;
    case SPARC64_OP3_WRASR:
        if (rd == 15U) {
            d->cls = SPARC64_ICLS_PRIV;
            return;
        }
        if (rd == SPARC64_ASR_Y || rd == SPARC64_ASR_CCR ||
            rd == SPARC64_ASR_ASI || rd == SPARC64_ASR_FPRS ||
            rd == SPARC64_ASR_GSR) {
            d->cls = SPARC64_ICLS_WRASR;
            if (i != 0U) {
                d->imm = sx(fld(word, 12U, 0U), 13U);
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
    case SPARC64_OP3_SAVED:
    case SPARC64_OP3_WRPR:
    case SPARC64_OP3_WRHPR:
    case SPARC64_OP3_DONE:
    case SPARC64_OP3_RETRY:
        if ((op3 == SPARC64_OP3_SAVED || op3 == SPARC64_OP3_DONE ||
                op3 == SPARC64_OP3_RETRY) &&
            rd != 0U && rd != 1U) {
            return;
        }
        d->cls = SPARC64_ICLS_PRIV;
        return;
    case SPARC64_OP3_FPOP1:
    case SPARC64_OP3_FPOP2:
        d->cls = SPARC64_ICLS_FPU;
        d->opf = fld(word, 13U, 5U);
        d->rs2 = (uint8_t)fld(word, 4U, 0U);
        return;
    case SPARC64_OP3_VIS: {
        uint32_t opf = fld(word, 13U, 5U);
        d->opf = opf;
        if (opf == SPARC64_OPF_ALIGNADDR ||
            opf == SPARC64_OPF_ALIGNADDRL) {
            d->cls = SPARC64_ICLS_ALIGN;
            if (i != 0U) {
                d->imm = sx(fld(word, 12U, 0U), 13U);
            } else {
                d->rs2 = (uint8_t)fld(word, 4U, 0U);
            }
            return;
        }
        d->cls = SPARC64_ICLS_FPU;
        d->rs2 = (uint8_t)fld(word, 4U, 0U);
        return;
    }
    case SPARC64_OP3_JMPL:
        d->cls = SPARC64_ICLS_JMPL;
        if (i != 0U) {
            d->imm = sx(fld(word, 12U, 0U), 13U);
        } else {
            d->rs2 = (uint8_t)fld(word, 4U, 0U);
        }
        return;
    case SPARC64_OP3_RETURN:
        d->cls = SPARC64_ICLS_RETURN;
        if (i != 0U) {
            d->imm = sx(fld(word, 12U, 0U), 13U);
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
        if (i != 0U) {
            d->imm = sx(fld(word, 12U, 0U), 13U);
        } else {
            d->rs2 = (uint8_t)fld(word, 4U, 0U);
        }
        return;
    case SPARC64_OP3_SAVE:
        d->cls = SPARC64_ICLS_SAVE;
        if (i != 0U) {
            d->imm = sx(fld(word, 12U, 0U), 13U);
        } else {
            d->rs2 = (uint8_t)fld(word, 4U, 0U);
        }
        return;
    case SPARC64_OP3_RESTORE:
        d->cls = SPARC64_ICLS_RESTORE;
        if (i != 0U) {
            d->imm = sx(fld(word, 12U, 0U), 13U);
        } else {
            d->rs2 = (uint8_t)fld(word, 4U, 0U);
        }
        return;
    default:
        return;
    }
}

/* Format-3 memory classifier (op == 3). */
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
    case SPARC64_OP3_LDFSR:
    case SPARC64_OP3_STFSR:
    case SPARC64_OP3_LDFA:
    case SPARC64_OP3_LDDFA:
    case SPARC64_OP3_STFA:
    case SPARC64_OP3_STDFA:
        break;
    case SPARC64_OP3_PREFETCH:
        d->cls = SPARC64_ICLS_FLUSH;
        return;
    default:
        if (op3 == SPARC64_OP3_LDF || op3 == SPARC64_OP3_LDTW ||
            op3 == SPARC64_OP3_LDDF || op3 == SPARC64_OP3_STF ||
            op3 == SPARC64_OP3_STTW || op3 == SPARC64_OP3_STDF) {
            d->cls = SPARC64_ICLS_FPU;
            if (i != 0U) {
                d->imm = sx(fld(word, 12U, 0U), 13U);
            } else {
                d->rs2 = (uint8_t)fld(word, 4U, 0U);
            }
        }
        return;
    }
    alt = (op3 >= SPARC64_OP3_LDA && op3 <= SPARC64_OP3_SWAPA) ||
        op3 == SPARC64_OP3_CASA || op3 == SPARC64_OP3_CASXA ||
        (op3 >= SPARC64_OP3_LDFA && op3 <= SPARC64_OP3_STDFA);
    if ((op3 == SPARC64_OP3_LDD || op3 == SPARC64_OP3_STD ||
            op3 == SPARC64_OP3_LDDA || op3 == SPARC64_OP3_STDA) &&
        (d->rd & 1U) != 0U) {
        d->cls = SPARC64_ICLS_ILLEGAL;
        return;
    }
    if (alt) {
        if (i == 0U) {
            d->asi = (uint8_t)fld(word, 12U, 5U);
        } else {
            d->asi = 0xFFU;
            d->regasi = 1U;
        }
    }
    if (i != 0U) {
        d->imm = sx(fld(word, 12U, 0U), 13U);
    } else {
        d->rs2 = (uint8_t)fld(word, 4U, 0U);
    }
    if (op3 == SPARC64_OP3_LDDA || op3 == SPARC64_OP3_STDA ||
        op3 == SPARC64_OP3_LDFA || op3 == SPARC64_OP3_LDDFA ||
        op3 == SPARC64_OP3_STFA || op3 == SPARC64_OP3_STDFA) {
        d->cls = SPARC64_ICLS_FPU;
        return;
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
    case SPARC64_OP3_STX:
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

void sparc64_decode_word(uint32_t word, sparc64_decoded_t *out)
{
    sparc64_dec_t d;
    if (out == NULL) {
        return;
    }
    sparc64_classify_word(word, &d);
    out->raw = word;
    out->op = d.op;
    out->op2 = (d.op == 0U) ? ((word >> 22) & 0x7U) : 0U;
    out->op3 = d.op3;
    out->rd = d.rd;
    out->rs1 = d.rs1;
    out->rs2 = d.rs2;
    out->is_imm = d.is_imm;
    out->simm = (int32_t)d.imm;
    out->asi = (d.op >= 2U && d.is_imm == 0U && d.asi == 0U) ?
        ((word >> 5) & 0xFFU) : d.asi;
    out->regasi = d.regasi;
    out->cond = d.cond;
    out->rcond = (d.cls == SPARC64_ICLS_BPR || d.cls == SPARC64_ICLS_MOVR) ?
        d.cond : 0U;
    out->cc_sel = d.cc;
    out->annul = d.annul;
    out->pred = d.pred;
    out->disp = (int32_t)d.disp;
    out->uimm = d.uimm;
    out->opf = d.opf;
    out->asr = (d.cls == SPARC64_ICLS_RDASR) ? d.rs1 :
        ((d.cls == SPARC64_ICLS_WRASR) ? d.rd : 0U);
    out->atomic = (d.cls == SPARC64_ICLS_LDSTUB ||
        d.cls == SPARC64_ICLS_SWAP || d.cls == SPARC64_ICLS_ATOMIC) ? 1U : 0U;
    out->cc = (d.cls == SPARC64_ICLS_ALU && d.op3 >= 0x10U &&
        d.op3 <= 0x24U) ? 1U : 0U;
    out->xbit = d.xbit;

    switch (d.cls) {
    case SPARC64_ICLS_SETHI: out->cls = SPARC64_OP_SETHI; break;
    case SPARC64_ICLS_BICC: out->cls = SPARC64_OP_BRANCH; break;
    case SPARC64_ICLS_BPCC: out->cls = SPARC64_OP_BPBRANCH; break;
    case SPARC64_ICLS_BPR: out->cls = SPARC64_OP_BPR; break;
    case SPARC64_ICLS_FBR: out->cls = SPARC64_OP_FBRANCH; break;
    case SPARC64_ICLS_CALL: out->cls = SPARC64_OP_CALL; break;
    case SPARC64_ICLS_ALU: out->cls = SPARC64_OP_ALU; break;
    case SPARC64_ICLS_SHIFT: out->cls = SPARC64_OP_SHIFT; break;
    case SPARC64_ICLS_SAVE: out->cls = SPARC64_OP_SAVE; break;
    case SPARC64_ICLS_RESTORE: out->cls = SPARC64_OP_RESTORE; break;
    case SPARC64_ICLS_JMPL: out->cls = SPARC64_OP_JMPL; break;
    case SPARC64_ICLS_RETURN: out->cls = SPARC64_OP_RETURN; break;
    case SPARC64_ICLS_MOVCC:
        out->cls = SPARC64_OP_MOVCC;
        out->cc_sel = ((d.cc & 4U) != 0U) ? (d.cc & 3U) : (d.cc >> 1U);
        out->rs1 = 0U;
        break;
    case SPARC64_ICLS_MOVR: out->cls = SPARC64_OP_MOVR; break;
    case SPARC64_ICLS_TCC: out->cls = SPARC64_OP_TRAP; break;
    case SPARC64_ICLS_RDASR: out->cls = SPARC64_OP_RDASR; break;
    case SPARC64_ICLS_WRASR: out->cls = SPARC64_OP_WRASR; break;
    case SPARC64_ICLS_MEMBAR: out->cls = SPARC64_OP_MEMBAR; break;
    case SPARC64_ICLS_FLUSH:
        out->cls = (d.op == 3U && d.op3 == SPARC64_OP3_PREFETCH) ?
            SPARC64_OP_PREFETCH : SPARC64_OP_FLUSH;
        break;
    case SPARC64_ICLS_LOAD:
    case SPARC64_ICLS_LDSTUB:
        out->cls = (d.op == 3U && d.is_imm != 0U &&
            d.op3 >= SPARC64_OP3_LDA && d.op3 <= SPARC64_OP3_SWAPA) ?
            SPARC64_OP_ILLEGAL : SPARC64_OP_LOAD;
        break;
    case SPARC64_ICLS_STORE:
        out->cls = (d.op == 3U && d.is_imm != 0U &&
            d.op3 >= SPARC64_OP3_LDA && d.op3 <= SPARC64_OP3_SWAPA) ?
            SPARC64_OP_ILLEGAL : SPARC64_OP_STORE;
        break;
    case SPARC64_ICLS_SWAP: out->cls = SPARC64_OP_SWAP; break;
    case SPARC64_ICLS_ATOMIC:
        out->is_imm = 0U;
        out->simm = 0;
        out->asi = (word >> 5) & 0xFFU;
        out->rs2 = word & 0x1FU;
        if (d.is_imm == 0U && out->asi < SPARC64_ASI_PRIMARY) {
            out->cls = SPARC64_OP_PRIV;
        } else {
            out->cls = (d.op3 == SPARC64_OP3_CASA) ?
                SPARC64_OP_CASA : SPARC64_OP_CASXA;
        }
        break;
    case SPARC64_ICLS_ALIGN: out->cls = SPARC64_OP_ALIGN; break;
    case SPARC64_ICLS_FPU:
        out->cls = (d.op == 3U) ? SPARC64_OP_FPMEM : SPARC64_OP_FPU;
        break;
    case SPARC64_ICLS_PRIV: out->cls = SPARC64_OP_PRIV; break;
    default: out->cls = SPARC64_OP_ILLEGAL; break;
    }
}

int sparc64_fetch_decode(sparc64_cpu_t *cpu,
                         const sparc64_mem_ops_t *memory,
                         void *context,
                         uint64_t va,
                         sparc64_decoded_t *out)
{
    uint8_t bytes[4];
    uint32_t word;
    sparc64_mem_fault_t fault;

    if (out == NULL) {
        return -1;
    }
    sparc64_decode_word(0U, out);
    if (cpu == NULL || memory == NULL || memory->read == NULL) {
        return -1;
    }
    if ((va & 0x3U) != 0U) {
        cpu->exit_reason = SPARC64_EXIT_FAULT;
        cpu->fault_addr = va;
        return -1;
    }
    fault.address = UINT64_C(0);
    fault.reason = SPARC64_MEM_FAULT_NONE;
    if (!memory->read(context, va, bytes, sizeof(bytes),
                      SPARC64_ACCESS_FETCH, &fault)) {
        if (fault.reason == SPARC64_MEM_FAULT_UNMAPPED ||
            fault.reason == SPARC64_MEM_FAULT_PERMISSION ||
            fault.reason == SPARC64_MEM_FAULT_RANGE ||
            fault.reason == SPARC64_MEM_FAULT_BUS) {
            cpu->exit_reason = SPARC64_EXIT_FAULT;
            cpu->fault_addr = va;
        }
        return -1;
    }
    word = ((uint32_t)bytes[0] << 24) | ((uint32_t)bytes[1] << 16) |
        ((uint32_t)bytes[2] << 8) | (uint32_t)bytes[3];
    sparc64_decode_word(word, out);
    return 0;
}
