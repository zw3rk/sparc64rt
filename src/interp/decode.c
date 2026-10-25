/*
 * src/interp/decode.c — SPARC V9 base integer instruction decoder
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Phase 1 lane L1a (SPEC section 2, experiments/E01..E06). Big-endian
 * fetch plus op/op2/op3 dispatch into sparc64_decoded_t. Execution
 * semantics belong to lane L1b; FPU execution belongs to Phase 3.
 *
 * Every multi-bit layout below is verified against sparc64-linux-gnu
 * GAS + objdump ground truth from the qemu-sparc64 oracle image; the
 * trickier derivations are recorded here so L1b/L2 never re-derive them:
 * - BPcc: a(29) cond(28:25) op2=001 cc(21:20: 0=icc, 2=xcc) p(19)
 *   disp19(18:0). BPr: a(29) rcond(27:25) op2=011 p(19) d16hi(21:20)
 *   rs1(18:14) d16lo(13:0); bit 28 reserved-0, rcond 0/4 reserved.
 * - MOVcc: op3 0x2c, bit 18 fixed-1, cond(17:14), cc = bit 12
 *   (0=icc, 1=xcc). MOVr: op3 0x2f, rs1(18:14), rcond(12:10, same
 *   numbering as BPr), simm10(9:0, sign-extended per E03).
 * - Tcc: cond(28:25), cc(12:11: 0=icc, 2=xcc, 1/3 reserved).
 * - CASA/CASXA address is always [rs1] (no offset); the i bit selects
 *   the ASI source (0 = imm bits 12:5, 1 = %asi register, E03).
 *   Alternate loads/stores carry imm ASI in 12:5, so i == 1 is
 *   unencodable there (illegal); CASA/CASXA are exempt (no simm).
 * - Privileged aliases: MEMBAR is op3 0x28/rs1 15; SIR is op3 0x30/
 *   rd 15; SAVED/RESTORED are op3 0x31 with rd 0/1; DONE/RETRY are
 *   op3 0x3e with rd 0/1 (all PRIV). RDHPR is 0x29, RDPR is 0x2a,
 *   WRPR is 0x32, WRHPR is 0x33 (all PRIV; binutils-verified).
 * - LDX 0x0b vs STX 0x0e asymmetry; LDXA 0x1b/STXA 0x1e; twin-word
 *   LDD/STD/LDDA/STDA ("TW/TWA") need an even rd; tagged op3 order is
 *   0x20 TADDcc, 0x21 TSUBcc, 0x22 TADDccTV, 0x23 TSUBccTV.
 */

#include "interp/decode.h"

#include <stddef.h>
#include <stdint.h>

#include "core/cpu.h"

/* Sign-extend the low n bits of v (1 <= n <= 31). Branchless and fully
 * defined: the old ((v << shift) >> shift) form shifted right as UNSIGNED
 * (logical shift), discarding the sign it had just shifted into bit 31. */
static int32_t sign_extend(uint32_t v, uint32_t n)
{
    uint32_t m = 1U << (n - 1U);
    uint32_t x = v & ((1U << n) - 1U);

    return (int32_t)((x ^ m) - m);
}

/* op == 2 ALU membership (integer operate incl. tagged, MULX/SDIVX/
 * UDIVX/POPC, MULScc). 0x19/0x1d are reserved (illegal). */
static int is_alu_op3(uint32_t op3)
{
    switch (op3) {
    case 0x00U:
    case 0x01U:
    case 0x02U:
    case 0x03U:
    case 0x04U:
    case 0x05U:
    case 0x06U:
    case 0x07U:
    case 0x08U:
    case SPARC64_OP3_MULX:
    case SPARC64_OP3_UMUL:
    case SPARC64_OP3_SMUL:
    case SPARC64_OP3_SUBX:
    case SPARC64_OP3_UDIVX:
    case SPARC64_OP3_SDIVX:
    case SPARC64_OP3_POPC:
    case SPARC64_OP3_UDIV:
    case SPARC64_OP3_SDIV:
    case 0x10U:
    case 0x11U:
    case 0x12U:
    case 0x13U:
    case 0x14U:
    case 0x15U:
    case 0x16U:
    case 0x17U:
    case 0x18U:
    case SPARC64_OP3_UMULCC:
    case SPARC64_OP3_SMULCC:
    case SPARC64_OP3_SUBXCC:
    case SPARC64_OP3_UDIVCC:
    case SPARC64_OP3_SDIVCC:
    case SPARC64_OP3_TADDCC:
    case SPARC64_OP3_TSUBCC:
    case SPARC64_OP3_TADDCCTV:
    case SPARC64_OP3_TSUBCCTV:
    case SPARC64_OP3_MULSCC:
        return 1;
    default:
        return 0;
    }
}

/* Doubleword/twin-word memory ops need an even rd. */
static int is_double_mem_op3(uint32_t op3)
{
    return op3 == SPARC64_OP3_LDD || op3 == SPARC64_OP3_STD ||
        op3 == SPARC64_OP3_LDDA || op3 == SPARC64_OP3_STDA;
}

static int is_load_op3(uint32_t op3)
{
    switch (op3) {
    case SPARC64_OP3_LDUW:
    case SPARC64_OP3_LDUB:
    case SPARC64_OP3_LDUH:
    case SPARC64_OP3_LDD:
    case SPARC64_OP3_LDSW:
    case SPARC64_OP3_LDSB:
    case SPARC64_OP3_LDSH:
    case SPARC64_OP3_LDX:
    case SPARC64_OP3_LDSTUB:
    case SPARC64_OP3_LDA:
    case SPARC64_OP3_LDUBA:
    case SPARC64_OP3_LDUHA:
    case SPARC64_OP3_LDDA:
    case SPARC64_OP3_LDSWA:
    case SPARC64_OP3_LDSBA:
    case SPARC64_OP3_LDSHA:
    case SPARC64_OP3_LDXA:
    case SPARC64_OP3_LDSTUBA:
        return 1;
    default:
        return 0;
    }
}

static int is_store_op3(uint32_t op3)
{
    switch (op3) {
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
        return 1;
    default:
        return 0;
    }
}

static int is_fp_mem_op3(uint32_t op3)
{
    return op3 >= SPARC64_OP3_LDF && op3 <= SPARC64_OP3_STDF;
}

/* Alternate-space memory ops (imm ASI in bits 12:5). */
static int is_alternate_op3(uint32_t op3)
{
    return op3 >= SPARC64_OP3_LDA && op3 <= SPARC64_OP3_SWAPA;
}

/* RDASR user register numbers (GAS-verified; other values illegal here). */
static int is_user_asr(uint32_t asr)
{
    return asr == SPARC64_ASR_Y || asr == SPARC64_ASR_CCR ||
        asr == SPARC64_ASR_ASI || asr == SPARC64_ASR_TICK ||
        asr == SPARC64_ASR_PC || asr == SPARC64_ASR_FPRS ||
        asr == SPARC64_ASR_GSR;
}

/* WRASR user register numbers: %tick (GAS-rejected) and %pc (read-only)
 * are not writable, so they stay illegal here. */
static int is_wrasr_asr(uint32_t asr)
{
    return asr == SPARC64_ASR_Y || asr == SPARC64_ASR_CCR ||
        asr == SPARC64_ASR_ASI || asr == SPARC64_ASR_FPRS ||
        asr == SPARC64_ASR_GSR;
}

/* Assigned BPr/MOVr register-test conditions (0 and 4 reserved). */
static int is_rcond(uint32_t rcond)
{
    return rcond == SPARC64_RCOND_Z || rcond == SPARC64_RCOND_LEZ ||
        rcond == SPARC64_RCOND_LZ || rcond == SPARC64_RCOND_NZ ||
        rcond == SPARC64_RCOND_GZ || rcond == SPARC64_RCOND_GEZ;
}

static void decode_op0(uint32_t word, sparc64_decoded_t *out)
{
    uint32_t op2 = (word >> 22) & 0x7U;

    out->op2 = op2;
    if (op2 == 0x4U) {
        out->cls = SPARC64_OP_SETHI;
        out->rd = (word >> 25) & 0x1FU;
        out->uimm = word & 0x3FFFFFU;
        return;
    }
    if (op2 == 0x2U) {
        out->cls = SPARC64_OP_BRANCH;
        out->annul = (word >> 29) & 0x1U;
        out->cond = (word >> 25) & 0x0FU;
        out->disp = sign_extend(word & 0x3FFFFFU, 22U) << 2;
        return;
    }
    if (op2 == 0x1U) {
        uint32_t cc = (word >> 20) & 0x3U;

        if (cc != SPARC64_CC_ICC && cc != SPARC64_CC_XCC) {
            out->cls = SPARC64_OP_ILLEGAL;
            return;
        }
        out->cls = SPARC64_OP_BPBRANCH;
        out->annul = (word >> 29) & 0x1U;
        out->cond = (word >> 25) & 0x0FU;
        out->cc_sel = cc;
        out->pred = (word >> 19) & 0x1U;
        out->disp = sign_extend(word & 0x7FFFFU, 19U) << 2;
        return;
    }
    if (op2 == 0x3U) {
        uint32_t hi = (word >> 20) & 0x3U;
        uint32_t lo = word & 0x3FFFU;
        uint32_t rcond = (word >> 25) & 0x7U;

        if (!is_rcond(rcond)) {
            out->cls = SPARC64_OP_ILLEGAL;
            return;
        }
        out->cls = SPARC64_OP_BPR;
        out->annul = (word >> 29) & 0x1U;
        out->rcond = rcond;
        out->pred = (word >> 19) & 0x1U;
        out->rs1 = (word >> 14) & 0x1FU;
        out->disp = sign_extend((hi << 14) | lo, 16U) << 2;
        return;
    }
    if (op2 == 0x5U || op2 == 0x6U) {
        out->cls = SPARC64_OP_FBRANCH;
        out->annul = (word >> 29) & 0x1U;
        out->cond = (word >> 25) & 0x0FU;
        out->cc_sel = (word >> 20) & 0x3U;
        out->pred = (word >> 19) & 0x1U;
        out->disp = sign_extend(word & 0x7FFFFU, 19U) << 2;
        return;
    }
    /* op2 == 0 is ILLTRAP (const22 trap operand); 1/3/5/7 handled
     * above, so 7 (and any gap) is illegal on this V9 target. */
    out->uimm = word & 0x3FFFFFU;
    out->cls = SPARC64_OP_ILLEGAL;
}

static void decode_op2(uint32_t word, sparc64_decoded_t *out)
{
    uint32_t op3 = (word >> 19) & 0x3FU;
    uint32_t rd = (word >> 25) & 0x1FU;
    uint32_t rs1 = (word >> 14) & 0x1FU;
    uint32_t i = (word >> 13) & 0x1U;

    out->op3 = op3;
    out->rd = rd;
    out->rs1 = rs1;
    out->is_imm = i;
    if (i != 0U) {
        out->simm = sign_extend(word & 0x1FFFU, 13U);
    } else {
        out->asi = (word >> 5) & 0xFFU;
        out->rs2 = word & 0x1FU;
    }

    if (is_alu_op3(op3)) {
        out->cls = SPARC64_OP_ALU;
        /* Only 0x10..0x24 update icc + xcc; MULX/UDIVX/SDIVX/POPC and
         * the plain 0x00..0x0f row do not. */
        out->cc = (op3 >= 0x10U && op3 <= 0x24U) ? 1U : 0U;
        return;
    }

    switch (op3) {
    case SPARC64_OP3_SLL:
    case SPARC64_OP3_SRL:
    case SPARC64_OP3_SRA:
        out->cls = SPARC64_OP_SHIFT;
        out->xbit = (word >> 12) & 0x1U;
        return;
    case SPARC64_OP3_RDASR:
        if (rs1 == 0xFU) {
            /* MEMBAR shares the RDASR opcode (objdump-verified). */
            out->cls = SPARC64_OP_MEMBAR;
            return;
        }
        if (!is_user_asr(rs1)) {
            out->cls = SPARC64_OP_ILLEGAL;
            return;
        }
        out->cls = SPARC64_OP_RDASR;
        out->asr = rs1;
        return;
    case SPARC64_OP3_RDHPR:
    case SPARC64_OP3_RDPR:
    case SPARC64_OP3_FLUSHW:
        out->cls = SPARC64_OP_PRIV;
        return;
    case SPARC64_OP3_MOVCC: {
        uint32_t cc = (word >> 12) & 0x1U;

        if (((word >> 18) & 0x1U) == 0U) {
            out->cls = SPARC64_OP_ILLEGAL;
            return;
        }
        out->cls = SPARC64_OP_MOVCC;
        out->cond = (word >> 14) & 0x0FU;
        out->cc_sel = cc;
        out->rs1 = 0U;
        return;
    }
    case SPARC64_OP3_MOVR: {
        uint32_t rcond = (word >> 10) & 0x7U;

        if (!is_rcond(rcond)) {
            out->cls = SPARC64_OP_ILLEGAL;
            return;
        }
        out->cls = SPARC64_OP_MOVR;
        out->rcond = rcond;
        if (i != 0U) {
            out->simm = sign_extend(word & 0x3FFU, 10U);
        }
        return;
    }
    case SPARC64_OP3_WRASR:
        if (rd == 0xFU) {
            /* SIR shares the WRASR opcode (software-initiated reset). */
            out->cls = SPARC64_OP_PRIV;
            return;
        }
        if (!is_wrasr_asr(rd)) {
            out->cls = SPARC64_OP_ILLEGAL;
            return;
        }
        out->cls = SPARC64_OP_WRASR;
        out->asr = rd;
        return;
    case SPARC64_OP3_SAVED:
        /* SAVED (rd 0) / RESTORED (rd 1); other rd values unassigned. */
        if (rd != 0U && rd != 1U) {
            out->cls = SPARC64_OP_ILLEGAL;
            return;
        }
        out->cls = SPARC64_OP_PRIV;
        return;
    case SPARC64_OP3_WRPR:
    case SPARC64_OP3_WRHPR:
        out->cls = SPARC64_OP_PRIV;
        return;
    case SPARC64_OP3_FPOP1:
    case SPARC64_OP3_FPOP2:
    case 0x37U: /* IMPDEP2 (VIS BSHUFFLE space): Phase 3 marker. */
        out->cls = SPARC64_OP_FPU;
        out->is_imm = 0U;
        out->simm = 0;
        out->asi = 0U;
        out->opf = (word >> 5) & 0x1FFU;
        out->rs2 = word & 0x1FU;
        return;
    case SPARC64_OP3_ALIGN:
        out->cls = SPARC64_OP_ALIGN;
        return;
    case SPARC64_OP3_JMPL:
        out->cls = SPARC64_OP_JMPL;
        return;
    case SPARC64_OP3_RETURN:
        out->cls = SPARC64_OP_RETURN;
        return;
    case SPARC64_OP3_TCC: {
        uint32_t cc = (word >> 11) & 0x3U;

        if (cc != SPARC64_CC_ICC && cc != SPARC64_CC_XCC) {
            out->cls = SPARC64_OP_ILLEGAL;
            return;
        }
        out->cls = SPARC64_OP_TRAP;
        out->cond = (word >> 25) & 0x0FU;
        out->cc_sel = cc;
        return;
    }
    case SPARC64_OP3_FLUSH:
        out->cls = SPARC64_OP_FLUSH;
        return;
    case SPARC64_OP3_SAVE:
        out->cls = SPARC64_OP_SAVE;
        return;
    case SPARC64_OP3_RESTORE:
        out->cls = SPARC64_OP_RESTORE;
        return;
    case SPARC64_OP3_DONE:
        /* DONE (rd 0) / RETRY (rd 1); other rd values unassigned. */
        if (rd != 0U && rd != 1U) {
            out->cls = SPARC64_OP_ILLEGAL;
            return;
        }
        out->cls = SPARC64_OP_PRIV;
        return;
    default:
        /* Reserved ALU (0x19/0x1d), RDHPR-slot 0x2a, 0x32: illegal. */
        out->cls = SPARC64_OP_ILLEGAL;
        return;
    }
}

static void decode_casa(uint32_t word, sparc64_decoded_t *out, uint32_t cls)
{
    uint32_t i = (word >> 13) & 0x1U;
    uint32_t asi = (word >> 5) & 0xFFU;

    /* The CASA address is always [rs1] with no offset; the i bit selects
     * the ASI source (E03): 0 takes the imm ASI from bits 12:5, 1 takes
     * the %asi register. There is no simm form. */
    out->is_imm = 0U;
    out->simm = 0;
    out->asi = asi;
    out->rs2 = word & 0x1FU;
    out->atomic = 1U;
    if (i == 0U) {
        out->regasi = 0U;
        if (asi < SPARC64_ASI_PRIMARY) {
            /* V9 ASIs below 0x80 trap privileged_action (E03 0x37). */
            out->cls = SPARC64_OP_PRIV;
            return;
        }
        out->cls = cls;
        return;
    }
    out->regasi = 1U;
    out->cls = cls;
}

static void decode_op3(uint32_t word, sparc64_decoded_t *out)
{
    uint32_t op3 = (word >> 19) & 0x3FU;
    uint32_t rd = (word >> 25) & 0x1FU;
    uint32_t rs1 = (word >> 14) & 0x1FU;
    uint32_t i = (word >> 13) & 0x1U;

    out->op3 = op3;
    out->rd = rd;
    out->rs1 = rs1;
    out->is_imm = i;
    if (i != 0U) {
        out->simm = sign_extend(word & 0x1FFFU, 13U);
    } else {
        out->asi = (word >> 5) & 0xFFU;
        out->rs2 = word & 0x1FU;
    }

    if (op3 == SPARC64_OP3_CASA) {
        decode_casa(word, out, SPARC64_OP_CASA);
        return;
    }
    if (op3 == SPARC64_OP3_CASXA) {
        decode_casa(word, out, SPARC64_OP_CASXA);
        return;
    }
    if (op3 == SPARC64_OP3_PREFETCH) {
        out->cls = SPARC64_OP_PREFETCH;
        return;
    }
    if (op3 == SPARC64_OP3_SWAP || op3 == SPARC64_OP3_SWAPA) {
        out->atomic = 1U;
        out->cls = SPARC64_OP_SWAP;
        return;
    }
    if (is_load_op3(op3)) {
        if (op3 == SPARC64_OP3_LDSTUB || op3 == SPARC64_OP3_LDSTUBA) {
            out->atomic = 1U;
        }
        if (is_double_mem_op3(op3) && ((rd & 0x1U) != 0U)) {
            out->cls = SPARC64_OP_ILLEGAL;
            return;
        }
        if (is_alternate_op3(op3) && i != 0U) {
            /* Imm ASI (bits 12:5) overlaps simm13: unencodable. */
            out->cls = SPARC64_OP_ILLEGAL;
            return;
        }
        out->cls = SPARC64_OP_LOAD;
        return;
    }
    if (is_store_op3(op3)) {
        if (is_double_mem_op3(op3) && ((rd & 0x1U) != 0U)) {
            out->cls = SPARC64_OP_ILLEGAL;
            return;
        }
        if (is_alternate_op3(op3) && i != 0U) {
            out->cls = SPARC64_OP_ILLEGAL;
            return;
        }
        out->cls = SPARC64_OP_STORE;
        return;
    }
    if (is_fp_mem_op3(op3)) {
        out->cls = SPARC64_OP_FPMEM;
        return;
    }
    /* LDXA/STXA gaps (0x0c/0x1c), FP gaps, and the remaining tail. */
    out->cls = SPARC64_OP_ILLEGAL;
}

void sparc64_decode_word(uint32_t word, sparc64_decoded_t *out)
{
    uint32_t op;

    if (out == NULL) {
        return;
    }
    out->raw = word;
    out->cls = SPARC64_OP_ILLEGAL;
    out->op = (word >> 30) & 0x3U;
    out->op2 = 0U;
    out->op3 = 0U;
    out->rd = 0U;
    out->rs1 = 0U;
    out->rs2 = 0U;
    out->is_imm = 0U;
    out->simm = 0;
    out->asi = 0U;
    out->regasi = 0U;
    out->cond = 0U;
    out->rcond = 0U;
    out->cc_sel = 0U;
    out->annul = 0U;
    out->pred = 0U;
    out->disp = 0;
    out->uimm = 0U;
    out->opf = 0U;
    out->asr = 0U;
    out->atomic = 0U;
    out->cc = 0U;
    out->xbit = 0U;

    op = out->op;
    if (op == 0x1U) {
        /* Format 1 CALL: 30-bit word displacement, delay slot executes. */
        out->cls = SPARC64_OP_CALL;
        out->disp = sign_extend(word & 0x3FFFFFFFU, 30U) << 2;
        return;
    }
    if (op == 0x0U) {
        decode_op0(word, out);
        return;
    }
    if (op == 0x2U) {
        decode_op2(word, out);
        return;
    }
    /* op == 0x3U: Format 3 memory incl. CASA/CASXA. */
    decode_op3(word, out);
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
    /* Big-endian assembly keeps this unit host-endian clean. */
    word = ((uint32_t)bytes[0] << 24) | ((uint32_t)bytes[1] << 16) |
        ((uint32_t)bytes[2] << 8) | (uint32_t)bytes[3];
    sparc64_decode_word(word, out);
    return 0;
}
