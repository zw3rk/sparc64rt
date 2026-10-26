/*
 * src/interp/decode.h — V9 decoded-instruction representation + decoder API
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Phase 1 lane L1a owns this file (SPEC section 2, experiments/E01..E06
 * oracle findings). It defines the decoded form of every SPEC section 2
 * base integer instruction and the big-endian fetch entry point used by
 * the reference interpreter (lane L1b) and the Phase 2 DBT frontend.
 *
 * Encoding authority: SPARC V9 manual, Format 1/2/3 field layout
 * (op/op2/op3 dispatch below), verified word-by-word against
 * sparc64-linux-gnu GAS + objdump ground truth
 * (qemu-sparc64 oracle image). Execution semantics belong to L1b; FPU
 * execution belongs to Phase 3.
 */

#ifndef SPARC64RT_INTERP_DECODE_H
#define SPARC64RT_INTERP_DECODE_H

#include <stdint.h>

#include "core/cpu.h"

/* Decoded instruction class (one per SPEC section 2 execution family). */
typedef enum {
    SPARC64_OP_ILLEGAL = 0, /* Undecodable, unassigned op2/op3, ILLTRAP,
                             * CASA/CASXA with (i == 0, ASI < 0x80),
                             * reserved BPcc/Tcc cc, reserved BPr/MOVr
                             * rcond, odd-rd twin-word, alternate with
                             * i == 1, DONE/RETRY-shaped op3 with rd > 1.
                             * L1b must never execute. */
    SPARC64_OP_CALL,    /* Format 1 CALL: disp30, writes %o7, delay executes. */
    SPARC64_OP_SETHI,   /* SETHI imm22 -> rd (rd == 0 is the classic NOP). */
    SPARC64_OP_BRANCH,  /* Bicc (op2 == 2): cond, annul bit, disp22. Tests
                         * icc only. cond == 8 is BA (unconditional; ,a
                         * always annuls). cond == 0 is BN (never branches;
                         * delay still runs unless annulled). */
    SPARC64_OP_BPBRANCH, /* BPcc (op2 == 1): cond, annul, cc select, predict
                         * bit, disp19. cc_sel 0 = %icc, 2 = %xcc. */
    SPARC64_OP_BPR,     /* BPr (op2 == 3): rcond, annul, predict bit, rs1,
                         * disp16 (split d16hi/d16lo). Tests full 64-bit
                         * register (E03). */
    SPARC64_OP_FBRANCH, /* FBfcc/FBPfcc (op2 == 5/6): cond, fcc index in
                         * cc_sel, annul, predict bit, disp19. Phase 3
                         * executes; interp returns EXIT_UNDEF. */
    SPARC64_OP_ALU,     /* Integer ALU incl. tagged, MULX/UDIVX/SDIVX,
                         * UMUL/SMUL/UDIV/SDIV (+cc), MULScc (op3 in struct
                         * field); cc flag mirrors "updates icc+xcc". */
    SPARC64_OP_SHIFT,   /* SLL/SRL/SRA + SLLX/SRLX/SRAX (xbit = bit 12). */
    SPARC64_OP_MOVCC,   /* Integer MOVcc (op3 0x2c): cond, cc select
                         * (cc_sel 0 = %icc, 1 = %xcc), rd/src2-or-simm13. */
    SPARC64_OP_MOVR,    /* Integer MOVr (op3 0x2f): rcond, rs1, rd,
                         * rs2-or-sign-extended-simm10 (E03). */
    SPARC64_OP_RDASR,   /* RDASR (op3 0x28): asr holds rs1. asr == 0 reads
                         * %y (RDY); 2/3/5/6/19 read %ccr/%asi/%pc/%fprs/
                         * %gsr; 4 reads %tick and traps privileged (L1b). */
    SPARC64_OP_WRASR,   /* WRASR (op3 0x30): asr holds rd. rd == 0 writes
                         * %y (WRY); 2/3/6/19 write %ccr/%asi/%fprs/%gsr. */
    SPARC64_OP_MEMBAR,  /* MEMBAR (op3 0x28, rs1 == 15): ordering hint;
                         * rd carries mmask, simm carries cmask. L1b nops. */
    SPARC64_OP_PRIV,    /* Privileged state/trap: RDHPR (0x29), RDPR (0x2a),
                         * FLUSHW (0x2b), SAVED/RESTORED (0x31, rd 0/1),
                         * WRPR (0x32), WRHPR (0x33), DONE/RETRY (0x3e,
                         * rd 0/1), SIR (0x30, rd 15), CASA/CASXA with
                         * (i == 0, ASI < 0x80) (E03 trap 0x37).
                         * User-mode execution traps (L1b). RDASR asr 4
                         * (RDTICK) is user-emulated, not folded here. */
    SPARC64_OP_FPU,     /* FPop1/FPop2/IMPDEP2-VIS pass-through marker for
                         * Phase 3, incl. integer-shaped FMOVcc/FMOVr
                         * (opf/rs1/rs2/rd recorded; interp: EXIT_UNDEF). */
    SPARC64_OP_JMPL,    /* JMPL (op3 0x38): rd/rs1/src2. rd == 0 discards;
                         * rd == 15 is the return/call linkage register. */
    SPARC64_OP_RETURN,  /* RETURN (op3 0x39): subroutine return, shaped
                         * like JMPL (canonically %i7 + 8 -> rd). */
    SPARC64_OP_SAVE,    /* SAVE (op3 0x3c): window rotate + spill (E01). */
    SPARC64_OP_RESTORE, /* RESTORE (op3 0x3d): window rotate + fill (E01). */
    SPARC64_OP_TRAP,    /* Tcc (op3 0x3a): cond + cc select + rs1/src2.
                         * cond == 8 (TA) with simm13 == 0x6d is the
                         * 64-bit Linux syscall trap (E02/E04). cc_sel
                         * 0 = %icc, 2 = %xcc. */
    SPARC64_OP_FLUSH,   /* FLUSH (op3 0x3b): rs1/src2 address hint. */
    SPARC64_OP_LOAD,    /* Loads incl. alternate-space (asi valid) and the
                         * LDSTUB atomic byte op (atomic flag set). */
    SPARC64_OP_STORE,   /* Stores incl. alternate-space (asi valid). */
    SPARC64_OP_SWAP,    /* SWAP/SWAPA atomic register/memory exchange
                         * (atomic flag set). */
    SPARC64_OP_CASA,    /* CASA (op 3, op3 0x3c): rs1/rs2(value)/rd(compare)
                         * /asi. i == 0 takes ASI from bits 12:5 (ASI < 0x80
                         * decodes PRIV); i == 1 takes ASI from %asi
                         * (regasi set, E03). */
    SPARC64_OP_CASXA,   /* CASXA (op 3, op3 0x3e): 64-bit form of CASA. */
    SPARC64_OP_FPMEM,   /* FP loads/stores (op 3, op3 0x20..0x27 plus the
                         * 0x30-group LDFA/LDDFA/STFA/STDFA): LDF/LDFSR/
                         * LDQF/LDDF/STF/STFSR/STQF/STDF. Purely
                         * syntactic; semantics and traps are Phase 3. */
    SPARC64_OP_PREFETCH, /* PREFETCH (op 3, op3 0x2d): cache hint; rd is
                         * the prefetch function. L1b checks ASI privilege
                         * then nops. */
    SPARC64_OP_ALIGN   /* ALIGNADDR/ALIGNADDRL/FALIGNDATA (op 2, op3 0x36):
                        * identical opcode word; integer form writes GSR
                        * (L1b), FP form splices (Phase 3). */
} sparc64_op_t;

/* op == 2 (Format 3 ALU/misc) op3 values (SPARC V9). Order of the tagged
 * row (0x20 TADDcc, 0x21 TSUBcc, 0x22 TADDccTV, 0x23 TSUBccTV) is
 * objdump-verified ground truth, not the V8 order. */
#define SPARC64_OP3_ADD     0x00U
#define SPARC64_OP3_AND     0x01U
#define SPARC64_OP3_OR      0x02U
#define SPARC64_OP3_XOR     0x03U
#define SPARC64_OP3_SUB     0x04U
#define SPARC64_OP3_ANDN    0x05U
#define SPARC64_OP3_ORN     0x06U
#define SPARC64_OP3_XNOR    0x07U
#define SPARC64_OP3_ADDX    0x08U
#define SPARC64_OP3_MULX    0x09U
#define SPARC64_OP3_UMUL    0x0AU
#define SPARC64_OP3_SMUL    0x0BU
#define SPARC64_OP3_SUBX    0x0CU
#define SPARC64_OP3_UDIVX   0x0DU
#define SPARC64_OP3_UDIV    0x0EU
#define SPARC64_OP3_SDIV    0x0FU
#define SPARC64_OP3_ADDCC   0x10U
#define SPARC64_OP3_ANDCC   0x11U
#define SPARC64_OP3_ORCC    0x12U
#define SPARC64_OP3_XORCC   0x13U
#define SPARC64_OP3_SUBCC   0x14U
#define SPARC64_OP3_ANDNCC  0x15U
#define SPARC64_OP3_ORNCC   0x16U
#define SPARC64_OP3_XNORCC  0x17U
#define SPARC64_OP3_ADDXCC  0x18U
#define SPARC64_OP3_UMULCC  0x1AU
#define SPARC64_OP3_SMULCC  0x1BU
#define SPARC64_OP3_SUBXCC  0x1CU
#define SPARC64_OP3_UDIVCC  0x1EU
#define SPARC64_OP3_SDIVCC  0x1FU
#define SPARC64_OP3_TADDCC   0x20U
#define SPARC64_OP3_TSUBCC   0x21U
#define SPARC64_OP3_TADDCCTV 0x22U
#define SPARC64_OP3_TSUBCCTV 0x23U
#define SPARC64_OP3_MULSCC  0x24U
#define SPARC64_OP3_SLL     0x25U
#define SPARC64_OP3_SRL     0x26U
#define SPARC64_OP3_SRA     0x27U
#define SPARC64_OP3_RDASR   0x28U
#define SPARC64_OP3_RDHPR   0x29U
#define SPARC64_OP3_RDPR    0x2AU
#define SPARC64_OP3_FLUSHW  0x2BU
#define SPARC64_OP3_MOVCC   0x2CU
#define SPARC64_OP3_SDIVX   0x2DU
#define SPARC64_OP3_POPC    0x2EU
#define SPARC64_OP3_MOVR    0x2FU
#define SPARC64_OP3_WRASR   0x30U
#define SPARC64_OP3_SAVED   0x31U
#define SPARC64_OP3_WRPR    0x32U
#define SPARC64_OP3_WRHPR   0x33U
#define SPARC64_OP3_FPOP1   0x34U
#define SPARC64_OP3_FPOP2   0x35U
#define SPARC64_OP3_ALIGN   0x36U
#define SPARC64_OP3_JMPL    0x38U
#define SPARC64_OP3_RETURN  0x39U
#define SPARC64_OP3_TCC     0x3AU
#define SPARC64_OP3_FLUSH   0x3BU
#define SPARC64_OP3_SAVE    0x3CU
#define SPARC64_OP3_RESTORE 0x3DU
#define SPARC64_OP3_DONE    0x3EU

/* op == 3 (Format 3 memory) op3 values (SPARC V9). Twin-word LDD/STD and
 * the LDXA/STXA asymmetry (LDX 0x0b vs STX 0x0e) are objdump-verified. */
#define SPARC64_OP3_LDUW   0x00U
#define SPARC64_OP3_LDUB   0x01U
#define SPARC64_OP3_LDUH   0x02U
#define SPARC64_OP3_LDD    0x03U
#define SPARC64_OP3_STW    0x04U
#define SPARC64_OP3_STB    0x05U
#define SPARC64_OP3_STH    0x06U
#define SPARC64_OP3_STD    0x07U
#define SPARC64_OP3_LDSW   0x08U
#define SPARC64_OP3_LDSB   0x09U
#define SPARC64_OP3_LDSH   0x0AU
#define SPARC64_OP3_LDX    0x0BU
#define SPARC64_OP3_LDSTUB 0x0DU
#define SPARC64_OP3_STX    0x0EU
#define SPARC64_OP3_SWAP   0x0FU
#define SPARC64_OP3_LDA    0x10U
#define SPARC64_OP3_LDUBA  0x11U
#define SPARC64_OP3_LDUHA  0x12U
#define SPARC64_OP3_LDDA   0x13U
#define SPARC64_OP3_STA    0x14U
#define SPARC64_OP3_STBA   0x15U
#define SPARC64_OP3_STHA   0x16U
#define SPARC64_OP3_STDA   0x17U
#define SPARC64_OP3_LDSWA  0x18U
#define SPARC64_OP3_LDSBA  0x19U
#define SPARC64_OP3_LDSHA  0x1AU
#define SPARC64_OP3_LDXA   0x1BU
#define SPARC64_OP3_LDSTUBA 0x1DU
#define SPARC64_OP3_STXA   0x1EU
#define SPARC64_OP3_SWAPA  0x1FU
#define SPARC64_OP3_LDF    0x20U
#define SPARC64_OP3_LDFSR  0x21U
#define SPARC64_OP3_LDQF   0x22U
#define SPARC64_OP3_LDDF   0x23U
#define SPARC64_OP3_STF    0x24U
#define SPARC64_OP3_STFSR  0x25U
#define SPARC64_OP3_STQF   0x26U
#define SPARC64_OP3_STDF   0x27U
/* FP alternate-space group (V9 0x30-0x37, imm ASI or %asi form);
 * values match src/interp/interp.h. Only the LDFA/LDDFA/STFA/STDFA
 * members are architecturally assigned (0x31/0x32/0x35/0x36 stay
 * illegal); glibc's VIS block memcpy uses LDDFA/STDFA with %asi. */
#define SPARC64_OP3_LDFA   0x30U
#define SPARC64_OP3_LDDFA  0x33U
#define SPARC64_OP3_STFA   0x34U
#define SPARC64_OP3_STDFA  0x37U
#define SPARC64_OP3_PREFETCH 0x2DU
#define SPARC64_OP3_CASA   0x3CU
#define SPARC64_OP3_CASXA  0x3EU

/* Bicc/BPcc/MOVcc/Tcc integer condition codes (V9 numbering). */
#define SPARC64_COND_N   0x0U
#define SPARC64_COND_E   0x1U
#define SPARC64_COND_LE  0x2U
#define SPARC64_COND_L   0x3U
#define SPARC64_COND_LEU 0x4U
#define SPARC64_COND_CS  0x5U
#define SPARC64_COND_NEG 0x6U
#define SPARC64_COND_VS  0x7U
#define SPARC64_COND_A   0x8U
#define SPARC64_COND_NE  0x9U
#define SPARC64_COND_G   0xAU
#define SPARC64_COND_GE  0xBU
#define SPARC64_COND_GU  0xCU
#define SPARC64_COND_CC  0xDU
#define SPARC64_COND_POS 0xEU
#define SPARC64_COND_VC  0xFU

/* BPr/MOVr register-test conditions (objdump-verified; 0 and 4 reserved). */
#define SPARC64_RCOND_Z   0x1U
#define SPARC64_RCOND_LEZ 0x2U
#define SPARC64_RCOND_LZ  0x3U
#define SPARC64_RCOND_NZ  0x5U
#define SPARC64_RCOND_GZ  0x6U
#define SPARC64_RCOND_GEZ 0x7U

/* FBfcc floating-point conditions (objdump-measured; full table is L1b /
 * Phase 3 domain, which verifies against the oracle). */
#define SPARC64_FCOND_N 0x0U
#define SPARC64_FCOND_L 0x4U
#define SPARC64_FCOND_U 0x7U
#define SPARC64_FCOND_E 0x9U
#define SPARC64_FCOND_O 0xFU

/* cc selector values: BPcc/Tcc use 0 for %icc and 2 for %xcc (1 and 3
 * reserved); integer MOVcc uses bit 12 (0 = %icc, 1 = %xcc); FBfcc
 * carries the fcc index (0..3, all valid). */
#define SPARC64_CC_ICC 0x0U
#define SPARC64_CC_XCC 0x2U

/* RDASR/WRASR register numbers (GAS-verified; other values illegal here:
 * 1 is unassigned, 7 is unassigned, 15 selects MEMBAR on op3 0x28 and
 * SIR on op3 0x30, and WRASR additionally excludes %tick/%pc. GAS
 * accepts raw %asrN for any N, but the oracle kills rd %asr1/7/16 with
 * SIGILL, so non-listed numbers decode ILLEGAL, matching the oracle. */
#define SPARC64_ASR_Y    0x00U
#define SPARC64_ASR_CCR  0x02U
#define SPARC64_ASR_ASI  0x03U
#define SPARC64_ASR_TICK 0x04U
#define SPARC64_ASR_PC   0x05U
#define SPARC64_ASR_FPRS 0x06U
#define SPARC64_ASR_GSR  0x13U

/* The SPARC64 Linux syscall trap word (E01..E04: ta 0x6d). */
#define SPARC64_TRAP_SYSCALL_NUM  0x6DU
#define SPARC64_TRAP_SYSCALL_WORD 0x91D0206DU

/* User-mode data ASIs admitted by SPEC section 2.1 (E03). Bit 3 selects
 * little-endian access (qemu bswap); ASIs below 0x80 trap privileged. */
#define SPARC64_ASI_PRIMARY       0x80U
#define SPARC64_ASI_PRIMARY_NOFAULT 0x82U
#define SPARC64_ASI_PRIMARY_LITTLE 0x88U
#define SPARC64_ASI_PRIMARY_NOFAULT_LITTLE 0x8AU

/* Decoded instruction: every field is filled to a defined value for every
 * class; fields unused by a class read 0. */
typedef struct {
    uint32_t raw;    /* Raw big-endian instruction word. */
    uint32_t cls;    /* sparc64_op_t class. */
    uint32_t op;     /* Top-level op field (bits 31:30). */
    uint32_t op2;    /* Format-2 op2 (op == 0 only). */
    uint32_t op3;    /* Format-3 op3 (op == 2/3 only). */
    uint32_t rd;     /* Destination register; Tcc trap cond lives in cond,
                      * MEMBAR mmask lives here, PREFETCH fcn lives here. */
    uint32_t rs1;    /* First source register (Format 3); BPr/MOVr test
                      * register; RDASR number lives in asr instead. */
    uint32_t rs2;    /* Second source register (Format 3, i == 0). */
    uint32_t is_imm; /* i bit (second-operand select; CASA/CASXA always 0). */
    int32_t  simm;   /* Sign-extended immediate: simm13 (i == 1), simm10
                      * (MOVr i == 1), cmask-ish (MEMBAR). */
    uint32_t asi;    /* Alternate-space ASI (op == 3, i == 0); raw
                      * bits 12:5 otherwise (L1b ignores for the rest). */
    uint32_t regasi; /* CASA/CASXA with i == 1: ASI comes from %asi (E03). */
    uint32_t cond;   /* Bicc/BPcc/FBfcc/Tcc/MOVcc condition (bits vary by
                      * class; see the class comment for the encoding). */
    uint32_t rcond;  /* BPr/MOVr register-test condition. */
    uint32_t cc_sel; /* BPcc/Tcc: 0 = %icc, 2 = %xcc; MOVcc: 0 = %icc,
                      * 1 = %xcc; FBfcc: fcc index 0..3. */
    uint32_t annul;  /* Branch annul (a) bit. */
    uint32_t pred;   /* BPcc/BPr/FBfcc prediction hint (1 predicts taken). */
    int32_t  disp;   /* Scaled branch/call displacement in bytes
                      * (sign-extended, already << 2). */
    uint32_t uimm;   /* SETHI imm22 (caller shifts << 10) / ILLTRAP const22. */
    uint32_t opf;    /* FPU opf field (bits 13:5) for SPARC64_OP_FPU. */
    uint32_t asr;    /* ASR number for RDASR/WRASR. */
    uint32_t atomic; /* Set for LDSTUB/SWAP/CASA/CASXA (single-copy atomic). */
    uint32_t cc;     /* Set when the ALU op updates icc + xcc. */
    uint32_t xbit;   /* Set for SLLX/SRLX/SRAX (shift bit 12). */
} sparc64_decoded_t;

/* Pure word decoder: classifies one raw instruction word, no memory access.
 * Always fills *out (illegal words yield SPARC64_OP_ILLEGAL). */
void sparc64_decode_word(uint32_t word, sparc64_decoded_t *out);

/* Big-endian fetch + decode at guest VA. Returns 0 on success. On fault
 * (misaligned VA or a failed checked read of [va, va + 4)) marks *out
 * illegal and returns -1. Guest-visible faults (unmapped, permission,
 * range, bus) additionally set cpu->exit_reason = SPARC64_EXIT_FAULT
 * with cpu->fault_addr = va; runtime conditions (resource, retry,
 * internal) leave cpu untouched for the caller to map to RETRY/INTERNAL.
 * Guest addresses are full 64-bit values, never truncated. */
int sparc64_fetch_decode(sparc64_cpu_t *cpu,
                         const sparc64_mem_ops_t *memory,
                         void *context,
                         uint64_t va,
                         sparc64_decoded_t *out);

#endif /* SPARC64RT_INTERP_DECODE_H */
