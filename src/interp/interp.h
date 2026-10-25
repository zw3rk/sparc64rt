/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Shared internals for the SPARC V9 reference interpreter (Phase 1, L1b).
 * Declares the decoded-instruction form, the inline register/condition-code
 * helpers, and the cross-file entry points implemented in interp_mem.c
 * (guest loads/stores/atomics) and interp_win.c (register-window file).
 * Not part of the frozen engine API (src/core/cpu.h).
 */

#ifndef SPARC64RT_INTERP_INTERP_H
#define SPARC64RT_INTERP_INTERP_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "core/cpu.h"

/* Decoded-instruction class: one per execution family. FPU forms decode so
 * the stepper can skip them to the Phase 3 illegal-trap marker. */
typedef enum {
    SPARC64_ICLS_ILLEGAL = 0,
    SPARC64_ICLS_CALL,
    SPARC64_ICLS_SETHI,
    SPARC64_ICLS_BICC,
    SPARC64_ICLS_BPCC,
    SPARC64_ICLS_BPR,
    SPARC64_ICLS_FBR,   /* FBfcc: delay-shape like Bicc, Phase 3 owns fcc. */
    SPARC64_ICLS_ALU,   /* Integer ALU incl. MULX/DIVX/POPC/TAG/MULScc. */
    SPARC64_ICLS_SHIFT, /* SLL/SRL/SRA/SLLX/SRLX/SRAX. */
    SPARC64_ICLS_MOVCC, /* Integer MOVcc (op3 0x2C, bit 18 set). */
    SPARC64_ICLS_MOVR,  /* Integer MOVr (op3 0x2F). */
    SPARC64_ICLS_RDASR,
    SPARC64_ICLS_WRASR,
    SPARC64_ICLS_MEMBAR, /* op3 0x2C with bit 18 clear: host-model nop. */
    SPARC64_ICLS_FLUSH,  /* Cache-flush hint: host-model nop. */
    SPARC64_ICLS_ALIGN,  /* ALIGNADDR / ALIGNADDRL (op3 0x36, opf 0x18/0x1A). */
    SPARC64_ICLS_JMPL,
    SPARC64_ICLS_RETURN,
    SPARC64_ICLS_TCC,
    SPARC64_ICLS_SAVE,
    SPARC64_ICLS_RESTORE,
    SPARC64_ICLS_LOAD,
    SPARC64_ICLS_STORE,
    SPARC64_ICLS_LDSTUB,
    SPARC64_ICLS_SWAP,
    SPARC64_ICLS_ATOMIC, /* CASA / CASXA. */
    SPARC64_ICLS_PRIV,   /* RDPR/WRPR/RDHPR/WRHPR/FLUSHW/SAVED/RESTORED/
                          * DONE/RETRY/SIR/RDPC/RDTICK/priv-ASR access. */
    SPARC64_ICLS_FPU     /* FPop1/FPop2, FP loads/stores, FALIGNDATA. */
} sparc64_icls_t;

/* op == 2 (Format 3 ALU/misc) op3 values (SPARC V9). */
#define SPARC64_OP3_ADD 0x00U
#define SPARC64_OP3_AND 0x01U
#define SPARC64_OP3_OR 0x02U
#define SPARC64_OP3_XOR 0x03U
#define SPARC64_OP3_SUB 0x04U
#define SPARC64_OP3_ANDN 0x05U
#define SPARC64_OP3_ORN 0x06U
#define SPARC64_OP3_XORN 0x07U
#define SPARC64_OP3_ADDX 0x08U
#define SPARC64_OP3_MULX 0x09U
#define SPARC64_OP3_UMUL 0x0AU
#define SPARC64_OP3_SMUL 0x0BU
#define SPARC64_OP3_SUBX 0x0CU
#define SPARC64_OP3_UDIVX 0x0DU
#define SPARC64_OP3_UDIV 0x0EU
#define SPARC64_OP3_SDIV 0x0FU
#define SPARC64_OP3_ADDCC 0x10U
#define SPARC64_OP3_ANDCC 0x11U
#define SPARC64_OP3_ORCC 0x12U
#define SPARC64_OP3_XORCC 0x13U
#define SPARC64_OP3_SUBCC 0x14U
#define SPARC64_OP3_ANDNCC 0x15U
#define SPARC64_OP3_ORNCC 0x16U
#define SPARC64_OP3_XORNCC 0x17U
#define SPARC64_OP3_ADDXCC 0x18U
#define SPARC64_OP3_UMULCC 0x1AU
#define SPARC64_OP3_SMULCC 0x1BU
#define SPARC64_OP3_SUBXCC 0x1CU
#define SPARC64_OP3_UDIVCC 0x1EU
#define SPARC64_OP3_SDIVCC 0x1FU
#define SPARC64_OP3_TADDCC 0x20U
#define SPARC64_OP3_TSUBCC 0x21U
#define SPARC64_OP3_TADDCTV 0x22U
#define SPARC64_OP3_TSUBCTV 0x23U
#define SPARC64_OP3_MULSCC 0x24U
#define SPARC64_OP3_SLL 0x25U
#define SPARC64_OP3_SRL 0x26U
#define SPARC64_OP3_SRA 0x27U
#define SPARC64_OP3_RDASR 0x28U
#define SPARC64_OP3_RDPR 0x2AU
#define SPARC64_OP3_RDHPR 0x29U
#define SPARC64_OP3_FLUSHW 0x2BU
#define SPARC64_OP3_MOVCC 0x2CU
#define SPARC64_OP3_SDIVX 0x2DU
#define SPARC64_OP3_POPC 0x2EU
#define SPARC64_OP3_MOVR 0x2FU
#define SPARC64_OP3_WRASR 0x30U
#define SPARC64_OP3_WRPR 0x32U
#define SPARC64_OP3_WRHPR 0x31U
#define SPARC64_OP3_FPOP1 0x34U
#define SPARC64_OP3_FPOP2 0x35U
#define SPARC64_OP3_VIS 0x36U
#define SPARC64_OP3_JMPL 0x38U
#define SPARC64_OP3_RETURN 0x39U
#define SPARC64_OP3_TCC 0x3AU
#define SPARC64_OP3_FLUSH 0x3BU
#define SPARC64_OP3_SAVE 0x3CU
#define SPARC64_OP3_RESTORE 0x3DU
#define SPARC64_OP3_DONE 0x3EU
#define SPARC64_OP3_RETRY 0x3FU

/* op == 3 (Format 3 memory) op3 values (SPARC V9). */
#define SPARC64_OP3_LDUW 0x00U
#define SPARC64_OP3_LDUB 0x01U
#define SPARC64_OP3_LDUH 0x02U
#define SPARC64_OP3_LDD 0x03U
#define SPARC64_OP3_STW 0x04U
#define SPARC64_OP3_STB 0x05U
#define SPARC64_OP3_STH 0x06U
#define SPARC64_OP3_STD 0x07U
#define SPARC64_OP3_LDSW 0x08U
#define SPARC64_OP3_LDSB 0x09U
#define SPARC64_OP3_LDSH 0x0AU
#define SPARC64_OP3_LDX 0x0BU
#define SPARC64_OP3_STX 0x0EU
#define SPARC64_OP3_LDSTUB 0x0DU
#define SPARC64_OP3_SWAP 0x0FU
#define SPARC64_OP3_LDA 0x10U
#define SPARC64_OP3_LDUBA 0x11U
#define SPARC64_OP3_LDUHA 0x12U
#define SPARC64_OP3_LDDA 0x13U
#define SPARC64_OP3_STA 0x14U
#define SPARC64_OP3_STBA 0x15U
#define SPARC64_OP3_STHA 0x16U
#define SPARC64_OP3_STDA 0x17U
#define SPARC64_OP3_LDSWA 0x18U
#define SPARC64_OP3_LDSBA 0x19U
#define SPARC64_OP3_LDSHA 0x1AU
#define SPARC64_OP3_LDXA 0x1BU
#define SPARC64_OP3_STXA 0x1CU
#define SPARC64_OP3_LDSTUBA 0x1DU
#define SPARC64_OP3_SWAPA 0x1FU
#define SPARC64_OP3_LDF 0x20U
#define SPARC64_OP3_LDFSR 0x21U
#define SPARC64_OP3_LDTW 0x22U
#define SPARC64_OP3_LDDF 0x23U
#define SPARC64_OP3_STF 0x24U
#define SPARC64_OP3_STFSR 0x25U
#define SPARC64_OP3_STTW 0x26U
#define SPARC64_OP3_STDF 0x27U
#define SPARC64_OP3_LDFA 0x30U
#define SPARC64_OP3_LDDFA 0x33U
#define SPARC64_OP3_STFA 0x34U
#define SPARC64_OP3_STDFA 0x37U
#define SPARC64_OP3_PREFETCH 0x2DU
#define SPARC64_OP3_CASA 0x3CU
#define SPARC64_OP3_CASXA 0x3EU

/* ASR numbers for RDASR/WRASR (rs1/rd field). TICK/PC/SOFTINT (20-22),
 * TICK_CMPR (23), STICK/STICK_CMPR (24-25) are supervisor-only. */
#define SPARC64_ASR_Y 0U
#define SPARC64_ASR_CCR 2U
#define SPARC64_ASR_ASI 3U
#define SPARC64_ASR_TICK 4U
#define SPARC64_ASR_PC 5U
#define SPARC64_ASR_FPRS 6U
#define SPARC64_ASR_GSR 19U

/* User data ASIs (SPEC 2.1). 0x80/0x82 big-endian, 0x88/0x8a little-endian
 * (endianness selects on bit 3). Anything below 0x80 traps privileged. */
#define SPARC64_ASI_P 0x80U
#define SPARC64_ASI_PNF 0x82U
#define SPARC64_ASI_PL 0x88U
#define SPARC64_ASI_PNFL 0x8AU

/* VIS opf values (op == 2, op3 == 0x36, opf in bits 13:5). */
#define SPARC64_OPF_ALIGNADDR 0x18U
#define SPARC64_OPF_ALIGNADDRL 0x1AU
#define SPARC64_OPF_FALIGNDATA 0x48U

/* Decoded instruction: every field reads 0 unless the class sets it. */
typedef struct {
    uint32_t raw;
    uint8_t cls;   /* sparc64_icls_t */
    uint8_t op;    /* Top-level op (bits 31:30). */
    uint8_t op3;   /* Format-3 op3 (op == 2/3 only). */
    uint8_t rd;    /* Destination register / TCC condition. */
    uint8_t rs1;   /* First source register / priv-reg / ASR number. */
    uint8_t rs2;   /* Second source register (i == 0). */
    uint8_t cond;  /* Branch/Tcc/MOVcc condition, BPr/MOVr rcond. */
    uint8_t cc;    /* cc select: 0 = icc, 2 = xcc. */
    uint8_t asi;   /* Immediate ASI (alternate-space forms, i == 0). */
    uint8_t regasi; /* i == 1 alternate form: ASI comes from %asi. */
    uint8_t annul; /* Branch annul (a) bit. */
    uint8_t pred;  /* Branch prediction (p) bit, advisory only. */
    uint8_t is_imm;
    uint8_t xbit;  /* Shift x bit (64-bit shift form). */
    int64_t imm;   /* Sign-extended operand: simm13 / simm10 / shift count. */
    int64_t disp;  /* Scaled branch/call displacement in bytes (already << 2). */
    uint32_t opf;  /* FPop/VIS opf field (bits 13:5). */
    uint32_t uimm; /* SETHI imm22 (caller shifts << 10). */
} sparc64_dec_t;

/* Pure word classifier: fills *out for any raw word (illegal words yield
 * SPARC64_ICLS_ILLEGAL). No memory access, no state change. */
void sparc64_classify_word(uint32_t word, sparc64_dec_t *out);

/* Register access: r[0] (%g0) reads as 0, writes to rd == 0 are dropped.
 * Guest addresses and operands are full 64-bit, never truncated. */
static inline uint64_t sparc64_rreg(const sparc64_cpu_t *cpu, unsigned i)
{
    return (i == 0U) ? UINT64_C(0) : cpu->r[i & 31U];
}

static inline void sparc64_wreg(sparc64_cpu_t *cpu, unsigned rd, uint64_t v)
{
    if (rd != 0U) {
        cpu->r[rd & 31U] = v;
    }
}

/* Condition-code update: sets the icc low nibble and xcc nibble, preserving
 * the upper CCR bits (always zero on entry, kept for safety). */
static inline void sparc64_cc_set(sparc64_ctx_t *ctx, unsigned icc,
    unsigned xcc)
{
    ctx->ccr = (ctx->ccr & ~(UINT64_C(0xff))) |
        (((uint64_t)(xcc & 15U) << 4) | (uint64_t)(icc & 15U));
}

static inline unsigned sparc64_cc_icc(const sparc64_ctx_t *ctx)
{
    return (unsigned)(ctx->ccr & UINT64_C(0xf));
}

static inline unsigned sparc64_cc_xcc(const sparc64_ctx_t *ctx)
{
    return (unsigned)((ctx->ccr >> 4) & UINT64_C(0xf));
}

/* Bicc/BPcc/Ticc/MOVcc condition evaluation. icc/xcc are the raw 4-bit
 * N/Z/V/C nibbles (bit 3 N, bit 2 Z, bit 1 V, bit 0 C). */
bool sparc64_eval_cond(unsigned cond, unsigned nibble);

/* Clean-completion step result (caller advances pc/npc). */
static inline sparc64_step_result_t sparc64_step_ok(uint64_t pc)
{
    sparc64_step_result_t r;
    r.kind = SPARC64_STEP_CONTINUE;
    r.cause = SPARC64_TRAP_ILLEGAL;
    r.pc = pc;
    r.tval = UINT64_C(0);
    r.length = 4U;
    r.memory_reason = SPARC64_MEM_FAULT_NONE;
    return r;
}

/* BPr/MOVr register test. rcond skips 4: 1 Z, 2 LEZ, 3 LZ, 5 NZ, 6 GZ,
 * 7 GEZ over the full 64-bit value. */
bool sparc64_eval_rcond(unsigned rcond, uint64_t v);

/* Result constructors shared by the three units. */
sparc64_step_result_t sparc64_trap(sparc64_trap_cause_t cause, uint64_t pc,
    uint64_t tval);
sparc64_step_result_t sparc64_mem_trap(const sparc64_mem_fault_t *fault,
    uint64_t pc, bool is_store);

/* Guest memory internals (interp_mem.c). All multi-byte integer traffic is
 * big-endian; single-byte accesses never fault on alignment; misaligned
 * multi-byte accesses trap (LOAD/STORE_MISALIGNED, qemu parity). The asi
 * argument selects byte order (bit 3 set: little-endian). */
bool sparc64_mem_read(const sparc64_mem_ops_t *mem, void *mc, uint64_t va,
    uint8_t *out, unsigned n, sparc64_step_result_t *res, uint64_t pc);
bool sparc64_mem_write(const sparc64_mem_ops_t *mem, void *mc, uint64_t va,
    const uint8_t *in, unsigned n, sparc64_step_result_t *res, uint64_t pc);
bool sparc64_ld_int(const sparc64_mem_ops_t *mem, void *mc, uint64_t va,
    unsigned size, bool sign_extend, bool little, uint64_t *out,
    sparc64_step_result_t *res, uint64_t pc);
bool sparc64_st_int(const sparc64_mem_ops_t *mem, void *mc, uint64_t va,
    unsigned size, bool little, uint64_t v, sparc64_step_result_t *res,
    uint64_t pc);
/* Atomic read-modify-write: 4/8-byte compare-and-swap, 4-byte swap, and
 * 1-byte LDSTUB (mem <- 0xFF). Uses memory->atomic (LR/SC loop for CAS)
 * when present, else a read/compare/write pair. Values are guest-ordered
 * integers (byte-swapped internally for little-endian ASIs). */
bool sparc64_cas(const sparc64_mem_ops_t *mem, void *mc, uint64_t va,
    unsigned size, bool little, uint64_t expect, uint64_t swap, uint64_t *old,
    sparc64_step_result_t *res, uint64_t pc);
bool sparc64_swap(const sparc64_mem_ops_t *mem, void *mc, uint64_t va,
    unsigned size, bool little, uint64_t swap, uint64_t *old,
    sparc64_step_result_t *res, uint64_t pc);

/* Register-window internals (interp_win.c). sum is the computed SAVE/
 * RESTORE operand (new %sp); rd receives it. Handles lazy fresh-process
 * init and 128-byte spill/fill at [sp + 2047] on window overflow/underflow
 * only; depth-1 rotation is pure register movement. */
bool sparc64_win_save(sparc64_cpu_t *cpu, const sparc64_mem_ops_t *mem,
    void *mc, uint64_t sum, unsigned rd, sparc64_step_result_t *res,
    uint64_t pc);
bool sparc64_win_restore(sparc64_cpu_t *cpu, const sparc64_mem_ops_t *mem,
    void *mc, uint64_t sum, unsigned rd, sparc64_step_result_t *res,
    uint64_t pc);
/* Flush-all (interp_win.c): mirror every outstanding window image into
 * its architectural stack slot (setjmp-trap helper, see above). */
bool sparc64_win_flush_all(sparc64_cpu_t *cpu, const sparc64_mem_ops_t *mem,
    void *mc, sparc64_step_result_t *res, uint64_t pc);
/* Invalidate-all (interp_win.c): drop every cached image (longjmp-trap
 * helper, see above). */
void sparc64_win_invalidate_all(void);

/* Integer execution backend (interp_win.c): single non-CTI data-path
 * instructions. Each returns CONTINUE (caller advances pc/npc) or a stop
 * result (trap, pc unchanged). d is the classifier output. */
sparc64_step_result_t sparc64_exec_alu(sparc64_cpu_t *cpu, uint64_t pc,
    const sparc64_dec_t *d);
sparc64_step_result_t sparc64_exec_shift(sparc64_cpu_t *cpu, uint64_t pc,
    const sparc64_dec_t *d);
sparc64_step_result_t sparc64_exec_mov(sparc64_cpu_t *cpu, uint64_t pc,
    const sparc64_dec_t *d);
sparc64_step_result_t sparc64_exec_rdasr(sparc64_cpu_t *cpu, uint64_t pc,
    const sparc64_dec_t *d);
sparc64_step_result_t sparc64_exec_wrasr(sparc64_cpu_t *cpu, uint64_t pc,
    const sparc64_dec_t *d);
sparc64_step_result_t sparc64_exec_align(sparc64_cpu_t *cpu, uint64_t pc,
    const sparc64_dec_t *d);
/* Minimal RC2 FPU kernel (interp/fp.c); Phase 3 subsumes it. */
sparc64_step_result_t sparc64_exec_fpu(sparc64_ctx_t *cpu,
    const sparc64_mem_ops_t *mem, void *mc, uint64_t pc,
    const sparc64_dec_t *d);

/* Alternate-space ASI check (interp_mem.c); the FPU kernel resolves
 * regasi into a copy before calling. */
bool sparc64_asi_check(uint64_t pc, const sparc64_dec_t *d, bool *little,
    sparc64_step_result_t *res);

/* Memory execution backend (interp_mem.c): loads, stores, and atomics over
 * the guest memory operations. */
sparc64_step_result_t sparc64_exec_load(sparc64_cpu_t *cpu,
    const sparc64_mem_ops_t *mem, void *mc, uint64_t pc,
    const sparc64_dec_t *d);
sparc64_step_result_t sparc64_exec_store(sparc64_cpu_t *cpu,
    const sparc64_mem_ops_t *mem, void *mc, uint64_t pc,
    const sparc64_dec_t *d);
sparc64_step_result_t sparc64_exec_atomic(sparc64_cpu_t *cpu,
    const sparc64_mem_ops_t *mem, void *mc, uint64_t pc,
    const sparc64_dec_t *d);

/* Big-endian instruction fetch (interp_mem.c, SPARC64_ACCESS_FETCH). */
bool sparc64_fetch_word(const sparc64_mem_ops_t *mem, void *mc, uint64_t va,
    uint32_t *out, sparc64_step_result_t *res);

#endif /* SPARC64RT_INTERP_INTERP_H */
