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

static sparc64_step_result_t exec_single(sparc64_cpu_t *cpu,
    const sparc64_mem_ops_t *mem, void *mc, uint64_t pc, const sparc64_dec_t *d);
static sparc64_step_result_t exec_cti(sparc64_cpu_t *cpu,
    const sparc64_mem_ops_t *mem, void *mc, uint64_t pc, const sparc64_dec_t *d);
static sparc64_step_result_t exec_tcc(sparc64_cpu_t *cpu, uint64_t pc,
    const sparc64_dec_t *d);

static unsigned sparc64_read_fcc(const sparc64_cpu_t *cpu, unsigned idx)
{
    unsigned i = idx & 3U;
    unsigned shift = (i == 0U) ? 10U : (30U + 2U * i);
    unsigned fcc_fsr = (unsigned)((cpu->fsr >> shift) & UINT64_C(3));
    return (cpu->fcc[i] != 0U) ? (unsigned)(cpu->fcc[i] & 3U) : fcc_fsr;
}

/* Integer MOVcc (%icc/%xcc and %fcc0..%fcc3) and MOVr. */
sparc64_step_result_t sparc64_exec_mov(sparc64_cpu_t *cpu, uint64_t pc,
    const sparc64_dec_t *d)
{
    uint64_t src = (d->is_imm != 0U) ? (uint64_t)d->imm
                                     : sparc64_rreg(cpu, d->rs2);
    bool take;
    if (d->cls == (uint8_t)SPARC64_ICLS_MOVCC) {
        if ((d->cc & 4U) != 0U) {
            take = sparc64_eval_fcond(d->cond, sparc64_read_fcc(cpu, d->cc));
        } else {
            unsigned nib = (d->cc == 2U) ? sparc64_cc_xcc(cpu)
                                         : sparc64_cc_icc(cpu);
            take = sparc64_eval_cond(d->cond, nib);
        }
    } else {
        take = sparc64_eval_rcond(d->cond, sparc64_rreg(cpu, d->rs1));
    }
    if (take) {
        sparc64_wreg(cpu, d->rd, src);
    }
    return sparc64_step_ok(pc);
}

#define SPARC64RT_TICK_VALUE UINT64_C(0x100000001)
sparc64_step_result_t sparc64_exec_rdasr(sparc64_cpu_t *cpu, uint64_t pc,
    const sparc64_dec_t *d)
{
    switch (d->rs1) {
    case SPARC64_ASR_Y:
        sparc64_wreg(cpu, d->rd, cpu->y);
        break;
    case SPARC64_ASR_TICK:
        sparc64_wreg(cpu, d->rd, SPARC64RT_TICK_VALUE);
        break;
    case SPARC64_ASR_PC:
        sparc64_wreg(cpu, d->rd, pc);
        break;
    case SPARC64_ASR_CCR:
        sparc64_wreg(cpu, d->rd, cpu->ccr & UINT64_C(0xff));
        break;
    case SPARC64_ASR_ASI:
        sparc64_wreg(cpu, d->rd, (uint64_t)cpu->asi);
        break;
    case SPARC64_ASR_FPRS:
        sparc64_wreg(cpu, d->rd, cpu->fprs);
        break;
    case SPARC64_ASR_GSR:
        sparc64_wreg(cpu, d->rd, cpu->gsr);
        break;
    default:
        return sparc64_trap(SPARC64_TRAP_PRIVILEGED, pc, d->raw);
    }
    return sparc64_step_ok(pc);
}

sparc64_step_result_t sparc64_exec_wrasr(sparc64_cpu_t *cpu, uint64_t pc,
    const sparc64_dec_t *d)
{
    uint64_t a = sparc64_rreg(cpu, d->rs1);
    uint64_t b = (d->is_imm != 0U) ? (uint64_t)d->imm
                                   : sparc64_rreg(cpu, d->rs2);
    switch (d->rd) {
    case SPARC64_ASR_Y:
        cpu->y = a ^ b;
        break;
    case SPARC64_ASR_CCR:
        cpu->ccr = (cpu->ccr & ~(UINT64_C(0xff))) | ((a ^ b) & UINT64_C(0xff));
        break;
    case SPARC64_ASR_ASI:
        cpu->asi = (uint32_t)((a ^ b) & UINT64_C(0xff));
        break;
    case SPARC64_ASR_FPRS:
        cpu->fprs = a ^ b;
        break;
    case SPARC64_ASR_GSR:
        cpu->gsr = a ^ b;
        break;
    default:
        return sparc64_trap(SPARC64_TRAP_PRIVILEGED, pc, d->raw);
    }
    return sparc64_step_ok(pc);
}

sparc64_step_result_t sparc64_exec_align(sparc64_cpu_t *cpu, uint64_t pc,
    const sparc64_dec_t *d)
{
    uint64_t a = sparc64_rreg(cpu, d->rs1);
    uint64_t b = (d->is_imm != 0U) ? (uint64_t)d->imm
                                   : sparc64_rreg(cpu, d->rs2);
    uint64_t sum = a + b;
    uint64_t off = (d->opf == SPARC64_OPF_ALIGNADDRL)
        ? ((UINT64_C(0) - sum) & UINT64_C(7))
        : (sum & UINT64_C(7));
    cpu->gsr = (cpu->gsr & ~(UINT64_C(7))) | off;
    sparc64_wreg(cpu, d->rd, sum & ~(UINT64_C(7)));
    return sparc64_step_ok(pc);
}

sparc64_step_result_t sparc64_exec_priv(sparc64_cpu_t *cpu,
    const sparc64_mem_ops_t *mem, void *mc, uint64_t pc,
    const sparc64_dec_t *d)
{
    sparc64_step_result_t res;
    if (d->op3 == SPARC64_OP3_FLUSHW) {
        if (!sparc64_win_flush_callers(cpu, mem, mc, &res, pc)) {
            return res;
        }
        cpu->canrestore = 0U;
        cpu->cansave = SPARC64_NWINDOWS - 1U;
        return sparc64_step_ok(pc);
    }
    return sparc64_trap(SPARC64_TRAP_PRIVILEGED, pc, d->raw);
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
        return sparc64_exec_priv(cpu, mem, mc, pc, d);
    case SPARC64_ICLS_FPU:
        return sparc64_exec_fpu(cpu, mem, mc, pc, d);
    case SPARC64_ICLS_FBR:
        /* Unreachable: FBR commits through exec_cti above. */
        return sparc64_trap(SPARC64_TRAP_ILLEGAL, pc, d->raw);
    case SPARC64_ICLS_ILLEGAL:
    default:
        /* Unknown markers trap like EXIT_UNDEF. */
        return sparc64_trap(SPARC64_TRAP_ILLEGAL, pc, d->raw);
    }
}

/* True for CTI classes that carry a delay slot (R7-1 deferral test). */
static bool is_cti_class(uint8_t cls)
{
    return cls == (uint8_t)SPARC64_ICLS_CALL ||
        cls == (uint8_t)SPARC64_ICLS_JMPL ||
        cls == (uint8_t)SPARC64_ICLS_RETURN ||
        cls == (uint8_t)SPARC64_ICLS_BICC ||
        cls == (uint8_t)SPARC64_ICLS_BPCC ||
        cls == (uint8_t)SPARC64_ICLS_BPR ||
        cls == (uint8_t)SPARC64_ICLS_FBR;
}

/* Control transfer at pc (cpu->npc == pc + 4): delay slot, annul, and
 * pc/npc update. Delayed transfers run through a bounded per-step state
 * machine (R7-1): one CTI level plus its delay slot per dispatcher
 * entry. A nested CTI in the delay slot is left published as
 * (delay_pc, target) and the step returns; the dispatcher executes the
 * nested transfer as its next entry, so host work per step stays O(1)
 * and control returns to the dispatcher even when guest branches nest
 * forever. Commit order matches the old recursion on every terminating
 * chain: per-level effects (CALL %o7, JMPL rd, RETURN RESTORE) run
 * before publishing (delay_pc, target) into (cpu->pc, cpu->npc), and a
 * nested CTI's delay slot is the outer target. Publish precedes each
 * delay slot so a delay-slot syscall/trap sees the pending destination
 * in cpu->npc. */
static sparc64_step_result_t exec_cti(sparc64_cpu_t *cpu,
    const sparc64_mem_ops_t *mem, void *mc, uint64_t pc, const sparc64_dec_t *d)
{
    uint64_t npc = cpu->npc;
    uint64_t target;
    uint64_t op2;
    uint32_t delay_raw;
    sparc64_dec_t dd;
    sparc64_step_result_t res;
    bool taken = true;
    if (d->cls == (uint8_t)SPARC64_ICLS_CALL) {
        target = pc + (uint64_t)d->disp; /* mod 2^64 */
        sparc64_wreg(cpu, SPARC64_O7, pc);
    } else if (d->cls == (uint8_t)SPARC64_ICLS_RETURN) {
        /* V9 A.45: the target is computed in the old window, rd is not
         * written, and RESTORE %g0,%g0,%g0 runs before the delay slot
         * (a bare JMPL/retl without restore would leak the window). */
        op2 = (d->is_imm != 0U) ? (uint64_t)d->imm
                                : sparc64_rreg(cpu, d->rs2);
        target = sparc64_rreg(cpu, d->rs1) + op2;
        if ((target & UINT64_C(3)) != UINT64_C(0)) {
            return sparc64_trap(SPARC64_TRAP_LOAD_MISALIGNED, pc, target);
        }
        if (!sparc64_win_restore(cpu, mem, mc, UINT64_C(0), 0U, &res,
            pc)) {
            return res;
        }
    } else if (d->cls == (uint8_t)SPARC64_ICLS_JMPL) {
        op2 = (d->is_imm != 0U) ? (uint64_t)d->imm
                                : sparc64_rreg(cpu, d->rs2);
        target = sparc64_rreg(cpu, d->rs1) + op2;
        if ((target & UINT64_C(3)) != UINT64_C(0)) {
            return sparc64_trap(SPARC64_TRAP_LOAD_MISALIGNED, pc, target);
        }
        sparc64_wreg(cpu, d->rd, pc);
    } else {
        /* Branches: condition, target, annul (BA,a always skips, E02). */
        if (d->cls == (uint8_t)SPARC64_ICLS_BICC) {
            taken = sparc64_eval_cond(d->cond, sparc64_cc_icc(cpu));
        } else if (d->cls == (uint8_t)SPARC64_ICLS_BPCC) {
            unsigned nib = (d->cc == 2U) ? sparc64_cc_xcc(cpu)
                                         : sparc64_cc_icc(cpu);
            taken = sparc64_eval_cond(d->cond, nib);
        } else if (d->cls == (uint8_t)SPARC64_ICLS_FBR) {
            taken = sparc64_eval_fcond(d->cond, sparc64_read_fcc(cpu, d->cc));
        } else {
            taken = sparc64_eval_rcond(d->cond, sparc64_rreg(cpu, d->rs1));
        }
        target = taken ? (pc + (uint64_t)d->disp) : (npc + 4U);
        if (d->annul != 0U) {
            bool skip = taken ? (d->cond == 8U &&
                    d->cls != (uint8_t)SPARC64_ICLS_BPR) : true;
            if (skip) {
                cpu->pc = target;
                cpu->npc = target + 4U;
                return sparc64_step_ok(pc);
            }
        }
    }
    cpu->pc = npc;
    cpu->npc = target;
    if (!sparc64_fetch_word(mem, mc, npc, &delay_raw, &res)) {
        return res;
    }
    sparc64_classify_word(delay_raw, &dd);
    if (is_cti_class(dd.cls)) {
        /* Nested CTI in the delay slot: (npc, target) stays published
         * and this entry ends here. The dispatcher fetches the nested
         * transfer at npc next, with its delay slot at target. */
        return sparc64_step_ok(pc);
    }
    if (dd.cls == (uint8_t)SPARC64_ICLS_TCC) {
        /* A trap-condition in the delay slot evaluates normally: a false
         * condition is a nop, a true one stops with cpu->pc/npc intact. */
        res = exec_tcc(cpu, npc, &dd);
    } else {
        res = exec_single(cpu, mem, mc, npc, &dd);
    }
    if (res.kind != SPARC64_STEP_CONTINUE) {
        return res;
    }
    cpu->pc = cpu->npc;
    cpu->npc += 4U;
    return sparc64_step_ok(pc);
}

/* Trap on condition: false advances; true with trap# 0x6d, 0x6e, or
 * 0x6f is a syscall gate (no state change, the L1c layer applies
 * carry + pc advance); any other true trap number traps ILLEGAL. */
static sparc64_step_result_t exec_tcc(sparc64_cpu_t *cpu, uint64_t pc,
    const sparc64_dec_t *d)
{
    unsigned nib = (d->cc == 2U) ? sparc64_cc_xcc(cpu) : sparc64_cc_icc(cpu);
    uint64_t trapno;
    if (!sparc64_eval_cond(d->cond, nib)) {
        return sparc64_step_ok(pc);
    }
    trapno = (sparc64_rreg(cpu, d->rs1) +
        ((d->is_imm != 0U) ? (uint64_t)d->imm
                           : sparc64_rreg(cpu, d->rs2))) &
        UINT64_C(0x7F);
    /* Linux user traps: 0x6d syscall gate, 0x6e setjmp, 0x6f longjmp.
     * tval carries the trap number; the engine re-reads the ta word, so
     * interp, DBT, and difftest share one dispatch without frozen-header
     * changes. Any other true trap number is an illegal instruction. */
    if ((trapno & UINT64_C(0x7F)) - UINT64_C(0x6D) <= UINT64_C(2)) {
        sparc64_step_result_t r;
        r.kind = SPARC64_STEP_SYSCALL;
        r.cause = SPARC64_TRAP_ILLEGAL;
        r.pc = pc;
        r.tval = trapno & UINT64_C(0x7F);
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
    uint64_t entry_npc;
    bool published;
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
    entry_npc = cpu->npc;
    res = sparc64_decode(cpu, memory, context, &in);
    if (res.kind != SPARC64_STEP_CONTINUE) {
        if (executed != NULL) {
            *executed = in;
        }
        cpu->r[0] = UINT64_C(0);
        return res;
    }
    sparc64_classify_word(in.raw, &d);
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
    case SPARC64_ICLS_FBR:
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
    published = (cpu->pc != pc) || (cpu->npc != entry_npc);
    if (res.kind == SPARC64_STEP_TRAP && !published &&
        cpu->pc != res.pc) {
        /* Trap context is precise: TPC names the faulting instruction.
         * When the faulting path already published pc/npc (exec_cti
         * publishes delay_pc/target before the delay slot, as does
         * dbt_delay_continuation), the pending destination in cpu->npc
         * is kept. Publication is tracked against the entry snapshot,
         * never by treating a guest address (including zero) as an
         * initialization sentinel. */
        cpu->pc = res.pc;
        cpu->npc = res.pc + 4U;
    }
    cpu->r[0] = UINT64_C(0);
    return res;
}

sparc64_step_result_t sparc64_step(sparc64_cpu_t *cpu,
    const sparc64_mem_ops_t *memory, void *context)
{
    return sparc64_step_with_insn(cpu, memory, context, NULL);
}

