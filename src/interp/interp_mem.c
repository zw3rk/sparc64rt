/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Guest memory accessors (Phase 1, L1b): checked loads/stores/atomics over
 * sparc64_mem_ops_t, shared by the executor (interp.c) and the register
 * windows (interp_win.c).
 *
 * Endianness: integer bytes on the guest are big-endian; little-endian
 * alternate-space ASIs (bit 3 set: 0x88/0x8a) byte-swap around a single
 * canonical integer value. Multi-byte accesses are emulated byte-wise, so
 * unaligned loads/stores never fault (kernel-fixup parity); only an
 * unmapped/protected byte or a resource failure stops the step.
 */

#include "interp/interp_mem.h"
#include "os/threads.h"

static uint64_t swap_bytes(uint64_t v, unsigned size)
{
    uint64_t out = UINT64_C(0);
    unsigned i;
    for (i = 0; i < size; i++) {
        out = (out << 8) | (v & UINT64_C(0xff));
        v >>= 8;
    }
    return out;
}

sparc64_step_result_t sparc64_trap(sparc64_trap_cause_t cause, uint64_t pc,
    uint64_t tval)
{
    sparc64_step_result_t r;
    r.kind = SPARC64_STEP_TRAP;
    r.cause = cause;
    r.pc = pc;
    r.tval = tval;
    r.length = 4U;
    r.memory_reason = SPARC64_MEM_FAULT_NONE;
    return r;
}

/* Maps a failed guest access onto the step outcome. RETRY/INTERNAL mark
 * runtime conditions and never enter guest trap delivery; mapping faults
 * become guest load/store traps. */
sparc64_step_result_t sparc64_mem_trap(const sparc64_mem_fault_t *fault,
    uint64_t pc, bool is_store)
{
    sparc64_step_result_t r;
    switch (fault->reason) {
    case SPARC64_MEM_FAULT_RETRY:
        r.kind = SPARC64_STEP_RETRY;
        r.cause = SPARC64_TRAP_LOAD_ACCESS;
        r.pc = pc;
        r.tval = fault->address;
        r.length = 4U;
        r.memory_reason = fault->reason;
        return r;
    case SPARC64_MEM_FAULT_RESOURCE:
    case SPARC64_MEM_FAULT_INTERNAL:
        r.kind = SPARC64_STEP_INTERNAL;
        r.cause = SPARC64_TRAP_LOAD_ACCESS;
        r.pc = pc;
        r.tval = fault->address;
        r.length = 4U;
        r.memory_reason = fault->reason;
        return r;
    case SPARC64_MEM_FAULT_UNMAPPED:
    case SPARC64_MEM_FAULT_PERMISSION:
    case SPARC64_MEM_FAULT_RANGE:
    case SPARC64_MEM_FAULT_BUS:
    case SPARC64_MEM_FAULT_NONE:
    default:
        break;
    }
    r.kind = SPARC64_STEP_TRAP;
    r.cause = is_store ? SPARC64_TRAP_STORE_ACCESS : SPARC64_TRAP_LOAD_ACCESS;
    r.pc = pc;
    r.tval = fault->address;
    r.length = 4U;
    r.memory_reason = fault->reason;
    return r;
}

/* Byte-wise checked access: single-byte accesses never fault on alignment;
 * multi-byte alignment traps are raised by ld_int/st_int (qemu parity). */
bool sparc64_mem_read(const sparc64_mem_ops_t *mem, void *mc, uint64_t va,
    uint8_t *out, unsigned n, sparc64_step_result_t *res, uint64_t pc)
{
    unsigned i;
    if (mem == NULL || mem->read == NULL) {
        *res = sparc64_trap(SPARC64_TRAP_LOAD_ACCESS, pc, va);
        res->memory_reason = SPARC64_MEM_FAULT_INTERNAL;
        return false;
    }
    if (n > 0U) {
        /* Backends serve whole spans natively (fault.address names the
         * exact failing byte): one call covers window spill/fill and
         * block transfers. On failure fall through to the byte loop so
         * partial progress before the fault matches byte-wise. */
        sparc64_mem_fault_t fault;
        fault.address = va;
        fault.reason = SPARC64_MEM_FAULT_NONE;
        if (mem->read(mc, va, out, n, SPARC64_ACCESS_LOAD, &fault)) {
            return true;
        }
    }
    for (i = 0; i < n; i++) {
        sparc64_mem_fault_t fault;
        fault.address = va + (uint64_t)i;
        fault.reason = SPARC64_MEM_FAULT_NONE;
        if (!mem->read(mc, va + (uint64_t)i, &out[i], 1U,
                SPARC64_ACCESS_LOAD, &fault)) {
            *res = sparc64_mem_trap(&fault, pc, false);
            return false;
        }
    }
    return true;
}

bool sparc64_mem_write(const sparc64_mem_ops_t *mem, void *mc, uint64_t va,
    const uint8_t *in, unsigned n, sparc64_step_result_t *res, uint64_t pc)
{
    unsigned i;
    if (mem == NULL || mem->write == NULL) {
        *res = sparc64_trap(SPARC64_TRAP_STORE_ACCESS, pc, va);
        res->memory_reason = SPARC64_MEM_FAULT_INTERNAL;
        return false;
    }
    if (n > 0U) {
        /* Same bulk-first shape as the read side: one call for the
         * whole span, byte loop fallback preserving partial-store
         * semantics before a fault. */
        sparc64_mem_fault_t fault;
        fault.address = va;
        fault.reason = SPARC64_MEM_FAULT_NONE;
        if (mem->write(mc, va, in, n, &fault)) {
            return true;
        }
    }
    for (i = 0; i < n; i++) {
        sparc64_mem_fault_t fault;
        fault.address = va + (uint64_t)i;
        fault.reason = SPARC64_MEM_FAULT_NONE;
        if (!mem->write(mc, va + (uint64_t)i, &in[i], 1U, &fault)) {
            *res = sparc64_mem_trap(&fault, pc, true);
            return false;
        }
    }
    return true;
}

/* Canonical integer load: bytes arrive big-endian, swap for LE ASIs, then
 * zero/sign-extend to 64 bits. */
bool sparc64_ld_int(const sparc64_mem_ops_t *mem, void *mc, uint64_t va,
    unsigned size, bool sign_extend, bool little, uint64_t *out,
    sparc64_step_result_t *res, uint64_t pc)
{
    uint8_t b[8];
    uint64_t v = UINT64_C(0);
    unsigned i;
    unsigned shift;
    if (size == 0U || size > 8U) {
        *res = sparc64_trap(SPARC64_TRAP_LOAD_ACCESS, pc, va);
        res->memory_reason = SPARC64_MEM_FAULT_INTERNAL;
        return false;
    }
    /* SPARC V9 traps on misaligned multi-byte accesses (qemu-sparc64
     * raises SIGBUS; single bytes never trap). Gate RC1 parity depends
     * on this: the guest test expects the trap, not silent emulation. */
    if (size > 1U && (va & (uint64_t)(size - 1U)) != UINT64_C(0)) {
        *res = sparc64_trap(SPARC64_TRAP_LOAD_MISALIGNED, pc, va);
        return false;
    }
    if (!sparc64_mem_read(mem, mc, va, b, size, res, pc)) {
        return false;
    }
    if (!little) {
        for (i = 0; i < size; i++) {
            v = (v << 8) | (uint64_t)b[i];
        }
    } else {
        for (i = 0; i < size; i++) {
            v |= ((uint64_t)b[i] << (8U * (unsigned)i));
        }
    }
    if (sign_extend && size < 8U) {
        shift = 64U - 8U * size;
        v = (uint64_t)(((int64_t)(v << shift)) >> shift);
    }
    *out = v;
    return true;
}

bool sparc64_st_int(const sparc64_mem_ops_t *mem, void *mc, uint64_t va,
    unsigned size, bool little, uint64_t v, sparc64_step_result_t *res,
    uint64_t pc)
{
    uint8_t b[8];
    unsigned i;
    if (size == 0U || size > 8U) {
        *res = sparc64_trap(SPARC64_TRAP_STORE_ACCESS, pc, va);
        res->memory_reason = SPARC64_MEM_FAULT_INTERNAL;
        return false;
    }
    if (size > 1U && (va & (uint64_t)(size - 1U)) != UINT64_C(0)) {
        *res = sparc64_trap(SPARC64_TRAP_STORE_MISALIGNED, pc, va);
        return false;
    }
    if (little) {
        v = swap_bytes(v, size);
    }
    for (i = 0; i < size; i++) {
        b[size - 1U - i] = (uint8_t)(v & UINT64_C(0xff));
        v >>= 8;
    }
    return sparc64_mem_write(mem, mc, va, b, size, res, pc);
}

/* Plain read/compare/conditional-write fallback used when the backend
 * offers no atomic callback (single-threaded interpreter). */
static bool cas_fallback(const sparc64_mem_ops_t *mem, void *mc, uint64_t va,
    unsigned size, bool little, uint64_t expect, uint64_t swap, uint64_t *old,
    sparc64_step_result_t *res, uint64_t pc)
{
    uint64_t cur;
    if (!sparc64_ld_int(mem, mc, va, size, false, little, &cur, res, pc)) {
        return false;
    }
    *old = cur;
    if (cur != expect) {
        return true;
    }
    return sparc64_st_int(mem, mc, va, size, little, swap, res, pc);
}

/* LR/SC compare-and-swap loop through the host CAS substrate. The SC
 * consumes its reservation either way; a value mismatch skips the store.
 * Bounded retries: a live lock costs a trap, never a host hang. */
static bool cas_link(const sparc64_mem_ops_t *mem, void *mc, uint64_t va,
    unsigned size, bool little, uint64_t expect, uint64_t swap, uint64_t *old,
    sparc64_step_result_t *res, uint64_t pc)
{
    unsigned attempt;
    uint64_t be_expect = little ? swap_bytes(expect, size) : expect;
    uint64_t be_swap = little ? swap_bytes(swap, size) : swap;
    for (attempt = 0; attempt < 128U; attempt++) {
        sparc64_atomic_request_t req;
        sparc64_atomic_result_t lr;
        sparc64_atomic_result_t sc;
        sparc64_mem_fault_t fault;
        uint64_t cur;
        req.op = SPARC64_ATOMIC_LR;
        req.width = size;
        req.address = va;
        req.value = UINT64_C(0);
        req.aq = false;
        req.rl = false;
        req.reservation_valid = false;
        req.reservation.binding_id = UINT64_C(0);
        req.reservation.write_epoch = UINT64_C(0);
        fault.address = va;
        fault.reason = SPARC64_MEM_FAULT_NONE;
        lr.old_value = UINT64_C(0);
        lr.sc_success = false;
        lr.reservation.binding_id = UINT64_C(0);
        lr.reservation.write_epoch = UINT64_C(0);
        if (!mem->atomic(mc, &req, &lr, &fault)) {
            *res = sparc64_mem_trap(&fault, pc, false);
            return false;
        }
        cur = little ? swap_bytes(lr.old_value, size) : lr.old_value;
        *old = cur;
        if (cur != expect) {
            return true;
        }
        req.op = SPARC64_ATOMIC_SC;
        req.value = be_swap;
        req.reservation_valid = true;
        req.reservation = lr.reservation;
        fault.address = va;
        fault.reason = SPARC64_MEM_FAULT_NONE;
        sc.old_value = UINT64_C(0);
        sc.sc_success = false;
        sc.reservation.binding_id = UINT64_C(0);
        sc.reservation.write_epoch = UINT64_C(0);
        if (!mem->atomic(mc, &req, &sc, &fault)) {
            *res = sparc64_mem_trap(&fault, pc, true);
            return false;
        }
        if (sc.sc_success) {
            (void)be_expect;
            return true;
        }
    }
    *res = sparc64_trap(SPARC64_TRAP_STORE_ACCESS, pc, va);
    res->memory_reason = SPARC64_MEM_FAULT_RETRY;
    return false;
}

bool sparc64_cas(const sparc64_mem_ops_t *mem, void *mc, uint64_t va,
    unsigned size, bool little, uint64_t expect, uint64_t swap, uint64_t *old,
    sparc64_step_result_t *res, uint64_t pc)
{
    if (size != 4U && size != 8U) {
        *res = sparc64_trap(SPARC64_TRAP_LOAD_ACCESS, pc, va);
        res->memory_reason = SPARC64_MEM_FAULT_INTERNAL;
        return false;
    }
    if (mem == NULL) {
        *res = sparc64_trap(SPARC64_TRAP_LOAD_ACCESS, pc, va);
        res->memory_reason = SPARC64_MEM_FAULT_INTERNAL;
        return false;
    }
    if (mem->atomic != NULL) {
        return cas_link(mem, mc, va, size, little, expect, swap, old, res,
            pc);
    }
    return cas_fallback(mem, mc, va, size, little, expect, swap, old, res,
        pc);
}

/* Atomic exchange: host SWAP when available, else read/write pair. */
bool sparc64_fetch_word(const sparc64_mem_ops_t *mem, void *mc, uint64_t va,
    uint32_t *out, sparc64_step_result_t *res)
{
    uint8_t b[4];
    unsigned i;
    if ((va & UINT64_C(3)) != UINT64_C(0)) {
        *res = sparc64_trap(SPARC64_TRAP_INST_MISALIGNED, va, va);
        return false;
    }
    if (mem == NULL || mem->read == NULL) {
        *res = sparc64_trap(SPARC64_TRAP_INST_ACCESS, va, va);
        res->memory_reason = SPARC64_MEM_FAULT_INTERNAL;
        return false;
    }
    for (i = 0; i < 4U; i++) {
        sparc64_mem_fault_t fault;
        fault.address = va + (uint64_t)i;
        fault.reason = SPARC64_MEM_FAULT_NONE;
        if (!mem->read(mc, va + (uint64_t)i, &b[i], 1U,
                SPARC64_ACCESS_FETCH, &fault)) {
            *res = sparc64_mem_trap(&fault, va, false);
            if (res->kind == SPARC64_STEP_TRAP) {
                res->cause = SPARC64_TRAP_INST_ACCESS;
            }
            return false;
        }
    }
    *out = ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16) |
        ((uint32_t)b[2] << 8) | (uint32_t)b[3];
    return true;
}

bool sparc64_swap(const sparc64_mem_ops_t *mem, void *mc, uint64_t va,
    unsigned size, bool little, uint64_t swap, uint64_t *old,
    sparc64_step_result_t *res, uint64_t pc)
{
    if (size != 1U && size != 4U && size != 8U) {
        *res = sparc64_trap(SPARC64_TRAP_LOAD_ACCESS, pc, va);
        res->memory_reason = SPARC64_MEM_FAULT_INTERNAL;
        return false;
    }
    if (mem == NULL) {
        *res = sparc64_trap(SPARC64_TRAP_LOAD_ACCESS, pc, va);
        res->memory_reason = SPARC64_MEM_FAULT_INTERNAL;
        return false;
    }
    if (mem->atomic != NULL) {
        sparc64_atomic_request_t req;
        sparc64_atomic_result_t out;
        sparc64_mem_fault_t fault;
        req.op = SPARC64_ATOMIC_SWAP;
        req.width = size;
        req.address = va;
        req.value = little ? swap_bytes(swap, size) : swap;
        req.aq = false;
        req.rl = false;
        req.reservation_valid = false;
        req.reservation.binding_id = UINT64_C(0);
        req.reservation.write_epoch = UINT64_C(0);
        fault.address = va;
        fault.reason = SPARC64_MEM_FAULT_NONE;
        out.old_value = UINT64_C(0);
        out.sc_success = false;
        out.reservation.binding_id = UINT64_C(0);
        out.reservation.write_epoch = UINT64_C(0);
        if (!mem->atomic(mc, &req, &out, &fault)) {
            *res = sparc64_mem_trap(&fault, pc, false);
            return false;
        }
        *old = little ? swap_bytes(out.old_value, size) : out.old_value;
        return true;
    }
    if (!sparc64_ld_int(mem, mc, va, size, false, little, old, res, pc)) {
        return false;
    }
    return sparc64_st_int(mem, mc, va, size, little, swap, res, pc);
}

/* Alternate-space ASI check (E03). Immediate ASIs 0x80/0x82 are
 * big-endian, 0x88/0x8a little-endian (bit 3). ASIs below 0x80 trap
 * privileged (qemu trap 0x37); the i == 1 %asi-register form and unknown
 * supervisor ASIs fault like the oracle's missing helper. Shared with the
 * FPU kernel, which resolves regasi into d.asi before calling. */
bool sparc64_asi_check(uint64_t pc, const sparc64_dec_t *d, bool *little,
    sparc64_step_result_t *res)
{
    unsigned asi = d->asi;
    if (asi == 0xFFU) {
        *res = sparc64_trap(SPARC64_TRAP_LOAD_ACCESS, pc, d->raw);
        return false;
    }
    if (asi == SPARC64_ASI_P || asi == SPARC64_ASI_PNF) {
        *little = false;
        return true;
    }
    if (asi == SPARC64_ASI_PL || asi == SPARC64_ASI_PNFL) {
        *little = true;
        return true;
    }
    if (asi < 0x80U) {
        *res = sparc64_trap(SPARC64_TRAP_PRIVILEGED, pc, d->raw);
        return false;
    }
    *res = sparc64_trap(SPARC64_TRAP_LOAD_ACCESS, pc, d->raw);
    return false;
}

/* Effective address: rs1 plus the sign-extended immediate or rs2. */
static uint64_t eff_addr(const sparc64_cpu_t *cpu, const sparc64_dec_t *d)
{
    uint64_t a = sparc64_rreg(cpu, d->rs1);
    uint64_t b = (d->is_imm != 0U) ? (uint64_t)d->imm
                                   : sparc64_rreg(cpu, d->rs2);
    return a + b;
}

sparc64_step_result_t sparc64_exec_load(sparc64_cpu_t *cpu,
    const sparc64_mem_ops_t *mem, void *mc, uint64_t pc,
    const sparc64_dec_t *d)
{
    uint64_t va = eff_addr(cpu, d);
    bool little = false;
    bool alt = d->op3 >= SPARC64_OP3_LDA && d->op3 <= SPARC64_OP3_LDXA;
    uint64_t v = UINT64_C(0);
    sparc64_step_result_t res;
    if (alt && !sparc64_asi_check(pc, d, &little, &res)) {
        return res;
    }
    switch (d->op3) {
    case SPARC64_OP3_LDUW:
    case SPARC64_OP3_LDA:
        if (!sparc64_ld_int(mem, mc, va, 4U, false, little, &v, &res, pc)) {
            return res;
        }
        sparc64_wreg(cpu, d->rd, v);
        break;
    case SPARC64_OP3_LDUB:
    case SPARC64_OP3_LDUBA:
        if (!sparc64_ld_int(mem, mc, va, 1U, false, little, &v, &res, pc)) {
            return res;
        }
        sparc64_wreg(cpu, d->rd, v);
        break;
    case SPARC64_OP3_LDUH:
    case SPARC64_OP3_LDUHA:
        if (!sparc64_ld_int(mem, mc, va, 2U, false, little, &v, &res, pc)) {
            return res;
        }
        sparc64_wreg(cpu, d->rd, v);
        break;
    case SPARC64_OP3_LDD:
    case SPARC64_OP3_LDDA:
        if (!sparc64_ld_int(mem, mc, va, 4U, false, little, &v, &res, pc)) {
            return res;
        }
        sparc64_wreg(cpu, d->rd, v);
        if (!sparc64_ld_int(mem, mc, va + UINT64_C(4), 4U, false, little, &v,
                &res, pc)) {
            return res;
        }
        sparc64_wreg(cpu, d->rd + 1U, v);
        break;
    case SPARC64_OP3_LDSW:
    case SPARC64_OP3_LDSWA:
        if (!sparc64_ld_int(mem, mc, va, 4U, true, little, &v, &res, pc)) {
            return res;
        }
        sparc64_wreg(cpu, d->rd, v);
        break;
    case SPARC64_OP3_LDSB:
    case SPARC64_OP3_LDSBA:
        if (!sparc64_ld_int(mem, mc, va, 1U, true, little, &v, &res, pc)) {
            return res;
        }
        sparc64_wreg(cpu, d->rd, v);
        break;
    case SPARC64_OP3_LDSH:
    case SPARC64_OP3_LDSHA:
        if (!sparc64_ld_int(mem, mc, va, 2U, true, little, &v, &res, pc)) {
            return res;
        }
        sparc64_wreg(cpu, d->rd, v);
        break;
    case SPARC64_OP3_LDX:
    case SPARC64_OP3_LDXA:
        if (!sparc64_ld_int(mem, mc, va, 8U, false, little, &v, &res, pc)) {
            return res;
        }
        sparc64_wreg(cpu, d->rd, v);
        break;
    default: /* LDFSR (rd 0: low 32, upper zeroed) / LDXFSR (rd 1:
        * full 64-bit, oracle-probed). Either form re-syncs the fcc
        * shadow from the FSR fields. */
        if (d->rd == 1U) {
            if (!sparc64_ld_int(mem, mc, va, 8U, false, little, &v, &res,
                    pc)) {
                return res;
            }
            cpu->fsr = v;
        } else {
            if (!sparc64_ld_int(mem, mc, va, 4U, false, little, &v, &res,
                    pc)) {
                return res;
            }
            cpu->fsr = v & UINT64_C(0xFFFFFFFF);
        }
        cpu->fcc[0] = (uint32_t)((cpu->fsr >> 10) & UINT64_C(3));
        cpu->fcc[1] = (uint32_t)((cpu->fsr >> 32) & UINT64_C(3));
        cpu->fcc[2] = (uint32_t)((cpu->fsr >> 34) & UINT64_C(3));
        cpu->fcc[3] = (uint32_t)((cpu->fsr >> 36) & UINT64_C(3));
        break;
    }
    return sparc64_step_ok(pc);
}

sparc64_step_result_t sparc64_exec_store(sparc64_cpu_t *cpu,
    const sparc64_mem_ops_t *mem, void *mc, uint64_t pc,
    const sparc64_dec_t *d)
{
    uint64_t va = eff_addr(cpu, d);
    bool little = false;
    bool alt = d->op3 >= SPARC64_OP3_STA && d->op3 <= SPARC64_OP3_STXA;
    uint64_t v = sparc64_rreg(cpu, d->rd);
    sparc64_step_result_t res;
    if (alt && !sparc64_asi_check(pc, d, &little, &res)) {
        return res;
    }
    switch (d->op3) {
    case SPARC64_OP3_STW:
    case SPARC64_OP3_STA:
        if (!sparc64_st_int(mem, mc, va, 4U, little, v, &res, pc)) {
            return res;
        }
        break;
    case SPARC64_OP3_STB:
    case SPARC64_OP3_STBA:
        if (!sparc64_st_int(mem, mc, va, 1U, little, v, &res, pc)) {
            return res;
        }
        break;
    case SPARC64_OP3_STH:
    case SPARC64_OP3_STHA:
        if (!sparc64_st_int(mem, mc, va, 2U, little, v, &res, pc)) {
            return res;
        }
        break;
    case SPARC64_OP3_STD:
    case SPARC64_OP3_STDA: {
        uint64_t hi = sparc64_rreg(cpu, d->rd);
        uint64_t lo = sparc64_rreg(cpu, d->rd + 1U);
        if (!sparc64_st_int(mem, mc, va, 4U, little, hi, &res, pc)) {
            return res;
        }
        if (!sparc64_st_int(mem, mc, va + UINT64_C(4), 4U, little, lo, &res,
                pc)) {
            return res;
        }
        break;
    }
    case SPARC64_OP3_STX:
    case SPARC64_OP3_STXA:
        if (!sparc64_st_int(mem, mc, va, 8U, little, v, &res, pc)) {
            return res;
        }
        break;
    default: /* STFSR (rd 0: low 32) / STXFSR (rd 1: full 64-bit,
        * oracle-probed). */
        if (d->rd == 1U) {
            if (!sparc64_st_int(mem, mc, va, 8U, little, cpu->fsr, &res,
                    pc)) {
                return res;
            }
            break;
        }
        if (!sparc64_st_int(mem, mc, va, 4U, little,
                cpu->fsr & UINT64_C(0xFFFFFFFF), &res, pc)) {
            return res;
        }
        break;
    }
    return sparc64_step_ok(pc);
}

/* LDSTUB/SWAP/CASA/CASXA via the host-CAS substrate above. */
sparc64_step_result_t sparc64_exec_atomic(sparc64_cpu_t *cpu,
    const sparc64_mem_ops_t *mem, void *mc, uint64_t pc,
    const sparc64_dec_t *d)
{
    /* CASA/CASXA address R[rs1] directly (E03): the low field names the
     * compare register, so there is no rs2/simm offset form. LDSTUB and
     * SWAP address like ordinary loads (rs1 plus the offset operand). */
    uint64_t va = (d->op3 == SPARC64_OP3_CASA ||
            d->op3 == SPARC64_OP3_CASXA)
        ? sparc64_rreg(cpu, d->rs1)
        : eff_addr(cpu, d);
    bool little = false;
    bool alt = d->op3 == SPARC64_OP3_LDSTUBA || d->op3 == SPARC64_OP3_SWAPA ||
        d->op3 == SPARC64_OP3_CASA || d->op3 == SPARC64_OP3_CASXA;
    uint64_t old = UINT64_C(0);
    sparc64_step_result_t res;
    /* L4b: single-copy host-__atomic fast path on the shared mapping
     * first; anything it declines (unmapped, page-crossing, misaligned,
     * non-data ASI) falls through to the reservation path unchanged. */
    if (sparc64_threads_try_host_atomic(cpu, mc, pc, d, &res)) {
        return res;
    }
    if (alt && !sparc64_asi_check(pc, d, &little, &res)) {
        return res;
    }
    if (d->cls == (uint8_t)SPARC64_ICLS_LDSTUB) {
        if (!sparc64_swap(mem, mc, va, 1U, little, UINT64_C(0xFF), &old, &res,
                pc)) {
            return res;
        }
    } else if (d->cls == (uint8_t)SPARC64_ICLS_SWAP) {
        if (!sparc64_swap(mem, mc, va, 4U, little, sparc64_rreg(cpu, d->rd),
                &old, &res, pc)) {
            return res;
        }
    } else if (d->op3 == SPARC64_OP3_CASA) {
        if (!sparc64_cas(mem, mc, va, 4U, little, sparc64_rreg(cpu, d->rs2),
                sparc64_rreg(cpu, d->rd), &old, &res, pc)) {
            return res;
        }
    } else {
        if (!sparc64_cas(mem, mc, va, 8U, little, sparc64_rreg(cpu, d->rs2),
                sparc64_rreg(cpu, d->rd), &old, &res, pc)) {
            return res;
        }
    }
    sparc64_wreg(cpu, d->rd, old);
    return sparc64_step_ok(pc);
}
