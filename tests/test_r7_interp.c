/*
 * tests/test_r7_interp.c — Round-7 ISA interpreter regression tests.
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Host-side white-box tests, part 1: control flow, decode, integer
 * windows, loads/stores, FSR, ASI/no-fault, atomics (S64-R7-1,8-30).
 * Deterministic stdout; exit 0 with R7-INTERP-PASS iff all pass.
 *
 * Build with `make check-r7` from the worktree root.
 */

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "core/cpu.h"
#include "dbt/mem_sites.h"
#include "interp/interp.h"

/* Process-global Soft-TLB base (interp_win.c spill/fill fast path).
 * Zero tags never match the nonzero test VAs, so every access below
 * takes the callback slow path. */
sparc64_tlb_entry_t sparc64_dbt_tlb[SPARC64_TLB_SIZE]
    __attribute__((aligned(32)));

/* The host-atomic fast path is out of scope here: decline everything so
 * the generic CAS/SWAP substrates (the R7-10/27/28 fix sites) run. */
bool sparc64_threads_try_host_atomic(sparc64_cpu_t *cpu, void *mc,
    uint64_t pc, const sparc64_dec_t *d, sparc64_step_result_t *out)
{
    (void)cpu;
    (void)mc;
    (void)pc;
    (void)d;
    (void)out;
    return false;
}

/* ---- Flat test memory ------------------------------------------------
 * [0x00000, 0x20000): read/write. [0x20000, 0x21000): read-only.
 * [0x21000, 0x30000): read/write. [0x30000, 0x40000): unmapped. */
#define R7_MEM_SIZE UINT64_C(0x40000)
#define R7_RO_BASE UINT64_C(0x20000)
#define R7_RO_END UINT64_C(0x21000)
#define R7_UNMAP_BASE UINT64_C(0x30000)
#define R7_CODE UINT64_C(0x1000)
#define R7_DATA UINT64_C(0x2000)
#define R7_STACK UINT64_C(0x10000)

static uint8_t r7_mem[0x40000];
static unsigned long r7_writes;

static bool r7_in_range(uint64_t va, uint64_t n)
{
    return n <= R7_MEM_SIZE && va <= R7_MEM_SIZE - n;
}

static bool r7_read(void *ctx, uint64_t va, void *out, size_t n,
    sparc64_access_t acc, sparc64_mem_fault_t *fault)
{
    (void)ctx;
    (void)acc;
    fault->address = va;
    if (va >= R7_UNMAP_BASE) {
        fault->reason = SPARC64_MEM_FAULT_UNMAPPED;
        return false;
    }
    if (!r7_in_range(va, (uint64_t)n)) {
        fault->reason = SPARC64_MEM_FAULT_RANGE;
        return false;
    }
    memcpy(out, &r7_mem[va], n);
    fault->reason = SPARC64_MEM_FAULT_NONE;
    return true;
}

static bool r7_write(void *ctx, uint64_t va, const void *in, size_t n,
    sparc64_mem_fault_t *fault)
{
    (void)ctx;
    fault->address = va;
    if (va >= R7_UNMAP_BASE) {
        fault->reason = SPARC64_MEM_FAULT_UNMAPPED;
        return false;
    }
    if (!r7_in_range(va, (uint64_t)n)) {
        fault->reason = SPARC64_MEM_FAULT_RANGE;
        return false;
    }
    if (va < R7_RO_END && va + (uint64_t)n > R7_RO_BASE) {
        fault->reason = SPARC64_MEM_FAULT_PERMISSION;
        return false;
    }
    memcpy(&r7_mem[va], in, n);
    r7_writes += (unsigned long)n;
    fault->reason = SPARC64_MEM_FAULT_NONE;
    return true;
}

static uint64_t r7_get_be(uint64_t va, unsigned width)
{
    uint64_t v = UINT64_C(0);
    unsigned i;
    for (i = 0U; i < width; i++) {
        v = (v << 8) | (uint64_t)r7_mem[va + (uint64_t)i];
    }
    return v;
}

static void r7_put_be(uint64_t va, unsigned width, uint64_t v)
{
    unsigned i;
    for (i = 0U; i < width; i++) {
        r7_mem[va + (uint64_t)(width - 1U - i)] =
            (uint8_t)(v & UINT64_C(0xFF));
        v >>= 8;
    }
}

static bool r7_atomic(void *ctx, const sparc64_atomic_request_t *req,
    sparc64_atomic_result_t *res, sparc64_mem_fault_t *fault)
{
    unsigned width = req->width;
    uint64_t va = req->address;
    (void)ctx;
    fault->address = va;
    if (va >= R7_UNMAP_BASE || !r7_in_range(va, (uint64_t)width)) {
        fault->reason = (va >= R7_UNMAP_BASE) ?
            SPARC64_MEM_FAULT_UNMAPPED : SPARC64_MEM_FAULT_RANGE;
        return false;
    }
    if (req->op == SPARC64_ATOMIC_LR) {
        res->old_value = r7_get_be(va, width);
        res->sc_success = false;
        res->reservation.binding_id = UINT64_C(1);
        res->reservation.write_epoch = UINT64_C(0);
        fault->reason = SPARC64_MEM_FAULT_NONE;
        return true;
    }
    if (va < R7_RO_END && va + (uint64_t)width > R7_RO_BASE) {
        fault->reason = SPARC64_MEM_FAULT_PERMISSION;
        return false;
    }
    if (req->op == SPARC64_ATOMIC_SC) {
        if (!req->reservation_valid) {
            res->old_value = r7_get_be(va, width);
            res->sc_success = false;
            fault->reason = SPARC64_MEM_FAULT_NONE;
            return true;
        }
        r7_put_be(va, width, req->value);
        res->old_value = req->value;
        res->sc_success = true;
        fault->reason = SPARC64_MEM_FAULT_NONE;
        return true;
    }
    if (req->op == SPARC64_ATOMIC_SWAP) {
        res->old_value = r7_get_be(va, width);
        r7_put_be(va, width, req->value);
        res->sc_success = false;
        fault->reason = SPARC64_MEM_FAULT_NONE;
        return true;
    }
    fault->reason = SPARC64_MEM_FAULT_INTERNAL;
    return false;
}

static const sparc64_mem_ops_t r7_ops = { r7_read, r7_write, NULL };
static const sparc64_mem_ops_t r7_ops_link = { r7_read, r7_write, r7_atomic };

/* ---- Word builders (V9 format-3 field layout) ------------------------ */
static uint32_t r7_f3(unsigned op3, unsigned rd, unsigned rs1, unsigned ibit,
    uint32_t lo13)
{
    return 0x80000000U | ((rd & 31U) << 25) | ((op3 & 63U) << 19) |
        ((rs1 & 31U) << 14) | ((ibit & 1U) << 13) | (lo13 & 0x1FFFU);
}

static uint32_t r7_f3m(unsigned op3, unsigned rd, unsigned rs1, unsigned ibit,
    uint32_t lo13)
{
    return 0xC0000000U | ((rd & 31U) << 25) | ((op3 & 63U) << 19) |
        ((rs1 & 31U) << 14) | ((ibit & 1U) << 13) | (lo13 & 0x1FFFU);
}

static uint32_t r7_fpop(unsigned op3, unsigned rd, unsigned rs1f,
    unsigned opf, unsigned rs2f)
{
    return 0x80000000U | ((rd & 31U) << 25) | ((op3 & 63U) << 19) |
        ((rs1f & 31U) << 14) | ((opf & 511U) << 5) | (rs2f & 31U);
}

static void r7_poke32(uint64_t va, uint32_t w)
{
    r7_mem[va] = (uint8_t)(w >> 24);
    r7_mem[va + 1U] = (uint8_t)(w >> 16);
    r7_mem[va + 2U] = (uint8_t)(w >> 8);
    r7_mem[va + 3U] = (uint8_t)w;
}

static uint64_t r7_peek64(uint64_t va)
{
    return r7_get_be(va, 8U);
}

static uint32_t r7_peek32(uint64_t va)
{
    return (uint32_t)r7_get_be(va, 4U);
}

static sparc64_step_result_t r7_step(sparc64_cpu_t *cpu, uint64_t va,
    const sparc64_mem_ops_t *ops)
{
    cpu->pc = va;
    cpu->npc = va + 4U;
    return sparc64_step(cpu, ops, NULL);
}

/* ---- Check harness --------------------------------------------------- */
static int r7_checks;
static int r7_failures;

#define R7_CHECK(cond) do { \
    r7_checks++; \
    if (!(cond)) { \
        r7_failures++; \
        printf("FAIL %s:%d: %s\n", __func__, __LINE__, #cond); \
    } \
} while (0)

/* ---- Subtests -------------------------------------------------------- */

static void t_r7_12_sir(void)
{
    /* S64-R7-12: TADDcc-shaped SIR word decodes and runs as integer ALU. */
    sparc64_cpu_t cpu;
    sparc64_step_result_t res;
    sparc64_dec_t dd;
    uint32_t w = r7_f3(0x20U, 31U, 0U, 1U, 0U);
    memset(r7_mem, 0, sizeof(r7_mem));
    sparc64_classify_word(w, &dd);
    R7_CHECK(dd.cls == (uint8_t)SPARC64_ICLS_ALU);
    sparc64_cpu_init(&cpu, R7_CODE);
    r7_poke32(R7_CODE, w);
    r7_poke32(R7_CODE + 4U, 0x01000000U);
    res = r7_step(&cpu, R7_CODE, &r7_ops);
    R7_CHECK(res.kind == SPARC64_STEP_CONTINUE);
    R7_CHECK(cpu.r[23] == UINT64_C(0));
}

static void t_r7_16_fbfcc(void)
{
    /* S64-R7-16: legacy op2=6 FBfcc decodes onto FCC0 with disp22. */
    sparc64_cpu_t cpu;
    sparc64_step_result_t res;
    sparc64_dec_t dd;
    uint32_t w = (8U << 25) | (6U << 22) | 2U;
    memset(r7_mem, 0, sizeof(r7_mem));
    sparc64_classify_word(w, &dd);
    R7_CHECK(dd.cls == (uint8_t)SPARC64_ICLS_FBR);
    R7_CHECK(dd.cc == 0U);
    sparc64_cpu_init(&cpu, R7_CODE);
    r7_poke32(R7_CODE, w);
    r7_poke32(R7_CODE + 4U, 0x01000000U);
    r7_poke32(R7_CODE + 8U, 0x01000000U);
    res = r7_step(&cpu, R7_CODE, &r7_ops);
    R7_CHECK(res.kind == SPARC64_STEP_CONTINUE);
    R7_CHECK(cpu.pc == R7_CODE + 8U);
}

static void t_r7_1_nested(void)
{
    /* S64-R7-1: self-targeting adjacent branches keep dispatching;
     * bounded work per step, no host-stack growth. */
    sparc64_cpu_t cpu;
    unsigned i;
    memset(r7_mem, 0, sizeof(r7_mem));
    sparc64_cpu_init(&cpu, R7_CODE);
    r7_poke32(R7_CODE, 0x10800000U);
    r7_poke32(R7_CODE + 4U, 0x10800000U);
    for (i = 0U; i < 20000U; i++) {
        sparc64_step_result_t res = sparc64_step(&cpu, &r7_ops, NULL);
        if (res.kind != SPARC64_STEP_CONTINUE) {
            break;
        }
    }
    R7_CHECK(i == 20000U);
    R7_CHECK(cpu.pc == R7_CODE || cpu.pc == R7_CODE + 4U);
}

static void t_r7_11_tagged(void)
{
    /* S64-R7-11: tag sets icc.V only; TV traps on tag/32-bit overflow
     * only. 64-bit overflow sets xcc.V (V9 6.3.3.5) but must not trap. */
    sparc64_cpu_t cpu;
    sparc64_step_result_t res;
    memset(r7_mem, 0, sizeof(r7_mem));
    sparc64_cpu_init(&cpu, R7_CODE);
    cpu.r[8] = UINT64_C(0x7FFFFFFF00000000);
    cpu.r[9] = UINT64_C(0x100000000);
    r7_poke32(R7_CODE, r7_f3(0x22U, 1U, 8U, 0U, 9U));
    r7_poke32(R7_CODE + 4U, 0x01000000U);
    res = r7_step(&cpu, R7_CODE, &r7_ops);
    R7_CHECK(res.kind == SPARC64_STEP_CONTINUE);
    R7_CHECK(cpu.r[1] == UINT64_C(0x8000000000000000));
    R7_CHECK(cpu.ccr == UINT64_C(0xA4));
    /* TADDcc(1, 0): tag overflow sets icc.V only. */
    sparc64_cpu_init(&cpu, R7_CODE);
    cpu.r[8] = UINT64_C(1);
    cpu.r[9] = UINT64_C(0);
    r7_poke32(R7_CODE, r7_f3(0x20U, 1U, 8U, 0U, 9U));
    r7_poke32(R7_CODE + 4U, 0x01000000U);
    res = r7_step(&cpu, R7_CODE, &r7_ops);
    R7_CHECK(res.kind == SPARC64_STEP_CONTINUE);
    R7_CHECK(cpu.r[1] == UINT64_C(1));
    R7_CHECK(cpu.ccr == UINT64_C(0x02));
}

static void t_r7_13_div(void)
{
    /* S64-R7-13: UDIV saturates, SDIV sign-extends, cc nibbles split. */
    sparc64_cpu_t cpu;
    sparc64_step_result_t res;
    memset(r7_mem, 0, sizeof(r7_mem));
    sparc64_cpu_init(&cpu, R7_CODE);
    cpu.y = UINT64_C(1);
    cpu.r[8] = UINT64_C(0);
    r7_poke32(R7_CODE, r7_f3(0x0EU, 10U, 8U, 1U, 1U));
    r7_poke32(R7_CODE + 4U, 0x01000000U);
    res = r7_step(&cpu, R7_CODE, &r7_ops);
    R7_CHECK(res.kind == SPARC64_STEP_CONTINUE);
    R7_CHECK(cpu.r[10] == UINT64_C(0xFFFFFFFF));
    sparc64_cpu_init(&cpu, R7_CODE);
    cpu.y = UINT64_C(0xFFFFFFFF);
    cpu.r[8] = UINT64_C(0xFFFFFFFF);
    r7_poke32(R7_CODE, r7_f3(0x0FU, 10U, 8U, 1U, 1U));
    r7_poke32(R7_CODE + 4U, 0x01000000U);
    res = r7_step(&cpu, R7_CODE, &r7_ops);
    R7_CHECK(res.kind == SPARC64_STEP_CONTINUE);
    R7_CHECK(cpu.r[10] == UINT64_C(0xFFFFFFFFFFFFFFFF));
    /* UDIVCC overflow: icc.V set, xcc.V clear, result saturated. */
    sparc64_cpu_init(&cpu, R7_CODE);
    cpu.y = UINT64_C(1);
    cpu.r[8] = UINT64_C(0);
    r7_poke32(R7_CODE, r7_f3(0x1EU, 10U, 8U, 1U, 1U));
    r7_poke32(R7_CODE + 4U, 0x01000000U);
    res = r7_step(&cpu, R7_CODE, &r7_ops);
    R7_CHECK(res.kind == SPARC64_STEP_CONTINUE);
    R7_CHECK(cpu.r[10] == UINT64_C(0xFFFFFFFF));
    R7_CHECK(cpu.ccr == UINT64_C(0x0A));
    /* SDIVCC -1: sign-extended rd, per-nibble flags. */
    sparc64_cpu_init(&cpu, R7_CODE);
    cpu.y = UINT64_C(0xFFFFFFFF);
    cpu.r[8] = UINT64_C(0xFFFFFFFF);
    r7_poke32(R7_CODE, r7_f3(0x1FU, 10U, 8U, 1U, 1U));
    r7_poke32(R7_CODE + 4U, 0x01000000U);
    res = r7_step(&cpu, R7_CODE, &r7_ops);
    R7_CHECK(res.kind == SPARC64_STEP_CONTINUE);
    R7_CHECK(cpu.r[10] == UINT64_C(0xFFFFFFFFFFFFFFFF));
    R7_CHECK(cpu.ccr == UINT64_C(0x88));
}

static void t_r7_14_mulscc(void)
{
    /* S64-R7-14: shift-then-add order with old Y[0] as the add gate. */
    sparc64_cpu_t cpu;
    sparc64_step_result_t res;
    memset(r7_mem, 0, sizeof(r7_mem));
    sparc64_cpu_init(&cpu, R7_CODE);
    cpu.r[8] = UINT64_C(0);
    cpu.r[9] = UINT64_C(2);
    cpu.y = UINT64_C(1);
    cpu.ccr = UINT64_C(0);
    r7_poke32(R7_CODE, r7_f3(0x24U, 10U, 8U, 0U, 9U));
    r7_poke32(R7_CODE + 4U, 0x01000000U);
    res = r7_step(&cpu, R7_CODE, &r7_ops);
    R7_CHECK(res.kind == SPARC64_STEP_CONTINUE);
    R7_CHECK(cpu.r[10] == UINT64_C(2));
    R7_CHECK(cpu.y == UINT64_C(0));
}

static void t_r7_15_flushw(void)
{
    /* S64-R7-15: FLUSHW spills callers only; a second FLUSHW is quiet. */
    sparc64_cpu_t cpu;
    sparc64_step_result_t res;
    memset(r7_mem, 0, sizeof(r7_mem));
    sparc64_cpu_init(&cpu, R7_CODE);
    cpu.r[14] = R7_STACK;
    r7_poke32(R7_CODE, r7_f3(0x3CU, 14U, 14U, 1U, 0x1FA0U));
    r7_poke32(R7_CODE + 4U, r7_f3(0x3CU, 14U, 14U, 1U, 0x1FA0U));
    r7_poke32(R7_CODE + 8U, r7_f3(0x2BU, 0U, 0U, 0U, 0U));
    r7_poke32(R7_CODE + 12U, r7_f3(0x2BU, 0U, 0U, 0U, 0U));
    r7_poke32(R7_CODE + 16U, 0x01000000U);
    res = r7_step(&cpu, R7_CODE, &r7_ops);
    R7_CHECK(res.kind == SPARC64_STEP_CONTINUE);
    res = r7_step(&cpu, R7_CODE + 4U, &r7_ops);
    R7_CHECK(res.kind == SPARC64_STEP_CONTINUE);
    r7_writes = 0UL;
    res = r7_step(&cpu, R7_CODE + 8U, &r7_ops);
    R7_CHECK(res.kind == SPARC64_STEP_CONTINUE);
    R7_CHECK(r7_writes == 256UL);
    r7_writes = 0UL;
    res = r7_step(&cpu, R7_CODE + 12U, &r7_ops);
    R7_CHECK(res.kind == SPARC64_STEP_CONTINUE);
    R7_CHECK(r7_writes == 0UL);
}

static void t_r7_19_align(void)
{
    /* S64-R7-19: ALIGNADDRL reports the complement offset. */
    sparc64_cpu_t cpu;
    sparc64_step_result_t res;
    memset(r7_mem, 0, sizeof(r7_mem));
    sparc64_cpu_init(&cpu, R7_CODE);
    cpu.r[1] = UINT64_C(0x1000);
    cpu.r[2] = UINT64_C(1);
    r7_poke32(R7_CODE, 0x80000000U | (3U << 25) | (0x36U << 19) |
        (1U << 14) | (0x1AU << 5) | 2U);
    r7_poke32(R7_CODE + 4U, 0x01000000U);
    res = r7_step(&cpu, R7_CODE, &r7_ops);
    R7_CHECK(res.kind == SPARC64_STEP_CONTINUE);
    R7_CHECK((cpu.gsr & UINT64_C(7)) == UINT64_C(7));
    R7_CHECK(cpu.r[3] == UINT64_C(0x1000));
    /* ALIGNADDR keeps the direct offset. */
    sparc64_cpu_init(&cpu, R7_CODE);
    cpu.r[1] = UINT64_C(0x1000);
    cpu.r[2] = UINT64_C(1);
    r7_poke32(R7_CODE, 0x80000000U | (3U << 25) | (0x36U << 19) |
        (1U << 14) | (0x18U << 5) | 2U);
    r7_poke32(R7_CODE + 4U, 0x01000000U);
    res = r7_step(&cpu, R7_CODE, &r7_ops);
    R7_CHECK(res.kind == SPARC64_STEP_CONTINUE);
    R7_CHECK((cpu.gsr & UINT64_C(7)) == UINT64_C(1));
}

static void t_r7_20_tcc(void)
{
    /* S64-R7-20: trap number is (rs1 + simm7) & 0x7F. */
    sparc64_cpu_t cpu;
    sparc64_step_result_t res;
    memset(r7_mem, 0, sizeof(r7_mem));
    sparc64_cpu_init(&cpu, R7_CODE);
    cpu.r[2] = UINT64_C(0x60);
    r7_poke32(R7_CODE, r7_f3(0x3AU, 8U, 2U, 1U, 0x0DU));
    r7_poke32(R7_CODE + 4U, 0x01000000U);
    res = r7_step(&cpu, R7_CODE, &r7_ops);
    R7_CHECK(res.kind == SPARC64_STEP_SYSCALL);
    R7_CHECK(res.tval == UINT64_C(0x6D));
    /* A non-syscall trap number stays a generic trap. */
    sparc64_cpu_init(&cpu, R7_CODE);
    r7_poke32(R7_CODE, r7_f3(0x3AU, 8U, 0U, 1U, 0x70U));
    r7_poke32(R7_CODE + 4U, 0x01000000U);
    res = r7_step(&cpu, R7_CODE, &r7_ops);
    R7_CHECK(res.kind == SPARC64_STEP_TRAP);
    R7_CHECK(res.cause == SPARC64_TRAP_ILLEGAL);
}

static void t_r7_21_jmpl(void)
{
    /* S64-R7-21: misaligned JMPL target traps with SIGBUS mapping. */
    sparc64_cpu_t cpu;
    sparc64_step_result_t res;
    memset(r7_mem, 0, sizeof(r7_mem));
    sparc64_cpu_init(&cpu, R7_CODE);
    cpu.r[1] = UINT64_C(0x1000);
    r7_poke32(R7_CODE, r7_f3(0x38U, 0U, 1U, 1U, 1U));
    r7_poke32(R7_CODE + 4U, 0x01000000U);
    res = r7_step(&cpu, R7_CODE, &r7_ops);
    R7_CHECK(res.kind == SPARC64_STEP_TRAP);
    R7_CHECK(res.cause == SPARC64_TRAP_LOAD_MISALIGNED);
    R7_CHECK(res.tval == UINT64_C(0x1001));
}

static void t_r7_22_branch_zero(void)
{
    /* S64-R7-22: branch-to-zero with a faulting delay slot keeps npc=0. */
    sparc64_cpu_t cpu;
    sparc64_step_result_t res;
    memset(r7_mem, 0, sizeof(r7_mem));
    sparc64_cpu_init(&cpu, R7_CODE);
    r7_poke32(R7_CODE, 0x10BFFC00U);
    r7_poke32(R7_CODE + 4U, r7_f3m(0x00U, 1U, 0U, 1U, 5U));
    res = r7_step(&cpu, R7_CODE, &r7_ops);
    R7_CHECK(res.kind == SPARC64_STEP_TRAP);
    R7_CHECK(res.cause == SPARC64_TRAP_LOAD_MISALIGNED);
    R7_CHECK(cpu.pc == R7_CODE + 4U);
    R7_CHECK(cpu.npc == UINT64_C(0));
}

static void t_r7_23_casa_asi(void)
{
    /* S64-R7-23: %asi-form CASA reads the swap register from bits 4:0. */
    sparc64_cpu_t cpu;
    sparc64_step_result_t res;
    memset(r7_mem, 0, sizeof(r7_mem));
    sparc64_cpu_init(&cpu, R7_CODE);
    cpu.r[8] = R7_DATA;
    cpu.r[9] = UINT64_C(1);
    cpu.r[10] = UINT64_C(2);
    r7_poke32(R7_DATA, 0x00000001U);
    r7_poke32(R7_CODE, r7_f3(0x30U, 3U, 0U, 1U, 0x80U));
    r7_poke32(R7_CODE + 4U,
        0xC0000000U | (10U << 25) | (0x3CU << 19) | (8U << 14) |
            (1U << 13) | 9U);
    r7_poke32(R7_CODE + 8U, 0x01000000U);
    res = r7_step(&cpu, R7_CODE, &r7_ops);
    R7_CHECK(res.kind == SPARC64_STEP_CONTINUE);
    R7_CHECK(cpu.asi == 0x80U);
    res = r7_step(&cpu, R7_CODE + 4U, &r7_ops);
    R7_CHECK(res.kind == SPARC64_STEP_CONTINUE);
    R7_CHECK(r7_peek32(R7_DATA) == 0x00000002U);
    R7_CHECK(cpu.r[10] == UINT64_C(1));
}

static void t_r7_24_nofault(void)
{
    /* S64-R7-24: unmapped no-fault loads read zero; nofault stores trap. */
    sparc64_cpu_t cpu;
    sparc64_step_result_t res;
    memset(r7_mem, 0, sizeof(r7_mem));
    sparc64_cpu_init(&cpu, R7_CODE);
    cpu.r[1] = UINT64_C(0x30000);
    r7_poke32(R7_CODE, r7_f3m(0x10U, 2U, 0U, 0U, 0x1041U));
    r7_poke32(R7_CODE + 4U, 0x01000000U);
    res = r7_step(&cpu, R7_CODE, &r7_ops);
    R7_CHECK(res.kind == SPARC64_STEP_CONTINUE);
    R7_CHECK(cpu.r[2] == UINT64_C(0));
    /* A no-fault store to mapped memory still faults. */
    sparc64_cpu_init(&cpu, R7_CODE);
    cpu.r[1] = R7_DATA;
    cpu.r[2] = UINT64_C(0xDEADBEEF);
    r7_poke32(R7_DATA, 0x00000000U);
    r7_poke32(R7_CODE, r7_f3m(0x14U, 2U, 0U, 0U, 0x1041U));
    r7_poke32(R7_CODE + 4U, 0x01000000U);
    res = r7_step(&cpu, R7_CODE, &r7_ops);
    R7_CHECK(res.kind == SPARC64_STEP_TRAP);
    R7_CHECK(res.cause == SPARC64_TRAP_STORE_ACCESS);
    R7_CHECK(r7_peek32(R7_DATA) == 0x00000000U);
}

static void t_r7_25_ldd(void)
{
    /* S64-R7-25: misaligned LDD traps before publishing either half. */
    sparc64_cpu_t cpu;
    sparc64_step_result_t res;
    memset(r7_mem, 0, sizeof(r7_mem));
    sparc64_cpu_init(&cpu, R7_CODE);
    cpu.r[2] = UINT64_C(0xAA);
    cpu.r[3] = UINT64_C(0xBB);
    r7_poke32(R7_CODE, r7_f3m(0x03U, 2U, 0U, 1U, 4U));
    r7_poke32(R7_CODE + 4U, 0x01000000U);
    res = r7_step(&cpu, R7_CODE, &r7_ops);
    R7_CHECK(res.kind == SPARC64_STEP_TRAP);
    R7_CHECK(res.cause == SPARC64_TRAP_LOAD_MISALIGNED);
    R7_CHECK(cpu.r[2] == UINT64_C(0xAA));
    R7_CHECK(cpu.r[3] == UINT64_C(0xBB));
}

static void t_r7_26_lddf(void)
{
    /* S64-R7-26: word-aligned LDDF succeeds via staged 4-byte pieces. */
    sparc64_cpu_t cpu;
    sparc64_step_result_t res;
    memset(r7_mem, 0, sizeof(r7_mem));
    sparc64_cpu_init(&cpu, R7_CODE);
    cpu.r[1] = R7_DATA;
    cpu.fp.d[4] = UINT64_C(0xAAAAAAAAAAAAAAAA);
    r7_poke32(R7_DATA + 4U, 0x3FF00000U);
    r7_poke32(R7_DATA + 8U, 0x00000000U);
    r7_poke32(R7_CODE, r7_f3m(0x23U, 8U, 1U, 1U, 4U));
    r7_poke32(R7_CODE + 4U, 0x01000000U);
    res = r7_step(&cpu, R7_CODE, &r7_ops);
    R7_CHECK(res.kind == SPARC64_STEP_CONTINUE);
    R7_CHECK(cpu.fp.d[4] == UINT64_C(0x3FF0000000000000));
}

static void t_r7_27_cas_ro(void)
{
    /* S64-R7-27: CAS mismatch on a read-only page faults (both paths). */
    unsigned cfg;
    for (cfg = 0U; cfg < 2U; cfg++) {
        sparc64_cpu_t cpu;
        sparc64_step_result_t res;
        const sparc64_mem_ops_t *ops = (cfg == 0U) ? &r7_ops : &r7_ops_link;
        memset(r7_mem, 0, sizeof(r7_mem));
        sparc64_cpu_init(&cpu, R7_CODE);
        cpu.r[8] = UINT64_C(0x20000);
        cpu.r[9] = UINT64_C(2);
        cpu.r[10] = UINT64_C(0);
        r7_poke32(0x20000U, 0x00000001U);
        r7_poke32(R7_CODE, r7_f3m(0x3CU, 10U, 8U, 0U, 0x1009U));
        r7_poke32(R7_CODE + 4U, 0x01000000U);
        res = r7_step(&cpu, R7_CODE, ops);
        R7_CHECK(res.kind == SPARC64_STEP_TRAP);
        R7_CHECK(res.cause == SPARC64_TRAP_STORE_ACCESS);
        R7_CHECK(cpu.r[10] == UINT64_C(0));
    }
}

static void t_r7_28_casa32(void)
{
    /* S64-R7-28: CASA compares the low 32 bits only (both paths). */
    unsigned cfg;
    for (cfg = 0U; cfg < 2U; cfg++) {
        sparc64_cpu_t cpu;
        sparc64_step_result_t res;
        const sparc64_mem_ops_t *ops = (cfg == 0U) ? &r7_ops : &r7_ops_link;
        memset(r7_mem, 0, sizeof(r7_mem));
        sparc64_cpu_init(&cpu, R7_CODE);
        cpu.r[8] = R7_DATA;
        cpu.r[9] = UINT64_C(0x100000001);
        cpu.r[10] = UINT64_C(5);
        r7_poke32(R7_DATA, 0x00000001U);
        r7_poke32(R7_CODE, r7_f3m(0x3CU, 10U, 8U, 0U, 0x1009U));
        r7_poke32(R7_CODE + 4U, 0x01000000U);
        res = r7_step(&cpu, R7_CODE, ops);
        R7_CHECK(res.kind == SPARC64_STEP_CONTINUE);
        R7_CHECK(r7_peek32(R7_DATA) == 0x00000005U);
        R7_CHECK(cpu.r[10] == UINT64_C(1));
    }
}

static void t_r7_29_fsr(void)
{
    /* S64-R7-29: LDFSR validates rd, masks fields, preserves the rest. */
    sparc64_cpu_t cpu;
    sparc64_step_result_t res;
    memset(r7_mem, 0, sizeof(r7_mem));
    sparc64_cpu_init(&cpu, R7_CODE);
    cpu.r[1] = R7_DATA;
    r7_poke32(R7_CODE, r7_f3m(0x21U, 2U, 1U, 1U, 0U));
    r7_poke32(R7_CODE + 4U, 0x01000000U);
    res = r7_step(&cpu, R7_CODE, &r7_ops);
    R7_CHECK(res.kind == SPARC64_STEP_TRAP);
    R7_CHECK(res.cause == SPARC64_TRAP_ILLEGAL);
    /* Full-word load: read-only and upper fields preserved. */
    sparc64_cpu_init(&cpu, R7_CODE);
    cpu.r[1] = R7_DATA;
    cpu.fsr = UINT64_C(0x3F00000000);
    r7_poke32(R7_DATA, 0xFFFFFFFFU);
    r7_poke32(R7_CODE, r7_f3m(0x21U, 0U, 1U, 1U, 0U));
    r7_poke32(R7_CODE + 4U, 0x01000000U);
    res = r7_step(&cpu, R7_CODE, &r7_ops);
    R7_CHECK(res.kind == SPARC64_STEP_CONTINUE);
    R7_CHECK((cpu.fsr & UINT64_C(0xFFFFFFFF)) == UINT64_C(0xDF800FFF));
    R7_CHECK(((cpu.fsr >> 32) & UINT64_C(0xFFFFFFFF)) ==
        UINT64_C(0x3F));
    R7_CHECK(cpu.fcc[1] == 3U && cpu.fcc[2] == 3U && cpu.fcc[3] == 3U);
    /* STFSR observes the pre-clear FSR, then clears FTT. */
    sparc64_cpu_init(&cpu, R7_CODE);
    cpu.r[1] = R7_DATA + 8U;
    cpu.fsr = UINT64_C(0x1000);
    r7_poke32(R7_CODE, r7_f3m(0x25U, 0U, 1U, 1U, 0U));
    r7_poke32(R7_CODE + 4U, 0x01000000U);
    res = r7_step(&cpu, R7_CODE, &r7_ops);
    R7_CHECK(res.kind == SPARC64_STEP_CONTINUE);
    R7_CHECK(r7_peek32(R7_DATA + 8U) == 0x00001000U);
    R7_CHECK((cpu.fsr & UINT64_C(0x7000)) == UINT64_C(0));
}

static void t_r7_30_fprs(void)
{
    /* S64-R7-30: committed FP writes set FPRS dirty bits. */
    sparc64_cpu_t cpu;
    sparc64_step_result_t res;
    memset(r7_mem, 0, sizeof(r7_mem));
    sparc64_cpu_init(&cpu, R7_CODE);
    cpu.fprs = UINT64_C(4);
    cpu.fp.f[0] = UINT32_C(0x3F800000);
    cpu.fp.f[3] = UINT32_C(0);
    r7_poke32(R7_CODE, r7_fpop(0x34U, 2U, 0U, 0x01U, 1U));
    r7_poke32(R7_CODE + 4U, 0x01000000U);
    res = r7_step(&cpu, R7_CODE, &r7_ops);
    R7_CHECK(res.kind == SPARC64_STEP_CONTINUE);
    R7_CHECK(cpu.fp.f[3] == UINT32_C(0x3F800000));
    R7_CHECK(cpu.fprs == UINT64_C(5));
    /* Upper-bank double write sets DU. */
    sparc64_cpu_init(&cpu, R7_CODE);
    cpu.fprs = UINT64_C(4);
    cpu.fp.d[4] = UINT64_C(0x3FF0000000000000);
    r7_poke32(R7_CODE, r7_fpop(0x35U, 9U, 8U, 0x02U, 8U));
    r7_poke32(R7_CODE + 4U, 0x01000000U);
    res = r7_step(&cpu, R7_CODE, &r7_ops);
    R7_CHECK(res.kind == SPARC64_STEP_CONTINUE);
    R7_CHECK(cpu.fp.d[20] == UINT64_C(0x3FF0000000000000));
    R7_CHECK(cpu.fprs == UINT64_C(6));
}

static void t_r7_17_fmovr(void)
{
    /* S64-R7-17: register-conditioned FMOVR copies on %g0 == 0. */
    sparc64_cpu_t cpu;
    sparc64_step_result_t res;
    memset(r7_mem, 0, sizeof(r7_mem));
    sparc64_cpu_init(&cpu, R7_CODE);
    cpu.fp.f[0] = UINT32_C(0x3F800000);
    cpu.fp.f[3] = UINT32_C(0);
    r7_poke32(R7_CODE, r7_fpop(0x35U, 2U, 0U, 0x25U, 1U));
    r7_poke32(R7_CODE + 4U, 0x01000000U);
    res = r7_step(&cpu, R7_CODE, &r7_ops);
    R7_CHECK(res.kind == SPARC64_STEP_CONTINUE);
    R7_CHECK(cpu.fp.f[3] == UINT32_C(0x3F800000));
}

static void t_r7_18_fmovug(void)
{
    /* S64-R7-18: cond 5 (unordered-or-greater) follows the FCC table. */
    sparc64_cpu_t cpu;
    sparc64_step_result_t res;
    memset(r7_mem, 0, sizeof(r7_mem));
    sparc64_cpu_init(&cpu, R7_CODE);
    cpu.fcc[0] = 2U;
    cpu.fp.f[0] = UINT32_C(0x3F800000);
    cpu.fp.f[3] = UINT32_C(0);
    r7_poke32(R7_CODE, r7_fpop(0x35U, 2U, 5U, 0x01U, 1U));
    r7_poke32(R7_CODE + 4U, 0x01000000U);
    res = r7_step(&cpu, R7_CODE, &r7_ops);
    R7_CHECK(res.kind == SPARC64_STEP_CONTINUE);
    R7_CHECK(cpu.fp.f[3] == UINT32_C(0x3F800000));
    sparc64_cpu_init(&cpu, R7_CODE);
    cpu.fcc[0] = 0U;
    cpu.fp.f[0] = UINT32_C(0x3F800000);
    cpu.fp.f[3] = UINT32_C(0);
    r7_poke32(R7_CODE, r7_fpop(0x35U, 2U, 5U, 0x01U, 1U));
    r7_poke32(R7_CODE + 4U, 0x01000000U);
    res = r7_step(&cpu, R7_CODE, &r7_ops);
    R7_CHECK(res.kind == SPARC64_STEP_CONTINUE);
    R7_CHECK(cpu.fp.f[3] == UINT32_C(0));
}

static void t_r7_8_stqf(void)
{
    /* S64-R7-8: STQF stores both quad halves in order. */
    sparc64_cpu_t cpu;
    sparc64_step_result_t res;
    memset(r7_mem, 0, sizeof(r7_mem));
    sparc64_cpu_init(&cpu, R7_CODE);
    cpu.r[1] = R7_DATA;
    cpu.fp.d[4] = UINT64_C(0x1111111111111111);
    cpu.fp.d[5] = UINT64_C(0x2222222222222222);
    r7_poke32(R7_CODE, r7_f3m(0x26U, 8U, 1U, 1U, 0U));
    r7_poke32(R7_CODE + 4U, 0x01000000U);
    res = r7_step(&cpu, R7_CODE, &r7_ops);
    R7_CHECK(res.kind == SPARC64_STEP_CONTINUE);
    R7_CHECK(r7_peek64(R7_DATA) == UINT64_C(0x1111111111111111));
    R7_CHECK(r7_peek64(R7_DATA + 8U) == UINT64_C(0x2222222222222222));
}

static void t_r7_9_ldda(void)
{
    /* S64-R7-9: integer LDDA writes integer registers, not the FPU. */
    sparc64_cpu_t cpu;
    sparc64_step_result_t res;
    memset(r7_mem, 0, sizeof(r7_mem));
    sparc64_cpu_init(&cpu, R7_CODE);
    cpu.asi = 0x80U;
    cpu.r[1] = R7_DATA;
    cpu.fp.d[8] = UINT64_C(0xDEADBEEFDEADBEEF);
    r7_poke32(R7_DATA, 0xAABBCCDDU);
    r7_poke32(R7_DATA + 4U, 0x11223344U);
    r7_poke32(R7_CODE, r7_f3m(0x13U, 16U, 1U, 1U, 0U));
    r7_poke32(R7_CODE + 4U, 0x01000000U);
    res = r7_step(&cpu, R7_CODE, &r7_ops);
    R7_CHECK(res.kind == SPARC64_STEP_CONTINUE);
    R7_CHECK(cpu.r[16] == UINT64_C(0xAABBCCDD));
    R7_CHECK(cpu.r[17] == UINT64_C(0x11223344));
    R7_CHECK(cpu.fp.d[8] == UINT64_C(0xDEADBEEFDEADBEEF));
}

static void t_r7_10_misaligned_atomic(void)
{
    /* S64-R7-10: misaligned CASA/CASXA/SWAP trap LOAD_MISALIGNED. */
    sparc64_cpu_t cpu;
    sparc64_step_result_t res;
    memset(r7_mem, 0, sizeof(r7_mem));
    sparc64_cpu_init(&cpu, R7_CODE);
    cpu.r[8] = UINT64_C(0x20001);
    cpu.r[9] = UINT64_C(1);
    cpu.r[10] = UINT64_C(2);
    r7_poke32(R7_CODE, r7_f3m(0x3CU, 10U, 8U, 0U, 0x1009U));
    r7_poke32(R7_CODE + 4U, 0x01000000U);
    res = r7_step(&cpu, R7_CODE, &r7_ops);
    R7_CHECK(res.kind == SPARC64_STEP_TRAP);
    R7_CHECK(res.cause == SPARC64_TRAP_LOAD_MISALIGNED);
    R7_CHECK(res.tval == UINT64_C(0x20001));
    memset(r7_mem, 0, sizeof(r7_mem));
    sparc64_cpu_init(&cpu, R7_CODE);
    cpu.r[8] = UINT64_C(0x20004);
    cpu.r[9] = UINT64_C(1);
    cpu.r[10] = UINT64_C(2);
    r7_poke32(R7_CODE, r7_f3m(0x3EU, 10U, 8U, 0U, 0x1009U));
    r7_poke32(R7_CODE + 4U, 0x01000000U);
    res = r7_step(&cpu, R7_CODE, &r7_ops);
    R7_CHECK(res.kind == SPARC64_STEP_TRAP);
    R7_CHECK(res.cause == SPARC64_TRAP_LOAD_MISALIGNED);
    R7_CHECK(res.tval == UINT64_C(0x20004));
    memset(r7_mem, 0, sizeof(r7_mem));
    sparc64_cpu_init(&cpu, R7_CODE);
    cpu.r[8] = UINT64_C(0x20000);
    cpu.r[10] = UINT64_C(0xDEAD);
    r7_poke32(R7_CODE, r7_f3m(0x0FU, 10U, 8U, 1U, 1U));
    r7_poke32(R7_CODE + 4U, 0x01000000U);
    res = r7_step(&cpu, R7_CODE, &r7_ops);
    R7_CHECK(res.kind == SPARC64_STEP_TRAP);
    R7_CHECK(res.cause == SPARC64_TRAP_LOAD_MISALIGNED);
    R7_CHECK(res.tval == UINT64_C(0x20001));
}

int main(void)
{
    t_r7_1_nested();
    t_r7_8_stqf();
    t_r7_9_ldda();
    t_r7_11_tagged();
    t_r7_12_sir();
    t_r7_13_div();
    t_r7_14_mulscc();
    t_r7_15_flushw();
    t_r7_16_fbfcc();
    t_r7_17_fmovr();
    t_r7_18_fmovug();
    t_r7_19_align();
    t_r7_20_tcc();
    t_r7_21_jmpl();
    t_r7_22_branch_zero();
    t_r7_23_casa_asi();
    t_r7_24_nofault();
    t_r7_25_ldd();
    t_r7_26_lddf();
    t_r7_27_cas_ro();
    t_r7_28_casa32();
    t_r7_29_fsr();
    t_r7_30_fprs();
    t_r7_10_misaligned_atomic();
    printf("R7-INTERP: %d checks, %d failures\n", r7_checks, r7_failures);
    if (r7_failures == 0) {
        printf("R7-INTERP-PASS\n");
        return 0;
    }
    return 1;
}
