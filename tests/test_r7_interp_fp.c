/*
 * tests/test_r7_interp_fp.c — Round-7 FP regression tests.
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Host-side white-box tests for FP arithmetic, conversions, quad, and
 * CEXC (S64-R7-2..7, S64-R7-31..35). Deterministic stdout; exit 0
 * with R7-INTERP-FP-PASS iff every check passed.
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
    fault->reason = SPARC64_MEM_FAULT_NONE;
    return true;
}

static const sparc64_mem_ops_t r7_ops = { r7_read, r7_write, NULL };

/* ---- Word builders (V9 format-3 field layout) ------------------------ */
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

static void t_r7_35_cexc(void)
{
    /* S64-R7-35: a trapped overflow reports OF alone in CEXC. */
    sparc64_cpu_t cpu;
    sparc64_step_result_t res;
    memset(r7_mem, 0, sizeof(r7_mem));
    sparc64_cpu_init(&cpu, R7_CODE);
    cpu.fsr = UINT64_C(0x4000000);
    cpu.fp.f[0] = UINT32_C(0x7F7FFFFF);
    cpu.fp.f[3] = UINT32_C(0x7F7FFFFF);
    r7_poke32(R7_CODE, r7_fpop(0x34U, 4U, 1U, 0x41U, 2U));
    r7_poke32(R7_CODE + 4U, 0x01000000U);
    res = r7_step(&cpu, R7_CODE, &r7_ops);
    R7_CHECK(res.kind == SPARC64_STEP_TRAP);
    R7_CHECK((cpu.fsr & UINT64_C(0x1F)) == UINT64_C(0x08));
    R7_CHECK((cpu.fsr & UINT64_C(0x7000)) == UINT64_C(0x4000));
}

static void r7_set_rd(sparc64_cpu_t *cpu, uint32_t rd)
{
    /* LDFSR a rounding mode word; only RD survives the write mask. */
    cpu->r[1] = R7_DATA;
    r7_poke32(R7_DATA, rd << 30);
    r7_poke32(R7_CODE, r7_f3m(0x21U, 0U, 1U, 1U, 0U));
    r7_poke32(R7_CODE + 4U, 0x01000000U);
    (void)r7_step(cpu, R7_CODE, &r7_ops);
}

static void t_r7_3_directed(void)
{
    /* S64-R7-3: directed modes increment only with discarded bits. */
    sparc64_cpu_t cpu;
    sparc64_step_result_t res;
    memset(r7_mem, 0, sizeof(r7_mem));
    sparc64_cpu_init(&cpu, R7_CODE);
    r7_set_rd(&cpu, 2U);
    cpu.fp.f[0] = UINT32_C(0x3F800000);
    cpu.fp.f[3] = UINT32_C(0x33800000);
    r7_poke32(R7_CODE, r7_fpop(0x34U, 4U, 1U, 0x41U, 2U));
    r7_poke32(R7_CODE + 4U, 0x01000000U);
    res = r7_step(&cpu, R7_CODE, &r7_ops);
    R7_CHECK(res.kind == SPARC64_STEP_CONTINUE);
    R7_CHECK(cpu.fp.f[5] == UINT32_C(0x3F800001));
    R7_CHECK((cpu.fsr & UINT64_C(1)) == UINT64_C(1));
    sparc64_cpu_init(&cpu, R7_CODE);
    r7_set_rd(&cpu, 3U);
    cpu.fp.f[0] = UINT32_C(0x3F800000);
    cpu.fp.f[3] = UINT32_C(0x33800000);
    r7_poke32(R7_CODE, r7_fpop(0x34U, 4U, 1U, 0x41U, 2U));
    r7_poke32(R7_CODE + 4U, 0x01000000U);
    res = r7_step(&cpu, R7_CODE, &r7_ops);
    R7_CHECK(res.kind == SPARC64_STEP_CONTINUE);
    R7_CHECK(cpu.fp.f[5] == UINT32_C(0x3F800000));
    R7_CHECK((cpu.fsr & UINT64_C(1)) == UINT64_C(1));
    /* An exact sum never increments, even upward. */
    sparc64_cpu_init(&cpu, R7_CODE);
    r7_set_rd(&cpu, 2U);
    cpu.fp.f[0] = UINT32_C(0x3F800000);
    cpu.fp.f[3] = UINT32_C(0x3F800000);
    r7_poke32(R7_CODE, r7_fpop(0x34U, 4U, 1U, 0x41U, 2U));
    r7_poke32(R7_CODE + 4U, 0x01000000U);
    res = r7_step(&cpu, R7_CODE, &r7_ops);
    R7_CHECK(res.kind == SPARC64_STEP_CONTINUE);
    R7_CHECK(cpu.fp.f[5] == UINT32_C(0x40000000));
    R7_CHECK((cpu.fsr & UINT64_C(1)) == UINT64_C(0));
}

static void t_r7_4_cancellation(void)
{
    /* S64-R7-4: FSUBS(1, 1-2^-24) is exact 2^-24 with NX clear. */
    sparc64_cpu_t cpu;
    sparc64_step_result_t res;
    memset(r7_mem, 0, sizeof(r7_mem));
    sparc64_cpu_init(&cpu, R7_CODE);
    cpu.fp.f[0] = UINT32_C(0x3F800000);
    cpu.fp.f[3] = UINT32_C(0x3F7FFFFF);
    r7_poke32(R7_CODE, r7_fpop(0x34U, 6U, 1U, 0x45U, 2U));
    r7_poke32(R7_CODE + 4U, 0x01000000U);
    res = r7_step(&cpu, R7_CODE, &r7_ops);
    R7_CHECK(res.kind == SPARC64_STEP_CONTINUE);
    R7_CHECK(cpu.fp.f[7] == UINT32_C(0x33800000));
    R7_CHECK((cpu.fsr & UINT64_C(1)) == UINT64_C(0));
}

static void t_r7_7_fsmuld(void)
{
    /* S64-R7-7: widened single product is exact in double. */
    sparc64_cpu_t cpu;
    sparc64_step_result_t res;
    memset(r7_mem, 0, sizeof(r7_mem));
    sparc64_cpu_init(&cpu, R7_CODE);
    cpu.fp.f[0] = UINT32_C(0x3F800001);
    cpu.fp.f[3] = UINT32_C(0x3F800001);
    r7_poke32(R7_CODE, r7_fpop(0x34U, 4U, 1U, 0x69U, 2U));
    r7_poke32(R7_CODE + 4U, 0x01000000U);
    res = r7_step(&cpu, R7_CODE, &r7_ops);
    R7_CHECK(res.kind == SPARC64_STEP_CONTINUE);
    R7_CHECK(cpu.fp.d[2] == UINT64_C(0x3FF0000040000040));
    R7_CHECK((cpu.fsr & UINT64_C(1)) == UINT64_C(0));
}

static void t_r7_32_dtoi(void)
{
    /* S64-R7-32: -2147483648.5 truncates to INT32_MIN with NX alone. */
    sparc64_cpu_t cpu;
    sparc64_step_result_t res;
    memset(r7_mem, 0, sizeof(r7_mem));
    sparc64_cpu_init(&cpu, R7_CODE);
    cpu.fp.d[4] = UINT64_C(0xC1E0000000100000);
    r7_poke32(R7_CODE, r7_fpop(0x34U, 2U, 0U, 0x0D2U, 8U));
    r7_poke32(R7_CODE + 4U, 0x01000000U);
    res = r7_step(&cpu, R7_CODE, &r7_ops);
    R7_CHECK(res.kind == SPARC64_STEP_CONTINUE);
    R7_CHECK(cpu.fp.f[3] == UINT32_C(0x80000000));
    R7_CHECK((cpu.fsr & UINT64_C(0x1F)) == UINT64_C(0x01));
    /* Quad exact endpoint -2^31 converts cleanly. */
    sparc64_cpu_init(&cpu, R7_CODE);
    cpu.fp.d[4] = UINT64_C(0xC01E000000000000);
    cpu.fp.d[5] = UINT64_C(0);
    cpu.fp.f[3] = UINT32_C(0);
    r7_poke32(R7_CODE, r7_fpop(0x34U, 2U, 0U, 0x0D3U, 8U));
    r7_poke32(R7_CODE + 4U, 0x01000000U);
    res = r7_step(&cpu, R7_CODE, &r7_ops);
    R7_CHECK(res.kind == SPARC64_STEP_CONTINUE);
    R7_CHECK(cpu.fp.f[3] == UINT32_C(0x80000000));
    R7_CHECK((cpu.fsr & UINT64_C(0x1F)) == UINT64_C(0));
}

static void t_r7_6_fqtos(void)
{
    /* S64-R7-6: FQSTOS carries the sign into bit 31. */
    sparc64_cpu_t cpu;
    sparc64_step_result_t res;
    memset(r7_mem, 0, sizeof(r7_mem));
    sparc64_cpu_init(&cpu, R7_CODE);
    cpu.fp.d[4] = UINT64_C(0xBFFF000000000000);
    cpu.fp.d[5] = UINT64_C(0);
    cpu.fp.f[3] = UINT32_C(0);
    r7_poke32(R7_CODE, r7_fpop(0x34U, 2U, 0U, 0x0C7U, 8U));
    r7_poke32(R7_CODE + 4U, 0x01000000U);
    res = r7_step(&cpu, R7_CODE, &r7_ops);
    R7_CHECK(res.kind == SPARC64_STEP_CONTINUE);
    R7_CHECK(cpu.fp.f[3] == UINT32_C(0xBF800000));
}

static void t_r7_34_fdivq(void)
{
    /* S64-R7-34: inf/0 divides to infinity with no flags. */
    sparc64_cpu_t cpu;
    sparc64_step_result_t res;
    memset(r7_mem, 0, sizeof(r7_mem));
    sparc64_cpu_init(&cpu, R7_CODE);
    cpu.fp.d[6] = UINT64_C(0x7FFF000000000000);
    cpu.fp.d[7] = UINT64_C(0);
    cpu.fp.d[8] = UINT64_C(0);
    cpu.fp.d[9] = UINT64_C(0);
    cpu.fp.d[4] = UINT64_C(0xDEAD);
    cpu.fp.d[5] = UINT64_C(0xBEEF);
    r7_poke32(R7_CODE, r7_fpop(0x34U, 8U, 12U, 0x4FU, 16U));
    r7_poke32(R7_CODE + 4U, 0x01000000U);
    res = r7_step(&cpu, R7_CODE, &r7_ops);
    R7_CHECK(res.kind == SPARC64_STEP_CONTINUE);
    R7_CHECK(cpu.fp.d[4] == UINT64_C(0x7FFF000000000000));
    R7_CHECK(cpu.fp.d[5] == UINT64_C(0));
    R7_CHECK((cpu.fsr & UINT64_C(0x1F)) == UINT64_C(0));
}

static void t_r7_2_qnan_trap(void)
{
    /* S64-R7-2: a trapped quad invalid leaves the destination alone. */
    sparc64_cpu_t cpu;
    sparc64_step_result_t res;
    memset(r7_mem, 0, sizeof(r7_mem));
    sparc64_cpu_init(&cpu, R7_CODE);
    cpu.fsr = UINT64_C(0x8000000);
    cpu.fp.d[6] = UINT64_C(0);
    cpu.fp.d[7] = UINT64_C(0);
    cpu.fp.d[8] = UINT64_C(0);
    cpu.fp.d[9] = UINT64_C(0);
    cpu.fp.d[4] = UINT64_C(0xDEADBEEFDEADBEEF);
    cpu.fp.d[5] = UINT64_C(0x1234567812345678);
    r7_poke32(R7_CODE, r7_fpop(0x34U, 8U, 12U, 0x4FU, 16U));
    r7_poke32(R7_CODE + 4U, 0x01000000U);
    res = r7_step(&cpu, R7_CODE, &r7_ops);
    R7_CHECK(res.kind == SPARC64_STEP_TRAP);
    R7_CHECK((cpu.fsr & UINT64_C(0x1F)) == UINT64_C(0x10));
    R7_CHECK(cpu.fp.d[4] == UINT64_C(0xDEADBEEFDEADBEEF));
    R7_CHECK(cpu.fp.d[5] == UINT64_C(0x1234567812345678));
}

static void t_r7_33_qzero(void)
{
    /* S64-R7-33: same-sign quad zero sums preserve the sign. */
    sparc64_cpu_t cpu;
    sparc64_step_result_t res;
    memset(r7_mem, 0, sizeof(r7_mem));
    sparc64_cpu_init(&cpu, R7_CODE);
    cpu.fp.d[6] = UINT64_C(0);
    cpu.fp.d[7] = UINT64_C(0);
    cpu.fp.d[8] = UINT64_C(0x8000000000000000);
    cpu.fp.d[9] = UINT64_C(0);
    cpu.fp.d[4] = UINT64_C(1);
    cpu.fp.d[5] = UINT64_C(1);
    r7_poke32(R7_CODE, r7_fpop(0x34U, 8U, 12U, 0x43U, 16U));
    r7_poke32(R7_CODE + 4U, 0x01000000U);
    res = r7_step(&cpu, R7_CODE, &r7_ops);
    R7_CHECK(res.kind == SPARC64_STEP_CONTINUE);
    R7_CHECK(cpu.fp.d[4] == UINT64_C(0));
    R7_CHECK(cpu.fp.d[5] == UINT64_C(0));
    sparc64_cpu_init(&cpu, R7_CODE);
    cpu.fp.d[6] = UINT64_C(0x8000000000000000);
    cpu.fp.d[7] = UINT64_C(0);
    cpu.fp.d[8] = UINT64_C(0x8000000000000000);
    cpu.fp.d[9] = UINT64_C(0);
    r7_poke32(R7_CODE, r7_fpop(0x34U, 8U, 12U, 0x43U, 16U));
    r7_poke32(R7_CODE + 4U, 0x01000000U);
    res = r7_step(&cpu, R7_CODE, &r7_ops);
    R7_CHECK(res.kind == SPARC64_STEP_CONTINUE);
    R7_CHECK(cpu.fp.d[4] == UINT64_C(0x8000000000000000));
    R7_CHECK(cpu.fp.d[5] == UINT64_C(0));
}

static void t_r7_31_widen_subnormal(void)
{
    /* S64-R7-31: subnormal single/double widen exactly to quad. */
    sparc64_cpu_t cpu;
    sparc64_step_result_t res;
    memset(r7_mem, 0, sizeof(r7_mem));
    sparc64_cpu_init(&cpu, R7_CODE);
    cpu.fp.f[1] = UINT32_C(0x00000003);
    r7_poke32(R7_CODE, r7_fpop(0x34U, 8U, 0U, 0x0CDU, 0U));
    r7_poke32(R7_CODE + 4U, 0x01000000U);
    res = r7_step(&cpu, R7_CODE, &r7_ops);
    R7_CHECK(res.kind == SPARC64_STEP_CONTINUE);
    R7_CHECK(cpu.fp.d[4] == UINT64_C(0x3F6B800000000000));
    R7_CHECK(cpu.fp.d[5] == UINT64_C(0));
    R7_CHECK((cpu.fsr & UINT64_C(0x1F)) == UINT64_C(0));
    memset(r7_mem, 0, sizeof(r7_mem));
    sparc64_cpu_init(&cpu, R7_CODE);
    cpu.fp.d[0] = UINT64_C(3);
    r7_poke32(R7_CODE, r7_fpop(0x34U, 8U, 0U, 0x0CEU, 0U));
    r7_poke32(R7_CODE + 4U, 0x01000000U);
    res = r7_step(&cpu, R7_CODE, &r7_ops);
    R7_CHECK(res.kind == SPARC64_STEP_CONTINUE);
    R7_CHECK(cpu.fp.d[4] == UINT64_C(0x3BCE800000000000));
    R7_CHECK(cpu.fp.d[5] == UINT64_C(0));
    R7_CHECK((cpu.fsr & UINT64_C(0x1F)) == UINT64_C(0));
}

static void t_r7_5_qsub(void)
{
    /* S64-R7-5/31: quad subnormal identity round-trips carry no flags. */
    sparc64_cpu_t cpu;
    sparc64_step_result_t res;
    memset(r7_mem, 0, sizeof(r7_mem));
    sparc64_cpu_init(&cpu, R7_CODE);
    cpu.fp.d[4] = UINT64_C(0);
    cpu.fp.d[5] = UINT64_C(1);
    cpu.fp.d[6] = UINT64_C(0);
    cpu.fp.d[7] = UINT64_C(0);
    cpu.fp.d[8] = UINT64_C(0xDEAD);
    cpu.fp.d[9] = UINT64_C(0xBEEF);
    r7_poke32(R7_CODE, r7_fpop(0x34U, 16U, 8U, 0x43U, 12U));
    r7_poke32(R7_CODE + 4U, 0x01000000U);
    res = r7_step(&cpu, R7_CODE, &r7_ops);
    R7_CHECK(res.kind == SPARC64_STEP_CONTINUE);
    R7_CHECK(cpu.fp.d[8] == UINT64_C(0));
    R7_CHECK(cpu.fp.d[9] == UINT64_C(1));
    R7_CHECK((cpu.fsr & UINT64_C(0x1F)) == UINT64_C(0));
}

int main(void)
{
    t_r7_35_cexc();
    t_r7_3_directed();
    t_r7_4_cancellation();
    t_r7_7_fsmuld();
    t_r7_32_dtoi();
    t_r7_6_fqtos();
    t_r7_34_fdivq();
    t_r7_2_qnan_trap();
    t_r7_33_qzero();
    t_r7_5_qsub();
    t_r7_31_widen_subnormal();
    printf("R7-INTERP-FP: %d checks, %d failures\n", r7_checks, r7_failures);
    if (r7_failures == 0) {
        printf("R7-INTERP-FP-PASS\n");
        return 0;
    }
    return 1;
}
