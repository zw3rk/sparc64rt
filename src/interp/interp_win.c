/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Register-window file and integer execution backend (Phase 1, L1b):
 * 8-window SAVE/RESTORE rotation over the active view in sparc64_ctx_t
 * (E01 model widened to 64 bits) plus the single-instruction integer
 * data path (ALU with dual icc/xcc codes, shifts, MOVcc/MOVr, and the
 * user state registers).
 *
 * Fresh processes start with every window resident (E01: depth-1
 * save/restore is pure rotation, zero memory traffic), tracked by the V9
 * CANSAVE/CANRESTORE counters. Guest stack traffic happens only on window
 * overflow (SAVE with CANSAVE == 0 spills the reused window to the new
 * [%sp + 2047]) and underflow (RESTORE with CANRESTORE == 0 fills from the
 * caller [%sp + 2047]), 16 x 64-bit big-endian registers, 128 bytes.
 */

#include "interp/interp_win.h"

#include <string.h>

#include "dbt/mem_sites.h"

/* Window backing file: winfile[w][0..7] = %l, [8..15] = %i. Single global
 * file serves one guest thread (matches the Phase 1 single-threaded
 * interpreter; Phase 4 threads need a side table). */
static uint64_t interp_winfile[SPARC64_NWINDOWS][16];
/* Home stack pointer per window: interp_winsp[w] is the %sp of the frame
 * whose L/I image sits in interp_winfile[w] (0 when w was never stashed,
 * e.g. fresh windows at the depth-8 boundary). Maintained on every stash
 * and fill so spill, fill, and flush_all address the frame's own
 * [%sp + 2047] slot; Phase 4 fork must copy this beside winfile. */
static uint64_t interp_winsp[SPARC64_NWINDOWS];
/* Validity per window: win_valid[w] means winfile[w] holds the image of
 * an outstanding frame. SAVE validates the switched-out frame, RESTORE
 * invalidates its source, fills validate targets; spill/flush consult
 * validity, never the saturating cansave/canrestore counters. Phase 4
 * fork must copy this beside winfile. */
static bool win_valid[SPARC64_NWINDOWS];

/* Fresh-process init is lazy: sparc64_ctx_init() zeroes the counters, and
 * the first SAVE/RESTORE arms CANSAVE = NWINDOWS - 1. The pattern only
 * matches a truly fresh (or exactly balanced) window state, where arming
 * is harmless because every backing image is already consistent. */
static void win_lazy_init(sparc64_cpu_t *cpu)
{
    if (cpu->cansave == 0U && cpu->canrestore == 0U &&
        cpu->otherwin == 0U) {
        cpu->cansave = SPARC64_NWINDOWS - 1U;
        cpu->canrestore = 0U;
        cpu->cleanwin = 0U;
    }
}

/* Spill a 16-register (l/i) image big-endian to [va, va + 128). */
static bool win_spill_to(const sparc64_mem_ops_t *mem, void *mc,
    const uint64_t img[16], uint64_t va, sparc64_step_result_t *res,
    uint64_t pc)
{
    /* Lane P13-5 Soft-TLB fast path: a whole-window spill/fill stays
     * inside one 4 KiB page (128 bytes at [va, va + 128)), so a DBT
     * Soft-TLB hit serves it with memcpy + bswap per word,
     * byte-identical to the callback loop below. Misses fall through
     * to the slow path, so fault behavior is unchanged. No guest
     * alignment gate: stack-bias addresses are 7-mod-8 by
     * construction, and memcpy needs none. */
    if ((va & 0xFFFULL) <= (4096ULL - 128ULL)) {
        uint64_t idx = (va >> 12) & (uint64_t)(SPARC64_TLB_SIZE - 1u);
        const sparc64_tlb_entry_t *e = &sparc64_dbt_tlb[idx];
        if (e->write_tag == (va & ~(uint64_t)0xFFFULL)) {
            uint8_t *host =
                (uint8_t *)(e->addend + (uintptr_t)va);
            unsigned i;
            for (i = 0U; i < 16U; i++) {
                uint64_t be = __builtin_bswap64(img[i]);
                (void)memcpy(host + 8U * (uint64_t)i, &be, 8U);
            }
            return true;
        }
    }
    uint8_t buf[SPARC64_RWINDOW_SIZE];
    unsigned i;
    for (i = 0; i < 16U; i++) {
        uint64_t v = img[i];
        buf[8U * i] = (uint8_t)(v >> 56);
        buf[8U * i + 1U] = (uint8_t)(v >> 48);
        buf[8U * i + 2U] = (uint8_t)(v >> 40);
        buf[8U * i + 3U] = (uint8_t)(v >> 32);
        buf[8U * i + 4U] = (uint8_t)(v >> 24);
        buf[8U * i + 5U] = (uint8_t)(v >> 16);
        buf[8U * i + 6U] = (uint8_t)(v >> 8);
        buf[8U * i + 7U] = (uint8_t)v;
    }
    return sparc64_mem_write(mem, mc, va, buf, SPARC64_RWINDOW_SIZE, res,
        pc);
}

/* Fill winfile[w] from guest [va, va + 128). Outs are never filled: they
 * survive RESTORE in-register (E01). */
static bool win_fill_from(sparc64_cpu_t *cpu, const sparc64_mem_ops_t *mem,
    void *mc, unsigned w, uint64_t va, sparc64_step_result_t *res,
    uint64_t pc)
{
    /* Lane P13-5 Soft-TLB fast path (mirror of win_spill_to): a
     * single-page 128-byte fill served from a read-tagged TLB entry,
     * byte-identical to the callback loop below. */
    if ((va & 0xFFFULL) <= (4096ULL - 128ULL)) {
        uint64_t idx = (va >> 12) & (uint64_t)(SPARC64_TLB_SIZE - 1u);
        const sparc64_tlb_entry_t *e = &sparc64_dbt_tlb[idx];
        if (e->read_tag == (va & ~(uint64_t)0xFFFULL)) {
            const uint8_t *host =
                (const uint8_t *)(e->addend + (uintptr_t)va);
            unsigned j;
            for (j = 0U; j < 16U; j++) {
                uint64_t be;
                (void)memcpy(&be, host + 8U * (uint64_t)j, 8U);
                interp_winfile[w][j] = __builtin_bswap64(be);
            }
            return true;
        }
    }
    uint8_t buf[SPARC64_RWINDOW_SIZE];
    unsigned i;
    (void)cpu;
    if (!sparc64_mem_read(mem, mc, va, buf, SPARC64_RWINDOW_SIZE, res, pc)) {
        return false;
    }
    for (i = 0; i < 16U; i++) {
        interp_winfile[w][i] = ((uint64_t)buf[8U * i] << 56) |
            ((uint64_t)buf[8U * i + 1U] << 48) |
            ((uint64_t)buf[8U * i + 2U] << 40) |
            ((uint64_t)buf[8U * i + 3U] << 32) |
            ((uint64_t)buf[8U * i + 4U] << 24) |
            ((uint64_t)buf[8U * i + 5U] << 16) |
            ((uint64_t)buf[8U * i + 6U] << 8) |
            (uint64_t)buf[8U * i + 7U];
    }
    return true;
}

bool sparc64_win_save(sparc64_cpu_t *cpu, const sparc64_mem_ops_t *mem,
    void *mc, uint64_t sum, unsigned rd, sparc64_step_result_t *res,
    uint64_t pc)
{
    unsigned tgt;
    unsigned i;
    uint64_t old_o[8];
    win_lazy_init(cpu);
    tgt = (cpu->cwp + SPARC64_NWINDOWS - 1U) % SPARC64_NWINDOWS;
    if (win_valid[tgt]) {
        /* Reuse of a window holding an outstanding frame: preserve it in
         * its own home slot first (valid implies outstanding, and the
         * recorded home equals the later fill's post_sp slot). An
         * invalid tgt holds nothing needed (fresh or dead image): reuse
         * it directly, no memory traffic. */
        if (!win_spill_to(mem, mc, interp_winfile[tgt],
                interp_winsp[tgt] + SPARC64_STACK_BIAS, res, pc)) {
            return false;
        }
    }
    if (cpu->cansave == 0U) {
        cpu->cansave = 1U;
    }
    for (i = 0; i < 8U; i++) {
        old_o[i] = sparc64_rreg(cpu, SPARC64_O0 + i);
    }
    for (i = 0; i < 8U; i++) {
        interp_winfile[cpu->cwp][i] = sparc64_rreg(cpu, SPARC64_L0 + i);
        interp_winfile[cpu->cwp][8U + i] =
            sparc64_rreg(cpu, SPARC64_I0 + i);
    }
    interp_winsp[cpu->cwp] = sparc64_rreg(cpu, SPARC64_SP);
    win_valid[cpu->cwp] = true;
    for (i = 0; i < 8U; i++) {
        sparc64_wreg(cpu, SPARC64_I0 + i, old_o[i]);
        sparc64_wreg(cpu, SPARC64_L0 + i, interp_winfile[tgt][i]);
    }
    cpu->cwp = tgt;
    cpu->cansave--;
    if (cpu->canrestore < SPARC64_NWINDOWS - 1U) {
        cpu->canrestore++;
    }
    sparc64_wreg(cpu, rd, sum);
    return true;
}

bool sparc64_win_restore(sparc64_cpu_t *cpu, const sparc64_mem_ops_t *mem,
    void *mc, uint64_t sum, unsigned rd, sparc64_step_result_t *res,
    uint64_t pc)
{
    unsigned tgt;
    unsigned i;
    uint64_t old_i[8];
    uint64_t post_sp;
    win_lazy_init(cpu);
    tgt = (cpu->cwp + 1U) % SPARC64_NWINDOWS;
    for (i = 0; i < 8U; i++) {
        old_i[i] = sparc64_rreg(cpu, SPARC64_I0 + i);
    }
    post_sp = old_i[6];
    for (i = 0; i < 8U; i++) {
        interp_winfile[cpu->cwp][i] = sparc64_rreg(cpu, SPARC64_L0 + i);
        interp_winfile[cpu->cwp][8U + i] =
            sparc64_rreg(cpu, SPARC64_I0 + i);
    }
    interp_winsp[cpu->cwp] = sparc64_rreg(cpu, SPARC64_SP);
    /* The switched-out frame dies with this pop: its window copy must not
     * be mistaken for an outstanding image by a later reuse or flush. */
    win_valid[cpu->cwp] = false;
    if (!win_valid[tgt]) {
        /* The target holds nothing usable (fresh, evicted, or longjmp-
         * invalidated): refill it from its home slot. */
        if (!win_fill_from(cpu, mem, mc, tgt, post_sp + SPARC64_STACK_BIAS,
                res, pc)) {
            return false;
        }
        interp_winsp[tgt] = post_sp;
        win_valid[tgt] = true;
        if (cpu->canrestore == 0U) {
            cpu->canrestore = 1U;
        }
    }
    for (i = 0; i < 8U; i++) {
        sparc64_wreg(cpu, SPARC64_O0 + i, old_i[i]);
        sparc64_wreg(cpu, SPARC64_L0 + i, interp_winfile[tgt][i]);
        sparc64_wreg(cpu, SPARC64_I0 + i, interp_winfile[tgt][8U + i]);
    }
    cpu->cwp = tgt;
    cpu->canrestore--;
    if (cpu->cansave < SPARC64_NWINDOWS - 1U) {
        cpu->cansave++;
    }
    sparc64_wreg(cpu, rd, sum);
    return true;
}

/* Flush every outstanding window image to its architectural home: the
 * live window from live registers, each stashed window from winfile to
 * its recorded [winsp + 2047] slot. After a flush, stack and winfile
 * agree, so later underflow fills are idempotent. Used by the setjmp
 * trap (ta 0x6e) before snapshotting; the matching longjmp unwinds
 * through win_restore, rebuilding winfile from these same slots. */
bool sparc64_win_flush_all(sparc64_cpu_t *cpu, const sparc64_mem_ops_t *mem,
    void *mc, sparc64_step_result_t *res, uint64_t pc)
{
    unsigned w;
    unsigned i;
    uint64_t live[16];
    for (i = 0U; i < 8U; i++) {
        live[i] = sparc64_rreg(cpu, SPARC64_L0 + i);
        live[8U + i] = sparc64_rreg(cpu, SPARC64_I0 + i);
    }
    if (!win_spill_to(mem, mc, live,
            sparc64_rreg(cpu, SPARC64_SP) + SPARC64_STACK_BIAS, res,
            pc)) {
        return false;
    }
    for (w = 0U; w < SPARC64_NWINDOWS; w++) {
        /* Only outstanding (valid) images are written back: dead images'
         * home slots are live stack space now, and touching them would
         * clobber descendant frames. */
        if (w == cpu->cwp || !win_valid[w]) {
            continue;
        }
        if (!win_spill_to(mem, mc, interp_winfile[w],
                interp_winsp[w] + SPARC64_STACK_BIAS, res, pc)) {
            return false;
        }
        win_valid[w] = false;
    }
    return true;
}

/* Drop every cached image (longjmp trap): the handler frames clobbered
 * winfile, so the subsequent unwind refills each reactivated window from
 * its flushed home slot instead of trusting the cache. */
void sparc64_win_invalidate_all(void)
{
    unsigned w;
    for (w = 0U; w < SPARC64_NWINDOWS; w++) {
        win_valid[w] = false;
    }
}

/* ---- Architectural condition codes (E02 + RC1 probes) --------------------
 * V9 integer ops set icc from the low 32 bits and xcc from the full 64
 * bits (E02 FINDINGS: addcc(0xffffffff,1) -> ccr 0x05; addcc(-1,1) ->
 * 0x55; subcc(0,1) -> 0x99). Plain Bicc/BPcc test icc, Bcc %xcc tests
 * xcc (micro-probes t2/t6: cmp(0x100000002,0x2) is Z=1 under plain be
 * because low32 halves are equal, and N=0/C=0 likewise from low32).
 * SLL/SRL (x=0) shift only low32 and zero-extend (V9 A.48, E02/E04,
 * P1 oracle), while SRA (x=0) sign-extends bit 31. */

/* Logic ops clear V/C; N/Z come from bit 31/low32-zero (icc) and bit 63 /
 * full-zero (xcc). */
static void cc_logic(sparc64_ctx_t *ctx, uint64_t res)
{
    unsigned icc = 0U;
    unsigned xcc = 0U;
    if ((res & UINT64_C(0x80000000)) != UINT64_C(0)) {
        icc |= 8U;
    }
    if ((uint32_t)res == 0U) {
        icc |= 4U;
    }
    if ((res & (UINT64_C(1) << 63)) != UINT64_C(0)) {
        xcc |= 8U;
    }
    if (res == UINT64_C(0)) {
        xcc |= 4U;
    }
    sparc64_cc_set(ctx, icc, xcc);
}

/* Width-parameterized add/sub with carry/borrow in (0/1): N/Z/V/C for one
 * nibble. Carry/borrow chain through unsigned comparisons and signed
 * overflow uses the unsigned identities, so no signed overflow occurs.
 * SUB carry is the borrow (E02: C=1 iff a < b + bin). */
static unsigned cc_add(unsigned width, uint64_t a, uint64_t b, unsigned cin,
    uint64_t *res)
{
    uint64_t mask = (width == 64U) ? ~(UINT64_C(0)) : UINT64_C(0xFFFFFFFF);
    uint64_t ua = a & mask;
    uint64_t ub = b & mask;
    uint64_t sum = ua + ub;
    uint64_t r = sum + (cin != 0U ? UINT64_C(1) : UINT64_C(0));
    uint64_t vs = (~(ua ^ ub)) & (r ^ ua);
    unsigned v = (unsigned)((vs >> (width - 1U)) & UINT64_C(1));
    unsigned c = (((sum < ua) || ((cin != 0U) && (r < sum)) ||
        ((r & ~mask) != UINT64_C(0))) ? 1U : 0U);
    unsigned nz = 0U;
    *res = r & mask;
    if (((r >> (width - 1U)) & UINT64_C(1)) != UINT64_C(0)) {
        nz |= 8U;
    }
    if ((r & mask) == UINT64_C(0)) {
        nz |= 4U;
    }
    if (v != 0U) {
        nz |= 2U;
    }
    if (c != 0U) {
        nz |= 1U;
    }
    return nz;
}

static unsigned cc_sub(unsigned width, uint64_t a, uint64_t b, unsigned bin,
    uint64_t *res)
{
    uint64_t mask = (width == 64U) ? ~(UINT64_C(0)) : UINT64_C(0xFFFFFFFF);
    uint64_t ua = a & mask;
    uint64_t ub = b & mask;
    uint64_t t = ua - ub;
    unsigned b1 = (t > ua) ? 1U : 0U;
    uint64_t r = t - (bin != 0U ? UINT64_C(1) : UINT64_C(0));
    unsigned b2 = ((bin != 0U) && (r > t)) ? 1U : 0U;
    uint64_t vs = (ua ^ ub) & (ua ^ (r & mask));
    unsigned v = (unsigned)((vs >> (width - 1U)) & UINT64_C(1));
    unsigned nz = 0U;
    *res = r & mask;
    if (((r >> (width - 1U)) & UINT64_C(1)) != UINT64_C(0)) {
        nz |= 8U;
    }
    if ((r & mask) == UINT64_C(0)) {
        nz |= 4U;
    }
    if (v != 0U) {
        nz |= 2U;
    }
    if ((b1 | b2) != 0U) {
        nz |= 1U;
    }
    return nz;
}

/* MULcc shared tail (oracle probes vs qemu-sparc64, coordinator
 * ruling on the H3 V-on-overflow open item): 32-bit operands, so the
 * 64-bit product always fits — V (64-bit overflow) never sets, and
 * the oracle reports V=0 on every probe including 41-bit products.
 * rd keeps the full product; Y the high 32 bits (product<63:32>);
 * icc N/Z from the low 32 bits, xcc N/Z from the full 64 bits; C 0. */
static void mulcc_tail(sparc64_ctx_t *ctx, unsigned rd, uint32_t lo,
    uint64_t prod)
{
    unsigned icc = 0U;
    unsigned xcc = 0U;
    if ((lo & UINT32_C(0x80000000)) != UINT32_C(0)) {
        icc |= 8U;
    }
    if (lo == 0U) {
        icc |= 4U;
    }
    if ((prod & UINT64_C(0x8000000000000000)) != UINT64_C(0)) {
        xcc |= 8U;
    }
    if (prod == UINT64_C(0)) {
        xcc |= 4U;
    }
    ctx->y = (uint32_t)(prod >> 32);
    sparc64_cc_set(ctx, icc, xcc);
    sparc64_wreg(ctx, rd, prod);
}

/* 64-bit population count. */
static uint64_t popcount64(uint64_t v)
{
    uint64_t n = UINT64_C(0);
    while (v != UINT64_C(0)) {
        n += v & UINT64_C(1);
        v >>= 1;
    }
    return n;
}

/* Integer ALU (op3 dispatch). Architectural cc: icc from low32, xcc from
 * full64 (see note above cc_logic). ADDX/SUBX carry in from icc.C
 * (oracle-verified). Integer divide by zero traps; 64-bit SDIVX overflow
 * saturates to INT64_MIN (oracle-verified). */
sparc64_step_result_t sparc64_exec_alu(sparc64_cpu_t *cpu, uint64_t pc,
    const sparc64_dec_t *d)
{
    uint64_t a = sparc64_rreg(cpu, d->rs1);
    uint64_t b = (d->is_imm != 0U) ? (uint64_t)d->imm
                                   : sparc64_rreg(cpu, d->rs2);
    uint64_t res = UINT64_C(0);
    uint32_t r32 = 0U;
    unsigned icc = 0U;
    unsigned xcc = 0U;
    unsigned cin;
    switch (d->op3) {
    case SPARC64_OP3_ADD:
        sparc64_wreg(cpu, d->rd, a + b);
        return sparc64_step_ok(pc);
    case SPARC64_OP3_AND:
        sparc64_wreg(cpu, d->rd, a & b);
        return sparc64_step_ok(pc);
    case SPARC64_OP3_OR:
        sparc64_wreg(cpu, d->rd, a | b);
        return sparc64_step_ok(pc);
    case SPARC64_OP3_XOR:
        sparc64_wreg(cpu, d->rd, a ^ b);
        return sparc64_step_ok(pc);
    case SPARC64_OP3_SUB:
        sparc64_wreg(cpu, d->rd, a - b);
        return sparc64_step_ok(pc);
    case SPARC64_OP3_ANDN:
        sparc64_wreg(cpu, d->rd, a & ~b);
        return sparc64_step_ok(pc);
    case SPARC64_OP3_ORN:
        sparc64_wreg(cpu, d->rd, a | ~b);
        return sparc64_step_ok(pc);
    case SPARC64_OP3_XORN:
        sparc64_wreg(cpu, d->rd, a ^ ~b);
        return sparc64_step_ok(pc);
    case SPARC64_OP3_ADDX:
        cin = sparc64_cc_icc(cpu) & 1U;
        sparc64_wreg(cpu, d->rd, a + b + (uint64_t)cin);
        return sparc64_step_ok(pc);
    case SPARC64_OP3_SUBX:
        cin = sparc64_cc_icc(cpu) & 1U;
        sparc64_wreg(cpu, d->rd, a - b - (uint64_t)cin);
        return sparc64_step_ok(pc);
    case SPARC64_OP3_MULX:
        sparc64_wreg(cpu, d->rd, a * b);
        return sparc64_step_ok(pc);
    case SPARC64_OP3_UMUL: {
        /* Oracle parity (H3): rd keeps the full 64-bit product; GCC's
         * strength-reduced division reads the high half out of rd. */
        uint64_t p = (uint64_t)(uint32_t)a * (uint64_t)(uint32_t)b;
        cpu->y = (uint32_t)(p >> 32);
        sparc64_wreg(cpu, d->rd, p);
        return sparc64_step_ok(pc);
    }
    case SPARC64_OP3_SMUL: {
        /* Oracle parity (H3): rd keeps the full 64-bit product. */
        int64_t p = (int64_t)(int32_t)(uint32_t)a *
            (int64_t)(int32_t)(uint32_t)b;
        cpu->y = (uint32_t)((uint64_t)p >> 32);
        sparc64_wreg(cpu, d->rd, (uint64_t)p);
        return sparc64_step_ok(pc);
    }
    case SPARC64_OP3_SDIVX: {
        int64_t dvd = (int64_t)a;
        int64_t dvs = (int64_t)b;
        if (dvs == 0) {
            return sparc64_trap(SPARC64_TRAP_ILLEGAL, pc, d->raw);
        }
        if (dvd == INT64_MIN && dvs == -1) {
            sparc64_wreg(cpu, d->rd, (uint64_t)INT64_MIN);
            return sparc64_step_ok(pc);
        }
        sparc64_wreg(cpu, d->rd, (uint64_t)(dvd / dvs));
        return sparc64_step_ok(pc);
    }
    case SPARC64_OP3_UDIVX:
        if (b == UINT64_C(0)) {
            return sparc64_trap(SPARC64_TRAP_ILLEGAL, pc, d->raw);
        }
        sparc64_wreg(cpu, d->rd, a / b);
        return sparc64_step_ok(pc);
    case SPARC64_OP3_SDIV: {
        int64_t dvd = ((int64_t)(int32_t)(uint32_t)cpu->y << 32) |
            (int64_t)(uint32_t)a;
        int32_t dvs = (int32_t)(uint32_t)b;
        if (dvs == 0) {
            return sparc64_trap(SPARC64_TRAP_ILLEGAL, pc, d->raw);
        }
        if (dvd == INT64_MIN && dvs == -1) {
            sparc64_wreg(cpu, d->rd, (uint64_t)(uint32_t)0x80000000U);
            return sparc64_step_ok(pc);
        }
        sparc64_wreg(cpu, d->rd,
            (uint64_t)(uint32_t)(uint64_t)(dvd / (int64_t)dvs));
        return sparc64_step_ok(pc);
    }
    case SPARC64_OP3_UDIV: {
        uint64_t dvd = ((uint64_t)(uint32_t)cpu->y << 32) |
            (uint64_t)(uint32_t)a;
        uint32_t dvs = (uint32_t)b;
        if (dvs == 0U) {
            return sparc64_trap(SPARC64_TRAP_ILLEGAL, pc, d->raw);
        }
        sparc64_wreg(cpu, d->rd, (uint64_t)(uint32_t)(dvd / (uint64_t)dvs));
        return sparc64_step_ok(pc);
    }
    case SPARC64_OP3_POPC:
        sparc64_wreg(cpu, d->rd, popcount64(b));
        return sparc64_step_ok(pc);
    case SPARC64_OP3_ADDCC:
        icc = cc_add(32U, a, b, 0U, &res);
        xcc = cc_add(64U, a, b, 0U, &res);
        sparc64_cc_set(cpu, icc, xcc);
        sparc64_wreg(cpu, d->rd, res);
        return sparc64_step_ok(pc);
    case SPARC64_OP3_ANDCC:
        cc_logic(cpu, a & b);
        sparc64_wreg(cpu, d->rd, a & b);
        return sparc64_step_ok(pc);
    case SPARC64_OP3_ORCC:
        cc_logic(cpu, a | b);
        sparc64_wreg(cpu, d->rd, a | b);
        return sparc64_step_ok(pc);
    case SPARC64_OP3_XORCC:
        cc_logic(cpu, a ^ b);
        sparc64_wreg(cpu, d->rd, a ^ b);
        return sparc64_step_ok(pc);
    case SPARC64_OP3_SUBCC:
        icc = cc_sub(32U, a, b, 0U, &res);
        xcc = cc_sub(64U, a, b, 0U, &res);
        sparc64_cc_set(cpu, icc, xcc);
        sparc64_wreg(cpu, d->rd, res);
        return sparc64_step_ok(pc);
    case SPARC64_OP3_ANDNCC:
        cc_logic(cpu, a & ~b);
        sparc64_wreg(cpu, d->rd, a & ~b);
        return sparc64_step_ok(pc);
    case SPARC64_OP3_ORNCC:
        cc_logic(cpu, a | ~b);
        sparc64_wreg(cpu, d->rd, a | ~b);
        return sparc64_step_ok(pc);
    case SPARC64_OP3_XORNCC:
        cc_logic(cpu, a ^ ~b);
        sparc64_wreg(cpu, d->rd, a ^ ~b);
        return sparc64_step_ok(pc);
    case SPARC64_OP3_ADDXCC:
        cin = sparc64_cc_icc(cpu) & 1U;
        icc = cc_add(32U, a, b, cin, &res);
        xcc = cc_add(64U, a, b, cin, &res);
        sparc64_cc_set(cpu, icc, xcc);
        sparc64_wreg(cpu, d->rd, res);
        return sparc64_step_ok(pc);
    case SPARC64_OP3_SUBXCC:
        cin = sparc64_cc_icc(cpu) & 1U;
        icc = cc_sub(32U, a, b, cin, &res);
        xcc = cc_sub(64U, a, b, cin, &res);
        sparc64_cc_set(cpu, icc, xcc);
        sparc64_wreg(cpu, d->rd, res);
        return sparc64_step_ok(pc);
    case SPARC64_OP3_UMULCC: {
        uint64_t p = (uint64_t)(uint32_t)a * (uint64_t)(uint32_t)b;
        mulcc_tail(cpu, d->rd, (uint32_t)p, p);
        return sparc64_step_ok(pc);
    }
    case SPARC64_OP3_SMULCC: {
        int64_t p = (int64_t)(int32_t)(uint32_t)a *
            (int64_t)(int32_t)(uint32_t)b;
        mulcc_tail(cpu, d->rd, (uint32_t)(uint64_t)p, (uint64_t)p);
        return sparc64_step_ok(pc);
    }
    case SPARC64_OP3_UDIVCC: {
        uint64_t dvd = ((uint64_t)(uint32_t)cpu->y << 32) |
            (uint64_t)(uint32_t)a;
        uint32_t dvs = (uint32_t)b;
        uint64_t q;
        if (dvs == 0U) {
            return sparc64_trap(SPARC64_TRAP_ILLEGAL, pc, d->raw);
        }
        q = dvd / (uint64_t)dvs;
        r32 = (uint32_t)q;
        icc = 0U;
        if ((r32 & UINT32_C(0x80000000)) != UINT32_C(0)) {
            icc |= 8U;
        }
        if (r32 == 0U) {
            icc |= 4U;
        }
        if (q > (uint64_t)UINT32_C(0xFFFFFFFF)) {
            icc |= 2U;
        }
        sparc64_cc_set(cpu, icc, icc);
        sparc64_wreg(cpu, d->rd, (uint64_t)r32);
        return sparc64_step_ok(pc);
    }
    case SPARC64_OP3_SDIVCC: {
        int64_t dvd = ((int64_t)(int32_t)(uint32_t)cpu->y << 32) |
            (int64_t)(uint32_t)a;
        int32_t dvs = (int32_t)(uint32_t)b;
        int64_t q;
        if (dvs == 0) {
            return sparc64_trap(SPARC64_TRAP_ILLEGAL, pc, d->raw);
        }
        if (dvd == INT64_MIN && dvs == -1) {
            sparc64_cc_set(cpu, 8U | 2U, 8U | 2U);
            sparc64_wreg(cpu, d->rd, (uint64_t)(uint32_t)0x80000000U);
            return sparc64_step_ok(pc);
        }
        q = dvd / (int64_t)dvs;
        r32 = (uint32_t)(uint64_t)q;
        icc = 0U;
        if ((r32 & UINT32_C(0x80000000)) != UINT32_C(0)) {
            icc |= 8U;
        }
        if (r32 == 0U) {
            icc |= 4U;
        }
        if (q != (int64_t)(int32_t)r32) {
            icc |= 2U;
        }
        sparc64_cc_set(cpu, icc, icc);
        sparc64_wreg(cpu, d->rd, (uint64_t)r32);
        return sparc64_step_ok(pc);
    }
    case SPARC64_OP3_TADDCC:
    case SPARC64_OP3_TSUBCC:
    case SPARC64_OP3_TADDCTV:
    case SPARC64_OP3_TSUBCTV: {
        bool is_sub = d->op3 == SPARC64_OP3_TSUBCC ||
            d->op3 == SPARC64_OP3_TSUBCTV;
        bool tv = d->op3 == SPARC64_OP3_TADDCTV ||
            d->op3 == SPARC64_OP3_TSUBCTV;
        bool tag = ((a | b) & UINT64_C(3)) != UINT64_C(0);
        if (is_sub) {
            icc = cc_sub(32U, a, b, 0U, &res);
            xcc = cc_sub(64U, a, b, 0U, &res);
        } else {
            icc = cc_add(32U, a, b, 0U, &res);
            xcc = cc_add(64U, a, b, 0U, &res);
        }
        if (tag) {
            icc |= 2U;
            xcc |= 2U;
        }
        if (tv && ((icc | xcc) & 2U) != 0U) {
            return sparc64_trap(SPARC64_TRAP_ILLEGAL, pc, d->raw);
        }
        sparc64_cc_set(cpu, icc, xcc);
        sparc64_wreg(cpu, d->rd, res);
        return sparc64_step_ok(pc);
    }
    case SPARC64_OP3_MULSCC: {
        /* Multiply step: 32-bit core (oracle shape verified by S1 probe
         * before RC1). opnd selected by xcc N^V; Y shifts rs1 bit 0 into
         * the top; rd takes old Y bit 0 plus the halved sum. */
        unsigned xcc0 = sparc64_cc_xcc(cpu);
        bool nv = ((xcc0 & 8U) != 0U) != ((xcc0 & 2U) != 0U);
        uint32_t a32 = (uint32_t)a;
        uint32_t opnd = nv ? (uint32_t)b : 0U;
        uint64_t full = (uint64_t)a32 + (uint64_t)opnd;
        uint32_t sum = (uint32_t)full;
        bool v = ((int64_t)(int32_t)a32 + (int64_t)(int32_t)opnd) !=
            (int64_t)(int32_t)sum;
        uint32_t yold = (uint32_t)cpu->y;
        unsigned ncc = 0U;
        cpu->y = (uint64_t)(((a32 & 1U) << 31) | (yold >> 1));
        if ((sum & UINT32_C(0x80000000)) != UINT32_C(0)) {
            ncc |= 8U;
        }
        if (sum == 0U) {
            ncc |= 4U;
        }
        if (v) {
            ncc |= 2U;
        }
        if ((full >> 32) != UINT64_C(0)) {
            ncc |= 1U;
        }
        sparc64_cc_set(cpu, ncc, ncc);
        sparc64_wreg(cpu, d->rd,
            (uint64_t)(((yold & 1U) << 31) | (sum >> 1)));
        return sparc64_step_ok(pc);
    }
    default:
        return sparc64_trap(SPARC64_TRAP_ILLEGAL, pc, d->raw);
    }
}

/* Shifts (op3 0x25-0x27). Oracle parity (V9 A.48, E02/E04, P1
 * oracle): SLL/SRL with x==0 shift only r[rs1][31:0] and zero-extend
 * bits 63:32; SRA sign-extends (bit 31 for plain, bit 63 for X
 * forms). Count masks to 5/6 bits. */
sparc64_step_result_t sparc64_exec_shift(sparc64_cpu_t *cpu, uint64_t pc,
    const sparc64_dec_t *d)
{
    uint64_t a = sparc64_rreg(cpu, d->rs1);
    uint64_t count;
    if (d->is_imm != 0U) {
        count = (uint64_t)d->imm;
    } else {
        count = sparc64_rreg(cpu, d->rs2);
    }
    if (d->xbit != 0U) {
        count &= UINT64_C(63);
        if (d->op3 == SPARC64_OP3_SLL) {
            sparc64_wreg(cpu, d->rd, a << count);
        } else if (d->op3 == SPARC64_OP3_SRL) {
            sparc64_wreg(cpu, d->rd, a >> count);
        } else {
            sparc64_wreg(cpu, d->rd, (uint64_t)(((int64_t)a) >> count));
        }
    } else {
        /* V9 A.48: 32-bit SLL/SRL shift only the low 32 bits and
         * zero-extend (E02/E04 oracle; P1 oracle: sll 0x80000001,1
         * gives 0x2, not 0x100000002). SRA sign-extends bit 31
         * into the upper half. */
        uint32_t a32 = (uint32_t)a;
        unsigned c = (unsigned)(count & UINT64_C(31));
        if (d->op3 == SPARC64_OP3_SLL) {
            sparc64_wreg(cpu, d->rd, (uint64_t)(a32 << c));
        } else if (d->op3 == SPARC64_OP3_SRL) {
            sparc64_wreg(cpu, d->rd, (uint64_t)(a32 >> c));
        } else {
            sparc64_wreg(cpu, d->rd,
                (uint64_t)((int64_t)((int32_t)a32 >> (int)c)));
        }
    }
    return sparc64_step_ok(pc);
}

/* Integer MOVcc/MOVr; FP forms decode as FPU and never reach here. */
sparc64_step_result_t sparc64_exec_mov(sparc64_cpu_t *cpu, uint64_t pc,
    const sparc64_dec_t *d)
{
    uint64_t src = (d->is_imm != 0U) ? (uint64_t)d->imm
                                     : sparc64_rreg(cpu, d->rs2);
    bool take;
    if (d->cls == (uint8_t)SPARC64_ICLS_MOVCC) {
        unsigned nib = (d->cc == 2U) ? sparc64_cc_xcc(cpu)
                                     : sparc64_cc_icc(cpu);
        take = sparc64_eval_cond(d->cond, nib);
    } else {
        take = sparc64_eval_rcond(d->cond, sparc64_rreg(cpu, d->rs1));
    }
    if (take) {
        sparc64_wreg(cpu, d->rd, src);
    }
    return sparc64_step_ok(pc);
}

/* User state registers: %y/%ccr/%asi/%pc/%fprs/%gsr (RDPC reads the
 * address of the instruction itself, V9 6.6.5). %tick is emulated
 * with a fixed value (Phase 5, L5a): the oracle returns its virtual
 * clock, but a live clock would diverge lockstep difftest (two
 * copies, separate reads) and interp-vs-dbt runs, so determinism
 * wins; the guest only samples it for startup mixing. */
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

/* ALIGNADDR/ALIGNADDRL (E05: rd = sum & ~7, GSR offset = sum & 7). The two
 * variants differ only in the Phase 3 FALIGNDATA merge direction. */
sparc64_step_result_t sparc64_exec_align(sparc64_cpu_t *cpu, uint64_t pc,
    const sparc64_dec_t *d)
{
    uint64_t a = sparc64_rreg(cpu, d->rs1);
    uint64_t b = (d->is_imm != 0U) ? (uint64_t)d->imm
                                   : sparc64_rreg(cpu, d->rs2);
    uint64_t sum = a + b;
    cpu->gsr = (cpu->gsr & ~(UINT64_C(7))) | (sum & UINT64_C(7));
    sparc64_wreg(cpu, d->rd, sum & ~(UINT64_C(7)));
    return sparc64_step_ok(pc);
}

/* Privileged-class execution. FLUSHW is the V9 exception: it is
 * unprivileged and spills all non-current windows to their stack homes,
 * leaving CANRESTORE == 0 so subsequent RESTOREs refill from memory
 * (required by libgcc uw_install_context, which rewrites the caller save
 * area on the stack before executing RETURN). */
sparc64_step_result_t sparc64_exec_priv(sparc64_cpu_t *cpu,
    const sparc64_mem_ops_t *mem, void *mc, uint64_t pc,
    const sparc64_dec_t *d)
{
    sparc64_step_result_t res;
    if (d->op3 == SPARC64_OP3_FLUSHW) {
        if (!sparc64_win_flush_all(cpu, mem, mc, &res, pc)) {
            return res;
        }
        cpu->canrestore = 0U;
        cpu->cansave = SPARC64_NWINDOWS - 1U;
        return sparc64_step_ok(pc);
    }
    return sparc64_trap(SPARC64_TRAP_PRIVILEGED, pc, d->raw);
}

/* Lane P5: DBT fast-path window bases; spill/fill stay on the slow path. */
uint64_t *sparc64_win_file_base(void) { return &interp_winfile[0][0]; }
uint64_t *sparc64_win_sp_base(void) { return &interp_winsp[0]; }
bool *sparc64_win_valid_base(void) { return &win_valid[0]; }
