/*
 * src/dbt/difftest.c — Lockstep interp-vs-dbt differential harness (Phase 2)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Lane L2d owns this file (Phase 2, SPEC sections 2-3). See difftest.h
 * for the compared-state contract and the single-step granularity rule
 * (one sparc64_step per side per iteration; a CTI plus its delay slot
 * counts as one step on both sides).
 *
 * Method: two sparc64_ctx_t copies (interp side / dbt side) share the one
 * guest mapping through the same sparc64_mem_ops_t. Each iteration steps
 * both engines once and compares r[32]/pc/npc/ccr. SYSCALL stops run the
 * caller-supplied handler exactly once on the interp copy and mirror the
 * result into the dbt copy. Atomic RMW (LDSTUB/SWAP/CASA/CASXA) uses a
 * snapshot/restore sandwich so both engines read identical pre-state.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "core/cpu.h"
#include "dbt/difftest.h"
#include "interp/decode.h"

/* Hang guard: the P2 static-libc guests terminate in well under this. */
#define DIFFTEST_DEFAULT_MAX_STEPS 100000000UL

/* Backtrace depth bound (fp-chain walk). */
#define DIFFTEST_BT_DEPTH 8U

static const char *const difftest_rnames[32] = {
    "g0", "g1", "g2", "g3", "g4", "g5", "g6", "g7",
    "o0", "o1", "o2", "o3", "o4", "o5", "sp", "o7",
    "l0", "l1", "l2", "l3", "l4", "l5", "l6", "l7",
    "i0", "i1", "i2", "i3", "i4", "i5", "fp", "i7",
};

static int difftest_cmp_u64(const char *name, uint64_t a, uint64_t b,
    uint64_t step_pc, int *count)
{
    if (a != b) {
        (void)printf("difftest: divergence at pc=0x%llx: %s interp=0x%llx dbt=0x%llx\n",
            (unsigned long long)step_pc, name,
            (unsigned long long)a, (unsigned long long)b);
        (*count)++;
        return 1;
    }
    return 0;
}

int sparc64_difftest_cmp(const sparc64_ctx_t *a, const sparc64_ctx_t *b,
    uint64_t step_pc)
{
    int n = 0;
    unsigned i;
    if (a == NULL || b == NULL) {
        return 1;
    }
    for (i = 0U; i < 32U; i++) {
        (void)difftest_cmp_u64(difftest_rnames[i], a->r[i], b->r[i],
            step_pc, &n);
    }
    (void)difftest_cmp_u64("pc", a->pc, b->pc, step_pc, &n);
    (void)difftest_cmp_u64("npc", a->npc, b->npc, step_pc, &n);
    (void)difftest_cmp_u64("ccr", a->ccr, b->ccr, step_pc, &n);
    return n;
}

static const char *difftest_kind_name(sparc64_step_kind_t kind)
{
    switch (kind) {
    case SPARC64_STEP_CONTINUE:
        return "CONTINUE";
    case SPARC64_STEP_SYSCALL:
        return "SYSCALL";
    case SPARC64_STEP_TRAP:
        return "TRAP";
    case SPARC64_STEP_RETRY:
        return "RETRY";
    case SPARC64_STEP_INTERNAL:
        return "INTERNAL";
    default:
        return "?";
    }
}

/* Checked guest read through the shared mapping. */
static bool difftest_mem_read(const sparc64_difftest_cfg_t *cfg, uint64_t va,
    uint8_t *out, size_t len, sparc64_access_t access)
{
    sparc64_mem_fault_t fault;
    if (cfg == NULL || cfg->mem == NULL || cfg->mem->read == NULL ||
        out == NULL) {
        return false;
    }
    if (len == 0U) {
        return true;
    }
    fault.address = UINT64_C(0);
    fault.reason = SPARC64_MEM_FAULT_NONE;
    return cfg->mem->read(cfg->mc, va, out, len, access, &fault);
}

/* Checked guest write through the shared mapping (RMW restore only). */
static bool difftest_mem_write(const sparc64_difftest_cfg_t *cfg, uint64_t va,
    const uint8_t *in, size_t len)
{
    sparc64_mem_fault_t fault;
    if (cfg == NULL || cfg->mem == NULL || cfg->mem->write == NULL ||
        in == NULL || len == 0U) {
        return false;
    }
    fault.address = UINT64_C(0);
    fault.reason = SPARC64_MEM_FAULT_NONE;
    return cfg->mem->write(cfg->mc, va, in, len, &fault);
}

static uint64_t difftest_ld_be64(const uint8_t *p)
{
    return ((uint64_t)p[0] << 56) | ((uint64_t)p[1] << 48) |
        ((uint64_t)p[2] << 40) | ((uint64_t)p[3] << 32) |
        ((uint64_t)p[4] << 24) | ((uint64_t)p[5] << 16) |
        ((uint64_t)p[6] << 8) | (uint64_t)p[7];
}

/*
 * Guest backtrace: fp-anchored register dump plus a best-effort fp-chain
 * walk. %fp (new %i6) holds the caller's biased %sp after SAVE, so the
 * unbiased frame base is F = fp + 2047 and the 128-byte rwindow_64 area
 * at [F, F + 128) carries ins[6] (caller's fp) at F + 112 and ins[7]
 * (return address) at F + 120. Every read is coverage-checked through
 * the shared mapping; the walk stops at the first unreadable,
 * misaligned, or non-progressing frame (fresh windows rotate
 * in-register with no spill, so an early stop is the common case).
 */
static void difftest_backtrace(const sparc64_difftest_cfg_t *cfg,
    const sparc64_ctx_t *ctx)
{
    uint64_t fp;
    uint8_t insn[4];
    unsigned depth;
    (void)printf("difftest: backtrace: pc=0x%llx npc=0x%llx sp=0x%llx fp=0x%llx o7=0x%llx i7=0x%llx\n",
        (unsigned long long)ctx->pc, (unsigned long long)ctx->npc,
        (unsigned long long)ctx->r[SPARC64_SP],
        (unsigned long long)ctx->r[SPARC64_FP],
        (unsigned long long)ctx->r[15], (unsigned long long)ctx->r[31]);
    if (difftest_mem_read(cfg, ctx->pc, insn, sizeof(insn),
        SPARC64_ACCESS_FETCH)) {
        (void)printf("difftest: insn at pc: 0x%02x%02x%02x%02x\n",
            insn[0], insn[1], insn[2], insn[3]);
    }
    fp = ctx->r[SPARC64_FP];
    for (depth = 0U; depth < DIFFTEST_BT_DEPTH; depth++) {
        uint64_t f;
        uint8_t frame[16];
        uint64_t next_fp;
        uint64_t ret;
        if ((fp & UINT64_C(7)) != UINT64_C(0) || fp == UINT64_C(0)) {
            break;
        }
        if (fp > UINT64_MAX - UINT64_C(2047) - UINT64_C(128)) {
            break;
        }
        f = fp + UINT64_C(2047);
        if (!difftest_mem_read(cfg, f + UINT64_C(112), frame,
            sizeof(frame), SPARC64_ACCESS_LOAD)) {
            (void)printf("difftest: frame %u: fp=0x%llx (unreadable, stop)\n",
                depth, (unsigned long long)fp);
            break;
        }
        next_fp = difftest_ld_be64(frame);
        ret = difftest_ld_be64(frame + 8);
        (void)printf("difftest: frame %u: fp=0x%llx ret=0x%llx\n",
            depth, (unsigned long long)fp, (unsigned long long)ret);
        if (next_fp == UINT64_C(0) || next_fp == fp) {
            break;
        }
        fp = next_fp;
    }
}

static uint64_t difftest_reg(const sparc64_ctx_t *ctx, uint32_t i)
{
    return (i == 0U) ? UINT64_C(0) : ctx->r[i & 31U];
}

/* Atomic RMW sandwich (LDSTUB/SWAP/CASA/CASXA): both engines share the
 * one guest mapping, so stepping interp first would let its write be
 * visible to the dbt side's subsequent read. Snapshot the touched
 * bytes, run interp, restore them, then run dbt, so both engines read
 * identical pre-state. Plain loads/stores need no sandwich (the second
 * write is idempotent). Only entered when the range reads back; any
 * faulting range faults identically on both sides instead. */
typedef struct {
    bool armed;
    uint64_t va;
    unsigned len;
    uint8_t bytes[8];
} difftest_rmw_t;

static difftest_rmw_t difftest_rmw_snap(const sparc64_difftest_cfg_t *cfg,
    const sparc64_ctx_t *ctx, uint64_t pc)
{
    difftest_rmw_t s;
    uint8_t insn[4];
    uint32_t word;
    sparc64_decoded_t d;
    unsigned len = 0U;
    uint64_t va;
    s.armed = false;
    s.va = UINT64_C(0);
    s.len = 0U;
    memset(s.bytes, 0, sizeof(s.bytes));
    if (!difftest_mem_read(cfg, pc, insn, sizeof(insn),
        SPARC64_ACCESS_FETCH)) {
        return s;
    }
    word = ((uint32_t)insn[0] << 24) | ((uint32_t)insn[1] << 16) |
        ((uint32_t)insn[2] << 8) | (uint32_t)insn[3];
    sparc64_decode_word(word, &d);
    if (d.atomic == 0U) {
        return s;
    }
    switch (d.cls) {
    case SPARC64_OP_LOAD:
        len = 1U; /* LDSTUB: single atomic byte. */
        break;
    case SPARC64_OP_SWAP:
        len = 4U;
        break;
    case SPARC64_OP_CASA:
        len = 4U;
        break;
    case SPARC64_OP_CASXA:
        len = 8U;
        break;
    default:
        return s;
    }
    va = difftest_reg(ctx, d.rs1) +
        ((d.is_imm != 0U) ? (uint64_t)(int64_t)d.simm
                          : difftest_reg(ctx, d.rs2));
    if (!difftest_mem_read(cfg, va, s.bytes, (size_t)len,
        SPARC64_ACCESS_LOAD)) {
        return s;
    }
    s.armed = true;
    s.va = va;
    s.len = len;
    return s;
}

static void difftest_rmw_restore(const sparc64_difftest_cfg_t *cfg,
    difftest_rmw_t *s)
{
    if (s->armed) {
        (void)difftest_mem_write(cfg, s->va, s->bytes, (size_t)s->len);
        s->armed = false;
    }
}

static sparc64_step_result_t difftest_step_interp(
    const sparc64_difftest_cfg_t *cfg, sparc64_ctx_t *ctx)
{
    return sparc64_step(ctx, cfg->mem, cfg->mc);
}

static sparc64_step_result_t difftest_step_dbt(
    const sparc64_difftest_cfg_t *cfg, sparc64_ctx_t *ctx)
{
    if (cfg->dbt_step != NULL) {
        return cfg->dbt_step(cfg->dbt, ctx, cfg->mem, cfg->mc);
    }
    return sparc64_step(ctx, cfg->mem, cfg->mc);
}

int sparc64_difftest_run(const sparc64_difftest_cfg_t *cfg,
    sparc64_ctx_t *ctx)
{
    sparc64_ctx_t a;
    sparc64_ctx_t b;
    unsigned long steps = 0UL;
    unsigned long max_steps;
    if (cfg == NULL || ctx == NULL || cfg->mem == NULL) {
        (void)printf("difftest: null config/context\n");
        return 2;
    }
    max_steps = (cfg->max_steps != 0UL) ? cfg->max_steps
                                        : DIFFTEST_DEFAULT_MAX_STEPS;
    a = *ctx;
    b = *ctx;
    for (;;) {
        sparc64_step_result_t ra;
        sparc64_step_result_t rb;
        uint64_t step_pc;
        difftest_rmw_t rmw;
        int n;
        if (steps >= max_steps) {
            (void)printf("difftest: step budget exhausted (%lu steps, pc=0x%llx)\n",
                steps, (unsigned long long)a.pc);
            return 2;
        }
        step_pc = a.pc;
        steps++;
        rmw = difftest_rmw_snap(cfg, &a, step_pc);
        ra = difftest_step_interp(cfg, &a);
        difftest_rmw_restore(cfg, &rmw);
        rb = difftest_step_dbt(cfg, &b);
        if (ra.kind != rb.kind) {
            (void)printf("difftest: divergence at pc=0x%llx: stop-kind interp=%s(%d) dbt=%s(%d)\n",
                (unsigned long long)step_pc, difftest_kind_name(ra.kind),
                (int)ra.kind, difftest_kind_name(rb.kind), (int)rb.kind);
            (void)printf("difftest: interp tval=0x%llx | dbt tval=0x%llx\n",
                (unsigned long long)ra.tval, (unsigned long long)rb.tval);
            difftest_backtrace(cfg, &a);
            return 1;
        }
        switch (ra.kind) {
        case SPARC64_STEP_CONTINUE:
            n = sparc64_difftest_cmp(&a, &b, step_pc);
            if (n != 0) {
                (void)printf("difftest: %d differing field(s) at step %lu\n",
                    n, steps);
                difftest_backtrace(cfg, &a);
                return 1;
            }
            break;
        case SPARC64_STEP_SYSCALL:
            /* Both engines trapped on the same instruction: state must
             * match first, then the syscall runs exactly once. */
            n = sparc64_difftest_cmp(&a, &b, step_pc);
            if (n != 0) {
                (void)printf("difftest: %d differing field(s) at step %lu\n",
                    n, steps);
                difftest_backtrace(cfg, &a);
                return 1;
            }
            if (cfg->syscall == NULL) {
                *ctx = a;
                (void)printf("difftest: both engines stopped at syscall pc=0x%llx nr=%lld (agreement, no handler wired)\n",
                    (unsigned long long)step_pc,
                    (long long)a.r[SPARC64_G1]);
                return 2;
            }
            {
                int is_exit = 0;
                long status = cfg->syscall(&a, cfg->syscall_arg, &is_exit);
                if (is_exit != 0) {
                    *ctx = a;
                    (void)printf("difftest: 0 divergences (%lu steps, guest exit %ld)\n",
                        steps, status & 0xffL);
                    return (int)(status & 0xffL);
                }
                /* One shared handler call: mirror the post-syscall
                 * state (advanced pc/npc, carry result) into both. */
                b = a;
            }
            break;
        default:
            /* Matching non-continuable stop (TRAP/RETRY/INTERNAL):
             * agreement only when the states and trap values match. */
            n = sparc64_difftest_cmp(&a, &b, step_pc);
            if (ra.tval != rb.tval) {
                (void)printf("difftest: divergence at pc=0x%llx: tval interp=0x%llx dbt=0x%llx\n",
                    (unsigned long long)step_pc,
                    (unsigned long long)ra.tval,
                    (unsigned long long)rb.tval);
                n++;
            }
            if (n != 0) {
                (void)printf("difftest: %d differing field(s) at step %lu\n",
                    n, steps);
                difftest_backtrace(cfg, &a);
                return 1;
            }
            *ctx = a;
            (void)printf("difftest: both engines stopped with %s(%d) at pc=0x%llx (agreement, guest did not exit)\n",
                difftest_kind_name(ra.kind), (int)ra.kind,
                (unsigned long long)step_pc);
            return 2;
        }
    }
}
