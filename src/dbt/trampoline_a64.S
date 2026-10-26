/*
 * src/dbt/trampoline_a64.S — DBT enter/exit trampoline (AArch64)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Phase 2 lane L2b (docs/lanes/phase-2.md). Enters translated code with
 * the guest context pointer in x19, so emitted fragments address
 * dispatcher state through it. Full 64-bit guest VAs go through the
 * sparc64_mem_ops_t callbacks (no direct host dereference of guest VA).
 *
 * Register contract (matches src/dbt/dbt.h and src/core/cpu.h offsets):
 *   x0 = ctx, x1 = entry (host RX address in the DBT code arena),
 *   x2 = chaining entry for x27 (slots provisioned by dbt.c),
 *   x3 = epoch word for x28 (&dbt->epoch to allow chaining).
 * Every emitted exit returns via `ret` with the resume/fault guest PC
 * in x15 and the SPARC64_EXIT_* reason in w16; the trampoline stores
 * w16 -> ctx->exit_reason (0x270) and x15 -> ctx->exit_dest (0x280)
 * and returns to the C dispatcher, which commits pc/npc from the exit.
 * sparc64_dbt_enter_step points x28 at a zero epoch word instead, so
 * every epoch-gated chain probe bails and exactly one guest
 * instruction executes (difftest lockstep).
 *
 * Never reads or writes the AArch64 platform register x18.
 * Assembled only by an AArch64 toolchain; the C dispatcher (dbt.c)
 * calls sparc64_dbt_enter/sparc64_dbt_enter_step and reads back ctx.
 */

    .text
    .arch armv8-a
    .align 2

/* Shared tail: x0 = ctx, x1 = entry, x27/x28 already set by the entry
 * prologue that branched here. */
.Ldbt_enter_go:
    /* x19 = ctx (xCtx) for exit commit. */
    mov x19, x0

    /* x20 = Soft-TLB base (Lane M3): &sparc64_dbt_tlb[0] from
     * dbt/mem_sites.c. cpu.h is frozen, so the table is process-global
     * until the coordinator pins a per-worker tlb field in ctx. */
#ifdef __APPLE__
    adrp x20, _sparc64_dbt_tlb@PAGE
    add x20, x20, _sparc64_dbt_tlb@PAGEOFF
#else
    adrp x20, sparc64_dbt_tlb
    add x20, x20, :lo12:sparc64_dbt_tlb
#endif

    /* Enter translated code; fragments return here via `ret`. */
    blr x1

    /* Commit the exit: w16 -> exit_reason, x15 -> exit_dest. */
    str w16, [x19, #0x270]
    str x15, [x19, #0x280]

    /* Epilogue: restore and return to the C dispatcher. */
    ldp d14, d15, [sp], #16
    ldp d12, d13, [sp], #16
    ldp d10, d11, [sp], #16
    ldp d8, d9, [sp], #16
    ldp x27, x28, [sp], #16
    ldp x25, x26, [sp], #16
    ldp x23, x24, [sp], #16
    ldp x21, x22, [sp], #16
    ldp x19, x20, [sp], #16
    ldp x29, x30, [sp], #16
    ret

/* Prologue shared by both entries: save fp/lr + callee-saved pairs
 * (no x18 anywhere), then install x27/x28 and join the shared tail. */
    .macro DBT_ENTER_PROLOGUE
    stp x29, x30, [sp, #-16]!
    mov x29, sp
    stp x19, x20, [sp, #-16]!
    stp x21, x22, [sp, #-16]!
    stp x23, x24, [sp, #-16]!
    stp x25, x26, [sp, #-16]!
    stp x27, x28, [sp, #-16]!
    stp d8, d9, [sp, #-16]!
    stp d10, d11, [sp, #-16]!
    stp d12, d13, [sp, #-16]!
    stp d14, d15, [sp, #-16]!
    .endm

    .globl sparc64_dbt_enter
/* ELF-only directive: Apple as rejects .type/.size (Lane M3 portability). */
#ifndef __APPLE__
    .type sparc64_dbt_enter, %function
#endif
sparc64_dbt_enter:
    DBT_ENTER_PROLOGUE
    /* x27 = chaining entry, x28 = live epoch word (chaining allowed). */
    mov x27, x2
    mov x28, x3
    b .Ldbt_enter_go
#ifndef __APPLE__
    .size sparc64_dbt_enter, .-sparc64_dbt_enter
#endif

    .globl sparc64_dbt_enter_step
#ifndef __APPLE__
    .type sparc64_dbt_enter_step, %function
#endif
sparc64_dbt_enter_step:
    DBT_ENTER_PROLOGUE
    /* x27 = chaining entry; x28 = zero epoch word so every
     * epoch-gated chain probe bails: single execution. */
    mov x27, x2
#ifdef __APPLE__
    adrp x28, .Ldbt_zero_epoch@PAGE
    add x28, x28, .Ldbt_zero_epoch@PAGEOFF
#else
    adrp x28, .Ldbt_zero_epoch
    add x28, x28, :lo12:.Ldbt_zero_epoch
#endif
    b .Ldbt_enter_go
#ifndef __APPLE__
    .size sparc64_dbt_enter_step, .-sparc64_dbt_enter_step
#endif

    /* Mach-O has no .rodata section name (Lane M3 portability). */
#ifdef __APPLE__
    .section __TEXT,__const
#else
    .section .rodata
#endif
    .align 2
.Ldbt_zero_epoch:
    .word 0
    .text
