/*
 * src/dbt/difftest.h — Lockstep interp-vs-dbt differential harness (Phase 2)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Lane L2d owns this file (Phase 2, SPEC sections 2-3). It declares the
 * --difftest entry point consumed by the Coordinator-owned main.c wiring:
 * sparc64_difftest_run() steps the reference interpreter (src/interp/)
 * and the DBT engine (lane L2b) in lockstep from the same loaded guest
 * and compares the user-visible state after every instruction.
 *
 * Compared state: r[32], pc, npc, ccr (SPEC 2.1 integer user state).
 * Guest memory — including the spilled window save areas — is shared:
 * both step-copies run over the same sparc64_mem_ops_t mapping, so
 * memory cannot diverge by construction and only the register views
 * are compared.
 *
 * Syscalls (SPARC64_STEP_SYSCALL) run exactly once through the
 * caller-supplied handler; the resulting state is then mirrored into
 * both engines before resuming.
 *
 * Standalone note: this header deliberately does not include L2b's
 * src/dbt/dbt.h (merged by the coordinator after the lanes land). The
 * DBT side is driven through sparc64_dbt_step_fn, whose contract
 * mirrors sparc64_step granularity: exactly one guest instruction per
 * call (a CTI plus its delay slot counts as one step, matching
 * sparc64_step). A NULL hook falls back to sparc64_step
 * (self-consistency mode, 0 divergences) until the wiring lands.
 */

#ifndef SPARC64RT_DBT_DIFFTEST_H
#define SPARC64RT_DBT_DIFFTEST_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "core/cpu.h"

/* Opaque DBT dispatcher state (defined by lane L2b in src/dbt/dbt.h).
 * Only a forward declaration is needed here; the step hook carries it. */
struct sparc64_dbt;

/*
 * Single DBT step supplied by the caller (L2b wiring post-merge).
 * Runs exactly one guest instruction at ctx->pc/ctx->npc over mem/mc
 * and reports through the same sparc64_step_result_t protocol as
 * sparc64_step (SYSCALL stops without advancing pc; the caller owns
 * the single pc = npc; npc += 4 commit via the syscall hook).
 */
typedef sparc64_step_result_t (*sparc64_dbt_step_fn)(struct sparc64_dbt *dbt,
    sparc64_ctx_t *ctx, const sparc64_mem_ops_t *mem, void *mc);

/*
 * Syscall hook: runs the shared handler exactly once on the interp
 * copy (carry convention + pc = npc; npc += 4 commit, as in
 * sparc64_handle_syscall). Sets *is_exit nonzero for the terminal
 * exit/exit_group calls and returns the guest exit status in that
 * case; returns 0 otherwise.
 */
typedef long (*sparc64_difftest_syscall_fn)(sparc64_ctx_t *ctx, void *arg,
    int *is_exit);

/*
 * Trap hook: delivers a synchronous guest signal for a STEP_TRAP stop
 * (writes the rt frame, redirects ctx at the handler). Runs once per
 * engine copy over the shared mapping. Returns 0 when delivered (both
 * copies resume in the handler and stepping continues), nonzero when
 * the trap is unhandled (the harness reports agreement and stops).
 */
typedef int (*sparc64_difftest_trap_fn)(sparc64_ctx_t *ctx, void *arg,
    int signo, int code, uint64_t fault_addr);

typedef struct {
    const sparc64_mem_ops_t *mem;   /* Shared guest-memory operations. */
    void *mc;                       /* Memory context threaded through. */
    struct sparc64_dbt *dbt;         /* DBT state for dbt_step (may be NULL). */
    sparc64_dbt_step_fn dbt_step;    /* NULL selects sparc64_step fallback. */
    sparc64_difftest_syscall_fn syscall; /* NULL stops at syscalls (agreement). */
    void *syscall_arg;              /* Opaque arg for the syscall hook. */
    sparc64_difftest_trap_fn trap_deliver; /* NULL stops at traps (agreement). */
    void *trap_arg;                 /* Opaque arg for the trap hook. */
    unsigned long max_steps;        /* 0 selects the default hang guard. */
} sparc64_difftest_cfg_t;

/*
 * Lockstep difftest from the already-loaded guest in *ctx.
 *
 * Prints "difftest: 0 divergences ..." when the guest terminates via an
 * exit syscall with no state mismatch, or the first divergence (step PC,
 * differing fields, guest backtrace) otherwise.
 *
 * Returns the guest exit status on a divergence-free guest exit, 1 on the
 * first state divergence, 2 when both engines agree on a non-exit stop
 * (syscall with no handler wired, matching trap, retry/internal state)
 * or the step budget is exhausted.
 */
int sparc64_difftest_run(const sparc64_difftest_cfg_t *cfg,
    sparc64_ctx_t *ctx);

/*
 * Compare the user-visible state after one lockstep step (r[32], pc,
 * npc, ccr). Prints one line per differing field and returns the
 * number of differing fields (0 = agreement).
 */
int sparc64_difftest_cmp(const sparc64_ctx_t *a, const sparc64_ctx_t *b,
    uint64_t step_pc);

#endif /* SPARC64RT_DBT_DIFFTEST_H */
