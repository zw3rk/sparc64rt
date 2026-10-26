/*
 * src/dbt/emit_rt.c — native-fragment runtime helpers (Lane M3)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Lane M3 owns the memory call-site swap: s64_rt_mem no longer
 * re-implements the classify/dispatch switch and no longer funnels
 * through the sparc64_threads_try_host_atomic pre-check. Both memory
 * and window helpers now route through the shared interpreter replay
 * in dbt/mem_sites.c (sparc64_mem_slow_step), so emitted fragments and
 * interp observe identical semantics by construction; any fault returns
 * nonzero and the fragment exits so the dispatcher replays the
 * instruction with sparc64_step for the precise trap. Guest register
 * state lives in ctx (x19) across the call; helpers preserve all
 * callee-saved registers per AAPCS64.
 */

#include <stdbool.h>
#include <stdint.h>

#include "core/cpu.h"
#include "dbt/emit_mem.h"
#include "dbt/mem_sites.h"
#include "interp/interp.h"
#include "os/threads.h"

uint64_t s64_rt_mem(sparc64_ctx_t *ctx, const sparc64_mem_ops_t *mem,
    void *mc, uint64_t pc, uint64_t pack_a, uint32_t raw, uint64_t pack_b)
{
    uint32_t rc;
    (void)pack_a;
    (void)raw;
    (void)pack_b;
    if (ctx == NULL || mem == NULL) {
        return (uint64_t)SPARC64_EXIT_UNDEF;
    }
    /* The interpreter re-fetches and re-decodes the word at pc, so the
     * packed op fields are informational only; parity holds because the
     * same step function backs the miss trampoline in mem_sites.c. */
    rc = sparc64_mem_slow_step(ctx, mem, mc, pc);
    return rc == (uint32_t)SPARC64_EXIT_NONE ? UINT64_C(0) :
        (uint64_t)SPARC64_EXIT_UNDEF;
}

uint64_t s64_rt_win(sparc64_ctx_t *ctx, const sparc64_mem_ops_t *mem,
    void *mc, uint64_t sum, uint64_t rd_save, uint64_t pc)
{
    sparc64_step_result_t res;
    unsigned rd = (unsigned)(rd_save & 31U);
    bool ok;
    if (ctx == NULL || mem == NULL) {
        return (uint64_t)SPARC64_EXIT_UNDEF;
    }
    /* Mirrors interp.c SAVE/RESTORE exactly: win_save/win_restore own
     * the rotation (including rd); no extra register write here. */
    if ((rd_save & 0x100U) != UINT64_C(0)) {
        ok = sparc64_win_save(ctx, mem, mc, sum, rd, &res, pc);
    } else {
        ok = sparc64_win_restore(ctx, mem, mc, sum, rd, &res, pc);
    }
    if (!ok) {
        return (uint64_t)SPARC64_EXIT_UNDEF;
    }
    return UINT64_C(0);
}
