/*
 * src/dbt/emit_rt.c — native-fragment runtime helpers (coordinator, RC2)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * L2c's emitter lowers memory and window ops to BLR calls into these two
 * C helpers (see emit_priv.h e_call_mem/e_call_win). They re-run the
 * reference interpreter's exact exec_* bodies, so emitted fragments and
 * interp observe identical semantics; any fault returns nonzero and the
 * fragment exits so the dispatcher replays the instruction with
 * sparc64_step for the precise trap. Guest register state lives in ctx
 * (x19) across the call; helpers preserve all callee-saved registers
 * per AAPCS64.
 */

#include <stdint.h>

#include "core/cpu.h"
#include "interp/interp.h"
#include "os/threads.h"

uint64_t s64_rt_mem(sparc64_ctx_t *ctx, const sparc64_mem_ops_t *mem,
    void *mc, uint64_t pc, uint64_t pack_a, uint32_t raw, uint64_t pack_b)
{
    sparc64_dec_t d;
    sparc64_step_result_t r;
    (void)pack_a;
    (void)pack_b;
    if (ctx == NULL || mem == NULL) {
        return (uint64_t)SPARC64_EXIT_UNDEF;
    }
    sparc64_classify_word(raw, &d);
    switch (d.cls) {
    case SPARC64_ICLS_LOAD:
        r = sparc64_exec_load(ctx, mem, mc, pc, &d);
        break;
    case SPARC64_ICLS_STORE:
        r = sparc64_exec_store(ctx, mem, mc, pc, &d);
        break;
    case SPARC64_ICLS_LDSTUB:
    case SPARC64_ICLS_SWAP:
    case SPARC64_ICLS_ATOMIC: {
        /* L4b: same single-copy host-__atomic fast path the interp
         * exec_atomic takes; the reservation path below is unchanged. */
        sparc64_step_result_t fast;
        if (sparc64_threads_try_host_atomic(ctx, mc, pc, &d, &fast)) {
            return fast.kind == SPARC64_STEP_CONTINUE ? UINT64_C(0) :
                (uint64_t)SPARC64_EXIT_UNDEF;
        }
        r = sparc64_exec_atomic(ctx, mem, mc, pc, &d);
        break;
    }
    default:
        return (uint64_t)SPARC64_EXIT_UNDEF;
    }
    return r.kind == SPARC64_STEP_CONTINUE ? UINT64_C(0) :
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
