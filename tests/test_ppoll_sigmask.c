/*
 * tests/test_ppoll_sigmask.c — ppoll/pselect6 temporary-mask delivery.
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Regression test for the canonical block-then-ppoll pattern: the
 * caller keeps SIGUSR1 blocked and unblocks it only in the ppoll (or
 * pselect6) temporary mask. A SIGUSR1 queued while blocked must run its
 * handler when the wait returns -EINTR (Linux restore_saved_sigmask),
 * and rt_sigreturn must resume past the trapping ta with %o0 = EINTR,
 * carry set, and the original mask (SIGUSR1 still blocked) restored.
 * Returning -EINTR with the original mask reinstalled but no delivery
 * leaves SIGUSR1 pending and blocked, so `while (!flag) ppoll(...)`
 * spins forever.
 *
 * The test drives the real dispatch (sparc64_handle_syscall) over a
 * guest_state_t space with the runner's sysmem ops; no SPARC code runs
 * (the handler body is simulated by a guest-memory store). Links every
 * translator object except main. Deterministic stdout; exit 0 with
 * PPOLL-SIGMASK-PASS iff every check passed.
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "core/cpu.h"
#include "os/guest_run_priv.h"
#include "os/mem_space.h"
#include "os/sigframe_sparc64rt.h"
#include "os/sync_sig.h"
#include "os/syscall_nr.h"
#include "os/syscalls_min.h"
#include "os/syscalls_sig.h"
#include "os/threads.h"

#define T_BASE UINT64_C(0x100000)
#define T_SPAN UINT64_C(0x10000)
#define T_ACT (T_BASE + UINT64_C(0x000))  /* struct sigaction (32 B). */
#define T_SET (T_BASE + UINT64_C(0x100))  /* {SIGUSR1}. */
#define T_EMPTY (T_BASE + UINT64_C(0x108)) /* {}. */
#define T_TS (T_BASE + UINT64_C(0x110))   /* Zero timespec. */
#define T_OSET (T_BASE + UINT64_C(0x120)) /* rt_sigprocmask old set. */
#define T_PAIR (T_BASE + UINT64_C(0x130)) /* pselect6 {ptr, size}. */
#define T_FLAG (T_BASE + UINT64_C(0x140)) /* "Handler ran" flag. */
#define T_STACK (T_BASE + UINT64_C(0x8000)) /* Unbiased stack top. */
#define T_TA UINT64_C(0x400100)            /* Trapping ta pc. */
#define T_HANDLER UINT64_C(0x400800)
#define T_RESTORER UINT64_C(0x400900)
#define T_USR1_BIT (UINT64_C(1) << (SPARC64_SIG_USR1 - 1U))
#define T_EINTR UINT64_C(4)
#define T_CARRY (SPARC64_CCR_ICC_C | SPARC64_CCR_XCC_C)

static guest_state_t g;
static sparc64_syscall_mem_t ops_storage;
static const sparc64_syscall_mem_t *ops;
static int fails = 0;

static void check(const char *name, int passed)
{
    (void)printf("%s: %s\n", name, passed ? "ok" : "FAIL");
    if (!passed) {
        fails++;
    }
}

static void put_be64(uint8_t out[8], uint64_t v)
{
    unsigned i;
    for (i = 0U; i < 8U; i++) {
        out[7U - i] = (uint8_t)(v & UINT64_C(0xff));
        v >>= 8;
    }
}

static uint64_t get_be64(const uint8_t in[8])
{
    unsigned i;
    uint64_t v = UINT64_C(0);
    for (i = 0U; i < 8U; i++) {
        v = (v << 8) | (uint64_t)in[i];
    }
    return v;
}

static int poke64(uint64_t va, uint64_t v)
{
    uint8_t b[8];
    put_be64(b, v);
    return ops->write(ops->context, va, b, sizeof b) ? 1 : 0;
}

static uint64_t peek64(uint64_t va)
{
    uint8_t b[8] = { 0 };
    (void)ops->read(ops->context, va, b, sizeof b);
    return get_be64(b);
}

/* One syscall trapped at T_TA (pc = ta, npc = ta + 4). */
static void sys(sparc64_ctx_t *ctx, uint64_t nr, uint64_t o0, uint64_t o1,
    uint64_t o2, uint64_t o3, uint64_t o4, uint64_t o5)
{
    ctx->pc = T_TA;
    ctx->npc = T_TA + 4U;
    ctx->r[SPARC64_G1] = nr;
    ctx->r[SPARC64_O0] = o0;
    ctx->r[SPARC64_O0 + 1U] = o1;
    ctx->r[SPARC64_O0 + 2U] = o2;
    ctx->r[SPARC64_O0 + 3U] = o3;
    ctx->r[SPARC64_O0 + 4U] = o4;
    ctx->r[SPARC64_O5] = o5;
    (void)sparc64_handle_syscall(ctx, ops);
}

/* Queue SIGUSR1 while blocked: the handler must not run yet. */
static void queue_usr1(sparc64_ctx_t *ctx, const char *tag)
{
    char name[64];
    sys(ctx, (uint64_t)SPARC64__NR_kill, (uint64_t)getpid(),
        (uint64_t)SPARC64_SIG_USR1, 0U, 0U, 0U, 0U);
    (void)snprintf(name, sizeof name, "%s-queued", tag);
    check(name, ctx->pc == T_TA + 4U && ctx->r[SPARC64_O0] == 0U &&
        (sparc64_sync_sig_pending_get(ctx) & T_USR1_BIT) != 0U);
}

/* After the interrupted wait: handler entry, run it (flag store), then
 * rt_sigreturn and the post-return mask query. */
static void expect_delivery(sparc64_ctx_t *ctx, const char *tag)
{
    char name[64];
    uint64_t frame = ctx->r[SPARC64_SP] + SPARC64_STACK_BIAS;
    (void)snprintf(name, sizeof name, "%s-handler-entry", tag);
    check(name, ctx->pc == T_HANDLER && ctx->npc == T_HANDLER + 4U &&
        ctx->r[SPARC64_O0] == (uint64_t)SPARC64_SIG_USR1 &&
        ctx->r[SPARC64_O7] == T_RESTORER);
    (void)snprintf(name, sizeof name, "%s-frame-tpc", tag);
    check(name, peek64(frame + 0x1c8U) == T_TA + 4U &&
        peek64(frame + 0x1d0U) == T_TA + 8U);
    /* Frame mask is the ORIGINAL mask (not the temporary one); the
     * handler runs with original | self. */
    (void)snprintf(name, sizeof name, "%s-frame-mask-saved", tag);
    check(name, peek64(frame + 0x200U) == T_USR1_BIT);
    (void)snprintf(name, sizeof name, "%s-handler-mask", tag);
    check(name, sparc64_sync_sig_blocked_get(ctx) == T_USR1_BIT &&
        (sparc64_sync_sig_pending_get(ctx) & T_USR1_BIT) == 0U);
    /* Handler body: set the guest flag, then rt_sigreturn (the
     * restorer's ta runs with the handler's %sp). */
    (void)poke64(T_FLAG, UINT64_C(1));
    ctx->pc = T_RESTORER;
    ctx->npc = T_RESTORER + 4U;
    ctx->r[SPARC64_G1] = (uint64_t)SPARC64__NR_rt_sigreturn;
    (void)sparc64_handle_syscall(ctx, ops);
    (void)snprintf(name, sizeof name, "%s-sigreturn-eintr", tag);
    check(name, peek64(T_FLAG) == UINT64_C(1) &&
        ctx->pc == T_TA + 4U && ctx->npc == T_TA + 8U &&
        ctx->r[SPARC64_O0] == T_EINTR &&
        (ctx->ccr & T_CARRY) == T_CARRY);
    sys(ctx, (uint64_t)SPARC64__NR_rt_sigprocmask,
        (uint64_t)SPARC64_SIG_BLOCK, 0U, T_OSET, 8U, 0U, 0U);
    (void)snprintf(name, sizeof name, "%s-mask-restored", tag);
    check(name, ctx->r[SPARC64_O0] == 0U && peek64(T_OSET) == T_USR1_BIT);
    (void)poke64(T_FLAG, UINT64_C(0));
}

static void set_action(sparc64_ctx_t *ctx, uint64_t handler)
{
    (void)poke64(T_ACT, handler);
    (void)poke64(T_ACT + 8U, (uint64_t)SPARC64_SA_SIGINFO);
    (void)poke64(T_ACT + 16U, UINT64_C(0));
    (void)poke64(T_ACT + 24U, UINT64_C(0));
    sys(ctx, (uint64_t)SPARC64__NR_rt_sigaction,
        (uint64_t)SPARC64_SIG_USR1, T_ACT, 0U, T_RESTORER, 8U, 0U);
}

int main(void)
{
    static sparc64_ctx_t ctx;
    int ok;

    (void)memset(&g, 0, sizeof g);
    sparc64_space_init(&g.space, 64U);
    ok = sparc64_space_map(&g.space, T_BASE, T_SPAN,
        (unsigned)(SPARC64_MEM_READ | SPARC64_MEM_WRITE), 0);
    check("map", ok);
    if (!ok) {
        (void)printf("PPOLL-SIGMASK-FAIL n=%d\n", fails);
        return 1;
    }
    ops = sysmem_ops(&g, &ops_storage);
    /* The runner holds the big guest lock across dispatch. */
    sparc64_thread_big_lock();
    sparc64_sync_sig_reset_all();
    sparc64_ctx_init(&ctx, T_TA);
    ctx.r[SPARC64_SP] = T_STACK - SPARC64_STACK_BIAS;
    (void)poke64(T_SET, T_USR1_BIT);
    (void)poke64(T_EMPTY, UINT64_C(0));
    (void)poke64(T_TS, UINT64_C(0));
    (void)poke64(T_TS + 8U, UINT64_C(0));
    (void)poke64(T_PAIR, T_EMPTY);
    (void)poke64(T_PAIR + 8U, UINT64_C(8));

    set_action(&ctx, T_HANDLER);
    check("sigaction", ctx.r[SPARC64_O0] == 0U);
    sys(&ctx, (uint64_t)SPARC64__NR_rt_sigprocmask,
        (uint64_t)SPARC64_SIG_BLOCK, T_SET, 0U, 8U, 0U, 0U);
    check("block-usr1", ctx.r[SPARC64_O0] == 0U &&
        sparc64_sync_sig_blocked_get(&ctx) == T_USR1_BIT);

    /* ppoll(NULL, 0, &zero, &empty, 8). */
    queue_usr1(&ctx, "ppoll");
    sys(&ctx, (uint64_t)SPARC64__NR_ppoll, 0U, 0U, T_TS, T_EMPTY, 8U, 0U);
    expect_delivery(&ctx, "ppoll");

    /* pselect6(0, NULL, NULL, NULL, &zero, &{&empty, 8}). */
    queue_usr1(&ctx, "pselect6");
    sys(&ctx, (uint64_t)SPARC64__NR_pselect6, 0U, 0U, 0U, 0U, T_TS,
        T_PAIR);
    expect_delivery(&ctx, "pselect6");

    /* A temporary mask that keeps SIGUSR1 blocked: plain timeout, no
     * delivery, original mask kept, signal still pending. */
    queue_usr1(&ctx, "ppoll-blocked");
    sys(&ctx, (uint64_t)SPARC64__NR_ppoll, 0U, 0U, T_TS, T_SET, 8U, 0U);
    check("ppoll-blocked-timeout", ctx.pc == T_TA + 4U &&
        ctx.r[SPARC64_O0] == 0U && (ctx.ccr & T_CARRY) == 0U &&
        sparc64_sync_sig_blocked_get(&ctx) == T_USR1_BIT &&
        (sparc64_sync_sig_pending_get(&ctx) & T_USR1_BIT) != 0U);

    /* Disposition switched to SIG_IGN while queued: ppoll still returns
     * -EINTR, pc advances exactly once, nothing runs, mask restored. */
    set_action(&ctx, UINT64_C(1));
    sys(&ctx, (uint64_t)SPARC64__NR_ppoll, 0U, 0U, T_TS, T_EMPTY, 8U, 0U);
    check("ppoll-ign-eintr-once", ctx.pc == T_TA + 4U &&
        ctx.npc == T_TA + 8U && ctx.r[SPARC64_O0] == T_EINTR &&
        (ctx.ccr & T_CARRY) == T_CARRY &&
        sparc64_sync_sig_blocked_get(&ctx) == T_USR1_BIT &&
        (sparc64_sync_sig_pending_get(&ctx) & T_USR1_BIT) == 0U);

    sparc64_thread_big_unlock();
    sparc64_space_destroy(&g.space);
    if (fails == 0) {
        (void)printf("PPOLL-SIGMASK-PASS\n");
        return 0;
    }
    (void)printf("PPOLL-SIGMASK-FAIL n=%d\n", fails);
    return 1;
}
