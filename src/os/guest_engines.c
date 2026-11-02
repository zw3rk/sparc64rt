/*
 * src/os/guest_engines.c — interp/dbt/difftest run loops (coordinator)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Engine loops shared by sparc64_guest_run_engine (guest_run.c): the
 * reference interpreter, the AArch64 DBT, and the lockstep difftest
 * harness. Trap delivery, syscall mirroring, and DBT invalidation are
 * identical across engines by construction.
 */

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core/cpu.h"
#include "dbt/dbt.h"
#include "dbt/difftest.h"
#include "interp/interp_win.h"
#include "os/guest_run_priv.h"
#include "vm/vm64.h"

/* Active quiescence worker table (src/vm/vm64.c); local externs keep
 * this TU off the shared headers, matching guest_run_sysmem.c. */
extern int vm64_worker_register(void);
extern void vm64_worker_unregister(void);
#include "os/sync_sig.h"
#include "os/syscalls_min.h"
#include "os/syscalls_sig.h"
#include "os/threads.h"

/* ---- Engine runners ------------------------------------------------------- */

/* Shared trap path: deliver synchronous signals, report the rest. */
static int run_deliver_trap(guest_state_t *g, sparc64_ctx_t *ctx,
    const sparc64_syscall_mem_t *ops, const sparc64_step_result_t *step)
{
    int code = 0;
    int signo = sparc64_sync_sig_for_trap(step->cause, &code);
    (void)g;
    if (signo > 0 &&
        sparc64_sync_sig_deliver(ctx, ops, signo, code, step->tval) == 0) {
        return 0;
    }
    (void)fprintf(stderr,
                  "sparc64rt: unhandled guest trap: cause=%d pc=0x%llx tval=0x%llx memreason=%d\n",
                  (int)step->cause,
                  (unsigned long long)step->pc,
                  (unsigned long long)step->tval,
                  (int)step->memory_reason);
    return 1;
}

/* ta trap dispatch: a SYSCALL stop leaves pc on the trapping ta, whose
 * low 7 bits select the Linux gate (0x6d syscall, 0x6e setjmp, 0x6f
 * longjmp). Re-read the word here so interp, DBT, and difftest share one
 * branch without touching the frozen step-result contract. */
static unsigned engine_trapno(const sparc64_syscall_mem_t *ops, uint64_t pc)
{
    uint8_t w[4];
    uint32_t word;
    if (!ops->read(ops->context, pc, w, (uint64_t)sizeof(w))) {
        return 0U;
    }
    word = ((uint32_t)w[0] << 24) | ((uint32_t)w[1] << 16) |
        ((uint32_t)w[2] << 8) | (uint32_t)w[3];
    return (unsigned)(word & 0x7FU);
}

static void engine_put64(uint8_t *p, uint64_t v)
{
    unsigned i;
    for (i = 0U; i < 8U; i++) {
        p[i] = (uint8_t)(v >> (56U - 8U * i));
    }
}

static uint64_t engine_get64(const uint8_t *p)
{
    unsigned i;
    uint64_t v = UINT64_C(0);
    for (i = 0U; i < 8U; i++) {
        v = (v << 8U) | (uint64_t)p[i];
    }
    return v;
}

/* setjmp/longjmp buffer (guest jmp_buf at %o0). Guest code touches only
 * +0x40 (longjmp return value, stored by __libc_longjmp before ta 0x6f)
 * and +0x200 (savemask flag word); the rest is kernel-private snapshot:
 * magic @0x00, %sp @0x08, resume pc @0x10, cwp @0x18, %g1..%g7 @0x20..
 * (skipping +0x40), signal mask @0x60, %asi @0x78, ccr @0x80, y @0x88.
 * The mask save/restore is Phase 4 (no mask state exists yet); RC2
 * stores zeros, matching _dl's savemask=0 use in _dl_catch_exception. */
#define ENGINE_SETJMP_MAGIC UINT64_C(0x534A425546310000)

static int engine_setjmp_trap(sparc64_ctx_t *ctx,
    const sparc64_syscall_mem_t *ops, guest_state_t *g, uint64_t pc)
{
    /* Snapshot layout (base = glibc jmp_buf). Slots +0x40 (longjmp
     * return value) and +0x200 (savemask flag) belong to glibc and are
     * never written here; everything else is engine-private. The full
     * out/local/in banks are captured so longjmp can snap back
     * directly instead of walking the window chain (which a signal
     * delivery's fresh stack link would otherwise break). */
    uint8_t jb[0x170];
    uint64_t base = ctx->r[SPARC64_O0];
    sparc64_step_result_t res;
    unsigned i;
    (void)memset(jb, 0, sizeof(jb));
    /* Mirror every outstanding image into its home slot first: fills
     * after a longjmp snap refill from these slots, and post-flush
     * fills are idempotent by construction. Only valid (outstanding)
     * images are written; dead images' homes are live stack space. */
    if (!sparc64_win_flush_all(ctx, &guest_mem_ops, g, &res, pc)) {
        return 1;
    }
    engine_put64(&jb[0x00], ENGINE_SETJMP_MAGIC);
    engine_put64(&jb[0x08], ctx->r[SPARC64_SP]);
    engine_put64(&jb[0x10], ctx->npc);
    engine_put64(&jb[0x18], (uint64_t)ctx->cwp);
    engine_put64(&jb[0x20], ctx->r[SPARC64_G1]);
    engine_put64(&jb[0x28], ctx->r[SPARC64_G2]);
    engine_put64(&jb[0x30], ctx->r[SPARC64_G3]);
    engine_put64(&jb[0x38], ctx->r[SPARC64_G4]);
    engine_put64(&jb[0x48], ctx->r[SPARC64_G5]);
    engine_put64(&jb[0x50], ctx->r[SPARC64_G6]);
    engine_put64(&jb[0x58], ctx->r[SPARC64_G7]);
    engine_put64(&jb[0x78], ctx->asi);
    engine_put64(&jb[0x80], ctx->ccr);
    engine_put64(&jb[0x88], ctx->y);
    for (i = 0U; i < 8U; i++) {
        engine_put64(&jb[0x90] + (uint64_t)i * 8U,
            ctx->r[SPARC64_O0 + i]);
        engine_put64(&jb[0xD0] + (uint64_t)i * 8U,
            ctx->r[SPARC64_L0 + i]);
        engine_put64(&jb[0x110] + (uint64_t)i * 8U,
            ctx->r[SPARC64_I0 + i]);
    }
    engine_put64(&jb[0x150], sparc64_sync_sig_blocked_get());
    engine_put64(&jb[0x158], (uint64_t)ctx->cansave);
    engine_put64(&jb[0x160], (uint64_t)ctx->canrestore);
    engine_put64(&jb[0x168], (uint64_t)ctx->otherwin);
    if (!ops->write(ops->context, base, jb, (uint64_t)sizeof(jb))) {
        return 1;
    }
    /* First return: 0 in %g1, resume at ctx->npc (past the ta). */
    ctx->r[SPARC64_G1] = UINT64_C(0);
    ctx->pc = ctx->npc;
    ctx->npc = ctx->pc + 4U;
    return 0;
}

static int engine_longjmp_trap(sparc64_ctx_t *ctx,
    const sparc64_syscall_mem_t *ops, guest_state_t *g, uint64_t pc)
{
    /* Snapshot layout is defined by engine_setjmp_trap; +0x40 (glibc
     * return value) and +0x200 (glibc savemask flag) are read here. */
    uint8_t jb[0x170];
    uint8_t w8[8];
    uint64_t base = ctx->r[SPARC64_O0];
    uint64_t val;
    uint64_t flag;
    uint64_t rpc;
    uint64_t cwp;
    unsigned i;
    (void)g;
    (void)pc;
    if (!ops->read(ops->context, base, jb, (uint64_t)sizeof(jb))) {
        return 1;
    }
    if (engine_get64(&jb[0x00]) != ENGINE_SETJMP_MAGIC) {
        return 1;
    }
    val = engine_get64(&jb[0x40]);
    rpc = engine_get64(&jb[0x10]);
    cwp = engine_get64(&jb[0x18]);
    if (cwp >= (uint64_t)SPARC64_NWINDOWS || rpc == UINT64_C(0) ||
        (rpc & UINT64_C(3)) != UINT64_C(0)) {
        return 1;
    }
    if (!ops->read(ops->context, base + UINT64_C(0x200), w8,
            (uint64_t)sizeof(w8))) {
        return 1;
    }
    flag = engine_get64(w8);
    /* Direct snap back to the setjmp state: restore the full register
     * file from the snapshot and drop the window cache so later
     * fills rebuild from the flushed home slots. Walking the window
     * chain instead cannot work across a signal delivery, whose
     * handler frame links back through a fresh stack link rather than
     * the interrupted stack pointer. */
    ctx->r[SPARC64_SP] = engine_get64(&jb[0x08]);
    ctx->cwp = (unsigned)cwp;
    ctx->r[SPARC64_G1] = val;
    ctx->r[SPARC64_G2] = engine_get64(&jb[0x28]);
    ctx->r[SPARC64_G3] = engine_get64(&jb[0x30]);
    ctx->r[SPARC64_G4] = engine_get64(&jb[0x38]);
    ctx->r[SPARC64_G5] = engine_get64(&jb[0x48]);
    ctx->r[SPARC64_G6] = engine_get64(&jb[0x50]);
    ctx->r[SPARC64_G7] = engine_get64(&jb[0x58]);
    for (i = 0U; i < 8U; i++) {
        ctx->r[SPARC64_O0 + i] = engine_get64(&jb[0x90] +
            (uint64_t)i * 8U);
        ctx->r[SPARC64_L0 + i] = engine_get64(&jb[0xD0] +
            (uint64_t)i * 8U);
        ctx->r[SPARC64_I0 + i] = engine_get64(&jb[0x110] +
            (uint64_t)i * 8U);
    }
    ctx->asi = engine_get64(&jb[0x78]);
    ctx->ccr = engine_get64(&jb[0x80]);
    ctx->y = engine_get64(&jb[0x88]);
    ctx->cansave = (unsigned)engine_get64(&jb[0x158]);
    ctx->canrestore = (unsigned)engine_get64(&jb[0x160]);
    ctx->otherwin = (unsigned)engine_get64(&jb[0x168]);
    sparc64_win_invalidate_all();
    if (flag != UINT64_C(0)) {
        uint64_t saved = engine_get64(&jb[0x150]);
        /* SIGKILL/SIGSTOP can never be blocked. */
        saved &= ~(SPARC64_SIGKILL_BIT | SPARC64_SIGSTOP_BIT);
        sparc64_sync_sig_blocked_set(saved);
    }
    ctx->pc = rpc;
    ctx->npc = rpc + 4U;
    return 0;
}

/* Reference interpreter loop (engine 0). Returns the guest exit status. */
int run_interp(guest_state_t *g, sparc64_ctx_t *ctx,
    const sparc64_syscall_mem_t *ops)
{
    /* L4b: register the main thread and serialize execution across
     * threads (shared interp winfile / shared space metadata). Child
     * threads reuse this same loop; futex WAIT drops the lock while
     * it sleeps so a waker can run. */
    sparc64_threads_boot(ops, 0, ctx);
    sparc64_thread_big_lock();
    /* Every lock acquisition starts with a clean window cache (see the
     * futex handoff in threads.c): cached images belong to whichever
     * thread cached them, so refill from our own homes on demand. */
    sparc64_win_invalidate_all();
    for (;;) {
        sparc64_step_result_t step = sparc64_step(ctx, &guest_mem_ops, g);
        if (step.kind == SPARC64_STEP_SYSCALL) {
            unsigned trapno = engine_trapno(ops, step.pc);
            if (trapno == 0x6eU) {
                if (engine_setjmp_trap(ctx, ops, g, step.pc) != 0) {
                    return 1;
                }
            } else if (trapno == 0x6fU) {
                if (engine_longjmp_trap(ctx, ops, g, step.pc) != 0) {
                    return 1;
                }
            } else {
                long nr = (long)ctx->r[SPARC64_G1];
                long status = sparc64_handle_syscall(ctx, ops);
                if (sparc64_syscall_is_exit(nr)) {
                    if (sparc64_syscall_is_group_exit(nr)) {
                        sparc64_threads_note_group_exit(status);
                    }
                    sparc64_thread_big_unlock();
                    return (int)(status & 0xffL);
                }
            }
        } else if (step.kind == SPARC64_STEP_TRAP) {
            if (run_deliver_trap(g, ctx, ops, &step) != 0) {
                sparc64_thread_big_unlock();
                return 1;
            }
        } else if (step.kind != SPARC64_STEP_CONTINUE) {
            (void)fprintf(stderr,
                          "sparc64rt: guest stopped: kind=%d cause=%d pc=0x%llx\n",
                          (int)step.kind, (int)step.cause,
                          (unsigned long long)step.pc);
            sparc64_thread_big_unlock();
            return 1;
        }
    }
}

/* DBT loop (engine 1): same stops as the interpreter, translated. */
int run_dbt(guest_state_t *g, sparc64_ctx_t *ctx,
    const sparc64_syscall_mem_t *ops)
{
    /* Heap, not stack: sparc64_dbt_t is ~70KB and CLONE_VM children run
     * on host threads with musl's 80KB default stack. A stack instance
     * overflowed the child stack on entry (SIGSEGV before first insn). */
    sparc64_dbt_t *dbt = calloc(1U, sizeof(*dbt));
    int rc;
    if (dbt == NULL || sparc64_dbt_init(dbt) != 0) {
        (void)fprintf(stderr, "sparc64rt: cannot init DBT\n");
        free(dbt);
        return 1;
    }
    /* L4b: same boot/serialization as run_interp. DBT instances stay
     * per-thread (no cache locking); re-assert g->dbt every iteration
     * because a sibling thread may have pointed it at its own DBT
     * while this thread slept in a blocking syscall. */
    uint64_t seen_epoch;
    sparc64_threads_boot(ops, 1, ctx);
    sparc64_thread_big_lock();
    /* Same clean-cache rule as the interp loop (shared winfile). */
    sparc64_win_invalidate_all();
    g->dbt = dbt;
    /* S64-R3-1: snapshot the shared code generation. A peer's mapping
     * change while this thread slept (futex wait, blocking syscall)
     * bumps it at commit; the check below flushes this thread's own
     * blocks and chaining entries before any cached execution. */
    seen_epoch = vm64_code_epoch_get();
    rc = 1;
    for (;;) {
        sparc64_step_result_t step;
        g->dbt = dbt;
        if (vm64_code_epoch_get() != seen_epoch) {
            sparc64_dbt_invalidate(dbt, 0U, SPARC64_TASK_SIZE);
            seen_epoch = vm64_code_epoch_get();
        }
        step = sparc64_dbt_run(ctx, &guest_mem_ops, g, dbt);
        if (step.kind == SPARC64_STEP_SYSCALL) {
            unsigned trapno = engine_trapno(ops, step.pc);
            if (trapno == 0x6eU) {
                if (engine_setjmp_trap(ctx, ops, g, step.pc) != 0) {
                    break;
                }
            } else if (trapno == 0x6fU) {
                if (engine_longjmp_trap(ctx, ops, g, step.pc) != 0) {
                    break;
                }
            } else {
                long nr = (long)ctx->r[SPARC64_G1];
                long status = sparc64_handle_syscall(ctx, ops);
                if (sparc64_syscall_is_exit(nr)) {
                    if (sparc64_syscall_is_group_exit(nr)) {
                        sparc64_threads_note_group_exit(status);
                    }
                    rc = (int)(status & 0xffL);
                    break;
                }
            }
        } else if (step.kind == SPARC64_STEP_TRAP) {
            if (run_deliver_trap(g, ctx, ops, &step) != 0) {
                break;
            }
        } else if (step.kind != SPARC64_STEP_CONTINUE) {
            (void)fprintf(stderr,
                          "sparc64rt: guest stopped: kind=%d cause=%d pc=0x%llx\n",
                          (int)step.kind, (int)step.cause,
                          (unsigned long long)step.pc);
            break;
        }
    }
    g->dbt = NULL;
    sparc64_thread_big_unlock();
    sparc64_dbt_fini(dbt);
    free(dbt);
    return rc;
}

/* ---- Phase 4 L4b thread entry/loop ---------------------------------------- */

/* Host-thread entry for one CLONE_VM thread: reuse the engine loop the
 * process booted with (interp or DBT) on the slot's own ctx, then
 * finalize through threads.c (CLEARTID + wake, mark done). The engine
 * loop re-acquires the big guest lock; only exit_group arms the group
 * flag, a plain thread exit ends just this slot. */
void *sparc64_thread_entry(void *arg)
{
    sparc64_thread_t *slot = (sparc64_thread_t *)arg;
    guest_state_t *g;
    long rc;
    if (slot == NULL) {
        return NULL;
    }
    sparc64_thread_entry_started(slot);
    /* RC-U4 #3: join the vm64 quiescence worker table for the whole
     * worker lifetime, so a concurrent prepare preempts (or parks)
     * this thread instead of missing it. S64-R3-5: on exhaustion
     * refuse to run guest code unregistered (no preemption). */
    if (vm64_worker_register() != 0) {
        vm64_worker_unregister();
        sparc64_thread_entry_done(slot, 1L);
        return NULL;
    }
    g = (guest_state_t *)slot->space_ctx;
    if (slot->engine == 1) {
        rc = (long)run_dbt(g, slot->ctx_ref, slot->ops);
    } else {
        rc = (long)run_interp(g, slot->ctx_ref, slot->ops);
    }
    vm64_worker_unregister();
    sparc64_thread_entry_done(slot, rc);
    return NULL;
}

/* Difftest syscall hook: run once on the interp copy, mirror to dbt. */
typedef struct {
    const sparc64_syscall_mem_t *ops;
    guest_state_t *g;
} diff_hook_arg_t;

static long diff_syscall_hook(sparc64_ctx_t *ic, void *arg, int *is_exit)
{
    diff_hook_arg_t *h = (diff_hook_arg_t *)arg;
    unsigned trapno = engine_trapno(h->ops, ic->pc);
    long nr;
    long status;
    if (trapno == 0x6eU) {
        if (engine_setjmp_trap(ic, h->ops, h->g, ic->pc) != 0) {
            *is_exit = 1;
            return 1L;
        }
        *is_exit = 0;
        return 0L;
    }
    if (trapno == 0x6fU) {
        if (engine_longjmp_trap(ic, h->ops, h->g, ic->pc) != 0) {
            *is_exit = 1;
            return 1L;
        }
        *is_exit = 0;
        return 0L;
    }
    nr = (long)ic->r[SPARC64_G1];
    status = sparc64_handle_syscall(ic, h->ops);
    *is_exit = sparc64_syscall_is_exit(nr);
    return status;
}

/* Difftest trap hook: synchronous signal delivery on one copy. */
static int diff_trap_hook(sparc64_ctx_t *c, void *arg, int signo, int code,
    uint64_t fault_addr)
{
    diff_hook_arg_t *h = (diff_hook_arg_t *)arg;
    return sparc64_sync_sig_deliver(c, h->ops, signo, code, fault_addr);
}

/* Difftest loop (engine 2): lockstep interp-vs-dbt from the same load. */
int run_difftest(guest_state_t *g, sparc64_ctx_t *ctx,
    const sparc64_syscall_mem_t *ops)
{
    sparc64_dbt_t dbt;
    sparc64_difftest_cfg_t cfg;
    diff_hook_arg_t hook;
    int rc;
    if (sparc64_dbt_init(&dbt) != 0) {
        (void)fprintf(stderr, "sparc64rt: cannot init DBT\n");
        return 1;
    }
    memset(&cfg, 0, sizeof(cfg));
    hook.ops = ops;
    hook.g = g;
    cfg.mem = &guest_mem_ops;
    cfg.mc = g;
    cfg.dbt = &dbt;
    cfg.dbt_step = sparc64_dbt_step_one;
    cfg.syscall = diff_syscall_hook;
    cfg.syscall_arg = &hook;
    cfg.trap_deliver = diff_trap_hook;
    cfg.trap_arg = &hook;
    rc = sparc64_difftest_run(&cfg, ctx);
    sparc64_dbt_fini(&dbt);
    return rc;
}

