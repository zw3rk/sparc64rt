/*
 * src/os/syscalls_sig.c — Phase 4 signal syscalls (L4a).
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Exact-Linux-UAPI signal syscalls for the SPARC64 guest: the 5-arg
 * rt_sigaction with mask persistence and old-action return, the real
 * rt_sigprocmask (blocked load/store plus pending-unblock delivery),
 * sigaltstack state, and kill/tkill/tgkill self-delivery. Dispatch
 * case arms live in src/os/syscalls_min.c only.
 *
 * Numbers are the frozen SPARC64 UAPI values (src/os/syscall_nr.h):
 * kill is 37 (the lane card's "62" is a typo; the frozen table and the
 * E04 oracle agree on 37), tkill 187, tgkill 211, sigaltstack 28,
 * rt_sigprocmask 103, rt_sigaction 102, rt_sigreturn 101.
 *
 * Syscall convention notes (E04 + L4a oracle probes under qemu-sparc64):
 * - Success clears only xcc.C (icc is preserved); error sets both
 *   carry bits. The frozen layer commits both-move; this file follows
 *   it for visible state and restores the trap-time icc.C only on the
 *   synchronous-delivery path, where the frame's tstate would otherwise
 *   diverge from the oracle (e.g. 0x8982001207 for a 0x99 trap).
 * - A delivered signal captures the POST-syscall pc/npc (the handler
 *   resumes past the trapping ta), so these handlers commit and
 *   advance before delivering and report *delivered for the dispatch
 *   tail to skip (mirroring rt_sigreturn's early return).
 * - Cross-thread targeting (pid/tid outside this thread) returns
 *   ESRCH: L4b's thread table owns routing once threads exist.
 */

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

#include "core/cpu.h"
#include "os/sigframe_sparc64rt.h"
#include "os/sync_sig.h"
#include "os/syscall_nr.h"
#include "os/syscalls_ext.h"
#include "os/syscalls_min.h"
#include "os/syscalls_sig.h"

/* Commit success and advance past the trapping ta (delivery captures
 * the post-syscall pc/npc as tpc/tnpc). Uses the shared dual-carry
 * commit from src/os/syscalls_min.c. */
static void sig_commit_advance(sparc64_ctx_t *ctx, long ret)
{
    sparc64_commit_sysret(ctx, ret);
    ctx->pc = ctx->npc;
    ctx->npc += 4U;
}

/* Fatal signal condition (SIGKILL, or no handler installed): report,
 * disarm every handler so the forced fault below cannot be caught,
 * and park pc on the always-unmapped zero page. The next step faults
 * INST_ACCESS, whose SIGSEGV finds no handler, so the engines return
 * the runner-fatal status. */
void sparc64_sig_force_fatal(sparc64_ctx_t *ctx,
    const sparc64_syscall_mem_t *mem, int signo)
{
    (void)mem;
    (void)fprintf(stderr, "sparc64rt: unhandled guest signal: signo=%d\n",
        signo);
    sparc64_sync_sig_reset_all();
    ctx->pc = UINT64_C(0);
    ctx->npc = UINT64_C(4);
}

long sparc64_sig_rt_sigaction(sparc64_ctx_t *ctx,
    const sparc64_syscall_mem_t *mem, uint64_t sig, uint64_t act_va,
    uint64_t oact_va, uint64_t restorer, uint64_t sigsetsize)
{
    uint8_t raw[32];
    uint64_t old_handler;
    uint64_t old_flags;
    uint64_t old_restorer;
    uint64_t old_mask;
    unsigned i;
    long rc;
    (void)ctx;
    if (sig == 0U || sig > (uint64_t)SPARC64_SIG_MAX ||
        sigsetsize != 8U) {
        return -EINVAL;
    }
    rc = (long)sparc64_sync_sig_query(sig, &old_handler, &old_flags,
        &old_restorer, &old_mask);
    if (rc != 0) {
        return rc;
    }
    if (act_va != UINT64_C(0)) {
        uint64_t handler = UINT64_C(0);
        uint64_t flags = UINT64_C(0);
        uint64_t mask = UINT64_C(0);
        uint64_t rst = UINT64_C(0);
        if (!mem->read(mem->context, act_va, raw, (uint64_t)sizeof(raw))) {
            return -EFAULT;
        }
        for (i = 0U; i < 8U; i++) {
            handler = (handler << 8U) | (uint64_t)raw[i];
            flags = (flags << 8U) | (uint64_t)raw[8U + i];
            rst = (rst << 8U) | (uint64_t)raw[16U + i];
            mask = (mask << 8U) | (uint64_t)raw[24U + i];
        }
        rc = (long)sparc64_sync_sig_install_full(sig, handler, flags,
            (handler == UINT64_C(0) || handler == UINT64_C(1)) ?
            UINT64_C(0) : restorer, mask);
        if (rc != 0) {
            return rc;
        }
    }
    /* The oracle (qemu-sparc64) reports the restorer slot as zero in
     * the old action even when a restorer was installed; match that
     * observable (the live restorer still feeds the handler's %o7). */
    (void)old_restorer;
    if (oact_va != UINT64_C(0)) {
        for (i = 0U; i < 8U; i++) {
            raw[i] = (uint8_t)(old_handler >> (56U - 8U * i));
            raw[8U + i] = (uint8_t)(old_flags >> (56U - 8U * i));
            raw[16U + i] = 0U;
            raw[24U + i] = (uint8_t)(old_mask >> (56U - 8U * i));
        }
        if (!mem->prepare_write(mem->context, oact_va,
                (uint64_t)sizeof(raw))) {
            return -EFAULT;
        }
        if (!mem->write(mem->context, oact_va, raw,
                (uint64_t)sizeof(raw))) {
            return -EFAULT;
        }
    }
    return 0L;
}

long sparc64_sig_rt_sigprocmask(sparc64_ctx_t *ctx,
    const sparc64_syscall_mem_t *mem, uint64_t how, uint64_t set_va,
    uint64_t oset_va, uint64_t sigsetsize, int *delivered)
{
    uint8_t old[8];
    uint8_t raw[8];
    uint64_t prev;
    uint64_t trap_ccr;
    unsigned i;
    int pending_rc;
    if (delivered != NULL) {
        *delivered = 0;
    }
    if (sigsetsize != 8U) {
        return -EINVAL;
    }
    if (how != (uint64_t)SPARC64_SIG_BLOCK &&
        how != (uint64_t)SPARC64_SIG_UNBLOCK &&
        how != (uint64_t)SPARC64_SIG_SETMASK) {
        return -EINVAL;
    }
    prev = sparc64_sync_sig_blocked_get(ctx);
    for (i = 0U; i < (unsigned)sizeof(old); i++) {
        old[i] = (uint8_t)(prev >> (56U - 8U * i));
    }
    if (set_va != UINT64_C(0)) {
        if (l2a_range_ok(set_va, (uint64_t)sizeof(raw)) != 0) {
            return -EFAULT;
        }
        if (!mem->read(mem->context, set_va, raw,
                (uint64_t)sizeof(raw))) {
            return -EFAULT;
        }
        {
            uint64_t set = l2a_get_be64(raw) &
                ~(SPARC64_SIGKILL_BIT | SPARC64_SIGSTOP_BIT);
            uint64_t updated = set;
            if (how == (uint64_t)SPARC64_SIG_BLOCK) {
                updated = prev | set;
            } else if (how == (uint64_t)SPARC64_SIG_UNBLOCK) {
                updated = prev & ~set;
            }
            sparc64_sync_sig_blocked_set(ctx, updated);
        }
    }
    if (oset_va != UINT64_C(0)) {
        if (l2a_store_buf(mem, oset_va, old,
                (uint64_t)sizeof(old)) != 0) {
            return -EFAULT;
        }
    }
    /* Success commits here (the dispatch tail is skipped): unblock
     * delivery below must see the post-syscall pc. */
    trap_ccr = ctx->ccr;
    sig_commit_advance(ctx, 0L);
    ctx->ccr |= trap_ccr & SPARC64_CCR_ICC_C;
    pending_rc = sparc64_sync_sig_deliver_pending(ctx, mem);
    if (pending_rc < 0) {
        sparc64_sig_force_fatal(ctx, mem, 0);
    }
    if (delivered != NULL) {
        *delivered = 1;
    }
    return 0L;
}

/* rt_sigpending: report the queued-signal set (BE64, 8 bytes). The
 * size must be 8 like the rest of the rt family; a NULL set faults. */
long sparc64_sig_rt_sigpending(sparc64_ctx_t *ctx,
    const sparc64_syscall_mem_t *mem, uint64_t set_va,
    uint64_t sigsetsize)
{
    uint8_t out[8];
    uint64_t pend;
    unsigned i;
    if (sigsetsize != 8U) {
        return -EINVAL;
    }
    if (set_va == UINT64_C(0)) {
        return -EFAULT;
    }
    pend = sparc64_sync_sig_pending_get(ctx);
    for (i = 0U; i < (unsigned)sizeof(out); i++) {
        out[i] = (uint8_t)(pend >> (56U - 8U * i));
    }
    if (l2a_store_buf(mem, set_va, out, (uint64_t)sizeof(out)) != 0) {
        return -EFAULT;
    }
    return 0L;
}

long sparc64_sig_sigaltstack(sparc64_ctx_t *ctx,
    const sparc64_syscall_mem_t *mem, uint64_t uss_va,
    uint64_t uoss_va)
{
    uint8_t raw[24];
    uint8_t old[24];
    uint64_t sp = UINT64_C(0);
    uint64_t flags = UINT64_C(0);
    uint64_t size = UINT64_C(0);
    int have_new = 0;
    long rc;
    /* Snapshot the new stack first: when uss and uoss alias (or
     * overlap), writing the old state below must not destroy the
     * input before it is read. No live state changes until both
     * directions validate. */
    if (uss_va != UINT64_C(0)) {
        if (l2a_range_ok(uss_va, (uint64_t)sizeof(raw)) != 0) {
            return -EFAULT;
        }
        if (!mem->read(mem->context, uss_va, raw,
                (uint64_t)sizeof(raw))) {
            return -EFAULT;
        }
        sp = l2a_get_be64(raw);
        flags = (uint64_t)l2a_get_be32(raw + 8);
        size = l2a_get_be64(raw + 16);
        have_new = 1;
    }
    if (uoss_va != UINT64_C(0)) {
        uint64_t osp;
        uint64_t oflags;
        uint64_t osize;
        unsigned i;
        uint64_t cur = ctx->r[SPARC64_SP] + SPARC64_STACK_BIAS;
        sparc64_sync_sig_altstack_get(ctx, &osp, &oflags, &osize, cur);
        for (i = 0U; i < 8U; i++) {
            old[i] = (uint8_t)(osp >> (56U - 8U * i));
            old[16U + i] = (uint8_t)(osize >> (56U - 8U * i));
        }
        old[8] = (uint8_t)(oflags >> 24);
        old[9] = (uint8_t)(oflags >> 16);
        old[10] = (uint8_t)(oflags >> 8);
        old[11] = (uint8_t)oflags;
        old[12] = 0U;
        old[13] = 0U;
        old[14] = 0U;
        old[15] = 0U;
        rc = l2a_store_buf(mem, uoss_va, old, (uint64_t)sizeof(old));
        if (rc != 0) {
            return rc;
        }
    }
    if (have_new != 0) {
        return sparc64_sync_sig_altstack_set(ctx, sp, flags, size);
    }
    return 0L;
}

/* Self-delivery core shared by kill/tkill/tgkill: the caller verified
 * the target names this thread and the signo is nonzero. Commits,
 * advances, applies the oracle carry shape, and delivers or queues. */
static long sig_deliver_self(sparc64_ctx_t *ctx,
    const sparc64_syscall_mem_t *mem, uint64_t sig, int *delivered)
{
    uint64_t trap_ccr = ctx->ccr;
    int rc;
    sig_commit_advance(ctx, 0L);
    ctx->ccr |= trap_ccr & SPARC64_CCR_ICC_C;
    rc = sparc64_sync_sig_queue(ctx, mem, (int)sig);
    if (rc < 0) {
        sparc64_sig_force_fatal(ctx, mem, (int)sig);
    }
    if (delivered != NULL) {
        *delivered = 1;
    }
    return 0L;
}

long sparc64_sig_kill(sparc64_ctx_t *ctx,
    const sparc64_syscall_mem_t *mem, uint64_t pid, uint64_t sig,
    int *delivered)
{
    uint64_t self;
    if (delivered != NULL) {
        *delivered = 0;
    }
    if (sig > (uint64_t)SPARC64_SIG_MAX) {
        return -EINVAL;
    }
    self = (uint64_t)getpid();
    if (pid != self && pid != UINT64_C(0)) {
        return -ESRCH;
    }
    if (sig == UINT64_C(0)) {
        return 0L;
    }
    return sig_deliver_self(ctx, mem, sig, delivered);
}

long sparc64_sig_tkill(sparc64_ctx_t *ctx,
    const sparc64_syscall_mem_t *mem, uint64_t tid, uint64_t sig,
    int *delivered)
{
    if (delivered != NULL) {
        *delivered = 0;
    }
    if (sig > (uint64_t)SPARC64_SIG_MAX) {
        return -EINVAL;
    }
    if (tid != (uint64_t)getpid()) {
        return -ESRCH;
    }
    if (sig == UINT64_C(0)) {
        return 0L;
    }
    return sig_deliver_self(ctx, mem, sig, delivered);
}

long sparc64_sig_tgkill(sparc64_ctx_t *ctx,
    const sparc64_syscall_mem_t *mem, uint64_t tgid, uint64_t tid,
    uint64_t sig, int *delivered)
{
    uint64_t self;
    if (delivered != NULL) {
        *delivered = 0;
    }
    if (sig > (uint64_t)SPARC64_SIG_MAX) {
        return -EINVAL;
    }
    self = (uint64_t)getpid();
    if (tgid != self || tid != self) {
        return -ESRCH;
    }
    if (sig == UINT64_C(0)) {
        return 0L;
    }
    return sig_deliver_self(ctx, mem, sig, delivered);
}
