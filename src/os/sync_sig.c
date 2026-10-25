/*
 * src/os/sync_sig.c — exact Linux UAPI guest signal delivery (Phase 4, L4a)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Frame layout follows SPEC 2.1 / E04 (rt_signal_frame64, 528-byte header
 * plus the always-present 280-byte inline sigfpu tail: 32 doubles, fsr,
 * gsr, fprs; total 808 bytes):
 * ss 192 @0x000, info 128 @0x0c0, regs 160 @0x140 (tstate @0x1c0,
 * tpc @0x1c8, tnpc @0x1d0, y @0x1d8, magic @0x1dc), fpu_save @0x1e0,
 * stack 24 @0x1e8, mask 8 @0x200, rwin_save 8 @0x208, sigfpu 280 @0x210.
 *
 * Oracle ground truth (qemu-sparc64, experiments/E04 + L4a probes):
 * - Handler entry (SA_SIGINFO): %o0 = signo, %o1 == %o2 == base+0xC0
 *   (&info both), %o7 = restorer, biased %sp, pc/npc = handler/+4.
 * - tstate = (ccr << 32) | (asi << 24) | 0x1200 | ((7 - cwp) & 7);
 *   asi defaults to 0x82 (PRIMARY_NOFAULT); tpc/tnpc name the
 *   interrupted pc/npc; y and PT_REGS_MAGIC carried verbatim.
 * - Register windows are flushed before capture (win_flush_all); the
 *   ss slot is the 128-byte copy of [interrupted %sp + 2047], which is
 *   zeroed for leaf flows and the spill image below a SAVE.
 *   rwin_save is 0 (Linux keeps spilled windows on the user stack;
 *   probed 0 at SAVE depth 0 and 1; deeper nesting is recorded the
 *   same way since every window has a stack home after the flush).
 * - mask @0x200 carries the pre-delivery blocked set; delivery computes
 *   new = (old | act.sa_mask | sigbit) & ~(KILL|STOP) (self-block unless
 *   SA_NODEFER, matching the oracle's curmask query); sigreturn
 *   restores it. stack @0x1e8 carries the current altstack unchanged.
 *   Delivery uses the altstack top when an enabled altstack exists, the
 *   handler asked SA_ONSTACK, and the interrupted stack is not already
 *   on it.
 * - siginfo: SI_USER (live pid/uid) for the kill family (code 0);
 *   SEGV_MAPERR + fault VA, ILL_ILLOPC + fault pc, BUS_ADRALN + fault
 *   VA, FPE_INTDIV + fault pc for traps; si_trapno is 0 (the oracle
 *   provides none). Integer divide forms and trap instructions arrive
 *   as ILLEGAL traps, so the deliver path refines them from the raw
 *   word (cause-level mapping cannot tell them apart).
 * - Pending set per thread; the blocked mask gates delivery. Fault
 *   delivery is unconditional (synchronous urgency). SIGKILL cannot be
 *   caught or blocked (fatal); SIGSTOP cannot be caught or blocked
 *   (no-op: a single-threaded translator has nothing to stop).
 * - Old sigreturn(216) stays -ENOSYS (dispatch default; documented).
 *
 * Delivery model (all lanes): signals deliver at fault traps, at
 * self-kill/tkill/tgkill, at rt_sigprocmask-unblock, at sigreturn when
 * the restored mask unblocks pending, and at the futex-WAIT EINTR
 * check only. No async host-signal injection.
 */

#include "os/sync_sig.h"

#include <errno.h>
#include <unistd.h>

#include "core/cpu.h"
#include "interp/interp.h"
#include "os/sigframe_sparc64rt.h"
#include "os/syscalls_min.h"
#include "os/syscalls_sig.h"

/* The guest window flush runs over the runner's address space. */
extern const sparc64_mem_ops_t guest_mem_ops;

#define SYNC_SIG_MAX 64U

static uint64_t sync_handler[SYNC_SIG_MAX + 1U];
static uint64_t sync_flags[SYNC_SIG_MAX + 1U];
static uint64_t sync_restorer[SYNC_SIG_MAX + 1U];
static uint64_t sync_sa_mask[SYNC_SIG_MAX + 1U];

/* Single-threaded signal state (L4b introduces the thread table and
 * routes cross-thread kills to ESRCH until threads exist). */
static uint64_t sync_blocked = UINT64_C(0);
static uint64_t sync_pending = UINT64_C(0);
static uint64_t sync_ss_sp = UINT64_C(0);
static uint64_t sync_ss_size = UINT64_C(0);
static uint64_t sync_ss_flags = (uint64_t)SPARC64_SS_DISABLE;

int sparc64_sync_sig_install(uint64_t sig, uint64_t handler_va,
    uint64_t restorer_va)
{
    if (sig == 0U || sig > (uint64_t)SYNC_SIG_MAX) {
        return -EINVAL;
    }
    sync_handler[sig] = handler_va;
    sync_restorer[sig] = restorer_va;
    return 0;
}

int sparc64_sync_sig_install_full(uint64_t sig, uint64_t handler,
    uint64_t flags, uint64_t restorer, uint64_t mask)
{
    uint64_t allowed;
    if (sig == 0U || sig > (uint64_t)SYNC_SIG_MAX) {
        return -EINVAL;
    }
    if (sig == (uint64_t)SPARC64_SIG_KILL ||
        sig == (uint64_t)SPARC64_SIG_STOP) {
        return -EINVAL;
    }
    allowed = (uint64_t)SPARC64_SA_SIGINFO |
        (uint64_t)SPARC64_SA_ONSTACK | (uint64_t)SPARC64_SA_NODEFER;
    if ((flags & ~allowed) != UINT64_C(0) ||
        (flags & (uint64_t)SPARC64_SA_SIGINFO) == UINT64_C(0)) {
        return -EINVAL;
    }
    if (handler != UINT64_C(0) && handler != UINT64_C(1) &&
        restorer == UINT64_C(0)) {
        return -EINVAL;
    }
    sync_handler[sig] = handler;
    sync_flags[sig] = flags;
    sync_restorer[sig] = restorer;
    sync_sa_mask[sig] = mask;
    return 0;
}

int sparc64_sync_sig_query(uint64_t sig, uint64_t *handler,
    uint64_t *flags, uint64_t *restorer, uint64_t *mask)
{
    if (sig == 0U || sig > (uint64_t)SYNC_SIG_MAX) {
        return -EINVAL;
    }
    if (handler != NULL) {
        *handler = sync_handler[sig];
    }
    if (flags != NULL) {
        *flags = sync_flags[sig];
    }
    if (restorer != NULL) {
        *restorer = sync_restorer[sig];
    }
    if (mask != NULL) {
        *mask = sync_sa_mask[sig];
    }
    return 0;
}

uint64_t sparc64_sync_sig_blocked_get(void)
{
    return sync_blocked;
}

void sparc64_sync_sig_blocked_set(uint64_t mask)
{
    sync_blocked = mask;
}

uint64_t sparc64_sync_sig_pending_get(void)
{
    return sync_pending;
}

long sparc64_sync_sig_altstack_set(uint64_t sp, uint64_t flags,
    uint64_t size)
{
    if ((flags & ~(uint64_t)SPARC64_SS_DISABLE) != UINT64_C(0)) {
        return -EINVAL;
    }
    if ((flags & (uint64_t)SPARC64_SS_DISABLE) == 0U) {
        uint64_t end;
        if (size < (uint64_t)SPARC64_MINSIGSTKSZ) {
            return -ENOMEM;
        }
        end = sp + size;
        if (end < sp || end > (uint64_t)SPARC64_TASK_SIZE) {
            return -ENOMEM;
        }
    }
    sync_ss_sp = sp;
    sync_ss_flags = flags;
    sync_ss_size = size;
    return 0L;
}

void sparc64_sync_sig_altstack_get(uint64_t *sp, uint64_t *flags,
    uint64_t *size, uint64_t cur_sp_unbiased)
{
    if (sp != NULL) {
        *sp = sync_ss_sp;
    }
    if (flags != NULL) {
        uint64_t f = sync_ss_flags;
        /* SS_ONSTACK is dynamic: report it when the stack is enabled
         * and the current stack pointer is inside its range. */
        if ((f & (uint64_t)SPARC64_SS_DISABLE) == UINT64_C(0) &&
            sync_ss_sp != UINT64_C(0)) {
            uint64_t end = sync_ss_sp + sync_ss_size;
            if (end >= sync_ss_sp && cur_sp_unbiased >= sync_ss_sp &&
                cur_sp_unbiased < end) {
                f |= (uint64_t)SPARC64_SS_ONSTACK;
            }
        }
        *flags = f;
    }
    if (size != NULL) {
        *size = sync_ss_size;
    }
}

void sparc64_sync_sig_reset_all(void)
{
    unsigned i;
    for (i = 0U; i <= SYNC_SIG_MAX; i++) {
        sync_handler[i] = UINT64_C(0);
        sync_flags[i] = UINT64_C(0);
        sync_restorer[i] = UINT64_C(0);
        sync_sa_mask[i] = UINT64_C(0);
    }
    sync_blocked = UINT64_C(0);
    sync_pending = UINT64_C(0);
    sync_ss_sp = UINT64_C(0);
    sync_ss_size = UINT64_C(0);
    sync_ss_flags = (uint64_t)SPARC64_SS_DISABLE;
}

int sparc64_sync_sig_for_trap(sparc64_trap_cause_t cause, int *code_out)
{
    int code = 0;
    int signo = 0;
    switch (cause) {
    case SPARC64_TRAP_LOAD_MISALIGNED:
    case SPARC64_TRAP_STORE_MISALIGNED:
        signo = (int)SPARC64_SIG_BUS;
        code = SPARC64_BUS_ADRALN;
        break;
    case SPARC64_TRAP_LOAD_ACCESS:
    case SPARC64_TRAP_STORE_ACCESS:
    case SPARC64_TRAP_INST_ACCESS:
        signo = (int)SPARC64_SIG_SEGV;
        code = SPARC64_SEGV_MAPERR;
        break;
    case SPARC64_TRAP_ILLEGAL:
    case SPARC64_TRAP_PRIVILEGED:
    case SPARC64_TRAP_INST_MISALIGNED:
        signo = (int)SPARC64_SIG_ILL;
        code = SPARC64_ILL_ILLOPC;
        break;
    default:
        signo = 0;
        break;
    }
    /* SIGFPE (integer divide) and SIGTRAP (trap instructions) arrive
     * with the ILLEGAL cause as well; the deliver path refines them
     * from the trapped raw word (sparc64_sync_sig_classify_raw),
     * which the cause alone cannot distinguish. */
    if (code_out != NULL) {
        *code_out = code;
    }
    return signo;
}

/* Bit extract helper for the raw-word classifier below. */
static uint32_t sync_bits(uint32_t w, unsigned lo, unsigned n)
{
    return (w >> lo) & (uint32_t)((n >= 32U) ? 0xffffffffU :
        ((1U << n) - 1U));
}

void sparc64_sync_sig_classify_raw(uint32_t raw, int *signo_out,
    int *code_out)
{
    int signo = (int)SPARC64_SIG_ILL;
    int code = SPARC64_ILL_ILLOPC;
    if (sync_bits(raw, 30U, 2U) == 2U) {
        uint32_t op3 = sync_bits(raw, 19U, 6U);
        if (op3 == 0x3aU) {
            /* Tcc / TA (trap on condition, always): breakpoint. */
            signo = (int)SPARC64_SIG_TRAP;
            code = SPARC64_TRAP_BRKPT;
        } else {
            switch (op3) {
            case 0x0dU:
            case 0x0eU:
            case 0x0fU:
            case 0x1eU:
            case 0x1fU:
            case 0x2dU:
                /* UDIVX/UDIV/SDIV/UDIVcc/SDIVcc/SDIVX: the only
                 * architectural trap is divide-by-zero. */
                signo = (int)SPARC64_SIG_FPE;
                code = SPARC64_FPE_INTDIV;
                break;
            default:
                break;
            }
        }
    }
    if (signo_out != NULL) {
        *signo_out = signo;
    }
    if (code_out != NULL) {
        *code_out = code;
    }
}

static void put_u64be(uint8_t *p, uint64_t v)
{
    unsigned i;
    for (i = 0U; i < 8U; i++) {
        p[i] = (uint8_t)(v >> (56U - 8U * i));
    }
}

static void put_u32be(uint8_t *p, uint32_t v)
{
    unsigned i;
    for (i = 0U; i < 4U; i++) {
        p[i] = (uint8_t)(v >> (24U - 8U * i));
    }
}

static uint64_t get_u64be(const uint8_t *p)
{
    unsigned i;
    uint64_t v = UINT64_C(0);
    for (i = 0U; i < 8U; i++) {
        v = (v << 8U) | (uint64_t)p[i];
    }
    return v;
}

static uint32_t get_u32be(const uint8_t *p)
{
    unsigned i;
    uint32_t v = 0U;
    for (i = 0U; i < 4U; i++) {
        v = (v << 8U) | (uint32_t)p[i];
    }
    return v;
}

static int sig_bit(int signo)
{
    return (signo > 0 && signo <= (int)SYNC_SIG_MAX) ? 1 : 0;
}

static uint64_t sig_mask_bit(int signo)
{
    return UINT64_C(1) << (unsigned)(signo - 1);
}

/* Queue-or-deliver for kill-family signals (code is always SI_USER).
 * Returns 0 on synchronous delivery, 1 when queued behind the blocked
 * mask, -1 when fatal (SIGKILL, or no handler installed). SIGSTOP is a
 * successful no-op. */
int sparc64_sync_sig_queue(sparc64_ctx_t *ctx,
    const sparc64_syscall_mem_t *mem, int signo)
{
    uint64_t handler;
    if (!sig_bit(signo)) {
        return -1;
    }
    if (signo == (int)SPARC64_SIG_KILL) {
        return -1;
    }
    if (signo == (int)SPARC64_SIG_STOP) {
        (void)ctx;
        (void)mem;
        return 0;
    }
    handler = sync_handler[(unsigned)signo];
    if (handler == UINT64_C(0) || handler == UINT64_C(1)) {
        return -1;
    }
    if ((sync_blocked & sig_mask_bit(signo)) != UINT64_C(0)) {
        sync_pending |= sig_mask_bit(signo);
        return 1;
    }
    return sparc64_sync_sig_deliver(ctx, mem, signo, SPARC64_SI_USER,
        UINT64_C(0));
}

int sparc64_sync_sig_deliver(sparc64_ctx_t *ctx,
    const sparc64_syscall_mem_t *mem, int signo, int code,
    uint64_t fault_addr)
{
    uint8_t frame[SPARC64_SIGFRAME_TOTAL];
    uint64_t unbiased;
    uint64_t top;
    uint64_t base;
    uint64_t handler;
    uint64_t restorer;
    uint64_t old_blocked;
    uint64_t new_blocked;
    uint64_t self_bit;
    uint64_t asi;
    uint64_t tstate;
    uint64_t pid;
    uint64_t uid;
    unsigned i;
    unsigned w;
    sparc64_step_result_t res;
    if (!sig_bit(signo)) {
        return -1;
    }
    handler = sync_handler[(unsigned)signo];
    restorer = sync_restorer[(unsigned)signo];
    if (handler == UINT64_C(0) || handler == UINT64_C(1)) {
        return -1;
    }
    /* ILLEGAL-caused traps refine from the raw word (32-bit): integer
     * divide forms become SIGFPE, trap instructions SIGTRAP. Fault
     * addresses are full 64-bit VAs and never collide with raw words
     * that decode as op==2 divide/trap forms. */
    if (signo == (int)SPARC64_SIG_ILL && fault_addr <= UINT64_C(0xffffffff)) {
        sparc64_sync_sig_classify_raw((uint32_t)fault_addr, &signo,
            &code);
        handler = sync_handler[(unsigned)signo];
        restorer = sync_restorer[(unsigned)signo];
        if (handler == UINT64_C(0) || handler == UINT64_C(1)) {
            return -1;
        }
        if (signo == (int)SPARC64_SIG_FPE ||
            signo == (int)SPARC64_SIG_TRAP) {
            fault_addr = ctx->pc;
        }
    }
    /* Synchronous trap signals name the faulting pc (the oracle shows
     * si_addr == tpc for ILL/FPE/TRAP); memory faults name the VA. */
    if (signo == (int)SPARC64_SIG_ILL) {
        fault_addr = ctx->pc;
    }
    /* Frame placement: altstack top when enabled, SA_ONSTACK asked,
     * and the interrupted stack is not already on it; else the
     * interrupted unbiased sp. The 808-byte frame holds the 528-byte
     * header plus the inline 280-byte sigfpu tail. */
    unbiased = ctx->r[SPARC64_SP] + SPARC64_STACK_BIAS;
    top = unbiased;
    if ((sync_ss_flags & (uint64_t)SPARC64_SS_DISABLE) == UINT64_C(0) &&
        sync_ss_sp != UINT64_C(0) &&
        ((sync_flags[(unsigned)signo] &
          (uint64_t)SPARC64_SA_ONSTACK) != UINT64_C(0))) {
        uint64_t end = sync_ss_sp + sync_ss_size;
        if (end < sync_ss_sp ||
            unbiased < sync_ss_sp || unbiased >= end) {
            top = end;
        }
    }
    if (top < (uint64_t)SPARC64_SIGFRAME_TOTAL) {
        return -1;
    }
    base = (top - (uint64_t)SPARC64_SIGFRAME_TOTAL) & ~UINT64_C(15);
    /* Flush every outstanding window image to its stack home first,
     * so the ss slot below mirrors the kernel's synchronized stack. */
    if (!sparc64_win_flush_all(ctx, &guest_mem_ops, mem->context, &res,
            ctx->pc)) {
        return -1;
    }
    for (i = 0U; i < (unsigned)SPARC64_SIGFRAME_TOTAL; i++) {
        frame[i] = 0U;
    }
    /* ss: the 128-byte copy of the interrupted [sp + 2047] slot. */
    if (!mem->read(mem->context, unbiased, frame, 128U)) {
        return -1;
    }
    /* siginfo @0x0c0: signo/errno/code, then the SI_USER pid/uid/value
     * for kill-family (code 0, sender is this thread) or the fault
     * address + trapno (0: the oracle provides none). */
    put_u32be(&frame[0xc0], (uint32_t)signo);
    put_u32be(&frame[0xc4], 0U);
    put_u32be(&frame[0xc8], (uint32_t)code);
    if (code == SPARC64_SI_USER) {
        pid = (uint64_t)getpid();
        uid = (uint64_t)getuid();
        put_u32be(&frame[0xd0], (uint32_t)pid);
        put_u32be(&frame[0xd4], (uint32_t)uid);
        put_u64be(&frame[0xd8], UINT64_C(0));
    } else {
        put_u64be(&frame[0xd0], fault_addr);
        put_u32be(&frame[0xd8], 0U);
    }
    /* pt_regs @0x140: live %g/%o view, then tstate/tpc/tnpc/y/magic. */
    for (i = 0U; i < 16U; i++) {
        put_u64be(&frame[0x140 + 8U * i], ctx->r[i]);
    }
    asi = (ctx->asi != 0U) ? (uint64_t)ctx->asi : UINT64_C(0x82);
    tstate = ((ctx->ccr & UINT64_C(0xff)) << 32) |
        ((asi & UINT64_C(0xff)) << 24) | UINT64_C(0x1200) |
        ((UINT64_C(7) - (uint64_t)(ctx->cwp & 7U)) & UINT64_C(7));
    put_u64be(&frame[0x1c0], tstate);
    put_u64be(&frame[0x1c8], ctx->pc);
    put_u64be(&frame[0x1d0], ctx->npc);
    put_u64be(&frame[0x1d8], ctx->y);
    put_u32be(&frame[0x1dc], SPARC64_PT_REGS_MAGIC);
    /* fpu_save @0x1e0 points at the inline tail @un+0x210 (always
     * present); stack @0x1e8 is the current altstack unchanged;
     * mask @0x200 is the pre-delivery blocked set; rwin_save is 0. */
    /* The inline tail starts right past the 528-byte header. */
    put_u64be(&frame[0x1e0], base + UINT64_C(0x210));
    put_u64be(&frame[0x1e8], sync_ss_sp);
    put_u32be(&frame[0x1f0], (uint32_t)sync_ss_flags);
    put_u32be(&frame[0x1f4], 0U);
    put_u64be(&frame[0x1f8], sync_ss_size);
    old_blocked = sync_blocked;
    put_u64be(&frame[0x200], old_blocked);
    put_u64be(&frame[0x208], UINT64_C(0));
    /* Inline sigfpu tail @0x210: 32 doubles, fsr, gsr, fprs. */
    for (w = 0U; w < 32U; w++) {
        put_u64be(&frame[0x210 + 8U * w], ctx->fp.d[w]);
    }
    put_u64be(&frame[0x210 + 8U * 32U], ctx->fsr);
    put_u64be(&frame[0x210 + 8U * 33U], ctx->gsr);
    put_u64be(&frame[0x210 + 8U * 34U], ctx->fprs);
    if (!mem->prepare_write(mem->context, base,
            (uint64_t)SPARC64_SIGFRAME_TOTAL)) {
        return -1;
    }
    if (!mem->write(mem->context, base, frame,
            (uint64_t)SPARC64_SIGFRAME_TOTAL)) {
        return -1;
    }
    /* New blocked set (visible to the handler's procmask query);
     * the pending bit clears on delivery. */
    self_bit = ((sync_flags[(unsigned)signo] &
        (uint64_t)SPARC64_SA_NODEFER) != UINT64_C(0)) ?
        UINT64_C(0) : sig_mask_bit(signo);
    new_blocked = (old_blocked | sync_sa_mask[(unsigned)signo] |
        self_bit) & ~(SPARC64_SIGKILL_BIT | SPARC64_SIGSTOP_BIT);
    sync_blocked = new_blocked;
    sync_pending &= ~sig_mask_bit(signo);
    /* Handler entry: signo in %o0, &info in %o1 and %o2, restorer in
     * %o7, biased handler %sp, pc/npc at handler/+4. */
    ctx->r[SPARC64_O0] = (uint64_t)signo;
    ctx->r[SPARC64_O1] = base + (uint64_t)SPARC64_RT_OFF_INFO;
    ctx->r[SPARC64_O2] = base + (uint64_t)SPARC64_RT_OFF_INFO;
    ctx->r[SPARC64_O7] = restorer;
    ctx->r[SPARC64_SP] = base - SPARC64_STACK_BIAS;
    ctx->pc = handler;
    ctx->npc = handler + 4U;
    return 0;
}

int sparc64_sync_sig_deliver_pending(sparc64_ctx_t *ctx,
    const sparc64_syscall_mem_t *mem)
{
    uint64_t deliverable;
    int signo;
    deliverable = sync_pending & ~sync_blocked;
    if (deliverable == UINT64_C(0)) {
        return 1;
    }
    for (signo = 1; signo <= (int)SYNC_SIG_MAX; signo++) {
        if ((deliverable & sig_mask_bit(signo)) == UINT64_C(0)) {
            continue;
        }
        if (sync_handler[(unsigned)signo] == UINT64_C(0) ||
            sync_handler[(unsigned)signo] == UINT64_C(1)) {
            return -1;
        }
        return sparc64_sync_sig_deliver(ctx, mem, signo,
            SPARC64_SI_USER, UINT64_C(0));
    }
    return 1;
}

long sparc64_sync_sig_return(sparc64_ctx_t *ctx,
    const sparc64_syscall_mem_t *mem)
{
    uint8_t frame[SPARC64_SIGFRAME_TOTAL];
    uint64_t base;
    uint64_t tstate;
    uint64_t fpu_save;
    uint64_t rwin_save;
    unsigned i;
    int pending_rc;
    base = ctx->r[SPARC64_SP] + SPARC64_STACK_BIAS;
    if ((base & UINT64_C(15)) != UINT64_C(0) ||
        base < (uint64_t)SPARC64_SIGFRAME_TOTAL) {
        return (long)-EFAULT;
    }
    if (!mem->read(mem->context, base, frame,
            (uint64_t)SPARC64_SIGFRAME_TOTAL)) {
        return (long)-EFAULT;
    }
    if (get_u32be(&frame[0x1dc]) != (uint32_t)SPARC64_PT_REGS_MAGIC) {
        return (long)-EFAULT;
    }
    /* Absolute resume: tpc/tnpc name the return point. */
    if (((get_u64be(&frame[0x1c8]) | get_u64be(&frame[0x1d0])) &
            UINT64_C(3)) != UINT64_C(0)) {
        return (long)-EFAULT;
    }
    /* Restore the integer view (r0 stays hardwired 0), y, and the
     * user-changeable tstate pieces (condition codes + ASI). */
    for (i = 1U; i < 16U; i++) {
        ctx->r[i] = get_u64be(&frame[0x140 + 8U * (uint64_t)i]);
    }
    ctx->y = get_u64be(&frame[0x1d8]);
    tstate = get_u64be(&frame[0x1c0]);
    ctx->ccr = (tstate >> 32) & UINT64_C(0xff);
    ctx->asi = (uint32_t)((tstate >> 24) & UINT64_C(0xff));
    /* Inline FPU tail when present. */
    fpu_save = get_u64be(&frame[0x1e0]);
    if (fpu_save != UINT64_C(0)) {
        uint8_t tail[SPARC64_SIGFPU_SIZE];
        if (!mem->read(mem->context, fpu_save, tail,
                (uint64_t)SPARC64_SIGFPU_SIZE)) {
            return (long)-EFAULT;
        }
        for (i = 0U; i < 32U; i++) {
            ctx->fp.d[i] = get_u64be(&tail[8U * (uint64_t)i]);
        }
        ctx->fsr = get_u64be(&tail[8U * 32U]);
        ctx->gsr = get_u64be(&tail[8U * 33U]);
        ctx->fprs = get_u64be(&tail[8U * 34U]);
    }
    /* Blocked mask, altstack, then pc/npc (absolute: the caller must
     * skip the usual advance on success). */
    sync_blocked = get_u64be(&frame[0x200]) &
        ~(SPARC64_SIGKILL_BIT | SPARC64_SIGSTOP_BIT);
    sync_ss_sp = get_u64be(&frame[0x1e8]);
    sync_ss_flags = (uint64_t)get_u32be(&frame[0x1f0]);
    sync_ss_size = get_u64be(&frame[0x1f8]);
    rwin_save = get_u64be(&frame[0x208]);
    if (rwin_save != UINT64_C(0)) {
        /* The translator always flushes windows to the user stack
         * before capture, so rwin_save is 0 on every frame it wrote;
         * a nonzero pointer names foreign state it cannot restore. */
        return (long)-EFAULT;
    }
    ctx->pc = get_u64be(&frame[0x1c8]);
    ctx->npc = get_u64be(&frame[0x1d0]);
    /* A restored mask can unblock pending signals: deliver the first
     * before returning to the guest (pc is absolute, no advance). */
    pending_rc = sparc64_sync_sig_deliver_pending(ctx, mem);
    if (pending_rc < 0) {
        return (long)-EFAULT;
    }
    return 0L;
}
