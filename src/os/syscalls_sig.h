/*
 * src/os/syscalls_sig.h — Phase 4 signal syscalls + signal state (L4a).
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Declares the exact-Linux-UAPI signal syscalls implemented in
 * src/os/syscalls_sig.c (rt_sigprocmask-real, sigaltstack, kill, tkill,
 * tgkill, and the mask-persisting rt_sigaction), plus the extended
 * synchronous-signal state interface backing them in src/os/sync_sig.c.
 * Dispatch case arms live in src/os/syscalls_min.c only.
 *
 * Guest constants are the SPARC UAPI numbers (arch/sparc, NOT generic):
 * SIGSTOP is 17 (SIGCONT is 19), SA_ONSTACK is 1, SA_NODEFER is 0x20,
 * rt_sigprocmask how values are 1/2/4, kill is 37.
 */

#ifndef SPARC64RT_OS_SYSCALLS_SIG_H
#define SPARC64RT_OS_SYSCALLS_SIG_H

#include <stdint.h>

#include "core/cpu.h"

/* macOS <sys/signal.h> (reached via <stdlib.h>) #defines sa_handler
 * and sa_sigaction over the host union; the frozen guest
 * sparc64_sigaction_t below needs those spellings as plain field
 * names, so drop the macros here (no TU including this header uses
 * the host struct sigaction). */
#ifdef sa_handler
#undef sa_handler
#endif
#ifdef sa_sigaction
#undef sa_sigaction
#endif
#include "os/sigframe_sparc64rt.h"
#include "os/syscalls_min.h"

/* ---- SPARC guest signal numbers (uapi asm/signal.h) -------------------- */
#define SPARC64_SIG_ILL 4U
#define SPARC64_SIG_TRAP 5U
#define SPARC64_SIG_FPE 8U
#define SPARC64_SIG_KILL 9U
#define SPARC64_SIG_BUS 10U
#define SPARC64_SIG_SEGV 11U
#define SPARC64_SIG_STOP 17U
#define SPARC64_SIG_USR1 30U
#define SPARC64_SIG_USR2 31U
#define SPARC64_SIG_MAX 64U

/* si_code values used by synchronous delivery. */
#define SPARC64_SI_USER 0
#define SPARC64_SEGV_MAPERR 1
#define SPARC64_BUS_ADRALN 1
#define SPARC64_ILL_ILLOPC 1
#define SPARC64_FPE_INTDIV 1
#define SPARC64_FPE_INTOVF 2
#define SPARC64_FPE_FLTDIV 3
#define SPARC64_FPE_FLTOVF 4
#define SPARC64_FPE_FLTUND 5
#define SPARC64_FPE_FLTRES 6
#define SPARC64_FPE_FLTINV 7
#define SPARC64_FPE_FLTSUB 8
#define SPARC64_TRAP_BRKPT 1

/* sa_flags bits accepted by rt_sigaction (SA_SIGINFO required). */
#define SPARC64_SA_ONSTACK 1U
#define SPARC64_SA_NODEFER 0x20U

/* sigaltstack ss_flags bits; minimum stack size enforced on enable. */
#define SPARC64_SS_ONSTACK 1
#define SPARC64_SS_DISABLE 2
#define SPARC64_MINSIGSTKSZ 2048U

/* rt_sigprocmask how values (SPARC, not generic). */
#define SPARC64_SIG_BLOCK 1U
#define SPARC64_SIG_UNBLOCK 2U
#define SPARC64_SIG_SETMASK 4U

/* Unblockable bits: SIGKILL (9) and SIGSTOP (17) are never blocked. */
#define SPARC64_SIGKILL_BIT (UINT64_C(1) << 8U)
#define SPARC64_SIGSTOP_BIT (UINT64_C(1) << 16U)

/* Signal-frame tail: __siginfo_fpu_t is 32 doubles + fsr + gsr + fprs
 * (280 bytes), always present (FPU is always enabled); rwin_save is 0. */
#define SPARC64_SIGFPU_WORDS 35U
#define SPARC64_SIGFPU_SIZE 280U
#define SPARC64_SIGFRAME_TOTAL \
    (SPARC64_RT_SIGFRAME_SIZE + SPARC64_SIGFPU_SIZE)

/* tstate construction (E04 + CCR multi-setting probes under qemu-sparc64):
 * CCR in bits 39:32, fixed PSTATE/ASI 0x82001200, and the CWP field
 * (7 - cwp) & 7 (leaf 7, one SAVE outstanding 0). */
#define SPARC64_TSTATE_FIXED UINT64_C(0x82001200)

/* ---- Extended synchronous-signal state (src/os/sync_sig.c) ------------- */

/* Record a handler with flags/restorer/mask. Returns 0 or -EINVAL
 * (bad signo, SIGKILL/SIGSTOP, or flags outside
 * SA_SIGINFO|SA_ONSTACK|SA_NODEFER without SA_SIGINFO). */
int sparc64_sync_sig_install_full(uint64_t sig, uint64_t handler,
    uint64_t flags, uint64_t restorer, uint64_t mask);

/* Read back the installed action (zeros when none). Returns 0 or -EINVAL. */
int sparc64_sync_sig_query(uint64_t sig, uint64_t *handler,
    uint64_t *flags, uint64_t *restorer, uint64_t *mask);

/* Current blocked mask (per thread, S64-R4-8; resolved by ctx). */
uint64_t sparc64_sync_sig_blocked_get(const sparc64_ctx_t *ctx);

/* Replace the blocked mask (KILL/STOP bits must already be stripped). */
void sparc64_sync_sig_blocked_set(const sparc64_ctx_t *ctx, uint64_t mask);

/* Store (0) or report (-EFAULT on bad guest address) the altstack. */
long sparc64_sync_sig_altstack_set(const sparc64_ctx_t *ctx, uint64_t sp,
    uint64_t flags, uint64_t size);
uint64_t sparc64_sync_sig_pending_get(const sparc64_ctx_t *ctx);
void sparc64_sync_sig_altstack_get(const sparc64_ctx_t *ctx, uint64_t *sp,
    uint64_t *flags, uint64_t *size, uint64_t cur_sp_unbiased);

/* Clone inheritance (S64-R4-8): the child starts with the parent's
 * blocked mask, an empty pending set, and a disabled altstack. */
void sparc64_sync_sig_clone(sparc64_ctx_t *child,
    const sparc64_ctx_t *parent);

/* Deliver the lowest pending unblocked signal with a handler.
 * Returns 0 on delivery, 1 when nothing is deliverable, -1 when the
 * deliverable signal has no handler (fatal, like the fault path). */
int sparc64_sync_sig_deliver_pending(sparc64_ctx_t *ctx,
    const sparc64_syscall_mem_t *mem);

/* Queue a kill-family signal for the current thread: SIGKILL is fatal
 * (-1), SIGSTOP is a no-op (0, cannot stop), an unhandled signal is
 * fatal (-1), a blocked signal is queued (1), otherwise the signal is
 * delivered synchronously (0). */
int sparc64_sync_sig_queue(sparc64_ctx_t *ctx,
    const sparc64_syscall_mem_t *mem, int signo);

/* Classify a raw instruction word trapped as ILLEGAL: integer divide
 * forms refine to (SIGFPE, FPE_INTDIV), trap instructions (Tcc/TA) to
 * (SIGTRAP, TRAP_BRKPT); anything else stays (SIGILL, ILL_ILLOPC).
 * Used by the deliver path (cause-level mapping cannot distinguish). */
void sparc64_sync_sig_classify_raw(uint32_t raw, int *signo_out,
    int *code_out);

/* ---- Signal syscalls (src/os/syscalls_sig.c) ----------------------------
 * Each takes the dispatch args; kill-family and rt_sigprocmask take a
 * delivered out-flag. When *delivered is set, the handler already
 * committed the result (dual-carry), advanced pc/npc past the trap,
 * and redirected ctx at the signal handler: the dispatch tail must be
 * skipped (ctx->syscalls_executed++ and return 0, like rt_sigreturn). */

long sparc64_sig_rt_sigaction(sparc64_ctx_t *ctx,
    const sparc64_syscall_mem_t *mem, uint64_t sig, uint64_t act_va,
    uint64_t oact_va, uint64_t restorer, uint64_t sigsetsize);

long sparc64_sig_rt_sigprocmask(sparc64_ctx_t *ctx,
    const sparc64_syscall_mem_t *mem, uint64_t how, uint64_t set_va,
    uint64_t oset_va, uint64_t sigsetsize, int *delivered);

long sparc64_sig_rt_sigpending(sparc64_ctx_t *ctx,
    const sparc64_syscall_mem_t *mem, uint64_t set_va,
    uint64_t sigsetsize);

long sparc64_sig_sigaltstack(sparc64_ctx_t *ctx,
    const sparc64_syscall_mem_t *mem, uint64_t uss_va,
    uint64_t uoss_va);

long sparc64_sig_kill(sparc64_ctx_t *ctx,
    const sparc64_syscall_mem_t *mem, uint64_t pid, uint64_t sig,
    int *delivered);

long sparc64_sig_tkill(sparc64_ctx_t *ctx,
    const sparc64_syscall_mem_t *mem, uint64_t tid, uint64_t sig,
    int *delivered);

long sparc64_sig_tgkill(sparc64_ctx_t *ctx,
    const sparc64_syscall_mem_t *mem, uint64_t tgid, uint64_t tid,
    uint64_t sig, int *delivered);

#endif /* SPARC64RT_OS_SYSCALLS_SIG_H */
