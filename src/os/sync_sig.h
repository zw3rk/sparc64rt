/*
 * src/os/sync_sig.h — synchronous guest signal delivery (Phase 1, RC1)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Minimal SA_SIGINFO delivery for traps the Phase-1 guest test requires:
 * rt_sigaction(102) records the handler, the guest_run loop delivers
 * SIGSEGV/SIGBUS/SIGILL with a kernel-layout rt_signal_frame64 (SPEC
 * 2.1, 528 bytes), and rt_sigreturn(101) resumes at the patched tpc/tnpc.
 * Async delivery, altstacks and threads arrive in Phase 4.
 */

#ifndef SPARC64RT_OS_SYNC_SIG_H
#define SPARC64RT_OS_SYNC_SIG_H

#include <stdint.h>

#include "core/cpu.h"
#include "os/syscalls_min.h"

/* Record a handler installed by rt_sigaction. Returns 0 or -EINVAL. */
int sparc64_sync_sig_install(uint64_t sig, uint64_t handler_va,
    uint64_t restorer_va);

/* Forget all handlers (execve reset). */
void sparc64_sync_sig_reset_all(void);

/* execve reset: caught dispositions return to SIG_DFL while ignored
 * dispositions, the blocked mask, and pending signals survive. */
void sparc64_sync_sig_exec_reset(void);

/* Map a step trap to (signo, si_code). Returns signo, or 0 when the trap
 * is not a synchronous signal (caller treats it as fatal). */
int sparc64_sync_sig_for_trap(sparc64_trap_cause_t cause, int *code_out);

/* Build the rt frame on the guest stack and redirect ctx at the handler.
 * Returns 0 on delivery, -1 when no handler is installed or the stack
 * frame cannot be written (caller treats it as fatal). */
int sparc64_sync_sig_deliver(sparc64_ctx_t *ctx,
    const sparc64_syscall_mem_t *mem, int signo, int code,
    uint64_t fault_addr);

/* rt_sigreturn body: restore regs/pc/npc from the frame. Returns 0 on
 * success (pc/npc already set: the caller must skip the usual advance),
 * or a negative host errno. */
long sparc64_sync_sig_return(sparc64_ctx_t *ctx,
    const sparc64_syscall_mem_t *mem);

#endif /* SPARC64RT_OS_SYNC_SIG_H */
