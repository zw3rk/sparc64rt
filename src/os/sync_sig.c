/*
 * src/os/sync_sig.c — synchronous guest signal delivery (Phase 1, RC1)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Frame layout follows SPEC 2.1 / E04 (rt_signal_frame64, 528 bytes):
 * ss 192 @0x000, info 128 @0x0c0, regs 160 @0x140 (tstate @0x80,
 * tpc @0x88, tnpc @0x90, y @0x98, magic @0x9c), fpu_save @0x1e0,
 * stack @0x1e8, mask @0x200, rwin_save @0x208. Delivery runs in the
 * faulting window (no SAVE): the frame captures %g/%o, tpc/tnpc, y and
 * ccr; rt_sigreturn restores exactly those.
 */

#include "os/sync_sig.h"

#include <errno.h>

#include "core/cpu.h"
#include "os/sigframe_sparc64rt.h"
#include "os/syscalls_min.h"

#define SYNC_SIG_MAX 64U

#define SYNC_SIGSEGV 11
#define SYNC_SIGBUS 10
#define SYNC_SIGILL 4

#define SYNC_SEGV_MAPERR 1
#define SYNC_BUS_ADRALN 1
#define SYNC_ILL_ILLOPC 1

static uint64_t sync_handler[SYNC_SIG_MAX + 1U];
static uint64_t sync_restorer[SYNC_SIG_MAX + 1U];

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

void sparc64_sync_sig_reset_all(void)
{
    unsigned i;
    for (i = 0U; i <= SYNC_SIG_MAX; i++) {
        sync_handler[i] = UINT64_C(0);
        sync_restorer[i] = UINT64_C(0);
    }
}

int sparc64_sync_sig_for_trap(sparc64_trap_cause_t cause, int *code_out)
{
    int code = 0;
    int signo = 0;
    switch (cause) {
    case SPARC64_TRAP_LOAD_MISALIGNED:
    case SPARC64_TRAP_STORE_MISALIGNED:
        signo = SYNC_SIGBUS;
        code = SYNC_BUS_ADRALN;
        break;
    case SPARC64_TRAP_LOAD_ACCESS:
    case SPARC64_TRAP_STORE_ACCESS:
    case SPARC64_TRAP_INST_ACCESS:
        signo = SYNC_SIGSEGV;
        code = SYNC_SEGV_MAPERR;
        break;
    case SPARC64_TRAP_ILLEGAL:
    case SPARC64_TRAP_PRIVILEGED:
    case SPARC64_TRAP_INST_MISALIGNED:
        signo = SYNC_SIGILL;
        code = SYNC_ILL_ILLOPC;
        break;
    default:
        signo = 0;
        break;
    }
    if (code_out != NULL) {
        *code_out = code;
    }
    return signo;
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

int sparc64_sync_sig_deliver(sparc64_ctx_t *ctx,
    const sparc64_syscall_mem_t *mem, int signo, int code,
    uint64_t fault_addr)
{
    uint8_t frame[SPARC64_RT_SIGFRAME_SIZE];
    uint64_t unbiased;
    uint64_t base;
    uint64_t handler;
    uint64_t restorer;
    unsigned i;
    if (signo <= 0 || signo > (int)SYNC_SIG_MAX) {
        return -1;
    }
    handler = sync_handler[signo];
    restorer = sync_restorer[signo];
    if (handler == UINT64_C(0)) {
        return -1;
    }
    unbiased = ctx->r[SPARC64_SP] + SPARC64_STACK_BIAS;
    if (unbiased < (uint64_t)SPARC64_RT_SIGFRAME_SIZE + 16U) {
        return -1;
    }
    base = (unbiased - (uint64_t)SPARC64_RT_SIGFRAME_SIZE) &
        ~UINT64_C(15);
    for (i = 0U; i < (unsigned)SPARC64_RT_SIGFRAME_SIZE; i++) {
        frame[i] = 0U;
    }
    /* siginfo @0x0c0: signo/errno/code, fault address @0x10. */
    put_u32be(&frame[0xc0], (uint32_t)signo);
    put_u32be(&frame[0xc4], 0U);
    put_u32be(&frame[0xc8], (uint32_t)code);
    put_u64be(&frame[0xd0], fault_addr);
    /* pt_regs @0x140: %g/%o view, tstate/tpc/tnpc/y/magic. */
    for (i = 0U; i < 16U; i++) {
        put_u64be(&frame[0x140 + 8U * i], ctx->r[i]);
    }
    put_u64be(&frame[0x1c0], ctx->ccr);
    put_u64be(&frame[0x1c8], ctx->pc);
    put_u64be(&frame[0x1d0], ctx->npc);
    put_u64be(&frame[0x1d8], ctx->y);
    put_u32be(&frame[0x1dc], SPARC64_PT_REGS_MAGIC);
    if (!mem->write(mem->context, base, frame,
            (uint64_t)SPARC64_RT_SIGFRAME_SIZE)) {
        return -1;
    }
    ctx->r[SPARC64_O0] = (uint64_t)signo;
    ctx->r[SPARC64_O1] = base + (uint64_t)SPARC64_RT_OFF_INFO;
    ctx->r[SPARC64_O2] = base + (uint64_t)SPARC64_RT_OFF_REGS;
    ctx->r[SPARC64_O7] = restorer;
    ctx->r[SPARC64_SP] = base - SPARC64_STACK_BIAS;
    ctx->pc = handler;
    ctx->npc = handler + 4U;
    return 0;
}

long sparc64_sync_sig_return(sparc64_ctx_t *ctx,
    const sparc64_syscall_mem_t *mem)
{
    uint8_t frame[SPARC64_RT_SIGFRAME_SIZE];
    uint64_t base;
    unsigned i;
    base = ctx->r[SPARC64_SP] + SPARC64_STACK_BIAS;
    if (base < 16U) {
        return (long)-EFAULT;
    }
    if (!mem->read(mem->context, base, frame,
            (uint64_t)SPARC64_RT_SIGFRAME_SIZE)) {
        return (long)-EFAULT;
    }
    if (get_u32be(&frame[0x1dc]) != (uint32_t)SPARC64_PT_REGS_MAGIC) {
        return (long)-EFAULT;
    }
    for (i = 1U; i < 16U; i++) {
        ctx->r[i] = get_u64be(&frame[0x140 + 8U * (uint64_t)i]);
    }
    ctx->y = get_u64be(&frame[0x1d8]);
    ctx->ccr = get_u64be(&frame[0x1c0]);
    ctx->pc = get_u64be(&frame[0x1c8]);
    ctx->npc = get_u64be(&frame[0x1d0]);
    return 0L;
}
