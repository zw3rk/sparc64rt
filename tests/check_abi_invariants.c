/*
 * tests/check_abi_invariants.c — host-runnable ABI invariant checks
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Lane L0b (Phase 0, RC0): compile-time _Static_assert plus runtime
 * offsetof/sizeof checks for every field offset and struct size in
 * src/os/sigframe_sparc64rt.h (SPEC section 2.1) and src/core/cpu.h
 * (sparc64_ctx_t, frozen by lane L0a; this test follows that header).
 *
 * Coordinator reconciliation (RC0 merge): RAS/IBTC/guest_base live in the
 * Phase-2 DBT dispatcher, not in frozen sparc64_ctx_t, so this test pins
 * only the frozen ABI-locked prefix (r..exit_dest) plus the C-only tail
 * offsets it shares with the trampoline contract.
 *
 * Build: cc -std=c11 -Werror=vla -pedantic -Wall -Wextra -Werror \
 *          -Iinclude -Isrc tests/check_abi_invariants.c \
 *          -o _build/check_abi_invariants
 */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "os/sigframe_sparc64rt.h"
#include "core/cpu.h"

static int failures = 0;

#define CHECK_OFF(type, member, expect)                                       \
    do {                                                                      \
        size_t got = offsetof(type, member);                                  \
        if (got != (size_t)(expect)) {                                        \
            printf("FAIL %s.%s: got %lu want %lu\n", #type, #member,         \
                (unsigned long)got, (unsigned long)(expect));                 \
            ++failures;                                                       \
        }                                                                     \
    } while (0)

#define CHECK_SIZE(type, expect)                                              \
    do {                                                                      \
        size_t got = sizeof(type);                                            \
        if (got != (size_t)(expect)) {                                        \
            printf("FAIL sizeof(%s): got %lu want %lu\n", #type,             \
                (unsigned long)got, (unsigned long)(expect));                 \
            ++failures;                                                       \
        }                                                                     \
    } while (0)

#define CHECK_CONST(name, got, expect)                                        \
    do {                                                                      \
        unsigned long long v = (unsigned long long)(got);                     \
        unsigned long long w = (unsigned long long)(expect);                  \
        if (v != w) {                                                         \
            printf("FAIL %s: got %llu want %llu\n", name, v, w);             \
            ++failures;                                                       \
        }                                                                     \
    } while (0)

/* Compile-time pins (duplicate the header's asserts from the consumer side
 * so a silent header edit breaks this TU too). */
_Static_assert(sizeof(sparc64_rt_sigframe_t) == 528, "rt frame 528");
_Static_assert(sizeof(sparc64_stat_t) == 104, "stat 104");
_Static_assert(sizeof(sparc64_stat64_t) == 144, "stat64 144");
_Static_assert(sizeof(sparc64_ucontext_t) == 216, "ucontext 216");

/* Consumer-side pins for the frozen L0a layout (src/core/cpu.h). */
_Static_assert(offsetof(sparc64_ctx_t, r) == 0x000, "ctx.r");
_Static_assert(offsetof(sparc64_ctx_t, pc) == 0x100, "ctx.pc");
_Static_assert(offsetof(sparc64_ctx_t, npc) == 0x108, "ctx.npc");
_Static_assert(offsetof(sparc64_ctx_t, y) == 0x110, "ctx.y");
_Static_assert(offsetof(sparc64_ctx_t, ccr) == 0x118, "ctx.ccr");
_Static_assert(offsetof(sparc64_ctx_t, fsr) == 0x120, "ctx.fsr");
_Static_assert(offsetof(sparc64_ctx_t, gsr) == 0x128, "ctx.gsr");
_Static_assert(offsetof(sparc64_ctx_t, fprs) == 0x130, "ctx.fprs");
_Static_assert(offsetof(sparc64_ctx_t, asi) == 0x138, "ctx.asi");
_Static_assert(offsetof(sparc64_ctx_t, pil) == 0x13c, "ctx.pil");
_Static_assert(offsetof(sparc64_ctx_t, fp) == 0x140, "ctx.fp");
_Static_assert(offsetof(sparc64_ctx_t, fcc) == 0x240, "ctx.fcc");
_Static_assert(offsetof(sparc64_ctx_t, cwp) == 0x250, "ctx.cwp");
_Static_assert(offsetof(sparc64_ctx_t, nwindows) == 0x268, "ctx.nwindows");
_Static_assert(offsetof(sparc64_ctx_t, exit_reason) == 0x270, "ctx.exit_reason");
_Static_assert(offsetof(sparc64_ctx_t, fault_addr) == 0x278, "ctx.fault_addr");
_Static_assert(offsetof(sparc64_ctx_t, exit_dest) == 0x280, "ctx.exit_dest");

static void check_ctx(void)
{
    CHECK_OFF(sparc64_ctx_t, r, 0x000);
    CHECK_OFF(sparc64_ctx_t, pc, 0x100);
    CHECK_OFF(sparc64_ctx_t, npc, 0x108);
    CHECK_OFF(sparc64_ctx_t, y, 0x110);
    CHECK_OFF(sparc64_ctx_t, ccr, 0x118);
    CHECK_OFF(sparc64_ctx_t, fsr, 0x120);
    CHECK_OFF(sparc64_ctx_t, gsr, 0x128);
    CHECK_OFF(sparc64_ctx_t, fprs, 0x130);
    CHECK_OFF(sparc64_ctx_t, asi, 0x138);
    CHECK_OFF(sparc64_ctx_t, pil, 0x13c);
    CHECK_OFF(sparc64_ctx_t, fp, 0x140);
    CHECK_OFF(sparc64_ctx_t, fcc, 0x240);
    CHECK_OFF(sparc64_ctx_t, cwp, 0x250);
    CHECK_OFF(sparc64_ctx_t, cansave, 0x254);
    CHECK_OFF(sparc64_ctx_t, canrestore, 0x258);
    CHECK_OFF(sparc64_ctx_t, otherwin, 0x25c);
    CHECK_OFF(sparc64_ctx_t, cleanwin, 0x260);
    CHECK_OFF(sparc64_ctx_t, wim, 0x264);
    CHECK_OFF(sparc64_ctx_t, nwindows, 0x268);
    CHECK_OFF(sparc64_ctx_t, exit_reason, 0x270);
    CHECK_OFF(sparc64_ctx_t, exit_arg, 0x274);
    CHECK_OFF(sparc64_ctx_t, fault_addr, 0x278);
    CHECK_OFF(sparc64_ctx_t, exit_dest, 0x280);

    /* ABI-locked constants (SPEC sections 2.1 and 3). */
    CHECK_CONST("SPARC64_NWINDOWS", SPARC64_NWINDOWS, 8);
    CHECK_CONST("SPARC64_RWINDOW_SIZE", SPARC64_RWINDOW_SIZE, 128);
    CHECK_CONST("SPARC64_RAS_SIZE", SPARC64_RAS_SIZE, 64);
    CHECK_CONST("SPARC64_IBTC_SIZE", SPARC64_IBTC_SIZE, 4096);
    CHECK_CONST("SPARC64_STACK_BIAS", SPARC64_STACK_BIAS, 2047);
    CHECK_CONST("SPARC64_TASK_SIZE", SPARC64_TASK_SIZE, 0x800000000000ULL);
    CHECK_CONST("sizeof(r)", sizeof(((sparc64_ctx_t *)0)->r), 256);
    CHECK_CONST("sizeof(fp)", sizeof(((sparc64_ctx_t *)0)->fp), 256);
    {
        sparc64_ctx_t ctx;
        for (unsigned i = 0; i < 32; ++i) {
            ctx.fp.d[i] = UINT64_C(0xdeadbeefcafebabe);
        }
        sparc64_ctx_init(&ctx, UINT64_C(0x1000));
        for (unsigned i = 0; i < 32; ++i) {
            CHECK_CONST("ctx_init_fp_d", ctx.fp.d[i], 0);
        }
    }
}

static void check_sigframe(void)
{
    CHECK_SIZE(sparc64_stackf_t, 192);
    CHECK_OFF(sparc64_stackf_t, locals, 0x00);
    CHECK_OFF(sparc64_stackf_t, ins, 0x40);
    CHECK_OFF(sparc64_stackf_t, fp, 0x70);
    CHECK_OFF(sparc64_stackf_t, callers_pc, 0x78);
    CHECK_OFF(sparc64_stackf_t, structptr, 0x80);
    CHECK_OFF(sparc64_stackf_t, xargs, 0x88);
    CHECK_OFF(sparc64_stackf_t, xxargs, 0xb8);

    CHECK_SIZE(sparc64_siginfo_t, 128);
    CHECK_OFF(sparc64_siginfo_t, si_signo, 0x00);
    CHECK_OFF(sparc64_siginfo_t, si_errno, 0x04);
    CHECK_OFF(sparc64_siginfo_t, si_code, 0x08);
    CHECK_OFF(sparc64_siginfo_t, sifields, 0x10);
    CHECK_OFF(sparc64_siginfo_t, sifields.kill.pid, 0x10);
    CHECK_OFF(sparc64_siginfo_t, sifields.kill.uid, 0x14);
    CHECK_OFF(sparc64_siginfo_t, sifields.kill.value, 0x18);
    CHECK_OFF(sparc64_siginfo_t, sifields.fault.addr, 0x10);
    CHECK_OFF(sparc64_siginfo_t, sifields.fault.u.trapno, 0x18);
    CHECK_OFF(sparc64_siginfo_t, sifields.fault.u.addr_lsb, 0x18);
    CHECK_OFF(sparc64_siginfo_t, sifields.fault.u.bnd.lower, 0x20);
    CHECK_OFF(sparc64_siginfo_t, sifields.fault.u.bnd.upper, 0x28);

    CHECK_SIZE(sparc64_pt_regs_t, 160);
    CHECK_OFF(sparc64_pt_regs_t, u_regs, 0x00);
    CHECK_OFF(sparc64_pt_regs_t, tstate, 0x80);
    CHECK_OFF(sparc64_pt_regs_t, tpc, 0x88);
    CHECK_OFF(sparc64_pt_regs_t, tnpc, 0x90);
    CHECK_OFF(sparc64_pt_regs_t, y, 0x98);
    CHECK_OFF(sparc64_pt_regs_t, magic, 0x9c);

    CHECK_SIZE(sparc64_sigmask_t, 8);
    CHECK_SIZE(sparc64_stack_t, 24);
    CHECK_OFF(sparc64_stack_t, ss_sp, 0x00);
    CHECK_OFF(sparc64_stack_t, ss_flags, 0x08);
    CHECK_OFF(sparc64_stack_t, ss_size, 0x10);

    CHECK_SIZE(sparc64_sigaction_t, 32);
    CHECK_OFF(sparc64_sigaction_t, sa_handler, 0x00);
    CHECK_OFF(sparc64_sigaction_t, sa_flags, 0x08);
    CHECK_OFF(sparc64_sigaction_t, sa_restorer, 0x10);
    CHECK_OFF(sparc64_sigaction_t, sa_mask, 0x18);

    CHECK_SIZE(sparc64_rt_sigframe_t, 528);
    CHECK_OFF(sparc64_rt_sigframe_t, ss, 0x000);
    CHECK_OFF(sparc64_rt_sigframe_t, info, 0x0c0);
    CHECK_OFF(sparc64_rt_sigframe_t, regs, 0x140);
    CHECK_OFF(sparc64_rt_sigframe_t, fpu_save, 0x1e0);
    CHECK_OFF(sparc64_rt_sigframe_t, stack, 0x1e8);
    CHECK_OFF(sparc64_rt_sigframe_t, mask, 0x200);
    CHECK_OFF(sparc64_rt_sigframe_t, rwin_save, 0x208);
    CHECK_OFF(sparc64_rt_sigframe_t, regs.tstate, 0x1c0);
    CHECK_OFF(sparc64_rt_sigframe_t, regs.tpc, 0x1c8);
    CHECK_OFF(sparc64_rt_sigframe_t, regs.tnpc, 0x1d0);
    CHECK_OFF(sparc64_rt_sigframe_t, regs.y, 0x1d8);
    CHECK_OFF(sparc64_rt_sigframe_t, regs.u_regs, 0x140);
    CHECK_OFF(sparc64_rt_sigframe_t, stack.ss_sp, 0x1e8);
    CHECK_OFF(sparc64_rt_sigframe_t, stack.ss_size, 0x1f8);

    /* Handler ABI pins (E04 + signal_64.c). */
    CHECK_CONST("UREG_I0(signo slot)", SPARC64_UREG_I0, 8);
    CHECK_CONST("UREG_I1(info ptr)", SPARC64_UREG_I1, 9);
    CHECK_CONST("UREG_I2(info ptr)", SPARC64_UREG_I2, 10);
    CHECK_CONST("UREG_FP", SPARC64_UREG_FP, 14);
    CHECK_CONST("UREG_RETPC", SPARC64_UREG_RETPC, 15);
    CHECK_CONST("NR_rt_sigreturn", SPARC64_NR_RT_SIGRETURN, 101);
    CHECK_CONST("NR_rt_sigaction", SPARC64_NR_RT_SIGACTION, 102);
    CHECK_CONST("ta 0x6d", SPARC64_TA_6D, 0x91d0206dUL);
    CHECK_CONST("SIGUSR1", SPARC64_SIGUSR1, 30);
    CHECK_CONST("SA_SIGINFO", SPARC64_SA_SIGINFO, 0x200);
    CHECK_CONST("PT_REGS_MAGIC", SPARC64_PT_REGS_MAGIC, 0x57ac6c00UL);
    CHECK_CONST("STACK_BIAS", SPARC64_STACK_BIAS, 2047);
    CHECK_CONST("SIGMASK_SIZE", SPARC64_SIGMASK_SIZE, 8);
    CHECK_CONST("RT_SIGFRAME_SIZE", SPARC64_RT_SIGFRAME_SIZE, 528);
}

static void check_ucontext(void)
{
    CHECK_SIZE(sparc64_mcontext_t, 160);
    CHECK_SIZE(sparc64_sigcontext_t, 168);
    CHECK_OFF(sparc64_sigcontext_t, regs, 0);
    CHECK_OFF(sparc64_sigcontext_t, mask, 160);
    CHECK_SIZE(sparc64_ucontext_t, 216);
    CHECK_OFF(sparc64_ucontext_t, uc_flags, 0);
    CHECK_OFF(sparc64_ucontext_t, uc_link, 8);
    CHECK_OFF(sparc64_ucontext_t, uc_stack, 16);
    CHECK_OFF(sparc64_ucontext_t, uc_mcontext, 40);
    CHECK_OFF(sparc64_ucontext_t, uc_sigmask, 208);
}

static void check_stat(void)
{
    CHECK_SIZE(sparc64_stat_t, 104);
    CHECK_OFF(sparc64_stat_t, st_dev, 0x00);
    CHECK_OFF(sparc64_stat_t, st_ino, 0x08);
    CHECK_OFF(sparc64_stat_t, st_mode, 0x10);
    CHECK_OFF(sparc64_stat_t, st_nlink, 0x14);
    CHECK_OFF(sparc64_stat_t, st_uid, 0x18);
    CHECK_OFF(sparc64_stat_t, st_gid, 0x1c);
    CHECK_OFF(sparc64_stat_t, st_rdev, 0x20);
    CHECK_OFF(sparc64_stat_t, st_size, 0x28);
    CHECK_OFF(sparc64_stat_t, st_atime, 0x30);
    CHECK_OFF(sparc64_stat_t, st_mtime, 0x38);
    CHECK_OFF(sparc64_stat_t, st_ctime, 0x40);
    CHECK_OFF(sparc64_stat_t, st_blksize, 0x48);
    CHECK_OFF(sparc64_stat_t, st_blocks, 0x50);
    CHECK_OFF(sparc64_stat_t, __unused4, 0x58);

    CHECK_SIZE(sparc64_stat64_t, 144);
    CHECK_OFF(sparc64_stat64_t, st_dev, 0x00);
    CHECK_OFF(sparc64_stat64_t, st_ino, 0x08);
    CHECK_OFF(sparc64_stat64_t, st_nlink, 0x10);
    CHECK_OFF(sparc64_stat64_t, st_mode, 0x18);
    CHECK_OFF(sparc64_stat64_t, st_uid, 0x1c);
    CHECK_OFF(sparc64_stat64_t, st_gid, 0x20);
    CHECK_OFF(sparc64_stat64_t, __pad0, 0x24);
    CHECK_OFF(sparc64_stat64_t, st_rdev, 0x28);
    CHECK_OFF(sparc64_stat64_t, st_size, 0x30);
    CHECK_OFF(sparc64_stat64_t, st_blksize, 0x38);
    CHECK_OFF(sparc64_stat64_t, st_blocks, 0x40);
    CHECK_OFF(sparc64_stat64_t, st_atime, 0x48);
    CHECK_OFF(sparc64_stat64_t, st_atime_nsec, 0x50);
    CHECK_OFF(sparc64_stat64_t, st_mtime, 0x58);
    CHECK_OFF(sparc64_stat64_t, st_mtime_nsec, 0x60);
    CHECK_OFF(sparc64_stat64_t, st_ctime, 0x68);
    CHECK_OFF(sparc64_stat64_t, st_ctime_nsec, 0x70);
    CHECK_OFF(sparc64_stat64_t, __unused_tail, 0x78);
}

int main(void)
{
    check_ctx();
    check_sigframe();
    check_ucontext();
    check_stat();
    if (failures != 0) {
        printf("FAILURES: %d\n", failures);
        return 1;
    }
    printf("PASS\n");
    return 0;
}
