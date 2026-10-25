/*
 * src/os/sigframe_sparc64rt.h — frozen SPARC64 signal-frame + stat UAPI
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Lane L0b owns this file (Phase 0 freeze, SPEC section 2.1,
 * experiments/E04/FINDINGS.md). Other lanes must not edit it; escalate
 * instead.
 *
 * Layout authority, in order:
 *   1. SPEC section 2.1 (frozen offsets, implemented verbatim below).
 *   2. Linux arch/sparc/include/uapi/asm/ptrace.h (sparc_stackf, pt_regs),
 *      arch/sparc/include/uapi/asm/stat.h (stat, stat64),
 *      include/uapi/asm-generic/siginfo.h (siginfo_t, 128 B),
 *      arch/sparc/include/uapi/asm/signal.h (signo constants, sigset words).
 *   3. Oracle behavior (qemu-sparc64, E04): signo in %o0, I1 == I2 == &info,
 *      %o7 == restorer, tpc/tnpc recoverable, fpu_save points at the inline
 *      sigfpu tail, rt_sigaction is 5-arg with sigsetsize 8.
 *
 * Handler ABI (E04 + signal_64.c setup_rt_frame/do_rt_sigreturn):
 *   - signo delivered in %o0 (regs.u_regs[UREG_I0], UREG_I0 == 8).
 *   - regs.u_regs[UREG_I1] == regs.u_regs[UREG_I2] == &sf->info (both point
 *     at sf->info, +0xC0 from the unbiased frame base).
 *   - regs.u_regs[UREG_I7] (%o7) holds the rt_sigaction restorer argument.
 *   - Frame placed at unbiased_sp = %sp + 2047 (16-byte aligned); handler
 *     receives biased %sp = unbiased_sp - 2047, i.e. FP = (uint64_t)sf - 2047.
 *   - regs carries the interrupted tstate/tpc/tnpc/y; rt_sigreturn restores
 *     tpc/tnpc, y, u_regs[G1..I7], mask, and altstack from the frame.
 *   - rt_sigaction (nr 102) is 5-arg: sig, act, oact, restorer, sigsetsize
 *     (== 8, sizeof kernel sigset_t); the 4-arg form is EINVAL (E04).
 *   - Kernel vs libc types differ: kernel sigset_t is 8 B (1 x u64, hence
 *     sigsetsize == 8) while libc sigset_t is 128 B; kernel
 *     struct sigaction is 32 B (handler@0 flags@8 restorer@16 mask@24)
 *     while libc's is larger (E04 finding 7).
 */

#ifndef SPARC64RT_OS_SIGFRAME_SPARC64RT_H
#define SPARC64RT_OS_SIGFRAME_SPARC64RT_H

#include <stddef.h>
#include <stdint.h>

/* ---- Frame geometry (SPEC section 2.1, frozen) --------------------------- */
#define SPARC64_SS_SIZE          192U
#define SPARC64_SIGINFO_SIZE     128U
#define SPARC64_PT_REGS_SIZE     160U
#define SPARC64_SIGMASK_SIZE     8U
#define SPARC64_STACK_SIZE       24U
#define SPARC64_RT_SIGFRAME_SIZE 528U

#define SPARC64_RT_OFF_SS        0x000U
#define SPARC64_RT_OFF_INFO      0x0c0U
#define SPARC64_RT_OFF_REGS      0x140U
#define SPARC64_RT_OFF_FPU_SAVE  0x1e0U
#define SPARC64_RT_OFF_STACK     0x1e8U
#define SPARC64_RT_OFF_MASK      0x200U
#define SPARC64_RT_OFF_RWIN_SAVE 0x208U

/* Stack bias, syscall + signal constants (SPEC 2.1, E04, uapi).
 * SPARC64_STACK_BIAS is frozen in src/core/cpu.h; reuse it here so the
 * two headers agree without a duplicate definition. */
#ifndef SPARC64_STACK_BIAS
#define SPARC64_STACK_BIAS       2047U /* 0x7ff: unbiased_sp = %sp + 2047 */
#endif
#define SPARC64_NR_RT_SIGRETURN  101U
#define SPARC64_NR_RT_SIGACTION  102U
#define SPARC64_TA_6D            0x91d0206dU /* ta 0x6d */
#define SPARC64_SIGUSR1          30U
#define SPARC64_SA_SIGINFO       0x200U
#define SPARC64_PT_REGS_MAGIC    0x57ac6c00U /* PT_REGS_MAGIC */

/* pt_regs u_regs[] indices (uapi asm/ptrace.h UREG_*; register windows are
 * flushed to the stack before delivery, u_regs carries %g + %o view). */
enum {
    SPARC64_UREG_G0 = 0,
    SPARC64_UREG_G1 = 1,
    SPARC64_UREG_G2 = 2,
    SPARC64_UREG_G3 = 3,
    SPARC64_UREG_G4 = 4,
    SPARC64_UREG_G5 = 5,
    SPARC64_UREG_G6 = 6,
    SPARC64_UREG_G7 = 7,
    SPARC64_UREG_I0 = 8,  /* handler %o0 (signo) aliases this slot */
    SPARC64_UREG_I1 = 9,  /* handler %o1 (&info) aliases this slot */
    SPARC64_UREG_I2 = 10, /* handler %o2 (&info) aliases this slot */
    SPARC64_UREG_I3 = 11,
    SPARC64_UREG_I4 = 12,
    SPARC64_UREG_I5 = 13,
    SPARC64_UREG_I6 = 14, /* UREG_FP: interrupted %sp + 2047 lives here */
    SPARC64_UREG_I7 = 15  /* UREG_RETPC: restorer address lives here */
};
#define SPARC64_UREG_FP    SPARC64_UREG_I6
#define SPARC64_UREG_RETPC SPARC64_UREG_I7

/* ---- struct sparc_stackf (192 B, uapi asm/ptrace.h, 64-bit) -------------- */
typedef struct {
    uint64_t locals[8];   /* 0x00 */
    uint64_t ins[6];      /* 0x40 */
    uint64_t fp;          /* 0x70 guest VA of the save area (or 0) */
    uint64_t callers_pc;  /* 0x78 */
    uint64_t structptr;   /* 0x80 */
    uint64_t xargs[6];    /* 0x88 */
    uint64_t xxargs[1];   /* 0xb8 */
} sparc64_stackf_t;

_Static_assert(sizeof(sparc64_stackf_t) == 192, "sparc_stackf must be 192 bytes");
_Static_assert(offsetof(sparc64_stackf_t, locals) == 0x00, "locals at 0x00");
_Static_assert(offsetof(sparc64_stackf_t, ins) == 0x40, "ins at 0x40");
_Static_assert(offsetof(sparc64_stackf_t, fp) == 0x70, "fp at 112");
_Static_assert(offsetof(sparc64_stackf_t, callers_pc) == 0x78, "callers_pc at 120");
_Static_assert(offsetof(sparc64_stackf_t, structptr) == 0x80, "structptr at 128");
_Static_assert(offsetof(sparc64_stackf_t, xargs) == 0x88, "xargs at 136");
_Static_assert(offsetof(sparc64_stackf_t, xxargs) == 0xb8, "xxargs at 184");

/* ---- siginfo_t (128 B, include/uapi/asm-generic/siginfo.h).
 * Kernel-exact 64-bit layout: union __sifields is pointer-carrying, hence
 * 8-byte aligned, so _sifields sits at +16 (4 pad bytes after si_code) and
 * spans 112 bytes. si_addr is the FIRST _sigfault member (+16); the
 * trapno/addr_lsb/bounds tail (used on sparc) follows at +24. si_pid/si_uid
 * share +16/+20 for both _kill and _rt; si_value (_rt._sigval) is at +24. -- */
typedef struct {
    int32_t si_signo; /* 0x00 */
    int32_t si_errno; /* 0x04 */
    int32_t si_code;  /* 0x08 */
    uint8_t __pad[4]; /* 0x0c alignment to union __sifields */
    union {
        uint8_t raw[112];     /* 0x10 */
        struct {
            int32_t  pid;     /* 0x10 sender's pid (_kill/_rt) */
            uint32_t uid;     /* 0x14 sender's uid */
            uint64_t value;   /* 0x18 sigval (_rt._sigval) */
        } kill;
        struct {
            uint64_t addr;    /* 0x10 faulting insn/memory ref. */
            union {
                int32_t trapno;   /* 0x18 TRAP # (used on sparc) */
                int16_t addr_lsb; /* 0x18 LSB of the reported address */
                struct {
                    uint8_t  dummy[8]; /* 0x18 */
                    uint64_t lower;    /* 0x20 bound, lower */
                    uint64_t upper;    /* 0x28 bound, upper */
                } bnd;
            } u;
        } fault;
    } sifields; /* 0x10 */
} sparc64_siginfo_t;

_Static_assert(sizeof(sparc64_siginfo_t) == 128, "siginfo_t must be 128 bytes");
_Static_assert(offsetof(sparc64_siginfo_t, si_signo) == 0x00, "si_signo at 0");
_Static_assert(offsetof(sparc64_siginfo_t, si_errno) == 0x04, "si_errno at 4");
_Static_assert(offsetof(sparc64_siginfo_t, si_code) == 0x08, "si_code at 8");
_Static_assert(offsetof(sparc64_siginfo_t, sifields) == 0x10, "sifields at 16");
_Static_assert(offsetof(sparc64_siginfo_t, sifields.kill.pid) == 0x10,
               "si_pid at siginfo+16");
_Static_assert(offsetof(sparc64_siginfo_t, sifields.kill.uid) == 0x14,
               "si_uid at siginfo+20");
_Static_assert(offsetof(sparc64_siginfo_t, sifields.kill.value) == 0x18,
               "si_value at siginfo+24");
_Static_assert(offsetof(sparc64_siginfo_t, sifields.fault.addr) == 0x10,
               "si_addr at siginfo+16");
_Static_assert(offsetof(sparc64_siginfo_t, sifields.fault.u.trapno) == 0x18,
               "si_trapno at siginfo+24");
_Static_assert(offsetof(sparc64_siginfo_t, sifields.fault.u.addr_lsb) == 0x18,
               "si_addr_lsb at siginfo+24");
_Static_assert(offsetof(sparc64_siginfo_t, sifields.fault.u.bnd.lower) == 0x20,
               "si_lower at siginfo+32");
_Static_assert(offsetof(sparc64_siginfo_t, sifields.fault.u.bnd.upper) == 0x28,
               "si_upper at siginfo+40");

/* ---- struct pt_regs (160 B, uapi asm/ptrace.h, 64-bit) ------------------- */
typedef struct {
    uint64_t u_regs[16]; /* 0x00 %g0..%g7, %o0..%o7 */
    uint64_t tstate;     /* 0x80 carries CCR icc/xcc */
    uint64_t tpc;         /* 0x88 interrupted tpc */
    uint64_t tnpc;        /* 0x90 interrupted tnpc */
    uint32_t y;           /* 0x98 */
    uint32_t magic;       /* 0x9c PT_REGS_MAGIC | %tt */
} sparc64_pt_regs_t;

_Static_assert(sizeof(sparc64_pt_regs_t) == 160, "pt_regs must be 160 bytes");
_Static_assert(offsetof(sparc64_pt_regs_t, u_regs) == 0x00, "u_regs at 0");
_Static_assert(offsetof(sparc64_pt_regs_t, tstate) == 0x80, "tstate at 128");
_Static_assert(offsetof(sparc64_pt_regs_t, tpc) == 0x88, "tpc at 136");
_Static_assert(offsetof(sparc64_pt_regs_t, tnpc) == 0x90, "tnpc at 144");
_Static_assert(offsetof(sparc64_pt_regs_t, y) == 0x98, "y at 152");
_Static_assert(offsetof(sparc64_pt_regs_t, magic) == 0x9c, "magic at 156");
_Static_assert(SPARC64_UREG_FP == 14, "UREG_FP == UREG_I6 == 14");
_Static_assert(SPARC64_UREG_RETPC == 15, "UREG_RETPC == UREG_I7 == 15");

/* ---- kernel sigset_t (8 B: _NSIG_WORDS == 1 on 64-bit sparc) -------------- */
typedef struct {
    uint64_t sig; /* 0x00 */
} sparc64_sigmask_t;

_Static_assert(sizeof(sparc64_sigmask_t) == 8, "sigset_t must be 8 bytes");
_Static_assert(offsetof(sparc64_sigmask_t, sig) == 0, "sig at 0");

/* ---- stack_t / sigaltstack (24 B, asm-generic uapi) ----------------------- */
typedef struct {
    uint64_t ss_sp;    /* 0x00 */
    int32_t  ss_flags; /* 0x08 */
    int32_t  _pad;     /* 0x0c */
    uint64_t ss_size;  /* 0x10 */
} sparc64_stack_t;

_Static_assert(sizeof(sparc64_stack_t) == 24, "stack_t must be 24 bytes");
_Static_assert(offsetof(sparc64_stack_t, ss_sp) == 0x00, "ss_sp at 0");
_Static_assert(offsetof(sparc64_stack_t, ss_flags) == 0x08, "ss_flags at 8");
_Static_assert(offsetof(sparc64_stack_t, ss_size) == 0x10, "ss_size at 16");

/* ---- kernel struct sigaction (32 B, uapi asm/signal.h, E04-verified) ------ */
typedef struct {
    uint64_t sa_handler; /* 0x00 guest function pointer */
    uint64_t sa_flags;   /* 0x08 */
    uint64_t sa_restorer; /* 0x10 guest restorer pointer (%o7 value) */
    uint64_t sa_mask;    /* 0x18 blocked mask (kernel sigset_t) */
} sparc64_sigaction_t;

_Static_assert(sizeof(sparc64_sigaction_t) == 32, "sigaction must be 32 bytes");
_Static_assert(offsetof(sparc64_sigaction_t, sa_handler) == 0x00, "handler at 0");
_Static_assert(offsetof(sparc64_sigaction_t, sa_flags) == 0x08, "flags at 8");
_Static_assert(offsetof(sparc64_sigaction_t, sa_restorer) == 0x10, "restorer at 16");
_Static_assert(offsetof(sparc64_sigaction_t, sa_mask) == 0x18, "mask at 24");

/* ---- rt_signal_frame64 (528 B, SPEC 2.1 + E04 klayout, frozen) ------------ */
typedef struct {
    sparc64_stackf_t  ss;        /* 0x000 */
    sparc64_siginfo_t info;      /* 0x0c0 */
    sparc64_pt_regs_t regs;      /* 0x140 */
    uint64_t          fpu_save;  /* 0x1e0 guest ptr to sigfpu tail or 0 */
    sparc64_stack_t   stack;     /* 0x1e8 sigaltstack */
    uint64_t          mask;      /* 0x200 blocked mask (kernel sigset_t) */
    uint64_t          rwin_save; /* 0x208 guest ptr to saved windows or 0 */
} sparc64_rt_sigframe_t;

_Static_assert(sizeof(sparc64_rt_sigframe_t) == 528, "rt frame must be 528 bytes");
_Static_assert(offsetof(sparc64_rt_sigframe_t, ss) == 0x000, "ss at 0x000");
_Static_assert(offsetof(sparc64_rt_sigframe_t, info) == 0x0c0, "info at 0x0c0");
_Static_assert(offsetof(sparc64_rt_sigframe_t, regs) == 0x140, "regs at 0x140");
_Static_assert(offsetof(sparc64_rt_sigframe_t, fpu_save) == 0x1e0, "fpu_save at 0x1e0");
_Static_assert(offsetof(sparc64_rt_sigframe_t, stack) == 0x1e8, "stack at 0x1e8");
_Static_assert(offsetof(sparc64_rt_sigframe_t, mask) == 0x200, "mask at 0x200");
_Static_assert(offsetof(sparc64_rt_sigframe_t, rwin_save) == 0x208, "rwin_save at 0x208");
_Static_assert(offsetof(sparc64_rt_sigframe_t, regs.tstate) == 0x1c0,
               "frame tstate at 0x1c0");
_Static_assert(offsetof(sparc64_rt_sigframe_t, regs.tpc) == 0x1c8,
               "frame tpc at 0x1c8");
_Static_assert(offsetof(sparc64_rt_sigframe_t, regs.tnpc) == 0x1d0,
               "frame tnpc at 0x1d0");
_Static_assert(offsetof(sparc64_rt_sigframe_t, regs.y) == 0x1d8,
               "frame y at 0x1d8");
_Static_assert(offsetof(sparc64_rt_sigframe_t, regs.u_regs) == 0x140,
               "frame u_regs at 0x140");
_Static_assert(offsetof(sparc64_rt_sigframe_t, stack.ss_sp) == 0x1e8,
               "frame ss_sp at 0x1e8");
_Static_assert(offsetof(sparc64_rt_sigframe_t, stack.ss_size) == 0x1f8,
               "frame ss_size at 0x1f8");

/*
 * ucontext/sigcontext/mcontext views (L0b-owned translator-side views, NOT
 * kernel ABI: asm/sigcontext.h is empty on 64-bit sparc and do_rt_sigreturn
 * consumes regs, mask, and stack directly from rt_signal_frame64). These
 * views bind Phase 4 code to exactly those frame-carried pieces; their
 * packing is internal to the translator.
 */
typedef sparc64_pt_regs_t sparc64_mcontext_t; /* machine context == pt_regs */

typedef struct {
    sparc64_pt_regs_t regs; /* restorable register state */
    uint64_t          mask; /* restorable blocked mask */
} sparc64_sigcontext_t;

typedef struct {
    uint64_t             uc_flags;
    uint64_t             uc_link;   /* guest ptr to outer ucontext or 0 */
    sparc64_stack_t      uc_stack;  /* sigaltstack */
    sparc64_sigcontext_t uc_mcontext;
    uint64_t             uc_sigmask;
} sparc64_ucontext_t;

_Static_assert(sizeof(sparc64_mcontext_t) == 160, "mcontext == pt_regs, 160 bytes");
_Static_assert(sizeof(sparc64_sigcontext_t) == 168, "sigcontext must be 168 bytes");
_Static_assert(offsetof(sparc64_sigcontext_t, regs) == 0, "sc.regs at 0");
_Static_assert(offsetof(sparc64_sigcontext_t, mask) == 160, "sc.mask at 160");
_Static_assert(sizeof(sparc64_ucontext_t) == 216, "ucontext must be 216 bytes");
_Static_assert(offsetof(sparc64_ucontext_t, uc_flags) == 0, "uc_flags at 0");
_Static_assert(offsetof(sparc64_ucontext_t, uc_link) == 8, "uc_link at 8");
_Static_assert(offsetof(sparc64_ucontext_t, uc_stack) == 16, "uc_stack at 16");
_Static_assert(offsetof(sparc64_ucontext_t, uc_mcontext) == 40, "uc_mcontext at 40");
_Static_assert(offsetof(sparc64_ucontext_t, uc_sigmask) == 208, "uc_sigmask at 208");

/* ---- struct stat (104 B, uapi asm/stat.h, 64-bit sparc).
 * Note the quirks: no nsec fields (no STAT_HAVE_NSEC on 64-bit sparc),
 * st_nlink stays 16-bit, and st_dev is 32-bit with explicit padding. ------- */
typedef struct {
    uint32_t st_dev;       /* 0x00 */
    uint32_t __pad1;       /* 0x04 */
    uint64_t st_ino;       /* 0x08 */
    uint32_t st_mode;      /* 0x10 */
    int16_t  st_nlink;     /* 0x14 */
    uint8_t  __pad2[2];    /* 0x16 */
    uint32_t st_uid;       /* 0x18 */
    uint32_t st_gid;       /* 0x1c */
    uint32_t st_rdev;      /* 0x20 */
    uint8_t  __pad3[4];    /* 0x24 */
    int64_t  st_size;      /* 0x28 */
    int64_t  st_atime;     /* 0x30 */
    int64_t  st_mtime;     /* 0x38 */
    int64_t  st_ctime;     /* 0x40 */
    int64_t  st_blksize;   /* 0x48 */
    int64_t  st_blocks;    /* 0x50 */
    uint64_t __unused4[2]; /* 0x58 */
} sparc64_stat_t;

_Static_assert(sizeof(sparc64_stat_t) == 104, "stat must be 104 bytes");
_Static_assert(offsetof(sparc64_stat_t, st_dev) == 0x00, "st_dev at 0");
_Static_assert(offsetof(sparc64_stat_t, st_ino) == 0x08, "st_ino at 8");
_Static_assert(offsetof(sparc64_stat_t, st_mode) == 0x10, "st_mode at 16");
_Static_assert(offsetof(sparc64_stat_t, st_nlink) == 0x14, "st_nlink at 20");
_Static_assert(offsetof(sparc64_stat_t, st_uid) == 0x18, "st_uid at 24");
_Static_assert(offsetof(sparc64_stat_t, st_gid) == 0x1c, "st_gid at 28");
_Static_assert(offsetof(sparc64_stat_t, st_rdev) == 0x20, "st_rdev at 32");
_Static_assert(offsetof(sparc64_stat_t, st_size) == 0x28, "st_size at 40");
_Static_assert(offsetof(sparc64_stat_t, st_atime) == 0x30, "st_atime at 48");
_Static_assert(offsetof(sparc64_stat_t, st_mtime) == 0x38, "st_mtime at 56");
_Static_assert(offsetof(sparc64_stat_t, st_ctime) == 0x40, "st_ctime at 64");
_Static_assert(offsetof(sparc64_stat_t, st_blksize) == 0x48, "st_blksize at 72");
_Static_assert(offsetof(sparc64_stat_t, st_blocks) == 0x50, "st_blocks at 80");
_Static_assert(offsetof(sparc64_stat_t, __unused4) == 0x58, "__unused4 at 88");

/* ---- struct stat64 (144 B, uapi asm/stat.h, 64-bit sparc).
 * Note the quirk: st_nlink is 64-bit here (unlike struct stat). ------------- */
typedef struct {
    uint64_t st_dev;        /* 0x00 */
    uint64_t st_ino;        /* 0x08 */
    uint64_t st_nlink;      /* 0x10 */
    uint32_t st_mode;       /* 0x18 */
    uint32_t st_uid;        /* 0x1c */
    uint32_t st_gid;        /* 0x20 */
    uint32_t __pad0;        /* 0x24 */
    uint64_t st_rdev;       /* 0x28 */
    int64_t  st_size;       /* 0x30 */
    int64_t  st_blksize;    /* 0x38 */
    int64_t  st_blocks;     /* 0x40 */
    uint64_t st_atime;      /* 0x48 */
    uint64_t st_atime_nsec; /* 0x50 */
    uint64_t st_mtime;      /* 0x58 */
    uint64_t st_mtime_nsec; /* 0x60 */
    uint64_t st_ctime;      /* 0x68 */
    uint64_t st_ctime_nsec; /* 0x70 */
    int64_t  __unused_tail[3]; /* 0x78 (kernel names it __unused;
                                 renamed: __unused is a host attribute
                                 macro on some platforms) */
} sparc64_stat64_t;

_Static_assert(sizeof(sparc64_stat64_t) == 144, "stat64 must be 144 bytes");
_Static_assert(offsetof(sparc64_stat64_t, st_dev) == 0x00, "st_dev at 0");
_Static_assert(offsetof(sparc64_stat64_t, st_ino) == 0x08, "st_ino at 8");
_Static_assert(offsetof(sparc64_stat64_t, st_nlink) == 0x10, "st_nlink at 16");
_Static_assert(offsetof(sparc64_stat64_t, st_mode) == 0x18, "st_mode at 24");
_Static_assert(offsetof(sparc64_stat64_t, st_uid) == 0x1c, "st_uid at 28");
_Static_assert(offsetof(sparc64_stat64_t, st_gid) == 0x20, "st_gid at 32");
_Static_assert(offsetof(sparc64_stat64_t, __pad0) == 0x24, "__pad0 at 36");
_Static_assert(offsetof(sparc64_stat64_t, st_rdev) == 0x28, "st_rdev at 40");
_Static_assert(offsetof(sparc64_stat64_t, st_size) == 0x30, "st_size at 48");
_Static_assert(offsetof(sparc64_stat64_t, st_blksize) == 0x38, "st_blksize at 56");
_Static_assert(offsetof(sparc64_stat64_t, st_blocks) == 0x40, "st_blocks at 64");
_Static_assert(offsetof(sparc64_stat64_t, st_atime) == 0x48, "st_atime at 72");
_Static_assert(offsetof(sparc64_stat64_t, st_atime_nsec) == 0x50, "atime_nsec at 80");
_Static_assert(offsetof(sparc64_stat64_t, st_mtime) == 0x58, "st_mtime at 88");
_Static_assert(offsetof(sparc64_stat64_t, st_mtime_nsec) == 0x60, "mtime_nsec at 96");
_Static_assert(offsetof(sparc64_stat64_t, st_ctime) == 0x68, "st_ctime at 104");
_Static_assert(offsetof(sparc64_stat64_t, st_ctime_nsec) == 0x70, "ctime_nsec at 112");
_Static_assert(offsetof(sparc64_stat64_t, __unused_tail) == 0x78,
               "__unused_tail at 120");

#endif /* SPARC64RT_OS_SIGFRAME_SPARC64RT_H */
