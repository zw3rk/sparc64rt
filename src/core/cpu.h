/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Frozen SPARC V9 (sparc64, Oracle M8 / Fujitsu SPARC64 XII) CPU context.
 * Field layout of the ABI-locked prefix is verified by
 * tests/check_abi_invariants.c (lane L0b) and must not change without a
 * phase-level review checkpoint.
 *
 * CPU state (SPEC section 2.1): active 32-register view r[32]
 * (%g0..%g7 = r[0..7] with r[0] hardwired to 0, %o0..%o7 = r[8..15] with
 * %o6 = %sp, %l0..%l7 = r[16..23], %i0..%i7 = r[24..31] with %i6 = %fp),
 * pc, npc, y, ccr (icc in bits 3:0, xcc in bits 7:4), fsr (fcc0 in bits
 * 11:10, fcc1..fcc3 in bits 35:32), gsr (alignaddr/faligndata), fprs,
 * asi, FPU file (%f0..%f31 / %d0..%d62 / %q0..%q60), window state (cwp,
 * cansave, canrestore, otherwin, cleanwin, wim, nwindows) and pil.
 * SAVE/RESTORE spill/fill 16 x 64-bit big-endian registers at
 * [%sp + 2047 .. %sp + 2047 + 120] (STACK_BIAS 2047).
 *
 * The ported rt64 substrate (src/rt64/memory, src/rt64/runtime,
 * src/rt64/linux, src/rt64/aot, vendored from ../rvrt/src with
 * rv_ -> sparc64_ renames) addresses this context as sparc64_cpu_t and
 * drives it through sparc64_decode / sparc64_step (src/interp/,
 * Phase 1) and the AArch64 DBT (src/dbt/, Phase 2).
 */
#ifndef SPARC64RT_CORE_CPU_H
#define SPARC64RT_CORE_CPU_H

#include "rt64/core/atomic.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Active register-view indices. */
#define SPARC64_G0 0U
#define SPARC64_G1 1U
#define SPARC64_G2 2U
#define SPARC64_G3 3U
#define SPARC64_G4 4U
#define SPARC64_G5 5U
#define SPARC64_G6 6U
#define SPARC64_G7 7U
#define SPARC64_O0 8U
#define SPARC64_O1 9U
#define SPARC64_O2 10U
#define SPARC64_O3 11U
#define SPARC64_O4 12U
#define SPARC64_O5 13U
#define SPARC64_O6 14U
#define SPARC64_O7 15U
#define SPARC64_SP 14U /* %o6 = %sp */
#define SPARC64_L0 16U
#define SPARC64_I0 24U
#define SPARC64_I6 30U
#define SPARC64_FP 30U /* %i6 = %fp */

/* CCR condition-code bits (SPARC V9 Tc CCR: icc in bits 3:0 as
 * N/Z/V/C, xcc in bits 7:4 as N/Z/V/C). The ta 0x6d syscall path
 * clears/sets BOTH carry bits (bit 0 icc.C, bit 4 xcc.C). */
#define SPARC64_CCR_ICC_N (1ULL << 3)
#define SPARC64_CCR_ICC_Z (1ULL << 2)
#define SPARC64_CCR_ICC_V (1ULL << 1)
#define SPARC64_CCR_ICC_C (1ULL << 0)
#define SPARC64_CCR_XCC_N (1ULL << 7)
#define SPARC64_CCR_XCC_Z (1ULL << 6)
#define SPARC64_CCR_XCC_V (1ULL << 5)
#define SPARC64_CCR_XCC_C (1ULL << 4)

/* FSR floating-point condition codes (fcc0 in bits 11:10). */
#define SPARC64_FSR_FCC0_SHIFT 10U
#define SPARC64_FSR_FCC0_MASK (3ULL << SPARC64_FSR_FCC0_SHIFT)

/* Register-window constants (8 windows, Oracle M8 / SPARC64 XII). */
#define SPARC64_NWINDOWS 8U
/* Mandatory stack bias: rwindow save area lives at [%sp + 2047]. */
#define SPARC64_STACK_BIAS 2047ULL
/* 16 x 64-bit spill/fill area (SPEC 2.1 struct rwindow_64, 128 bytes). */
#define SPARC64_RWINDOW_SIZE 128ULL

/* Guest user address space: 1ULL << 47 (128 TiB, va_bits = 47).
 * Guest VAs are full 64-bit values, never truncated to 32 bits. */
#define SPARC64_VA_BITS 47
#define SPARC64_TASK_SIZE (UINT64_C(1) << SPARC64_VA_BITS)

/* ELF admission (SPEC 1.1): ELFCLASS64, ELFDATA2MSB, EM_SPARCV9. */
#define SPARC64_ELFCLASS64 2U
#define SPARC64_ELFDATA2MSB 2U
#define SPARC64_EM_SPARCV9 43U

/* Block exit reasons (engines report through ctx->exit_reason). */
#define SPARC64_EXIT_NONE 0U
#define SPARC64_EXIT_BRANCH 1U
#define SPARC64_EXIT_SYSCALL 2U /* ta 0x6d: %g1 = nr, %o0..%o5 = args */
#define SPARC64_EXIT_UNDEF 3U
#define SPARC64_EXIT_FAULT 4U
#define SPARC64_EXIT_TRAP 5U
#define SPARC64_EXIT_SINGLE_STEP 6U

/* Architectural limits and cache capacities. Guest page size is defined
 * by the ported substrate (src/rt64/memory/space.h, SPARC64_PAGE_SIZE). */
#define SPARC64_RAS_SIZE 64U
#define SPARC64_IBTC_SIZE 4096U

/* Engine selection (SPARC64RT_ENGINE, --engine). */
enum {
    SPARC64_ENGINE_INTERP = 0, /* portable C interpreter: oracle engine */
    SPARC64_ENGINE_DBT = 1     /* SPARC V9 -> A64 dynamic binary translator */
};

/*
 * Architectural + dispatcher state for one SPARC V9 guest thread.
 *
 * ABI-locked prefix (offsets verified in check_abi_invariants):
 *   0x000 r[32]            active window view (r[0] reads as 0)
 *   0x100 pc, 0x108 npc, 0x110 y, 0x118 ccr
 *   0x120 fsr, 0x128 gsr, 0x130 fprs, 0x138 asi, 0x13c pil
 *   0x140 fp union, 256 bytes (f[32] / d[32] / q[16])
 *   0x240 fcc[4]
 *   0x250 cwp, cansave, canrestore, otherwin, cleanwin, wim, nwindows
 *   0x270 exit_reason / exit_arg, 0x278 fault_addr, 0x280 exit_dest
 */
typedef struct sparc64_ctx {
    uint64_t r[32]; /* 0x000 active window view */
    uint64_t pc;    /* 0x100 */
    uint64_t npc;   /* 0x108 */
    uint64_t y;     /* 0x110 */
    uint64_t ccr;   /* 0x118 */
    uint64_t fsr;   /* 0x120 */
    uint64_t gsr;   /* 0x128 */
    uint64_t fprs;  /* 0x130 */
    uint32_t asi;   /* 0x138 current address-space identifier */
    uint32_t pil;   /* 0x13c processor interrupt level */
    union {         /* 0x140 FPU register file, 256 bytes */
        uint32_t f[32];     /* %f0..%f31 single */
        uint64_t d[32];     /* %d0..%d62 double overlay */
        __uint128_t q[16];  /* %q0..%q60 quad overlay (step 4) */
    } fp;
    uint32_t fcc[4];      /* 0x240 fcc0..fcc3 */
    uint32_t cwp;         /* 0x250 current window pointer */
    uint32_t cansave;     /* 0x254 */
    uint32_t canrestore;  /* 0x258 */
    uint32_t otherwin;    /* 0x25c */
    uint32_t cleanwin;    /* 0x260 */
    uint32_t wim;         /* 0x264 window invalid mask */
    uint32_t nwindows;    /* 0x268 */
    uint32_t pad_win;     /* 0x26c reserved */
    uint32_t exit_reason; /* 0x270 */
    uint32_t exit_arg;    /* 0x274 */
    uint64_t fault_addr;  /* 0x278 */
    uint64_t exit_dest;   /* 0x280 */

    /* ---- C-only tail (extend at end only, never inside the prefix) ---- */
    int      engine;        /* SPARC64_ENGINE_* */
    bool     difftest;
    bool     trace_enabled;
    uint64_t blocks_executed;
    uint64_t syscalls_executed;
} sparc64_ctx_t;

/* The ported rt64 substrate addresses the context through this alias. */
typedef sparc64_ctx_t sparc64_cpu_t;

/* ABI-locked offsets (Phase 2 trampoline + a64 emitter must agree). */
#define SPARC64_CTX_R_OFFSET 0x000U
#define SPARC64_CTX_PC_OFFSET 0x100U
#define SPARC64_CTX_NPC_OFFSET 0x108U
#define SPARC64_CTX_CCR_OFFSET 0x118U
#define SPARC64_CTX_FSR_OFFSET 0x120U
#define SPARC64_CTX_FP_OFFSET 0x140U
#define SPARC64_CTX_CWP_OFFSET 0x250U
#define SPARC64_CTX_EXIT_REASON_OFFSET 0x270U
#define SPARC64_CTX_FAULT_ADDR_OFFSET 0x278U
#define SPARC64_CTX_EXIT_DEST_OFFSET 0x280U

_Static_assert(offsetof(sparc64_ctx_t, r) == 0x000, "r at 0x000");
_Static_assert(offsetof(sparc64_ctx_t, pc) == 0x100, "pc at 0x100");
_Static_assert(offsetof(sparc64_ctx_t, npc) == 0x108, "npc at 0x108");
_Static_assert(offsetof(sparc64_ctx_t, y) == 0x110, "y at 0x110");
_Static_assert(offsetof(sparc64_ctx_t, ccr) == 0x118, "ccr at 0x118");
_Static_assert(offsetof(sparc64_ctx_t, fsr) == 0x120, "fsr at 0x120");
_Static_assert(offsetof(sparc64_ctx_t, gsr) == 0x128, "gsr at 0x128");
_Static_assert(offsetof(sparc64_ctx_t, fprs) == 0x130, "fprs at 0x130");
_Static_assert(offsetof(sparc64_ctx_t, asi) == 0x138, "asi at 0x138");
_Static_assert(offsetof(sparc64_ctx_t, pil) == 0x13c, "pil at 0x13c");
_Static_assert(offsetof(sparc64_ctx_t, fp) == 0x140, "fp at 0x140");
_Static_assert(offsetof(sparc64_ctx_t, fcc) == 0x240, "fcc at 0x240");
_Static_assert(offsetof(sparc64_ctx_t, cwp) == 0x250, "cwp at 0x250");
_Static_assert(offsetof(sparc64_ctx_t, nwindows) == 0x268, "nwindows at 0x268");
_Static_assert(offsetof(sparc64_ctx_t, exit_reason) == 0x270,
               "exit_reason at 0x270");
_Static_assert(offsetof(sparc64_ctx_t, fault_addr) == 0x278,
               "fault_addr at 0x278");
_Static_assert(offsetof(sparc64_ctx_t, exit_dest) == 0x280,
               "exit_dest at 0x280");
_Static_assert(sizeof(((sparc64_ctx_t *)0)->fp) == 256,
               "fp union spans 256 bytes");

static inline void sparc64_ctx_init(sparc64_ctx_t *ctx, uint64_t entry_pc)
{
    for (unsigned i = 0; i < 32; ++i)
        ctx->r[i] = UINT64_C(0);
    ctx->pc = entry_pc;
    ctx->npc = entry_pc + 4;
    ctx->y = UINT64_C(0);
    ctx->ccr = UINT64_C(0);
    ctx->fsr = UINT64_C(0);
    ctx->gsr = UINT64_C(0);
    ctx->fprs = UINT64_C(0);
    ctx->asi = 0U;
    ctx->pil = 0U;
    for (unsigned i = 0; i < 32; ++i)
        ctx->fp.f[i] = 0U;
    for (unsigned i = 0; i < 4; ++i)
        ctx->fcc[i] = 0U;
    ctx->cwp = 0U;
    ctx->cansave = 0U;
    ctx->canrestore = 0U;
    ctx->otherwin = 0U;
    ctx->cleanwin = 0U;
    ctx->wim = 0U;
    ctx->nwindows = SPARC64_NWINDOWS;
    ctx->exit_reason = SPARC64_EXIT_NONE;
    ctx->exit_arg = 0U;
    ctx->fault_addr = UINT64_C(0);
    ctx->exit_dest = UINT64_C(0);
    ctx->engine = SPARC64_ENGINE_INTERP;
    ctx->difftest = false;
    ctx->trace_enabled = false;
    ctx->blocks_executed = UINT64_C(0);
    ctx->syscalls_executed = UINT64_C(0);
}

/* Guest memory access classes and failure reasons. Guest address faults
 * are distinct from internal resource failures, which must never enter
 * guest signal delivery. */
typedef enum {
    SPARC64_ACCESS_FETCH,
    SPARC64_ACCESS_LOAD
} sparc64_access_t;

typedef enum {
    SPARC64_MEM_FAULT_NONE,
    SPARC64_MEM_FAULT_UNMAPPED,
    SPARC64_MEM_FAULT_PERMISSION,
    SPARC64_MEM_FAULT_RANGE,
    SPARC64_MEM_FAULT_BUS,
    SPARC64_MEM_FAULT_RESOURCE,
    SPARC64_MEM_FAULT_RETRY,
    SPARC64_MEM_FAULT_INTERNAL
} sparc64_mem_fault_reason_t;

typedef struct {
    uint64_t address;
    sparc64_mem_fault_reason_t reason;
} sparc64_mem_fault_t;

/* Checked guest memory operations. Integer bytes are in guest big-endian
 * order; the core never receives host pointers. */
typedef struct {
    bool (*read)(void *context, uint64_t address, void *bytes,
                 size_t size, sparc64_access_t access,
                 sparc64_mem_fault_t *fault);
    bool (*write)(void *context, uint64_t address, const void *bytes,
                  size_t size, sparc64_mem_fault_t *fault);
    bool (*atomic)(void *context, const sparc64_atomic_request_t *request,
                   sparc64_atomic_result_t *result,
                   sparc64_mem_fault_t *fault);
} sparc64_mem_ops_t;

/* One interpreter step outcome. RETRY/INTERNAL mark runtime conditions,
 * never an architectural guest trap. */
typedef enum {
    SPARC64_STEP_CONTINUE,
    SPARC64_STEP_SYSCALL,
    SPARC64_STEP_TRAP,
    SPARC64_STEP_RETRY,
    SPARC64_STEP_INTERNAL
} sparc64_step_kind_t;

/* Translator-internal trap causes consumed by the signal layer (Phase 4).
 * Phase 4 refines SPARC trap types (mem_address_not_aligned, illegal,
 * privileged, trap_instruction) without changing these members. */
typedef enum {
    SPARC64_TRAP_INST_MISALIGNED = 0,
    SPARC64_TRAP_INST_ACCESS = 1,
    SPARC64_TRAP_ILLEGAL = 2,
    SPARC64_TRAP_PRIVILEGED = 3,
    SPARC64_TRAP_LOAD_MISALIGNED = 4,
    SPARC64_TRAP_LOAD_ACCESS = 5,
    SPARC64_TRAP_STORE_MISALIGNED = 6,
    SPARC64_TRAP_STORE_ACCESS = 7
} sparc64_trap_cause_t;

typedef struct {
    sparc64_step_kind_t kind;
    sparc64_trap_cause_t cause;
    uint64_t pc;   /* Faulting instruction, including for syscall. */
    uint64_t tval; /* Faulting address or illegal instruction bits. */
    uint8_t length;
    sparc64_mem_fault_reason_t memory_reason;
} sparc64_step_result_t;

/* One fetched SPARC instruction: always 4 bytes. raw holds the
 * big-endian instruction word. */
typedef struct {
    uint64_t pc;
    uint32_t raw;
    uint8_t length;
} sparc64_insn_t;

static inline void sparc64_cpu_init(sparc64_cpu_t *cpu, uint64_t entry_pc)
{
    sparc64_ctx_init(cpu, entry_pc);
}

/* Reference interpreter entry points (defined in src/interp/, Phase 1).
 * decode fetches one instruction without executing it; step executes one;
 * step_with_insn exposes the actually fetched instruction to the caller so
 * the scheduler never refetches guest code that may have changed. */
sparc64_step_result_t sparc64_decode(const sparc64_cpu_t *cpu,
                                     const sparc64_mem_ops_t *memory,
                                     void *context,
                                     sparc64_insn_t *instruction);
sparc64_step_result_t sparc64_step(sparc64_cpu_t *cpu,
                                   const sparc64_mem_ops_t *memory,
                                   void *context);
sparc64_step_result_t sparc64_step_with_insn(sparc64_cpu_t *cpu,
                                             const sparc64_mem_ops_t *memory,
                                             void *context,
                                             sparc64_insn_t *executed);

#endif /* SPARC64RT_CORE_CPU_H */
