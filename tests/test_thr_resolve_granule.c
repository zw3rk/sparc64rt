/*
 * tests/test_thr_resolve_granule.c — host-atomic resolution granule probe.
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Wave U2 regression test (coordinator): the guest ABI page is 8 KiB
 * (GUEST_ABI_PAGE_SIZE) but the space substrate pages — and therefore
 * the Soft-TLB translation granule — stay 4 KiB. thr_resolve() (used by
 * the host-atomic fast path and futex pinning) must resolve at the 4 KiB
 * granule: resolving an upper-half address (offset 4096..8191 within an
 * 8 KiB chunk) at the 8 KiB base lands on the neighboring lower 4 KiB
 * page and reads/writes up to 4095 bytes past its heap backing
 * (heap overread + silent guest-memory corruption, observed as a
 * difftest g4 divergence on glibc's version_lock CASXA).
 *
 * Method: map one 8 KiB span as two 4 KiB pages with distinct patterns,
 * run a CASXA on an upper-half address through the public
 * sparc64_threads_try_host_atomic() entry, and verify the old value came
 * from the upper page, the swap landed in the upper page, and the lower
 * page is untouched. Deterministic stdout; exit 0 with
 * THR-RESOLVE-GRANULE-PASS iff every check passed.
 *
 * Build (worktree root):
 *   cc -std=c11 -Wall -Wextra -Werror=vla -pedantic -Isrc \
 *     tests/test_thr_resolve_granule.c src/os/threads.c \
 *     src/os/mem_space.c src/os/mem_space_write.c \
 *     -o _build/test_thr_resolve_granule -pthread
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "core/cpu.h"
#include "dbt/mem_sites.h"
#include "interp/interp.h"
#include "os/guest_run_priv.h"
#include "os/mem_space.h"
#include "os/sigframe_sparc64rt.h"
#include "os/sync_sig.h"
#include "os/syscalls_sig.h"
#include "os/threads.h"

/* ---- Test-only link stubs ---------------------------------------------
 * try_host_atomic() lives in src/os/threads.c alongside the clone and
 * futex paths, which reference two symbols this focused test never
 * executes (no threads are spawned, no futex waits run). The stubs below
 * exist only to close the link; reaching any of them fails the test. */
static int stub_reached = 0;

static bool test_mem_read(void *ctx, uint64_t va, void *dst, size_t n,
    sparc64_access_t acc, sparc64_mem_fault_t *fault);
static bool test_mem_write(void *ctx, uint64_t va, const void *src, size_t n,
    sparc64_mem_fault_t *fault);

sparc64_tlb_entry_t sparc64_dbt_tlb[SPARC64_TLB_SIZE]
    __attribute__((aligned(32)));
const sparc64_mem_ops_t guest_mem_ops = {
    test_mem_read,
    test_mem_write,
    NULL
};

long sparc64_l2a_futex(sparc64_ctx_t *ctx, const sparc64_syscall_mem_t *mem,
    uint64_t uaddr, uint64_t op, uint64_t val, uint64_t timeout_va)
{
    (void)ctx;
    (void)mem;
    (void)uaddr;
    (void)op;
    (void)val;
    (void)timeout_va;
    stub_reached = 1;
    return -1L;
}

void *sparc64_thread_entry(void *arg)
{
    (void)arg;
    stub_reached = 1;
    return arg;
}

/* The epoch-sync leg in thr_futex_wait() drops block-cache coverage
 * through this hook (never reached here: no mapping commits run, so
 * the generation never advances past its initial value). */
void sparc64_dbt_invalidate(sparc64_dbt_t *dbt, uint64_t va, uint64_t len)
{
    (void)dbt;
    (void)va;
    (void)len;
    stub_reached = 1;
}

#if !defined(__APPLE__) || !defined(__aarch64__)
/* Non-Darwin hosts compile the Darwin backend TUs to empty shells, so
 * the vm64 quiescence legs linked in for the epoch check close over
 * these stubs (no preemption or worker table exists there). */
int rt_host_preempt_worker(uint64_t host_tid)
{
    (void)host_tid;
    stub_reached = 1;
    return 0;
}

uint64_t rt_host_register_self(void)
{
    return UINT64_C(1);
}

void rt_host_unregister_self(void)
{
}
#endif

static bool test_mem_read(void *ctx, uint64_t va, void *dst, size_t n,
    sparc64_access_t acc, sparc64_mem_fault_t *fault)
{
    guest_state_t *g = (guest_state_t *)ctx;
    unsigned flags = (acc == SPARC64_ACCESS_FETCH) ?
        (unsigned)SPARC64_MEM_EXEC : (unsigned)SPARC64_MEM_READ;
    (void)fault;
    return sparc64_space_read(&g->space, va, dst, n, flags);
}

static bool test_mem_write(void *ctx, uint64_t va, const void *src, size_t n,
    sparc64_mem_fault_t *fault)
{
    guest_state_t *g = (guest_state_t *)ctx;
    (void)fault;
    return sparc64_space_write(&g->space, va, src, n);
}

static bool test_sys_read(void *ctx, uint64_t va, void *dst, uint64_t n)
{
    guest_state_t *g = (guest_state_t *)ctx;
    return sparc64_space_read(&g->space, va, dst, (size_t)n,
        (unsigned)SPARC64_MEM_READ);
}

static bool test_sys_write(void *ctx, uint64_t va, const void *src, uint64_t n)
{
    guest_state_t *g = (guest_state_t *)ctx;
    return sparc64_space_write(&g->space, va, src, (size_t)n);
}

static bool test_sys_prep(void *ctx, uint64_t va, uint64_t n)
{
    (void)ctx;
    (void)va;
    (void)n;
    return true;
}

static int fails = 0;

static void check(const char *ok, const char *bad, int passed)
{
    if (passed) {
        (void)printf("%s\n", ok);
    } else {
        (void)printf("%s\n", bad);
        fails++;
    }
}

/* Store a u64 to 8 bytes in guest (big-endian) order. */
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

int main(void)
{
    static guest_state_t g;
    sparc64_cpu_t cpu;
    sparc64_dec_t d;
    sparc64_step_result_t res;
    const uint64_t base = UINT64_C(0x100000); /* 8 KiB aligned. */
    const uint64_t va = base + UINT64_C(0x1080); /* Upper 4K half. */
    const uint64_t initial = UINT64_C(0x1122334455667788);
    const uint64_t swap = UINT64_C(0xaabbccddeeff0011);
    uint8_t pattern[8];
    uint8_t back[8];
    uint8_t lower[8];
    int ok;
    (void)memset(&g, 0, sizeof(g));
    (void)memset(&cpu, 0, sizeof(cpu));
    (void)memset(&d, 0, sizeof(d));
    (void)memset(&res, 0, sizeof(res));

    sparc64_space_init(&g.space, 64U);
    ok = sparc64_space_map(&g.space, base, UINT64_C(8192),
        (unsigned)(SPARC64_MEM_READ | SPARC64_MEM_WRITE), 0);
    check("map-8k: ok", "map-8k: FAIL", ok);
    if (!ok) {
        (void)printf("THR-RESOLVE-GRANULE-FAIL n=%d\n", fails);
        return 1;
    }
    /* Lower 4 KiB half: solid 0xAA (must stay untouched). Upper half:
     * BE(initial) at va, rest zero. */
    (void)memset(pattern, 0xaa, sizeof(pattern));
    {
        uint64_t off;
        for (off = UINT64_C(0); off < UINT64_C(4096); off += 8U) {
            if (!sparc64_space_write_initial(&g.space, base + off, pattern,
                    sizeof(pattern))) {
                check("fill-lower: ok", "fill-lower: FAIL", 0);
                return 1;
            }
        }
    }
    put_be64(pattern, initial);
    check("write-upper: ok", "write-upper: FAIL",
        sparc64_space_write_initial(&g.space, va, pattern, sizeof(pattern)));

    /* CASXA [rs1], rs2, rd with rs1 = va (upper half), rs2 = expect,
     * rd = swap. */
    cpu.r[2] = initial; /* %g2 = expect. */
    cpu.r[4] = swap; /* %g4 = swap. */
    cpu.r[8] = va; /* %o0 = address. */
    d.cls = (uint32_t)SPARC64_ICLS_ATOMIC;
    d.op3 = (uint32_t)SPARC64_OP3_CASXA;
    d.rd = 4U;
    d.rs1 = 8U;
    d.rs2 = 2U;
    d.asi = (uint32_t)SPARC64_ASI_P;
    d.is_imm = 0U;
    ok = sparc64_threads_try_host_atomic(&cpu, &g, base,
        &d, &res);
    check("host-atomic-taken: ok", "host-atomic-taken: FAIL", ok);
    check("old-is-upper: ok", "old-is-upper: FAIL",
        ok && res.kind == SPARC64_STEP_CONTINUE && cpu.r[4] == initial);
    if (!ok || res.kind != SPARC64_STEP_CONTINUE || cpu.r[4] != initial) {
        (void)printf("THR-RESOLVE-GRANULE-FAIL n=%d\n", fails);
        sparc64_space_destroy(&g.space);
        return 1;
    }
    /* Swap must have landed in the upper page ... */
    ok = sparc64_space_read(&g.space, va, back, sizeof(back),
        (unsigned)SPARC64_MEM_READ);
    check("swap-landed-upper: ok", "swap-landed-upper: FAIL",
        ok && get_be64(back) == swap);
    /* ... and the lower page must be untouched. */
    ok = sparc64_space_read(&g.space, base + UINT64_C(0x0080), lower,
        sizeof(lower), (unsigned)SPARC64_MEM_READ);
    check("lower-untouched: ok", "lower-untouched: FAIL",
        ok && get_be64(lower) == UINT64_C(0xaaaaaaaaaaaaaaaa));

    /* S64-R2-1: signal frame 32-bit Y register round-trip at 0x1d8 must
     * not be overwritten by PT_REGS_MAGIC at 0x1dc. */
    {
        sparc64_syscall_mem_t smem;
        sparc64_ctx_t sctx;
        smem.read = test_sys_read;
        smem.write = test_sys_write;
        smem.prepare_write = test_sys_prep;
        smem.context = &g;
        sparc64_ctx_init(&sctx, base + UINT64_C(0x100));
        sctx.r[SPARC64_SP] = (base + UINT64_C(0x1800)) - SPARC64_STACK_BIAS;
        sctx.y = UINT64_C(0xcafebabe);
        sparc64_sync_sig_reset_all();
        check("sig-install: ok", "sig-install: FAIL",
            sparc64_sync_sig_install_full(SPARC64_SIGUSR1,
                base + UINT64_C(0x200), SPARC64_SA_SIGINFO,
                base + UINT64_C(0x300), UINT64_C(0)) == 0);
        check("sig-deliver: ok", "sig-deliver: FAIL",
            sparc64_sync_sig_deliver(&sctx, &smem, (int)SPARC64_SIGUSR1,
                SPARC64_SI_USER, UINT64_C(0)) == 0);
        sctx.y = UINT64_C(0x12345678);
        check("sig-return: ok", "sig-return: FAIL",
            sparc64_sync_sig_return(&sctx, &smem) == 0L);
        check("sig-y-preserved: ok", "sig-y-preserved: FAIL",
            sctx.y == UINT64_C(0xcafebabe) &&
            sctx.pc == base + UINT64_C(0x100) &&
            sctx.npc == base + UINT64_C(0x104));
    }

    /* S64-R2-2: taken branch with a delay-slot `ta 0x6d` syscall must
     * publish (delay_pc, target) into (cpu.pc, cpu.npc) before executing
     * the delay slot so syscall return advances pc to target. */
    {
        sparc64_mem_ops_t mops;
        sparc64_ctx_t bctx;
        sparc64_step_result_t bres;
        const uint64_t code_va = base + UINT64_C(0x2000);
        const uint8_t code_words[8] = {
            0x10, 0x80, 0x00, 0x04, /* ba +0x10 (target = code_va + 0x10) */
            0x91, 0xd0, 0x20, 0x6d  /* ta 0x6d (delay-slot syscall) */
        };
        mops.read = test_mem_read;
        mops.write = test_mem_write;
        mops.atomic = NULL;
        check("map-code-page: ok", "map-code-page: FAIL",
            sparc64_space_map(&g.space, code_va, UINT64_C(8192),
                (unsigned)(SPARC64_MEM_READ | SPARC64_MEM_EXEC), 0) &&
            sparc64_space_write_initial(&g.space, code_va, code_words,
                sizeof(code_words)));
        sparc64_ctx_init(&bctx, code_va);
        bctx.r[1] = UINT64_C(20); /* NR_getpid */
        bres = sparc64_step(&bctx, &mops, &g);
        check("cti-delay-syscall-npc: ok", "cti-delay-syscall-npc: FAIL",
            bres.kind == SPARC64_STEP_SYSCALL &&
            bctx.pc == code_va + UINT64_C(4) &&
            bctx.npc == code_va + UINT64_C(0x10));
    }

    sparc64_space_destroy(&g.space);
    check("no-test-stub-reached: ok", "no-test-stub-reached: FAIL",
        stub_reached == 0);
    if (fails == 0) {
        (void)printf("THR-RESOLVE-GRANULE-PASS\n");
        return 0;
    }
    (void)printf("THR-RESOLVE-GRANULE-FAIL n=%d\n", fails);
    return 1;
}
