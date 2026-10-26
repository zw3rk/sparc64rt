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
#include "interp/interp.h"
#include "os/guest_run_priv.h"
#include "os/mem_space.h"
#include "os/threads.h"

/* ---- Test-only link stubs ---------------------------------------------
 * try_host_atomic() lives in src/os/threads.c alongside the clone and
 * futex paths, which reference four symbols this focused test never
 * executes (no threads are spawned, no futex waits run). The stubs below
 * exist only to close the link; reaching any of them fails the test. */
static int stub_reached = 0;

const sparc64_mem_ops_t guest_mem_ops;

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

void sparc64_win_invalidate_all(void)
{
    stub_reached = 1;
}

bool sparc64_win_flush_all(sparc64_cpu_t *cpu, const sparc64_mem_ops_t *mem,
    void *mc, sparc64_step_result_t *res, uint64_t pc)
{
    (void)cpu;
    (void)mem;
    (void)mc;
    (void)res;
    (void)pc;
    stub_reached = 1;
    return 0;
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
