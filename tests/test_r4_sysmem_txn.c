/*
 * tests/test_r4_sysmem_txn.c — Round-4 sysmem transaction tests.
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * S64-R4-3/4/5/6 via the sparc64_sysmem_* shells: retained-fd growth
 * after guest close (R4-4), mremap growth rollback (R4-3), mprotect
 * splits (R4-6), munmap drops (R4-5), dup exhaustion (R4-4), and
 * table-grow failure without eviction (R4-5; hooks are R4-10).
 * Deterministic; exit 0 with R4-SYSMEM-TXN-PASS iff all checks pass.
 */

#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "core/cpu.h"
#include "dbt/dbt.h"
#include "dbt/mem_sites.h"
#include "os/guest_proc.h"
#include "os/guest_run_priv.h"
#include "os/mem_space.h"
#include "os/sysmem_file.h"
#include "vm/vm64.h"

extern long sparc64_sysmem_mmap(void *ctx, uint64_t addr, uint64_t len,
    unsigned prot, unsigned flags, int fd, uint64_t offset);
extern long sparc64_sysmem_munmap(void *ctx, uint64_t addr, uint64_t len);
extern long sparc64_sysmem_mprotect(void *ctx, uint64_t addr, uint64_t len,
    unsigned prot);
extern long sparc64_sysmem_mremap(void *ctx, uint64_t old_addr,
    uint64_t old_size, uint64_t new_size, unsigned flags,
    uint64_t new_addr);

/* Same stubs as test_r3_registry.c plus the maps-label hook the
 * file-backed mmap shell calls and this link does not provide. */
int64_t rt_host_pread64(int fd, void *buf, size_t count, int64_t offset)
{
    ssize_t got = pread(fd, buf, count, (off_t)offset);
    if (buf == NULL) {
        return -22L;
    }
    return (got < 0) ? (int64_t)-errno : (int64_t)got;
}

int64_t rt_host_msync(void *a, size_t len, int flags)
{
    (void)a;
    (void)len;
    (void)flags;
    return 0L;
}

int rt_host_preempt_worker(uint64_t tid)
{
    (void)tid;
    return 0;
}

uint64_t rt_host_register_self(void)
{
    return UINT64_C(1);
}

void rt_host_unregister_self(void)
{
}

static unsigned tlb_calls = 0u;
static unsigned dbt_calls = 0u;

void sparc64_tlb_invalidate_gva(uint64_t gva, uint64_t len)
{
    (void)gva;
    (void)len;
    tlb_calls++;
}

void sparc64_dbt_invalidate(sparc64_dbt_t *dbt, uint64_t va, uint64_t len)
{
    (void)dbt;
    (void)va;
    (void)len;
    dbt_calls++;
}

void sparc64_guest_proc_note_map(void *g, uint64_t lo, uint64_t hi,
    const char *path)
{
    (void)g;
    (void)lo;
    (void)hi;
    (void)path;
}

static int fails = 0;

static void check(const char *name, int passed)
{
    (void)printf(passed ? "ok %s\n" : "FAIL %s\n", name);
    fails += !passed;
}

static const sysmem_file_range_t *find_entry(uint64_t base)
{
    size_t i;
    for (i = 0u; i < sysmem_file_cap; i++) {
        if (sysmem_files[i].live && sysmem_files[i].base == base) {
            return &sysmem_files[i];
        }
    }
    return NULL;
}

#define A_BASE UINT64_C(0x200000)
#define B_BASE UINT64_C(0x300000)
#define D_BASE UINT64_C(0x500000)
#define N_BASE UINT64_C(0x1000000)
#define SPAN24 UINT64_C(24576)

static unsigned char pat[24576];
static unsigned char back[8192];

int main(void)
{
    static guest_state_t g;
    static sparc64_dbt_t dummy_dbt;
    char tmpl[] = "/tmp/sparc64rt-r4-XXXXXX";
    int fd = mkstemp(tmpl);
    size_t i;
    long r;
    unsigned before;
    const sysmem_file_range_t *ent;
    (void)memset(&g, 0, sizeof(g));
    for (i = 0u; i < sizeof(pat); i++) {
        pat[i] = (unsigned char)((i * 31u + 7u) & 255u);
    }
    if (fd < 0 || write(fd, pat, sizeof(pat)) != (ssize_t)sizeof(pat)) {
        (void)printf("FAIL temp-file\n");
        return 1;
    }
    sparc64_space_init(&g.space, 64U);
    g.space_live = 1;
    g.dbt = &dummy_dbt;

    /* R4-4: guest close, then in-place growth serves retained bytes. */
    r = sparc64_sysmem_mmap(&g, A_BASE, UINT64_C(8192), 3U, 0x12U, fd,
        UINT64_C(0));
    check("mmap-file", r == (long)A_BASE);
    check("mmap-bytes", sparc64_space_read(&g.space, A_BASE, back,
        sizeof(back), (unsigned)SPARC64_MEM_READ) &&
        memcmp(back, pat, sizeof(back)) == 0);
    (void)close(fd);
    fd = -1;
    r = sparc64_sysmem_mremap(&g, A_BASE, UINT64_C(8192),
        UINT64_C(16384), 1U, UINT64_C(0));
    check("grow-retained", r == (long)A_BASE);
    check("grow-tail", sparc64_space_read(&g.space, A_BASE + UINT64_C(8192),
        back, sizeof(back), (unsigned)SPARC64_MEM_READ) &&
        memcmp(back, pat + 8192, sizeof(back)) == 0);
    check("one-entry", sysmem_file_live_count() == 1u);

    /* R4-3: injected tail failure keeps span, bytes, and entry. */
    sysmem_file_test_fail_next_fill(1);
    before = sysmem_file_live_count();
    r = sparc64_sysmem_mremap(&g, A_BASE, UINT64_C(16384), SPAN24, 1U,
        UINT64_C(0));
    check("grow-fail-enomem", r == (long)-ENOMEM);
    check("grow-fail-bytes", sparc64_space_read(&g.space, A_BASE, back,
        sizeof(back), (unsigned)SPARC64_MEM_READ) &&
        memcmp(back, pat, sizeof(back)) == 0);
    check("grow-fail-hole", !sparc64_space_read(&g.space,
        A_BASE + UINT64_C(16384), back, (size_t)1024,
        (unsigned)SPARC64_MEM_READ));
    ent = find_entry(A_BASE);
    check("grow-fail-entry", ent != NULL && ent->len == UINT64_C(16384) &&
        sysmem_file_live_count() == before);
    r = sparc64_sysmem_mremap(&g, A_BASE, UINT64_C(16384), SPAN24, 1U,
        UINT64_C(0));
    check("grow-retry", r == (long)A_BASE);
    check("grow-retry-tail", sparc64_space_read(&g.space,
        A_BASE + UINT64_C(16384), back, sizeof(back),
        (unsigned)SPARC64_MEM_READ) &&
        memcmp(back, pat + 16384, sizeof(back)) == 0);

    /* R4-6: mprotect splits coverage; holes fail without mutation. */
    fd = open(tmpl, O_RDONLY);
    check("reopen", fd >= 0);
    r = sparc64_sysmem_mmap(&g, B_BASE, SPAN24, 3U, 0x12U, fd,
        UINT64_C(0));
    check("mmap-b", r == (long)B_BASE);
    before = sysmem_file_live_count();
    check("protect-mid", sparc64_sysmem_mprotect(&g, B_BASE +
        UINT64_C(8192), UINT64_C(8192), 1U) == 0L);
    check("protect-split", find_entry(B_BASE) != NULL &&
        find_entry(B_BASE)->prot == 3u &&
        find_entry(B_BASE + UINT64_C(8192)) != NULL &&
        find_entry(B_BASE + UINT64_C(8192))->prot == 1u &&
        find_entry(B_BASE + UINT64_C(16384)) != NULL &&
        sysmem_file_live_count() == before + 2u);
    check("protect-hole", sparc64_sysmem_mprotect(&g, UINT64_C(0x900000),
        UINT64_C(8192), 1U) == (long)-ENOMEM &&
        sysmem_file_live_count() == before + 2u);

    /* R4-5: munmap drops the middle; neighbors keep bytes. */
    check("unmap-mid", sparc64_sysmem_munmap(&g, B_BASE + UINT64_C(8192),
        UINT64_C(8192)) == 0L);
    check("unmap-head", sparc64_space_read(&g.space, B_BASE, back,
        sizeof(back), (unsigned)SPARC64_MEM_READ) &&
        memcmp(back, pat, sizeof(back)) == 0);
    check("unmap-tail", sparc64_space_read(&g.space,
        B_BASE + UINT64_C(16384), back, sizeof(back),
        (unsigned)SPARC64_MEM_READ) &&
        memcmp(back, pat + 16384, sizeof(back)) == 0);
    check("unmap-gone", !sparc64_space_read(&g.space,
        B_BASE + UINT64_C(8192), back, (size_t)64,
        (unsigned)SPARC64_MEM_READ));

    /* R4-4: dup exhaustion fails clean; the retry then succeeds. */
    sysmem_file_test_fail_next_dup(1);
    before = sysmem_file_live_count();
    check("dup-fail", sparc64_sysmem_mmap(&g, D_BASE, UINT64_C(8192),
        3U, 0x12U, fd, UINT64_C(0)) == (long)-ENOMEM);
    check("dup-clean", !sparc64_space_read(&g.space, D_BASE, back,
        (size_t)64, (unsigned)SPARC64_MEM_READ) &&
        sysmem_file_live_count() == before);
    check("dup-retry", sparc64_sysmem_mmap(&g, D_BASE, UINT64_C(8192),
        3U, 0x12U, fd, UINT64_C(0)) == (long)D_BASE);

    /* R4-5/R4-10: full table plus grow failure evicts nothing. */
    for (i = 0u; sysmem_file_live_count() < sysmem_file_cap; i++) {
        if (sysmem_file_note_map(&g, -1, UINT64_C(1000) + i,
                UINT64_C(2000) + i, UINT64_C(0), N_BASE + i * UINT64_C(8192),
                UINT64_C(8192), 3U, 1, NULL, 0u) != 0) {
            break;
        }
    }
    before = sysmem_file_live_count();
    check("table-full", before == sysmem_file_cap);
    sysmem_file_test_fail_next_grow(1);
    check("reserve-fails", sysmem_file_reserve(1u) != 0);
    check("reserve-keeps", sysmem_file_live_count() == before &&
        find_entry(N_BASE) != NULL && find_entry(A_BASE) != NULL);
    check("reserve-retry", sysmem_file_reserve(1u) == 0);
    check("invalidated", tlb_calls > 0u && dbt_calls > 0u);

    for (i = 0u; i < 64u; i++) {
        sysmem_file_drop_map(&g, N_BASE + i * UINT64_C(8192),
            UINT64_C(8192));
    }
    (void)sparc64_sysmem_munmap(&g, A_BASE, SPAN24);
    (void)sparc64_sysmem_munmap(&g, B_BASE, UINT64_C(8192));
    (void)sparc64_sysmem_munmap(&g, B_BASE + UINT64_C(16384),
        UINT64_C(8192));
    (void)sparc64_sysmem_munmap(&g, D_BASE, UINT64_C(8192));
    if (fd >= 0) {
        (void)close(fd);
    }
    (void)unlink(tmpl);
    sparc64_space_destroy(&g.space);
    if (fails != 0) {
        (void)printf("R4-SYSMEM-TXN-FAIL n=%d\n", fails);
        return 1;
    }
    (void)printf("R4-SYSMEM-TXN-PASS\n");
    return 0;
}
