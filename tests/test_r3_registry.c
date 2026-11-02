/*
 * tests/test_r3_registry.c — Round-3 file-registry regression test.
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Covers S64-R3-2 (file-backed mremap growth serves file bytes, not
 * zeros, with beyond-EOF BUS classification) and S64-R3-3 (the
 * file-range registry never evicts a live entry: 70 concurrent
 * mappings stay tracked past the old 64-slot bound). Also pins the
 * S64-R3-1 truncate leg (resize bumps the shared code generation and
 * invalidates TLB + DBT coverage). Deterministic stdout; exit 0 with
 * R3-REGISTRY-PASS iff every check passed.
 *
 * Build (worktree root):
 *   cc -std=c11 -Werror -Werror=vla -pedantic -Wall -Wextra -Isrc \
 *     tests/test_r3_registry.c src/os/guest_run_sysmem_file.c \
 *     src/os/sysmem_file_fill.c src/os/mem_space.c \
 *     src/os/mem_space_write.c src/vm/vm64.c src/vm/vm_file.c \
 *     -o _build/test_r3_registry
 */

#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "core/cpu.h"
#include "dbt/dbt.h"
#include "dbt/mem_sites.h"
#include "os/guest_run_priv.h"
#include "os/mem_space.h"
#include "os/sysmem_file.h"
#include "vm/vm64.h"

/* ---- Test-only link stubs ---------------------------------------------
 * The linked TUs reference host-backend and translator symbols this
 * focused test never executes through (no threads spawn, no real DBT
 * runs, no family table). vm_file.c reads through rt_host_pread64;
 * vm64.c preempts/registers through rt_host_*; the registry TUs drop
 * TLB/DBT coverage through the two invalidate hooks, whose call counts
 * the test asserts (proving the legs fire). */

/* NOLINTNEXTLINE: test stub over a native call. */
int64_t rt_host_pread64(int fd, void *buf, size_t count, int64_t offset)
{
    ssize_t got;
    if (buf == NULL) {
        return -22L;
    }
    got = pread(fd, buf, count, (off_t)offset);
    if (got < 0) {
        return (int64_t)-errno;
    }
    return (int64_t)got;
}

/* NOLINTNEXTLINE: test stub, msync is a no-op here. */
int64_t rt_host_msync(void *host_addr, size_t len, int linux_flags)
{
    (void)host_addr;
    (void)len;
    (void)linux_flags;
    return 0L;
}

int rt_host_preempt_worker(uint64_t host_tid)
{
    (void)host_tid;
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

static int fails = 0;

static void check(const char *name, int passed)
{
    if (passed) {
        (void)printf("ok %s\n", name);
    } else {
        (void)printf("FAIL %s\n", name);
        ++fails;
    }
}

/* Find a live registry entry by its guest base (white-box: the entry
 * layout is project source in src/os/sysmem_file.h). */
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

#define R3_BASE UINT64_C(0x200000)
#define R3_FILE_BYTES UINT64_C(9216)

static unsigned char file_pat[16384];

int main(void)
{
    static guest_state_t g;
    static sparc64_dbt_t dummy_dbt;
    char tmpl[] = "/tmp/sparc64rt-r3-XXXXXX";
    int fd = -1;
    size_t i;
    unsigned before;
    uint64_t epoch0;
    const sysmem_file_range_t *ent;
    unsigned char back[8192];
    unsigned t0;
    unsigned d0;
    (void)memset(&g, 0, sizeof(g));
    (void)memset(file_pat, 0, sizeof(file_pat));
    for (i = 0u; i < sizeof(file_pat); i++) {
        file_pat[i] = (unsigned char)((i * 31u + 7u) & 255u);
    }
    fd = mkstemp(tmpl);
    if (fd < 0) {
        (void)printf("FAIL temp-file\n");
        return 1;
    }
    if (write(fd, file_pat, sizeof(file_pat)) !=
        (ssize_t)sizeof(file_pat) ||
        ftruncate(fd, (off_t)R3_FILE_BYTES) != 0) {
        (void)printf("FAIL temp-fill\n");
        (void)close(fd);
        (void)unlink(tmpl);
        return 1;
    }
    sparc64_space_init(&g.space, 64U);
    g.space_live = 1;
    /* Stand-in DBT instance: the stub never dereferences it, and a
     * non-NULL value arms the invalidate legs under test. */
    g.dbt = &dummy_dbt;

    /* ---- S64-R3-2: mremap growth serves file bytes --------------------
     * Map 8 KiB of the 9216-byte file, then grow the span to 24 KiB
     * the way the mremap shell does (space remap, coverage update,
     * growth fill before commit). */
    check("map-8k", sparc64_space_map(&g.space, R3_BASE, UINT64_C(8192),
        (unsigned)(SPARC64_MEM_READ | SPARC64_MEM_WRITE), 0));
    /* Initial mmap fill of the head, exactly like the mmap shell. */
    check("fill-head",
        sysmem_file_fill(&g, fd, UINT64_C(0), R3_BASE, UINT64_C(8192),
            R3_FILE_BYTES, 1, NULL, 0u, NULL) == 0);
    check("remap-8k-24k", sparc64_space_remap(&g.space, R3_BASE,
        UINT64_C(8192), R3_BASE, UINT64_C(24576),
        (unsigned)(SPARC64_MEM_READ | SPARC64_MEM_WRITE)));
    check("note-8k",
        sysmem_file_note_map(&g, fd, UINT64_C(7), UINT64_C(9),
            UINT64_C(0), R3_BASE, UINT64_C(8192), 7U, 1, NULL, 0u) == 0);
    sysmem_file_remap_update(&g, R3_BASE, UINT64_C(8192), R3_BASE,
        UINT64_C(24576));
    check("fill-growth",
        sysmem_file_fill_growth(&g, R3_BASE, UINT64_C(8192),
            UINT64_C(24576)) == 0);
    /* File head + straddling tail byte must match the file. */
    check("head-bytes",
        sparc64_space_read(&g.space, R3_BASE, back, UINT64_C(8192),
            (unsigned)SPARC64_MEM_READ) &&
        memcmp(back, file_pat, 8192) == 0);
    check("tail-byte",
        sparc64_space_read(&g.space, R3_BASE + UINT64_C(8192), back,
            (size_t)1024, (unsigned)SPARC64_MEM_READ) &&
        memcmp(back, file_pat + 8192, 1024) == 0);
    /* Partial page past EOF stays mapped and zero. */
    check("eof-partial-zero",
        sparc64_space_read(&g.space, R3_BASE + UINT64_C(9216), back,
            (size_t)1024, (unsigned)SPARC64_MEM_READ) != 0);
    {
        int all_zero = 1;
        if (sparc64_space_read(&g.space, R3_BASE + UINT64_C(9216),
                back, (size_t)1024,
                (unsigned)SPARC64_MEM_READ)) {
            size_t k;
            for (k = 0u; k < 1024u; k++) {
                if (back[k] != 0u) {
                    all_zero = 0;
                    break;
                }
            }
        } else {
            all_zero = 0;
        }
        check("eof-partial-zero-bytes", all_zero);
    }
    /* Full 8 KiB page beyond EOF faults BUS, not stale zeros. */
    {
        int bus = 0;
        g.space.fault_reason = SPARC64_FAULT_NONE;
        if (!sparc64_space_read(&g.space, R3_BASE + UINT64_C(16384),
                back, (size_t)512, (unsigned)SPARC64_MEM_READ) &&
            g.space.fault_reason == SPARC64_FAULT_BUS) {
            bus = 1;
        }
        check("beyond-eof-bus", bus);
    }
    /* Private tail chunk materialized from the file promotes DIRTY. */
    ent = find_entry(R3_BASE);
    check("tail-chunk-dirty", ent != NULL && ent->nchunk >= 2u &&
        ent->cstate[1] == (uint8_t)VM64_PAGE_COW_DIRTY);

    /* ---- S64-R3-1: truncate strips bump epoch + invalidate --------
     * Shrinking the file to 4 KiB strips the mapping's second page. */
    epoch0 = vm64_code_epoch_get();
    t0 = tlb_calls;
    d0 = dbt_calls;
    if (ftruncate(fd, (off_t)4096) != 0) {
        check("truncate-file", 0);
    } else {
        sysmem_file_resize(&g, UINT64_C(7), UINT64_C(9),
            R3_FILE_BYTES, UINT64_C(4096));
        check("resize-bumps-epoch", vm64_code_epoch_get() != epoch0);
        check("resize-tlb", tlb_calls > t0);
        check("resize-dbt", dbt_calls > d0);
        {
            int bus = 0;
            g.space.fault_reason = SPARC64_FAULT_NONE;
            if (!sparc64_space_read(&g.space, R3_BASE + UINT64_C(8192),
                    back, (size_t)512,
                    (unsigned)SPARC64_MEM_READ) &&
                g.space.fault_reason == SPARC64_FAULT_BUS) {
                bus = 1;
            }
            check("truncate-strip-bus", bus);
        }
    }

    /* ---- S64-R3-3: 70 live mappings, none evicted ------------------ */
    before = sysmem_file_live_count();
    for (i = 0u; i < 70u; i++) {
        uint64_t base = UINT64_C(0x1000000) + i * UINT64_C(8192);
        int rc = sysmem_file_note_map(&g, -1, UINT64_C(100) + i,
            UINT64_C(200) + i, UINT64_C(0), base, UINT64_C(8192), 7U,
            1, NULL, 0u);
        if (rc != 0) {
            break;
        }
    }
    check("seventy-notes", i == 70u);
    check("seventy-live", sysmem_file_live_count() == before + 70u);
    check("first-survives", find_entry(R3_BASE) != NULL);
    check("reserve-extra", sysmem_file_reserve(8u) == 0);
    for (i = 0u; i < 70u; i++) {
        uint64_t base = UINT64_C(0x1000000) + i * UINT64_C(8192);
        sysmem_file_drop_map(&g, base, UINT64_C(8192));
    }
    check("drops-reclaim", sysmem_file_live_count() == before);

    /* Reclaim the growth entry (and its retained fd) before exit. */
    sysmem_file_drop_map(&g, R3_BASE, UINT64_C(24576));
    (void)close(fd);
    (void)unlink(tmpl);
    sparc64_space_destroy(&g.space);
    if (fails != 0) {
        (void)printf("R3-REGISTRY-FAIL n=%d\n", fails);
        return 1;
    }
    (void)printf("R3-REGISTRY-PASS\n");
    return 0;
}
