/*
 * tests/test_rc_u2_8k_cow_eof.c — RC-U2 gate: 8 KiB COW/EOF data path.
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Lane A3 (RC-U12-sparc64 P2-5/P2-6): pins the Provider-A file-mapping
 * data path that was previously unreachable (no callers of
 * vm64_cow_promote_8k / vm64_eof_upper_half / vm_file_populate_segment):
 * whole-8KiB COW promotion, [st_size, 8 KiB) EOF tail zeroing including
 * upper-half materialization, beyond-EOF SIGBUS, failed
 * ftruncate/mprotect state preservation, 8 KiB mremap alignment, and the
 * dbt_mem_site_t[] AOT round-trip. Host-runnable (no guest image).
 *
 * Method: direct unit calls into src/vm/vm64.c, src/vm/vm_file.c, the
 * sparc64_space substrate, and src/dbt/aot/sites.c. Deterministic
 * stdout; exit 0 with RC-U2-8K-COW-EOF-PASS iff every check passed.
 *
 * Build (worktree root):
 *   cc -std=c11 -Wall -Wextra -Werror=vla -pedantic -Isrc \
 *     tests/test_rc_u2_8k_cow_eof.c src/vm/vm64.c src/vm/vm_file.c \
 *     src/os/mem_space.c src/os/mem_space_write.c src/dbt/aot/sites.c \
 *     -o _build/test_rc_u2_8k_cow_eof
 */

#define _POSIX_C_SOURCE 200809L
#if defined(__APPLE__) && !defined(_DARWIN_C_SOURCE)
#define _DARWIN_C_SOURCE 1
#endif

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "dbt/aot/sites.h"
#include "dbt/aot/format.h"
#include "os/mem_space.h"

/* ---- Cross-TU declarations --------------------------------------------
 * vm64 page states and quiescence come from src/vm/vm64.h (real
 * declarations, not int-punned externs); the file-table pointer stays
 * opaque and the op code is the small vm_file_op_t enum. */
#include "vm/vm64.h"
extern int vm64_check_mremap_args(uint64_t old_addr, uint64_t old_size,
    uint64_t new_size, unsigned flags, uint64_t new_addr);
extern long vm_file_populate_segment(int host_fd, uint64_t file_offset,
    uint64_t file_size, void *host_addr, size_t seg_len,
    vm64_page_state_t *lower_state, vm64_page_state_t *upper_state,
    uint64_t *bus_base_out, uint64_t *bus_len_out);
extern void vm_file_table_init(void *t);
extern int vm_file_intern(void *t, uint64_t st_dev, uint64_t st_ino,
    uint64_t st_ctime_nsec, int host_fd, uint64_t file_size);
extern bool vm_file_refresh_on_miss(void *t, int index,
    uint64_t fstat_size);
extern long vm_file_commit_resize(void *t, int index, uint64_t new_size,
    long host_rc, int op, void *discard, void *discard_ctx,
    uint64_t *discard_base_out, uint64_t *discard_len_out);

/* Backend legs used by the linked TUs, stubbed over native calls. */
int64_t rt_host_pread64(int fd, void *buf, size_t count, int64_t offset)
{
    ssize_t got;
    if (buf == NULL) {
        return -22L;
    }
    got = pread(fd, buf, count, (off_t)offset);
    if (got < 0) {
        return (long)-errno;
    }
    return (int64_t)got;
}

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

/* Opaque family-table storage: ~20 KiB live, 64 KiB reserved, 8-byte
 * aligned for the atomic state words. Never dereferenced here. */
static _Alignas(8) unsigned char table_store[65536];

#define SEG_LEN ((size_t)16384)
#define FILE_LEN ((uint64_t)5000)

static unsigned char pattern[SEG_LEN];
static unsigned char stage[SEG_LEN];

static void fill_pattern(void)
{
    size_t i;
    for (i = 0; i < SEG_LEN; ++i) {
        pattern[i] = (unsigned char)((i * 31u + 7u) & 0xffu);
    }
}

static int make_temp(char *tmpl, size_t tmpl_cap)
{
    static const char src[] = "/tmp/rcu2_8k_cow_eof_XXXXXX";
    int fd;
    if (tmpl_cap < sizeof(src)) {
        return -1;
    }
    memcpy(tmpl, src, sizeof(src));
    fd = mkstemp(tmpl);
    return fd;
}

static int write_all(int fd, const unsigned char *bytes, size_t len)
{
    size_t done = 0;
    while (done < len) {
        ssize_t got = write(fd, bytes + done, len - done);
        if (got <= 0) {
            return -1;
        }
        done += (size_t)got;
    }
    return 0;
}

static int all_zero(const unsigned char *bytes, size_t len)
{
    size_t i;
    for (i = 0; i < len; ++i) {
        if (bytes[i] != 0u) {
            return 0;
        }
    }
    return 1;
}

int main(void)
{
    fill_pattern();
    /* A. Whole-8KiB COW promotion. */
    {
        vm64_page_state_t lo = VM64_PAGE_COW_CLEAN;
        vm64_page_state_t hi = VM64_PAGE_COW_CLEAN;
        check("cow-clean-clean-promotes", vm64_cow_promote_8k(&lo, &hi) &&
            lo == VM64_PAGE_COW_DIRTY && hi == VM64_PAGE_COW_DIRTY);
    }
    {
        vm64_page_state_t lo = VM64_PAGE_COW_DIRTY;
        vm64_page_state_t hi = VM64_PAGE_COW_DIRTY;
        check("cow-dirty-dirty-noop", !vm64_cow_promote_8k(&lo, &hi) &&
            lo == VM64_PAGE_COW_DIRTY && hi == VM64_PAGE_COW_DIRTY);
    }
    {
        vm64_page_state_t lo = VM64_PAGE_COW_CLEAN;
        vm64_page_state_t hi = VM64_PAGE_COW_DIRTY;
        check("cow-mixed-promotes", vm64_cow_promote_8k(&lo, &hi) &&
            lo == VM64_PAGE_COW_DIRTY && hi == VM64_PAGE_COW_DIRTY);
    }
    check("cow-null-refused", !vm64_cow_promote_8k(NULL, NULL));
    check("cow-writable-both-dirty",
        vm64_cow_writable(VM64_PAGE_COW_DIRTY, VM64_PAGE_COW_DIRTY));
    check("cow-not-writable-clean",
        !vm64_cow_writable(VM64_PAGE_COW_CLEAN, VM64_PAGE_COW_DIRTY) &&
        !vm64_cow_writable(VM64_PAGE_COW_CLEAN, VM64_PAGE_COW_CLEAN) &&
        !vm64_cow_writable(VM64_PAGE_UNMAPPED, VM64_PAGE_COW_DIRTY));

    /* B. EOF upper-half span. */
    {
        uint64_t zs = 0;
        uint64_t zl = 0;
        check("eof-upper-half-span", vm64_eof_upper_half(UINT64_C(100),
            UINT64_C(16384), &zs, &zl) && zs == UINT64_C(4096) &&
            zl == UINT64_C(4096));
    }
    check("eof-upper-half-covered-no-span",
        !vm64_eof_upper_half(FILE_LEN, UINT64_C(16384), NULL, NULL));
    {
        uint64_t zs = 0;
        uint64_t zl = 0;
        check("eof-exact-4k-materializes", vm64_eof_upper_half(
            UINT64_C(4096), UINT64_C(16384), &zs, &zl) &&
            zs == UINT64_C(4096) && zl == UINT64_C(4096));
    }
    check("eof-exact-page-no-span",
        !vm64_eof_upper_half(UINT64_C(8192), UINT64_C(16384), NULL, NULL));
    check("eof-empty-no-span",
        !vm64_eof_upper_half(UINT64_C(0), UINT64_C(16384), NULL, NULL));
    check("eof-map-end-at-size-no-span",
        !vm64_eof_upper_half(FILE_LEN, FILE_LEN, NULL, NULL));
    check("eof-map-end-before-upper-no-span",
        !vm64_eof_upper_half(FILE_LEN, UINT64_C(4096), NULL, NULL));

    /* C. Segment population through a real temp file. */
    {
        char tmpl[64];
        int fd = make_temp(tmpl, sizeof(tmpl));
        check("temp-file-created", fd >= 0);
        if (fd >= 0) {
            memset(stage, 0xa5, sizeof(stage));
            check("temp-file-written",
                write_all(fd, pattern, (size_t)FILE_LEN) == 0);
            {
                vm64_page_state_t lo = VM64_PAGE_COW_CLEAN;
                vm64_page_state_t hi = VM64_PAGE_COW_CLEAN;
                uint64_t bb = 0;
                uint64_t bl = 0;
                long rc = vm_file_populate_segment(fd, UINT64_C(0),
                    FILE_LEN, stage, SEG_LEN, &lo, &hi, &bb, &bl);
                check("populate-returns-file-bytes", rc == 5000L);
                check("populate-bytes-match",
                    memcmp(stage, pattern, (size_t)FILE_LEN) == 0);
                check("populate-eof-tail-zero",
                    all_zero(stage + (size_t)FILE_LEN,
                        SEG_LEN - (size_t)FILE_LEN));
                check("populate-promotes-pair", lo == VM64_PAGE_COW_DIRTY && hi == VM64_PAGE_COW_DIRTY);
                check("populate-bus-span",
                    bb == UINT64_C(8192) && bl == UINT64_C(8192));
            }
            {
                long rc;
                memset(stage, 0xa5, sizeof(stage));
                rc = vm_file_populate_segment(fd, UINT64_C(0), FILE_LEN,
                    stage, SEG_LEN, NULL, NULL, NULL, NULL);
                check("populate-null-states-ok", rc == 5000L &&
                    memcmp(stage, pattern, (size_t)FILE_LEN) == 0 &&
                    all_zero(stage + (size_t)FILE_LEN,
                        SEG_LEN - (size_t)FILE_LEN));
            }
            check("populate-shrink-eio",
                vm_file_populate_segment(fd, UINT64_C(0),
                    UINT64_C(16384), stage, SEG_LEN, NULL, NULL, NULL,
                    NULL) == -5L);
            check("populate-bad-fd-einval",
                vm_file_populate_segment(-1, UINT64_C(0), FILE_LEN,
                    stage, SEG_LEN, NULL, NULL, NULL, NULL) == -22L);
            check("populate-null-addr-einval",
                vm_file_populate_segment(fd, UINT64_C(0), FILE_LEN, NULL,
                    SEG_LEN, NULL, NULL, NULL, NULL) == -22L);
            check("populate-zero-len-einval",
                vm_file_populate_segment(fd, UINT64_C(0), FILE_LEN,
                    stage, 0u, NULL, NULL, NULL, NULL) == -22L);
            /* Grow to exactly 8 KiB: no tail, no BUS span. */
            check("temp-file-grown",
                write_all(fd, pattern + (size_t)FILE_LEN,
                    8192u - (size_t)FILE_LEN) == 0);
            {
                vm64_page_state_t lo = VM64_PAGE_COW_CLEAN;
                vm64_page_state_t hi = VM64_PAGE_COW_CLEAN;
                uint64_t bb = 9;
                uint64_t bl = 9;
                long rc;
                memset(stage, 0xa5, sizeof(stage));
                rc = vm_file_populate_segment(fd, UINT64_C(0),
                    UINT64_C(8192), stage, 8192u, &lo, &hi, &bb, &bl);
                check("populate-exact-8k", rc == 8192L &&
                    memcmp(stage, pattern, 8192u) == 0 && lo == VM64_PAGE_COW_DIRTY &&
                    hi == VM64_PAGE_COW_DIRTY && bb == UINT64_C(0) && bl == UINT64_C(0));
            }
            /* Lower-half EOF: upper-half leg fires and the partial 8 KiB
             * page is zero tail, not SIGBUS: BUS coverage starts at the
             * next full 8 KiB page, which equals seg_end here, so no
             * BUS span is reported. */
            check("temp-file-shrunk", ftruncate(fd, 100) == 0);
            {
                vm64_page_state_t lo = VM64_PAGE_COW_CLEAN;
                vm64_page_state_t hi = VM64_PAGE_COW_CLEAN;
                uint64_t bb = 9;
                uint64_t bl = 9;
                long rc;
                memset(stage, 0xa5, sizeof(stage));
                rc = vm_file_populate_segment(fd, UINT64_C(0),
                    UINT64_C(100), stage, 8192u, &lo, &hi, &bb, &bl);
                check("populate-lower-half-eof", rc == 100L &&
                    memcmp(stage, pattern, 100u) == 0 &&
                    all_zero(stage + 100u, 8192u - 100u) && lo == VM64_PAGE_COW_DIRTY &&
                    hi == VM64_PAGE_COW_DIRTY && bb == UINT64_C(0) &&
                    bl == UINT64_C(0));
            }
            /* The 8 KiB BUS boundary itself is already pinned by the
             * populate-bus-span case above (5000-byte file in a
             * 16384-byte segment reports bb=8192, bl=8192). */
            (void)close(fd);
            (void)unlink(tmpl);
        }
    }

    /* D. Beyond-EOF SIGBUS at the space substrate level. */
    {
        sparc64_space_t space;
        uint64_t base = UINT64_C(0x1000000);
        unsigned char buf[64];
        memset(&space, 0, sizeof(space));
        sparc64_space_init(&space, 64);
        check("space-map-16k",
            sparc64_space_map(&space, base, SEG_LEN,
                SPARC64_MEM_READ | SPARC64_MEM_WRITE, false));
        check("space-write-file-bytes",
            sparc64_space_write_initial(&space, base, pattern,
                (size_t)FILE_LEN));
        check("space-tail-zero",
            sparc64_space_read(&space, base + FILE_LEN, buf, 64u,
                SPARC64_MEM_READ) && all_zero(buf, 64u));
        check("space-map-bus-tail",
            sparc64_space_map_bus(&space, base + UINT64_C(8192),
                UINT64_C(8192),
                SPARC64_MEM_READ | SPARC64_MEM_WRITE, true));
        check("space-beyond-eof-sigbus",
            !sparc64_space_read(&space, base + UINT64_C(8192), buf, 16u,
                SPARC64_MEM_READ) &&
            space.fault_reason == SPARC64_FAULT_BUS);
        check("space-file-part-readable",
            sparc64_space_read(&space, base, buf, 16u,
                SPARC64_MEM_READ) && memcmp(buf, pattern, 16u) == 0);
        sparc64_space_destroy(&space);
    }

    /* E1. Failed ftruncate preserves Provider-A state. */
    {
        int fd = open("/dev/null", O_RDONLY);
        int idx;
        long rc;
        uint64_t db = UINT64_C(0xdead);
        uint64_t dl = UINT64_C(0xdead);
        check("null-fd-open", fd >= 0);
        vm_file_table_init(table_store);
        idx = vm_file_intern(table_store, UINT64_C(1), UINT64_C(2),
            UINT64_C(3), fd, UINT64_C(16384));
        check("table-intern", idx >= 0);
        rc = vm_file_commit_resize(table_store, idx, UINT64_C(4096), -16L,
            0, NULL, NULL, &db, &dl);
        check("failed-resize-no-mutation", rc == -16L &&
            db == UINT64_C(0xdead) && dl == UINT64_C(0xdead) &&
            !vm_file_refresh_on_miss(table_store, idx, UINT64_C(16384)));
        rc = vm_file_commit_resize(table_store, idx, UINT64_C(4096), 0L,
            0, NULL, NULL, &db, &dl);
        check("resize-discard-span", rc == 0L && db == UINT64_C(8192) &&
            dl == UINT64_C(8192));
        check("resize-size-published",
            !vm_file_refresh_on_miss(table_store, idx, UINT64_C(4096)));
        check("resize-refresh-detects-external",
            vm_file_refresh_on_miss(table_store, idx, UINT64_C(16384)));
        if (fd >= 0) {
            (void)close(fd);
        }
    }

    /* E2. Failed mprotect preserves mapping state. */
    {
        sparc64_space_t space;
        uint64_t base = UINT64_C(0x2000000);
        unsigned char buf[16];
        memset(&space, 0, sizeof(space));
        sparc64_space_init(&space, 64);
        check("protect-space-map",
            sparc64_space_map(&space, base, UINT64_C(8192),
                SPARC64_MEM_READ | SPARC64_MEM_WRITE, false));
        check("protect-space-write",
            sparc64_space_write(&space, base, pattern, 16u));
        check("protect-unmapped-fails",
            !sparc64_space_protect(&space, base + UINT64_C(0x1000000),
                UINT64_C(4096), SPARC64_MEM_READ));
        check("protect-failure-preserves",
            sparc64_space_read(&space, base, buf, 16u,
                SPARC64_MEM_READ) && memcmp(buf, pattern, 16u) == 0 &&
            sparc64_space_write(&space, base, pattern, 16u));
        check("protect-mapped-succeeds",
            sparc64_space_protect(&space, base, UINT64_C(8192),
                SPARC64_MEM_READ));
        check("protect-perms-change-visible",
            sparc64_space_read(&space, base, buf, 16u,
                SPARC64_MEM_READ) &&
            !sparc64_space_write(&space, base, pattern, 16u));
        sparc64_space_destroy(&space);
    }

    /* F. mremap 8 KiB alignment. */
    check("mremap-4k-old-rejected",
        vm64_check_mremap_args(UINT64_C(0x1000), UINT64_C(8192),
            UINT64_C(8192), 0u, UINT64_C(0)) == -22);
    check("mremap-8k-old-accepted",
        vm64_check_mremap_args(UINT64_C(0x10000), UINT64_C(8192),
            UINT64_C(16384), 0u, UINT64_C(0)) == 0);
    check("mremap-zero-size-rejected",
        vm64_check_mremap_args(UINT64_C(0x10000), UINT64_C(0),
            UINT64_C(8192), 0u, UINT64_C(0)) == -22);
    check("mremap-fixed-needs-maymove",
        vm64_check_mremap_args(UINT64_C(0x10000), UINT64_C(8192),
            UINT64_C(8192), 2u, UINT64_C(0x20000)) == -22);
    check("mremap-fixed-4k-new-rejected",
        vm64_check_mremap_args(UINT64_C(0x10000), UINT64_C(8192),
            UINT64_C(8192), 3u, UINT64_C(0x1000)) == -22);
    check("mremap-fixed-8k-new-accepted",
        vm64_check_mremap_args(UINT64_C(0x10000), UINT64_C(8192),
            UINT64_C(16384), 3u, UINT64_C(0x20000)) == 0);

    /* G. dbt_mem_site_t[] AOT round-trip. */
    {
        sparc64_mem_site_t in[2];
        sparc64_mem_site_t out[2];
        uint8_t wire[48];
        size_t written = 0;
        memset(in, 0, sizeof(in));
        memset(out, 0, sizeof(out));
        in[0].seq_start_offset = 16u;
        in[0].host_insn_offset = 24u;
        in[0].cont_insn_offset = 48u;
        in[0].guest_pc_delta = 8u;
        in[0].npc_delta = 4;
        in[0].insn_word = UINT32_C(0xc25ef00d);
        in[0].sp_rollback_delta = 0;
        in[0].npc_mode = 0u;
        in[0].width = 8u;
        in[0].flags = (uint8_t)(SPARC64_MEM_F_STORE | SPARC64_MEM_F_BE);
        in[0].val_or_dst_reg = 3u;
        in[0].addr_base_reg = 5u;
        in[1].seq_start_offset = 64u;
        in[1].host_insn_offset = 72u;
        in[1].cont_insn_offset = 120u;
        in[1].guest_pc_delta = 12u;
        in[1].npc_delta = -8;
        in[1].insn_word = UINT32_C(0xd65ef104);
        in[1].sp_rollback_delta = -16;
        in[1].npc_mode = 2u;
        in[1].width = 16u;
        in[1].flags = 0u;
        in[1].val_or_dst_reg = 11u;
        in[1].addr_base_reg = 30u;
        check("sites-round-trip",
            sparc64_aot_sites_encode(in, 2u, wire, sizeof(wire),
                &written) == 0 && written == 48u &&
            sparc64_aot_sites_decode(wire, sizeof(wire), out, 2u) == 0 &&
            memcmp(in, out, sizeof(in)) == 0);
    }
    {
        sparc64_mem_site_t bad;
        uint8_t wire[24];
        size_t written = 0;
        memset(&bad, 0, sizeof(bad));
        bad.width = 3u;
        errno = 0;
        check("sites-bad-width-rejected",
            sparc64_aot_sites_encode(&bad, 1u, wire, sizeof(wire),
                &written) == -1 && errno == EINVAL);
    }
    {
        sparc64_mem_site_t one;
        uint8_t wire[48];
        size_t written = 0;
        memset(&one, 0, sizeof(one));
        one.width = 4u;
        check("sites-encode-one",
            sparc64_aot_sites_encode(&one, 1u, wire, sizeof(wire),
                &written) == 0 && written == 24u);
        errno = 0;
        check("sites-short-decode-rejected",
            sparc64_aot_sites_decode(wire, 23u, &one, 1u) == -1 &&
            errno == EINVAL);
        wire[20] = 0xffu;
        errno = 0;
        check("sites-bad-flags-rejected",
            sparc64_aot_sites_decode(wire, 24u, &one, 1u) == -1 &&
            errno == EINVAL);
    }
    {
        size_t size = 0;
        errno = 0;
        check("sites-zero-count-rejected",
            sparc64_aot_sites_encoded_size(0u, &size) == -1 &&
            errno == EINVAL);
    }

    /* V3 format round-trip: per-block site tables survive encode and
     * decode; V1 refuses images that carry sites (fail-closed). */
    {
        static const uint8_t src_bytes[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
        static const uint8_t text_bytes[8] = { 9, 10, 11, 12, 13, 14,
            15, 16 };
        static const uint8_t digest[32] = { 0 };
        sparc64_mem_site_t sites[2];
        sparc64_aot_block_t blocks[2];
        sparc64_aot_image_t image;
        sparc64_aot_view_t view;
        sparc64_aot_block_view_t bv;
        sparc64_mem_site_t back;
        uint8_t record[8192];
        size_t written = 0;
        size_t sized = 0;
        memset(sites, 0, sizeof(sites));
        sites[0].guest_pc_delta = 4u;
        sites[0].width = 8u;
        sites[0].flags = (uint8_t)SPARC64_MEM_F_BE;
        sites[0].val_or_dst_reg = 3u;
        sites[0].addr_base_reg = 5u;
        sites[1].guest_pc_delta = 12u;
        sites[1].width = 4u;
        sites[1].flags = (uint8_t)(SPARC64_MEM_F_STORE |
            SPARC64_MEM_F_IN_DELAY_SLOT |
            (unsigned)SPARC64_MEM_F_BE);
        sites[1].val_or_dst_reg = 7u;
        sites[1].addr_base_reg = 9u;
        memset(&blocks, 0, sizeof(blocks));
        blocks[0].source_offset = 0u;
        blocks[0].source_bytes = src_bytes;
        blocks[0].source_size = sizeof(src_bytes);
        blocks[0].a64_text = text_bytes;
        blocks[0].a64_size = sizeof(text_bytes);
        blocks[0].sites = sites;
        blocks[0].site_count = 2u;
        blocks[1].source_offset = 8u;
        blocks[1].source_bytes = src_bytes;
        blocks[1].source_size = sizeof(src_bytes);
        blocks[1].a64_text = text_bytes;
        blocks[1].a64_size = sizeof(text_bytes);
        memset(&image, 0, sizeof(image));
        image.guest_extensions = 0u;
        image.a64_host_requirements = 0u;
        image.guest_page_size = 8192u;
        image.a64_host_page_size = 4096u;
        image.memory_model = SPARC64_AOT_MEMORY_SPARSE_CHECKED;
        image.xlen = 64u;
        image.abi = (uint8_t)SPARC64_AOT_ABI_LP64D;
        image.block_count = 2u;
        image.blocks = blocks;
        check("v3-size-ok",
            sparc64_aot_encoded_size_v3(&image, &sized) == 0 &&
            sized > 0u && sized <= sizeof(record));
        check("v3-encode-ok",
            sparc64_aot_encode_v3(&image, digest, record,
                sizeof(record), &written) == 0 && written == sized);
        memset(&view, 0, sizeof(view));
        check("v3-decode-ok",
            sparc64_aot_decode(record, written, &view) == 0 &&
            view.format_version == SPARC64_AOT_FORMAT_V3 &&
            view.block_count == 2u);
        memset(&bv, 0, sizeof(bv));
        check("v3-view-block0",
            sparc64_aot_view_block(&view, 0u, &bv) == 0 &&
            bv.site_count == 2u && bv.sites != NULL);
        memset(&back, 0, sizeof(back));
        check("v3-view-site0",
            sparc64_aot_view_site(&bv, 0u, &back) == 0 &&
            memcmp(&back, &sites[0], sizeof(back)) == 0);
        memset(&back, 0, sizeof(back));
        check("v3-view-site1",
            sparc64_aot_view_site(&bv, 1u, &back) == 0 &&
            memcmp(&back, &sites[1], sizeof(back)) == 0);
        memset(&bv, 0, sizeof(bv));
        check("v3-view-block1-empty",
            sparc64_aot_view_block(&view, 1u, &bv) == 0 &&
            bv.site_count == 0u);
        check("v3-view-site-oor",
            sparc64_aot_view_site(&bv, 0u, &back) != 0);
        errno = 0;
        check("v1-with-sites-rejected",
            sparc64_aot_encode(&image, record, sizeof(record),
                &written) != 0 && errno == EINVAL);
    }

    if (fails == 0) {
        (void)printf("RC-U2-8K-COW-EOF-PASS\n");
        return 0;
    }
    (void)printf("RC-U2-8K-COW-EOF-FAIL\n");
    return 1;
}
