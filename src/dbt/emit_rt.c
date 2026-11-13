/*
 * src/dbt/emit_rt.c — DBT page-version, cache-flush, and invalidation helpers
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Manages the DBT page-version table, full cache flushes, and precise range
 * invalidations, plus compile-time layout assertions for trampoline_a64.S.
 * Runtime memory and window helpers (`s64_jrt_mem`, `s64_jrt_win`) live in
 * dbt/emit_mem.h alongside their inline Soft-TLB emitters.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "a32host.h"
#include "core/cpu.h"
#include "dbt/dbt.h"
#include "dbt/mem_sites.h"

/* A small-range invalidate (fewer than this many 4 KiB pages) evicts
 * only the overlapping direct-mapped block-cache and IBTC slots (see
 * sparc64_dbt_invalidate): unrelated pages keep their cached blocks
 * and IBTC entries hot. Wider ranges course to a full flush (which
 * also reclaims the code arena). */
#define DBT_MAX_PRECISE_PAGES 8U

/* A translated block spans at most 64 insns plus one inline CTI delay
 * slot, so any block overlapping [va, end) starts within MAX_SPAN
 * bytes before va (4-byte-aligned probes cover every direct-mapped
 * block-cache and IBTC slot it could occupy). */
#define DBT_INVALIDATE_MAX_SPAN \
    ((uint64_t)SPARC64_DBT_MAX_INSNS_PER_BLOCK * UINT64_C(4) + \
        UINT64_C(4))

/* Trampoline probe layout contract (trampoline_a64.S hardcodes these
 * field offsets; break the build loudly if dbt.h ever drifts). */
_Static_assert(sizeof(sparc64_dbt_ibtc_t) == 24U, "ibtc stride");
_Static_assert(offsetof(sparc64_dbt_ibtc_t, key) == 0U, "ibtc key");
_Static_assert(offsetof(sparc64_dbt_ibtc_t, index) == 8U, "ibtc index");
_Static_assert(offsetof(sparc64_dbt_ibtc_t, epoch) == 12U, "ibtc epoch");
_Static_assert(offsetof(sparc64_dbt_ibtc_t, valid) == 16U, "ibtc valid");
_Static_assert(sizeof(sparc64_dbt_block_t) == 48U, "block stride");
_Static_assert(offsetof(sparc64_dbt_block_t, start_pc) == 0U, "blk start");
_Static_assert(offsetof(sparc64_dbt_block_t, page_version) == 20U,
    "blk pagever");
_Static_assert(offsetof(sparc64_dbt_block_t, epoch) == 24U, "blk epoch");
_Static_assert(offsetof(sparc64_dbt_block_t, valid) == 28U, "blk valid");
_Static_assert(offsetof(sparc64_dbt_block_t, host_code) == 40U,
    "blk code");
_Static_assert(sizeof(sparc64_dbt_page_t) == 16U, "page stride");
_Static_assert(offsetof(sparc64_dbt_page_t, vpn) == 0U, "page vpn");
_Static_assert(offsetof(sparc64_dbt_page_t, version) == 8U, "page ver");
_Static_assert(offsetof(sparc64_dbt_page_t, valid) == 12U, "page valid");

static uint32_t dbt_page_index(uint64_t vpn)
{
    return (uint32_t)(vpn & (uint64_t)(SPARC64_DBT_PAGE_TABLE_SIZE - 1U));
}

uint32_t sparc64_dbt_page_version(sparc64_dbt_t *dbt, uint64_t va)
{
    uint64_t vpn = va >> SPARC64_DBT_PAGE_SHIFT;
    sparc64_dbt_page_t *e = &dbt->pages[dbt_page_index(vpn)];
    if (e->valid && e->vpn == vpn) {
        return e->version;
    }
    return 0U;
}

static void dbt_flush_all(sparc64_dbt_t *dbt)
{
    uint32_t i;
    size_t span;
    for (i = 0U; i < SPARC64_DBT_CACHE_SIZE; i++) {
        dbt->blocks[i].valid = false;
        dbt->blocks[i].host_code = NULL;
    }
    for (i = 0U; i < SPARC64_IBTC_SIZE; i++) {
        dbt->ibtc[i].valid = false;
    }
    dbt->cached_count = 0U;
    dbt->epoch += 1U;
    if (dbt->epoch == 0U) {
        dbt->epoch = 1U;
    }
    if (dbt->arena_base != NULL) {
        if (dbt->arena_published) {
            span = a32h_page_span(dbt->arena_used);
            if (a32h_wx_reopen(dbt->arena_base, span) != 0) {
                return;
            }
            dbt->arena_published = false;
        }
        dbt->arena_used = 0U;
    }
}

/* Record one VPN in the page-version table (fresh version 1). */
static void dbt_page_record(sparc64_dbt_t *dbt, uint64_t vpn)
{
    sparc64_dbt_page_t *e = &dbt->pages[dbt_page_index(vpn)];
    e->vpn = vpn;
    e->version = 1U;
    e->valid = true;
}

/* Bump one VPN's version; true when the slot held a different live
 * VPN (hash alias), so the caller flushes and re-records instead of
 * trusting a recycled version. */
static bool dbt_page_bump(sparc64_dbt_t *dbt, uint64_t vpn)
{
    sparc64_dbt_page_t *e = &dbt->pages[dbt_page_index(vpn)];
    if (!e->valid || e->vpn != vpn) {
        bool aliased = e->valid && e->vpn != vpn;
        dbt_page_record(dbt, vpn);
        return aliased;
    }
    e->version += 1U;
    if (e->version == 0U) {
        dbt_flush_all(dbt);
        dbt_page_record(dbt, vpn);
    }
    return false;
}

int sparc64_dbt_init(sparc64_dbt_t *dbt)
{
    if (dbt == NULL) {
        return -1;
    }
    (void)memset(dbt, 0, sizeof(*dbt));
    sparc64_tlb_init();
    dbt->epoch = 1U;
    dbt->arena_base = NULL;
    dbt->arena_used = 0U;
    dbt->arena_published = false;
    return 0;
}

void sparc64_dbt_fini(sparc64_dbt_t *dbt)
{
    if (dbt == NULL) {
        return;
    }
    a32h_arena_unmap(dbt->arena_base, SPARC64_DBT_CODE_ARENA_SIZE);
    (void)memset(dbt, 0, sizeof(*dbt));
}

void sparc64_dbt_invalidate(sparc64_dbt_t *dbt, uint64_t va, uint64_t len)
{
    uint64_t end;
    uint64_t first_vpn;
    uint64_t last_vpn;
    uint64_t vpn;
    uint64_t va_aligned;
    uint64_t scan_lo;
    uint64_t scan_hi;
    uint64_t pc;
    if (dbt == NULL || len == UINT64_C(0)) {
        return;
    }
    end = va + len;
    if (end <= va) {
        dbt_flush_all(dbt);
        return;
    }
    first_vpn = va >> SPARC64_DBT_PAGE_SHIFT;
    last_vpn = (end - UINT64_C(1)) >> SPARC64_DBT_PAGE_SHIFT;
    if (last_vpn - first_vpn >= (uint64_t)DBT_MAX_PRECISE_PAGES) {
        dbt_flush_all(dbt);
        return;
    }
    /* A CTI at prev_page + 0xffc delays into va: version the previous
     * page too when va sits at its very start. */
    if ((va & (SPARC64_DBT_PAGE_SIZE - UINT64_C(1))) < UINT64_C(4) &&
        first_vpn > UINT64_C(0) &&
        dbt_page_bump(dbt, first_vpn - UINT64_C(1))) {
        dbt_flush_all(dbt);
        dbt_page_record(dbt, first_vpn - UINT64_C(1));
    }
    for (vpn = first_vpn; vpn <= last_vpn; vpn++) {
        if (dbt_page_bump(dbt, vpn)) {
            dbt_flush_all(dbt);
            dbt_page_record(dbt, vpn);
        }
        if (vpn == UINT64_MAX >> SPARC64_DBT_PAGE_SHIFT) {
            break;
        }
    }
    /* Direct-mapped probes only: every overlapping block starts in
     * [scan_lo, scan_hi), so no full cache or IBTC scan is needed and
     * the epoch stays put (unrelated pages keep their entries hot).
     * Cleared blocks also release their Soft-TLB write guard (the
     * page_has_code check in mem_sites.c keys on valid/host_code). */
    va_aligned = va & ~UINT64_C(3);
    scan_lo = (va_aligned > DBT_INVALIDATE_MAX_SPAN) ?
        (va_aligned - DBT_INVALIDATE_MAX_SPAN) : UINT64_C(0);
    if (end >= UINT64_C(0xFFFFFFFFFFFFFFFC)) {
        scan_hi = UINT64_C(0xFFFFFFFFFFFFFFFC);
    } else {
        scan_hi = (end + UINT64_C(3)) & ~UINT64_C(3);
    }
    for (pc = scan_lo; pc < scan_hi; pc += UINT64_C(4)) {
        sparc64_dbt_block_t *b = &dbt->blocks[(uint32_t)((pc >> 2U) &
            (uint64_t)(SPARC64_DBT_CACHE_SIZE - 1U))];
        sparc64_dbt_ibtc_t *e = &dbt->ibtc[(uint32_t)((pc >> 2U) &
            (uint64_t)(SPARC64_IBTC_SIZE - 1U))];
        if (b->valid && !(b->end_pc <= va || b->start_pc >= end)) {
            b->valid = false;
            b->host_code = NULL;
            if (dbt->cached_count != 0U) {
                dbt->cached_count -= 1U;
            }
        }
        if (e->valid && !(e->key < scan_lo || e->key >= scan_hi)) {
            e->valid = false;
        }
        if (pc >= UINT64_C(0xFFFFFFFFFFFFFFFC)) {
            break;
        }
    }
}
