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

/* Invalidate wider than this many pages courses to a full flush. */
#define DBT_MAX_PRECISE_PAGES 4096U

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

static void dbt_page_bump(sparc64_dbt_t *dbt, uint64_t vpn)
{
    sparc64_dbt_page_t *e = &dbt->pages[dbt_page_index(vpn)];
    if (!e->valid || e->vpn != vpn) {
        e->vpn = vpn;
        e->version = 1U;
        e->valid = true;
        return;
    }
    e->version += 1U;
    if (e->version == 0U) {
        dbt_flush_all(dbt);
        e->vpn = vpn;
        e->version = 1U;
        e->valid = true;
    }
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
    uint32_t i;
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
    for (vpn = first_vpn; vpn <= last_vpn; vpn++) {
        dbt_page_bump(dbt, vpn);
        if (vpn == UINT64_MAX >> SPARC64_DBT_PAGE_SHIFT) {
            break;
        }
    }
    for (i = 0U; i < SPARC64_DBT_CACHE_SIZE; i++) {
        sparc64_dbt_block_t *b = &dbt->blocks[i];
        if (b->valid && !(b->end_pc <= va || b->start_pc >= end)) {
            b->valid = false;
            b->host_code = NULL;
            if (dbt->cached_count != 0U) {
                dbt->cached_count -= 1U;
            }
        }
    }
    for (i = 0U; i < SPARC64_IBTC_SIZE; i++) {
        sparc64_dbt_ibtc_t *e = &dbt->ibtc[i];
        if (e->valid && !(e->key < va || e->key >= end)) {
            e->valid = false;
        }
    }
}
