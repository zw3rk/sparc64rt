/*
 * src/dbt/dbt.c — AArch64 DBT core: dispatcher, block cache, IBTC, RAS
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Phase 2 lane L2b (docs/lanes/phase-2.md). The block cache, W^X code
 * arena, direct-chaining dispatcher, IBTC, and RAS live here; integer
 * lowering is L2c's src/dbt/emit_int.h. Until that merge, every block
 * executes through the shared reference interpreter (sparc64_step over
 * sparc64_mem_ops_t, never a direct host dereference of guest VA), so
 * interp and dbt observe one window/memory model for difftest parity.
 * Blocks the classifier marks PRIV/FPU/FBR/ILLEGAL always take this
 * interpreter fallback with identical protocol.
 *
 * Exit reporting: sparc64_dbt_run returns the first non-CONTINUE step
 * result (SYSCALL with no register or pc change, precise TRAP with
 * TPC/TNPC fixup already applied by sparc64_step) so the caller handles
 * it exactly like an interpreter stop. EXIT_UNDEF-style stops (Phase 3
 * FPU/FBR markers surface as TRAP/ILLEGAL with the raw word in tval)
 * are replayed one interpreter step at a time by construction.
 *
 * W^X: emitted code (L2c) stages into the anonymous RW arena; the run
 * loop flips it to PROT_READ | PROT_EXEC and clears the I-cache (via
 * a32host.h) before any execution, reopening RW only to translate.
 * Guest data pages are never mapped PROT_EXEC.
 *
 * Invariants: every file <= 900 lines; curated C11 (no VLAs); full
 * 64-bit guest addresses, never truncated; no x18 anywhere (no inline
 * asm at all; the trampoline owns the asm and avoids x18 too).
 */

#include <string.h>

#include "a32host.h"
#include "dbt/dbt.h"
#include "interp/interp.h"

/* Staging reserved per translated block for future L2c emission. */
#define DBT_STAGE_BYTES_PER_BLOCK 64U
/* Invalidate wider than this many pages courses to a full flush. */
#define DBT_MAX_PRECISE_PAGES 4096U

static uint32_t dbt_cache_index(uint64_t pc)
{
    return (uint32_t)((pc >> 2U) & (uint64_t)(SPARC64_DBT_CACHE_SIZE - 1U));
}

static uint32_t dbt_ibtc_index(uint64_t pc)
{
    return (uint32_t)((pc >> 2U) & (uint64_t)(SPARC64_IBTC_SIZE - 1U));
}

static uint32_t dbt_page_index(uint64_t vpn)
{
    return (uint32_t)(vpn & (uint64_t)(SPARC64_DBT_PAGE_TABLE_SIZE - 1U));
}

static sparc64_step_result_t dbt_internal(uint64_t pc)
{
    sparc64_step_result_t r;
    r.kind = SPARC64_STEP_INTERNAL;
    r.cause = SPARC64_TRAP_INST_ACCESS;
    r.pc = pc;
    r.tval = pc;
    r.length = 4U;
    r.memory_reason = SPARC64_MEM_FAULT_INTERNAL;
    return r;
}

/* ---- Page versions (SMC/mprotect guards) ---- */

static uint32_t dbt_page_version(sparc64_dbt_t *dbt, uint64_t va)
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
            (void)a32h_wx_reopen(dbt->arena_base, span);
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
        /* Version wrap: fall back to a coarse flush so no stale
         * block can compare equal again. */
        dbt_flush_all(dbt);
        e->vpn = vpn;
        e->version = 1U;
        e->valid = true;
    }
}

/* ---- W^X code arena (anonymous host memory, outside guest space) ---- */

static void *dbt_stage(sparc64_dbt_t *dbt, size_t nbytes)
{
    uint32_t i;
    void *out;
    if (nbytes == (size_t)0) {
        return NULL;
    }
    if (dbt->arena_base == NULL) {
        dbt->arena_base = a32h_arena_map(SPARC64_DBT_CODE_ARENA_SIZE);
        if (dbt->arena_base == NULL) {
            return NULL;
        }
        dbt->arena_used = 0U;
        dbt->arena_published = false;
    }
    if (dbt->arena_published) {
        size_t span = a32h_page_span(dbt->arena_used);
        if (a32h_wx_reopen(dbt->arena_base, span) != 0) {
            return NULL;
        }
        dbt->arena_published = false;
    }
    if (nbytes > SPARC64_DBT_CODE_ARENA_SIZE - dbt->arena_used) {
        /* Recycle staging; emitted entries are L2c-owned, so drop
         * every staged pointer back to interpreter fallback. */
        for (i = 0U; i < SPARC64_DBT_CACHE_SIZE; i++) {
            dbt->blocks[i].host_code = NULL;
        }
        dbt->arena_used = 0U;
    }
    if (nbytes > SPARC64_DBT_CODE_ARENA_SIZE - dbt->arena_used) {
        return NULL;
    }
    out = (void *)((uint8_t *)dbt->arena_base + dbt->arena_used);
    dbt->arena_used += nbytes;
    return out;
}

/* Flip newly staged code RX + I-cache clear (W^X stays sequential). */
static void dbt_publish(sparc64_dbt_t *dbt)
{
    size_t span;
    if (dbt->arena_base == NULL || dbt->arena_published ||
        dbt->arena_used == (size_t)0) {
        return;
    }
    span = a32h_page_span(dbt->arena_used);
    if (a32h_wx_publish(dbt->arena_base, span) != 0) {
        return;
    }
    a32h_icache_clear(dbt->arena_base,
        (void *)((uint8_t *)dbt->arena_base + dbt->arena_used));
    dbt->arena_published = true;
}

/* ---- Decode helpers ---- */

static bool dbt_fetch_classify(const sparc64_mem_ops_t *mem, void *mc,
    uint64_t pc, sparc64_dec_t *out)
{
    sparc64_step_result_t res;
    uint32_t raw;
    if (!sparc64_fetch_word(mem, mc, pc, &raw, &res)) {
        return false;
    }
    sparc64_classify_word(raw, out);
    return true;
}

static bool dbt_is_cti(const sparc64_dec_t *d)
{
    return d->cls == (uint8_t)SPARC64_ICLS_CALL ||
        d->cls == (uint8_t)SPARC64_ICLS_JMPL ||
        d->cls == (uint8_t)SPARC64_ICLS_RETURN ||
        d->cls == (uint8_t)SPARC64_ICLS_BICC ||
        d->cls == (uint8_t)SPARC64_ICLS_BPCC ||
        d->cls == (uint8_t)SPARC64_ICLS_BPR ||
        d->cls == (uint8_t)SPARC64_ICLS_TCC;
}

/* ---- Translation: classify a block, stage room, install metadata ---- */

static const sparc64_dbt_block_t *dbt_translate(
    const sparc64_mem_ops_t *mem, void *mc, sparc64_dbt_t *dbt, uint64_t pc,
    sparc64_step_result_t *fail)
{
    uint32_t idx = dbt_cache_index(pc);
    sparc64_dbt_block_t *b = &dbt->blocks[idx];
    uint64_t cur = pc;
    uint32_t n = 0U;
    uint64_t end = pc;
    bool ends_cti = false;
    bool is_link = false;
    bool indirect = false;
    bool needs_interp = false;
    bool stop = false;
    void *staging;

    while (n < SPARC64_DBT_MAX_INSNS_PER_BLOCK && !stop) {
        sparc64_dec_t d;
        uint32_t raw;
        sparc64_step_result_t res;
        if (n != 0U && (cur & (SPARC64_DBT_PAGE_SIZE - UINT64_C(1))) == 0U) {
            break; /* Never cross a guest page boundary. */
        }
        if (!sparc64_fetch_word(mem, mc, cur, &raw, &res)) {
            if (n == 0U) {
                *fail = res;
                return NULL;
            }
            break;
        }
        sparc64_classify_word(raw, &d);
        n += 1U;
        switch (d.cls) {
        case SPARC64_ICLS_CALL:
            ends_cti = true;
            is_link = true;
            end = cur + 8U;
            stop = true;
            break;
        case SPARC64_ICLS_JMPL:
            ends_cti = true;
            indirect = true;
            is_link = (d.rd == (uint8_t)SPARC64_O7);
            end = cur + 8U;
            stop = true;
            break;
        case SPARC64_ICLS_RETURN:
            ends_cti = true;
            indirect = true;
            end = cur + 8U;
            stop = true;
            break;
        case SPARC64_ICLS_BICC:
        case SPARC64_ICLS_BPCC:
        case SPARC64_ICLS_BPR:
            ends_cti = true;
            end = cur + 8U; /* Delay slot executes inline. */
            stop = true;
            break;
        case SPARC64_ICLS_TCC:
            ends_cti = true;
            end = cur + 4U; /* No delay slot; always ends the block. */
            stop = true;
            break;
        case SPARC64_ICLS_PRIV:
        case SPARC64_ICLS_FPU:
        case SPARC64_ICLS_FBR:
        case SPARC64_ICLS_ILLEGAL:
            /* Rare/system/privileged: pristine interpreter fallback. */
            needs_interp = true;
            end = cur + 4U;
            stop = true;
            break;
        default:
            end = cur + 4U;
            break;
        }
        if (!stop) {
            cur += 4U;
        }
    }

    staging = dbt_stage(dbt, (size_t)DBT_STAGE_BYTES_PER_BLOCK);
    b->start_pc = pc;
    b->end_pc = end;
    b->n_insns = n;
    b->page_version = dbt_page_version(dbt, pc);
    b->epoch = dbt->epoch;
    b->valid = true;
    b->needs_interp = needs_interp;
    b->ends_cti = ends_cti;
    b->is_link = is_link;
    b->indirect = indirect;
    b->host_code = (const void *)staging;
    dbt->cached_count += 1U;
    dbt->stat_blocks += 1U;
    return b;
}

static const sparc64_dbt_block_t *dbt_lookup(
    const sparc64_mem_ops_t *mem, void *mc, sparc64_dbt_t *dbt, uint64_t pc,
    sparc64_step_result_t *fail)
{
    uint32_t idx = dbt_cache_index(pc);
    sparc64_dbt_block_t *b = &dbt->blocks[idx];
    if (b->valid && b->epoch == dbt->epoch && b->start_pc == pc &&
        b->page_version == dbt_page_version(dbt, pc)) {
        dbt->stat_hits += 1U;
        return b;
    }
    return dbt_translate(mem, mc, dbt, pc, fail);
}

/* ---- IBTC / RAS (architectural arrays in dbt, SPEC section 3.2) ---- */

static const sparc64_dbt_block_t *dbt_ibtc_probe(sparc64_dbt_t *dbt,
    uint64_t pc)
{
    sparc64_dbt_ibtc_t *e = &dbt->ibtc[dbt_ibtc_index(pc)];
    const sparc64_dbt_block_t *b;
    if (!e->valid || e->epoch != dbt->epoch || e->key != pc) {
        return NULL;
    }
    if (e->index >= SPARC64_DBT_CACHE_SIZE) {
        return NULL;
    }
    b = &dbt->blocks[e->index];
    if (!b->valid || b->epoch != dbt->epoch || b->start_pc != pc ||
        b->page_version != dbt_page_version(dbt, pc)) {
        return NULL;
    }
    dbt->stat_ibtc_hits += 1U;
    return b;
}

static void dbt_ibtc_fill(sparc64_dbt_t *dbt, uint64_t pc, uint32_t index)
{
    sparc64_dbt_ibtc_t *e = &dbt->ibtc[dbt_ibtc_index(pc)];
    if (index >= SPARC64_DBT_CACHE_SIZE) {
        return;
    }
    e->key = pc;
    e->index = index;
    e->epoch = dbt->epoch;
    e->valid = true;
}

static void dbt_ras_push(sparc64_dbt_t *dbt, uint64_t ret_pc)
{
    dbt->ras_top = (dbt->ras_top + 1U) % SPARC64_RAS_SIZE;
    dbt->ras[dbt->ras_top] = ret_pc;
}

static bool dbt_ras_match(const sparc64_dbt_t *dbt, uint64_t pc)
{
    /* Stats-only prediction: a cold (all-zero) match is benign since the
     * dispatcher never steers execution off the RAS, it only counts. */
    return dbt->ras[dbt->ras_top] == pc;
}

/* Bookkeeping after one interpreter step over a classified insn:
 * pair calls with returns, confirm RAS predictions, feed the IBTC. */
static void dbt_note_transfer(sparc64_dbt_t *dbt, const sparc64_dec_t *d,
    uint64_t npc0, uint64_t target)
{
    if (d->cls == (uint8_t)SPARC64_ICLS_CALL ||
        (d->cls == (uint8_t)SPARC64_ICLS_JMPL &&
            d->rd == (uint8_t)SPARC64_O7)) {
        dbt_ras_push(dbt, npc0 + 4U);
        dbt_ibtc_fill(dbt, target, dbt_cache_index(target));
    } else if (d->cls == (uint8_t)SPARC64_ICLS_RETURN ||
        (d->cls == (uint8_t)SPARC64_ICLS_JMPL)) {
        if (dbt_ras_match(dbt, target)) {
            dbt->stat_ras_hits += 1U;
        }
        dbt_ibtc_fill(dbt, target, dbt_cache_index(target));
    } else if (dbt_is_cti(d)) {
        dbt_ibtc_fill(dbt, target, dbt_cache_index(target));
    }
}

/* ---- Frozen cross-lane interface ---- */

int sparc64_dbt_init(sparc64_dbt_t *dbt)
{
    if (dbt == NULL) {
        return -1;
    }
    (void)memset(dbt, 0, sizeof(*dbt));
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

sparc64_step_result_t sparc64_dbt_run(sparc64_ctx_t *ctx,
    const sparc64_mem_ops_t *mem, void *mc, sparc64_dbt_t *dbt)
{
    if (ctx == NULL || mem == NULL || dbt == NULL) {
        return dbt_internal((ctx != NULL) ? ctx->pc : UINT64_C(0));
    }
    for (;;) {
        const sparc64_dbt_block_t *b;
        sparc64_step_result_t fail;
        uint32_t i;
        dbt_publish(dbt);
        b = dbt_ibtc_probe(dbt, ctx->pc);
        if (b == NULL) {
            b = dbt_lookup(mem, mc, dbt, ctx->pc, &fail);
            if (b == NULL) {
                return fail;
            }
            dbt_ibtc_fill(dbt, ctx->pc, dbt_cache_index(ctx->pc));
        }
        ctx->blocks_executed += 1U;
        for (i = 0U; i < b->n_insns; i++) {
            sparc64_dec_t d;
            uint64_t npc0 = ctx->npc;
            bool known = dbt_fetch_classify(mem, mc, ctx->pc, &d);
            sparc64_step_result_t r = sparc64_step(ctx, mem, mc);
            if (r.kind != SPARC64_STEP_CONTINUE) {
                return r;
            }
            if (known && dbt_is_cti(&d)) {
                dbt_note_transfer(dbt, &d, npc0, ctx->pc);
            }
            if (b->ends_cti) {
                break; /* CTI consumed its delay slot; chain next. */
            }
        }
    }
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
        dbt_flush_all(dbt); /* Range wraps: coarse flush. */
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
