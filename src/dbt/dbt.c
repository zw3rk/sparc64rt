/*
 * src/dbt/dbt.c — AArch64 DBT core: dispatcher, block cache, IBTC, RAS
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Phase 2 lane L2b (docs/lanes/phase-2.md) plus coordinator RC2 emission
 * wiring. The block cache, W^X code arena, direct-chaining dispatcher,
 * IBTC, and RAS live here; integer lowering is L2c's src/dbt/emit_int.h
 * (dbt_emit_range below). Emitted blocks run natively through the
 * trampoline and exit back per instruction (BRANCH chains, SYSCALL
 * stops, anything else replays one interpreter step for precise traps).
 * Blocks the classifier marks PRIV/FPU/FBR/ILLEGAL, or whose delay slot
 * the emitter refuses, always take the interpreter fallback with
 * identical protocol.
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
#include "dbt/emit_fp.h"
#include "dbt/emit_int.h"
#include "dbt/emit_mem.h"
#include "dbt/mem_sites.h"
#include "interp/interp.h"

/* Trampoline entries (trampoline_a64.S): ctx in x0, fragment entry in
 * x1, chaining entry in x2 (unused by exit-to-dispatcher fragments),
 * epoch word in x3. enter_step additionally pins x28 at a zero word
 * so any future epoch-gated chain probe bails after one fragment. */
extern void sparc64_dbt_enter(sparc64_ctx_t *ctx, const void *entry,
    const void *chain, const void *epoch);
extern void sparc64_dbt_enter_step(sparc64_ctx_t *ctx, const void *entry,
    const void *chain, const void *epoch);

/* Staging reserved per translated block for future L2c emission. */
#define DBT_STAGE_BYTES_PER_BLOCK 64U
/* Staging per emitted block (worst case: 64 insns plus delay slot). */
#define DBT_EMIT_STAGE_BYTES (4096U * 3U)
#define DBT_EMIT_STAGE_WORDS (DBT_EMIT_STAGE_BYTES / 4U)
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

/* ---- L2c emission (coordinator, RC2) ---- */

/* A delay slot is emittable only as a plain data/control op: a CTI,
 * Tcc, privileged, FPU, or illegal delay ends the block before the CTI
 * (the emitter refuses it and the interpreter replays both). SETHI
 * (which covers nop) plus the no-op MEMBAR/FLUSH are accepted on top
 * of the ALU/memory baseline: without SETHI, ordinary sethi/nop
 * delay fillers silently force whole blocks into the interpreter
 * fallback (H3: 78% of CoreMark block entries fell back for this
 * reason alone). This list mirrors e_delay_is_plain in emit_int.c:
 * SETHI covers nop fillers; SAVE/RESTORE are safe because JMPL now
 * snapshots a register-indirect target before the delay slot instead
 * of re-reading it after a window rotation (interp exec_cti order;
 * the old recompute jumped into the wrong window on ret-with-
 * restore). Keep the two lists in sync: any skew reintroduces
 * silent fallback-or-divergence risk. */
static bool dbt_delay_emittable(const sparc64_dec_t *d)
{
    switch (d->cls) {
    case SPARC64_ICLS_SETHI:
    case SPARC64_ICLS_MEMBAR:
    case SPARC64_ICLS_FLUSH:
    case SPARC64_ICLS_LOAD:
    case SPARC64_ICLS_STORE:
    case SPARC64_ICLS_LDSTUB:
    case SPARC64_ICLS_SWAP:
    case SPARC64_ICLS_ATOMIC:
    case SPARC64_ICLS_ALU:
    case SPARC64_ICLS_SHIFT:
    case SPARC64_ICLS_RDASR:
    case SPARC64_ICLS_WRASR:
    case SPARC64_ICLS_MOVCC:
    case SPARC64_ICLS_MOVR:
    case SPARC64_ICLS_ALIGN:
    case SPARC64_ICLS_SAVE:
    case SPARC64_ICLS_RESTORE:
        return true;
    default:
        return false;
    }
}

/* Emit [pc, end) into fresh arena staging. Returns the entry on success,
 * NULL when anything refuses (caller keeps the interpreter fallback and
 * rewinds the unused staging). CTI/Tcc always terminate [pc, end), so a
 * CTI here owns its delay slot at a + 4. */
static const void *dbt_emit_range(sparc64_dbt_t *dbt,
    const sparc64_mem_ops_t *mem, void *mc, uint64_t pc, uint64_t end)
{
    uint8_t *stage = dbt_stage(dbt, (size_t)DBT_EMIT_STAGE_BYTES);
    size_t used_before;
    sparc64_dbt_buf_t buf;
    sparc64_emit_ctx_t ec;
    uint64_t a;
    if (stage == NULL) {
        return NULL;
    }
    used_before = dbt->arena_used - (size_t)DBT_EMIT_STAGE_BYTES;
    buf.words = (uint32_t *)stage;
    buf.count = 0U;
    buf.capacity = DBT_EMIT_STAGE_WORDS;
    buf.overflow = false;
    buf.is_call = false;
    ec.buf = &buf;
    ec.mem = mem;
    ec.mc = mc;
    ec.delay = NULL;
    sparc64_mem_block_begin(pc);
    a = pc;
    while (a < end) {
        sparc64_dec_t d;
        bool term_here;
        ec.pc = a;
        ec.fault_pc = a;
        ec.delay = NULL;
        if (!dbt_fetch_classify(mem, mc, a, &d)) {
            goto fail;
        }
        if (d.cls != (uint8_t)SPARC64_ICLS_TCC && dbt_is_cti(&d)) {
            /* CTI plus delay slot ends the range and self-terminates. */
            sparc64_dec_t dl;
            if (!dbt_fetch_classify(mem, mc, a + 4U, &dl) ||
                !dbt_delay_emittable(&dl)) {
                goto fail;
            }
            ec.delay = &dl;
            if (!sparc64_emit_int(&ec, &d)) {
                goto fail;
            }
            break;
        }
        /* Tcc with a live condition self-terminates; everything else
         * (plain insns, never-trapping Tcc) needs a fall-through exit
         * at the range end. */
        term_here = d.cls == (uint8_t)SPARC64_ICLS_TCC && d.cond != 0U;
        if (d.cls == (uint8_t)SPARC64_ICLS_FPU) {
            if (!sparc64_emit_fp(&ec, &d)) {
                goto fail;
            }
        } else if (!sparc64_emit_int(&ec, &d)) {
            goto fail;
        }
        a += 4U;
        if (a == end && !term_here) {
            e_exit_imm(&buf, end, (uint32_t)SPARC64_EXIT_BRANCH);
        }
    }
    /* Append the Soft-TLB miss tail when sites were recorded; without
     * sites this is a no-op. Failure rewinds to the interpreter. */
    if (!sparc64_mem_block_end(&buf, mem, mc)) {
        goto fail;
    }
    if (buf.overflow) {
        goto fail;
    }
    /* Commit only the emitted bytes: the 12KB stage is scratch, and
     * keeping all of it per block fills the 4MB arena after ~341
     * translations, after which every recycle drops all native code
     * into interpreter replay (H3: ~79% of CoreMark entries). */
    dbt->arena_used = used_before + (size_t)buf.count * 4U;
    return (const void *)stage;
fail:
    dbt->arena_used = used_before;
    return NULL;
}

/* Commit one fragment exit into ctx; returns the step-shaped outcome.
 * BRANCH chains (CONTINUE with advanced pc/npc), SYSCALL stops without
 * advancing (the caller runs the handler), anything else replays one
 * interpreter step from the exit PC so traps stay precise. */
static sparc64_step_result_t dbt_commit_exit(sparc64_ctx_t *ctx,
    const sparc64_mem_ops_t *mem, void *mc)
{
    sparc64_step_result_t r;
    uint32_t why = ctx->exit_reason;
    uint64_t dst = ctx->exit_dest;
    if (why == SPARC64_EXIT_BRANCH) {
        ctx->pc = dst;
        ctx->npc = dst + 4U;
        return sparc64_step_ok(dst);
    }
    if (why == SPARC64_EXIT_SYSCALL) {
        ctx->pc = dst;
        ctx->npc = dst + 4U;
        r.kind = SPARC64_STEP_SYSCALL;
        r.cause = SPARC64_TRAP_ILLEGAL;
        r.pc = dst;
        r.tval = UINT64_C(0);
        r.length = 4U;
        r.memory_reason = SPARC64_MEM_FAULT_NONE;
        return r;
    }
    ctx->pc = dst;
    ctx->npc = dst + 4U;
    return sparc64_step(ctx, mem, mc);
}

/* Enter one emitted fragment and commit its exit. */
static sparc64_step_result_t dbt_enter_block(sparc64_ctx_t *ctx,
    const sparc64_mem_ops_t *mem, void *mc, sparc64_dbt_t *dbt,
    const void *code, bool single)
{
    if (single) {
        sparc64_dbt_enter_step(ctx, code, NULL, &dbt->epoch);
    } else {
        sparc64_dbt_enter(ctx, code, NULL, &dbt->epoch);
    }
    return dbt_commit_exit(ctx, mem, mc);
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
    void *staging = NULL;

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

    if (!needs_interp) {
        const void *code = dbt_emit_range(dbt, mem, mc, pc, end);
        if (code == NULL) {
            needs_interp = true;
        } else {
            staging = (void *)code;
        }
    }
    if (staging == NULL && !needs_interp) {
        staging = dbt_stage(dbt, (size_t)DBT_STAGE_BYTES_PER_BLOCK);
    }
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

/* Single-instruction step for difftest lockstep (a CTI plus its delay
 * slot counts as one step, matching sparc64_step). Emits at most the
 * pair into scratch staging, enters it once, and commits the exit;
 * falls back to the interpreter whenever anything refuses, so every
 * natively executed step is exactly what the block runner executes. */
sparc64_step_result_t sparc64_dbt_step_one(sparc64_dbt_t *dbt,
    sparc64_ctx_t *ctx, const sparc64_mem_ops_t *mem, void *mc)
{
    uint64_t pc = ctx->pc;
    sparc64_dec_t d;
    uint64_t span = 4U;
    const void *code;
    if (dbt == NULL) {
        return sparc64_step(ctx, mem, mc);
    }
    if (!dbt_fetch_classify(mem, mc, pc, &d)) {
        sparc64_step_result_t fail;
        (void)sparc64_fetch_word(mem, mc, pc, &(uint32_t){ 0U },
            &fail);
        return fail;
    }
    if (d.cls != (uint8_t)SPARC64_ICLS_TCC && dbt_is_cti(&d)) {
        sparc64_dec_t dl;
        if (!dbt_fetch_classify(mem, mc, pc + 4U, &dl) ||
            !dbt_delay_emittable(&dl)) {
            return sparc64_step(ctx, mem, mc);
        }
        span = 8U;
    }
    code = dbt_emit_range(dbt, mem, mc, pc, pc + span);
    if (code == NULL) {
        return sparc64_step(ctx, mem, mc);
    }
    dbt_publish(dbt);
    return dbt_enter_block(ctx, mem, mc, dbt, code, false);
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
    /* Emitted blocks report exits directly (NULL here): RAS/IBTC fills
     * are stats-only, so there is nothing to record for them. */
    if (d == NULL) {
        return;
    }
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
    /* The Soft-TLB table is BSS-zeroed (tag 0 would false-hit VPN 0 and
     * dereference the raw guest VA on the host); poison every tag to
     * ~0ULL before any translated code can run. */
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
        if (!b->needs_interp && b->host_code != NULL) {
            sparc64_step_result_t r;
            dbt_publish(dbt);
            r = dbt_enter_block(ctx, mem, mc, dbt, b->host_code,
                false);
            dbt_note_transfer(dbt, NULL, ctx->pc, 0U);
            if (r.kind != SPARC64_STEP_CONTINUE) {
                return r;
            }
            continue;
        }
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
