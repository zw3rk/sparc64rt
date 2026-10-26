/*
 * src/dbt/mem_sites.c — Soft-TLB storage and miss slow path (Lane M3)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Implements mem_sites.h: the process-global 128 KiB Soft-TLB, range
 * invalidation, per-block records, and the interpreter-backed slow path
 * used by the emitted per-block miss trampoline and by emit_rt.c.
 * Correctness comes from replaying the exact guest instruction with
 * sparc64_step, so DBT/interp parity holds by construction.
 */

#include "dbt/mem_sites.h"

#include <stdlib.h>
#include <string.h>

#include "interp/interp.h"

sparc64_tlb_entry_t sparc64_dbt_tlb[SPARC64_TLB_SIZE]
    __attribute__((aligned(32)));

void sparc64_tlb_init(void)
{
    uint32_t i;
    for (i = 0u; i < SPARC64_TLB_SIZE; i++) {
        sparc64_dbt_tlb[i].read_tag = SPARC64_TLB_INVALID_TAG;
        sparc64_dbt_tlb[i].addend = (uintptr_t)0;
        sparc64_dbt_tlb[i].write_tag = SPARC64_TLB_INVALID_TAG;
        sparc64_dbt_tlb[i].reserved = UINT64_C(0);
    }
}

void sparc64_tlb_invalidate_gva(uint64_t gva, uint64_t len)
{
    uint64_t pages;
    uint64_t vpn;
    uint64_t i;
    if (len == UINT64_C(0)) {
        return;
    }
    pages = (len + UINT64_C(0xfff)) >> 12;
    vpn = (gva >> 12) & (uint64_t)(SPARC64_TLB_SIZE - 1u);
    if (pages >= UINT64_C(512) || pages == UINT64_C(0)) {
        sparc64_tlb_init();
        return;
    }
    /* Range may wrap the 12-bit index window; walk pages, not indices. */
    for (i = UINT64_C(0); i < pages; i++) {
        uint64_t idx = (vpn + i) & (uint64_t)(SPARC64_TLB_SIZE - 1u);
        sparc64_dbt_tlb[idx].read_tag = SPARC64_TLB_INVALID_TAG;
        sparc64_dbt_tlb[idx].write_tag = SPARC64_TLB_INVALID_TAG;
    }
}

sparc64_mem_block_t *sparc64_mem_block_alloc(
    const sparc64_mem_ops_t *mem, void *mc, uint64_t guest_pc_base,
    uint64_t rx_base, uint32_t n_sites)
{
    sparc64_mem_block_t *blk;
    size_t total;
    if (mem == NULL || n_sites == 0u) {
        return NULL;
    }
    total = sizeof(*blk) + (size_t)n_sites * sizeof(blk->sites[0]);
    blk = (sparc64_mem_block_t *)malloc(total);
    if (blk == NULL) {
        return NULL;
    }
    (void)memset(blk, 0, total);
    blk->mem = mem;
    blk->mc = mc;
    blk->guest_pc_base = guest_pc_base;
    blk->rx_base = rx_base;
    blk->n_sites = n_sites;
    return blk;
}

void sparc64_mem_block_free(sparc64_mem_block_t *blk)
{
    free(blk);
}

uint32_t sparc64_mem_slow_step(sparc64_ctx_t *ctx,
    const sparc64_mem_ops_t *mem, void *mc, uint64_t fault_pc)
{
    sparc64_step_result_t r;
    uint64_t saved_pc;
    uint64_t saved_npc;
    if (ctx == NULL || mem == NULL) {
        return (uint32_t)SPARC64_EXIT_UNDEF;
    }
    saved_pc = ctx->pc;
    saved_npc = ctx->npc;
    /* The block never advances pc/npc per instruction; replay exactly
     * one instruction at the fault PC and restore the pair so the
     * resumed block and its exits observe undisturbed state. */
    ctx->pc = fault_pc;
    ctx->npc = fault_pc + UINT64_C(4);
    r = sparc64_step(ctx, mem, mc);
    if (r.kind == SPARC64_STEP_CONTINUE) {
        ctx->pc = saved_pc;
        ctx->npc = saved_npc;
        return (uint32_t)SPARC64_EXIT_NONE;
    }
    if (r.kind == SPARC64_STEP_SYSCALL) {
        ctx->pc = fault_pc;
        ctx->npc = fault_pc + UINT64_C(4);
        ctx->exit_reason = (uint32_t)SPARC64_EXIT_SYSCALL;
        ctx->exit_dest = fault_pc;
        return (uint32_t)SPARC64_EXIT_SYSCALL;
    }
    if (r.kind == SPARC64_STEP_TRAP) {
        /* Chain at the trap target: the dispatcher advances there. */
        ctx->pc = r.pc;
        ctx->npc = r.pc + UINT64_C(4);
        ctx->exit_reason = (uint32_t)SPARC64_EXIT_BRANCH;
        ctx->exit_dest = r.pc;
        return (uint32_t)SPARC64_EXIT_BRANCH;
    }
    ctx->pc = saved_pc;
    ctx->npc = saved_npc;
    ctx->exit_reason = (uint32_t)SPARC64_EXIT_UNDEF;
    ctx->exit_dest = fault_pc;
    return (uint32_t)SPARC64_EXIT_UNDEF;
}

void *sparc64_mem_miss(sparc64_ctx_t *ctx, uint64_t gva, uint64_t val,
    const sparc64_mem_block_t *blk, uint32_t site_idx)
{
    const sparc64_mem_site_t *site;
    uint64_t fault_pc;
    uint32_t rc;
    (void)gva;
    (void)val;
    if (ctx == NULL || blk == NULL || blk->mem == NULL ||
        site_idx >= blk->n_sites) {
        if (ctx != NULL) {
            ctx->exit_reason = (uint32_t)SPARC64_EXIT_UNDEF;
            ctx->exit_dest = ctx->pc;
        }
        return NULL;
    }
    site = &blk->sites[site_idx];
    fault_pc = blk->guest_pc_base + (uint64_t)site->guest_pc_delta;
    if (site->sp_rollback_delta != 0 &&
        site->addr_base_reg < 32u) {
        ctx->r[site->addr_base_reg] =
            ctx->r[site->addr_base_reg] +
            (uint64_t)(int64_t)site->sp_rollback_delta;
    }
    rc = sparc64_mem_slow_step(ctx, blk->mem, blk->mc, fault_pc);
    if (rc == (uint32_t)SPARC64_EXIT_NONE) {
        return (void *)(blk->rx_base +
            (uint64_t)site->cont_insn_offset);
    }
    return NULL;
}
