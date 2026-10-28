/*
 * src/dbt/dbt.h — AArch64 DBT core: dispatcher, block cache, IBTC, RAS
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Phase 2 lane L2b owns this file (docs/lanes/phase-2.md lane card L2b).
 * Frozen cross-lane interfaces below must not change without the
 * coordinator; integer lowering lives in L2c's src/dbt/emit_int.h.
 *
 * Design: blocks are keyed by guest PC (direct-mapped cache) with
 * page-version guards so SMC/mprotect re-translates stale ranges. The
 * 4096-entry IBTC chains indirect targets in software and the 64-entry
 * RAS pairs calls with returns. Blocks that the classifier marks
 * PRIV/FPU/FBR/ILLEGAL, plus every block until L2c's emitter lands,
 * execute through the reference interpreter (sparc64_step); the
 * dispatcher still fills IBTC/RAS and keeps W^X discipline on the code
 * arena (RW staging via a32host.h, RX + I-cache clear before execution)
 * so the L2c merge only adds emission into the staged area.
 */

#ifndef SPARC64RT_DBT_DBT_H
#define SPARC64RT_DBT_DBT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "core/cpu.h"

/* Translation limits: up to 64 guest insns per block, stopping at
 * control transfers or guest page boundaries (never crossing pages). */
#define SPARC64_DBT_MAX_INSNS_PER_BLOCK 64U
#define SPARC64_DBT_CACHE_SIZE 16384U
#define SPARC64_DBT_PAGE_TABLE_SIZE 512U
#define SPARC64_DBT_CODE_ARENA_SIZE (4U * 1024U * 1024U)
#define SPARC64_DBT_PAGE_SHIFT 12U /* 4096-byte guest pages */
#define SPARC64_DBT_PAGE_SIZE (UINT64_C(1) << SPARC64_DBT_PAGE_SHIFT)

/* IBTC slot: software chaining entry for one indirect-target guest PC. */
typedef struct {
    uint64_t key;     /* Guest target PC. */
    uint32_t index;   /* Block-cache slot holding the target block. */
    uint32_t epoch;   /* Cache epoch; stale entries never match. */
    bool valid;
} sparc64_dbt_ibtc_t;

/* Guest page-version slot: bumped by sparc64_dbt_invalidate. */
typedef struct {
    uint64_t vpn;     /* Guest virtual page number. */
    uint32_t version; /* Starts at 0 (absent); first bump makes it 1. */
    bool valid;
} sparc64_dbt_page_t;

/* Cached block descriptor (dispatcher metadata). host_code is staging
 * (RW) until publish flips the arena RX; NULL while L2c emission for
 * the block has not landed. needs_interp blocks always run via
 * sparc64_step with identical protocol. */
typedef struct {
    uint64_t start_pc;    /* First guest PC covered. */
    uint64_t end_pc;      /* First guest PC past the block (covers an
                           * inline CTI delay slot). */
    uint32_t n_insns;     /* Classified instructions in the block. */
    uint32_t page_version; /* Start-page version at translate time. */
    uint32_t epoch;       /* Cache epoch at translate time. */
    bool valid;
    bool needs_interp;    /* No emitted code: run via sparc64_step. */
    bool ends_cti;        /* Final insn is CALL/JMPL/RETURN/branch/Tcc. */
    bool is_link;         /* ends_cti with linkage (CALL, JMPL %o7). */
    bool indirect;        /* ends_cti with register target. */
    const void *host_code; /* Staged/RX entry point, NULL when unset. */
} sparc64_dbt_block_t;

/* Opaque dispatcher state (defined here so callers can hold it inline;
 * only init/fini/run/invalidate below are the cross-lane contract). */
struct sparc64_dbt {
    sparc64_dbt_ibtc_t ibtc[SPARC64_IBTC_SIZE];
    uint64_t ras[SPARC64_RAS_SIZE];
    uint32_t ras_top;
    sparc64_dbt_block_t blocks[SPARC64_DBT_CACHE_SIZE];
    sparc64_dbt_page_t pages[SPARC64_DBT_PAGE_TABLE_SIZE];
    uint32_t epoch;         /* Bumped on coarse flushes; 0 = invalid. */
    uint32_t cached_count;
    void *arena_base;       /* Anonymous RW staging, outside guest space. */
    size_t arena_used;
    bool arena_published;   /* True once flipped RX (reopen RW to emit). */
    uint64_t stat_blocks;   /* Blocks translated. */
    uint64_t stat_hits;     /* Block-cache hits. */
    uint64_t stat_ibtc_hits; /* IBTC chain hits. */
    uint64_t stat_ras_hits; /* RAS return predictions confirmed. */
};
typedef struct sparc64_dbt sparc64_dbt_t;

int sparc64_dbt_init(sparc64_dbt_t *dbt);
void sparc64_dbt_fini(sparc64_dbt_t *dbt);
/* Run until exit/trap; falls back to sparc64_step for EXIT_UNDEF and
 * single-step cases. Owns the 4096-entry IBTC + 64-entry RAS. */
sparc64_step_result_t sparc64_dbt_run(sparc64_ctx_t *ctx,
    const sparc64_mem_ops_t *mem, void *mc, sparc64_dbt_t *dbt);
/* Invalidate translated code overlapping [va, va+len) (SMC/mprotect). */
void sparc64_dbt_invalidate(sparc64_dbt_t *dbt, uint64_t va, uint64_t len);

/* Single-instruction step for difftest lockstep (a CTI plus its delay
 * slot counts as one step, matching sparc64_step). Falls back to the
 * interpreter whenever the instruction refuses emission. */
sparc64_step_result_t sparc64_dbt_step_one(sparc64_dbt_t *dbt,
    sparc64_ctx_t *ctx, const sparc64_mem_ops_t *mem, void *mc);

#endif /* SPARC64RT_DBT_DBT_H */
