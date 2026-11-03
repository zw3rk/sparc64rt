/*
 * src/os/sysmem_file_resize.c -- truncate resize for file-backed sysmem.
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Split from src/os/guest_run_sysmem_file.c (S64-R4 line discipline)
 * so neither TU exceeds the 900-line limit: this file owns the
 * truncate/ftruncate resize leg (shrink converts stripped pages to
 * BUS spans and zero-fills the surviving partial-page tail; growth
 * restores previously-bused pages as zero heap pages, S64-R4-6 prot
 * aware via the registry). Shared types live in
 * src/os/sysmem_file.h. Never maps guest data PROT_EXEC on the host
 * and never touches host register x18.
 */

#define _POSIX_C_SOURCE 200809L

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "os/sysmem_file.h"

/* Resize a file all live mappings observe: shrink converts stripped
 * full 8 KiB pages to BUS spans, zero-fills the surviving partial-page
 * tail [new_size, min(old_size, 8 KiB page end)) in place, and growth
 * restores previously-bused pages as zero heap pages. All three legs
 * invalidate paired TLB coverage. */
void sysmem_file_resize(void *context, uint64_t dev, uint64_t ino,
    uint64_t old_size, uint64_t new_size)
{
    guest_state_t *g = (guest_state_t *)context;
    size_t i;
    int changed = 0;
    if (g == NULL || old_size == new_size) {
        return;
    }
    for (i = 0u; i < sysmem_file_cap; i++) {
        sysmem_file_range_t *slot = &sysmem_files[i];
        uint64_t ob = 0u;
        uint64_t ob_len = 0u;
        uint64_t nb = 0u;
        uint64_t nb_len = 0u;
        uint64_t lo;
        uint64_t hi;
        bool had_bus;
        bool has_bus;
        if (!slot->live || slot->dev != dev || slot->ino != ino) {
            continue;
        }
        /* RC-U4 #4: a shrink landing mid-8KiB-page leaves the surviving
         * head [new_size, min(old_size, page end)) mapped, so stale
         * file bytes past the new EOF must read zero. Zero them in
         * the guest pages (clamped to this entry's file range); the
         * BUS leg below starts at the page end and never overlaps. */
        if (new_size < old_size) {
            uint64_t zs = new_size > slot->file_offset ? new_size :
                slot->file_offset;
            uint64_t ze = sysmem_align_up_8k(new_size);
            uint64_t slot_end = slot->file_offset + slot->len;
            uint8_t zeros[4096];
            uint64_t at;
            if (old_size < ze) {
                ze = old_size;
            }
            if (slot_end < ze) {
                ze = slot_end;
            }
            if (ze > zs) {
                uint64_t gva = slot->base + (zs - slot->file_offset);
                uint64_t left = ze - zs;
                uint64_t pc0 = zs & ~(UINT64_C(8192) - 1u);
                uint64_t cj;
                (void)memset(zeros, 0, sizeof(zeros));
                for (at = 0u; at < left;) {
                    size_t want = (size_t)(left - at);
                    if (want > sizeof(zeros)) {
                        want = sizeof(zeros);
                    }
                    /* Mapped by construction (the BUS leg below only
                     * covers whole pages at/after the page end). */
                    (void)sparc64_space_write_initial(&g->space,
                        gva + at, zeros, want);
                    at += (uint64_t)want;
                }
                /* RC-U4 #5: the zeroed tail diverges from the file for
                 * a private mapping, so its chunk promotes (SHARED
                 * chunks never transition). */
                cj = pc0 >= slot->file_offset ?
                    (pc0 - slot->file_offset) / UINT64_C(8192) : 0u;
                if (cj < (uint64_t)slot->nchunk &&
                    slot->cstate[cj] ==
                    (uint8_t)VM64_PAGE_COW_CLEAN) {
                    slot->cstate[cj] = (uint8_t)VM64_PAGE_COW_DIRTY;
                }
                /* S64-R3-1: zeroed code bytes invalidate the live
                 * block cache alongside the TLB leg below. */
                if (g->dbt != NULL) {
                    sparc64_dbt_invalidate(g->dbt, gva, left);
                }
                changed = 1;
            }
        }
        /* BUS spans always run to the mapping end, so the delta is a
         * single interval: shrink newly strips [nb, ob), growth
         * re-admits [ob, nb). (Shrink: nb <= ob; growth: nb >= ob.) */
        had_bus = sysmem_file_bus_span(slot->file_offset, slot->len,
            old_size, &ob, &ob_len);
        has_bus = sysmem_file_bus_span(slot->file_offset, slot->len,
            new_size, &nb, &nb_len);
        (void)ob_len;
        (void)nb_len;
        if (has_bus && (!had_bus || nb < ob)) {
            /* Newly stripped pages: BUS + invalidate paired TLB. */
            lo = slot->base + (nb - slot->file_offset);
            hi = lo + (had_bus ? ob - nb :
                slot->file_offset + slot->len - nb);
            (void)sparc64_space_map_bus(&g->space, lo, hi - lo,
                slot->prot, true);
            sparc64_tlb_invalidate_gva(lo, hi - lo);
            /* S64-R3-1: stripped code pages leave the block cache
             * alongside the TLB (the generation bump below covers
             * sleeping threads' private DBTs). */
            if (g->dbt != NULL) {
                sparc64_dbt_invalidate(g->dbt, lo, hi - lo);
            }
            changed = 1;
        } else if (had_bus && (!has_bus || ob < nb)) {
            /* Re-admitted pages (growth): zero heap pages + invalidate.
             * The guard mirrors the strip leg: run when the old span
             * had BUS coverage that shrank (or vanished). */
            uint64_t re_end = has_bus ? nb :
                slot->file_offset + slot->len;
            uint64_t j0 = (ob - slot->file_offset) / UINT64_C(8192);
            uint64_t j1 = (re_end - slot->file_offset) / UINT64_C(8192);
            uint64_t j;
            lo = slot->base + (ob - slot->file_offset);
            hi = lo + (re_end - ob);
            /* Replace (not merge): the re-admitted span is BUS-backed
             * and merge would keep the BUS backings alive. */
            (void)sparc64_space_replace(&g->space, lo, hi - lo,
                slot->prot);
            sparc64_tlb_invalidate_gva(lo, hi - lo);
            if (g->dbt != NULL) {
                sparc64_dbt_invalidate(g->dbt, lo, hi - lo);
            }
            changed = 1;
            /* RC-U4 #5: re-admitted pages are fresh zero pages, so
             * their materialized chunks reset to the mapping default
             * (a later guest write promotes via note_write). */
            if (j1 > (uint64_t)slot->nchunk) {
                j1 = (uint64_t)slot->nchunk;
            }
            for (j = j0; j < j1; j++) {
                slot->cstate[j] = slot->kind;
            }
        }
    }
    /* S64-R3-1: a truncate that changed bytes or BUS coverage commits
     * a new code generation (this path runs outside the 6-step legs),
     * so threads that slept through it flush before cached execution. */
    if (changed != 0) {
        vm64_code_epoch_bump();
    }
}
