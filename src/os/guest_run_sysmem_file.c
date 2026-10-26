/*
 * src/os/guest_run_sysmem_file.c — file-backed sysmem range registry
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Split from src/os/guest_run_sysmem.c (RC-U4) so neither TU exceeds
 * the 900-line limit: this file owns the file-backed range registry
 * (note/drop/resize/remap-update), the Provider-A populate fill, and
 * the per-8KiB-chunk COW/SHARED state recording. guest_run_sysmem.c
 * keeps the mmap/munmap/mprotect/mremap shells and calls in here.
 * Every mapping mutation runs under the caller's 6-step quiescence
 * legs; paired Soft-TLB invalidation stays with the callers that own
 * the live sparc64_dbt_tlb. Guest VA is 8 KiB-granular; this file
 * never maps guest data PROT_EXEC on the host and never touches host
 * register x18.
 */

#define _POSIX_C_SOURCE 200809L

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "core/cpu.h"
#include "os/guest_run_priv.h"
#include "os/mem_space.h"
#include "dbt/mem_sites.h"
#include "vm/vm64.h"

/* Provider-A populate helper (src/vm/vm_file.c); local extern, no
 * header exists for it, matching the syscalls_min.c precedent. Short
 * reads at EOF leave the tail zero-filled by the callee. */
extern long vm_file_populate_segment(int host_fd, uint64_t file_offset,
    uint64_t file_size, void *host_addr, size_t seg_len,
    vm64_page_state_t *lower_state, vm64_page_state_t *upper_state,
    uint64_t *bus_base_out, uint64_t *bus_len_out);

/* ---- File-backed range registry --------------------------------------
 * Tracks live file-backed sysmem mappings so truncate/ftruncate can
 * convert stripped 8 KiB pages to BUS spans (and regrow them back to
 * zero pages) instead of leaving stale readable mappings behind.
 * Keyed by (dev, ino); updated (not dropped) across mremap so moved
 * mappings keep receiving truncate-driven updates. Ring of 64:
 * overflow evicts oldest, degrading to pre-registry behavior
 * (stale readable bytes) for the evicted range only. */
#define SYSMEM_FILERANGE_SLOTS 64u
/* Per-entry 8 KiB chunk states recorded by the populate fill:
 * VM64_PAGE_COW_CLEAN (MAP_PRIVATE) or VM64_PAGE_SHARED (MAP_SHARED)
 * per chunk, kinds uniform per mapping. Bounded: longer mappings keep
 * the first 64 chunks (512 KiB); the rest still fill correctly, they
 * only lose truncate-time chunk detail. */
#define SYSMEM_FILERANGE_CHUNKS 64u
typedef struct {
    bool live;
    uint64_t dev;
    uint64_t ino;
    uint64_t file_offset;
    uint64_t base;
    uint64_t len;
    unsigned prot;
    uint8_t kind;
    uint8_t nchunk;
    uint8_t cstate[SYSMEM_FILERANGE_CHUNKS];
} sysmem_file_range_t;
static sysmem_file_range_t sysmem_files[SYSMEM_FILERANGE_SLOTS];
static unsigned sysmem_file_next;

static uint64_t sysmem_align_up_8k(uint64_t v)
{
    if (v > UINT64_C(0xffffffffffffffff) - UINT64_C(8191)) {
        return UINT64_C(0xffffffffffffffff);
    }
    return (v + UINT64_C(8191)) & ~UINT64_C(8191);
}

/* Beyond-EOF BUS span of a file mapping, in file coordinates: full 8 KiB
 * pages of [file_offset, file_offset + len) lying entirely at/after
 * file_size. Partial tail pages read zero and stay mapped. Non-static
 * so the mmap shell can convert the span after the fill. */
bool sysmem_file_bus_span(uint64_t file_offset, uint64_t len,
    uint64_t file_size, uint64_t *bus_out, uint64_t *bus_len_out)
{
    uint64_t bus;
    uint64_t end = file_offset + len;
    if (len == 0u || end < file_offset) {
        return false;
    }
    bus = sysmem_align_up_8k(file_size);
    if (bus < file_offset) {
        bus = file_offset;
    }
    if (bus >= end) {
        return false;
    }
    if (bus_out != NULL) {
        *bus_out = bus;
    }
    if (bus_len_out != NULL) {
        *bus_len_out = end - bus;
    }
    return true;
}

void sysmem_file_note_map(void *context, uint64_t dev, uint64_t ino,
    uint64_t file_offset, uint64_t base, uint64_t len, unsigned prot,
    int is_private, const uint8_t *cstate, size_t nchunk)
{
    sysmem_file_range_t *slot;
    size_t n;
    size_t i;
    (void)context;
    if (len == 0u || file_offset > UINT64_C(0xffffffffffffffff) - len) {
        return;
    }
    slot = &sysmem_files[sysmem_file_next % SYSMEM_FILERANGE_SLOTS];
    sysmem_file_next++;
    slot->live = true;
    slot->dev = dev;
    slot->ino = ino;
    slot->file_offset = file_offset;
    slot->base = base;
    slot->len = len;
    slot->prot = prot & 7u;
    slot->kind = (is_private != 0) ? (uint8_t)VM64_PAGE_COW_CLEAN :
        (uint8_t)VM64_PAGE_SHARED;
    n = nchunk < (size_t)SYSMEM_FILERANGE_CHUNKS ? nchunk :
        (size_t)SYSMEM_FILERANGE_CHUNKS;
    slot->nchunk = (uint8_t)n;
    for (i = 0u; i < n; i++) {
        /* A NULL chunk vector means uniform kind-default coverage. */
        slot->cstate[i] = (cstate != NULL) ? cstate[i] : slot->kind;
    }
    for (; i < (size_t)SYSMEM_FILERANGE_CHUNKS; i++) {
        slot->cstate[i] = slot->kind;
    }
}

/* Claim a free registry slot for a split survivor; NULL when the
 * table is full (the caller then drops that survivor, degrading to
 * pre-registry behavior for its range only). */
static sysmem_file_range_t *sysmem_file_claim_free(void)
{
    unsigned i;
    for (i = 0; i < SYSMEM_FILERANGE_SLOTS; i++) {
        if (!sysmem_files[i].live) {
            return &sysmem_files[i];
        }
    }
    return NULL;
}

/* Copy one coverage piece's per-chunk states: slices the materialized
 * prefix of the source states, kind-filling the rest (chunks past the
 * 64-chunk bound and any growth tail carry the mapping default). */
static void sysmem_file_slice_states(sysmem_file_range_t *dst,
    const uint8_t *src_states, uint8_t src_nchunk, uint64_t src_first,
    uint64_t n_dst)
{
    uint64_t j;
    for (j = 0u; j < n_dst; j++) {
        if (src_first + j < (uint64_t)src_nchunk) {
            dst->cstate[j] = src_states[src_first + j];
        } else {
            dst->cstate[j] = dst->kind;
        }
    }
    dst->nchunk = (uint8_t)n_dst;
}

/* Excise [base, base + len) from every tracked range (RC-U4 #4): fully
 * covered entries drop; straddlers keep their surviving head and/or
 * tail (the tail claims a free slot, else it drops). All bounds are
 * 8 KiB-aligned by the mmap/munmap/mremap shells, so chunk indices
 * divide exactly. TLB invalidation stays with the callers. */
void sysmem_file_drop_map(void *context, uint64_t base, uint64_t len)
{
    unsigned i;
    uint64_t end;
    (void)context;
    if (len == 0u) {
        return;
    }
    end = base + len;
    if (end < base) {
        end = UINT64_C(0xffffffffffffffff);
    }
    for (i = 0; i < SYSMEM_FILERANGE_SLOTS; i++) {
        sysmem_file_range_t *slot = &sysmem_files[i];
        uint64_t s0;
        uint64_t s1;
        if (!slot->live) {
            continue;
        }
        s0 = slot->base;
        s1 = slot->base + slot->len;
        if (s0 >= end || s1 <= base) {
            continue;
        }
        if (base <= s0 && s1 <= end) {
            slot->live = false;
            continue;
        }
        if (s0 < base && s1 > end) {
            /* Middle excised: the head stays in place, the tail moves
             * to a free slot (or drops when the table is full). The
             * tail slice reads the pre-trim states (saved count). */
            sysmem_file_range_t *tail = sysmem_file_claim_free();
            uint8_t onchunk = slot->nchunk;
            uint64_t keep = base - s0;
            uint64_t tn;
            slot->len = keep;
            tn = keep / UINT64_C(8192);
            if (tn > (uint64_t)SYSMEM_FILERANGE_CHUNKS) {
                tn = (uint64_t)SYSMEM_FILERANGE_CHUNKS;
            }
            if ((uint64_t)onchunk > tn) {
                slot->nchunk = (uint8_t)tn;
            }
            if (tail == NULL) {
                continue;
            }
            tail->live = true;
            tail->dev = slot->dev;
            tail->ino = slot->ino;
            tail->file_offset = slot->file_offset + (end - s0);
            tail->base = end;
            tail->len = s1 - end;
            tail->prot = slot->prot;
            tail->kind = slot->kind;
            tn = (s1 - end) / UINT64_C(8192);
            if (tn > (uint64_t)SYSMEM_FILERANGE_CHUNKS) {
                tn = (uint64_t)SYSMEM_FILERANGE_CHUNKS;
            }
            sysmem_file_slice_states(tail, slot->cstate, onchunk,
                (end - s0) / UINT64_C(8192), tn);
            continue;
        }
        if (s0 < base) {
            /* Tail excised: trim the length (the state prefix stays). */
            uint64_t tn = (base - s0) / UINT64_C(8192);
            slot->len = base - s0;
            if (tn > (uint64_t)SYSMEM_FILERANGE_CHUNKS) {
                tn = (uint64_t)SYSMEM_FILERANGE_CHUNKS;
            }
            if ((uint64_t)slot->nchunk > tn) {
                slot->nchunk = (uint8_t)tn;
            }
            continue;
        }
        /* Head excised: shift the base, file offset, and states left in
         * place (no free slot needed for the survivor). */
        {
            uint64_t cut = (end - s0) / UINT64_C(8192);
            uint64_t k;
            slot->file_offset += end - s0;
            slot->base = end;
            slot->len = s1 - end;
            if (cut >= (uint64_t)slot->nchunk) {
                slot->nchunk = 0u;
            } else {
                uint64_t keep = (uint64_t)slot->nchunk - cut;
                for (k = 0u; k < keep; k++) {
                    slot->cstate[k] = slot->cstate[cut + k];
                }
                slot->nchunk = (uint8_t)keep;
            }
        }
    }
}

/* Resize a file all live mappings observe: shrink converts stripped
 * full 8 KiB pages to BUS spans, zero-fills the surviving partial-page
 * tail [new_size, min(old_size, 8 KiB page end)) in place, and growth
 * restores previously-bused pages as zero heap pages. All three legs
 * invalidate paired TLB coverage. */
void sysmem_file_resize(void *context, uint64_t dev, uint64_t ino,
    uint64_t old_size, uint64_t new_size)
{
    guest_state_t *g = (guest_state_t *)context;
    unsigned i;
    if (g == NULL || old_size == new_size) {
        return;
    }
    for (i = 0; i < SYSMEM_FILERANGE_SLOTS; i++) {
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
}

/* Move (or shrink/extend in place) the tracked coverage across mremap
 * (RC-U4 #4): entries fully inside the old span rebase to the
 * destination (trimmed past a shrunken new length, grown with
 * kind-default chunks when the piece abuts the span end); straddlers
 * keep their unmoved head/tail and move only the middle piece (extra
 * survivors claim free slots, else they drop); replaced destination
 * spans excise via the split-aware drop above. Growth covers fresh
 * zero pages whether moved or in place. Degraded ranges lose truncate
 * tracking only, never corrupt an address. Paired TLB invalidation
 * stays with the mremap shell. */
void sysmem_file_remap_update(void *context, uint64_t old_base,
    uint64_t old_len, uint64_t dest, uint64_t new_len)
{
    unsigned i;
    uint64_t old_end;
    (void)context;
    if (old_len == 0u || new_len == 0u) {
        return;
    }
    old_end = old_base + old_len;
    if (old_end < old_base) {
        return;
    }
    /* The destination span is replaced: excise anything tracked there.
     * In-place hangs onto its entries (the move loop below owns them). */
    if (dest != old_base) {
        sysmem_file_drop_map(context, dest, new_len);
    }
    for (i = 0; i < SYSMEM_FILERANGE_SLOTS; i++) {
        sysmem_file_range_t *slot = &sysmem_files[i];
        uint64_t s0;
        uint64_t s1;
        uint64_t m0;
        uint64_t m1;
        if (!slot->live) {
            continue;
        }
        s0 = slot->base;
        s1 = slot->base + slot->len;
        if (s0 >= old_end || s1 <= old_base) {
            continue;
        }
        m0 = s0 > old_base ? s0 : old_base;
        m1 = s1 < old_end ? s1 : old_end;
        if (m0 == s0 && m1 == s1) {
            /* Fully inside: rebase the whole entry. */
            uint64_t off = s0 - old_base;
            uint64_t keep = slot->len;
            uint64_t k;
            if (off >= new_len) {
                slot->live = false;
                continue;
            }
            if (keep > new_len - off) {
                keep = new_len - off;
            } else if (m1 == old_end && keep < new_len - off) {
                /* Abuts the span end: cover the growth tail (fresh
                 * zero pages, same file bytes ahead) with
                 * kind-default chunks. */
                keep = new_len - off;
            }
            slot->base = dest + off;
            slot->len = keep;
            k = (keep + UINT64_C(8191)) / UINT64_C(8192);
            if (k > (uint64_t)SYSMEM_FILERANGE_CHUNKS) {
                k = (uint64_t)SYSMEM_FILERANGE_CHUNKS;
            }
            if ((uint64_t)slot->nchunk > k) {
                slot->nchunk = (uint8_t)k;
            }
            while ((uint64_t)slot->nchunk < k) {
                slot->cstate[slot->nchunk] = slot->kind;
                slot->nchunk++;
            }
            continue;
        }
        /* Straddles the moved span: the head [s0, m0) stays in this
         * slot, the middle [m0, m1) moves, the tail [m1, s1) stays.
         * The middle reuses this slot when there is no head (nothing
         * unmoved below it); otherwise it claims a free slot, as does
         * the tail. Unplaceable pieces drop. */
        {
            uint64_t moff = m0 - old_base;
            uint64_t keep = m1 - m0;
            uint8_t onchunk = slot->nchunk;
            uint8_t saved_kind = slot->kind;
            uint64_t ofo = slot->file_offset;
            unsigned oprot = slot->prot;
            uint64_t dev = slot->dev;
            uint64_t ino = slot->ino;
            uint8_t saved[SYSMEM_FILERANGE_CHUNKS];
            sysmem_file_range_t *mid = NULL;
            sysmem_file_range_t *tail = NULL;
            uint64_t k;
            (void)memcpy(saved, slot->cstate, sizeof(saved));
            if (moff < new_len) {
                if (keep > new_len - moff) {
                    keep = new_len - moff;
                } else if (m1 == old_end && keep < new_len - moff) {
                    keep = new_len - moff;
                }
            } else {
                keep = 0u;
            }
            /* Claim and install eagerly (in middle, tail, head
             * order): a later claim must see the earlier survivor as
             * live, never re-claim the same free slot. */
            if (keep != 0u) {
                if (m0 == s0) {
                    mid = slot;
                } else {
                    mid = sysmem_file_claim_free();
                }
                if (mid != NULL) {
                    mid->live = true;
                    mid->dev = dev;
                    mid->ino = ino;
                    mid->file_offset = ofo + (m0 - s0);
                    mid->base = dest + moff;
                    mid->len = keep;
                    mid->prot = oprot;
                    mid->kind = saved_kind;
                    k = keep / UINT64_C(8192);
                    if (k > (uint64_t)SYSMEM_FILERANGE_CHUNKS) {
                        k = (uint64_t)SYSMEM_FILERANGE_CHUNKS;
                    }
                    sysmem_file_slice_states(mid, saved, onchunk,
                        (m0 - s0) / UINT64_C(8192), k);
                }
            }
            if (m1 < s1) {
                tail = sysmem_file_claim_free();
                if (tail != NULL) {
                    tail->live = true;
                    tail->dev = dev;
                    tail->ino = ino;
                    tail->file_offset = ofo + (m1 - s0);
                    tail->base = m1;
                    tail->len = s1 - m1;
                    tail->prot = oprot;
                    tail->kind = saved_kind;
                    k = (s1 - m1) / UINT64_C(8192);
                    if (k > (uint64_t)SYSMEM_FILERANGE_CHUNKS) {
                        k = (uint64_t)SYSMEM_FILERANGE_CHUNKS;
                    }
                    sysmem_file_slice_states(tail, saved, onchunk,
                        (m1 - s0) / UINT64_C(8192), k);
                }
            }
            if (m0 > s0) {
                /* The head stays in this slot: trim the length (the
                 * state prefix stays valid). */
                slot->live = true;
                slot->dev = dev;
                slot->ino = ino;
                slot->len = m0 - s0;
                k = (m0 - s0) / UINT64_C(8192);
                if (k > (uint64_t)SYSMEM_FILERANGE_CHUNKS) {
                    k = (uint64_t)SYSMEM_FILERANGE_CHUNKS;
                }
                slot->nchunk = onchunk > (uint8_t)k ? (uint8_t)k :
                    onchunk;
            } else if (keep == 0u) {
                /* No head and no moved survivor: this slot's whole
                 * span is consumed (any tail lives in its own slot,
                 * and a fully covered entry simply drops). */
                slot->live = false;
            }
        }
    }
}

/* Populate len bytes from fd@file_offset into guest space at base via
 * the Provider-A helper (RC-U4 #5): each 8 KiB chunk goes through
 * vm_file_populate_segment into a bounded 8 KiB stack staging buffer
 * (fresh-size aware, so the [st_size, 8 KiB) tail and the upper-half
 * materialization span read zero), then into the guest pages. Short
 * reads at EOF keep the mapping with a zero tail and report LOAD_IO,
 * exactly like the old pread loop; LOAD_NOMEM rolls the span back.
 * Per-chunk post-populate state lands in cstate_out (up to
 * cstate_cap entries, count in nchunk_out) for the caller to file
 * with the range-tracking entry: COW_DIRTY for a materialized private
 * copy, SHARED for shared, CLEAN when the chunk served no file bytes. */
/* Promote every tracked COW_CLEAN chunk overlapping [base, base+len)
 * to COW_DIRTY (RC-U4 #5): the runtime guest-write paths call this
 * after a successful write so the per-chunk registry states mirror the
 * substrate's private_cow promotion (write_prepared_bytes) instead of
 * going stale. SHARED chunks never transition. Chunks past the
 * 64-chunk materialized bound keep their implicit kind default. */
void sysmem_file_note_write(void *context, uint64_t base, uint64_t len)
{
    unsigned i;
    uint64_t end;
    (void)context;
    if (len == 0u) {
        return;
    }
    end = base + len;
    if (end < base) {
        end = UINT64_C(0xffffffffffffffff);
    }
    for (i = 0; i < SYSMEM_FILERANGE_SLOTS; i++) {
        sysmem_file_range_t *slot = &sysmem_files[i];
        uint64_t s1;
        uint64_t o0;
        uint64_t o1;
        uint64_t c0;
        uint64_t c1;
        uint64_t c;
        if (!slot->live || slot->kind != (uint8_t)VM64_PAGE_COW_CLEAN) {
            continue;
        }
        s1 = slot->base + slot->len;
        if (slot->base >= end || s1 <= base) {
            continue;
        }
        o0 = slot->base > base ? slot->base : base;
        o1 = s1 < end ? s1 : end;
        c0 = (o0 - slot->base) / UINT64_C(8192);
        c1 = (o1 - 1u - slot->base) / UINT64_C(8192) + 1u;
        if (c1 > (uint64_t)slot->nchunk) {
            c1 = (uint64_t)slot->nchunk;
        }
        for (c = c0; c < c1; c++) {
            if (slot->cstate[c] == (uint8_t)VM64_PAGE_COW_CLEAN) {
                slot->cstate[c] = (uint8_t)VM64_PAGE_COW_DIRTY;
            }
        }
    }
}

int sysmem_file_fill(void *context, int fd, uint64_t file_offset,
    uint64_t base, uint64_t len, uint64_t file_size, int is_private,
    uint8_t *cstate_out, size_t cstate_cap, size_t *nchunk_out)
{
    guest_state_t *g = (guest_state_t *)context;
    uint64_t done = 0u;
    size_t ncs = 0u;
    uint8_t kind;
    uint8_t stage[GUEST_PAGE_SIZE];
    if (g == NULL || len == 0u) {
        return (len == 0u) ? LOAD_OK : -LOAD_NOMEM;
    }
    kind = (is_private != 0) ? (uint8_t)VM64_PAGE_COW_CLEAN :
        (uint8_t)VM64_PAGE_SHARED;
    while (done < len) {
        uint64_t want = len - done;
        long got;
        /* Real per-chunk states (RC-U4 #5): the populate call promotes
         * the pair in place for private mappings with file bytes, so
         * the recorded state is the populate result (COW_DIRTY after
         * materializing the private copy, SHARED untouched, CLEAN
         * when the chunk served no file bytes). */
        vm64_page_state_t lo = (vm64_page_state_t)kind;
        vm64_page_state_t hi = (vm64_page_state_t)kind;
        if (want > (uint64_t)sizeof(stage)) {
            want = (uint64_t)sizeof(stage);
        }
        got = vm_file_populate_segment(fd, file_offset + done,
            file_size, stage, (size_t)want, &lo, &hi, NULL, NULL);
        if (got < 0L) {
            if (nchunk_out != NULL) {
                *nchunk_out = ncs;
            }
            /* Host error or a file that shrank under the caller: keep
             * the mapping with a zero tail, like a short read. */
            return -LOAD_IO;
        }
        if (ncs < cstate_cap && cstate_out != NULL) {
            /* The populate result: lo and hi promote as one unit, so
             * lo carries the chunk (DIRTY for a materialized private
             * copy, SHARED for shared, CLEAN when no bytes served). */
            cstate_out[ncs] = (uint8_t)lo;
            ncs++;
        }
        if (!sparc64_space_write_initial(&g->space, base + done, stage,
                (size_t)want)) {
            if (nchunk_out != NULL) {
                *nchunk_out = ncs;
            }
            return -LOAD_NOMEM;
        }
        /* Advance by served bytes (not the staged span): a short
         * final chunk then reports LOAD_IO below, as documented. */
        done += (uint64_t)got;
        if ((uint64_t)got < want) {
            /* Short (EOF): the tail is already zeroed by the populate
             * above; keep the mapping. */
            break;
        }
    }
    if (nchunk_out != NULL) {
        *nchunk_out = ncs;
    }
    return (done < len) ? -LOAD_IO : LOAD_OK;
}
