/*
 * src/os/sysmem_file_remap.c -- registry drop/remap-update legs.
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Split from src/os/guest_run_sysmem_file.c (S64-R4 line discipline)
 * so neither TU exceeds the 900-line limit: this file owns the
 * split-aware excision leg (sysmem_file_drop_map) and the mremap
 * coverage rebase (sysmem_file_remap_update) with the helpers they
 * share (claim_free, slot_release, slice_states). The note/protect/
 * snapshot core stays in src/os/guest_run_sysmem_file.c; shared
 * types and signatures live in src/os/sysmem_file.h. Never maps
 * guest data PROT_EXEC on the host and never touches host
 * register x18.
 */

#define _POSIX_C_SOURCE 200809L

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "os/sysmem_file.h"

/* Claim a free registry slot for a split survivor; grows the table on
 * demand (S64-R3-3) and returns NULL only when growth fails. Callers
 * that reserved up front never see NULL; the munmap drop leg (which
 * cannot fail the syscall) drops that survivor on OOM. */
sysmem_file_range_t *sysmem_file_claim_free(void)
{
    size_t i;
    if (sysmem_file_reserve(1u) != 0) {
        return NULL;
    }
    for (i = 0u; i < sysmem_file_cap; i++) {
        if (!sysmem_files[i].live) {
            return &sysmem_files[i];
        }
    }
    return NULL;
}

/* Release one entry's retained description without touching the
 * slot liveness (shared with the note/drop TU). */
void sysmem_file_slot_release(sysmem_file_range_t *slot)
{
    sysmem_desc_release(&slot->desc);
}

/* Copy one coverage piece's per-chunk states: slices the materialized
 * prefix of the source states, kind-filling the rest (chunks past the
 * 64-chunk bound and any growth tail carry the mapping default). */
void sysmem_file_slice_states(sysmem_file_range_t *dst,
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
    size_t i;
    uint64_t end;
    (void)context;
    if (len == 0u) {
        return;
    }
    end = base + len;
    if (end < base) {
        end = UINT64_C(0xffffffffffffffff);
    }
    for (i = 0u; i < sysmem_file_cap; i++) {
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
            /* Fully covered: reclaim the slot and its retained fd
             * (S64-R3-3/R3-5: unmap reclaims, never leaks). */
            sysmem_file_slot_release(slot);
            slot->live = false;
            continue;
        }
        if (s0 < base && s1 > end) {
            /* Middle excised: the head stays in place, the tail moves
             * to a free slot (or drops when the table is full). The
             * tail slice reads the pre-trim states (saved count).
             * S64-R3-3 REGRESSION: claim_free can realloc the table,
             * so snapshot the entry and re-derive slot afterwards. */
            sysmem_file_range_t orig = *slot;
            sysmem_file_range_t *tail = sysmem_file_claim_free();
            uint8_t onchunk = orig.nchunk;
            uint64_t keep = base - s0;
            uint64_t tn;
            slot = &sysmem_files[i];
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
            /* S64-R4-4: the survivor shares the retained description
             * (no new host descriptor needed to split). */
            tail->desc = orig.desc;
            sysmem_desc_share(tail->desc);
            tail->dev = orig.dev;
            tail->ino = orig.ino;
            tail->file_offset = orig.file_offset + (end - s0);
            tail->base = end;
            tail->len = s1 - end;
            tail->prot = orig.prot;
            tail->kind = orig.kind;
            tn = (s1 - end) / UINT64_C(8192);
            if (tn > (uint64_t)SYSMEM_FILERANGE_CHUNKS) {
                tn = (uint64_t)SYSMEM_FILERANGE_CHUNKS;
            }
            sysmem_file_slice_states(tail, orig.cstate, onchunk,
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
    size_t i;
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
    for (i = 0u; i < sysmem_file_cap; i++) {
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
                /* Shrunken away entirely: reclaim slot + fd. */
                sysmem_file_slot_release(slot);
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
            sysmem_file_desc_t *odesc = slot->desc;
            uint8_t saved[SYSMEM_FILERANGE_CHUNKS];
            sysmem_file_range_t *mid = NULL;
            sysmem_file_range_t *tail = NULL;
            uint64_t k;
            int mid_reuses_slot = (m0 == s0) ? 1 : 0;
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
             * live, never re-claim the same free slot. S64-R3-3
             * REGRESSION: claim_free can realloc the table, so every
             * source field is snapshotted above and slot is
             * re-derived after each claim. */
            if (keep != 0u) {
                if (mid_reuses_slot != 0) {
                    mid = slot;
                } else {
                    mid = sysmem_file_claim_free();
                    slot = &sysmem_files[i];
                }
                if (mid != NULL) {
                    mid->live = true;
                    /* S64-R4-4: the survivor reusing this slot keeps
                     * the retained description; a fresh slot shares
                     * it (refcounted, released on drop). */
                    if (mid_reuses_slot == 0) {
                        mid->desc = odesc;
                        sysmem_desc_share(mid->desc);
                    }
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
                size_t mid_idx = (size_t)-1;
                if (mid != NULL && mid_reuses_slot == 0 && keep != 0u) {
                    mid_idx = (size_t)(mid - sysmem_files);
                }
                tail = sysmem_file_claim_free();
                slot = &sysmem_files[i];
                if (mid_idx != (size_t)-1) {
                    mid = &sysmem_files[mid_idx];
                } else if (mid_reuses_slot != 0 && keep != 0u) {
                    mid = slot;
                }
                if (tail != NULL) {
                    tail->live = true;
                    tail->desc = odesc;
                    sysmem_desc_share(tail->desc);
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
            slot = &sysmem_files[i];
            if (mid_reuses_slot != 0 && keep != 0u) {
                /* Middle reused this slot: already describes the moved
                 * piece; the tail (if any) lives elsewhere. */
            } else if (m0 > s0) {
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
                if (m1 >= s1) {
                    sysmem_file_slot_release(slot);
                    slot->live = false;
                } else {
                    /* Tail claimed above (sharing the retained
                     * description); this slot releases its own
                     * reference either way. */
                    sysmem_file_slot_release(slot);
                    slot->live = false;
                }
            }
        }
    }
}
