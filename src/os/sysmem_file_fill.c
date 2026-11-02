/*
 * src/os/sysmem_file_fill.c — file-backed sysmem populate/growth fills
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Split from src/os/guest_run_sysmem_file.c (S64-R3 line discipline)
 * so neither TU exceeds the 900-line limit: this file owns the
 * Provider-A populate fill (initial mmap) and the mremap growth-tail
 * fill (S64-R3-2) with beyond-EOF BUS classification. The range table
 * core (note/drop/resize/remap-update) stays in
 * src/os/guest_run_sysmem_file.c; shared types live in
 * src/os/sysmem_file.h. Never maps guest data PROT_EXEC on the host
 * and never touches host register x18.
 */

#define _POSIX_C_SOURCE 200809L

#include <sys/stat.h>
#include <unistd.h>

#include "os/sysmem_file.h"


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

/* Worst-case extra registry slots an mremap needs (S64-R3-3): every
 * entry overlapping the old span can leave two survivors (middle +
 * tail), and every entry overlapping the replaced destination span
 * can leave one (drop-split tail). The shell reserves this BEFORE the
 * 6-step prepare, so the update below cannot fail mid-mutation. */
size_t sysmem_file_span_extra(uint64_t old_base, uint64_t old_len,
    uint64_t dest, uint64_t new_len)
{
    uint64_t old_end = old_base + old_len;
    uint64_t new_end = dest + new_len;
    size_t extra = 0u;
    size_t i;
    if (old_len == 0u || new_len == 0u || old_end < old_base ||
        new_end < dest) {
        return 0u;
    }
    for (i = 0u; i < sysmem_file_cap; i++) {
        const sysmem_file_range_t *slot = &sysmem_files[i];
        uint64_t s1;
        if (!slot->live) {
            continue;
        }
        s1 = slot->base + slot->len;
        if (slot->base < old_end && s1 > old_base) {
            extra += 2u;
        }
        if (dest != old_base && slot->base < new_end && s1 > dest) {
            extra += 1u;
        }
    }
    return extra;
}

/* Populate one mremap growth-tail overlap [o0, o1) from an entry's
 * retained description (S64-R3-2): file bytes through the same
 * populate path as the initial mmap fill (so MAP_PRIVATE tails land
 * COW_DIRTY, MAP_SHARED tails SHARED), chunk states patched onto the
 * entry, and full 8 KiB pages beyond the fresh EOF converted to BUS
 * with paired TLB invalidation. 0 on success (including short-EOF),
 * -ENOMEM when the tail pages reject the fill. */
static int sysmem_file_fill_overlap(guest_state_t *g,
    sysmem_file_range_t *slot, uint64_t o0, uint64_t o1)
{
    struct stat st;
    uint64_t fsize;
    uint64_t foff;
    uint64_t len;
    int is_private;
    uint8_t cstate[SYSMEM_FILERANGE_CHUNKS];
    size_t nchunk = 0u;
    uint64_t bus;
    uint64_t bus_len;
    size_t k;
    int frc;
    if (slot->fd < 0 || o1 <= o0) {
        /* No retained description (dup failed at note time): the tail
         * stays zero, exactly like an anonymous extension. */
        return 0;
    }
    if (fstat(slot->fd, &st) != 0 || !S_ISREG(st.st_mode) ||
        st.st_size < 0 ||
        (uint64_t)st.st_size > (uint64_t)INT64_MAX) {
        return 0;
    }
    fsize = (uint64_t)st.st_size;
    foff = slot->file_offset + (o0 - slot->base);
    len = o1 - o0;
    is_private = (slot->kind == (uint8_t)VM64_PAGE_SHARED) ? 0 : 1;
    frc = sysmem_file_fill(g, slot->fd, foff, o0, len, fsize,
        is_private, cstate, sizeof(cstate), &nchunk);
    if (frc == -LOAD_NOMEM) {
        return -12;
    }
    /* Patch the populate result onto the entry's tail chunks (the
     * remap update pre-covered them with kind-default states). */
    for (k = 0u; k < nchunk; k++) {
        uint64_t idx = (o0 - slot->base) / UINT64_C(8192) + k;
        if (idx < (uint64_t)slot->nchunk) {
            slot->cstate[idx] = cstate[k];
        }
    }
    /* Beyond-EOF full pages fault instead of serving stale zeros,
     * mirroring the initial-mmap BUS leg. */
    if (sysmem_file_bus_span(foff, len, fsize, &bus, &bus_len)) {
        uint64_t gbus = o0 + (bus - foff);
        (void)sparc64_space_map_bus(&g->space, gbus, bus_len,
            slot->prot, true);
        sparc64_tlb_invalidate_gva(gbus, bus_len);
        if (g->dbt != NULL) {
            sparc64_dbt_invalidate(g->dbt, gbus, bus_len);
        }
    }
    return 0;
}

/* Populate the mremap growth tail [dest + old_len, dest + new_len)
 * from retained file descriptions (S64-R3-2). Called after the space
 * remap published and the coverage update extended entries over the
 * tail, but before the commit leg: anonymous tails (no covering
 * entry) correctly stay zero. Returns 0, or -ENOMEM when a tail fill
 * is rejected (the shell rolls an in-place extension back). */
int sysmem_file_fill_growth(void *context, uint64_t dest,
    uint64_t old_len, uint64_t new_len)
{
    guest_state_t *g = (guest_state_t *)context;
    uint64_t tail0;
    uint64_t tail1;
    size_t i;
    if (g == NULL || new_len <= old_len) {
        return 0;
    }
    tail0 = dest + old_len;
    tail1 = dest + new_len;
    if (tail1 < tail0) {
        return -22;
    }
    for (i = 0u; i < sysmem_file_cap; i++) {
        sysmem_file_range_t *slot = &sysmem_files[i];
        uint64_t s1;
        uint64_t o0;
        uint64_t o1;
        int rc;
        if (!slot->live) {
            continue;
        }
        s1 = slot->base + slot->len;
        if (slot->base >= tail1 || s1 <= tail0) {
            continue;
        }
        o0 = slot->base > tail0 ? slot->base : tail0;
        o1 = s1 < tail1 ? s1 : tail1;
        rc = sysmem_file_fill_overlap(g, slot, o0, o1);
        if (rc != 0) {
            return rc;
        }
    }
    return 0;
}
