/*
 * src/os/guest_run_sysmem_file.c — file-backed sysmem range registry
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Split from src/os/guest_run_sysmem.c (RC-U4) so neither TU exceeds
 * the 900-line limit: this file owns the file-backed range registry
 * (note/drop/remap-update/protect-update) and the per-8KiB-chunk
 * COW/SHARED state recording. The Provider-A populate fill and the
 * mremap growth-tail fill live in src/os/sysmem_file_fill.c (S64-R3
 * split); truncate resize lives in src/os/sysmem_file_resize.c
 * (S64-R4 split); guest_run_sysmem.c keeps the
 * mmap/munmap/mprotect/mremap shells and calls in here.
 * Every mapping mutation runs under the caller's 6-step quiescence
 * legs; paired Soft-TLB invalidation stays with the callers that own
 * the live sparc64_dbt_tlb. Guest VA is 8 KiB-granular; this file
 * never maps guest data PROT_EXEC on the host and never touches host
 * register x18.
 */

#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

#include "os/sysmem_file.h"

/* ---- File-backed range registry --------------------------------------
 * Tracks live file-backed sysmem mappings so truncate/ftruncate can
 * convert stripped 8 KiB pages to BUS spans (and regrow them back to
 * zero pages) instead of leaving stale readable mappings behind.
 * Keyed by (dev, ino); updated (not dropped) across mremap so moved
 * mappings keep receiving truncate-driven updates. S64-R3-3: the
 * table is growable (64 slots initial, doubling on demand) and never
 * evicts a live entry: a new mapping without a free slot grows the
 * table, and mapping shells reserve their worst-case slots BEFORE
 * mutating host mappings, so exhaustion reports -ENOMEM with zero
 * mutation instead of silently discarding another mapping's
 * correctness metadata. */
#define SYSMEM_FILERANGE_INIT 64u
/* Entry layout and table storage live in src/os/sysmem_file.h (shared
 * with the fill TU src/os/sysmem_file_fill.c). */
sysmem_file_range_t *sysmem_files;
size_t sysmem_file_cap;

/* Failure-injection hooks for the R4 transaction tests (S64-R4-10).
 * Production callers never arm these; each armed use fails without
 * mutating live state. */
static int sysmem_test_fail_grow;
static int sysmem_test_fail_dup;

void sysmem_file_test_fail_next_grow(int count)
{
    sysmem_test_fail_grow = (count > 0) ? count : 0;
}

void sysmem_file_test_fail_next_dup(int count)
{
    sysmem_test_fail_dup = (count > 0) ? count : 0;
}

/* Growable-table core (S64-R3-3): ensure room, claim, count. The
 * engine serializes mapping syscalls on the big guest lock, so no
 * locking is needed here. */
static int sysmem_file_grow(void)
{
    size_t ncap = (sysmem_file_cap == 0u) ? (size_t)SYSMEM_FILERANGE_INIT :
        sysmem_file_cap * 2u;
    sysmem_file_range_t *ntab;
    size_t i;
    if (sysmem_test_fail_grow > 0) {
        sysmem_test_fail_grow--;
        return -12;
    }
    if (ncap < sysmem_file_cap) {
        return -12;
    }
    ntab = (sysmem_file_range_t *)realloc(sysmem_files,
        ncap * sizeof(*ntab));
    if (ntab == NULL) {
        return -12;
    }
    for (i = sysmem_file_cap; i < ncap; i++) {
        (void)memset(&ntab[i], 0, sizeof(ntab[i]));
        ntab[i].desc = NULL;
    }
    sysmem_files = ntab;
    sysmem_file_cap = ncap;
    return 0;
}

/* Guarantee at least n free slots (S64-R3-3 reservation leg): mapping
 * shells call this BEFORE the 6-step prepare so a later claim cannot
 * fail mid-mutation. 0 on success, -ENOMEM when the table cannot
 * grow (zero mutation in either case). */
int sysmem_file_reserve(size_t n)
{
    size_t free = 0u;
    size_t i;
    if (sysmem_files == NULL || sysmem_file_cap == 0u) {
        if (sysmem_file_grow() != 0) {
            return -12;
        }
    }
    for (i = 0u; i < sysmem_file_cap; i++) {
        if (!sysmem_files[i].live) {
            free++;
        }
    }
    while (free < n) {
        size_t had = sysmem_file_cap;
        if (sysmem_file_grow() != 0) {
            return -12;
        }
        free += sysmem_file_cap - had;
    }
    return 0;
}

/* Live-entry count (diagnostics and the R3 focused test). */
unsigned sysmem_file_live_count(void)
{
    size_t i;
    unsigned n = 0u;
    for (i = 0u; i < sysmem_file_cap; i++) {
        if (sysmem_files[i].live) {
            n++;
        }
    }
    return n;
}

/* Retained-fd duplication with close-on-exec (S64-R3 follow-up #4):
 * without CLOEXEC a guest with ~100 file mappings exhausts the 256
 * soft fd budget and leaks retained fds across exec. F_DUPFD_CLOEXEC
 * is atomic (no dup + SETFD race). S64-R4-4: armed test hooks fail
 * the acquisition with EMFILE instead of duplicating, so descriptor
 * exhaustion is observable and never silent. */
static int sysmem_file_dup_cloexec(int fd)
{
    int nfd;
    if (fd < 0) {
        return -1;
    }
    if (sysmem_test_fail_dup > 0) {
        sysmem_test_fail_dup--;
        errno = EMFILE;
        return -1;
    }
#ifdef F_DUPFD_CLOEXEC
    nfd = fcntl(fd, F_DUPFD_CLOEXEC, 0);
#else
    nfd = dup(fd);
    if (nfd >= 0) {
        (void)fcntl(nfd, F_SETFD, FD_CLOEXEC);
    }
#endif
    return nfd;
}

/* Acquire a retained CLOEXEC duplicate BEFORE publishing mapping
 * changes (S64-R4-4): -1 for fd < 0 (nothing to retain), the dup'd
 * fd, or a negative errno when acquisition fails. */
int sysmem_file_acquire(int fd)
{
    int nfd;
    if (fd < 0) {
        return -1;
    }
    nfd = sysmem_file_dup_cloexec(fd);
    if (nfd < 0) {
        return -(long)errno;
    }
    return nfd;
}

/* Share one retained description across split survivors (S64-R4-4):
 * splits never need a new host descriptor. */
void sysmem_desc_share(sysmem_file_desc_t *desc)
{
    if (desc != NULL) {
        desc->refs++;
    }
}

/* Release one reference; the last close frees the description. */
void sysmem_desc_release(sysmem_file_desc_t **desc)
{
    if (desc == NULL || *desc == NULL) {
        return;
    }
    if ((*desc)->refs > 1U) {
        (*desc)->refs--;
    } else {
        (void)close((*desc)->fd);
        free(*desc);
    }
    *desc = NULL;
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

/* Record one live mapping, taking ownership of a retained fd
 * acquired up front (S64-R4-4). Returns 0, or a negative errno when
 * the table cannot grow or the description cannot be wrapped: live
 * entries are never evicted and a failed acquisition never degrades
 * to anonymous zero-fill, so the caller must roll its mapping back
 * (zero net mutation). */
int sysmem_file_note_map_owned(void *context, int owned_fd, uint64_t dev,
    uint64_t ino, uint64_t file_offset, uint64_t base, uint64_t len,
    unsigned prot, int is_private, const uint8_t *cstate, size_t nchunk)
{
    sysmem_file_range_t *slot;
    sysmem_file_desc_t *desc = NULL;
    size_t n;
    size_t i;
    (void)context;
    if (len == 0u || file_offset > UINT64_C(0xffffffffffffffff) - len) {
        if (owned_fd >= 0) {
            (void)close(owned_fd);
        }
        return -22;
    }
    if (owned_fd >= 0) {
        desc = (sysmem_file_desc_t *)malloc(sizeof(*desc));
        if (desc == NULL) {
            (void)close(owned_fd);
            return -12;
        }
        desc->fd = owned_fd;
        desc->refs = 1U;
    }
    if (sysmem_file_reserve(1u) != 0) {
        if (desc != NULL) {
            (void)close(desc->fd);
            free(desc);
        }
        return -12;
    }
    for (i = 0u; i < sysmem_file_cap; i++) {
        if (!sysmem_files[i].live) {
            break;
        }
    }
    if (i >= sysmem_file_cap) {
        if (desc != NULL) {
            (void)close(desc->fd);
            free(desc);
        }
        return -12;
    }
    slot = &sysmem_files[i];
    slot->live = true;
    slot->desc = desc;
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
    return 0;
}

/* Record one live mapping (S64-R3-2/R3-3): duplicates the fd inline.
 * S64-R4-4: a failed duplication propagates the errno instead of
 * recording a descriptor-less entry that would silently serve zeros
 * from growth tails. */
int sysmem_file_note_map(void *context, int fd, uint64_t dev,
    uint64_t ino, uint64_t file_offset, uint64_t base, uint64_t len,
    unsigned prot, int is_private, const uint8_t *cstate, size_t nchunk)
{
    int owned;
    if (len == 0u || file_offset > UINT64_C(0xffffffffffffffff) - len) {
        return -22;
    }
    owned = sysmem_file_acquire(fd);
    if (owned < 0 && fd >= 0) {
        return owned;
    }
    return sysmem_file_note_map_owned(context, owned, dev, ino,
        file_offset, base, len, prot, is_private, cstate, nchunk);
}

/* Drop every tracked range, closing retained descriptions (S64-R4-7:
 * execve commit replaces the whole address space, so stale coverage
 * must not survive it). */
void sysmem_file_drop_all(void)
{
    size_t i;
    for (i = 0u; i < sysmem_file_cap; i++) {
        if (sysmem_files[i].live) {
            sysmem_file_slot_release(&sysmem_files[i]);
            sysmem_files[i].live = false;
        }
    }
}

/* True when fd names a live retained descriptor (S64-R4-7: the guest
 * CLOEXEC sweep must not close translator-owned descriptors, whose
 * numbers the registry entries still reference). */
bool sysmem_file_is_retained(int fd)
{
    size_t i;
    if (fd < 0) {
        return false;
    }
    for (i = 0u; i < sysmem_file_cap; i++) {
        if (sysmem_files[i].live && sysmem_files[i].desc != NULL &&
            sysmem_files[i].desc->fd == fd) {
            return true;
        }
    }
    return false;
}

/* Worst-case extra slots an mprotect split needs (S64-R4-6): every
 * overlapping entry can leave two survivors (middle + tail) past the
 * head that stays in place. Reserved before the protect legs so
 * claim_free cannot realloc mid-update. */
size_t sysmem_file_protect_extra(uint64_t base, uint64_t len)
{
    uint64_t end = base + len;
    size_t extra = 0u;
    size_t i;
    if (len == 0u) {
        return 0u;
    }
    if (end < base) {
        end = UINT64_C(0xffffffffffffffff);
    }
    for (i = 0u; i < sysmem_file_cap; i++) {
        const sysmem_file_range_t *slot = &sysmem_files[i];
        uint64_t s1;
        if (!slot->live) {
            continue;
        }
        s1 = slot->base + slot->len;
        if (slot->base < end && s1 > base) {
            extra += 2u;
        }
    }
    return extra;
}

/* Apply a successful mprotect to the registry (S64-R4-6): fully
 * covered entries take the new prot; straddlers split so the outside
 * pieces keep their old prot and only the inside piece changes. The
 * shell reserves protect_extra() slots first, so splits below cannot
 * fail; a NULL claim (unreachable after reservation) drops that piece
 * instead of corrupting an address. */
void sysmem_file_protect_update(void *context, uint64_t base, uint64_t len,
    unsigned prot)
{
    size_t i;
    uint64_t end;
    unsigned np = prot & 7u;
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
        sysmem_file_range_t orig;
        sysmem_file_range_t *mid = NULL;
        sysmem_file_range_t *tail = NULL;
        uint64_t s0;
        uint64_t s1;
        uint64_t m0;
        uint64_t m1;
        uint64_t k;
        if (!slot->live) {
            continue;
        }
        s0 = slot->base;
        s1 = slot->base + slot->len;
        if (s0 >= end || s1 <= base) {
            continue;
        }
        m0 = s0 > base ? s0 : base;
        m1 = s1 < end ? s1 : end;
        if (m0 == s0 && m1 == s1) {
            slot->prot = np;
            continue;
        }
        /* Straddler: snapshot (S64-R3-3 REGRESSION: claims can realloc
         * the table, so every source field is snapshotted first). The
         * head [s0, m0) stays in this slot when present, the middle
         * [m0, m1) takes the new prot, the tail [m1, s1) keeps the
         * old prot. */
        orig = *slot;
        if (m0 > s0) {
            /* Head stays: trim the length (the state prefix stays). */
            slot = &sysmem_files[i];
            slot->len = m0 - s0;
            k = (m0 - s0) / UINT64_C(8192);
            if (k > (uint64_t)SYSMEM_FILERANGE_CHUNKS) {
                k = (uint64_t)SYSMEM_FILERANGE_CHUNKS;
            }
            if ((uint64_t)slot->nchunk > k) {
                slot->nchunk = (uint8_t)k;
            }
            mid = sysmem_file_claim_free();
            slot = &sysmem_files[i];
            if (mid != NULL) {
                mid->live = true;
                mid->desc = orig.desc;
                sysmem_desc_share(mid->desc);
                mid->dev = orig.dev;
                mid->ino = orig.ino;
                mid->file_offset = orig.file_offset + (m0 - s0);
                mid->base = m0;
                mid->len = m1 - m0;
                mid->prot = np;
                mid->kind = orig.kind;
                k = (m1 - m0) / UINT64_C(8192);
                if (k > (uint64_t)SYSMEM_FILERANGE_CHUNKS) {
                    k = (uint64_t)SYSMEM_FILERANGE_CHUNKS;
                }
                sysmem_file_slice_states(mid, orig.cstate,
                    orig.nchunk, (m0 - s0) / UINT64_C(8192), k);
            }
        } else {
            /* No head: the middle reuses this slot (shift left). */
            uint64_t cut = (m0 - s0) / UINT64_C(8192);
            uint64_t n;
            slot = &sysmem_files[i];
            mid = slot;
            slot->file_offset = orig.file_offset + (m0 - s0);
            slot->base = m0;
            slot->len = m1 - m0;
            slot->prot = np;
            if (cut >= (uint64_t)orig.nchunk) {
                slot->nchunk = 0u;
            } else {
                n = (uint64_t)orig.nchunk - cut;
                for (k = 0u; k < n; k++) {
                    slot->cstate[k] = orig.cstate[cut + k];
                }
                slot->nchunk = (uint8_t)n;
            }
        }
        if (m1 < s1) {
            tail = sysmem_file_claim_free();
            slot = &sysmem_files[i];
            if (tail != NULL) {
                tail->live = true;
                tail->desc = orig.desc;
                sysmem_desc_share(tail->desc);
                tail->dev = orig.dev;
                tail->ino = orig.ino;
                tail->file_offset = orig.file_offset + (m1 - s0);
                tail->base = m1;
                tail->len = s1 - m1;
                tail->prot = orig.prot;
                tail->kind = orig.kind;
                k = (s1 - m1) / UINT64_C(8192);
                if (k > (uint64_t)SYSMEM_FILERANGE_CHUNKS) {
                    k = (uint64_t)SYSMEM_FILERANGE_CHUNKS;
                }
                sysmem_file_slice_states(tail, orig.cstate,
                    orig.nchunk, (m1 - s0) / UINT64_C(8192), k);
            }
        }
    }
}


/* Promote every tracked COW_CLEAN chunk overlapping [base, base+len)
 * to COW_DIRTY (RC-U4 #5): the runtime guest-write paths call this
 * after a successful write so the per-chunk registry states mirror the
 * substrate's private_cow promotion (write_prepared_bytes) instead of
 * going stale. SHARED chunks never transition. Chunks past the
 * 64-chunk materialized bound keep their implicit kind default. */
void sysmem_file_note_write(void *context, uint64_t base, uint64_t len)
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

/* Registry snapshot for transactional rollback (S64-R4-3): copies the
 * table with shared (refcount-bumped) descriptors. 0 on success, -12
 * with zero mutation when the copy cannot be allocated. The caller
 * runs exactly one of discard (success) or restore (failure). */
int sysmem_file_snapshot(sysmem_file_range_t **out_tab, size_t *out_cap)
{
    sysmem_file_range_t *tab;
    size_t i;
    if (out_tab == NULL || out_cap == NULL) {
        return -22;
    }
    *out_tab = NULL;
    *out_cap = 0u;
    if (sysmem_files == NULL || sysmem_file_cap == 0u) {
        return 0;
    }
    tab = (sysmem_file_range_t *)malloc(sysmem_file_cap * sizeof(*tab));
    if (tab == NULL) {
        return -12;
    }
    (void)memcpy(tab, sysmem_files, sysmem_file_cap * sizeof(*tab));
    for (i = 0u; i < sysmem_file_cap; i++) {
        sysmem_desc_share(tab[i].desc);
    }
    *out_tab = tab;
    *out_cap = sysmem_file_cap;
    return 0;
}

/* Drop a snapshot taken for a successful operation (releases the
 * extra descriptor references). */
void sysmem_file_snapshot_discard(sysmem_file_range_t *tab, size_t cap)
{
    size_t i;
    if (tab == NULL) {
        return;
    }
    for (i = 0u; i < cap; i++) {
        sysmem_desc_release(&tab[i].desc);
    }
    free(tab);
}

/* Roll back to a snapshot after a failed operation (S64-R4-3):
 * releases every descriptor the failed legs acquired or shared and
 * reinstalls the snapshot (ownership transfers to the table). */
void sysmem_file_restore(sysmem_file_range_t *tab, size_t cap)
{
    size_t i;
    for (i = 0u; i < sysmem_file_cap; i++) {
        if (sysmem_files[i].live) {
            sysmem_file_slot_release(&sysmem_files[i]);
        }
    }
    free(sysmem_files);
    sysmem_files = tab;
    sysmem_file_cap = cap;
}
