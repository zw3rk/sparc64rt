/*
 * src/os/sysmem_file.h — file-backed sysmem registry internals (S64-R3)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Shared declarations for the registry TUs: the range table core
 * (src/os/guest_run_sysmem_file.c: note/drop/resize/remap-update) and
 * the populate/growth fills (src/os/sysmem_file_fill.c). The mapping
 * shells (src/os/guest_run_sysmem.c) include this instead of body-local
 * externs so the compiler checks signatures. Not a frozen header.
 */

#ifndef SPARC64RT_OS_SYSMEM_FILE_H
#define SPARC64RT_OS_SYSMEM_FILE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "core/cpu.h"
#include "os/guest_run_priv.h"
#include "os/mem_space.h"
#include "dbt/mem_sites.h"
#include "vm/vm64.h"

/* Per-entry 8 KiB chunk states recorded by the populate fill:
 * VM64_PAGE_COW_CLEAN (MAP_PRIVATE) or VM64_PAGE_SHARED (MAP_SHARED)
 * per chunk, kinds uniform per mapping. Bounded: longer mappings keep
 * the first 64 chunks (512 KiB); the rest still fill correctly, they
 * only lose truncate-time chunk detail. */
#define SYSMEM_FILERANGE_CHUNKS 64u

/* Retained backing description (S64-R4-4): one reference-counted
 * object per mapped inode range. Splits share the pointer instead of
 * duplicating the host descriptor, so splitting never needs a new fd
 * and descriptor exhaustion cannot silently change mapping semantics.
 * The engine serializes mapping syscalls on the big guest lock, so the
 * count needs no atomics. */
typedef struct sysmem_file_desc {
    int fd;
    unsigned refs;
} sysmem_file_desc_t;

typedef struct {
    bool live;
    /* Retained description shared across split survivors (NULL when the
     * mapping was registered without a host fd, e.g. fd -1 in tests).
     * NULL is never a degraded file mapping: note fails instead. */
    sysmem_file_desc_t *desc;
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

extern sysmem_file_range_t *sysmem_files;
extern size_t sysmem_file_cap;

/* Provider-A populate helper (src/vm/vm_file.c); declared here (not
 * int-punned) so both fill TUs share one checked signature. */
extern long vm_file_populate_segment(int host_fd, uint64_t file_offset,
    uint64_t file_size, void *host_addr, size_t seg_len,
    vm64_page_state_t *lower_state, vm64_page_state_t *upper_state,
    uint64_t *bus_base_out, uint64_t *bus_len_out);

/* Beyond-EOF BUS span of a file mapping, in file coordinates. */
bool sysmem_file_bus_span(uint64_t file_offset, uint64_t len,
    uint64_t file_size, uint64_t *bus_out, uint64_t *bus_len_out);

/* Reserve n free slots BEFORE mutating mappings (S64-R3-3); 0 or
 * -ENOMEM with zero mutation. */
int sysmem_file_reserve(size_t n);

/* Live-entry count (diagnostics and tests). */
unsigned sysmem_file_live_count(void);

/* Acquire a retained CLOEXEC duplicate of fd (S64-R4-4): call BEFORE
 * publishing mapping changes so descriptor exhaustion reports failure
 * with zero mutation. Returns the dup'd fd, -1 for fd < 0 (nothing to
 * retain), or a negative errno on failure. */
int sysmem_file_acquire(int fd);

/* Reference-count helpers shared with the remap TU (S64-R4-4): splits
 * share one retained description instead of duplicating the host fd. */
void sysmem_desc_share(sysmem_file_desc_t *desc);
void sysmem_desc_release(sysmem_file_desc_t **desc);

/* Free-slot claim and per-chunk slice helpers shared with the remap
 * TU (split survivors in drop/remap/protect legs). */
sysmem_file_range_t *sysmem_file_claim_free(void);
void sysmem_file_slot_release(sysmem_file_range_t *slot);
void sysmem_file_slice_states(sysmem_file_range_t *dst,
    const uint8_t *src_states, uint8_t src_nchunk, uint64_t src_first,
    uint64_t n_dst);

/* Record one live mapping, taking ownership of an acquired fd (>= 0)
 * or -1 for no descriptor. Returns 0, or a negative errno (live
 * entries are never evicted, so the caller must roll its mapping
 * back). */
int sysmem_file_note_map_owned(void *context, int owned_fd, uint64_t dev,
    uint64_t ino, uint64_t file_offset, uint64_t base, uint64_t len,
    unsigned prot, int is_private, const uint8_t *cstate, size_t nchunk);

/* Record one live mapping (dups fd); 0 or negative errno. */
int sysmem_file_note_map(void *context, int fd, uint64_t dev,
    uint64_t ino, uint64_t file_offset, uint64_t base, uint64_t len,
    unsigned prot, int is_private, const uint8_t *cstate, size_t nchunk);

/* Excise [base, base+len) from every tracked range. */
void sysmem_file_drop_map(void *context, uint64_t base, uint64_t len);

/* Drop every tracked range, closing retained descriptors (execve
 * commit: the old address space is gone, S64-R4-7). */
void sysmem_file_drop_all(void);

/* True when fd names a live retained descriptor (execve CLOEXEC sweep
 * exclusion, S64-R4-7). */
bool sysmem_file_is_retained(int fd);

/* Guest-syscall-layer alias for the retained-fd predicate above, used
 * by the execve CLOEXEC sweep (S64-R4-7). */
static inline bool sparc64_sysmem_is_retained_fd(int fd)
{
    return sysmem_file_is_retained(fd);
}

/* Rebase tracked coverage across mremap. */
void sysmem_file_remap_update(void *context, uint64_t old_base,
    uint64_t old_len, uint64_t dest, uint64_t new_len);

/* Apply a successful mprotect to the registry (S64-R4-6): entries
 * fully inside [base, base+len) take prot, straddlers split so the
 * surviving outside pieces keep their old prot. The caller reserves
 * sysmem_file_protect_extra(base, len) slots first, so no split can
 * fail mid-update. */
void sysmem_file_protect_update(void *context, uint64_t base, uint64_t len,
    unsigned prot);

/* Promote tracked COW_CLEAN chunks overlapping a guest write. */
void sysmem_file_note_write(void *context, uint64_t base, uint64_t len);

/* Truncate/ftruncate resize handling for one (dev, ino). */
void sysmem_file_resize(void *context, uint64_t dev, uint64_t ino,
    uint64_t old_size, uint64_t new_size);

/* Populate len bytes from fd@file_offset at base (mmap fill). */
int sysmem_file_fill(void *context, int fd, uint64_t file_offset,
    uint64_t base, uint64_t len, uint64_t file_size, int is_private,
    uint8_t *cstate_out, size_t cstate_cap, size_t *nchunk_out);

/* Worst-case extra slots an mremap needs (reserve before prepare). */
size_t sysmem_file_span_extra(uint64_t old_base, uint64_t old_len,
    uint64_t dest, uint64_t new_len);

/* Worst-case extra slots a munmap/MAP_FIXED excision needs (one tail per
 * overlapping entry). Shells reserve this before the drop legs so a
 * later claim_free cannot realloc mid-iteration (S64-R3-3). */
size_t sysmem_file_drop_extra(uint64_t base, uint64_t len);

/* Worst-case extra slots an mprotect split needs (two survivors per
 * overlapping entry, S64-R4-6). */
size_t sysmem_file_protect_extra(uint64_t base, uint64_t len);

/* Populate the mremap growth tail before the commit leg. */
int sysmem_file_fill_growth(void *context, uint64_t dest,
    uint64_t old_len, uint64_t new_len);

/* Registry snapshot for transactional rollback (S64-R4-3): copies the
 * table with shared (refcount-bumped) descriptors. 0 on success, -12
 * with zero mutation when the copy cannot be allocated. The caller
 * either discards the snapshot on success or restores it on failure
 * (exactly one of the two must run). */
int sysmem_file_snapshot(sysmem_file_range_t **out_tab, size_t *out_cap);
void sysmem_file_snapshot_discard(sysmem_file_range_t *tab, size_t cap);
void sysmem_file_restore(sysmem_file_range_t *tab, size_t cap);

/* Failure-injection hooks for the R4 transaction tests (S64-R4-10):
 * production callers never arm these. Each count decrements per
 * attempted use; armed uses fail with -ENOMEM (grow/fill) or a failed
 * acquisition (dup) without mutating live state. */
void sysmem_file_test_fail_next_grow(int count);
void sysmem_file_test_fail_next_dup(int count);
void sysmem_file_test_fail_next_fill(int count);

/* 8 KiB round-up shared by the registry TUs (resize + remap legs). */
static inline uint64_t sysmem_align_up_8k(uint64_t v)
{
    if (v > UINT64_C(0xffffffffffffffff) - UINT64_C(8191)) {
        return UINT64_C(0xffffffffffffffff);
    }
    return (v + UINT64_C(8191)) & ~UINT64_C(8191);
}

#endif /* SPARC64RT_OS_SYSMEM_FILE_H */
