/*
 * src/os/sysmem_file.h — file-backed sysmem registry internals (S64-R3)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Shared declarations for the two registry TUs: the range table core
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

typedef struct {
    bool live;
    /* Retained duplicate of the mapped fd (S64-R3-2): mremap growth
     * tails populate from it after the guest closed its descriptor.
     * -1 when the dup failed at note time (tail stays zero). */
    int fd;
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

/* Record one live mapping (dups fd); 0 or negative errno. */
int sysmem_file_note_map(void *context, int fd, uint64_t dev,
    uint64_t ino, uint64_t file_offset, uint64_t base, uint64_t len,
    unsigned prot, int is_private, const uint8_t *cstate, size_t nchunk);

/* Excise [base, base+len) from every tracked range. */
void sysmem_file_drop_map(void *context, uint64_t base, uint64_t len);

/* Rebase tracked coverage across mremap. */
void sysmem_file_remap_update(void *context, uint64_t old_base,
    uint64_t old_len, uint64_t dest, uint64_t new_len);

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

/* Populate the mremap growth tail before the commit leg. */
int sysmem_file_fill_growth(void *context, uint64_t dest,
    uint64_t old_len, uint64_t new_len);

#endif /* SPARC64RT_OS_SYSMEM_FILE_H */
