/* src/vm/vm64.h — Provider-A VM substrate contract (Wave U2/U4).
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Shared declarations for the 8 KiB page-state helpers and the
 * 6-step quiescence transactions implemented in src/vm/vm64.c.
 * Consumers (src/vm/vm_file.c, the RC-U2 gate test) include this
 * instead of declaring body-local externs, so the compiler checks
 * signatures (notably vm64_page_state_t* rather than int*).
 */

#ifndef SPARC64RT_VM_VM64_H
#define SPARC64RT_VM_VM64_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Per-8KiB-page states (section 5.1: in-place non-relocating COW). */
typedef enum {
    VM64_PAGE_UNMAPPED = 0,
    VM64_PAGE_ANON = 1,      /* anonymous / zero-fill, writable */
    VM64_PAGE_SHARED = 2,    /* MAP_SHARED file page, write-through */
    VM64_PAGE_COW_CLEAN = 3, /* MAP_PRIVATE file page, not yet dirtied */
    VM64_PAGE_COW_DIRTY = 4  /* MAP_PRIVATE file page, promoted in place */
} vm64_page_state_t;

/* In-place COW promotion of one 8 KiB page split into two 4 KiB
 * translation-granule halves; true if either half transitioned. */
bool vm64_cow_promote_8k(vm64_page_state_t *lower_half,
    vm64_page_state_t *upper_half);
/* True when a write to a CLEAN/DIRTY page may proceed without a
 * copy (DIRTY everywhere, or CLEAN only for shared mappings). */
bool vm64_cow_writable(vm64_page_state_t lower_half,
    vm64_page_state_t upper_half);
/* Upper-half zeroing for a file ending mid-8KiB page: when file_size
 * lies in the lower 4 KiB half of an 8 KiB page and map_end runs into
 * the upper half, returns the [start, len) span to zero. */
bool vm64_eof_upper_half(uint64_t file_size, uint64_t map_end,
    uint64_t *zero_start_out, uint64_t *zero_len_out);

/* 6-step quiescence transactions (section 4.5). */
int vm64_stxn_prepare(void);
long vm64_stxn_host_op(long (*op)(void *), void *op_ctx);
int vm64_stxn_commit(uint64_t changed_base, uint64_t changed_len);
void vm64_stxn_abort(void);
void vm64_stxn_register_self(void);

/* Active worker table (RC-U4 #3): register on worker-thread start
 * (the main thread registers at engine startup), unregister on thread
 * exit; prepare iterates the live slots instead of a hardcoded
 * single-participant slot. All three are idempotent. */
void vm64_worker_register(void);
void vm64_worker_unregister(void);
unsigned vm64_worker_live_count(void);

/* Live Soft-TLB window (section 4.5.2). */
uint64_t vm64_seq_rewind(uint64_t pc, uint64_t seq_start,
    uint64_t host_insn);
void vm64_seq_publish(uint64_t arena_base, uint64_t arena_size);
uint64_t vm64_seq_rewind_live(uint64_t pc);

/* Zero a host span (memset); split out for testability. */
void vm64_zero_span(void *host_addr, size_t len);

#endif /* SPARC64RT_VM_VM64_H */
