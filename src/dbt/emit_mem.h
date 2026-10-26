/*
 * src/dbt/emit_mem.h — 7-instruction BE Soft-TLB emitter API (Lane M3)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Emits the UNIFICATION-PLAN Rev 4 section 4.3 fast path for SPARC64
 * (big-endian) guests. Entry convention, established by the caller:
 * x1 holds the guest effective address; for stores x0 holds the value
 * (for 16-byte stores x5 holds the high half); x5-x8 are dead scratch.
 * The sequence never touches PSTATE.NZCV and never reads or writes
 * host register x18.
 *
 * Loads (N in {1,2,4,8}): x0 receives the value (sign- or
 * zero-extended to 64 bits). 16-byte loads leave the low half in the
 * caller-chosen dst register and the high half in x4. Stores preserve
 * x0 on every path (the byte-swap lands in x4 after the miss check).
 *
 * Atomics (LDSTUB/SWAP/CASA/CASXA) have no inline form: the caller
 * emits an unconditional edge to the per-site stub and the C slow path
 * performs the __atomic operation through the interpreter.
 *
 * Block layout: the caller emits one fast path per site inline, then
 * closes the block with sparc64_mem_emit_tail, which appends the
 * 2-instruction stubs (mov w4, #k; b common) and the single per-block
 * miss trampoline (mrs x5, nzcv ... msr nzcv, x5) and redirects every
 * recorded miss edge at it. Site records are filled by the caller
 * (guest deltas, widths, flags); the fast emitter fills the three
 * code offsets.
 *
 * AOT note: the tail bakes the C-side block-record address and the
 * slow-path helper address as immediates. The AOT writer lane must
 * relocate those two words per load base; the site table itself is
 * position-independent.
 */

#ifndef SPARC64RT_DBT_EMIT_MEM_H
#define SPARC64RT_DBT_EMIT_MEM_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "dbt/mem_sites.h"

/* Code buffer owned by the block builder (defined in emit_priv.h). */
struct sparc64_dbt_buf;

/* Upper bound on memory sites per block (at most one per guest insn). */
#define SPARC64_DBT_MAX_SITES_PER_BLOCK 64u

/* Emit the 7-instruction big-endian fast path for one scalar access.
 * is_store selects ldp x3,x2 / str vs ldp x2,x3 / ldr; width is
 * 1, 2, 4, 8, or 16; is_signed selects the sign-extending load form
 * (ignored for stores and width 8/16). vd is the load destination
 * (ignored for stores, where x0 is the value). site receives the
 * seq_start/host_insn/cont code offsets. Returns the miss-edge patch
 * index to hand to sparc64_mem_emit_tail, or (size_t)-1 on refusal
 * (bad width, buffer overflow). */
size_t sparc64_mem_emit_fast(struct sparc64_dbt_buf *b, bool is_store,
    unsigned width, bool is_signed, unsigned vd,
    sparc64_mem_site_t *site);

/* Emit the 1-word unconditional miss edge for an atomic site. Returns
 * the branch patch index for the tail, or (size_t)-1 on overflow. */
size_t sparc64_mem_emit_atomic_edge(struct sparc64_dbt_buf *b);

/* Append per-site stubs plus the shared miss trampoline and redirect
 * every edge in edges[0..n-1] at its stub. blk carries the site
 * records (n_sites must equal n) and receives no mutations here; the
 * baked block address is read from blk at emit time. Returns false on
 * buffer overflow or bad arguments. */
bool sparc64_mem_emit_tail(struct sparc64_dbt_buf *b,
    const sparc64_mem_block_t *blk, const size_t *edges, uint32_t n);

#endif /* SPARC64RT_DBT_EMIT_MEM_H */
