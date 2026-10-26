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
 * The only clobber beyond the result is x5 on 16-byte stores (high
 * half in, byte-swapped out); every other width leaves x5-x8 alone on
 * the hit path. The sequence never touches PSTATE.NZCV and never reads
 * or writes host register x18.
 *
 * Loads (N in {1,2,4,8}): x0 receives the value (sign- or
 * zero-extended to 64 bits). 16-byte loads leave the low half in the
 * caller-chosen dst register and the high half in x4. Stores preserve
 * x0 on every path (the byte-swap lands in x4 after the miss check).
 *
 * Miss-path resume contract (P2): the per-block trampoline resumes
 * with 'br x0' where x0 is the HOST resume address, never the loaded
 * value. The slow path (sparc64_mem_miss over sparc64_mem_slow_step)
 * replays the guest instruction through the reference interpreter, so
 * on resume ctx->r[rd] already carries the loaded value (loads) or
 * the store is already performed (stores). cont_insn_offset must
 * therefore point PAST the caller's register writeback: the hit path
 * falls through the writeback into cont, while the miss path lands on
 * cont with the writeback already applied and must not re-execute it.
 * The fast-path vd register is stale on the miss path and is never
 * consumed there. sparc64_mem_emit_site upholds this by advancing
 * cont past the writeback it emits for loads.
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
 * code offsets (the caller then advances cont past its writeback for
 * loads, per the resume contract above). The final block record is
 * carved from the tail of the same code buffer, so its lifetime is
 * the block's: no malloc, no free, nothing to release on recycle.
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
#include "interp/interp.h"

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
 * every edge in edges[0..n-1] at its stub. blk is a template carrying
 * the site records (n_sites must equal n); the tail copies it into a
 * slot carved from the end of the same code buffer and bakes THAT
 * address (not the template's) into the trampoline, so the record
 * lives and dies with the block. Returns false on buffer overflow or
 * bad arguments. */
bool sparc64_mem_emit_tail(struct sparc64_dbt_buf *b,
    const sparc64_mem_block_t *blk, const size_t *edges, uint32_t n);

/* One inline fast-path site for the integer emitter: plain single-
 * access loads/stores only (LDUW/LDUB/LDUH/LDSW/LDSB/LDSH/LDX and
 * STW/STB/STH/STX with the default big-endian ASI). Twin-word
 * (LDD/STD), alternate-ASI, FSR, and atomic forms return false so the
 * caller falls back to the checked helper path. On success the site
 * is recorded for the block tail (fault_pc is the helper-convention
 * fault address, normally the instruction address; in_delay marks a
 * CTI delay-slot site) and the register writeback is emitted for loads
 * with cont advanced past it per the resume contract above. Uses
 * x0/x1 plus scratch x9-x11 and the x20 TLB base; never x18 and never
 * host NZCV. Returns false with nothing recorded on refusal. */
bool sparc64_mem_emit_site(struct sparc64_dbt_buf *b,
    const sparc64_dec_t *d, uint64_t fault_pc, bool in_delay);

/* Per-block site accumulator: begin resets it (guest_base is the block
 * start for guest_pc_delta), end emits the tail when at least one site
 * was recorded (no-op true when empty). End borrows a heap template
 * only for the copy and frees it before returning. */
void sparc64_mem_block_begin(uint64_t guest_base);
bool sparc64_mem_block_end(struct sparc64_dbt_buf *b,
    const sparc64_mem_ops_t *mem, void *mc);

#endif /* SPARC64RT_DBT_EMIT_MEM_H */
