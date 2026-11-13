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
 * closes the block with sparc64_mem_emit_tail, which appends one cold
 * stub per site (mov w4, #k; bl common; cache repair; br x0) and the
 * single per-block miss subroutine (mrs/msr nzcv plus x7/x8 save and
 * restore, balanced on both the resume and fault paths) and redirects
 * every recorded miss edge at it. Site records are filled by the
 * caller (guest deltas, widths, flags); the fast emitter fills the
 * three code offsets (the caller then advances cont past its writeback
 * for loads, per the resume contract above). The final block record is
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
#include "dbt/emit_priv.h"

/* ---- translator-local memory/window runtime helpers (Lane P13-5) ----
 * Moved here from dbt/emit_priv.h so the shared header stays under the
 * 900-line discipline: s64_jrt_mem/s64_jrt_win replay through the shared
 * interpreter backend (parity by construction), and e_call_mem /
 * e_call_win emit the faultable BLR sequences used by the integer,
 * fast-window, and FP-memory emitters. */

/* Memory op: packA carries op3 | rd<<8 | rs1<<16 | rs2<<24 | is_imm<<29,
 * raw is the instruction word (trap tval), packB carries the low 32 bits
 * of the sign-extended immediate plus the ASI at bits 32..39 and the
 * regasi flag at bit 40. */
static inline uint32_t s64_jrt_mem(sparc64_ctx_t *ctx,
    const sparc64_mem_ops_t *mem, void *mc, uint64_t pc, uint32_t pack_a,
    uint32_t raw, uint64_t pack_b)
{
    sparc64_dec_t d;
    sparc64_step_result_t r;
    d.raw = raw;
    d.cls = SPARC64_ICLS_ILLEGAL;
    d.op = 3U;
    d.op3 = (uint8_t)(pack_a & 0x3fU);
    d.rd = (uint8_t)((pack_a >> 8) & 31U);
    d.rs1 = (uint8_t)((pack_a >> 16) & 31U);
    d.rs2 = (uint8_t)((pack_a >> 24) & 31U);
    d.cond = 0U;
    d.cc = 0U;
    d.asi = (uint8_t)((pack_b >> 32) & 0xffU);
    d.regasi = (uint8_t)((pack_b >> 40) & 1U);
    d.annul = 0U;
    d.pred = 0U;
    d.is_imm = (uint8_t)((pack_a >> 29) & 1U);
    d.xbit = 0U;
    d.imm = (int64_t)(int32_t)(pack_b & 0xffffffffULL);
    d.disp = 0;
    d.opf = 0U;
    d.uimm = 0U;
    switch (d.op3) {
    case SPARC64_OP3_LDUW:
    case SPARC64_OP3_LDUB:
    case SPARC64_OP3_LDUH:
    case SPARC64_OP3_LDD:
    case SPARC64_OP3_LDSW:
    case SPARC64_OP3_LDSB:
    case SPARC64_OP3_LDSH:
    case SPARC64_OP3_LDX:
    case SPARC64_OP3_LDA:
    case SPARC64_OP3_LDUBA:
    case SPARC64_OP3_LDUHA:
    case SPARC64_OP3_LDDA:
    case SPARC64_OP3_LDSWA:
    case SPARC64_OP3_LDSBA:
    case SPARC64_OP3_LDSHA:
    case SPARC64_OP3_LDXA:
    case SPARC64_OP3_LDFSR:
        d.cls = SPARC64_ICLS_LOAD;
        r = sparc64_exec_load(ctx, mem, mc, pc, &d);
        break;
    case SPARC64_OP3_STW:
    case SPARC64_OP3_STB:
    case SPARC64_OP3_STH:
    case SPARC64_OP3_STD:
    case SPARC64_OP3_STX:
    case SPARC64_OP3_STA:
    case SPARC64_OP3_STBA:
    case SPARC64_OP3_STHA:
    case SPARC64_OP3_STDA:
    case SPARC64_OP3_STXA:
    case SPARC64_OP3_STFSR:
        d.cls = SPARC64_ICLS_STORE;
        r = sparc64_exec_store(ctx, mem, mc, pc, &d);
        break;
    case SPARC64_OP3_LDSTUB:
    case SPARC64_OP3_LDSTUBA:
        d.cls = SPARC64_ICLS_LDSTUB;
        r = sparc64_exec_atomic(ctx, mem, mc, pc, &d);
        break;
    case SPARC64_OP3_SWAP:
    case SPARC64_OP3_SWAPA:
        d.cls = SPARC64_ICLS_SWAP;
        r = sparc64_exec_atomic(ctx, mem, mc, pc, &d);
        break;
    default:
        d.cls = SPARC64_ICLS_ATOMIC;
        r = sparc64_exec_atomic(ctx, mem, mc, pc, &d);
        break;
    }
    if (r.kind == SPARC64_STEP_CONTINUE) {
        return SPARC64_EXIT_NONE;
    }
    return SPARC64_EXIT_UNDEF;
}

/* Window op: rd_save carries rd | save<<8; sum is SAVE/RESTORE operand. */
static inline uint32_t s64_jrt_win(sparc64_ctx_t *ctx,
    const sparc64_mem_ops_t *mem, void *mc, uint64_t sum, uint32_t rd_save,
    uint64_t pc)
{
    sparc64_step_result_t res;
    unsigned rd = rd_save & 31U;
    bool is_save = ((rd_save >> 8) & 1U) != 0U;
    if (is_save) {
        if (!sparc64_win_save(ctx, mem, mc, sum, rd, &res, pc)) {
            return SPARC64_EXIT_UNDEF;
        }
    } else {
        if (!sparc64_win_restore(ctx, mem, mc, sum, rd, &res, pc)) {
            return SPARC64_EXIT_UNDEF;
        }
    }
    return SPARC64_EXIT_NONE;
}

/* Memory/backend call: x0=ctx x1=mem x2=mc x3=pc x4=packA x5=raw
 * x6=packB, then BLR s64_jrt_mem with the UNDEF fault path. */
static inline size_t e_call_mem(sparc64_emit_ctx_t *ec, const sparc64_dec_t *d)
{
    sparc64_dbt_buf_t *b = ec->buf;
    uint32_t pack_a = (d->op3 & 0x3fU) | ((d->rd & 31U) << 8) |
        ((d->rs1 & 31U) << 16) | ((d->rs2 & 31U) << 24) |
        ((d->is_imm & 1U) << 29);
    uint64_t pack_b = ((uint64_t)(uint32_t)d->imm) |
        ((uint64_t)d->asi << 32) |
        ((uint64_t)(d->regasi & 1U) << 40);
    e_arg_ctx(b);
    sb_mov_imm64(b, 1U, (uint64_t)(uintptr_t)ec->mem);
    sb_mov_imm64(b, 2U, (uint64_t)(uintptr_t)ec->mc);
    sb_mov_imm64(b, 3U, ec->pc);
    sb_mov_imm32(b, 4U, pack_a);
    sb_mov_imm32(b, 5U, d->raw);
    sb_mov_imm64(b, 6U, pack_b);
    return e_call_faultable(b, (uint64_t)(uintptr_t)&s64_jrt_mem);
}

/* Window call: x0=ctx x1=mem x2=mc x3=sum x4=rd|save<<8 x5=pc.
 * The SAVE/RESTORE sum arrives in ES0. */
static inline size_t e_call_win(sparc64_emit_ctx_t *ec, unsigned rd,
    bool is_save)
{
    sparc64_dbt_buf_t *b = ec->buf;
    e_arg_ctx(b);
    sb_mov_imm64(b, 1U, (uint64_t)(uintptr_t)ec->mem);
    sb_mov_imm64(b, 2U, (uint64_t)(uintptr_t)ec->mc);
    sb_mov_reg(b, true, 3U, ES0);
    sb_mov_imm32(b, 4U, (rd & 31U) | (is_save ? 0x100U : 0U));
    sb_mov_imm64(b, 5U, ec->pc);
    return e_call_faultable(b, (uint64_t)(uintptr_t)&s64_jrt_win);
}



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
