/*
 * src/dbt/emit_int.h — AArch64 integer emitter interface (Phase 2, L2c)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Lane L2c owns this file (Phase 2 card, SPEC sections 2-3). L2b consumes
 * it; L2b owns the code buffer storage, the dispatcher, block chaining,
 * and the trampoline. See the Phase 2 lane card for the frozen signature.
 *
 * Contract with L2b (dispatcher / block builder):
 * - x19 holds the sparc64_ctx_t pointer on fragment entry (never x18).
 * - Guest registers live in ctx memory (r[32] at offset 0); the emitter
 *   performs no host register allocation for guest state, so emitted code
 *   is safe across helper calls (helpers preserve x19-x28 per AAPCS64).
 * - Guest memory is touched only through the sparc64_mem_ops_t callbacks
 *   carried in the emit context; emitted code never dereferences guest
 *   VA on the host.
 * - ctx->pc/npc are NOT advanced instruction by instruction. Every exit
 *   sequence carries the resume/fault guest PC in x15 and the reason in
 *   w16 (SPARC64_EXIT_*); L2b commits pc/npc from those on block exit.
 * - Normal control transfers and fall-throughs exit with
 *   SPARC64_EXIT_BRANCH. The Tcc syscall trap exits with
 *   SPARC64_EXIT_SYSCALL (guest %g1 already stored to ctx->exit_arg).
 *   Any fault, trap, or unemittable shape exits (or returns false, see
 *   below) with SPARC64_EXIT_UNDEF so L2b replays the instruction with
 *   the reference interpreter, which reproduces the exact trap.
 * - Before each sparc64_emit_int call L2b sets ec->pc (insn address),
 *   ec->fault_pc (guest PC reported on fault exits; normally == pc),
 *   ec->mem/ec->mc (guest memory callbacks), and, for CTI classes
 *   (CALL/JMPL/RETURN/branches), ec->delay to the decoded delay-slot
 *   instruction (or NULL when absent/undecodable).
 * - A CTI with a NULL delay, a CTI/Tcc/privileged/FPU/illegal delay
 *   slot, or any PRIV/FPU/FBR/ILLEGAL instruction makes sparc64_emit_int
 *   return false with zero words emitted (pristine fallback): L2b must
 *   end the block before this instruction and replay it with
 *   sparc64_step. Previously emitted words of the block stay valid.
 * - CALL sets buf->is_call; JMPL/RETURN with rd == %o7 sets
 *   buf->is_call for the RAS push path (L2b may override when linking).
 */

#ifndef SPARC64RT_DBT_EMIT_INT_H
#define SPARC64RT_DBT_EMIT_INT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "interp/interp.h" /* sparc64_dec_t decoded form (classify_word) */
#include "dbt/emit_priv.h" /* sparc64_dbt_buf_t code buffer */

/* Per-instruction emit context (sparc64_emit_ctx_t) lives in
 * dbt/emit_priv.h next to the buffer it borrows. */

/* Emit one translated guest instruction; returns false when the op must
 * fall back to the interpreter (rare/system/privileged). Never emits
 * any read or write of AArch64 x18. */
bool sparc64_emit_int(sparc64_emit_ctx_t *ec, const sparc64_dec_t *d);

#endif /* SPARC64RT_DBT_EMIT_INT_H */
