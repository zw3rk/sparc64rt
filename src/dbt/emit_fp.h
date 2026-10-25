/*
 * src/dbt/emit_fp.h — AArch64 FP/NEON emitter interface (Phase 3, L3b)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Lane L3b owns this file (Phase 3 card). It declares the single entry
 * point the DBT dispatcher (L2b, src/dbt/dbt.c) calls for ICLS_FPU
 * instructions; anything this unit refuses (false) keeps the pristine
 * interpreter fallback with zero words emitted.
 *
 * Contract with L2b (mirrors emit_int.h): x19 holds the sparc64_ctx_t
 * pointer on fragment entry (never x18). Guest FP registers live in ctx
 * memory (fp union at 0x140: f[i] at 0x140+i*4, d[i] at 0x140+i*8 with
 * %dN = f-pair 2N/2N+1 so d-index (N>>1)&31; fsr at 0x120, fcc[i] at
 * 0x240+4i). Guest memory is touched only through the sparc64_mem_ops_t
 * callbacks carried in the emit context. Every exit sequence carries the
 * resume/fault guest PC in x15 and the reason in w16 (SPARC64_EXIT_*).
 * Rounding-sensitive lowered ops (arith, sqrt, conversions) emit a
 * runtime FSR.RD == 0 guard prologue and exit SPARC64_EXIT_UNDEF on
 * nonzero (cached blocks stay correct across LDFSR mode changes).
 */

#ifndef SPARC64RT_DBT_EMIT_FP_H
#define SPARC64RT_DBT_EMIT_FP_H

#include <stdbool.h>

#include "interp/interp.h" /* sparc64_dec_t decoded form (classify_word) */
#include "dbt/emit_priv.h" /* sparc64_emit_ctx_t code buffer context */

/* Emit one translated guest FPU instruction; returns false when the op
 * must fall back to the interpreter (quad, VIS/FALIGNDATA, block ASIs,
 * FCMP*, FMOVcc/FMOVr, LDFSR, FBR, everything else). Never emits any
 * read or write of AArch64 x18. */
bool sparc64_emit_fp(sparc64_emit_ctx_t *ec, const sparc64_dec_t *d);

#endif /* SPARC64RT_DBT_EMIT_FP_H */
