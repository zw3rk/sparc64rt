/*
 * src/dbt/emit_cond.h — AArch64 condition emitter interface (Lane P13-5)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Split out of emit_int.c so emit_int.c stays under the 900-line
 * discipline. Same contract as emit_int.h: x19 holds ctx, scratch
 * x9-x14, exits carry PC in x15 and reason in w16, never x18.
 * Bicc/BPcc/MOVcc take the live-NZCV fast path when the block's
 * nzcv_state matches the tested width (zero setup instructions).
 */

#ifndef SPARC64RT_DBT_EMIT_COND_H
#define SPARC64RT_DBT_EMIT_COND_H

#include <stdbool.h>

#include "interp/interp.h" /* sparc64_dec_t decoded form (classify_word) */
#include "dbt/emit_priv.h" /* sparc64_dbt_buf_t code buffer */

/* Emit one translated guest Bicc/BPcc/BPr transfer; false when the
 * shape must fall back to the interpreter. */
bool sparc64_emit_branch(sparc64_emit_ctx_t *ec, const sparc64_dec_t *d);

/* Emit one translated guest MOVcc / MOVr; false on fallback shapes. */
bool sparc64_emit_movcc(sparc64_emit_ctx_t *ec, const sparc64_dec_t *d);
bool sparc64_emit_movr(sparc64_emit_ctx_t *ec, const sparc64_dec_t *d);

/* Emit one translated guest Tcc; false on fallback shapes. */
bool sparc64_emit_tcc(sparc64_emit_ctx_t *ec, const sparc64_dec_t *d);

/* Delay-slot helpers shared with the CALL/JMPL emitters in emit_int.c:
 * plain-shape check, annul/run rules, and single-copy emission (FPU
 * delays lower via emit_fp.h). The branch emitter snapshots the
 * write-through caches across its two delay copies itself. */
bool sparc64_delay_is_plain(const sparc64_dec_t *d);
bool sparc64_delay_runs(uint8_t cls, unsigned cond, bool taken,
    bool annul);
bool sparc64_emit_delay(sparc64_emit_ctx_t *ec);

#endif /* SPARC64RT_DBT_EMIT_COND_H */
