/*
 * src/dbt/emit_fast.h — Lane P5 inline fast paths (MUL/DIV, SAVE/RESTORE)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SPARC64RT_DBT_EMIT_FAST_H
#define SPARC64RT_DBT_EMIT_FAST_H

#include <stdbool.h>

#include "dbt/emit_priv.h"
#include "interp/interp.h"

/* Inline UMUL/SMUL/UDIVX/SDIVX (Y, traps identical to the helper).
 * Returns true when emitted (fast path with precise slow fallback),
 * false only on buffer overflow. Call only for those four op3s. */
bool sparc64_fast_alu(sparc64_emit_ctx_t *ec, const sparc64_dec_t *d);

/* Fast-path SAVE/RESTORE when no spill/fill is needed
 * (SAVE: cansave > 0 and reuse target invalid; RESTORE: target valid
 * and canrestore > 0); otherwise the shared window helper runs.
 * Returns true when emitted, false on overflow or missing mem ops. */
bool sparc64_fast_win(sparc64_emit_ctx_t *ec, const sparc64_dec_t *d,
    bool is_save);

#endif /* SPARC64RT_DBT_EMIT_FAST_H */
