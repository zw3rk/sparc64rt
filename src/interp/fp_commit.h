/*
 * src/interp/fp_commit.h — shared FP exception-commit helper (S64-R4-11).
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Single/double (fp_conv.c) and single/double arithmetic (fp_sd.c)
 * implement the same architectural commit: overwrite the current
 * exceptions, accumulate into the accrued flags, and take the generic
 * synchronous-trap path when a trapped condition is enabled. One
 * repository-local helper keeps future exception corrections in one
 * place; result publication stays with the callers.
 */

#ifndef SPARC64RT_INTERP_FP_COMMIT_H
#define SPARC64RT_INTERP_FP_COMMIT_H

#include <stdint.h>

#include "core/cpu.h"
#include "interp/interp.h"

sparc64_step_result_t sparc64_fp_commit(sparc64_cpu_t *cpu, uint64_t pc,
    const sparc64_dec_t *d, unsigned fresh);

/* FPRS state bits (V9 5.1.6: FEF bit 2, DU bit 1, DL bit 0). */
enum {
    SPARC64_FPRS_DL = 1U,
    SPARC64_FPRS_DU = 2U,
    SPARC64_FPRS_FEF = 4U
};

/* Mark the bank holding a committed FP destination dirty (upper selects
 * DU, otherwise DL). Call only after commit succeeds, beside the write. */
static inline void sparc64_fp_mark_dirty(sparc64_cpu_t *cpu, unsigned upper)
{
    cpu->fprs |= (uint64_t)((upper != 0U) ? SPARC64_FPRS_DU :
        SPARC64_FPRS_DL);
}

#endif /* SPARC64RT_INTERP_FP_COMMIT_H */
