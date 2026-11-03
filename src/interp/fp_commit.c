/*
 * src/interp/fp_commit.c — shared FP exception-commit helper (S64-R4-11).
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * One implementation of the FSR commit shared by the conversion
 * (fp_conv.c) and arithmetic (fp_sd.c) halves: current exceptions
 * overwritten, accrued exceptions sticky, trapped conditions take the
 * synchronous-trap path like ILLEGAL.
 */

#include "interp/fp_commit.h"

sparc64_step_result_t sparc64_fp_commit(sparc64_cpu_t *cpu, uint64_t pc,
    const sparc64_dec_t *d, unsigned fresh)
{
    unsigned tem;
    fresh &= 0x1FU;
    tem = (unsigned)((cpu->fsr >> 23) & UINT64_C(0x1F));
    if (((unsigned)fresh & tem) != 0U) {
        unsigned cexc = fresh;
        if ((fresh & 0x08U) != 0U) {
            cexc = 0x08U;
        } else if ((fresh & 0x04U) != 0U) {
            cexc = 0x04U;
        }
        cpu->fsr = (cpu->fsr & ~UINT64_C(0x1F)) | (uint64_t)cexc;
        cpu->fsr = (cpu->fsr & ~(UINT64_C(7) << 14)) |
            (UINT64_C(1) << 14);
        return sparc64_trap(SPARC64_TRAP_ILLEGAL, pc, d->raw);
    }
    cpu->fsr = (cpu->fsr & ~UINT64_C(0x1F)) | (uint64_t)fresh;
    cpu->fsr |= (uint64_t)fresh << 5;
    cpu->fsr &= ~(UINT64_C(7) << 14);
    return sparc64_step_ok(pc);
}
