/* src/interp/fp_qcommon.h — shared binary128 (quad) helpers (S64-R13-5/6).
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * One authoritative copy of the quad NaN-propagation rule and of the
 * subnormal GRS extraction used by both fp_quad.c (FADDQ/FSUBQ/FMULQ/
 * FDMULQ) and fp_qdiv.c (FDIVQ/FSQRTQ). At the extraction point the
 * 128-bit container (hi, lo) holds a normalized 113-bit significand:
 * hi bit 48 is the hidden integer bit (value bit 112), hi bits 47:0
 * are value bits 111:64, lo holds value bits 63:0. Shifting right
 * by 113 places value bit 112 into the guard bit, value bit 111 into
 * round, and value bits [110:0] into sticky (hi mask 0x7FFFFFFFFFFF
 * plus all of lo); shifting by 114 moves value bit 112 into round
 * with sticky over value bits [111:0] (hi mask 0xFFFFFFFFFFFF).
 * Larger shifts collapse every input bit (including incoming g/r/s)
 * into sticky. Guard/round/sticky feed the shared IEEE-754 round
 * decision in each TU's pack routine, so both engines stay bit-exact
 * with qemu-sparc64.
 */

#ifndef SPARC64RT_INTERP_FP_QCOMMON_H
#define SPARC64RT_INTERP_FP_QCOMMON_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Quad class: 0 zero, 2 finite, 3 inf, 4 QNaN, 5 SNaN. */
static inline unsigned sparc64_quad_class(uint64_t hi, uint64_t lo)
{
    unsigned rawexp = (unsigned)((hi >> 48) & UINT64_C(0x7FFF));
    bool frac = ((hi & UINT64_C(0xFFFFFFFFFFFF)) != UINT64_C(0)) ||
        (lo != UINT64_C(0));
    if (rawexp == 0x7FFFU) {
        if (!frac) {
            return 3U;
        }
        return ((hi & UINT64_C(0x0000800000000000)) != UINT64_C(0)) ?
            4U : 5U;
    }
    if (rawexp == 0U && !frac) {
        return 0U;
    }
    return 2U;
}

/* Quad payload compare (fraction only): 1 when a >= b. */
static inline bool sparc64_quad_payload_ge(uint64_t ahi, uint64_t alo,
    uint64_t bhi, uint64_t blo)
{
    uint64_t af = ahi & UINT64_C(0xFFFFFFFFFFFF);
    uint64_t bf = bhi & UINT64_C(0xFFFFFFFFFFFF);
    if (af != bf) {
        return af > bf;
    }
    return alo >= blo;
}

/* Quad NaN: SNaN wins (NV), else larger payload (tie rs1). */
static inline bool sparc64_quad_nan2(uint64_t ahi, uint64_t alo,
    uint64_t bhi, uint64_t blo, uint64_t *ohi, uint64_t *olo,
    unsigned *nv)
{
    unsigned ca = sparc64_quad_class(ahi, alo);
    unsigned cb = sparc64_quad_class(bhi, blo);
    bool sa = ca == 5U;
    bool sb = cb == 5U;
    bool qa = ca == 4U;
    bool qb = cb == 4U;
    bool pick_a;
    if (ohi == NULL || olo == NULL || nv == NULL) {
        return false;
    }
    if (!sa && !sb && !qa && !qb) {
        return false;
    }
    *nv = (sa || sb) ? 0x10U : 0U;
    if (sa || sb) {
        if (sa && sb) {
            pick_a = sparc64_quad_payload_ge(ahi, alo, bhi, blo);
        } else {
            pick_a = sa;
        }
    } else if (qa && qb) {
        pick_a = sparc64_quad_payload_ge(ahi, alo, bhi, blo);
    } else {
        pick_a = qa;
    }
    if (pick_a) {
        *ohi = ahi;
        *olo = alo;
    } else {
        *ohi = bhi;
        *olo = blo;
    }
    if (sa || sb) {
        *ohi |= UINT64_C(0x0000800000000000);
    }
    return true;
}

/* Subnormal GRS extraction for shift >= 113 (caller zeroes shi/slo
 * after and rounds from the gg/rr/ss outputs. Incoming g/r/s fold
 * sticky seed so a previously discarded bit is never lost. */
static inline void sparc64_quad_grs_trunc(uint64_t shi, uint64_t slo,
    unsigned g, unsigned r, unsigned s, unsigned shift, unsigned *gg,
    unsigned *rr, unsigned *ss)
{
    unsigned acc = g | r | s;
    if (gg == NULL || rr == NULL || ss == NULL) {
        return;
    }
    if (shift == 113U) {
        *gg = (unsigned)((shi >> 48) & UINT64_C(1));
        *rr = (unsigned)((shi >> 47) & UINT64_C(1));
        *ss = ((((shi & UINT64_C(0x7FFFFFFFFFFF)) != UINT64_C(0)) ||
            (slo != UINT64_C(0)) || acc != 0U)) ? 1U : 0U;
    } else if (shift == 114U) {
        *gg = 0U;
        *rr = (unsigned)((shi >> 48) & UINT64_C(1));
        *ss = ((((shi & UINT64_C(0xFFFFFFFFFFFF)) != UINT64_C(0)) ||
            (slo != UINT64_C(0)) || acc != 0U)) ? 1U : 0U;
    } else {
        *gg = 0U;
        *rr = 0U;
        *ss = ((shi != UINT64_C(0)) || (slo != UINT64_C(0)) ||
            acc != 0U) ? 1U : 0U;
    }
}

#endif /* SPARC64RT_INTERP_FP_QCOMMON_H */
