/*
 * src/interp/interp_cond.c — architectural condition-code evaluators
 * (Lane P13-5 split of interp_win.c)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Moved verbatim from interp_win.c (Phase 1, L1b) so interp_win.c stays
 * under the 900-line discipline. Pure functions shared by the
 * interpreter, the DBT delay-continuation logic, and the FP-branches.
 */

#include "interp/interp.h"

/* Bicc/BPcc/Ticc/MOVcc condition over one 4-bit N/Z/V/C nibble
 * (bit 3 N, bit 2 Z, bit 1 V, bit 0 C). */
bool sparc64_eval_cond(unsigned cond, unsigned nibble)
{
    bool n = (nibble & 8U) != 0U;
    bool z = (nibble & 4U) != 0U;
    bool v = (nibble & 2U) != 0U;
    bool c = (nibble & 1U) != 0U;
    switch (cond & 15U) {
    case 0x0U: return false;
    case 0x1U: return z;
    case 0x2U: return z || (n != v);
    case 0x3U: return n != v;
    case 0x4U: return c || z;
    case 0x5U: return c;
    case 0x6U: return n;
    case 0x7U: return v;
    case 0x8U: return true;
    case 0x9U: return !z;
    case 0xAU: return !(z || (n != v));
    case 0xBU: return n == v;
    case 0xCU: return !(c || z);
    case 0xDU: return !c;
    case 0xEU: return !n;
    default: return !v;
    }
}

/* BPr/MOVr register test over the full 64-bit value. rcond skips 4. */
bool sparc64_eval_rcond(unsigned rcond, uint64_t v)
{
    switch (rcond & 15U) {
    case 1U: return v == UINT64_C(0);
    case 2U: return (int64_t)v <= (int64_t)0;
    case 3U: return (int64_t)v < (int64_t)0;
    case 5U: return v != UINT64_C(0);
    case 6U: return (int64_t)v > (int64_t)0;
    case 7U: return (int64_t)v >= (int64_t)0;
    default: return false;
    }
}

/* FBfcc condition over one fcc field (0 eq, 1 lt, 2 gt, 3 unordered). */
bool sparc64_eval_fcond(unsigned cond, uint32_t fcc)
{
    switch (cond & 15U) {
    case 0x0U: return false;
    case 0x1U: return fcc != 0U;
    case 0x2U: return fcc == 1U || fcc == 2U;
    case 0x3U: return fcc == 3U || fcc == 1U;
    case 0x4U: return fcc == 1U;
    case 0x5U: return fcc == 3U || fcc == 2U;
    case 0x6U: return fcc == 2U;
    case 0x7U: return fcc == 3U;
    case 0x8U: return true;
    case 0x9U: return fcc == 0U;
    case 0xAU: return fcc == 0U || fcc == 3U;
    case 0xBU: return fcc == 0U || fcc == 2U;
    case 0xCU: return fcc != 1U;
    case 0xDU: return fcc == 0U || fcc == 1U;
    case 0xEU: return fcc != 2U;
    default: return fcc != 3U;
    }
}

