/*
 * src/interp/fp_conv.c — Phase 3 single/double conversion interpreter.
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Single/double half of the SPEC section 2 conversion matrix, entered
 * from the fp.c dispatcher (sparc64_fp_conv). Quad-involving conversions
 * live in fp_quad.c. All behavior is verified against the qemu-sparc64
 * 7.2.22 oracle:
 *
 * - Integer to float (FITOS/FITOD/FXTOS/FXTOD): exact bit conversion
 *   with explicit RD rounding (no host FP environment); NX when
 *   rounded (overflow is impossible: int64 < float max).
 * - Float to integer (FSTOI/FDTOI/FSTOX/FDTOX): truncate toward zero
 *   regardless of RD; NX when the double bits show a fraction; NV + OF
 *   with saturation on NaN/out-of-range/inf (positive side and NaN
 *   saturate to MAX, negative side to MIN).
 * - Widening (FSTOD): exact; SNaN input sets NV and widens the quieted
 *   NaN, QNaN widens quietly.
 * - Narrowing (FDTOS) lives in fp_sd.c (explicit GRS pack).
 */

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "core/cpu.h"
#include "interp/interp.h"

/* Double-pair index (mirrors fp.c): even field is the lower f-pair,
 * odd field the upper bank. */
static unsigned cv_pair(unsigned v)
{
    if ((v & 1U) != 0U) {
        return 16U + (v >> 1U);
    }
    return v >> 1U;
}

static float cv_f32(uint32_t u)
{
    float v = 0.0F;
    memcpy(&v, &u, sizeof(v));
    return v;
}

static uint64_t cv_b64(double v)
{
    uint64_t u = UINT64_C(0);
    memcpy(&u, &v, sizeof(u));
    return u;
}

static double cv_f64(uint64_t u)
{
    double v = 0.0;
    memcpy(&v, &u, sizeof(v));
    return v;
}

static sparc64_step_result_t cv_commit(sparc64_cpu_t *cpu, uint64_t pc,
    const sparc64_dec_t *d, unsigned fresh)
{
    fresh &= 0x1FU;
    cpu->fsr = (cpu->fsr & ~UINT64_C(0x1F)) | (uint64_t)fresh;
    cpu->fsr |= (uint64_t)fresh << 5;
    if ((((cpu->fsr >> 23) & UINT64_C(0x1F)) & (cpu->fsr & UINT64_C(0x1F))) !=
        UINT64_C(0)) {
        return sparc64_trap(SPARC64_TRAP_ILLEGAL, pc, d->raw);
    }
    return sparc64_step_ok(pc);
}

/* 64-bit leading-zero count (unrolled binary search). */
static unsigned cv_clz64(uint64_t v)
{
    unsigned n = 0U;
    if ((v >> 32) == UINT64_C(0)) {
        n += 32U;
        v <<= 32;
    }
    if ((v >> 48) == UINT64_C(0)) {
        n += 16U;
        v <<= 16;
    }
    if ((v >> 56) == UINT64_C(0)) {
        n += 8U;
        v <<= 8;
    }
    if ((v >> 60) == UINT64_C(0)) {
        n += 4U;
        v <<= 4;
    }
    if ((v >> 62) == UINT64_C(0)) {
        n += 2U;
        v <<= 2;
    }
    if ((v >> 63) == UINT64_C(0)) {
        n += 1U;
    }
    return n;
}

/* Integer magnitude to float bits: exact when the magnitude fits P
 * significand bits, else rounded per the raw RD tag (oracle map:
 * 0 nearest-even, 1 toward-zero, 2 toward-+inf, 3 toward--inf) with
 * NX. Overflow is impossible (int64 < float max). */
static uint64_t cv_int_bits(uint64_t mag, unsigned neg, unsigned p,
    unsigned rm, int bias, unsigned eshift, uint64_t fmask, unsigned *nx)
{
    uint64_t sig = UINT64_C(0);
    unsigned g = 0U;
    unsigned r = 0U;
    unsigned s = 0U;
    unsigned bitlen;
    int exp;
    bool up;
    if (mag == UINT64_C(0)) {
        *nx = 0U;
        return (uint64_t)neg << ((p == 24U) ? 31U : 63U);
    }
    bitlen = 64U - cv_clz64(mag);
    exp = (int)(bitlen - 1U);
    if (bitlen <= p) {
        sig = mag << (p - bitlen);
    } else {
        unsigned shift = bitlen - p;
        unsigned i;
        sig = mag >> shift;
        for (i = 0U; i < shift; i++) {
            unsigned b = (unsigned)((mag >> i) & UINT64_C(1));
            if (i == shift - 1U) {
                g = b;
            } else if (i == shift - 2U) {
                r = b;
            } else {
                s |= b;
            }
        }
    }
    *nx = (g != 0U || r != 0U || s != 0U) ? 1U : 0U;
    if (rm == 0U) {
        up = (g != 0U) && ((r != 0U) || (s != 0U) ||
            ((sig & UINT64_C(1)) != UINT64_C(0)));
    } else if (rm == 1U) {
        up = false;
    } else if (rm == 2U) {
        up = neg == 0U;
    } else {
        up = neg != 0U;
    }
    if (up) {
        sig += UINT64_C(1);
        if ((sig >> p) != UINT64_C(0)) {
            sig >>= 1;
            exp += 1;
        }
    }
    return ((uint64_t)neg << ((p == 24U) ? 31U : 63U)) |
        ((uint64_t)((unsigned)(exp + bias)) << eshift) | (sig & fmask);
}

/* 32-bit integer source to single/double: exact bit conversion with
 * explicit RD rounding; NX when rounded. */
static sparc64_step_result_t cv_itos(sparc64_cpu_t *cpu, uint64_t pc,
    const sparc64_dec_t *d, unsigned to_double)
{
    int32_t v = (int32_t)cpu->fp.f[(d->raw & 31U) ^ 1U];
    unsigned neg = (v < 0) ? 1U : 0U;
    uint64_t mag = (neg != 0U) ? (UINT64_C(0) - (uint64_t)(uint32_t)v)
                               : (uint64_t)(uint32_t)v;
    unsigned rm = (unsigned)((cpu->fsr >> 30) & UINT64_C(3));
    unsigned nx = 0U;
    if (to_double != 0U) {
        cpu->fp.d[cv_pair(d->rd)] = cv_int_bits(mag, neg, 53U, rm, 1023,
            52U, UINT64_C(0x000FFFFFFFFFFFFF), &nx);
    } else {
        cpu->fp.f[(d->rd & 31U) ^ 1U] = (uint32_t)cv_int_bits(mag, neg,
            24U, rm, 127, 23U, UINT64_C(0x7FFFFF), &nx);
    }
    return cv_commit(cpu, pc, d, nx);
}

/* 64-bit integer source to single/double: same rules as 32-bit. */
static sparc64_step_result_t cv_xtos(sparc64_cpu_t *cpu, uint64_t pc,
    const sparc64_dec_t *d, unsigned to_double)
{
    int64_t v;
    unsigned neg;
    uint64_t mag;
    unsigned rm = (unsigned)((cpu->fsr >> 30) & UINT64_C(3));
    unsigned nx = 0U;
    memcpy(&v, &cpu->fp.d[cv_pair(d->raw & 31U)], sizeof(v));
    neg = (v < 0) ? 1U : 0U;
    mag = (neg != 0U) ? (UINT64_C(0) - (uint64_t)v) : (uint64_t)v;
    if (to_double != 0U) {
        cpu->fp.d[cv_pair(d->rd)] = cv_int_bits(mag, neg, 53U, rm, 1023,
            52U, UINT64_C(0x000FFFFFFFFFFFFF), &nx);
    } else {
        cpu->fp.f[(d->rd & 31U) ^ 1U] = (uint32_t)cv_int_bits(mag, neg,
            24U, rm, 127, 23U, UINT64_C(0x7FFFFF), &nx);
    }
    return cv_commit(cpu, pc, d, nx);
}

/* Inexact-truncation test on double bits: true when the value has a
 * nonzero fractional part (exact for integral values of any
 * magnitude, unlike a (double)(int64_t)v round-trip which misflags
 * odd integers past 2^53). */
static bool cv_frac_nx(uint64_t u)
{
    unsigned rawexp = (unsigned)((u >> 52) & UINT64_C(0x7FF));
    int e = (int)rawexp - 1023;
    if (rawexp == 0x7FFU) {
        return true;
    }
    if (e < 0) {
        return (u & UINT64_C(0x7FFFFFFFFFFFFFFF)) != UINT64_C(0);
    }
    if (e >= 52) {
        return false;
    }
    return (u & ((UINT64_C(1) << (unsigned)(52 - e)) - UINT64_C(1))) !=
        UINT64_C(0);
}

/* Double value to 32-bit integer: truncate, NX when inexact, NV + OF
 * with saturation when NaN or out of range. */
static sparc64_step_result_t cv_dtoi32(sparc64_cpu_t *cpu, uint64_t pc,
    const sparc64_dec_t *d, double v)
{
    int64_t t;
    uint32_t r;
    unsigned fl = 0U;
    uint64_t u = UINT64_C(0);
    if (!(v >= -2147483648.0) || !(v < 2147483648.0)) {
        fl = 0x18U;
        r = (v < -2147483648.0) ? UINT32_C(0x80000000)
                                : UINT32_C(0x7FFFFFFF);
        cpu->fp.f[(d->rd & 31U) ^ 1U] = r;
        return cv_commit(cpu, pc, d, fl);
    }
    t = (int64_t)v;
    memcpy(&u, &v, sizeof(u));
    if (cv_frac_nx(u)) {
        fl = 0x01U;
    }
    cpu->fp.f[(d->rd & 31U) ^ 1U] = (uint32_t)t;
    return cv_commit(cpu, pc, d, fl);
}

/* Double value to 64-bit integer, same rules with 64-bit range. */
static sparc64_step_result_t cv_dtoi64(sparc64_cpu_t *cpu, uint64_t pc,
    const sparc64_dec_t *d, double v)
{
    int64_t t;
    unsigned fl = 0U;
    uint64_t u = UINT64_C(0);
    if (!(v >= -9223372036854775808.0) || !(v < 9223372036854775808.0)) {
        fl = 0x18U;
        t = (v < -9223372036854775808.0) ? (int64_t)INT64_C(-9223372036854775807 - 1)
                                         : (int64_t)INT64_C(9223372036854775807);
        memcpy(&cpu->fp.d[cv_pair(d->rd)], &t, sizeof(t));
        return cv_commit(cpu, pc, d, fl);
    }
    t = (int64_t)v;
    memcpy(&u, &v, sizeof(u));
    if (cv_frac_nx(u)) {
        fl = 0x01U;
    }
    memcpy(&cpu->fp.d[cv_pair(d->rd)], &t, sizeof(t));
    return cv_commit(cpu, pc, d, fl);
}

/* Single to double widening: exact for finite values; NaN widens the
 * payload (SNaN sets NV and quiets). */
static sparc64_step_result_t cv_stod(sparc64_cpu_t *cpu, uint64_t pc,
    const sparc64_dec_t *d)
{
    uint32_t a = cpu->fp.f[(d->raw & 31U) ^ 1U];
    uint64_t r;
    if (((a & UINT32_C(0x7F800000)) == UINT32_C(0x7F800000)) &&
        ((a & UINT32_C(0x007FFFFF)) != UINT32_C(0))) {
        r = ((uint64_t)(a & UINT32_C(0x80000000)) << 32) |
            UINT64_C(0x7FF0000000000000) |
            ((uint64_t)(a & UINT32_C(0x007FFFFF)) << 29);
        if ((a & UINT32_C(0x00400000)) == UINT32_C(0)) {
            r |= UINT64_C(0x0008000000000000);
            cpu->fp.d[cv_pair(d->rd)] = r;
            return cv_commit(cpu, pc, d, 0x10U);
        }
        cpu->fp.d[cv_pair(d->rd)] = r;
        return cv_commit(cpu, pc, d, 0U);
    }
    cpu->fp.d[cv_pair(d->rd)] = cv_b64((double)cv_f32(a));
    return cv_commit(cpu, pc, d, 0U);
}

sparc64_step_result_t sparc64_fp_conv(sparc64_cpu_t *cpu, uint64_t pc,
    const sparc64_dec_t *d)
{
    switch (d->opf) {
    case 0x0C4U:
        return cv_itos(cpu, pc, d, 0U);
    case 0x0C8U:
        return cv_itos(cpu, pc, d, 1U);
    case 0x084U:
        return cv_xtos(cpu, pc, d, 0U);
    case 0x088U:
        return cv_xtos(cpu, pc, d, 1U);
    case 0x0D1U:
        return cv_dtoi32(cpu, pc, d, (double)cv_f32(cpu->fp.f[(d->raw & 31U) ^ 1U]));
    case 0x0D2U:
        return cv_dtoi32(cpu, pc, d,
            cv_f64(cpu->fp.d[cv_pair(d->raw & 31U)]));
    case 0x081U:
        return cv_dtoi64(cpu, pc, d, (double)cv_f32(cpu->fp.f[(d->raw & 31U) ^ 1U]));
    case 0x082U:
        return cv_dtoi64(cpu, pc, d,
            cv_f64(cpu->fp.d[cv_pair(d->raw & 31U)]));
    case 0x0C9U:
        return cv_stod(cpu, pc, d);
    default:
        return sparc64_trap(SPARC64_TRAP_ILLEGAL, pc, d->raw);
    }
}
