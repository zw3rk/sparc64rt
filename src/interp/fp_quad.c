/* src/interp/fp_quad.c — quad-precision (binary128) FADDQ/FSUBQ/FMULQ/FDMULQ.
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0 */

#include <fenv.h>
#include <stdint.h>
#include <string.h>

#include "core/cpu.h"
#include "interp/fp_commit.h"
#include "interp/interp.h"

/* FDIVQ/FSQRTQ entry (defined in fp_qdiv.c). */
sparc64_step_result_t sparc64_fp_qdiv(sparc64_cpu_t *cpu, uint64_t pc,
    const sparc64_dec_t *d);

#define Q_BIAS 16383
#define Q_EMAX 16383
#define Q_EMIN (-16382)

/* Count leading zeros of a nonzero 64-bit value (binary search). */
static unsigned qq_clz64(uint64_t x)
{
    unsigned n = 0U;
    if ((x >> 32) == UINT64_C(0)) {
        n += 32U;
        x <<= 32;
    }
    if ((x >> 48) == UINT64_C(0)) {
        n += 16U;
        x <<= 16;
    }
    if ((x >> 56) == UINT64_C(0)) {
        n += 8U;
        x <<= 8;
    }
    if ((x >> 60) == UINT64_C(0)) {
        n += 4U;
        x <<= 4;
    }
    if ((x >> 62) == UINT64_C(0)) {
        n += 2U;
        x <<= 2;
    }
    if ((x >> 63) == UINT64_C(0)) {
        n += 1U;
    }
    return n;
}

static void qq_shl(uint64_t *hi, uint64_t *lo, unsigned k)
{
    if (k == 0U) {
        return;
    }
    if (k >= 64U) {
        *hi = *lo << (k - 64U);
        *lo = UINT64_C(0);
    } else {
        *hi = (*hi << k) | (*lo >> (64U - k));
        *lo <<= k;
    }
}

static void qq_shr(uint64_t *hi, uint64_t *lo, unsigned k)
{
    if (k == 0U) {
        return;
    }
    if (k >= 64U) {
        *lo = *hi >> (k - 64U);
        *hi = UINT64_C(0);
    } else {
        *lo = (*lo >> k) | (*hi << (64U - k));
        *hi >>= k;
    }
}

static unsigned qq_bit(uint64_t hi, uint64_t lo, unsigned i)
{
    if (i < 64U) {
        return (unsigned)((lo >> i) & UINT64_C(1));
    }
    return (unsigned)((hi >> (i - 64U)) & UINT64_C(1));
}

/* Quad pair index: mod4 0 lower, 1 upper bank, else 16 (invalid). */
static unsigned qq_qidx(unsigned w)
{
    unsigned m = w & 3U;
    if (m == 0U) {
        return w >> 2U;
    }
    if (m == 1U) {
        return 8U + (w >> 2U);
    }
    return 16U;
}

/* Double-pair index (mirrors fp.c). */
static unsigned qq_pair(unsigned v)
{
    if ((v & 1U) != 0U) {
        return 16U + (v >> 1U);
    }
    return v >> 1U;
}

static int qq_rd_mode(const sparc64_cpu_t *cpu)
{
    static const int modes[4] = {
        FE_TONEAREST, FE_TOWARDZERO, FE_UPWARD, FE_DOWNWARD
    };
    return modes[(cpu->fsr >> 30) & UINT64_C(3)];
}

static sparc64_step_result_t qq_commit(sparc64_cpu_t *cpu, uint64_t pc,
    const sparc64_dec_t *d, unsigned fresh)
{
    return sparc64_fp_commit(cpu, pc, d, fresh);
}

/* Quad class: 0 zero, 2 finite, 3 inf, 4 QNaN, 5 SNaN. */
static unsigned qq_class(uint64_t hi, uint64_t lo)
{
    unsigned rawexp = (unsigned)((hi >> 48) & UINT64_C(0x7FFF));
    bool frac = ((hi & UINT64_C(0xFFFFFFFFFFFF)) != UINT64_C(0)) ||
        (lo != UINT64_C(0));
    if (rawexp == 0x7FFFU) {
        if (!frac) {
            return 3U;
        }
        return ((hi & UINT64_C(0x0000800000000000)) != UINT64_C(0)) ? 4U : 5U;
    }
    if (rawexp == 0U && !frac) {
        return 0U;
    }
    return 2U;
}

/* Quad payload compare (fraction only): 1 when a >= b. */
static bool qq_payload_ge(uint64_t ahi, uint64_t alo, uint64_t bhi,
    uint64_t blo)
{
    uint64_t af = ahi & UINT64_C(0xFFFFFFFFFFFF);
    uint64_t bf = bhi & UINT64_C(0xFFFFFFFFFFFF);
    if (af != bf) {
        return af > bf;
    }
    return alo >= blo;
}

/* Unpacked quad: sig * 2^(exp-112), hidden bit shi:48. */
typedef struct {
    unsigned neg;
    int exp;
    uint64_t shi;
    uint64_t slo;
} qq_unp_t;

/* Unpack a finite nonzero quad (caller pre-screens zero/inf/NaN). */
static void qq_unpack(uint64_t hi, uint64_t lo, qq_unp_t *q)
{
    unsigned rawexp = (unsigned)((hi >> 48) & UINT64_C(0x7FFF));
    uint64_t fh = hi & UINT64_C(0xFFFFFFFFFFFF);
    unsigned lz;
    unsigned top;
    q->neg = (unsigned)(hi >> 63);
    if (rawexp != 0U) {
        q->exp = (int)rawexp - Q_BIAS;
        q->shi = fh | (UINT64_C(1) << 48);
        q->slo = lo;
        return;
    }
    q->exp = Q_EMIN;
    q->shi = fh;
    q->slo = lo;
    if (fh != UINT64_C(0)) {
        lz = qq_clz64(fh);
        top = 48U - (63U - lz);
        qq_shl(&q->shi, &q->slo, top);
        q->exp -= (int)top;
    } else if (lo != UINT64_C(0)) {
        lz = qq_clz64(lo);
        top = 112U - (63U - lz);
        qq_shl(&q->shi, &q->slo, top);
        q->exp -= (int)top;
    }
}

/* Round/pack 113-bit sig with GRS into binary128; returns cexc. */
static unsigned qq_pack(unsigned neg, int exp, uint64_t shi, uint64_t slo,
    unsigned g, unsigned r, unsigned s, int rm, uint64_t *ohi,
    uint64_t *olo)
{
    unsigned lsb;
    bool up;
    bool inexact;
    bool tiny;
    if (shi == UINT64_C(0) && slo == UINT64_C(0) && g == 0U && r == 0U &&
        s == 0U) {
        *ohi = (uint64_t)neg << 63;
        *olo = UINT64_C(0);
        return 0U;
    }
    if ((shi >> 49) != UINT64_C(0)) {
        unsigned ng = (unsigned)(slo & UINT64_C(1));
        qq_shr(&shi, &slo, 1U);
        s = r | s;
        r = g;
        g = ng;
        exp += 1;
    } else if (((shi >> 48) & UINT64_C(1)) == UINT64_C(0)) {
        unsigned bitlen;
        unsigned k;
        if (shi != UINT64_C(0)) {
            bitlen = 128U - qq_clz64(shi);
        } else {
            bitlen = 64U - qq_clz64(slo);
        }
        k = 113U - bitlen;
        qq_shl(&shi, &slo, k);
        exp -= (int)k;
    }
    if (exp < Q_EMIN) {
        unsigned shift = (unsigned)(Q_EMIN - exp);
        if (shift >= 113U) {
            /* Value is below one output ulp: keep exact GRS and round. */
            unsigned gg = 0U;
            unsigned rr = 0U;
            unsigned ss = g | r | s;
            if (shift == 113U) {
                gg = (unsigned)((shi >> 48) & UINT64_C(1));
                rr = (unsigned)((shi >> 47) & UINT64_C(1));
                ss |= (unsigned)(((shi & UINT64_C(0x7FFFFFFFFFFF)) !=
                    UINT64_C(0)) || (slo != UINT64_C(0))) ? 1U : 0U;
            } else if (shift == 114U) {
                rr = (unsigned)((shi >> 48) & UINT64_C(1));
                ss |= (unsigned)(((shi & UINT64_C(0xFFFFFFFFFFFF)) !=
                    UINT64_C(0)) || (slo != UINT64_C(0))) ? 1U : 0U;
            } else {
                ss |= (unsigned)(((shi != UINT64_C(0)) || (slo !=
                    UINT64_C(0))) ? 1U : 0U);
            }
            shi = UINT64_C(0);
            slo = UINT64_C(0);
            g = gg;
            r = rr;
            s = (ss != 0U) ? 1U : 0U;
        } else {
            unsigned g2 = qq_bit(shi, slo, shift - 1U);
            unsigned r2 =
                (shift > 1U) ? qq_bit(shi, slo, shift - 2U) : 0U;
            unsigned s2 = g | r | s;
            unsigned i;
            for (i = 0U; (shift > 2U) && (i < shift - 2U); i++) {
                s2 |= qq_bit(shi, slo, i);
            }
            qq_shr(&shi, &slo, shift);
            g = g2;
            r = r2;
            s = (s2 != 0U) ? 1U : 0U;
        }
        exp = Q_EMIN;
    }
    lsb = (unsigned)(slo & UINT64_C(1));
    if (rm == FE_TONEAREST) {
        up = (g != 0U) && ((r != 0U) || (s != 0U) || (lsb != 0U));
    } else if (rm == FE_TOWARDZERO) {
        up = false;
    } else if (rm == FE_UPWARD) {
        up = (neg == 0U) && ((g != 0U) || (r != 0U) || (s != 0U));
    } else {
        up = (neg != 0U) && ((g != 0U) || (r != 0U) || (s != 0U));
    }
    if (up) {
        slo += UINT64_C(1);
        if (slo == UINT64_C(0)) {
            shi += UINT64_C(1);
        }
        if ((shi >> 49) != UINT64_C(0)) {
            qq_shr(&shi, &slo, 1U);
            exp += 1;
        }
    }
    inexact = (g != 0U) || (r != 0U) || (s != 0U);
    tiny = (exp == Q_EMIN) && (((shi >> 48) & UINT64_C(1)) == UINT64_C(0));
    if (exp > Q_EMAX) {
        /* Overflow is always inexact for finite inputs. */
        bool to_inf;
        if (rm == FE_TONEAREST) {
            to_inf = true;
        } else if (rm == FE_TOWARDZERO) {
            to_inf = false;
        } else if (rm == FE_UPWARD) {
            to_inf = neg == 0U;
        } else {
            to_inf = neg != 0U;
        }
        if (to_inf) {
            *ohi = ((uint64_t)neg << 63) |
                ((uint64_t)UINT64_C(0x7FFF) << 48);
            *olo = UINT64_C(0);
        } else {
            *ohi = ((uint64_t)neg << 63) |
                ((uint64_t)(Q_EMAX + Q_BIAS) << 48) |
                UINT64_C(0xFFFFFFFFFFFF);
            *olo = UINT64_C(0xFFFFFFFFFFFFFFFF);
        }
        return 0x09U;
    }
    if (tiny || ((shi == UINT64_C(0)) && (slo == UINT64_C(0)))) {
        *ohi = ((uint64_t)neg << 63) | (shi & UINT64_C(0xFFFFFFFFFFFF));
        *olo = slo;
    } else {
        *ohi = ((uint64_t)neg << 63) |
            ((uint64_t)(exp + Q_BIAS) << 48) |
            (shi & UINT64_C(0xFFFFFFFFFFFF));
        *olo = slo;
    }
    return (tiny && inexact ? 0x04U : 0U) | (inexact ? 0x01U : 0U);
}

/* 128-bit bit-length; caller guarantees nonzero. */
static unsigned qq_bitlen128(__uint128_t v)
{
    if ((v >> 64) != (__uint128_t)0) {
        return 128U - qq_clz64((uint64_t)(v >> 64));
    }
    return 64U - qq_clz64((uint64_t)v);
}

/* Add/sub unpacked values; sub flips sign; outputs for qq_pack. */
static void qq_addsub(const qq_unp_t *a, const qq_unp_t *b, unsigned sub,
    unsigned *neg, int *exp, uint64_t *shi, uint64_t *slo, unsigned *g,
    unsigned *r, unsigned *s, bool *iszero)
{
    unsigned aneg = a->neg;
    unsigned bneg = b->neg ^ (sub & 1U);
    int aexp = a->exp;
    int bexp = b->exp;
    uint64_t ahi = a->shi;
    uint64_t alo = a->slo;
    uint64_t bhi = b->shi;
    uint64_t blo = b->slo;
    __uint128_t hi128;
    __uint128_t lo128;
    __uint128_t lsx = (__uint128_t)0;
    unsigned s2 = 0U;
    unsigned d = 0U;
    if (aexp < bexp) {
        aneg = b->neg ^ (sub & 1U);
        bneg = a->neg;
        aexp = b->exp;
        bexp = a->exp;
        ahi = b->shi;
        alo = b->slo;
        bhi = a->shi;
        blo = a->slo;
    }
    hi128 = ((__uint128_t)ahi << 64) | (__uint128_t)alo;
    lo128 = ((__uint128_t)bhi << 64) | (__uint128_t)blo;
    d = (unsigned)(aexp - bexp);
    /* Align with three exact guard bits plus sticky: the extended pair
     * keeps every dropped bit, so add/sub below are exact and rounding
     * happens once in qq_pack. */
    hi128 <<= 3;
    if (d >= 128U) {
        s2 = (lo128 != (__uint128_t)0) ? 1U : 0U;
    } else {
        __uint128_t full = lo128 << 3;
        __uint128_t mask = (d == 0U) ? (__uint128_t)0
            : (((__uint128_t)1 << d) - (__uint128_t)1);
        lsx = full >> d;
        s2 = ((full & mask) != (__uint128_t)0) ? 1U : 0U;
    }
    if (aneg == bneg) {
        __uint128_t sum = hi128 + lsx;
        *neg = aneg;
        *exp = aexp;
        *iszero = false;
        if (((sum >> 116U) & (__uint128_t)1) != (__uint128_t)0) {
            *slo = (uint64_t)(sum >> 4);
            *shi = (uint64_t)(sum >> 68);
            *g = (unsigned)((sum >> 3) & (__uint128_t)1);
            *r = (unsigned)((sum >> 2) & (__uint128_t)1);
            *s = ((((sum & (__uint128_t)7) != (__uint128_t)0) || (s2 != 0U))
                ? 1U : 0U);
            *exp += 1;
        } else {
            *slo = (uint64_t)(sum >> 3);
            *shi = (uint64_t)(sum >> 67);
            *g = (unsigned)((sum >> 2) & (__uint128_t)1);
            *r = (unsigned)((sum >> 1) & (__uint128_t)1);
            *s = ((((sum & (__uint128_t)1) != (__uint128_t)0) || (s2 != 0U))
                ? 1U : 0U);
        }
    } else if ((hi128 == lsx) && (s2 == 0U)) {
        *neg = 0U;
        *exp = 0;
        *shi = UINT64_C(0);
        *slo = UINT64_C(0);
        *iszero = true;
        *g = 0U;
        *r = 0U;
        *s = 0U;
    } else if (hi128 == lsx) {
        /* Equal extended significands with a dropped fraction below:
         * tiny nonzero value, sign of the subtrahend side. */
        *neg = bneg;
        *exp = aexp;
        *shi = UINT64_C(0);
        *slo = UINT64_C(0);
        *iszero = false;
        *g = 0U;
        *r = 0U;
        *s = 1U;
    } else if (hi128 > lsx) {
        __uint128_t diff = hi128 - lsx;
        unsigned bitlen;
        unsigned k;
        if (s2 != 0U) {
            /* Borrow one ulp for the truncated subtrahend fraction
             * below diff's lsb (sticky stays set). */
            diff -= (__uint128_t)1;
            if (diff == (__uint128_t)0) {
                *exp = aexp;
                *neg = aneg;
                *shi = UINT64_C(0);
                *slo = UINT64_C(0);
                *iszero = false;
                *g = 0U;
                *r = 0U;
                *s = 1U;
                return;
            }
        }
        bitlen = qq_bitlen128(diff);
        k = 116U - bitlen;
        diff <<= k;
        *exp = aexp - (int)k;
        *neg = aneg;
        *slo = (uint64_t)(diff >> 3);
        *shi = (uint64_t)(diff >> 67);
        *g = (unsigned)((diff >> 2) & (__uint128_t)1);
        *r = (unsigned)((diff >> 1) & (__uint128_t)1);
        *s = ((((diff & (__uint128_t)1) != (__uint128_t)0) || (s2 != 0U))
            ? 1U : 0U);
        *iszero = false;
    } else {
        __uint128_t diff = lsx - hi128;
        unsigned bitlen;
        unsigned k;
        if (s2 != 0U) {
            diff -= (__uint128_t)1;
            if (diff == (__uint128_t)0) {
                *exp = aexp;
                *neg = bneg;
                *shi = UINT64_C(0);
                *slo = UINT64_C(0);
                *iszero = false;
                *g = 0U;
                *r = 0U;
                *s = 1U;
                return;
            }
        }
        bitlen = qq_bitlen128(diff);
        k = 116U - bitlen;
        diff <<= k;
        *exp = aexp - (int)k;
        *neg = bneg;
        *slo = (uint64_t)(diff >> 3);
        *shi = (uint64_t)(diff >> 67);
        *g = (unsigned)((diff >> 2) & (__uint128_t)1);
        *r = (unsigned)((diff >> 1) & (__uint128_t)1);
        *s = ((((diff & (__uint128_t)1) != (__uint128_t)0) || (s2 != 0U))
            ? 1U : 0U);
        *iszero = false;
    }
}

/* Multiply unpacked values: 113x113-bit product, top bits + GRS. */
static void qq_mul(const qq_unp_t *a, const qq_unp_t *b, unsigned *neg,
    int *exp, uint64_t *shi, uint64_t *slo, unsigned *g, unsigned *r,
    unsigned *s)
{
    uint32_t al[4];
    uint32_t bl[4];
    uint64_t p[8];
    unsigned i;
    unsigned j;
    unsigned bitlen;
    unsigned shift;
    unsigned gg = 0U;
    unsigned rr = 0U;
    unsigned ss = 0U;
    al[0] = (uint32_t)(a->slo & UINT64_C(0xFFFFFFFF));
    al[1] = (uint32_t)(a->slo >> 32);
    al[2] = (uint32_t)(a->shi & UINT64_C(0xFFFFFFFF));
    al[3] = (uint32_t)(a->shi >> 32);
    bl[0] = (uint32_t)(b->slo & UINT64_C(0xFFFFFFFF));
    bl[1] = (uint32_t)(b->slo >> 32);
    bl[2] = (uint32_t)(b->shi & UINT64_C(0xFFFFFFFF));
    bl[3] = (uint32_t)(b->shi >> 32);
    for (i = 0U; i < 8U; i++) {
        p[i] = UINT64_C(0);
    }
    for (i = 0U; i < 4U; i++) {
        uint64_t carry = UINT64_C(0);
        for (j = 0U; j < 4U; j++) {
            uint64_t t = p[i + j] + (uint64_t)al[i] * (uint64_t)bl[j] +
                carry;
            p[i + j] = t & UINT64_C(0xFFFFFFFF);
            carry = t >> 32;
        }
        p[i + 4U] += carry;
    }
    for (i = 0U; i < 7U; i++) {
        p[i + 1U] += p[i] >> 32;
        p[i] &= UINT64_C(0xFFFFFFFF);
    }
    /* The product of two 113-bit significands is 225 or 226 bits. */
    if (((p[7] >> 1) & UINT64_C(1)) != UINT64_C(0)) {
        bitlen = 226U;
    } else {
        bitlen = 225U;
    }
    shift = bitlen - 113U;
    *shi = UINT64_C(0);
    *slo = UINT64_C(0);
    for (i = 0U; i < 113U; i++) {
        unsigned bitpos = shift + i;
        unsigned limb = bitpos >> 5;
        unsigned bit =
            (unsigned)((p[limb] >> (bitpos & 31U)) & UINT64_C(1));
        if (i < 64U) {
            *slo |= (uint64_t)bit << i;
        } else {
            *shi |= (uint64_t)bit << (i - 64U);
        }
    }
    for (i = 0U; i < shift; i++) {
        unsigned limb = i >> 5;
        unsigned bit = (unsigned)((p[limb] >> (i & 31U)) & UINT64_C(1));
        if (i == shift - 1U) {
            gg = bit;
        } else if (shift >= 2U && i == shift - 2U) {
            rr = bit;
        } else {
            ss |= bit;
        }
    }
    *neg = a->neg ^ b->neg;
    *exp = a->exp + b->exp + ((bitlen == 226U) ? 1 : 0);
    *g = gg;
    *r = rr;
    *s = ss;
}

/* Quad NaN: SNaN wins (NV), else larger payload (tie rs1). */
static bool qq_nan2(uint64_t ahi, uint64_t alo, uint64_t bhi, uint64_t blo,
    uint64_t *ohi, uint64_t *olo, unsigned *nv)
{
    unsigned ca = qq_class(ahi, alo);
    unsigned cb = qq_class(bhi, blo);
    bool sa = ca == 5U;
    bool sb = cb == 5U;
    bool qa = ca == 4U;
    bool qb = cb == 4U;
    bool pick_a;
    if (!sa && !sb && !qa && !qb) {
        return false;
    }
    *nv = (sa || sb) ? 0x10U : 0U;
    if (sa || sb) {
        if (sa && sb) {
            pick_a = qq_payload_ge(ahi, alo, bhi, blo);
        } else {
            pick_a = sa;
        }
    } else if (qa && qb) {
        pick_a = qq_payload_ge(ahi, alo, bhi, blo);
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

static void qq_get(const sparc64_cpu_t *cpu, unsigned qi, uint64_t *hi,
    uint64_t *lo)
{
    *hi = cpu->fp.d[2U * qi];
    *lo = cpu->fp.d[2U * qi + 1U];
}

static void qq_put(sparc64_cpu_t *cpu, unsigned qi, uint64_t hi, uint64_t lo)
{
    cpu->fp.d[2U * qi] = hi;
    cpu->fp.d[2U * qi + 1U] = lo;
    sparc64_fp_mark_dirty(cpu, (qi >= 8U) ? 1U : 0U);
}

static void qq_put_inf(sparc64_cpu_t *cpu, unsigned qi, unsigned neg)
{
    qq_put(cpu, qi, ((uint64_t)neg << 63) | ((uint64_t)UINT64_C(0x7FFF) << 48),
        UINT64_C(0));
}

static void qq_put_allones(sparc64_cpu_t *cpu, unsigned qi)
{
    qq_put(cpu, qi, UINT64_C(0xFFFFFFFFFFFFFFFF),
        UINT64_C(0xFFFFFFFFFFFFFFFF));
}

/* Commit-first publish (R7-2): trap leaves dest/FCC/AEXC untouched. */
static sparc64_step_result_t qq_publish(sparc64_cpu_t *cpu, uint64_t pc,
    const sparc64_dec_t *d, unsigned fresh, unsigned qd, uint64_t hi,
    uint64_t lo)
{
    sparc64_step_result_t sr = qq_commit(cpu, pc, d, fresh);
    if (sr.kind != SPARC64_STEP_CONTINUE) {
        return sr;
    }
    qq_put(cpu, qd, hi, lo);
    return sr;
}

static sparc64_step_result_t qq_publish_inf(sparc64_cpu_t *cpu, uint64_t pc,
    const sparc64_dec_t *d, unsigned fresh, unsigned qd, unsigned neg)
{
    sparc64_step_result_t sr = qq_commit(cpu, pc, d, fresh);
    if (sr.kind != SPARC64_STEP_CONTINUE) {
        return sr;
    }
    qq_put_inf(cpu, qd, neg);
    return sr;
}

static sparc64_step_result_t qq_publish_ones(sparc64_cpu_t *cpu, uint64_t pc,
    const sparc64_dec_t *d, unsigned fresh, unsigned qd)
{
    sparc64_step_result_t sr = qq_commit(cpu, pc, d, fresh);
    if (sr.kind != SPARC64_STEP_CONTINUE) {
        return sr;
    }
    qq_put_allones(cpu, qd);
    return sr;
}

/* Quad operate: 0 add, 1 sub, 2 mul, with IEEE pre-screen. */
static sparc64_step_result_t qq_arith(sparc64_cpu_t *cpu, uint64_t pc,
    const sparc64_dec_t *d, unsigned op)
{
    unsigned qa = qq_qidx(d->rs1);
    unsigned qb = qq_qidx(d->raw & 31U);
    unsigned qd = qq_qidx(d->rd);
    uint64_t ahi;
    uint64_t alo;
    uint64_t bhi;
    uint64_t blo;
    unsigned ca;
    unsigned cb;
    unsigned aneg;
    unsigned bneg;
    int rm;
    qq_unp_t ua;
    qq_unp_t ub;
    unsigned neg = 0U;
    int exp = 0;
    uint64_t shi = UINT64_C(0);
    uint64_t slo = UINT64_C(0);
    unsigned g = 0U;
    unsigned r = 0U;
    unsigned s = 0U;
    bool iszero = false;
    uint64_t ohi;
    uint64_t olo;
    unsigned fl;
    if (qa > 15U || qb > 15U || qd > 15U) {
        return sparc64_trap(SPARC64_TRAP_ILLEGAL, pc, d->raw);
    }
    qq_get(cpu, qa, &ahi, &alo);
    qq_get(cpu, qb, &bhi, &blo);
    ca = qq_class(ahi, alo);
    cb = qq_class(bhi, blo);
    aneg = (unsigned)(ahi >> 63);
    bneg = (unsigned)(bhi >> 63);
    rm = qq_rd_mode(cpu);
    if (ca >= 4U || cb >= 4U) {
        if (!qq_nan2(ahi, alo, bhi, blo, &ohi, &olo, &fl)) {
            return sparc64_trap(SPARC64_TRAP_ILLEGAL, pc, d->raw);
        }
        return qq_publish(cpu, pc, d, fl, qd, ohi, olo);
    }
    if (op <= 1U) {
        unsigned eff = bneg ^ (op & 1U);
        if (ca == 3U && cb == 3U) {
            if (aneg == eff) {
                return qq_publish_inf(cpu, pc, d, 0U, qd, aneg);
            }
            return qq_publish_ones(cpu, pc, d, 0x10U, qd);
        }
        if (ca == 3U) {
            return qq_publish_inf(cpu, pc, d, 0U, qd, aneg);
        }
        if (cb == 3U) {
            return qq_publish_inf(cpu, pc, d, 0U, qd, eff);
        }
        if (ca == 0U && cb == 0U) {
            unsigned zn = (aneg == eff) ? aneg
                : ((rm == FE_DOWNWARD) ? 1U : 0U);
            return qq_publish(cpu, pc, d, 0U, qd, (uint64_t)zn << 63,
                UINT64_C(0));
        }
        if (ca == 0U) {
            return qq_publish(cpu, pc, d, 0U, qd,
                (op == 0U) ? bhi : bhi ^ UINT64_C(0x8000000000000000), blo);
        }
        if (cb == 0U) {
            return qq_publish(cpu, pc, d, 0U, qd, ahi, alo);
        }
        qq_unpack(ahi, alo, &ua);
        qq_unpack(bhi, blo, &ub);
        qq_addsub(&ua, &ub, op & 1U, &neg, &exp, &shi, &slo, &g, &r, &s,
            &iszero);
        if (iszero) {
            neg = (rm == FE_DOWNWARD) ? 1U : 0U;
        }
    } else if (op == 2U) {
        if ((ca == 3U && cb == 0U) || (cb == 3U && ca == 0U)) {
            return qq_publish_ones(cpu, pc, d, 0x10U, qd);
        }
        if (ca == 3U || cb == 3U) {
            return qq_publish_inf(cpu, pc, d, 0U, qd, aneg ^ bneg);
        }
        if (ca == 0U || cb == 0U) {
            return qq_publish(cpu, pc, d, 0U, qd,
                ((uint64_t)(aneg ^ bneg) << 63), UINT64_C(0));
        }
        qq_unpack(ahi, alo, &ua);
        qq_unpack(bhi, blo, &ub);
        qq_mul(&ua, &ub, &neg, &exp, &shi, &slo, &g, &r, &s);
    } else {
        return sparc64_fp_qdiv(cpu, pc, d);
    }
    fl = qq_pack(neg, exp, shi, slo, g, r, s, rm, &ohi, &olo);
    return qq_publish(cpu, pc, d, fl, qd, ohi, olo);
}

/* Unpack a finite nonzero double into 113-bit quad scale (exact). */
static void qq_unpack_d(uint64_t v, qq_unp_t *q)
{
    unsigned rawexp = (unsigned)((v >> 52) & UINT64_C(0x7FF));
    uint64_t frac = v & UINT64_C(0x000FFFFFFFFFFFFF);
    q->neg = (unsigned)(v >> 63);
    if (rawexp != 0U) {
        q->exp = (int)rawexp - 1023;
        q->shi = (frac >> 4) | (UINT64_C(1) << 48);
        q->slo = frac << 60;
        return;
    }
    q->exp = -1022;
    q->shi = frac >> 4;
    q->slo = frac << 60;
    while (((q->shi >> 48) & UINT64_C(1)) == UINT64_C(0)) {
        qq_shl(&q->shi, &q->slo, 1U);
        q->exp -= 1;
    }
}

/* Double class: 0 zero, 2 finite, 3 inf, 4 QNaN, 5 SNaN. */
static unsigned qq_dclass(uint64_t v)
{
    unsigned rawexp = (unsigned)((v >> 52) & UINT64_C(0x7FF));
    bool frac = (v & UINT64_C(0x000FFFFFFFFFFFFF)) != UINT64_C(0);
    if (rawexp == 0x7FFU) {
        if (!frac) {
            return 3U;
        }
        return ((v & UINT64_C(0x0008000000000000)) != UINT64_C(0)) ? 4U : 5U;
    }
    if (rawexp == 0U && !frac) {
        return 0U;
    }
    return 2U;
}

/* FDMULQ: double * double -> quad (exact; NaN/inf*0 invalid). */
static sparc64_step_result_t qq_fdmulq(sparc64_cpu_t *cpu, uint64_t pc,
    const sparc64_dec_t *d)
{
    unsigned da = qq_pair(d->rs1);
    unsigned db = qq_pair(d->raw & 31U);
    unsigned qd = qq_qidx(d->rd);
    uint64_t a = cpu->fp.d[da];
    uint64_t b = cpu->fp.d[db];
    unsigned ca = qq_dclass(a);
    unsigned cb = qq_dclass(b);
    unsigned aneg = (unsigned)(a >> 63);
    unsigned bneg = (unsigned)(b >> 63);
    qq_unp_t ua;
    qq_unp_t ub;
    unsigned neg = 0U;
    int exp = 0;
    uint64_t shi = UINT64_C(0);
    uint64_t slo = UINT64_C(0);
    unsigned g = 0U;
    unsigned r = 0U;
    unsigned s = 0U;
    int rm;
    uint64_t ohi;
    uint64_t olo;
    unsigned fl;
    if (qd > 15U) {
        return sparc64_trap(SPARC64_TRAP_ILLEGAL, pc, d->raw);
    }
    rm = qq_rd_mode(cpu);
    if (ca >= 4U || cb >= 4U) {
        bool sa = ca == 5U;
        bool sb = cb == 5U;
        bool pick_a;
        uint64_t w;
        if (sa || sb) {
            uint64_t af = a & UINT64_C(0x000FFFFFFFFFFFFF);
            uint64_t bf = b & UINT64_C(0x000FFFFFFFFFFFFF);
            fl = 0x10U;
            if (sa && sb) {
                pick_a = af >= bf;
            } else {
                pick_a = sa;
            }
            w = pick_a ? a : b;
            ohi = ((w >> 32) & UINT64_C(0x80000000)) != UINT64_C(0)
                ? UINT64_C(0xFFFF000000000000)
                : UINT64_C(0x7FFF000000000000);
            ohi |= (w & UINT64_C(0x000FFFFFFFFFFFFF)) >> 4;
            ohi |= UINT64_C(0x0000800000000000);
            olo = (w & UINT64_C(0x000FFFFFFFFFFFFF)) << 60;
        } else {
            uint64_t af = a & UINT64_C(0x000FFFFFFFFFFFFF);
            uint64_t bf = b & UINT64_C(0x000FFFFFFFFFFFFF);
            fl = 0U;
            if (ca == 4U && cb == 4U) {
                pick_a = af >= bf;
            } else {
                pick_a = ca == 4U;
            }
            w = pick_a ? a : b;
            ohi = ((w >> 32) & UINT64_C(0x80000000)) != UINT64_C(0)
                ? UINT64_C(0xFFFF000000000000)
                : UINT64_C(0x7FFF000000000000);
            ohi |= (w & UINT64_C(0x000FFFFFFFFFFFFF)) >> 4;
            olo = (w & UINT64_C(0x000FFFFFFFFFFFFF)) << 60;
        }
        return qq_publish(cpu, pc, d, fl, qd, ohi, olo);
    }
    if ((ca == 3U && cb == 0U) || (cb == 3U && ca == 0U)) {
        return qq_publish_ones(cpu, pc, d, 0x10U, qd);
    }
    if (ca == 3U || cb == 3U) {
        return qq_publish_inf(cpu, pc, d, 0U, qd, aneg ^ bneg);
    }
    if (ca == 0U || cb == 0U) {
        return qq_publish(cpu, pc, d, 0U, qd,
            ((uint64_t)(aneg ^ bneg) << 63), UINT64_C(0));
    }
    qq_unpack_d(a, &ua);
    qq_unpack_d(b, &ub);
    qq_mul(&ua, &ub, &neg, &exp, &shi, &slo, &g, &r, &s);
    fl = qq_pack(neg, exp, shi, slo, g, r, s, rm, &ohi, &olo);
    return qq_publish(cpu, pc, d, fl, qd, ohi, olo);
}

sparc64_step_result_t sparc64_fp_quad(sparc64_cpu_t *cpu, uint64_t pc,
    const sparc64_dec_t *d)
{
    switch (d->opf) {
    case 0x043U:
        return qq_arith(cpu, pc, d, 0U);
    case 0x047U:
        return qq_arith(cpu, pc, d, 1U);
    case 0x04BU:
        return qq_arith(cpu, pc, d, 2U);
    case 0x06EU:
        return qq_fdmulq(cpu, pc, d);
    default:
        return sparc64_trap(SPARC64_TRAP_ILLEGAL, pc, d->raw);
    }
}
