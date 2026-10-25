/*
 * src/interp/fp_sd.c — Phase 3 single/double arithmetic via explicit
 * integer cores.
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Single/double FADD/FSUB/FMUL/FDIV/FSQRT/FSMULD plus FDTOS, entered
 * from the fp.c dispatcher (sparc64_fp_sd). Every op is implemented
 * with integer bit manipulation (unpack, magnitude add/sub/mul/div/
 * isqrt, GRS pack with explicit FSR.RD rounding); the host floating
 * point environment is never consulted for values or flags, because
 * the toolchain does not honor <fenv.h> here (GCC reorders pure FP
 * ops across feclearexcept/fetestexcept and ignores fesetround, so
 * host cumulative flags always read back clear and directed modes
 * evaluate as nearest). All behavior below is verified bit-for-bit
 * against the qemu-sparc64 7.2.22 oracle:
 *
 * NaN rules (as in fp.c): SNaN arithmetic input sets NV and yields
 * the quieted NaN (larger payload first, tie: rs1); QNaN-only inputs
 * yield the larger-payload QNaN (tie: rs1), quietly; invalid non-NaN
 * results (0/0, inf-inf, inf*0, inf/inf, sqrt of negative) yield
 * all-ones with NV. x/0 (finite nonzero x) yields signed inf with DZ;
 * inf/0 yields signed inf quietly. Exact zero sums/differences yield
 * +0 except under RD toward -inf, which yields -0.
 *
 * Flags mirror the quad packer: overflow yields inf (or max-finite
 * under RD toward-zero/opposite-inf) with OF|NX; tiny results set UF
 * only when also inexact, plus NX whenever any discarded bit is set.
 * Single field s addresses fp.f[(s) ^ 1U] (see fp.c): the union
 * shares LE bytes while SPARC pairs even = HIGH.
 */

#include <fenv.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "core/cpu.h"
#include "interp/interp.h"

/* Double-pair index (mirrors fp.c): even field is the lower f-pair,
 * odd field the upper bank. */
static unsigned sd_pair(unsigned v)
{
    if ((v & 1U) != 0U) {
        return 16U + (v >> 1U);
    }
    return v >> 1U;
}

/* Rounding tag from FSR.RD (oracle map: 0 nearest-even, 1 toward-zero,
 * 2 toward-+inf, 3 toward--inf). Only reused as an integer tag; the
 * host rounding mode is never touched. */
static int sd_rd_mode(const sparc64_cpu_t *cpu)
{
    static const int modes[4] = {
        FE_TONEAREST, FE_TOWARDZERO, FE_UPWARD, FE_DOWNWARD
    };
    return modes[(cpu->fsr >> 30) & UINT64_C(3)];
}

static unsigned sd_rd_raw(const sparc64_cpu_t *cpu)
{
    return (unsigned)((cpu->fsr >> 30) & UINT64_C(3));
}

/* Commit one operate instruction's flags: cexc overwritten, aexc
 * sticky. A trapped (TEM & cexc) condition takes the generic
 * synchronous-trap path, like ILLEGAL. */
static sparc64_step_result_t sd_commit(sparc64_cpu_t *cpu, uint64_t pc,
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

static unsigned sd_clz64(uint64_t v)
{
    unsigned n = 0U;
    if (v == UINT64_C(0)) {
        return 64U;
    }
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

/* Unpacked finite value: neg sign, exp unbiased exponent of the hidden
 * bit position, sig P-bit significand with the hidden bit set at
 * position P - 1. Zero is represented with sig 0 (exp ignored). */
typedef struct sd_unp {
    unsigned neg;
    int exp;
    uint64_t sig;
} sd_unp_t;

/* Classify a raw pattern: 0 zero, 2 finite nonzero, 3 infinity,
 * 4 quiet NaN, 5 signaling NaN. Width selects single (0) / double. */
static unsigned sd_class(uint64_t u, unsigned w)
{
    unsigned eshift = (w == 0U) ? 23U : 52U;
    uint64_t emask = (w == 0U) ? UINT64_C(0xFF) : UINT64_C(0x7FF);
    uint64_t fmask = (w == 0U) ? UINT64_C(0x7FFFFF)
                               : UINT64_C(0x000FFFFFFFFFFFFF);
    uint64_t qbit = (w == 0U) ? UINT64_C(0x400000)
                              : UINT64_C(0x0008000000000000);
    unsigned rawexp = (unsigned)((u >> eshift) & emask);
    uint64_t frac = u & fmask;
    unsigned emax = (w == 0U) ? 0xFFU : 0x7FFU;
    if (rawexp == emax) {
        if (frac == UINT64_C(0)) {
            return 3U;
        }
        return ((u & qbit) != UINT64_C(0)) ? 4U : 5U;
    }
    if (rawexp == 0U && frac == UINT64_C(0)) {
        return 0U;
    }
    return 2U;
}

/* Unpack a finite-nonzero pattern (caller classifies first). P is the
 * significand width (24/53); emin the least normal exponent. */
static void sd_unpack(uint64_t u, unsigned w, unsigned p, int emin,
    sd_unp_t *q)
{
    unsigned eshift = (w == 0U) ? 23U : 52U;
    unsigned emask = (w == 0U) ? 0xFFU : 0x7FFU;
    uint64_t fmask = (w == 0U) ? UINT64_C(0x7FFFFF)
                               : UINT64_C(0x000FFFFFFFFFFFFF);
    int bias = (w == 0U) ? 127 : 1023;
    unsigned rawexp = (unsigned)((u >> eshift) & (uint64_t)emask);
    uint64_t frac = u & fmask;
    q->neg = (unsigned)(u >> ((w == 0U) ? 31U : 63U));
    if (rawexp == 0U) {
        unsigned top;
        unsigned shift;
        if (frac == UINT64_C(0)) {
            q->exp = emin;
            q->sig = UINT64_C(0);
            return;
        }
        top = 63U - sd_clz64(frac);
        shift = (p - 1U) - top;
        q->sig = frac << shift;
        q->exp = emin - (int)shift;
        return;
    }
    q->sig = frac | (UINT64_C(1) << (p - 1U));
    q->exp = (int)rawexp - bias;
}

/* Binary NaN propagation: SNaN input sets NV and yields the quieted
 * NaN (larger payload first, tie: rs1); QNaN-only inputs yield the
 * larger-payload QNaN (tie: rs1), quietly. Width selects single (0) /
 * double. Returns true when a NaN input was present. */
static bool sd_nan2(uint64_t a, uint64_t b, unsigned w, uint64_t *out,
    unsigned *nv)
{
    unsigned ca = sd_class(a, w);
    unsigned cb = sd_class(b, w);
    uint64_t fmask = (w == 0U) ? UINT64_C(0x7FFFFF)
                               : UINT64_C(0x000FFFFFFFFFFFFF);
    uint64_t qbit = (w == 0U) ? UINT64_C(0x400000)
                              : UINT64_C(0x0008000000000000);
    uint64_t fa = a & fmask;
    uint64_t fb = b & fmask;
    bool sa = ca == 5U;
    bool sb = cb == 5U;
    bool pick_a;
    uint64_t v;
    if (!sa && !sb && ca != 4U && cb != 4U) {
        return false;
    }
    *nv = (sa || sb) ? 0x10U : 0U;
    if (sa || sb) {
        if (sa && sb) {
            pick_a = fa >= fb;
        } else {
            pick_a = sa;
        }
    } else {
        if (ca == 4U && cb == 4U) {
            pick_a = fa >= fb;
        } else {
            pick_a = ca == 4U;
        }
    }
    v = pick_a ? a : b;
    *out = v | qbit;
    return true;
}

/* Unary NaN propagation (sqrt, and single-source moves use raw copy).
 * SNaN sets NV and quiets; QNaN propagates quietly. */
static bool sd_nan1(uint64_t a, unsigned w, uint64_t *out, unsigned *nv)
{
    unsigned ca = sd_class(a, w);
    uint64_t qbit = (w == 0U) ? UINT64_C(0x400000)
                              : UINT64_C(0x0008000000000000);
    if (ca != 4U && ca != 5U) {
        *nv = 0U;
        *out = a;
        return false;
    }
    *nv = (ca == 5U) ? 0x10U : 0U;
    *out = a | qbit;
    return true;
}

/* Round and pack: sig is a P-bit significand with the hidden bit at
 * P - 1, exp the unbiased exponent, g/r/s the guard/round/sticky bits.
 * Yields the encoded value and the cexc flags (OF|NX on overflow,
 * UF when tiny and inexact, NX whenever anything was discarded). */
static unsigned sd_pack(unsigned neg, int exp, uint64_t sig, unsigned g,
    unsigned r, unsigned s, unsigned p, int emin, int emax, int bias,
    int rm, uint64_t *out)
{
    unsigned lsb;
    bool up;
    bool inexact;
    bool tiny;
    unsigned eshift = (p == 24U) ? 23U : 52U;
    uint64_t fmask = (p == 24U) ? UINT64_C(0x7FFFFF)
                                : UINT64_C(0x000FFFFFFFFFFFFF);
    if (sig == UINT64_C(0) && g == 0U && r == 0U && s == 0U) {
        *out = (uint64_t)neg << ((p == 24U) ? 31U : 63U);
        return 0U;
    }
    if (((sig >> p) & UINT64_C(1)) != UINT64_C(0)) {
        s |= r;
        r = g;
        g = (unsigned)(sig & UINT64_C(1));
        sig >>= 1;
        exp += 1;
    } else if (sig != UINT64_C(0) &&
        (((sig >> (p - 1U)) & UINT64_C(1)) == UINT64_C(0))) {
        unsigned bitlen = 64U - sd_clz64(sig);
        unsigned k = p - bitlen;
        sig <<= k;
        exp -= (int)k;
    }
    if (exp < emin) {
        unsigned shift = (unsigned)(emin - exp);
        if (shift >= p + 3U) {
            sig = UINT64_C(0);
            g = 0U;
            r = 0U;
            s = 1U;
        } else {
            uint64_t keep = sig;
            unsigned g2 = (unsigned)((keep >> (shift - 1U)) & UINT64_C(1));
            unsigned r2 = (shift > 1U)
                ? (unsigned)((keep >> (shift - 2U)) & UINT64_C(1))
                : 0U;
            unsigned s2 = g | r | s;
            unsigned i;
            for (i = 0U; (shift > 2U) && (i < shift - 2U); i++) {
                s2 |= (unsigned)((keep >> i) & UINT64_C(1));
            }
            sig >>= shift;
            g = g2;
            r = r2;
            s = (s2 != 0U) ? 1U : 0U;
        }
        exp = emin;
    }
    lsb = (unsigned)(sig & UINT64_C(1));
    if (rm == FE_TONEAREST) {
        up = (g != 0U) && ((r != 0U) || (s != 0U) || (lsb != 0U));
    } else if (rm == FE_TOWARDZERO) {
        up = false;
    } else if (rm == FE_UPWARD) {
        up = neg == 0U;
    } else {
        up = neg != 0U;
    }
    if (up) {
        sig += UINT64_C(1);
        if (((sig >> p) & UINT64_C(1)) != UINT64_C(0)) {
            sig >>= 1;
            exp += 1;
        }
    }
    inexact = (g != 0U) || (r != 0U) || (s != 0U);
    tiny = (exp == emin) && (((sig >> (p - 1U)) & UINT64_C(1)) == UINT64_C(0));
    if (exp > emax) {
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
            *out = ((uint64_t)neg << ((p == 24U) ? 31U : 63U)) |
                ((uint64_t)((unsigned)(emax + 1 + bias)) << eshift);
        } else {
            *out = ((uint64_t)neg << ((p == 24U) ? 31U : 63U)) |
                ((uint64_t)((unsigned)(emax + bias)) << eshift) | fmask;
        }
        return 0x09U;
    }
    if (tiny || sig == UINT64_C(0)) {
        *out = ((uint64_t)neg << ((p == 24U) ? 31U : 63U)) |
            (sig & fmask);
    } else {
        *out = ((uint64_t)neg << ((p == 24U) ? 31U : 63U)) |
            ((uint64_t)((unsigned)(exp + bias)) << eshift) |
            (sig & fmask);
    }
    return (tiny && inexact ? 0x04U : 0U) | (inexact ? 0x01U : 0U);
}

/* 128-bit leading-zero count for the add/sub normalizer. */
static unsigned sd_clz128(__uint128_t v)
{
    uint64_t hi = (uint64_t)(v >> 64);
    if (hi != UINT64_C(0)) {
        return sd_clz64(hi);
    }
    return 64U + sd_clz64((uint64_t)v);
}

/* Magnitude add/sub of unpacked finite values (sub flips the second
 * sign). Produces a normalized (sig, g, r, s) tuple for sd_pack.
 * Exact zero results are +0 except under RD toward -inf (-0). */
static void sd_addsub(const sd_unp_t *a, const sd_unp_t *b, unsigned sub,
    unsigned p, int rd, unsigned *neg, int *exp, uint64_t *sig,
    unsigned *g, unsigned *r, unsigned *s)
{
    unsigned aneg = a->neg;
    unsigned bneg = b->neg ^ (sub & 1U);
    const sd_unp_t *hi = a;
    const sd_unp_t *lo = b;
    unsigned hneg = aneg;
    unsigned lneg = bneg;
    __uint128_t hs;
    __uint128_t ls = (__uint128_t)0;
    unsigned st = 0U;
    unsigned d = 0U;
    unsigned i;
    __uint128_t kept;
    if (b->exp > a->exp) {
        hi = b;
        lo = a;
        hneg = bneg;
        lneg = aneg;
    }
    hs = (__uint128_t)hi->sig;
    if (hi->exp != lo->exp) {
        d = (unsigned)(hi->exp - lo->exp);
    }
    kept = (__uint128_t)lo->sig;
    if (d >= 128U) {
        st = (lo->sig != UINT64_C(0)) ? 1U : 0U;
    } else {
        for (i = 0U; i < d; i++) {
            st |= (unsigned)(kept & (__uint128_t)1);
            kept >>= 1;
        }
        ls = kept;
    }
    *exp = hi->exp;
    if (hneg == lneg) {
        __uint128_t sum = hs + ls;
        if (((sum >> p) & (__uint128_t)1) != (__uint128_t)0) {
            *neg = hneg;
            *sig = (uint64_t)(sum >> 1);
            *g = (unsigned)(sum & (__uint128_t)1);
            *r = 0U;
            *s = st;
            *exp += 1;
        } else if (sum == (__uint128_t)0 && st == 0U) {
            *neg = hneg;
            *sig = UINT64_C(0);
            *g = 0U;
            *r = 0U;
            *s = 0U;
        } else {
            *neg = hneg;
            *sig = (uint64_t)sum;
            *g = 0U;
            *r = 0U;
            *s = st;
        }
        return;
    }
    if (hs == ls && st == 0U) {
        *neg = (rd == 3) ? 1U : 0U;
        *sig = UINT64_C(0);
        *g = 0U;
        *r = 0U;
        *s = 0U;
        return;
    }
    if (hs >= ls) {
        __uint128_t diff = hs - ls;
        unsigned bitlen = 128U - sd_clz128(diff);
        unsigned k = (diff == (__uint128_t)0) ? 0U : p - bitlen;
        diff <<= k;
        *exp -= (int)k;
        *neg = hneg;
        *sig = (uint64_t)diff;
        *g = 0U;
        *r = 0U;
        *s = st;
        return;
    }
    {
        __uint128_t diff = ls - hs;
        unsigned bitlen = 128U - sd_clz128(diff);
        unsigned k = p - bitlen;
        diff <<= k;
        *exp -= (int)k;
        *neg = lneg;
        *sig = (uint64_t)diff;
        *g = 0U;
        *r = 0U;
        *s = st;
    }
}

/* Divide unpacked finite nonzero values: long division to P + 3
 * quotient bits (sig P, guard, round, sticky-from-remainder). */
static void sd_div(const sd_unp_t *a, const sd_unp_t *b, unsigned p,
    unsigned *neg, int *exp, uint64_t *sig, unsigned *g, unsigned *r,
    unsigned *s)
{
    __uint128_t top = (__uint128_t)a->sig;
    __uint128_t bot = (__uint128_t)b->sig;
    __uint128_t dividend;
    __uint128_t quo;
    __uint128_t rem;
    int e;
    if (top < bot) {
        top <<= 1;
        e = a->exp - b->exp - 1;
    } else {
        e = a->exp - b->exp;
    }
    dividend = top << (p + 2U);
    quo = dividend / bot;
    rem = dividend % bot;
    *neg = a->neg ^ b->neg;
    *exp = e;
    *sig = (uint64_t)(quo >> 3);
    *g = (unsigned)((quo >> 2) & (__uint128_t)1);
    *r = (unsigned)((quo >> 1) & (__uint128_t)1);
    *s = ((((quo & (__uint128_t)1) != (__uint128_t)0) || (rem !=
        (__uint128_t)0)) ? 1U : 0U);
}

/* Integer square root: restoring binary sqrt over the even bit
 * positions down from top, remainder jammed into the sticky bit. */
static void sd_isqrt(__uint128_t n, unsigned top, uint64_t *root,
    unsigned *s)
{
    __uint128_t rr = (__uint128_t)0;
    __uint128_t rem = (__uint128_t)0;
    unsigned i = top;
    for (;;) {
        __uint128_t trial;
        rem = (rem << 2) | ((n >> i) & (__uint128_t)3);
        rr <<= 1;
        trial = (rr << 1) | (__uint128_t)1;
        if (rem >= trial) {
            rem -= trial;
            rr |= (__uint128_t)1;
        }
        if (i == 0U) {
            break;
        }
        i -= 2U;
    }
    *root = (uint64_t)rr;
    *s = (rem != (__uint128_t)0) ? 1U : 0U;
}

/* Square root of a finite nonzero positive value. With the P + 3
 * shift the radicand spans [2^(2P+2), 2^(2P+4)), so the root has
 * exactly P + 2 bits and splits into sig P + guard + round. */
static void sd_sqrt(const sd_unp_t *a, unsigned p, unsigned *neg, int *exp,
    uint64_t *sig, unsigned *g, unsigned *r, unsigned *s)
{
    __uint128_t top = (__uint128_t)a->sig;
    __uint128_t n;
    uint64_t root;
    unsigned ss;
    int e = a->exp;
    unsigned topbit = 2U * p + 2U;
    if ((e & 1) != 0) {
        top <<= 1;
        e -= 1;
    }
    n = top << (p + 3U);
    sd_isqrt(n, topbit, &root, &ss);
    *neg = a->neg;
    *exp = e / 2;
    *sig = root >> 2;
    *g = (unsigned)((root >> 1) & UINT64_C(1));
    *r = (unsigned)(root & UINT64_C(1));
    *s = ss;
}

/* Forward declarations: the op dispatcher precedes the mul core. */
static void sd_mul(const sd_unp_t *a, const sd_unp_t *b, unsigned p,
    unsigned *neg, int *exp, uint64_t *sig, unsigned *g, unsigned *r,
    unsigned *s);

/* All-ones result (invalid non-NaN): single 0x7FFFFFFF or double
 * 0x7FFFFFFFFFFFFFFF. */
static uint64_t sd_allones(unsigned w)
{
    return (w == 0U) ? UINT64_C(0x7FFFFFFF) : UINT64_C(0x7FFFFFFFFFFFFFFF);
}

static void sd_store(sparc64_cpu_t *cpu, unsigned w, unsigned field,
    uint64_t v)
{
    if (w == 0U) {
        cpu->fp.f[(field & 31U) ^ 1U] = (uint32_t)v;
    } else {
        cpu->fp.d[sd_pair(field)] = v;
    }
}

static uint64_t sd_load(const sparc64_cpu_t *cpu, unsigned w, unsigned field)
{
    if (w == 0U) {
        return (uint64_t)cpu->fp.f[(field & 31U) ^ 1U];
    }
    return cpu->fp.d[sd_pair(field)];
}

/* Add/sub/mul/div dispatcher over unpacked finite values with the
 * oracle's inf/zero edge rules. Op 0 add, 1 sub, 2 mul, 3 div. */
static sparc64_step_result_t sd_arith(sparc64_cpu_t *cpu, uint64_t pc,
    const sparc64_dec_t *d, unsigned w, unsigned op)
{
    uint64_t a = sd_load(cpu, w, d->rs1);
    uint64_t b = sd_load(cpu, w, d->raw & 31U);
    unsigned p = (w == 0U) ? 24U : 53U;
    int emin = (w == 0U) ? -126 : -1022;
    int emax = (w == 0U) ? 127 : 1023;
    int bias = (w == 0U) ? 127 : 1023;
    unsigned ca = sd_class(a, w);
    unsigned cb = sd_class(b, w);
    unsigned aneg = (unsigned)(a >> ((w == 0U) ? 31U : 63U));
    unsigned bneg = (unsigned)(b >> ((w == 0U) ? 31U : 63U));
    int rm = sd_rd_mode(cpu);
    int rd = (int)sd_rd_raw(cpu);
    sd_unp_t ua;
    sd_unp_t ub;
    unsigned neg = 0U;
    int exp = 0;
    uint64_t sig = UINT64_C(0);
    unsigned g = 0U;
    unsigned r = 0U;
    unsigned s = 0U;
    uint64_t o;
    unsigned fl;
    uint64_t rzero = (w == 0U) ? (uint64_t)((unsigned)(aneg ^ bneg ^ (op == 1U ? 1U : 0U)) << 31)
                               : ((uint64_t)(aneg ^ bneg ^ (op == 1U ? 1U : 0U)) << 63);
    if (ca >= 4U || cb >= 4U) {
        if (!sd_nan2(a, b, w, &o, &fl)) {
            return sparc64_trap(SPARC64_TRAP_ILLEGAL, pc, d->raw);
        }
        sd_store(cpu, w, d->rd, o);
        return sd_commit(cpu, pc, d, fl);
    }
    if (op <= 1U) {
        unsigned eff = bneg ^ (op & 1U);
        if (ca == 3U && cb == 3U && aneg != eff) {
            sd_store(cpu, w, d->rd, sd_allones(w));
            return sd_commit(cpu, pc, d, 0x10U);
        }
        if (ca == 3U || cb == 3U) {
            unsigned n = (ca == 3U) ? aneg : eff;
            o = (w == 0U) ? ((uint64_t)n << 31) | UINT64_C(0x7F800000)
                          : ((uint64_t)n << 63) | (UINT64_C(0x7FF) << 52);
            sd_store(cpu, w, d->rd, o);
            return sd_commit(cpu, pc, d, 0U);
        }
    } else if (op == 2U) {
        if ((ca == 3U && cb == 0U) || (ca == 0U && cb == 3U)) {
            sd_store(cpu, w, d->rd, sd_allones(w));
            return sd_commit(cpu, pc, d, 0x10U);
        }
        if (ca == 3U || cb == 3U) {
            unsigned n = aneg ^ bneg;
            o = (w == 0U) ? ((uint64_t)n << 31) | UINT64_C(0x7F800000)
                          : ((uint64_t)n << 63) | (UINT64_C(0x7FF) << 52);
            sd_store(cpu, w, d->rd, o);
            return sd_commit(cpu, pc, d, 0U);
        }
        if (ca == 0U || cb == 0U) {
            sd_store(cpu, w, d->rd, rzero);
            return sd_commit(cpu, pc, d, 0U);
        }
    } else {
        if ((ca == 0U && cb == 0U) || (ca == 3U && cb == 3U)) {
            sd_store(cpu, w, d->rd, sd_allones(w));
            return sd_commit(cpu, pc, d, 0x10U);
        }
        if (cb == 0U) {
            unsigned n = aneg ^ bneg;
            o = (w == 0U) ? ((uint64_t)n << 31) | UINT64_C(0x7F800000)
                          : ((uint64_t)n << 63) | (UINT64_C(0x7FF) << 52);
            if (ca == 3U) {
                sd_store(cpu, w, d->rd, o);
                return sd_commit(cpu, pc, d, 0U);
            }
            sd_store(cpu, w, d->rd, o);
            return sd_commit(cpu, pc, d, 0x02U);
        }
        if (ca == 3U || cb == 3U) {
            unsigned n = aneg ^ bneg;
            o = (ca == 3U)
                ? ((w == 0U) ? ((uint64_t)n << 31) | UINT64_C(0x7F800000)
                             : ((uint64_t)n << 63) | (UINT64_C(0x7FF) << 52))
                : rzero;
            sd_store(cpu, w, d->rd, o);
            return sd_commit(cpu, pc, d, 0U);
        }
        if (ca == 0U) {
            sd_store(cpu, w, d->rd, rzero);
            return sd_commit(cpu, pc, d, 0U);
        }
    }
    sd_unpack(a, w, p, emin, &ua);
    sd_unpack(b, w, p, emin, &ub);
    if (op <= 1U) {
        sd_addsub(&ua, &ub, op & 1U, p, rd, &neg, &exp, &sig, &g, &r, &s);
    } else if (op == 2U) {
        sd_mul(&ua, &ub, p, &neg, &exp, &sig, &g, &r, &s);
    } else {
        sd_div(&ua, &ub, p, &neg, &exp, &sig, &g, &r, &s);
    }
    fl = sd_pack(neg, exp, sig, g, r, s, p, emin, emax, bias, rm, &o);
    sd_store(cpu, w, d->rd, o);
    return sd_commit(cpu, pc, d, fl);
}

/* Multiply unpacked finite nonzero values. The product has at most
 * 2P bits; the top P feed sig (hidden at P - 1) with GRS below. */
static void sd_mul(const sd_unp_t *a, const sd_unp_t *b, unsigned p,
    unsigned *neg, int *exp, uint64_t *sig, unsigned *g, unsigned *r,
    unsigned *s)
{
    __uint128_t prod = (__uint128_t)a->sig * (__uint128_t)b->sig;
    __uint128_t smask;
    *neg = a->neg ^ b->neg;
    if (((prod >> (2U * p - 1U)) & (__uint128_t)1) != (__uint128_t)0) {
        *sig = (uint64_t)(prod >> p);
        *g = (unsigned)((prod >> (p - 1U)) & (__uint128_t)1);
        *r = (unsigned)((prod >> (p - 2U)) & (__uint128_t)1);
        smask = (((__uint128_t)1 << (p - 2U)) - (__uint128_t)1);
        *s = ((prod & smask) != (__uint128_t)0) ? 1U : 0U;
        *exp = a->exp + b->exp + 1;
    } else {
        *sig = (uint64_t)(prod >> (p - 1U));
        *g = (unsigned)((prod >> (p - 2U)) & (__uint128_t)1);
        *r = (unsigned)((prod >> (p - 3U)) & (__uint128_t)1);
        smask = (((__uint128_t)1 << (p - 3U)) - (__uint128_t)1);
        *s = ((prod & smask) != (__uint128_t)0) ? 1U : 0U;
        *exp = a->exp + b->exp;
    }
}

/* Square root with the oracle's edge rules. */
static sparc64_step_result_t sd_sqrt_op(sparc64_cpu_t *cpu, uint64_t pc,
    const sparc64_dec_t *d, unsigned w)
{
    uint64_t a = sd_load(cpu, w, d->raw & 31U);
    unsigned p = (w == 0U) ? 24U : 53U;
    int emin = (w == 0U) ? -126 : -1022;
    int emax = (w == 0U) ? 127 : 1023;
    int bias = (w == 0U) ? 127 : 1023;
    unsigned ca = sd_class(a, w);
    unsigned aneg = (unsigned)(a >> ((w == 0U) ? 31U : 63U));
    int rm = sd_rd_mode(cpu);
    sd_unp_t ua;
    unsigned neg = 0U;
    int exp = 0;
    uint64_t sig = UINT64_C(0);
    unsigned g = 0U;
    unsigned r = 0U;
    unsigned s = 0U;
    uint64_t o;
    unsigned fl;
    if (ca >= 4U) {
        if (!sd_nan1(a, w, &o, &fl)) {
            return sparc64_trap(SPARC64_TRAP_ILLEGAL, pc, d->raw);
        }
        sd_store(cpu, w, d->rd, o);
        return sd_commit(cpu, pc, d, fl);
    }
    if (aneg != 0U && ca != 0U) {
        sd_store(cpu, w, d->rd, sd_allones(w));
        return sd_commit(cpu, pc, d, 0x10U);
    }
    if (ca == 0U || ca == 3U) {
        sd_store(cpu, w, d->rd, a);
        return sd_commit(cpu, pc, d, 0U);
    }
    sd_unpack(a, w, p, emin, &ua);
    sd_sqrt(&ua, p, &neg, &exp, &sig, &g, &r, &s);
    fl = sd_pack(neg, exp, sig, g, r, s, p, emin, emax, bias, rm, &o);
    sd_store(cpu, w, d->rd, o);
    return sd_commit(cpu, pc, d, fl);
}

/* FSMULD: single * single -> double. The product needs at most 48
 * significand bits, so it is always exact; only NaN and inf*0 need
 * handling (invalid -> all-ones double + NV). A subnormal double
 * result sets UF. */
static sparc64_step_result_t sd_fsmuld(sparc64_cpu_t *cpu, uint64_t pc,
    const sparc64_dec_t *d)
{
    uint32_t a = cpu->fp.f[(d->rs1 & 31U) ^ 1U];
    uint32_t b = cpu->fp.f[(d->raw & 31U) ^ 1U];
    bool an = sd_class((uint64_t)a, 0U) >= 4U;
    bool bn = sd_class((uint64_t)b, 0U) >= 4U;
    bool az = ((a & UINT32_C(0x7FFFFFFF)) == UINT32_C(0));
    bool bz = ((b & UINT32_C(0x7FFFFFFF)) == UINT32_C(0));
    bool ai = ((a & UINT32_C(0x7FFFFFFF)) == UINT32_C(0x7F800000));
    bool bi = ((b & UINT32_C(0x7FFFFFFF)) == UINT32_C(0x7F800000));
    uint64_t r;
    if (an || bn) {
        uint64_t o;
        unsigned fl;
        uint64_t aw = (uint64_t)a;
        uint64_t bw = (uint64_t)b;
        if (!sd_nan2(aw, bw, 0U, &o, &fl)) {
            return sparc64_trap(SPARC64_TRAP_ILLEGAL, pc, d->raw);
        }
        r = ((o & UINT64_C(0x80000000)) << 32) |
            UINT64_C(0x7FF0000000000000) |
            ((o & UINT64_C(0x007FFFFF)) << 29);
        cpu->fp.d[sd_pair(d->rd)] = r;
        return sd_commit(cpu, pc, d, fl);
    }
    if ((ai && bz) || (az && bi)) {
        cpu->fp.d[sd_pair(d->rd)] = UINT64_C(0x7FFFFFFFFFFFFFFF);
        return sd_commit(cpu, pc, d, 0x10U);
    }
    if (ai || bi) {
        cpu->fp.d[sd_pair(d->rd)] =
            ((uint64_t)(((a ^ b) >> 31) & 1U) << 63) |
            (UINT64_C(0x7FF) << 52);
        return sd_commit(cpu, pc, d, 0U);
    }
    if (az || bz) {
        cpu->fp.d[sd_pair(d->rd)] =
            (uint64_t)(((a ^ b) >> 31) & 1U) << 63;
        return sd_commit(cpu, pc, d, 0U);
    }
    {
        sd_unp_t ua;
        sd_unp_t ub;
        unsigned neg;
        int exp;
        uint64_t sig;
        unsigned g;
        unsigned rr;
        unsigned ss;
        uint64_t o;
        unsigned fl;
        sd_unpack((uint64_t)a, 0U, 24U, -126, &ua);
        sd_unpack((uint64_t)b, 0U, 24U, -126, &ub);
        sd_mul(&ua, &ub, 24U, &neg, &exp, &sig, &g, &rr, &ss);
        fl = sd_pack(neg, exp, sig << 29, 0U, 0U, 0U, 53U, -1022,
            1023, 1023, sd_rd_mode(cpu), &o);
        cpu->fp.d[sd_pair(d->rd)] = o;
        return sd_commit(cpu, pc, d, fl);
    }
}

/* Double to single narrowing with explicit overflow/underflow: the
 * 53-bit significand splits into 24 bits + GRS without rounding. */
static sparc64_step_result_t sd_dtos(sparc64_cpu_t *cpu, uint64_t pc,
    const sparc64_dec_t *d)
{
    uint64_t a = cpu->fp.d[sd_pair(d->raw & 31U)];
    unsigned ca = sd_class(a, 1U);
    unsigned aneg = (unsigned)(a >> 63);
    int rm = sd_rd_mode(cpu);
    uint64_t o;
    unsigned fl;
    if (ca >= 4U) {
        uint64_t frac = a & UINT64_C(0x000FFFFFFFFFFFFF);
        bool quiet = ((a & UINT64_C(0x0008000000000000)) != UINT64_C(0));
        uint32_t r = (aneg << 31) | UINT32_C(0x7F800000) |
            (uint32_t)(frac >> 29);
        if (!quiet) {
            r |= UINT32_C(0x00400000);
            cpu->fp.f[(d->rd & 31U) ^ 1U] = r;
            return sd_commit(cpu, pc, d, 0x10U);
        }
        cpu->fp.f[(d->rd & 31U) ^ 1U] = r;
        return sd_commit(cpu, pc, d, 0U);
    }
    if (ca == 0U || ca == 3U) {
        uint32_t r = (aneg << 31) |
            ((ca == 3U) ? UINT32_C(0x7F800000) : UINT32_C(0));
        cpu->fp.f[(d->rd & 31U) ^ 1U] = r;
        return sd_commit(cpu, pc, d, 0U);
    }
    {
        sd_unp_t u;
        unsigned g;
        unsigned rr;
        unsigned ss;
        sd_unpack(a, 1U, 53U, -1022, &u);
        g = (unsigned)((u.sig >> 28) & UINT64_C(1));
        rr = (unsigned)((u.sig >> 27) & UINT64_C(1));
        ss = ((u.sig & (((UINT64_C(1) << 27) - UINT64_C(1)))) !=
            UINT64_C(0)) ? 1U : 0U;
        fl = sd_pack(u.neg, u.exp, u.sig >> 29, g, rr, ss, 24U,
            -126, 127, 127, rm, &o);
        cpu->fp.f[(d->rd & 31U) ^ 1U] = (uint32_t)o;
        return sd_commit(cpu, pc, d, fl);
    }
}

sparc64_step_result_t sparc64_fp_sd(sparc64_cpu_t *cpu, uint64_t pc,
    const sparc64_dec_t *d)
{
    switch (d->opf) {
    case 0x41U:
        return sd_arith(cpu, pc, d, 0U, 0U);
    case 0x45U:
        return sd_arith(cpu, pc, d, 0U, 1U);
    case 0x49U:
        return sd_arith(cpu, pc, d, 0U, 2U);
    case 0x4DU:
        return sd_arith(cpu, pc, d, 0U, 3U);
    case 0x42U:
        return sd_arith(cpu, pc, d, 1U, 0U);
    case 0x46U:
        return sd_arith(cpu, pc, d, 1U, 1U);
    case 0x4AU:
        return sd_arith(cpu, pc, d, 1U, 2U);
    case 0x4EU:
        return sd_arith(cpu, pc, d, 1U, 3U);
    case 0x29U:
        return sd_sqrt_op(cpu, pc, d, 0U);
    case 0x2AU:
        return sd_sqrt_op(cpu, pc, d, 1U);
    case 0x69U:
        return sd_fsmuld(cpu, pc, d);
    case 0x0C6U:
        return sd_dtos(cpu, pc, d);
    default:
        return sparc64_trap(SPARC64_TRAP_ILLEGAL, pc, d->raw);
    }
}
