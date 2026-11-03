/*
 * src/interp/fp_qdiv.c — Phase 3 quad divide/square-root interpreter.
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * FDIVQ/FSQRTQ for the fp.c dispatcher (sparc64_fp_qdiv), also entered
 * from fp_quad.c's add/sub/mul handler for op 3. Integer
 * bit-manipulation core (115-bit restoring divide, 115-step restoring
 * square root) with correct rounding, verified against qemu-sparc64.
 * The small unpack/pack/commit helpers duplicate fp_quad.c on purpose:
 * every helper stays static and no shared header changes are needed.
 */

#include <fenv.h>
#include <stdint.h>
#include <string.h>

#include "core/cpu.h"
#include "interp/fp_commit.h"
#include "interp/interp.h"

#define QD_BIAS 16383
#define QD_EMAX 16383
#define QD_EMIN (-16382)

static unsigned qd_clz64(uint64_t x)
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

static void qd_shl(uint64_t *hi, uint64_t *lo, unsigned k)
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

static void qd_shr(uint64_t *hi, uint64_t *lo, unsigned k)
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

static unsigned qd_bit(uint64_t hi, uint64_t lo, unsigned i)
{
    if (i < 64U) {
        return (unsigned)((lo >> i) & UINT64_C(1));
    }
    return (unsigned)((hi >> (i - 64U)) & UINT64_C(1));
}

static unsigned qd_qidx(unsigned w)
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

static int qd_rd_mode(const sparc64_cpu_t *cpu)
{
    static const int modes[4] = {
        FE_TONEAREST, FE_TOWARDZERO, FE_UPWARD, FE_DOWNWARD
    };
    return modes[(cpu->fsr >> 30) & UINT64_C(3)];
}

static sparc64_step_result_t qd_commit(sparc64_cpu_t *cpu, uint64_t pc,
    const sparc64_dec_t *d, unsigned fresh)
{
    return sparc64_fp_commit(cpu, pc, d, fresh);
}

static unsigned qd_class(uint64_t hi, uint64_t lo)
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

static bool qd_payload_ge(uint64_t ahi, uint64_t alo, uint64_t bhi,
    uint64_t blo)
{
    uint64_t af = ahi & UINT64_C(0xFFFFFFFFFFFF);
    uint64_t bf = bhi & UINT64_C(0xFFFFFFFFFFFF);
    if (af != bf) {
        return af > bf;
    }
    return alo >= blo;
}

typedef struct {
    unsigned neg;
    int exp;
    uint64_t shi;
    uint64_t slo;
} qd_unp_t;

static void qd_unpack(uint64_t hi, uint64_t lo, qd_unp_t *q)
{
    unsigned rawexp = (unsigned)((hi >> 48) & UINT64_C(0x7FFF));
    uint64_t fh = hi & UINT64_C(0xFFFFFFFFFFFF);
    unsigned lz;
    unsigned top;
    q->neg = (unsigned)(hi >> 63);
    if (rawexp != 0U) {
        q->exp = (int)rawexp - QD_BIAS;
        q->shi = fh | (UINT64_C(1) << 48);
        q->slo = lo;
        return;
    }
    q->exp = QD_EMIN;
    q->shi = fh;
    q->slo = lo;
    if (fh != UINT64_C(0)) {
        lz = qd_clz64(fh);
        top = 48U - (63U - lz);
        qd_shl(&q->shi, &q->slo, top);
        q->exp -= (int)top;
    } else if (lo != UINT64_C(0)) {
        lz = qd_clz64(lo);
        top = 112U - (63U - lz);
        qd_shl(&q->shi, &q->slo, top);
        q->exp -= (int)top;
    }
}

static unsigned qd_pack(unsigned neg, int exp, uint64_t shi, uint64_t slo,
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
        qd_shr(&shi, &slo, 1U);
        s = r | s;
        r = g;
        g = ng;
        exp += 1;
    } else if (((shi >> 48) & UINT64_C(1)) == UINT64_C(0)) {
        unsigned bitlen;
        unsigned k;
        if (shi != UINT64_C(0)) {
            bitlen = 128U - qd_clz64(shi);
        } else {
            bitlen = 64U - qd_clz64(slo);
        }
        k = 113U - bitlen;
        qd_shl(&shi, &slo, k);
        exp -= (int)k;
    }
    if (exp < QD_EMIN) {
        unsigned shift = (unsigned)(QD_EMIN - exp);
        if (shift >= 113U) {
            /* Value is below one output ulp: keep exact GRS and round. */
            unsigned gg = 0U;
            unsigned rr = 0U;
            unsigned ss = g | r | s;
            if (shift == 113U) {
                gg = (unsigned)((shi >> 48) & UINT64_C(1));
                rr = (unsigned)((shi >> 47) & UINT64_C(1));
                ss |= (unsigned)(((shi & UINT64_C(0xFFFFFFFFFFFF)) !=
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
            unsigned g2 = qd_bit(shi, slo, shift - 1U);
            unsigned r2 =
                (shift > 1U) ? qd_bit(shi, slo, shift - 2U) : 0U;
            unsigned s2 = g | r | s;
            unsigned i;
            for (i = 0U; (shift > 2U) && (i < shift - 2U); i++) {
                s2 |= qd_bit(shi, slo, i);
            }
            qd_shr(&shi, &slo, shift);
            g = g2;
            r = r2;
            s = (s2 != 0U) ? 1U : 0U;
        }
        exp = QD_EMIN;
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
            qd_shr(&shi, &slo, 1U);
            exp += 1;
        }
    }
    inexact = (g != 0U) || (r != 0U) || (s != 0U);
    tiny = (exp == QD_EMIN) && (((shi >> 48) & UINT64_C(1)) == UINT64_C(0));
    if (exp > QD_EMAX) {
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
                ((uint64_t)(QD_EMAX + QD_BIAS) << 48) |
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
            ((uint64_t)(exp + QD_BIAS) << 48) |
            (shi & UINT64_C(0xFFFFFFFFFFFF));
        *olo = slo;
    }
    return (tiny && inexact ? 0x04U : 0U) | (inexact ? 0x01U : 0U);
}

static bool qd_nan2(uint64_t ahi, uint64_t alo, uint64_t bhi, uint64_t blo,
    uint64_t *ohi, uint64_t *olo, unsigned *nv)
{
    unsigned ca = qd_class(ahi, alo);
    unsigned cb = qd_class(bhi, blo);
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
            pick_a = qd_payload_ge(ahi, alo, bhi, blo);
        } else {
            pick_a = sa;
        }
    } else if (qa && qb) {
        pick_a = qd_payload_ge(ahi, alo, bhi, blo);
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

static bool qd_nan1(uint64_t ahi, uint64_t alo, uint64_t *ohi,
    uint64_t *olo, unsigned *nv)
{
    unsigned ca = qd_class(ahi, alo);
    if (ca != 4U && ca != 5U) {
        return false;
    }
    *ohi = ahi;
    *olo = alo;
    if (ca == 5U) {
        *nv = 0x10U;
        *ohi |= UINT64_C(0x0000800000000000);
    } else {
        *nv = 0U;
    }
    return true;
}

static void qd_get(const sparc64_cpu_t *cpu, unsigned qi, uint64_t *hi,
    uint64_t *lo)
{
    *hi = cpu->fp.d[2U * qi];
    *lo = cpu->fp.d[2U * qi + 1U];
}

static void qd_put(sparc64_cpu_t *cpu, unsigned qi, uint64_t hi, uint64_t lo)
{
    cpu->fp.d[2U * qi] = hi;
    cpu->fp.d[2U * qi + 1U] = lo;
    sparc64_fp_mark_dirty(cpu, (qi >= 8U) ? 1U : 0U);
}

static void qd_put_inf(sparc64_cpu_t *cpu, unsigned qi, unsigned neg)
{
    qd_put(cpu, qi, ((uint64_t)neg << 63) | ((uint64_t)UINT64_C(0x7FFF) << 48),
        UINT64_C(0));
}

static void qd_put_allones(sparc64_cpu_t *cpu, unsigned qi)
{
    qd_put(cpu, qi, UINT64_C(0xFFFFFFFFFFFFFFFF),
        UINT64_C(0xFFFFFFFFFFFFFFFF));
}

/* Commit-first publish paths (R7-2): the shared helper runs before the
 * destination publishes, so a trapped exception leaves dest/FCC/AEXC
 * untouched; FPRS dirty bits ride inside qd_put. */
static sparc64_step_result_t qd_publish(sparc64_cpu_t *cpu, uint64_t pc,
    const sparc64_dec_t *d, unsigned fresh, unsigned qd, uint64_t hi,
    uint64_t lo)
{
    sparc64_step_result_t sr = qd_commit(cpu, pc, d, fresh);
    if (sr.kind != SPARC64_STEP_CONTINUE) {
        return sr;
    }
    qd_put(cpu, qd, hi, lo);
    return sr;
}

static sparc64_step_result_t qd_publish_inf(sparc64_cpu_t *cpu, uint64_t pc,
    const sparc64_dec_t *d, unsigned fresh, unsigned qd, unsigned neg)
{
    sparc64_step_result_t sr = qd_commit(cpu, pc, d, fresh);
    if (sr.kind != SPARC64_STEP_CONTINUE) {
        return sr;
    }
    qd_put_inf(cpu, qd, neg);
    return sr;
}

static sparc64_step_result_t qd_publish_ones(sparc64_cpu_t *cpu, uint64_t pc,
    const sparc64_dec_t *d, unsigned fresh, unsigned qd)
{
    sparc64_step_result_t sr = qd_commit(cpu, pc, d, fresh);
    if (sr.kind != SPARC64_STEP_CONTINUE) {
        return sr;
    }
    qd_put_allones(cpu, qd);
    return sr;
}

static void qd_div(const qd_unp_t *a, const qd_unp_t *b, unsigned *neg,
    int *exp, uint64_t *shi, uint64_t *slo, unsigned *g, unsigned *r,
    unsigned *s)
{
    uint32_t dv[8];
    uint32_t ds[4];
    uint32_t rem[4];
    uint32_t quo[4];
    uint32_t t32[8];
    int i;
    unsigned k;
    unsigned carry;
    uint64_t w;
    bool ge;
    unsigned kk;
    uint64_t borrow;
    uint64_t tt;
    dv[0] = (uint32_t)(a->slo & UINT64_C(0xFFFFFFFF));
    dv[1] = (uint32_t)(a->slo >> 32);
    dv[2] = (uint32_t)(a->shi & UINT64_C(0xFFFFFFFF));
    dv[3] = (uint32_t)((a->shi >> 32) & UINT64_C(0xFFFFFFFF));
    t32[0] = UINT32_C(0);
    t32[1] = UINT32_C(0);
    t32[2] = UINT32_C(0);
    t32[3] = dv[0];
    t32[4] = dv[1];
    t32[5] = dv[2];
    t32[6] = dv[3];
    t32[7] = UINT32_C(0);
    carry = 0U;
    for (k = 0U; k < 8U; k++) {
        w = ((uint64_t)t32[k] << 18) | (uint64_t)carry;
        dv[k] = (uint32_t)(w & UINT64_C(0xFFFFFFFF));
        carry = (unsigned)(w >> 32);
    }
    ds[0] = (uint32_t)(b->slo & UINT64_C(0xFFFFFFFF));
    ds[1] = (uint32_t)(b->slo >> 32);
    ds[2] = (uint32_t)(b->shi & UINT64_C(0xFFFFFFFF));
    ds[3] = (uint32_t)((b->shi >> 32) & UINT64_C(0xFFFFFFFF));
    for (k = 0U; k < 4U; k++) {
        rem[k] = UINT32_C(0);
        quo[k] = UINT32_C(0);
    }
    for (i = 226; i >= 0; i--) {
        unsigned bitpos = (unsigned)i;
        unsigned bit =
            (unsigned)((dv[bitpos >> 5] >> (bitpos & 31U)) & UINT32_C(1));
        unsigned c = 0U;
        for (k = 0U; k < 4U; k++) {
            unsigned nk =
                (unsigned)(((uint64_t)rem[k] << 1) | c) & UINT32_C(0xFFFFFFFF);
            c = (unsigned)(((uint64_t)rem[k] << 1) >> 32);
            rem[k] = nk;
        }
        rem[0] |= bit;
        ge = false;
        for (kk = 4U; kk > 0U; kk--) {
            if (rem[kk - 1U] != ds[kk - 1U]) {
                ge = rem[kk - 1U] > ds[kk - 1U];
                break;
            }
            if (kk == 1U) {
                ge = true;
            }
        }
        if (ge) {
            borrow = UINT64_C(0);
            for (kk = 0U; kk < 4U; kk++) {
                tt = (uint64_t)rem[kk] - (uint64_t)ds[kk] - borrow;
                rem[kk] = (uint32_t)(tt & UINT64_C(0xFFFFFFFF));
                borrow = (tt >> 63) & UINT64_C(1);
            }
            if (i < 128) {
                quo[(unsigned)i >> 5] |= UINT32_C(1) << ((unsigned)i & 31U);
            }
        }
    }
    *neg = a->neg ^ b->neg;
    if (((quo[3] >> 18) & UINT32_C(1)) != UINT32_C(0)) {
        *slo = ((uint64_t)(quo[0] >> 2)) | ((uint64_t)quo[1] << 30) |
            ((uint64_t)(quo[2] & UINT32_C(3)) << 62);
        *shi = (((uint64_t)(quo[2] >> 2)) | ((uint64_t)quo[3] << 30)) &
            UINT64_C(0x0001FFFFFFFFFFFF);
        *g = (quo[0] >> 1) & UINT32_C(1);
        *r = quo[0] & UINT32_C(1);
        *exp = a->exp - b->exp;
    } else {
        unsigned c = 0U;
        *slo = ((uint64_t)(quo[0] >> 1)) | ((uint64_t)quo[1] << 31) |
            ((uint64_t)(quo[2] & UINT32_C(1)) << 63);
        *shi = (((uint64_t)(quo[2] >> 1)) | ((uint64_t)quo[3] << 31)) &
            UINT64_C(0x0001FFFFFFFFFFFF);
        *g = quo[0] & UINT32_C(1);
        for (k = 0U; k < 4U; k++) {
            unsigned nk =
                (unsigned)(((uint64_t)rem[k] << 1) | c) & UINT32_C(0xFFFFFFFF);
            c = (unsigned)(((uint64_t)rem[k] << 1) >> 32);
            rem[k] = nk;
        }
        ge = false;
        for (kk = 4U; kk > 0U; kk--) {
            if (rem[kk - 1U] != ds[kk - 1U]) {
                ge = rem[kk - 1U] > ds[kk - 1U];
                break;
            }
            if (kk == 1U) {
                ge = true;
            }
        }
        if (ge) {
            borrow = UINT64_C(0);
            for (kk = 0U; kk < 4U; kk++) {
                tt = (uint64_t)rem[kk] - (uint64_t)ds[kk] - borrow;
                rem[kk] = (uint32_t)(tt & UINT64_C(0xFFFFFFFF));
                borrow = (tt >> 63) & UINT64_C(1);
            }
            *r = 1U;
        } else {
            *r = 0U;
        }
        *exp = a->exp - b->exp - 1;
    }
    *s = ((rem[0] | rem[1] | rem[2] | rem[3]) != UINT32_C(0)) ? 1U : 0U;
}

static sparc64_step_result_t qd_divide(sparc64_cpu_t *cpu, uint64_t pc,
    const sparc64_dec_t *d)
{
    unsigned qa = qd_qidx(d->rs1);
    unsigned qb = qd_qidx(d->raw & 31U);
    unsigned qd = qd_qidx(d->rd);
    uint64_t ahi;
    uint64_t alo;
    uint64_t bhi;
    uint64_t blo;
    unsigned ca;
    unsigned cb;
    unsigned aneg;
    unsigned bneg;
    int rm;
    qd_unp_t ua;
    qd_unp_t ub;
    unsigned neg = 0U;
    int exp = 0;
    uint64_t shi = UINT64_C(0);
    uint64_t slo = UINT64_C(0);
    unsigned g = 0U;
    unsigned r = 0U;
    unsigned s = 0U;
    uint64_t ohi;
    uint64_t olo;
    unsigned fl;
    if (qa > 15U || qb > 15U || qd > 15U) {
        return sparc64_trap(SPARC64_TRAP_ILLEGAL, pc, d->raw);
    }
    qd_get(cpu, qa, &ahi, &alo);
    qd_get(cpu, qb, &bhi, &blo);
    ca = qd_class(ahi, alo);
    cb = qd_class(bhi, blo);
    aneg = (unsigned)(ahi >> 63);
    bneg = (unsigned)(bhi >> 63);
    rm = qd_rd_mode(cpu);
    if (ca >= 4U || cb >= 4U) {
        if (!qd_nan2(ahi, alo, bhi, blo, &ohi, &olo, &fl)) {
            return sparc64_trap(SPARC64_TRAP_ILLEGAL, pc, d->raw);
        }
        return qd_publish(cpu, pc, d, fl, qd, ohi, olo);
    }
    if ((ca == 0U && cb == 0U) || (ca == 3U && cb == 3U)) {
        return qd_publish_ones(cpu, pc, d, 0x10U, qd);
    }
    if (ca == 3U) {
        /* Infinite numerator (including inf/0): exact infinity, no flags. */
        return qd_publish_inf(cpu, pc, d, 0U, qd, aneg ^ bneg);
    }
    if (cb == 0U) {
        return qd_publish_inf(cpu, pc, d, 0x02U, qd, aneg ^ bneg);
    }
    if (ca == 0U || cb == 3U) {
        return qd_publish(cpu, pc, d, 0U, qd,
            ((uint64_t)(aneg ^ bneg) << 63), UINT64_C(0));
    }
    qd_unpack(ahi, alo, &ua);
    qd_unpack(bhi, blo, &ub);
    qd_div(&ua, &ub, &neg, &exp, &shi, &slo, &g, &r, &s);
    fl = qd_pack(neg, exp, shi, slo, g, r, s, rm, &ohi, &olo);
    return qd_publish(cpu, pc, d, fl, qd, ohi, olo);
}

static void qd_isqrt(const uint32_t n[8], uint32_t r[4], uint32_t rem[4])
{
    int i;
    unsigned k;
    for (k = 0U; k < 4U; k++) {
        r[k] = UINT32_C(0);
        rem[k] = UINT32_C(0);
    }
    for (i = 114; i >= 0; i--) {
        unsigned b0pos = 2U * (unsigned)i;
        unsigned b1pos = b0pos + 1U;
        unsigned b0 =
            (unsigned)((n[b0pos >> 5] >> (b0pos & 31U)) & UINT32_C(1));
        unsigned b1 =
            (unsigned)((n[b1pos >> 5] >> (b1pos & 31U)) & UINT32_C(1));
        unsigned c = 0U;
        uint32_t t[4];
        bool ge = false;
        unsigned kk;
        uint64_t borrow;
        for (k = 0U; k < 4U; k++) {
            uint64_t w = ((uint64_t)rem[k] << 2) | (uint64_t)c;
            rem[k] = (uint32_t)(w & UINT64_C(0xFFFFFFFF));
            c = (unsigned)(w >> 32);
        }
        rem[0] |= (uint32_t)(b0 | (b1 << 1));
        c = 0U;
        for (k = 0U; k < 4U; k++) {
            uint64_t w = ((uint64_t)r[k] << 1) | (uint64_t)c;
            r[k] = (uint32_t)(w & UINT64_C(0xFFFFFFFF));
            c = (unsigned)(w >> 32);
        }
        c = 1U;
        for (k = 0U; k < 4U; k++) {
            uint64_t w = ((uint64_t)r[k] << 1) | (uint64_t)c;
            t[k] = (uint32_t)(w & UINT64_C(0xFFFFFFFF));
            c = (unsigned)(w >> 32);
        }
        for (kk = 4U; kk > 0U; kk--) {
            if (rem[kk - 1U] != t[kk - 1U]) {
                ge = rem[kk - 1U] > t[kk - 1U];
                break;
            }
            if (kk == 1U) {
                ge = true;
            }
        }
        if (ge) {
            borrow = UINT64_C(0);
            for (kk = 0U; kk < 4U; kk++) {
                uint64_t w =
                    (uint64_t)rem[kk] - (uint64_t)t[kk] - borrow;
                rem[kk] = (uint32_t)(w & UINT64_C(0xFFFFFFFF));
                borrow = (w >> 63) & UINT64_C(1);
            }
            r[0] |= UINT32_C(1);
        }
    }
}

static void qd_sqrt_core(const qd_unp_t *a, unsigned *neg, int *exp,
    uint64_t *shi, uint64_t *slo, unsigned *g, unsigned *r, unsigned *s)
{
    uint32_t n[8];
    uint32_t rt[4];
    uint32_t rem[4];
    unsigned k;
    unsigned sh = ((a->exp & 1) != 0) ? 21U : 20U;
    unsigned carry = 0U;
    uint64_t w;
    n[0] = UINT32_C(0);
    n[1] = UINT32_C(0);
    n[2] = UINT32_C(0);
    n[3] = (uint32_t)(a->slo & UINT64_C(0xFFFFFFFF));
    n[4] = (uint32_t)(a->slo >> 32);
    n[5] = (uint32_t)(a->shi & UINT64_C(0xFFFFFFFF));
    n[6] = (uint32_t)((a->shi >> 32) & UINT64_C(0xFFFFFFFF));
    n[7] = UINT32_C(0);
    for (k = 0U; k < 8U; k++) {
        w = ((uint64_t)n[k] << sh) | (uint64_t)carry;
        n[k] = (uint32_t)(w & UINT64_C(0xFFFFFFFF));
        carry = (unsigned)(w >> 32);
    }
    qd_isqrt(n, rt, rem);
    *slo = ((uint64_t)(rt[0] >> 2)) | ((uint64_t)rt[1] << 30) |
        ((uint64_t)(rt[2] & UINT32_C(3)) << 62);
    *shi = (((uint64_t)(rt[2] >> 2)) | ((uint64_t)rt[3] << 30)) &
        UINT64_C(0x0001FFFFFFFFFFFF);
    *g = (rt[0] >> 1) & UINT32_C(1);
    *r = rt[0] & UINT32_C(1);
    *s = ((rem[0] | rem[1] | rem[2] | rem[3]) != UINT32_C(0)) ? 1U : 0U;
    *exp = ((a->exp & 1) != 0) ? (a->exp - 1) / 2 : a->exp / 2;
    *neg = 0U;
}

static sparc64_step_result_t qd_sqrt(sparc64_cpu_t *cpu, uint64_t pc,
    const sparc64_dec_t *d)
{
    unsigned qs = qd_qidx(d->raw & 31U);
    unsigned qd = qd_qidx(d->rd);
    uint64_t ahi;
    uint64_t alo;
    unsigned ca;
    unsigned aneg;
    int rm;
    qd_unp_t ua;
    unsigned neg = 0U;
    int exp = 0;
    uint64_t shi = UINT64_C(0);
    uint64_t slo = UINT64_C(0);
    unsigned g = 0U;
    unsigned r = 0U;
    unsigned s = 0U;
    uint64_t ohi;
    uint64_t olo;
    unsigned fl;
    if (qs > 15U || qd > 15U) {
        return sparc64_trap(SPARC64_TRAP_ILLEGAL, pc, d->raw);
    }
    qd_get(cpu, qs, &ahi, &alo);
    ca = qd_class(ahi, alo);
    aneg = (unsigned)(ahi >> 63);
    rm = qd_rd_mode(cpu);
    if (ca == 4U || ca == 5U) {
        if (!qd_nan1(ahi, alo, &ohi, &olo, &fl)) {
            return sparc64_trap(SPARC64_TRAP_ILLEGAL, pc, d->raw);
        }
        return qd_publish(cpu, pc, d, fl, qd, ohi, olo);
    }
    if (aneg != 0U && ca != 0U) {
        return qd_publish_ones(cpu, pc, d, 0x10U, qd);
    }
    if (ca == 0U) {
        return qd_publish(cpu, pc, d, 0U, qd, ahi, alo);
    }
    if (ca == 3U) {
        return qd_publish_inf(cpu, pc, d, 0U, qd, 0U);
    }
    qd_unpack(ahi, alo, &ua);
    qd_sqrt_core(&ua, &neg, &exp, &shi, &slo, &g, &r, &s);
    fl = qd_pack(neg, exp, shi, slo, g, r, s, rm, &ohi, &olo);
    return qd_publish(cpu, pc, d, fl, qd, ohi, olo);
}

sparc64_step_result_t sparc64_fp_qdiv(sparc64_cpu_t *cpu, uint64_t pc,
    const sparc64_dec_t *d)
{
    if (d->opf == 0x04FU) {
        return qd_divide(cpu, pc, d);
    }
    if (d->opf == 0x02BU) {
        return qd_sqrt(cpu, pc, d);
    }
    return sparc64_trap(SPARC64_TRAP_ILLEGAL, pc, d->raw);
}
