/*
 * src/interp/fp_qconv.c — Phase 3 quad move/compare/convert interpreter.
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * FMOVQ/FNEGQ/FABSQ, FCMPQ/FCMPEQ, and the quad half of the conversion
 * matrix (FITOQ/FXTOQ/FQTOI/FQTOX/FSTOQ/FDTOQ/FQTOS/FQTOD) for the fp.c
 * dispatcher (sparc64_fp_qconv), verified against qemu-sparc64. Quad
 * slots go through d[2*i]/d[2*i+1]; narrowing honors RD with flags.
 * The small unpack/pack/commit helpers duplicate fp_quad.c on purpose:
 * every helper stays static and no shared header changes are needed.
 */

#include <fenv.h>
#include <stdint.h>
#include <string.h>

#include "core/cpu.h"
#include "interp/fp_commit.h"
#include "interp/interp.h"

#define QC_BIAS 16383
#define QC_EMAX 16383
#define QC_EMIN (-16382)

static unsigned qc_clz64(uint64_t x)
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

static void qc_shl(uint64_t *hi, uint64_t *lo, unsigned k)
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

static void qc_shr(uint64_t *hi, uint64_t *lo, unsigned k)
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

static unsigned qc_bit(uint64_t hi, uint64_t lo, unsigned i)
{
    if (i < 64U) {
        return (unsigned)((lo >> i) & UINT64_C(1));
    }
    return (unsigned)((hi >> (i - 64U)) & UINT64_C(1));
}

static unsigned qc_qidx(unsigned w)
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

static unsigned qc_pair(unsigned v)
{
    if ((v & 1U) != 0U) {
        return 16U + (v >> 1U);
    }
    return v >> 1U;
}

static int qc_rd_mode(const sparc64_cpu_t *cpu)
{
    static const int modes[4] = {
        FE_TONEAREST, FE_TOWARDZERO, FE_UPWARD, FE_DOWNWARD
    };
    return modes[(cpu->fsr >> 30) & UINT64_C(3)];
}

static sparc64_step_result_t qc_commit(sparc64_cpu_t *cpu, uint64_t pc,
    const sparc64_dec_t *d, unsigned fresh)
{
    return sparc64_fp_commit(cpu, pc, d, fresh);
}

static void qc_fcc_write(sparc64_cpu_t *cpu, unsigned idx, unsigned v)
{
    static const unsigned shifts[4] = { 10U, 32U, 34U, 36U };
    v &= 3U;
    idx &= 3U;
    cpu->fcc[idx] = (uint32_t)v;
    cpu->fsr = (cpu->fsr & ~((uint64_t)UINT64_C(3) << shifts[idx])) |
        ((uint64_t)v << shifts[idx]);
}

static unsigned qc_class(uint64_t hi, uint64_t lo)
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

typedef struct {
    unsigned neg;
    int exp;
    uint64_t shi;
    uint64_t slo;
} qc_unp_t;

static void qc_unpack(uint64_t hi, uint64_t lo, qc_unp_t *q)
{
    unsigned rawexp = (unsigned)((hi >> 48) & UINT64_C(0x7FFF));
    uint64_t fh = hi & UINT64_C(0xFFFFFFFFFFFF);
    unsigned lz;
    unsigned top;
    q->neg = (unsigned)(hi >> 63);
    if (rawexp != 0U) {
        q->exp = (int)rawexp - QC_BIAS;
        q->shi = fh | (UINT64_C(1) << 48);
        q->slo = lo;
        return;
    }
    q->exp = QC_EMIN;
    q->shi = fh;
    q->slo = lo;
    if (fh != UINT64_C(0)) {
        lz = qc_clz64(fh);
        top = 48U - (63U - lz);
        qc_shl(&q->shi, &q->slo, top);
        q->exp -= (int)top;
    } else if (lo != UINT64_C(0)) {
        lz = qc_clz64(lo);
        top = 112U - (63U - lz);
        qc_shl(&q->shi, &q->slo, top);
        q->exp -= (int)top;
    }
}

/* Round and pack into width-bit float (113/53/24). Quad callers pass
 * 113/QC_EMIN/QC_EMAX/QC_BIAS; narrowing passes the target format. */
static unsigned qc_pack(unsigned neg, int exp, uint64_t shi, uint64_t slo,
    unsigned g, unsigned r, unsigned s, unsigned width, int emin, int emax,
    int bias, int rm, uint64_t *ohi, uint64_t *olo)
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
        qc_shr(&shi, &slo, 1U);
        s = r | s;
        r = g;
        g = ng;
        exp += 1;
    } else if (((shi >> 48) & UINT64_C(1)) == UINT64_C(0)) {
        unsigned bitlen;
        unsigned k;
        if (shi != UINT64_C(0)) {
            bitlen = 128U - qc_clz64(shi);
        } else {
            bitlen = 64U - qc_clz64(slo);
        }
        k = 113U - bitlen;
        qc_shl(&shi, &slo, k);
        exp -= (int)k;
    }
    if (width < 113U) {
        unsigned shift = 113U - width;
        unsigned g2 = qc_bit(shi, slo, shift - 1U);
        unsigned r2 = (shift > 1U) ? qc_bit(shi, slo, shift - 2U) : 0U;
        unsigned s2 = g | r | s;
        unsigned i;
        for (i = 0U; (shift > 2U) && (i < shift - 2U); i++) {
            s2 |= qc_bit(shi, slo, i);
        }
        qc_shr(&shi, &slo, shift);
        g = g2;
        r = r2;
        s = (s2 != 0U) ? 1U : 0U;
    }
    if (exp < emin) {
        unsigned shift = (unsigned)(emin - exp);
        if (shift >= 113U) {
            shi = UINT64_C(0);
            slo = UINT64_C(0);
            g = 0U;
            r = 0U;
            s = 1U;
        } else {
            unsigned g2 = qc_bit(shi, slo, shift - 1U);
            unsigned r2 =
                (shift > 1U) ? qc_bit(shi, slo, shift - 2U) : 0U;
            unsigned s2 = g | r | s;
            unsigned i;
            for (i = 0U; (shift > 2U) && (i < shift - 2U); i++) {
                s2 |= qc_bit(shi, slo, i);
            }
            qc_shr(&shi, &slo, shift);
            g = g2;
            r = r2;
            s = (s2 != 0U) ? 1U : 0U;
        }
        exp = emin;
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
        if (width == 113U) {
            if ((shi >> 49) != UINT64_C(0)) {
                qc_shr(&shi, &slo, 1U);
                exp += 1;
            }
        } else if (width == 53U) {
            if (shi != UINT64_C(0) || (slo >> 53) != UINT64_C(0)) {
                qc_shr(&shi, &slo, 1U);
                exp += 1;
            }
        } else {
            if (shi != UINT64_C(0) || (slo >> 24) != UINT64_C(0)) {
                qc_shr(&shi, &slo, 1U);
                exp += 1;
            }
        }
    }
    inexact = (g != 0U) || (r != 0U) || (s != 0U);
    if (width == 113U) {
        tiny = (exp == emin) && (((shi >> 48) & UINT64_C(1)) == UINT64_C(0));
    } else if (width == 53U) {
        tiny = (exp == emin) && (slo < (UINT64_C(1) << 52));
    } else {
        tiny = (exp == emin) && (slo < (UINT64_C(1) << 23));
    }
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
        if (width == 113U) {
            if (to_inf) {
                *ohi = ((uint64_t)neg << 63) |
                    ((uint64_t)UINT64_C(0x7FFF) << 48);
                *olo = UINT64_C(0);
            } else {
                *ohi = ((uint64_t)neg << 63) |
                    ((uint64_t)(emax + bias) << 48) |
                    UINT64_C(0xFFFFFFFFFFFF);
                *olo = UINT64_C(0xFFFFFFFFFFFFFFFF);
            }
        } else if (width == 53U) {
            if (to_inf) {
                *ohi = UINT64_C(0);
                *olo = ((uint64_t)neg << 63) |
                    ((uint64_t)UINT64_C(0x7FF) << 52);
            } else {
                *ohi = UINT64_C(0);
                *olo = ((uint64_t)neg << 63) |
                    ((uint64_t)(emax + bias) << 52) |
                    UINT64_C(0xFFFFFFFFFFFFF);
            }
        } else {
            if (to_inf) {
                *ohi = UINT64_C(0);
                *olo = ((uint64_t)neg << 31) |
                    ((uint64_t)UINT64_C(0xFF) << 23);
            } else {
                *ohi = UINT64_C(0);
                *olo = ((uint64_t)neg << 31) |
                    ((uint64_t)(emax + bias) << 23) |
                    UINT64_C(0x7FFFFF);
            }
        }
        return 0x09U;
    }
    if (width == 113U) {
        if (tiny || ((shi == UINT64_C(0)) && (slo == UINT64_C(0)))) {
            *ohi = (uint64_t)neg << 63;
            *olo = slo;
        } else {
            *ohi = ((uint64_t)neg << 63) |
                ((uint64_t)(exp + bias) << 48) |
                (shi & UINT64_C(0xFFFFFFFFFFFF));
            *olo = slo;
        }
    } else if (width == 53U) {
        if (tiny || (slo == UINT64_C(0))) {
            *ohi = UINT64_C(0);
            *olo = ((uint64_t)neg << 63) | (slo & UINT64_C(0xFFFFFFFFFFFFF));
        } else {
            *ohi = UINT64_C(0);
            *olo = ((uint64_t)neg << 63) |
                ((uint64_t)(exp + bias) << 52) |
                (slo & UINT64_C(0xFFFFFFFFFFFFF));
        }
    } else {
        uint32_t f = (uint32_t)(slo & UINT64_C(0x7FFFFF));
        if (tiny || (slo == UINT64_C(0))) {
            *ohi = UINT64_C(0);
            *olo = ((uint64_t)neg << 31) | (uint64_t)f;
        } else {
            *ohi = UINT64_C(0);
            *olo = ((uint64_t)neg << 31) |
                ((uint64_t)(uint64_t)(exp + bias) << 23) | (uint64_t)f;
        }
    }
    return (tiny && inexact ? 0x04U : 0U) | (inexact ? 0x01U : 0U);
}

static void qc_get(const sparc64_cpu_t *cpu, unsigned qi, uint64_t *hi,
    uint64_t *lo)
{
    *hi = cpu->fp.d[2U * qi];
    *lo = cpu->fp.d[2U * qi + 1U];
}

static void qc_put(sparc64_cpu_t *cpu, unsigned qi, uint64_t hi, uint64_t lo)
{
    cpu->fp.d[2U * qi] = hi;
    cpu->fp.d[2U * qi + 1U] = lo;
    sparc64_fp_mark_dirty(cpu, (qi >= 8U) ? 1U : 0U);
}

/* Commit-first publish paths (R7-2): the shared helper runs before the
 * destination publishes, so a trapped exception leaves dest/FCC/AEXC
 * untouched; FPRS dirty bits ride inside qc_put. */
static sparc64_step_result_t qc_publish(sparc64_cpu_t *cpu, uint64_t pc,
    const sparc64_dec_t *d, unsigned fresh, unsigned qd, uint64_t hi,
    uint64_t lo)
{
    sparc64_step_result_t sr = qc_commit(cpu, pc, d, fresh);
    if (sr.kind != SPARC64_STEP_CONTINUE) {
        return sr;
    }
    qc_put(cpu, qd, hi, lo);
    return sr;
}

static sparc64_step_result_t qc_publish_i32(sparc64_cpu_t *cpu, uint64_t pc,
    const sparc64_dec_t *d, unsigned fresh, uint32_t r)
{
    sparc64_step_result_t sr = qc_commit(cpu, pc, d, fresh);
    if (sr.kind != SPARC64_STEP_CONTINUE) {
        return sr;
    }
    cpu->fp.f[(d->rd & 31U) ^ 1U] = r;
    sparc64_fp_mark_dirty(cpu, 0U);
    return sr;
}

static sparc64_step_result_t qc_publish_i64(sparc64_cpu_t *cpu, uint64_t pc,
    const sparc64_dec_t *d, unsigned fresh, uint64_t r)
{
    sparc64_step_result_t sr = qc_commit(cpu, pc, d, fresh);
    if (sr.kind != SPARC64_STEP_CONTINUE) {
        return sr;
    }
    cpu->fp.d[qc_pair(d->rd)] = r;
    sparc64_fp_mark_dirty(cpu, (qc_pair(d->rd) >= 16U) ? 1U : 0U);
    return sr;
}

/* Quad data movement: raw copy, sign flip, sign clear. An operate
 * instruction: overwrites cexc (no flags raised), aexc sticky. */
static sparc64_step_result_t qc_move(sparc64_cpu_t *cpu, uint64_t pc,
    const sparc64_dec_t *d, unsigned op)
{
    unsigned qs = qc_qidx(d->raw & 31U);
    unsigned qd = qc_qidx(d->rd);
    uint64_t hi;
    uint64_t lo;
    if (qs > 15U || qd > 15U) {
        return sparc64_trap(SPARC64_TRAP_ILLEGAL, pc, d->raw);
    }
    qc_get(cpu, qs, &hi, &lo);
    if (op == 1U) {
        hi ^= UINT64_C(0x8000000000000000);
    } else if (op == 2U) {
        hi &= ~UINT64_C(0x8000000000000000);
    }
    return qc_publish(cpu, pc, d, 0U, qd, hi, lo);
}

static unsigned qc_ordered(uint64_t ahi, uint64_t alo, uint64_t bhi,
    uint64_t blo)
{
    uint64_t ma_hi = ahi & UINT64_C(0x7FFFFFFFFFFFFFFF);
    uint64_t mb_hi = bhi & UINT64_C(0x7FFFFFFFFFFFFFFF);
    bool az = (ma_hi == UINT64_C(0)) && (alo == UINT64_C(0));
    bool bz = (mb_hi == UINT64_C(0)) && (blo == UINT64_C(0));
    bool sa = ((ahi >> 63) != UINT64_C(0));
    bool sb = ((bhi >> 63) != UINT64_C(0));
    int c;
    if (az && bz) {
        return 0U;
    }
    if (sa != sb) {
        return sa ? 1U : 2U;
    }
    if (ma_hi != mb_hi) {
        c = (ma_hi < mb_hi) ? -1 : 1;
    } else if (alo != blo) {
        c = (alo < blo) ? -1 : 1;
    } else {
        c = 0;
    }
    if (sa) {
        return (c < 0) ? 2U : ((c > 0) ? 1U : 0U);
    }
    return (c < 0) ? 1U : ((c > 0) ? 2U : 0U);
}

static sparc64_step_result_t qc_cmp(sparc64_cpu_t *cpu, uint64_t pc,
    const sparc64_dec_t *d, unsigned cmpe)
{
    unsigned qa = qc_qidx(d->rs1);
    unsigned qb = qc_qidx(d->raw & 31U);
    uint64_t ahi;
    uint64_t alo;
    uint64_t bhi;
    uint64_t blo;
    unsigned ca;
    unsigned cb;
    unsigned fcc = 3U;
    unsigned nv = 0U;
    if (qa > 15U || qb > 15U) {
        return sparc64_trap(SPARC64_TRAP_ILLEGAL, pc, d->raw);
    }
    qc_get(cpu, qa, &ahi, &alo);
    qc_get(cpu, qb, &bhi, &blo);
    ca = qc_class(ahi, alo);
    cb = qc_class(bhi, blo);
    if (ca >= 4U || cb >= 4U) {
        if (cmpe != 0U || ca == 5U || cb == 5U) {
            nv = 0x10U;
        }
    } else {
        fcc = qc_ordered(ahi, alo, bhi, blo);
    }
    {
        sparc64_step_result_t sr = qc_commit(cpu, pc, d, nv);
        if (sr.kind != SPARC64_STEP_CONTINUE) {
            return sr;
        }
        qc_fcc_write(cpu, d->rd, fcc);
        return sr;
    }
}

/* Signed integer to quad (exact, FSR untouched). */
static sparc64_step_result_t qc_itoq(sparc64_cpu_t *cpu, uint64_t pc,
    const sparc64_dec_t *d, int64_t v)
{
    unsigned qd = qc_qidx(d->rd);
    unsigned neg;
    uint64_t mag;
    unsigned bitlen;
    unsigned shift;
    uint64_t shi;
    uint64_t slo;
    int exp;
    if (qd > 15U) {
        return sparc64_trap(SPARC64_TRAP_ILLEGAL, pc, d->raw);
    }
    if (v == 0) {
        return qc_publish(cpu, pc, d, 0U, qd, UINT64_C(0), UINT64_C(0));
    }
    neg = (v < 0) ? 1U : 0U;
    mag = (neg != 0U) ? (uint64_t)(-(v + 1)) + UINT64_C(1) : (uint64_t)v;
    bitlen = 64U - qc_clz64(mag);
    exp = (int)(bitlen - 1U);
    shift = 112U - (bitlen - 1U);
    if (shift >= 64U) {
        shi = mag << (shift - 64U);
        slo = UINT64_C(0);
    } else {
        shi = mag >> (64U - shift);
        slo = mag << shift;
    }
    return qc_publish(cpu, pc, d, 0U, qd,
        ((uint64_t)neg << 63) | ((uint64_t)(exp + QC_BIAS) << 48) |
            (shi & UINT64_C(0xFFFFFFFFFFFF)),
        slo);
}

/* Quad to integer (bits 32/64): truncate, NX when inexact, NV + OF
 * with saturation when NaN or out of range. */
static sparc64_step_result_t qc_qtoi(sparc64_cpu_t *cpu, uint64_t pc,
    const sparc64_dec_t *d, unsigned bits)
{
    unsigned qs = qc_qidx(d->raw & 31U);
    uint64_t ahi;
    uint64_t alo;
    unsigned ca;
    unsigned neg;
    int exp;
    unsigned limit;
    uint64_t shi;
    uint64_t slo;
    uint64_t t;
    bool inexact = false;
    unsigned fl;
    if (qs > 15U) {
        return sparc64_trap(SPARC64_TRAP_ILLEGAL, pc, d->raw);
    }
    qc_get(cpu, qs, &ahi, &alo);
    ca = qc_class(ahi, alo);
    neg = (unsigned)(ahi >> 63);
    limit = (bits == 32U) ? 31U : 63U;
    if (ca == 0U) {
        if (bits == 32U) {
            return qc_publish_i32(cpu, pc, d, 0U, UINT32_C(0));
        }
        return qc_publish_i64(cpu, pc, d, 0U, UINT64_C(0));
    }
    if (ca >= 4U) {
        if (bits == 32U) {
            return qc_publish_i32(cpu, pc, d, 0x10U,
                (neg != 0U) ? UINT32_C(0x80000000) : UINT32_C(0x7FFFFFFF));
        }
        return qc_publish_i64(cpu, pc, d, 0x10U, (neg != 0U)
            ? UINT64_C(0x8000000000000000)
            : UINT64_C(0x7FFFFFFFFFFFFFFF));
    }
    exp = (int)((ahi >> 48) & UINT64_C(0x7FFF));
    exp = (exp == 0) ? QC_EMIN : exp - QC_BIAS;
    if (exp > (int)limit) {
        if (bits == 32U) {
            return qc_publish_i32(cpu, pc, d, 0x10U,
                (neg != 0U) ? UINT32_C(0x80000000) : UINT32_C(0x7FFFFFFF));
        }
        return qc_publish_i64(cpu, pc, d, 0x10U, (neg != 0U)
            ? UINT64_C(0x8000000000000000)
            : UINT64_C(0x7FFFFFFFFFFFFFFF));
    }
    if (exp == (int)limit) {
        /* Truncation toward zero keeps -2^limit whenever the integer
         * part is exactly 2^limit (top `limit` fraction bits clear);
         * a nonzero fraction then sets NX alone (S64-R7-32). */
        uint64_t fh = ahi & UINT64_C(0xFFFFFFFFFFFF);
        if ((neg != 0U) && (bits == 32U) &&
            ((fh >> 17) == UINT64_C(0))) {
            bool inx = ((fh & UINT64_C(0x1FFFF)) != UINT64_C(0)) ||
                (alo != UINT64_C(0));
            return qc_publish_i32(cpu, pc, d, inx ? 0x01U : 0U,
                UINT32_C(0x80000000));
        }
        if ((neg != 0U) && (bits != 32U) && (fh == UINT64_C(0)) &&
            ((alo >> 49) == UINT64_C(0))) {
            bool inx = alo != UINT64_C(0);
            return qc_publish_i64(cpu, pc, d, inx ? 0x01U : 0U,
                UINT64_C(0x8000000000000000));
        }
        if (bits == 32U) {
            return qc_publish_i32(cpu, pc, d, 0x10U,
                (neg != 0U) ? UINT32_C(0x80000000) : UINT32_C(0x7FFFFFFF));
        }
        return qc_publish_i64(cpu, pc, d, 0x10U, (neg != 0U)
            ? UINT64_C(0x8000000000000000)
            : UINT64_C(0x7FFFFFFFFFFFFFFF));
    }
    /* Finite value with exp < limit <= 63 < 112: pure right shift. */
    shi = ahi & UINT64_C(0xFFFFFFFFFFFF);
    if (((ahi >> 48) & UINT64_C(0x7FFF)) != UINT64_C(0)) {
        shi |= UINT64_C(1) << 48;
    }
    slo = alo;
    {
        unsigned shift = (unsigned)(112 - exp);
        unsigned i;
        uint64_t dhi = shi;
        uint64_t dlo = slo;
        if (shift >= 128U) {
            t = UINT64_C(0);
            inexact = true;
        } else {
            for (i = 0U; i < shift; i++) {
                unsigned b = (i < 64U)
                    ? (unsigned)((dlo >> i) & UINT64_C(1))
                    : (unsigned)((dhi >> (i - 64U)) & UINT64_C(1));
                inexact = inexact || (b != 0U);
            }
            qc_shr(&dhi, &dlo, shift);
            t = dlo;
        }
    }
    fl = inexact ? 0x01U : 0U;
    if (bits == 32U) {
        uint32_t r = (neg != 0U) ? (uint32_t)(0U - (uint32_t)t)
                                 : (uint32_t)t;
        return qc_publish_i32(cpu, pc, d, fl, r);
    }
    {
        uint64_t r = (neg != 0U) ? (UINT64_C(0) - t) : t;
        return qc_publish_i64(cpu, pc, d, fl, r);
    }
}

/* Single to quad widening (exact; SNaN sets NV and quiets). */
static sparc64_step_result_t qc_fstoq(sparc64_cpu_t *cpu, uint64_t pc,
    const sparc64_dec_t *d)
{
    unsigned qd = qc_qidx(d->rd);
    uint32_t a = cpu->fp.f[(d->raw & 31U) ^ 1U];
    unsigned neg = (a >> 31) & 1U;
    unsigned rawexp = (a >> 23) & UINT32_C(0xFF);
    uint32_t frac = a & UINT32_C(0x7FFFFF);
    uint64_t ohi;
    int exp;
    if (qd > 15U) {
        return sparc64_trap(SPARC64_TRAP_ILLEGAL, pc, d->raw);
    }
    if (rawexp == 0xFFU) {
        if (frac == UINT32_C(0)) {
            return qc_publish(cpu, pc, d, 0U, qd,
                ((uint64_t)neg << 63) |
                    ((uint64_t)UINT64_C(0x7FFF) << 48),
                UINT64_C(0));
        }
        ohi = ((uint64_t)neg << 63) | ((uint64_t)UINT64_C(0x7FFF) << 48) |
            ((uint64_t)frac << 25);
        if ((frac & UINT32_C(0x400000)) == UINT32_C(0)) {
            ohi |= UINT64_C(0x0000800000000000);
            return qc_publish(cpu, pc, d, 0x10U, qd, ohi, UINT64_C(0));
        }
        return qc_publish(cpu, pc, d, 0U, qd, ohi, UINT64_C(0));
    }
    if (rawexp == 0U && frac == UINT32_C(0)) {
        return qc_publish(cpu, pc, d, 0U, qd, (uint64_t)neg << 63,
            UINT64_C(0));
    }
    if (rawexp == 0U) {
        unsigned bitlen = 64U - qc_clz64((uint64_t)frac);
        unsigned p = bitlen - 1U;
        exp = (int)p - 149;
        frac = (frac << (23U - p)) & UINT32_C(0x7FFFFF);
    } else {
        exp = (int)rawexp - 127;
    }
    ohi = ((uint64_t)neg << 63) | ((uint64_t)(exp + QC_BIAS) << 48) |
        ((uint64_t)frac << 25);
    return qc_publish(cpu, pc, d, 0U, qd, ohi, UINT64_C(0));
}

/* Double to quad widening (exact; SNaN sets NV and quiets). */
static sparc64_step_result_t qc_fdtoq(sparc64_cpu_t *cpu, uint64_t pc,
    const sparc64_dec_t *d)
{
    unsigned qd = qc_qidx(d->rd);
    uint64_t a = cpu->fp.d[qc_pair(d->raw & 31U)];
    unsigned neg = (unsigned)(a >> 63);
    unsigned rawexp = (unsigned)((a >> 52) & UINT64_C(0x7FF));
    uint64_t frac = a & UINT64_C(0x000FFFFFFFFFFFFF);
    uint64_t ohi;
    uint64_t olo;
    int exp;
    if (qd > 15U) {
        return sparc64_trap(SPARC64_TRAP_ILLEGAL, pc, d->raw);
    }
    if (rawexp == 0x7FFU) {
        if (frac == UINT64_C(0)) {
            return qc_publish(cpu, pc, d, 0U, qd,
                ((uint64_t)neg << 63) |
                    ((uint64_t)UINT64_C(0x7FFF) << 48),
                UINT64_C(0));
        }
        ohi = ((uint64_t)neg << 63) | ((uint64_t)UINT64_C(0x7FFF) << 48) |
            (frac >> 4);
        olo = frac << 60;
        if ((frac & UINT64_C(0x0008000000000000)) == UINT64_C(0)) {
            ohi |= UINT64_C(0x0000800000000000);
            return qc_publish(cpu, pc, d, 0x10U, qd, ohi, olo);
        }
        return qc_publish(cpu, pc, d, 0U, qd, ohi, olo);
    }
    if (rawexp == 0U && frac == UINT64_C(0)) {
        return qc_publish(cpu, pc, d, 0U, qd, (uint64_t)neg << 63,
            UINT64_C(0));
    }
    if (rawexp == 0U) {
        unsigned bitlen = 64U - qc_clz64(frac);
        unsigned p = bitlen - 1U;
        exp = (int)p - 1074;
        frac = (frac << (52U - p)) & UINT64_C(0x000FFFFFFFFFFFFF);
    } else {
        exp = (int)rawexp - 1023;
    }
    ohi = ((uint64_t)neg << 63) | ((uint64_t)(exp + QC_BIAS) << 48) |
        (frac >> 4);
    olo = frac << 60;
    return qc_publish(cpu, pc, d, 0U, qd, ohi, olo);
}

/* Quad narrowing to single/double: NaN narrows the payload (SNaN sets
 * NV and quiets); otherwise round per RD with flags. */
static sparc64_step_result_t qc_qton(sparc64_cpu_t *cpu, uint64_t pc,
    const sparc64_dec_t *d, unsigned bits)
{
    unsigned qs = qc_qidx(d->raw & 31U);
    uint64_t ahi;
    uint64_t alo;
    unsigned ca;
    unsigned neg;
    unsigned width;
    int emin;
    int emax;
    int bias;
    int rm;
    qc_unp_t u;
    uint64_t ohi;
    uint64_t olo;
    unsigned fl;
    if (qs > 15U) {
        return sparc64_trap(SPARC64_TRAP_ILLEGAL, pc, d->raw);
    }
    qc_get(cpu, qs, &ahi, &alo);
    ca = qc_class(ahi, alo);
    neg = (unsigned)(ahi >> 63);
    width = (bits == 32U) ? 24U : 53U;
    emin = (bits == 32U) ? -126 : -1022;
    emax = (bits == 32U) ? 127 : 1023;
    bias = (bits == 32U) ? 127 : 1023;
    rm = qc_rd_mode(cpu);
    if (ca >= 4U) {
        uint64_t fh = ahi & UINT64_C(0xFFFFFFFFFFFF);
        bool quiet = ((ahi & UINT64_C(0x0000800000000000)) != UINT64_C(0));
        if (bits == 32U) {
            uint32_t r = (neg << 31) | UINT32_C(0x7F800000) |
                (uint32_t)(fh >> 25);
            if (!quiet) {
                r |= UINT32_C(0x00400000);
            }
            return qc_publish_i32(cpu, pc, d, !quiet ? 0x10U : 0U, r);
        }
        olo = ((uint64_t)neg << 63) | ((uint64_t)UINT64_C(0x7FF) << 52) |
            ((fh << 4) | (alo >> 60));
        if (!quiet) {
            olo |= UINT64_C(0x0008000000000000);
        }
        return qc_publish_i64(cpu, pc, d, !quiet ? 0x10U : 0U, olo);
    }
    if (ca == 0U) {
        if (bits == 32U) {
            return qc_publish_i32(cpu, pc, d, 0U, neg << 31);
        }
        return qc_publish_i64(cpu, pc, d, 0U, (uint64_t)neg << 63);
    }
    if (ca == 3U) {
        if (bits == 32U) {
            return qc_publish_i32(cpu, pc, d, 0U,
                (neg << 31) | UINT32_C(0x7F800000));
        }
        return qc_publish_i64(cpu, pc, d, 0U,
            ((uint64_t)neg << 63) | (UINT64_C(0x7FF) << 52));
    }
    qc_unpack(ahi, alo, &u);
    fl = qc_pack(u.neg, u.exp, u.shi, u.slo, 0U, 0U, 0U, width, emin, emax,
        bias, rm, &ohi, &olo);
    if (bits == 32U) {
        return qc_publish_i32(cpu, pc, d, fl, (uint32_t)olo);
    }
    return qc_publish_i64(cpu, pc, d, fl, olo);
}

sparc64_step_result_t sparc64_fp_qconv(sparc64_cpu_t *cpu, uint64_t pc,
    const sparc64_dec_t *d)
{
    int64_t v;
    switch (d->opf) {
    case 0x003U:
        return qc_move(cpu, pc, d, 0U);
    case 0x007U:
        return qc_move(cpu, pc, d, 1U);
    case 0x00BU:
        return qc_move(cpu, pc, d, 2U);
    case 0x053U:
        return qc_cmp(cpu, pc, d, 0U);
    case 0x057U:
        return qc_cmp(cpu, pc, d, 1U);
    case 0x0CCU:
        return qc_itoq(cpu, pc, d, (int64_t)(int32_t)cpu->fp.f[(d->raw & 31U) ^ 1U]);
    case 0x08CU:
        memcpy(&v, &cpu->fp.d[qc_pair(d->raw & 31U)], sizeof(v));
        return qc_itoq(cpu, pc, d, v);
    case 0x0D3U:
        return qc_qtoi(cpu, pc, d, 32U);
    case 0x083U:
        return qc_qtoi(cpu, pc, d, 64U);
    case 0x0CDU:
        return qc_fstoq(cpu, pc, d);
    case 0x0CEU:
        return qc_fdtoq(cpu, pc, d);
    case 0x0C7U:
        return qc_qton(cpu, pc, d, 32U);
    case 0x0CBU:
        return qc_qton(cpu, pc, d, 64U);
    default:
        return sparc64_trap(SPARC64_TRAP_ILLEGAL, pc, d->raw);
    }
}
