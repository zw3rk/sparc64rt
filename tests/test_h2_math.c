/*
 * tests/test_h2_math.c -- Phase 7 libc-test math battery (lane H2).
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Static-glibc SPARC64 guest exercising libm (sqrt, sin, cos, exp,
 * log, pow, floor, ceil, fmod, fabs, float variants, isnan/isinf).
 * Inexact checks use tight tolerances; exact functions use ==.
 * Computed values print in %a (exact hex float) so oracle, interp,
 * and dbt outputs are bit-for-bit comparable. Exit status is 0 iff
 * every check passed.
 *
 * Build (debian:stable-slim container, from the worktree root):
 *   docker exec sparc64rt-h2 sh -c 'cd /w && mkdir -p _build \
 *     && sparc64-linux-gnu-gcc -static -O2 -o _build/guest_h2_math \
 *       tests/test_h2_math.c -lm'
 * Oracle: qemu-sparc64 ./_build/guest_h2_math
 *
 * Expected stdout tail: H2-MATH-PASS (full golden recorded in
 * docs/h2-report.md, which also pins every %a line).
 */

#include <math.h>
#include <stdio.h>

static int failures = 0;

static void check(const char *label, int ok)
{
    if (ok) {
        (void)printf("%s-OK\n", label);
    } else {
        (void)printf("%s-FAIL\n", label);
        failures++;
    }
}

static double dabs(double v)
{
    return (v < 0.0) ? -v : v;
}

int main(void)
{
    double s2;
    double s;
    double c;
    double e1;
    double l1;
    double pw;
    float s2f;

    s2 = sqrt(2.0);
    (void)printf("sqrt2=%a\n", s2);
    check("SQRT", dabs(s2 - 1.4142135623730951) < 1e-15 &&
        dabs(s2 * s2 - 2.0) < 1e-15);

    s = sin(0.5);
    c = cos(0.5);
    (void)printf("sincos=%a,%a\n", s, c);
    check("SINCOS", dabs(s * s + c * c - 1.0) < 2e-16 &&
        dabs(s - 0.4794255386042030) < 1e-15 &&
        dabs(c - 0.8775825618903728) < 1e-15);

    e1 = exp(1.0);
    (void)printf("exp1=%a\n", e1);
    check("EXP", dabs(e1 - 2.7182818284590451) < 2e-15);
    l1 = log(e1);
    check("LOG", dabs(l1 - 1.0) < 1e-15);

    pw = pow(2.0, 10.0);
    (void)printf("pow2t10=%a\n", pw);
    check("POW", pw == 1024.0 && pow(9.0, 0.5) == 3.0);

    check("FLOOR", floor(2.7) == 2.0 && floor(-2.1) == -3.0);
    check("CEIL", ceil(2.1) == 3.0 && ceil(-2.7) == -2.0);
    check("FMOD", fmod(5.5, 2.0) == 1.5 && fmod(-5.5, 2.0) == -1.5);
    check("FABS", fabs(-3.25) == 3.25 && fabs(0.0) == 0.0);

    s2f = sqrtf(2.0f);
    (void)printf("sqrt2f=%a\n", (double)s2f);
    check("FLOAT", dabs((double)s2f - 1.41421356) < 1e-7 &&
        sinf(0.0f) == 0.0f && cosf(0.0f) == 1.0f);

    check("NANINF", isnan(sqrt(-1.0)) && !isnan(1.0) &&
        isinf(1.0 / 0.0) && !isinf(1.0));

    if (failures == 0) {
        (void)printf("H2-MATH-PASS\n");
    } else {
        (void)printf("H2-MATH-FAIL n=%d\n", failures);
    }
    return (failures != 0) ? 1 : 0;
}
