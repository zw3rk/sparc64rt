/*
 * tests/libp5.c -- Phase 5 shared-library companion (lane L5b).
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Built as a dynamic-only shared object:
 *   sparc64-linux-gnu-gcc -shared -fPIC -O2 -o _build/libp5.so tests/libp5.c
 * No static archive is produced on purpose: the lane proves dynamic
 * ld.so startup, so libp5 must only ever resolve at runtime.
 */

#include "libp5.h"

#include <stddef.h>

static __thread int p5_tls_cell = 0;

int p5_add(int a, int b)
{
    return a + b;
}

int p5_mul(int a, int b)
{
    return a * b;
}

const char *p5_name(void)
{
    return "libp5";
}

int p5_get_tls(void)
{
    return p5_tls_cell;
}

void p5_set_tls(int v)
{
    p5_tls_cell = v;
}
