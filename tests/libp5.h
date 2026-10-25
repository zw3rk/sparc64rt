/*
 * tests/libp5.h -- Phase 5 shared-library companion (lane L5b).
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Narrow cross-DSO surface for tests/test_p5_dyn.c: arithmetic calls,
 * an identity string, and a DSO-resident __thread cell so the guest
 * can prove TLS works across the DSO boundary.
 */

#ifndef SPARC64RT_TEST_LIBP5_H
#define SPARC64RT_TEST_LIBP5_H

int p5_add(int a, int b);
int p5_mul(int a, int b);
const char *p5_name(void);
int p5_get_tls(void);
void p5_set_tls(int v);

#endif /* SPARC64RT_TEST_LIBP5_H */
