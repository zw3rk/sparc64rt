/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SPARC64RT_AOT_MBEDTLS_CONFIG_H
#define SPARC64RT_AOT_MBEDTLS_CONFIG_H
/* SHA-256 only. In particular, no hardware feature probes, TLS, PSA, RNG,
 * threading globals, or platform callbacks are part of this build. */
#define MBEDTLS_SHA256_C
#endif
