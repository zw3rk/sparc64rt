/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SPARC64RT_RUNTIME_PRETRANSLATE_H
#define SPARC64RT_RUNTIME_PRETRANSLATE_H

#include "aot/authority.h"
#include "runtime/measure.h"
#include "runtime/image_expectation.h"

typedef struct {
    const char *target, *execfn, *sysroot, *directory;
    int image_fd, runtime_fd, argc;
    char *const *argv;
    char *const *envp;
    sparc64_aot_authority_policy_t authority;
    uint32_t quantum, cache_blocks;
    sparc64_measure_observer_t *measure;
    const sparc64_image_expectation_t *expected_image;
} sparc64_pretranslate_options_t;

typedef struct {
    const char *status, *reason; /* Static strings, valid after cleanup. */
    char error[256];
} sparc64_pretranslate_result_t;

/* Consumes image_fd when nonnegative, including0; runtime_fd is borrowed.
 * No guest worker, signal state, stack, family backing or executable mapping
 * is created. Success means one entry record was stored or verified, never
 * guest execution. Return0/1/125 for success/decline/internal failure.
 * options must describe a validated fresh CLI launch; out must be nonnull. */
int sparc64_runtime_pretranslate(const sparc64_pretranslate_options_t *options,
                            sparc64_pretranslate_result_t *out);

#endif
