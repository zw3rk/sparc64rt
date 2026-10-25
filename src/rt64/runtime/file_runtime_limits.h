/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SPARC64RT_RUNTIME_FILE_RUNTIME_LIMITS_H
#define SPARC64RT_RUNTIME_FILE_RUNTIME_LIMITS_H

#include <stdint.h>

typedef struct sparc64_runtime_file_limits sparc64_runtime_file_limits_t;

typedef struct {
    uint64_t soft, hard; /* UINT64_MAX is RLIM_INFINITY. */
} sparc64_runtime_file_limit_values_t;

/* Process-owned values. Sample the native startup ceiling once, before guest
 * workers; later snapshots never consult or change the host process limit.
 * A fork child and an exec image construct fresh ownership from values only. */
int sparc64_runtime_file_limits_create_native(sparc64_runtime_file_limits_t **out);
int sparc64_runtime_file_limits_create_values(sparc64_runtime_file_limits_t **out,
                                        sparc64_runtime_file_limit_values_t values);
int sparc64_runtime_file_limits_snapshot(sparc64_runtime_file_limits_t *owner,
                                    sparc64_runtime_file_limit_values_t *out);
/* Unprivileged process-local prlimit operation. Atomically return the old
 * values and optionally replace them. A hard ceiling can be lowered but not
 * raised; invalid values and EPERM preserve both owner and output. Never
 * changes the translator's native limit. Guest CAP_SYS_RESOURCE is excluded
 * from this internal profile. A NULL old_values is allowed. */
int sparc64_runtime_file_limits_prlimit(sparc64_runtime_file_limits_t *owner,
    const sparc64_runtime_file_limit_values_t *replacement,
    sparc64_runtime_file_limit_values_t *old_values);
void sparc64_runtime_file_limits_destroy(sparc64_runtime_file_limits_t **owner);

#endif
