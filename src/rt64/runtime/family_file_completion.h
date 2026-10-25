/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SPARC64RT_RUNTIME_FAMILY_FILE_COMPLETION_H
#define SPARC64RT_RUNTIME_FAMILY_FILE_COMPLETION_H

#include "runtime/file_caps.h"

/* A transient one-shot result for the live syscall owner. This is not durable
 * recovery state: if its caller dies, recovery reconciles memory and drops
 * the event rather than delivering SIGXFSZ to a later task. */
typedef struct {
    uint64_t operation_id;
    sparc64_file_caps_call_context_t caller;
    sparc64_file_caps_mutation_result_t native;
} sparc64_family_file_completion_t;

/* Validate and take the completion for its exact immutable caller tuple.
 * Success moves the native result to out_native and consumes the ticket by
 * clearing it. On failure, both ticket and output remain unchanged. The
 * caller serializes this operation with the family guard and only takes the
 * ticket after committing the syscall result and PC. */
int sparc64_family_file_completion_take(sparc64_family_file_completion_t *ticket,
    const sparc64_file_caps_call_context_t *expected_caller,
    sparc64_file_caps_mutation_result_t *out_native);

#endif
