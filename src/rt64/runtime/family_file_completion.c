/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#include "runtime/family_file_completion.h"

#include <errno.h>

static bool native_result_valid(const sparc64_file_caps_mutation_result_t *native)
{
    return native != NULL && native->native_errno >= 0 &&
           native->native_errno < 4096 &&
           (native->native_errno == 0 ?
                native->transferred >= 0 &&
                    (uint64_t)native->transferred <= SPARC64_FILE_CAPS_MAX_WRITE_BYTES :
                                        native->transferred == -1);
}

int sparc64_family_file_completion_take(sparc64_family_file_completion_t *ticket,
    const sparc64_file_caps_call_context_t *expected_caller,
    sparc64_file_caps_mutation_result_t *out_native)
{
    if (ticket == NULL || out_native == NULL || expected_caller == NULL ||
        !sparc64_file_caps_call_context_valid(expected_caller)) {
        errno = EINVAL;
        return -1;
    }
    if (ticket->operation_id == 0 ||
        !sparc64_file_caps_call_context_valid(&ticket->caller) ||
        !native_result_valid(&ticket->native)) {
        errno = EPROTO;
        return -1;
    }
    if (!sparc64_file_caps_call_context_equal(&ticket->caller, expected_caller)) {
        errno = EPERM;
        return -1;
    }

    sparc64_file_caps_mutation_result_t result = ticket->native;
    *ticket = (sparc64_family_file_completion_t){0};
    *out_native = result;
    return 0;
}
