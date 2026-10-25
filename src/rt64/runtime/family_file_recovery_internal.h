/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SPARC64RT_RUNTIME_FAMILY_FILE_RECOVERY_INTERNAL_H
#define SPARC64RT_RUNTIME_FAMILY_FILE_RECOVERY_INTERNAL_H

#include "runtime/family_file_index.h"
#include "runtime/family_file_recovery.h"

/* The target-owning begin path queries its exact native identity. The built-in
 * guard drain uses only the persisted proof, keeping native query/provider
 * selection out of source-family attach and ordinary anonymous components. */
int sparc64_family_file_preflight_payloads(sparc64_family_guard_t *guard,
                                        const sparc64_family_file_index_state_t *index,
                                        const sparc64_file_identity_t *identity,
                                        uint64_t length);
int sparc64_family_file_drain(sparc64_family_guard_t *guard, int *out_native_errno);
int sparc64_family_file_preflight_write(sparc64_family_guard_t *guard,
                                     const sparc64_family_file_index_state_t *index,
                                     const sparc64_file_identity_t *identity,
                                     uint64_t offset, uint64_t count);
int sparc64_family_file_drain_write(sparc64_family_guard_t *guard,
                                sparc64_file_caps_write_result_t *out);
int sparc64_family_file_drain_attributed(sparc64_family_guard_t *guard,
    const sparc64_file_caps_call_context_t *caller, sparc64_family_file_completion_t *out);

#endif
