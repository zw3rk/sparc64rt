/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SPARC64RT_RUNTIME_FILE_RUNTIME_BINDING_H
#define SPARC64RT_RUNTIME_FILE_RUNTIME_BINDING_H

#include "linux/file.h"
#include "linux/signal.h"
#include "runtime/family.h"
#include "runtime/family_file_completion.h"
#include "runtime/file_runtime_limits.h"

/* Start with a zeroed object. One guarded syscall owner. The family guard, exact borrowed native target,
 * and Linux worker remain live from callback through post-result completion.
 * Never carry this object into a later task or recover an event from storage. */
typedef struct {
    sparc64_family_guard_t *guard;
    sparc64_linux_signals_t *signals;
    sparc64_file_identity_policy_t policy;
    sparc64_file_caps_call_context_t caller;
    sparc64_family_file_completion_t ticket;
    uint64_t guest_result;
    bool truncate_result, open_result;
    bool pending, fatal;
} sparc64_runtime_file_call_t;

int sparc64_runtime_file_call_prepare(sparc64_runtime_file_call_t *call,
    sparc64_family_guard_t *guard, uint64_t mm_id, uint32_t guest_tid,
    sparc64_runtime_file_limits_t *limits, sparc64_linux_signals_t *signals,
    sparc64_file_identity_policy_t policy);
/* Set on a fresh worker's sparc64_linux_file_io_t only in an internal source-family
 * run. Ordinary runtime callbacks stay NULL. All three call the existing
 * attributed canonical engine and leave the transient ticket in call.
 * The open-result hook converts a confirmed truncate outcome to the exact
 * reserved guest descriptor or final Linux open error before completion.
 * Nonregular positioned writes retain their ordinary native route. */
void sparc64_runtime_file_call_bind(sparc64_runtime_file_call_t *call,
                               sparc64_linux_file_io_t *io);
/* Call only after both guest x10 and PC have been committed, while the same
 * guard is held. Validate the exact caller and result before taking the ticket.
 * Only an event actually captured by the service enters this worker's queue.
 * Failure is infrastructure-fatal; the caller must not resume guest code. */
int sparc64_runtime_file_call_complete(sparc64_runtime_file_call_t *call,
    uint64_t guest_result, uint64_t committed_pc, uint64_t expected_pc);

#endif
