/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SPARC64RT_LINUX_THREAD_H
#define SPARC64RT_LINUX_THREAD_H

#include "core/cpu.h"
#include "runtime/scheduler.h"

#include <stdbool.h>
#include <stdint.h>

typedef struct {
    uint64_t stack;
    uint64_t parent_tid;
    uint64_t child_tid;
    uint64_t tls;
    bool set_tls;
    bool parent_set_tid;
    bool child_set_tid;
    bool child_clear_tid;
} sparc64_linux_clone_request_t;

/* The first pthread-profile vertical accepts the canonical Linux thread
 * sharing flags and the four optional TID/TLS flags. Return a guest Linux
 * negative errno; pointer writes remain best-effort at their Linux stage. */
uint64_t sparc64_linux_clone_decode(const uint64_t args[6],
                               sparc64_linux_clone_request_t *request);

/* Classify the instruction actually executed, without refetching guest code.
 * This is a bounded scheduling allowance, not proof that an entire static
 * LR/SC retry loop satisfies the architectural constrained-loop rules. */
sparc64_sched_sequence_t sparc64_lrsc_classify(sparc64_insn_t executed, uint64_t after_pc,
                                     sparc64_step_kind_t outcome, unsigned xlen);

#endif
