/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SPARC64RT_LINUX_RESTART_H
#define SPARC64RT_LINUX_RESTART_H

#include "linux/signal.h"

#include <stdbool.h>
#include <stdint.h>

typedef enum {
    SPARC64_RESTART_CLASS_NONE,
    SPARC64_RESTART_CLASS_SYS,
    SPARC64_RESTART_CLASS_NOHAND
} sparc64_restart_class_t;

typedef struct {
    uint64_t ecall_pc;
    uint32_t ecall_length; /* ECALL is always one 32-bit instruction. */
    uint64_t number;
    uint64_t arguments[6];
    int64_t raw_result; /* Native Linux negative errno, not libc's -1/errno. */
    sparc64_restart_class_t restart_class;
    bool explained_interrupt; /* A captured guest signal explains this EINTR. */
} sparc64_restart_flight_t;

typedef enum {
    SPARC64_RESTART_COMPLETE,   /* Commit raw_result at next_pc. */
    SPARC64_RESTART_RETRY,      /* Repeat the native operation, no guest CPU change. */
    SPARC64_RESTART_SAVE_ECALL, /* Frame saves original PC/nr/args for sigreturn. */
    SPARC64_RESTART_SAVE_EINTR, /* Frame saves next PC and -EINTR for sigreturn. */
    SPARC64_RESTART_FATAL       /* Deliver the default-fatal signal. */
} sparc64_restart_plan_kind_t;

typedef struct {
    sparc64_restart_plan_kind_t kind;
    uint64_t pc;
    uint64_t number;
    uint64_t arguments[6];
    uint64_t result; /* a0 for COMPLETE/SAVE_EINTR, original a0 for SAVE_ECALL. */
} sparc64_restart_plan_t;

/* Pure decision. The native capture, next-action query, decision and delivery
 * must be serialized by the caller. A completed raw result always wins;
 * unexplained EINTR never triggers a retry. Class NONE promises no restart
 * even when the captured signal becomes ignored/masked. No guest state is
 * committed for RETRY or FATAL. */
bool sparc64_restart_decide(const sparc64_restart_flight_t *flight,
                       sparc64_signal_next_t next, sparc64_restart_plan_t *plan);

#endif
