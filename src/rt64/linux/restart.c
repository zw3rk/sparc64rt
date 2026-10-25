/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#include "linux/restart.h"

#define GUEST_EINTR UINT64_C(4)

static bool valid_next(sparc64_signal_next_t next)
{
    switch (next.kind) {
    case SPARC64_SIGNAL_NONE:
        return next.signal == 0 && !next.restart;
    case SPARC64_SIGNAL_CAUGHT:
        return next.signal >= 1 && next.signal <= 64;
    case SPARC64_SIGNAL_FATAL:
        return next.signal >= 1 && next.signal <= 64 && !next.restart;
    }
    return false;
}

static bool valid_class(sparc64_restart_class_t restart_class)
{
    switch (restart_class) {
    case SPARC64_RESTART_CLASS_NONE:
    case SPARC64_RESTART_CLASS_SYS:
    case SPARC64_RESTART_CLASS_NOHAND:
        return true;
    }
    return false;
}

bool sparc64_restart_decide(const sparc64_restart_flight_t *flight,
                       sparc64_signal_next_t next, sparc64_restart_plan_t *plan)
{
    if (flight == NULL || plan == NULL || !valid_next(next) ||
        flight->ecall_length != 4 ||
        flight->ecall_pc > UINT64_MAX - flight->ecall_length ||
        !valid_class(flight->restart_class))
        return false;
    sparc64_restart_plan_t result = {
        .kind = SPARC64_RESTART_COMPLETE,
        .pc = flight->ecall_pc + flight->ecall_length,
        .number = flight->number,
        .result = (uint64_t)flight->raw_result
    };
    for (unsigned int i = 0; i < 6; ++i)
        result.arguments[i] = flight->arguments[i];

    /* Zero/positive/other negative completions and bare host EINTR are
     * final. Only a captured guest signal may enter restart policy. */
    if (flight->raw_result == -(int64_t)GUEST_EINTR &&
        flight->explained_interrupt) {
        switch (next.kind) {
        case SPARC64_SIGNAL_NONE:
            if (flight->restart_class != SPARC64_RESTART_CLASS_NONE)
                result.kind = SPARC64_RESTART_RETRY;
            break;
        case SPARC64_SIGNAL_FATAL:
            result.kind = SPARC64_RESTART_FATAL;
            break;
        case SPARC64_SIGNAL_CAUGHT:
            if (flight->restart_class == SPARC64_RESTART_CLASS_SYS && next.restart) {
                result.kind = SPARC64_RESTART_SAVE_ECALL;
                result.pc = flight->ecall_pc;
                result.result = flight->arguments[0];
            } else {
                result.kind = SPARC64_RESTART_SAVE_EINTR;
                result.result = UINT64_C(0) - GUEST_EINTR;
            }
            break;
        }
    }
    *plan = result;
    return true;
}
