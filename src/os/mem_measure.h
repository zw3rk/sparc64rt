/*
 * src/os/mem_measure.h -- ported from src/rt64/runtime/measure.h (Wave U1 coordinator).
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SPARC64RT_OS_MEM_MEASURE_H
#define SPARC64RT_OS_MEM_MEASURE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef enum {
    SPARC64_MEASURE_LOAD = 0,
    SPARC64_MEASURE_SETUP,
    SPARC64_MEASURE_DISPATCH,
    SPARC64_MEASURE_TRANSLATE,
    SPARC64_MEASURE_JIT,
    SPARC64_MEASURE_INTERP,
    SPARC64_MEASURE_NATIVE_SIGNAL,
    SPARC64_MEASURE_SYSCALL,
    SPARC64_MEASURE_MEMORY,
    SPARC64_MEASURE_FILE_REFRESH, /* Managed-page and file-backed refresh work. */
    SPARC64_MEASURE_MANAGED_GUARD, /* Space's managed guard callback. */
    SPARC64_MEASURE_FAMILY_GUARD, /* Refresh's exact guarded-owner validation. */
    SPARC64_MEASURE_FAMILY_PID, /* Actual getpid in refresh guard/snapshot checks. */
    SPARC64_MEASURE_FAMILY_SNAPSHOT, /* Guarded page-state snapshot. */
    SPARC64_MEASURE_FAMILY_COMPARE, /* Canonical state versus local mirror. */
    /* Strict guard validation and managed-refresh stamp comparison. */
    SPARC64_MEASURE_FAMILY_REFRESH_CHECK,
    /* Successful reuse only; the completed-call count is an observed hit count. */
    SPARC64_MEASURE_FAMILY_REFRESH_HIT,
    SPARC64_MEASURE_FILE_STAT,
    SPARC64_MEASURE_FILE_READ,
    SPARC64_MEASURE_PUBLISH,
    /* Cache preparation is inclusive of the following nested subphases. */
    SPARC64_MEASURE_AOT_PREPARE,
    /* Initial directory open/type/owner/mode/ACL authority check. */
    SPARC64_MEASURE_AOT_AUTHORITY,
    /* Input, runtime, emitter and profile identity hashing. */
    SPARC64_MEASURE_AOT_IDENTITY,
    /* Fresh checked decode and A64 block emission. */
    SPARC64_MEASURE_AOT_EMIT,
    /* Snapshot reader, including its own authority and record checks. */
    SPARC64_MEASURE_AOT_READ,
    /* Saved block bytes and relocations compared with fresh emission. */
    SPARC64_MEASURE_AOT_VERIFY,
    /* Guest-relative relocation application after verification. */
    SPARC64_MEASURE_AOT_RELOCATE,
    /* FSIZE preflight, record encoding and atomic snapshot writer. */
    SPARC64_MEASURE_AOT_WRITE,
    SPARC64_MEASURE_CLEANUP,
    SPARC64_MEASURE_TOTAL,
    SPARC64_MEASURE_PHASE_COUNT
} sparc64_measure_phase_t;

typedef bool (*sparc64_measure_clock_fn)(void *context, uint64_t *nanoseconds);

/* Phase totals are inclusive and can overlap; do not sum them as disjoint time.
 * With sampling, elapsed time is the raw sum of measured calls, not an estimate
 * for all calls. Report both counts rather than silently extrapolating. */
typedef struct {
    uint64_t elapsed_nanoseconds;
    /* Ended measurements, including skipped calls and failed/backward ends.
     * A failed start is counted separately by clock_failures. */
    uint64_t completed_calls;
    uint64_t measured_calls;
    /* Failed clock reads at either begin or end. */
    uint64_t clock_failures;
    /* End reads earlier than their corresponding start. */
    uint64_t backwards_samples;
    /* Set when any counter or elapsed-time total saturates at UINT64_MAX. */
    bool overflow;
    uint64_t sample_countdown; /* Private scheduling state, starts at zero. */
} sparc64_measure_phase_stats_t;

typedef struct {
    sparc64_measure_clock_fn clock;
    void *clock_context;
    sparc64_measure_phase_stats_t phases[SPARC64_MEASURE_PHASE_COUNT];
    uint64_t sample_period; /* Zero/one measures every call; otherwise every Nth. */
} sparc64_measure_observer_t;

typedef struct {
    uint64_t start_nanoseconds;
    bool valid;
    bool skipped;
} sparc64_measure_stamp_t;

/* A null clock disables observation and causes no clock reads. */
static inline sparc64_measure_stamp_t
sparc64_measure_begin(sparc64_measure_observer_t *observer, sparc64_measure_phase_t phase)
{
    sparc64_measure_stamp_t stamp = {0U, false, false};
    uint64_t now;

    if (observer == NULL || observer->clock == NULL ||
        phase < 0 || phase >= SPARC64_MEASURE_PHASE_COUNT) {
        return stamp;
    }
    sparc64_measure_phase_stats_t *stats = &observer->phases[phase];
    if (stats->sample_countdown != 0) {
        --stats->sample_countdown;
        stamp.skipped = true;
        return stamp;
    }
    stats->sample_countdown = observer->sample_period > 1 ?
                             observer->sample_period - 1 : 0;
    if (!observer->clock(observer->clock_context, &now)) {
        if (stats->clock_failures == UINT64_MAX) {
            stats->overflow = true;
        } else {
            ++stats->clock_failures;
        }
        return stamp;
    }
    stamp.start_nanoseconds = now;
    stamp.valid = true;
    return stamp;
}

static inline void
sparc64_measure_end(sparc64_measure_observer_t *observer, sparc64_measure_phase_t phase,
               sparc64_measure_stamp_t stamp)
{
    sparc64_measure_phase_stats_t *stats;
    uint64_t now;

    if (observer == NULL || observer->clock == NULL || (!stamp.valid && !stamp.skipped) ||
        phase < 0 || phase >= SPARC64_MEASURE_PHASE_COUNT) {
        return;
    }
    stats = &observer->phases[phase];
    if (stats->completed_calls == UINT64_MAX) {
        stats->overflow = true;
    } else {
        ++stats->completed_calls;
    }
    if (stamp.skipped)
        return;
    if (!observer->clock(observer->clock_context, &now)) {
        if (stats->clock_failures == UINT64_MAX) {
            stats->overflow = true;
        } else {
            ++stats->clock_failures;
        }
        return;
    }
    if (now < stamp.start_nanoseconds) {
        if (stats->backwards_samples == UINT64_MAX) {
            stats->overflow = true;
        } else {
            ++stats->backwards_samples;
        }
        return;
    }
    if (stats->measured_calls == UINT64_MAX)
        stats->overflow = true;
    else
        ++stats->measured_calls;
    uint64_t elapsed = now - stamp.start_nanoseconds;
    if (elapsed > UINT64_MAX - stats->elapsed_nanoseconds) {
        stats->elapsed_nanoseconds = UINT64_MAX;
        stats->overflow = true;
    } else {
        stats->elapsed_nanoseconds += elapsed;
    }
}

#endif
