/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SPARC64RT_RUNTIME_PROGRESS_H
#define SPARC64RT_RUNTIME_PROGRESS_H

#include "runtime/measure.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

typedef void (*sparc64_progress_write_fn)(void *context, const char *bytes, size_t size);

typedef enum {
    SPARC64_PROGRESS_BUDGET,
    SPARC64_PROGRESS_ACCOUNT,
    SPARC64_PROGRESS_YIELD,
    SPARC64_PROGRESS_PARK,
    SPARC64_PROGRESS_WAKE,
    SPARC64_PROGRESS_TURN_WAIT,
    SPARC64_PROGRESS_GUARD_LEAVE,
    SPARC64_PROGRESS_GUARD_ENTER,
    SPARC64_PROGRESS_FUTEX_SLEEP,
    SPARC64_PROGRESS_PHASE_COUNT
} sparc64_progress_phase_t;

typedef struct {
    uint64_t calls, samples, sampled_ns, clock_failures, backwards;
} sparc64_progress_phase_stats_t;

typedef struct {
    bool sampled, valid;
    uint64_t start_ns;
} sparc64_progress_stamp_t;

/* One native worker owns and mutates this record. No shared counters or
 * observer are accessed after the worker releases its family guard. Ordinary
 * phase times sample one in 128 calls; futex native sleep is measured every
 * time. Report raw sampled time, never extrapolate it to all calls. */
typedef struct {
    sparc64_measure_clock_fn clock;
    void *clock_context;
    FILE *output;
    sparc64_progress_write_fn write;
    void *write_context;
    uint32_t guest_tid;
    uint64_t interval;
    uint64_t total_attempts, attempts, retired, jit, fallback, yields;
    uint64_t last_emit_ns, timestamp_failures, timestamp_backwards;
    bool last_emit_valid;
    sparc64_progress_phase_stats_t phases[SPARC64_PROGRESS_PHASE_COUNT];
} sparc64_progress_t;

void sparc64_progress_init(sparc64_progress_t *progress, uint32_t guest_tid,
                      uint64_t interval, sparc64_measure_clock_fn clock,
                      void *clock_context, FILE *output);
void sparc64_progress_init_writer(sparc64_progress_t *progress, uint32_t guest_tid,
                             uint64_t interval, sparc64_measure_clock_fn clock,
                             void *clock_context, sparc64_progress_write_fn write,
                             void *write_context);
sparc64_progress_stamp_t sparc64_progress_begin(sparc64_progress_t *progress,
                                       sparc64_progress_phase_t phase);
void sparc64_progress_end(sparc64_progress_t *progress, sparc64_progress_phase_t phase,
                     sparc64_progress_stamp_t stamp);
bool sparc64_progress_step(sparc64_progress_t *progress, uint64_t attempted,
                     uint64_t retired, bool jit, uint64_t pc);
void sparc64_progress_yield(sparc64_progress_t *progress);
void sparc64_progress_event(sparc64_progress_t *progress, const char *event, uint64_t pc);
/* One-off lifecycle marker outside a running worker, e.g. main join. */
void sparc64_progress_mark(bool enabled, sparc64_measure_clock_fn clock,
                       void *clock_context, FILE *output,
                       const char *event, uint32_t guest_tid,
                       uint32_t related_tid);

void sparc64_progress_mark_writer(bool enabled, sparc64_measure_clock_fn clock,
                              void *clock_context, sparc64_progress_write_fn write,
                              void *write_context, const char *event,
                              uint32_t guest_tid, uint32_t related_tid);

#endif
