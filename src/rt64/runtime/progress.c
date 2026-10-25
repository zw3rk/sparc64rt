/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#include "runtime/progress.h"

#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stdarg.h>
#include <string.h>

static const char *const phase_names[SPARC64_PROGRESS_PHASE_COUNT] = {
    "budget", "account", "yield", "park", "wake", "turn_wait",
    "guard_leave", "guard_enter", "futex_sleep"
};

static void increment(uint64_t *value)
{
    if (*value != UINT64_MAX)
        ++*value;
}

static void add(uint64_t *value, uint64_t delta)
{
    *value = delta > UINT64_MAX - *value ? UINT64_MAX : *value + delta;
}

void sparc64_progress_init(sparc64_progress_t *progress, uint32_t guest_tid,
                      uint64_t interval, sparc64_measure_clock_fn clock,
                      void *clock_context, FILE *output)
{
    if (progress == NULL)
        return;
    int saved_errno = errno;
    memset(progress, 0, sizeof(*progress));
    progress->guest_tid = guest_tid;
    if (interval == 0 || clock == NULL || output == NULL)
        goto done;
    progress->interval = interval;
    progress->clock = clock;
    progress->clock_context = clock_context;
    progress->output = output;
    progress->last_emit_valid = clock(clock_context, &progress->last_emit_ns);
    if (!progress->last_emit_valid)
        increment(&progress->timestamp_failures);
done:
    errno = saved_errno;
}

void sparc64_progress_init_writer(sparc64_progress_t *progress, uint32_t guest_tid,
                             uint64_t interval, sparc64_measure_clock_fn clock,
                             void *clock_context, sparc64_progress_write_fn write,
                             void *write_context)
{
    if (progress == NULL)
        return;
    int saved = errno;
    memset(progress, 0, sizeof(*progress));
    progress->guest_tid = guest_tid;
    if (interval != 0 && clock != NULL && write != NULL) {
        progress->interval = interval;
        progress->clock = clock;
        progress->clock_context = clock_context;
        progress->write = write;
        progress->write_context = write_context;
        progress->last_emit_valid = clock(clock_context, &progress->last_emit_ns);
        if (!progress->last_emit_valid)
            increment(&progress->timestamp_failures);
    }
    errno = saved;
}

static void emit(sparc64_progress_t *progress, const char *format, ...)
{
    va_list arguments;
    va_start(arguments, format);
    if (progress->write != NULL) {
        char line[1024];
        int size = vsnprintf(line, sizeof(line), format, arguments);
        if (size > 0 && (size_t)size < sizeof(line))
            progress->write(progress->write_context, line, (size_t)size);
    } else if (progress->output != NULL) {
        (void)vfprintf(progress->output, format, arguments);
    }
    va_end(arguments);
}

sparc64_progress_stamp_t sparc64_progress_begin(sparc64_progress_t *progress,
                                       sparc64_progress_phase_t phase)
{
    sparc64_progress_stamp_t stamp = {0};
    int saved_errno = errno;
    if (progress == NULL || progress->interval == 0 ||
        phase < 0 || phase >= SPARC64_PROGRESS_PHASE_COUNT)
        return stamp;
    sparc64_progress_phase_stats_t *stats = &progress->phases[phase];
    increment(&stats->calls);
    stamp.sampled = phase == SPARC64_PROGRESS_FUTEX_SLEEP ||
                    stats->calls % UINT64_C(128) == 1;
    if (!stamp.sampled)
        return stamp;
    stamp.valid = progress->clock(progress->clock_context, &stamp.start_ns);
    if (!stamp.valid)
        increment(&stats->clock_failures);
    errno = saved_errno;
    return stamp;
}

void sparc64_progress_end(sparc64_progress_t *progress, sparc64_progress_phase_t phase,
                     sparc64_progress_stamp_t stamp)
{
    if (progress == NULL || progress->interval == 0 || !stamp.sampled ||
        !stamp.valid || phase < 0 || phase >= SPARC64_PROGRESS_PHASE_COUNT)
        return;
    int saved_errno = errno;
    sparc64_progress_phase_stats_t *stats = &progress->phases[phase];
    uint64_t now;
    if (!progress->clock(progress->clock_context, &now)) {
        increment(&stats->clock_failures);
    } else if (now < stamp.start_ns) {
        increment(&stats->backwards);
    } else {
        increment(&stats->samples);
        add(&stats->sampled_ns, now - stamp.start_ns);
    }
    errno = saved_errno;
}

void sparc64_progress_event(sparc64_progress_t *progress, const char *event, uint64_t pc)
{
    if (progress == NULL || progress->interval == 0 || event == NULL)
        return;
    int saved_errno = errno;
    uint64_t now = 0, elapsed = 0;
    bool valid = progress->clock(progress->clock_context, &now);
    bool elapsed_valid = false;
    if (!valid) {
        increment(&progress->timestamp_failures);
    } else if (progress->last_emit_valid && now < progress->last_emit_ns) {
        increment(&progress->timestamp_backwards);
    } else if (progress->last_emit_valid) {
        elapsed = now - progress->last_emit_ns;
        elapsed_valid = true;
    }
    emit(progress,
            "sparc64rt: progress event=%s tid=%" PRIu32 " pc=0x%" PRIx64
            " mono_ns=%" PRIu64 " clock_valid=%u interval_ns=%" PRIu64
            " interval_valid=%u"
            " attempts=%" PRIu64 " retired=%" PRIu64
            " jit=%" PRIu64 " fallback=%" PRIu64
            " yields=%" PRIu64 " total_attempts=%" PRIu64
            " clock_failures=%" PRIu64 " backwards=%" PRIu64 "\n",
            event, progress->guest_tid, pc, valid ? now : 0, valid ? 1u : 0u,
            elapsed, elapsed_valid ? 1u : 0u,
            progress->attempts, progress->retired, progress->jit,
            progress->fallback, progress->yields, progress->total_attempts,
            progress->timestamp_failures, progress->timestamp_backwards);
    for (size_t i = 0; i < SPARC64_PROGRESS_PHASE_COUNT; ++i) {
        const sparc64_progress_phase_stats_t *phase = &progress->phases[i];
        if (phase->calls != 0 || phase->clock_failures != 0)
            emit(progress,
                    "sparc64rt: progress_phase tid=%" PRIu32 " phase=%s calls=%" PRIu64
                    " samples=%" PRIu64 " sampled_ns=%" PRIu64
                    " clock_failures=%" PRIu64 " backwards=%" PRIu64 "\n",
                    progress->guest_tid, phase_names[i], phase->calls,
                    phase->samples, phase->sampled_ns,
                    phase->clock_failures, phase->backwards);
    }
    memset(progress->phases, 0, sizeof(progress->phases));
    progress->attempts = progress->retired = progress->jit = 0;
    progress->fallback = progress->yields = 0;
    progress->timestamp_failures = progress->timestamp_backwards = 0;
    progress->last_emit_ns = now;
    progress->last_emit_valid = valid;
    errno = saved_errno;
}

bool sparc64_progress_step(sparc64_progress_t *progress, uint64_t attempted,
                      uint64_t retired, bool jit, uint64_t pc)
{
    if (progress == NULL || progress->interval == 0)
        return false;
    add(&progress->total_attempts, attempted);
    add(&progress->attempts, attempted);
    add(&progress->retired, retired);
    add(jit ? &progress->jit : &progress->fallback, attempted);
    if (progress->attempts >= progress->interval) {
        sparc64_progress_event(progress, "sample", pc);
        return true;
    }
    return false;
}

void sparc64_progress_yield(sparc64_progress_t *progress)
{
    if (progress != NULL && progress->interval != 0)
        increment(&progress->yields);
}

void sparc64_progress_mark(bool enabled, sparc64_measure_clock_fn clock,
                       void *clock_context, FILE *output,
                       const char *event, uint32_t guest_tid,
                       uint32_t related_tid)
{
    if (!enabled || clock == NULL || output == NULL || event == NULL)
        return;
    int saved_errno = errno;
    uint64_t now = 0;
    bool valid = clock(clock_context, &now);
    fprintf(output,
            "sparc64rt: progress event=%s tid=%" PRIu32 " related_tid=%" PRIu32
            " mono_ns=%" PRIu64 " clock_valid=%u\n",
            event, guest_tid, related_tid, valid ? now : 0, valid ? 1u : 0u);
    errno = saved_errno;
}

void sparc64_progress_mark_writer(bool enabled, sparc64_measure_clock_fn clock,
                              void *clock_context, sparc64_progress_write_fn write,
                              void *write_context, const char *event,
                              uint32_t guest_tid, uint32_t related_tid)
{
    if (!enabled || clock == NULL || write == NULL || event == NULL)
        return;
    int saved = errno;
    uint64_t now = 0;
    bool valid = clock(clock_context, &now);
    char line[512];
    int size = snprintf(line, sizeof(line),
                        "sparc64rt: progress event=%s tid=%" PRIu32 " related_tid=%" PRIu32
                        " mono_ns=%" PRIu64 " clock_valid=%u\n",
                        event, guest_tid, related_tid, valid ? now : 0, valid ? 1u : 0u);
    if (size > 0 && (size_t)size < sizeof(line))
        write(write_context, line, (size_t)size);
    errno = saved;
}
