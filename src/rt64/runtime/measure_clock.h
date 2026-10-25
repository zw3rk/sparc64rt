/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SPARC64RT_RUNTIME_MEASURE_CLOCK_H
#define SPARC64RT_RUNTIME_MEASURE_CLOCK_H

#include <stdbool.h>
#include <stdint.h>
#include <time.h>

/* NULL context uses the production clock. A supplied source makes failure
 * and range behavior testable without changing guest or host clocks. */
typedef int (*sparc64_measure_clock_read_fn)(void *context, struct timespec *now);
typedef struct {
    sparc64_measure_clock_read_fn read;
    void *context;
} sparc64_measure_clock_source_t;

/* Linux stats reads bypass libc/vDSO time caching with a direct monotonic
 * syscall. Darwin native units use clock_gettime. This is observation only;
 * syscall deadlines keep their existing clock. Caller errno is preserved,
 * and the output changes only when a valid time was obtained. */
bool sparc64_measure_clock_monotonic(void *context, uint64_t *nanoseconds);

#endif
