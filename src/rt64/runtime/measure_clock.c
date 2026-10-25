/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L
#include "runtime/measure_clock.h"

#include <errno.h>
#include <stdint.h>
#if defined(__linux__)
#include <sys/syscall.h>
#include <unistd.h>
#endif

static int production_read(void *context, struct timespec *now)
{
    (void)context;
#if defined(__linux__)
    return (int)syscall(SYS_clock_gettime, CLOCK_MONOTONIC, now);
#else
    return clock_gettime(CLOCK_MONOTONIC, now);
#endif
}

bool sparc64_measure_clock_monotonic(void *context, uint64_t *nanoseconds)
{
    int saved_errno = errno;
    bool success = false;
    if (nanoseconds != NULL) {
        const sparc64_measure_clock_source_t *source = context;
        sparc64_measure_clock_read_fn read = source != NULL ? source->read : production_read;
        struct timespec now = {0};
        if (read != NULL && read(source == NULL ? NULL : source->context, &now) == 0 &&
            now.tv_sec >= 0 && now.tv_nsec >= 0 && now.tv_nsec < 1000000000L &&
            (uint64_t)now.tv_sec <=
            (UINT64_MAX - (uint64_t)now.tv_nsec) / UINT64_C(1000000000)) {
            *nanoseconds = (uint64_t)now.tv_sec * UINT64_C(1000000000) +
                           (uint64_t)now.tv_nsec;
            success = true;
        }
    }
    errno = saved_errno;
    return success;
}
