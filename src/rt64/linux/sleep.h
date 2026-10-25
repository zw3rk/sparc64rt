/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SPARC64RT_LINUX_SLEEP_H
#define SPARC64RT_LINUX_SLEEP_H

#include "linux/file.h"

#include <time.h>

typedef int (*sparc64_linux_sleep_clock_fn)(clockid_t clock, struct timespec *time,
                                       void *context);

/* Handle RV64 nanosleep and clock_nanosleep, including deliberate errors.
 * clock_nanosleep supports CLOCK_REALTIME and CLOCK_MONOTONIC, relative or
 * absolute. Other known/dynamic clock profiles decline with EOPNOTSUPP.
 * The injected-clock variant permits deterministic deadline/clock-step tests;
 * normal dispatch reads the corresponding host clock. */
bool sparc64_linux_sleep_dispatch_io(sparc64_space_t *space,
                                const sparc64_linux_file_io_t *io,
                                uint64_t number,
                                const uint64_t arguments[6],
                                uint64_t *result);
bool sparc64_linux_sleep_dispatch_io_clock(sparc64_space_t *space,
                                     const sparc64_linux_file_io_t *io,
                                     sparc64_linux_sleep_clock_fn clock,
                                     void *clock_context,
                                     uint64_t number,
                                     const uint64_t arguments[6],
                                     uint64_t *result);

#endif
