/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SPARC64RT_LINUX_MISC_H
#define SPARC64RT_LINUX_MISC_H

#include "memory/space.h"

#include <stdbool.h>
#include <stdint.h>

/* Small RV64 Linux entropy, clock, UTS and identity syscall surface.
 * True includes handled errors; false leaves the syscall to another family. */
bool sparc64_linux_misc_dispatch(sparc64_space_t *space, uint64_t number,
                            const uint64_t arguments[6], uint64_t *result);

#endif
