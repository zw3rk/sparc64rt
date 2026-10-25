/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SPARC64RT_LINUX_METADATA_H
#define SPARC64RT_LINUX_METADATA_H

#include "linux/file.h"

#include <stdbool.h>
#include <stdint.h>

/* Pathname metadata and removal subset. True includes handled error results;
 * the caller owns the ordinary file/memory syscall dispatch order. */
bool sparc64_linux_metadata_dispatch(sparc64_linux_file_t *files, uint64_t number,
                                const uint64_t arguments[6], uint64_t *result);

#endif
