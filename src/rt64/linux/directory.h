/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SPARC64RT_LINUX_DIRECTORY_H
#define SPARC64RT_LINUX_DIRECTORY_H

#include "linux/file.h"

#include <stdbool.h>
#include <stdint.h>

/* RISC-V Linux directory operations. Unknown numbers return false unchanged.
 * Native Darwin has no Linux getdents64 ABI and reports ENOSYS for 61; the
 * shipped AArch64 Linux runtime uses the kernel's ABI on Linux and hl. */
bool sparc64_linux_directory_dispatch(sparc64_linux_file_t *files, uint64_t number,
                                 const uint64_t arguments[6], uint64_t *result);

#endif
