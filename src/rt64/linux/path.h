/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SPARC64RT_LINUX_PATH_H
#define SPARC64RT_LINUX_PATH_H

#include "memory/space.h"

#include <stdbool.h>
#include <stdint.h>

#define SPARC64_LINUX_PATH_MAX 4096u
#define SPARC64_LINUX_HOST_PATH_MAX 8192u

/* Copies through the guest NUL terminator. Empty paths are valid here. */
int sparc64_linux_copy_path(sparc64_space_t *space, uint64_t guest_address,
                       char output[SPARC64_LINUX_PATH_MAX]);

/* Absolute guest paths are rooted under sysroot when one is supplied.
 * Relative paths are returned unchanged for native cwd/dirfd resolution. */
int sparc64_linux_path_join(const char *sysroot, const char *guest_path,
                       char output[SPARC64_LINUX_HOST_PATH_MAX]);

/* Translate pinned asm-generic open flags. Host descriptors should always
 * additionally use O_CLOEXEC; guest close-on-exec is reported separately. */
int sparc64_linux_open_flags(uint32_t guest_flags, int *native_flags,
                        bool *guest_cloexec);

/* Translate supported host file status flags into the Linux guest ABI. */
uint32_t sparc64_linux_getfl(int native_flags);

#endif
