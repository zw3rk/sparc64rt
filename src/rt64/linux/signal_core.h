/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Guest signal trampoline placement. The trampoline page lives below the
 * 47-bit guest TASK_SIZE so it is addressable from any guest mapping.
 */
#ifndef SPARC64RT_LINUX_SIGNAL_CORE_H
#define SPARC64RT_LINUX_SIGNAL_CORE_H

#include <stdint.h>

#include "memory/space.h"

/* One 4 KiB trampoline page with a 1 MiB guard below the task limit. */
#define SPARC64_SIG_TRAMP_SIZE UINT64_C(4096)
#define SPARC64_SIG_TRAMP_BASE \
    (SPARC64_TASK_SIZE - UINT64_C(0x100000) - SPARC64_SIG_TRAMP_SIZE)

int sparc64_signal_trampoline_address(uint64_t *out);

#endif
