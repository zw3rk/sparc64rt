/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#include "linux/signal_core.h"

_Static_assert(SPARC64_SIG_TRAMP_BASE + SPARC64_SIG_TRAMP_SIZE <= SPARC64_TASK_SIZE,
               "sparc64 signal trampoline must sit below TASK_SIZE");
_Static_assert(SPARC64_TASK_SIZE == (UINT64_C(1) << 47),
               "sparc64 guest is a 47-bit (128 TiB) address space");

int sparc64_signal_trampoline_address(uint64_t *out)
{
    if (out == NULL)
        return -1;
    *out = SPARC64_SIG_TRAMP_BASE;
    return 0;
}
