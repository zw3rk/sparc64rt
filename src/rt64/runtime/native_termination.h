/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SPARC64RT_RUNTIME_NATIVE_TERMINATION_H
#define SPARC64RT_RUNTIME_NATIVE_TERMINATION_H

#include <stdbool.h>

/* Terminal path only, after guest workers have stopped and joined. Keep all
 * blockable signals blocked through remaining owner/image cleanup. */
bool sparc64_native_termination_block(void);
/* After cleanup, terminate with one native default-fatal signal. The AArch64
 * Linux runtime maps its standard guest signals to the same Linux numbers.
 * This does not construct a RISC-V core file; native core handling remains
 * the host kernel's policy. Infrastructure failures exit125. */
_Noreturn void sparc64_native_termination_raise(int native_signal);

#endif
