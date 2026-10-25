/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SPARC64RT_LINUX_HWPROBE_H
#define SPARC64RT_LINUX_HWPROBE_H

#include "memory/space.h"
#include <stdint.h>

/* Linux v6.18 riscv_hwprobe pair/cpuset ABI for the implemented RV64 profile.
 * One homogeneous virtual CPU (CPU0) is online; native CPU IDs, HWCAP and vDSO
 * state are never inputs. RV32 remains ENOSYS until its execution profile lands.
 * The caller holds guest memory ownership throughout this nonblocking call. */
uint64_t sparc64_linux_hwprobe(sparc64_space_t *space, unsigned int xlen,
                           const uint64_t arguments[6]);

#endif
