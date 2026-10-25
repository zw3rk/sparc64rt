/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SPARC64RT_LINUX_WAIT_H
#define SPARC64RT_LINUX_WAIT_H

#include "memory/space.h"

#include <stdbool.h>
#include <stdint.h>

typedef struct {
    int32_t pid; /* -1 for P_ALL; positive for P_PID. */
    uint64_t info_address;
    bool nohang;
    bool nowait;
} sparc64_linux_waitid_request_t;

typedef struct {
    int32_t pid; /* Zero denotes no selected child. */
    uint32_t uid;
    uint32_t cause; /* Linux CLD_* values, not native host constants. */
    int32_t status;
} sparc64_linux_waitid_info_t;

/* P_ALL/P_PID, WEXITED with optional WNOHANG/WNOWAIT, no rusage yet.
 * Invalid Linux arguments return EINVAL; valid unimplemented profiles return
 * EOPNOTSUPP. Decode failure leaves *out unchanged. */
uint64_t sparc64_linux_waitid_decode(const uint64_t args[6],
                                sparc64_linux_waitid_request_t *out);

/* Linux v6.18 waitid writes six fields, even on wait failure, and does not
 * overwrite siginfo padding or clock fields. The caller supplies zero info
 * unless an event was selected, preserves native wait/reap ownership, and
 * lets a copyout fault override the wait error. A null infop is accepted.
 * Writes occur in kernel order; a later fault retains preceding field writes.
 * A complete 128-byte user-VA range is required, but untouched bytes need not
 * be mapped. Caller holds the address-space/family guard for the whole call.
 * INTERNAL faults remain sticky and require caller fatal-error handling. */
uint64_t sparc64_linux_waitid_copyout64(sparc64_space_t *space, uint64_t address,
                                   const sparc64_linux_waitid_info_t *info);

#endif
