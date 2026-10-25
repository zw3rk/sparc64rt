/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SPARC64RT_LINUX_RLIMIT_H
#define SPARC64RT_LINUX_RLIMIT_H

#include "memory/space.h"
#include "runtime/file_runtime_limits.h"

/* Internal source profile only: prlimit64(261), RLIMIT_FSIZE(1), process self
 * or calling TID, with the unprivileged hard-ceiling policy. Other valid
 * resources and remote positive PIDs deliberately return EOPNOTSUPP. No native
 * limit is changed. The caller holds the memory/family guard through dispatch.
 * Copy new values before lookup/validation; commit before copying old values.
 * An old-value EFAULT therefore never rolls a successful update back. Native
 * RV32 Linux maps input values >=UINT32_MAX to infinity before validation.
 * Initial process values must already use that profile's normalized form. */
bool sparc64_linux_fsize_prlimit_dispatch(sparc64_space_t *space,
    sparc64_runtime_file_limits_t *limits, unsigned int xlen,
    uint32_t guest_pid, uint32_t guest_tid, uint64_t number,
    const uint64_t arguments[6], uint64_t *result);

/* The ordinary runtime still uses the native file-size limit for guest file
 * operations. Admit only the self read of that same native limit; accepting a
 * logical-only setter here would make subsequent guest writes inconsistent. */
bool sparc64_linux_fsize_prlimit_native_query(sparc64_space_t *space, unsigned int xlen,
    uint32_t guest_pid, uint32_t guest_tid, uint64_t number,
    const uint64_t arguments[6], uint64_t *result);

#endif
