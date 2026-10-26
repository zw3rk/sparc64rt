/*
 * src/os/guest_interp_map.h — BE SPARC64 PT_INTERP mapping (Wave U1 coordinator)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Ported from src/rt64/loader/interp_map.h: path read/resolve (plus
 * SPARC64RT_INTERP_PATH_MAX) live in os/host_contract_interp.h (Wave U1
 * lane M1); this header adds the free-base hint, sysroot open, and the
 * ET_DYN interpreter mapper over the ported os/mem_space.h substrate.
 */

#ifndef SPARC64RT_OS_GUEST_INTERP_MAP_H
#define SPARC64RT_OS_GUEST_INTERP_MAP_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "os/host_contract_interp.h"
#include "os/mem_space.h"

/* Free-base hint for the interpreter (128 GiB, clear of the PIE app
 * bias, the mmap base, and the stack). */
#define SPARC64RT_INTERP_HINT UINT64_C(0x2000000000)

/* Open an absolute guest path against the translator sysroot (qemu -L
 * semantics): SPARC64RT_SYSROOT+path first, ENOENT/ENOTDIR falls back
 * to the raw path (serves $ORIGIN libraries outside the sysroot).
 * Returns true with *fd_out set (errno preserved) when attempted;
 * false means open the raw path. */
bool sparc64_sysroot_try_open(int dirfd, const char *path, int flags,
    unsigned mode, int *fd_out);

/* Map the ET_DYN BE SPARC64 interpreter open on fd at a free base
 * honouring the largest PT_LOAD p_align. Returns 0 with the
 * interpreter entry in entry_out, the load bias (AT_BASE) in
 * base_out, and the page-aligned post-image end in hi_out;
 * -ENOEXEC for a bad interpreter (incl. a nested PT_INTERP),
 * -ENOMEM when no hole fits, -EIO on short reads. The fd stays open. */
int sparc64_interp_map(sparc64_space_t *space, int fd,
    uint64_t *entry_out, uint64_t *base_out, uint64_t *hi_out);

#endif /* SPARC64RT_OS_GUEST_INTERP_MAP_H */
