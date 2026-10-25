/* src/rt64/loader/interp_map.h — BE SPARC64 PT_INTERP mapping (Phase 5, L5a)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Helpers for dynamic guests: extract the PT_INTERP path from an open
 * BE SPARC64 ELF, resolve it against SPARC64RT_SYSROOT, and map the
 * ET_DYN interpreter at a free base honouring p_align. Operates only
 * on the rt64 space substrate and host fds; the SPARC64 runner in
 * src/os/guest_run.c orchestrates app-first ordering and entry
 * selection (dynamic entry = interpreter e_entry, AT_ENTRY = app).
 */

#ifndef SPARC64RT_LOADER_INTERP_MAP_H
#define SPARC64RT_LOADER_INTERP_MAP_H

#include <stddef.h>
#include <stdint.h>

#include "memory/space.h"

/* Longest PT_INTERP byte range accepted (incl. the NUL). */
#define SPARC64RT_INTERP_PATH_MAX 4096U

/* Free-base hint for the interpreter (128 GiB, clear of the PIE app
 * bias, the mmap base, and the stack). */
#define SPARC64RT_INTERP_HINT UINT64_C(0x2000000000)

/* Read the PT_INTERP path from an open BE SPARC64 ELF fd. Returns 0
 * with the NUL-terminated path in out, -ENOENT when the ELF has no
 * PT_INTERP, -ENOEXEC when it is not a BE SPARC64 ELF. */
int sparc64_interp_read_path(int fd, char *out, size_t cap);

/* Resolve interp against sysroot into out (cap bytes incl. NUL).
 * sysroot NULL/empty/every-slash means the container root: interp is
 * used verbatim. Absolute interp is prefixed with sysroot (trailing
 * slashes stripped); relative interp is used verbatim (cwd). Returns
 * 0, -ENAMETOOLONG on overflow, -EINVAL on bad arguments. */
int sparc64_interp_resolve(const char *interp, const char *sysroot,
    char *out, size_t cap);

/* Map the ET_DYN BE SPARC64 interpreter open on fd at a free base
 * honouring the largest PT_LOAD p_align. Returns 0 with the
 * interpreter entry in entry_out, the load bias (AT_BASE) in
 * base_out, and the page-aligned post-image end in hi_out;
 * -ENOEXEC for a bad interpreter (incl. a nested PT_INTERP),
 * -ENOMEM when no hole fits, -EIO on short reads. The fd stays open. */
int sparc64_interp_map(sparc64_space_t *space, int fd,
    uint64_t *entry_out, uint64_t *base_out, uint64_t *hi_out);

#endif /* SPARC64RT_LOADER_INTERP_MAP_H */
