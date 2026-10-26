/*
 * src/os/host_contract_interp.h — Wave U1 PT_INTERP path helpers
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Minimal migration of the PT_INTERP path extraction/resolution slice
 * of src/rt64/loader/interp_map.h needed by the host-contract cache
 * identity (dynamic PT_INTERP binds both file digests). The space-backed
 * mapper (sparc64_interp_map) and sysroot opener stay with the loader;
 * only the position-independent pread helpers move here.
 */

#ifndef SPARC64RT_OS_HOST_CONTRACT_INTERP_H
#define SPARC64RT_OS_HOST_CONTRACT_INTERP_H

#include <stddef.h>

/* Longest PT_INTERP byte range accepted (incl. the NUL). */
#define SPARC64RT_INTERP_PATH_MAX 4096U

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

#endif /* SPARC64RT_OS_HOST_CONTRACT_INTERP_H */
