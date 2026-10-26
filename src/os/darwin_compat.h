/*
 * src/os/darwin_compat.h -- macOS portability shims (Lane S1)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Declarations consumed by the syscall TUs that reference Linux-only
 * APIs: O_PATH has no Darwin equivalent, and pipe2(2) is absent on
 * macOS. Everything here is portability-only: guest layouts, return
 * codes, and dispatch in the calling TUs are unchanged.
 */

#ifndef SPARC64RT_OS_DARWIN_COMPAT_H
#define SPARC64RT_OS_DARWIN_COMPAT_H

#include <fcntl.h>

/* O_PATH (Linux path-only open) has no APFS equivalent. Define it as 0
 * so the O_ACCMODE masks in the syscall TUs keep compiling: a guest
 * O_PATH request degrades to a read-only open, which the synthetic
 * /proc handlers already gate to ENOENT/EACCES where it matters. */
#ifndef O_PATH
#define O_PATH 0
#endif

/* pipe2(2) via pipe(2) + fcntl. Only O_CLOEXEC and O_NONBLOCK are
 * accepted; anything else is -EINVAL, mirroring the Linux call. */
int rt_darwin_pipe2(int fds[2], int flags);

#endif /* SPARC64RT_OS_DARWIN_COMPAT_H */
