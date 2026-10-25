/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SPARC64RT_LINUX_ERROR_H
#define SPARC64RT_LINUX_ERROR_H

/* Translate a host errno to the Linux UAPI number; unknown values become EIO. */
unsigned int sparc64_linux_errno(int host_errno);

#endif
