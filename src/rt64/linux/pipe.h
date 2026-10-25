/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SPARC64RT_LINUX_PIPE_H
#define SPARC64RT_LINUX_PIPE_H

#include "linux/file.h"

/* pipe2 and owned-pipe FIONREAD. The caller serializes guest state with its
 * family guard; FIONREAD retains the exact native descriptor through query
 * and checked LE32 copyout and never consumes data. Native descriptors stay
 * private and close-on-exec; fork ownership remains a separate requirement. */
bool sparc64_linux_pipe_dispatch(sparc64_linux_file_t *files, uint64_t number,
                            const uint64_t arguments[6], uint64_t *result);

#endif
