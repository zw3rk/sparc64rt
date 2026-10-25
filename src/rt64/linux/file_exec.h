/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SPARC64RT_LINUX_FILE_EXEC_H
#define SPARC64RT_LINUX_FILE_EXEC_H

#include "linux/file.h"
#include "linux/fd_handoff.h"

/* Initialize a new exec image without importing the host's standard FDs.
 * `files` must point to zero-initialized, unused storage. `absolute_sysroot`
 * must be a non-NULL absolute path. The FIFO list is trusted same-UID
 * self-exec metadata, not independently authenticated provenance.
 *
 * Before `sparc64_fd_handoff_receive` is called, invalid storage/count or other
 * factory arguments leave metadata/capability descriptors and their vector
 * untouched. With valid storage, receive owns the metadata value and consumes
 * each distinct capability FD according to that API even if the metadata FD
 * itself is invalid, clearing consumed vector slots. Later initialization
 * failures destroy all transferred state.
 */
int sparc64_linux_file_exec_init(sparc64_linux_file_t *files, sparc64_space_t *space,
                            int owned_metadata, int *owned_descriptors,
                            size_t descriptor_count,
                            const sparc64_linux_fifo_identity_t *fifo_identities,
                            size_t fifo_count, const char *absolute_sysroot);

#endif
