/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SPARC64RT_LINUX_FD_HANDOFF_H
#define SPARC64RT_LINUX_FD_HANDOFF_H

#include "linux/fd.h"
#include "linux/resolve.h"

typedef struct sparc64_fd_handoff sparc64_fd_handoff_t;

/* Quiescent exec preparation. Filter guest CLOEXEC entries, retain one lease
 * per surviving description, and encode explicit little-endian records in an
 * unlinked owner-only regular file. A scoped resolver registration protects
 * its metadata inode until owner destruction, before resolver teardown. All native
 * leases and metadata start CLOEXEC; the source table is unchanged.
 * Temporary dup/close can affect native process record locks: guest record
 * locks are currently unsupported; this is not their final exec contract. */
int sparc64_fd_handoff_create(sparc64_fd_table_t *table, sparc64_path_resolver_t *resolver,
                          sparc64_fd_handoff_t **out);
/* Borrowed capabilities; never close or reuse them while the owner is live.
 * The eventual startup transport carries these separately from the metadata.
 * Metadata records contain description indices, never native FD numbers. */
int sparc64_fd_handoff_metadata(const sparc64_fd_handoff_t *handoff);
size_t sparc64_fd_handoff_descriptors(const sparc64_fd_handoff_t *handoff,
                                 int output[SPARC64_FD_TABLE_LIMIT]);

/* Under complete runtime/native-I/O quiescence, clear only native CLOEXEC.
 * A failed activation rolls back changes. Deactivate after a failed exec and
 * before resuming guest workers. Any deactivation/rollback failure is fatal
 * to the runtime: never resume with unintended inheritable capabilities. */
int sparc64_fd_handoff_activate(sparc64_fd_handoff_t *handoff);
int sparc64_fd_handoff_deactivate(sparc64_fd_handoff_t *handoff);
/* Destroy under the same quiescence/token used for creation, while the
 * borrowed resolver is alive. Retire metadata protection before its last pin. */
void sparc64_fd_handoff_destroy(sparc64_fd_handoff_t **handoff);

/* Child startup only, before guest stdio/resolver/workers exist. The caller
 * supplies explicitly owned received capabilities, not FD numbers extracted
 * from the metadata. Count must be <= SPARC64_FD_TABLE_LIMIT with non-NULL storage
 * when nonzero; invalid storage/count does not transfer ownership. Otherwise
 * consume metadata and every distinct vector FD >=3 on every outcome, clear
 * vector slots, and publish a fresh table only after complete validation.
 * Restore CLOEXEC on received capabilities before parsing/import. The private
 * metadata FD is never a guest entry. Same-UID native callers are trusted;
 * this format authenticates neither managed provenance nor OFD identity. */
int sparc64_fd_handoff_receive(int owned_metadata, int *owned_descriptors,
                           size_t count, sparc64_fd_table_t *destination);

#endif
