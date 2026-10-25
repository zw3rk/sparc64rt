/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SPARC64RT_RUNTIME_INITIAL_CHILDREN_H
#define SPARC64RT_RUNTIME_INITIAL_CHILDREN_H

#include "runtime/process_children.h"

/* Fresh, single-threaded bootstrap only, before spawning private helpers.
 * Capture visible, direct, ordinary Linux children through a verified proc
 * instance and exact nonconsuming pidfd waits. Success transfers private
 * CLOEXEC descriptors to the initially empty registry. Failure closes only
 * staged descriptors, leaves the registry unchanged, and sets errno.
 *
 * An initially empty PID1 is allowed without procfs; a child-bearing PID1
 * and every explicit subreaper are declined. Later orphan adoption remains
 * unsupported and is not automatically detected by the registry.
 * The first profile excludes init/subreaper adoption, ptrace-only inventories,
 * concurrent mount changes and new CLONE_PARENT births during discovery.
 * Private sparc64rt self-exec imports its existing exact inventory instead. */
int sparc64_process_children_discover_initial(sparc64_process_children_t *children);
/* Same operation with optional internal checkpoint diagnostics. *stage names
 * the last attempted step using static storage; it conveys no authority and
 * must not replace errno or the transactional success/failure result. */
int sparc64_process_children_discover_initial_diagnostic(
    sparc64_process_children_t *children, const char **stage);

#endif
