/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SPARC64RT_RUNTIME_PROCESS_MEMORY_H
#define SPARC64RT_RUNTIME_PROCESS_MEMORY_H

#include "linux/memory.h"
#include "memory/family_backing.h"
#include "memory/file_backing.h"

typedef struct sparc64_process_memory sparc64_process_memory_t;

/* Build an unpublished child image under the parent's uninterrupted family
 * guard. Parent mappings, bytes, bindings, counters and file sources are never
 * modified. Private payloads are copied once per alias group; shared anonymous
 * pages import their family keys. Private file views use child-owned sources.
 * On failure *out stays NULL and all child-local references are discarded.
 * It is safe to carry this heap-staged owner through a native fork: no copied
 * family mutex, object view or thread-bound guard is retained. */
int sparc64_process_memory_prepare(sparc64_process_memory_t **out,
                              const sparc64_linux_memory_t *parent,
                              sparc64_family_backing_t *parent_backing,
                              sparc64_family_t *parent_family,
                              sparc64_family_guard_t *parent_guard);
/* Native child only: allocate a fresh, empty local owner for an already
 * published canonical child MM. It copies no parent view, lock, file source
 * or payload. The exact inherited family guard owns backing installation;
 * the caller admits the prepared child root before guest execution. */
int sparc64_process_memory_create_canonical_empty(sparc64_process_memory_t **out,
    sparc64_family_t *child_family, sparc64_family_guard_t *child_guard,
    uint64_t limit, uint32_t slots_per_object,
    sparc64_file_identity_policy_t identity_policy);

/* Under a newly attached child family's local guard, adopt staged private
 * pages into child-owned objects and import shared keys. No guest pointer to
 * the child image escapes until the whole conversion succeeds. On failure the
 * caller discards the candidate and exits its child setup path. Family objects
 * created during a failed conversion remain private until family cleanup. */
int sparc64_process_memory_commit(sparc64_process_memory_t *prepared,
                              sparc64_family_t *child_family,
                              sparc64_family_guard_t *child_guard,
                              uint32_t slots_per_object);
/* Configure an unpublished child before commit. Callers capture the parent's
 * policy before destroying its copied registry, including a source-free mm. */
int sparc64_process_memory_set_file_identity_policy(sparc64_process_memory_t *prepared,
                                                sparc64_file_identity_policy_t policy);
int sparc64_process_memory_bind(sparc64_process_memory_t *committed,
                           sparc64_family_guard_t *child_guard);
void sparc64_process_memory_unbind(sparc64_process_memory_t *owner);

sparc64_space_t *sparc64_process_memory_space(sparc64_process_memory_t *owner);
sparc64_linux_memory_t *sparc64_process_memory_vmas(sparc64_process_memory_t *owner);
sparc64_file_registry_t *sparc64_process_memory_files(sparc64_process_memory_t *owner);
sparc64_family_backing_t *sparc64_process_memory_backing(sparc64_process_memory_t *owner);

/* Accessors expose only a committed child image. */
/* Abort an unpublished image or destroy a quiescent committed one. All page
 * owners and copyout capabilities must already be quiescent. NULL is accepted. */
void sparc64_process_memory_discard(sparc64_process_memory_t **owner);

#ifdef SPARC64_PROCESS_MEMORY_TEST_CHILD
/* Force a post-adoption shared import failure in the native fork test. */
void sparc64_process_memory_test_corrupt_shared_key(sparc64_process_memory_t *prepared);
#endif

#endif
