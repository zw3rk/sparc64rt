/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SPARC64RT_MEMORY_MM_FORK_H
#define SPARC64RT_MEMORY_MM_FORK_H

#include "runtime/mm_view.h"

typedef struct sparc64_mm_fork_image sparc64_mm_fork_image_t;

/* The caller owns the parent's uninterrupted family guard and has frozen all
 * other guest workers, native I/O and MM mutation. This stages a zero-member
 * child MM before native fork: private aliases get fresh exact payload states;
 * shared DATA/BUS keys and original manifests remain shared. File origins for
 * fresh private keys are admitted before the new MM root. No parent MM root,
 * member or local copyout binding changes. The result contains only immutable
 * IDs and identity values, never a copied lock, descriptor, view or source.
 * Unreachable staged objects/origins may remain after failure. EIO from a
 * staged object/index/root commit is infrastructure-uncertain and must follow
 * family recovery/fatal policy, never become an ordinary retryable fork errno. */
int sparc64_mm_fork_prepare(sparc64_mm_view_t *parent, sparc64_family_guard_t *parent_guard,
                       sparc64_mm_fork_image_t **out);

/* Child-only, after native family transfer/enter and creation of a fresh
 * backing installed on an empty space. The memory registry is also empty and
 * names that space. Bind the inherited family source namespace and stage the
 * local maps, publish exactly the new guard incarnation/task member, then
 * apply the prepared maps without allocation.
 * 0 transfers *image to *out. -1 is pre-member failure, with *image retained;
 * -2 means member commit was attempted and its outcome is uncertain:
 * terminate the child, never retry or enter guest execution. This component
 * does not own or retire the family's source service. */
int sparc64_mm_fork_child_adopt(sparc64_mm_fork_image_t **image,
                            sparc64_family_guard_t *child_guard,
                            sparc64_family_backing_t *child_backing,
                            sparc64_space_t *empty_space,
                            sparc64_linux_memory_t *empty_memory,
                            sparc64_file_identity_policy_t identity_policy,
                            uint64_t child_task_id, sparc64_mm_view_t **out);

/* Parent thaw/failure drops only local metadata. The published zero-member MM
 * and immutable origin orphans remain under normal family lifetime cleanup. */
void sparc64_mm_fork_image_destroy(sparc64_mm_fork_image_t **owned);

#endif
