/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SPARC64RT_RUNTIME_MM_JOIN_H
#define SPARC64RT_RUNTIME_MM_JOIN_H

#include "runtime/mm_view.h"

typedef struct sparc64_mm_join_image sparc64_mm_join_image_t;

/* Hold the parent's exact family guard after refreshing and freezing its
 * local workers. Capture the existing MM identity without copying private
 * keys, creating a root, or publishing a child member. Source-enabled family
 * capabilities must remain owned across native fork. This is an internal
 * component, not guest clone/vfork admission or a parent-suspension protocol. */
int sparc64_mm_join_prepare(sparc64_mm_view_t *parent, sparc64_family_guard_t *parent_guard,
                        sparc64_mm_join_image_t **out);

/* Fresh native child only, with a transferred family and fresh empty backing,
 * space and memory registry under the child's exact guard. Read the CURRENT
 * parent MM root, prepare all local views, then publish the child's unique
 * incarnation/task member and apply without failure. Parent departure does
 * not invalidate the retained MM; zero remaining members are permitted.
 * 0 consumes *image and publishes *out. -1 leaves both unchanged before any
 * member commit; -2 means publication was attempted with uncertain outcome:
 * fail-stop rather than retry or execute. No source service is created here.
 * Destroy space/VMAs under the guard before destroying the fresh backing. */
int sparc64_mm_join_child_adopt(sparc64_mm_join_image_t **image,
                            sparc64_family_guard_t *child_guard,
                            sparc64_family_backing_t *child_backing,
                            sparc64_space_t *empty_space,
                            sparc64_linux_memory_t *empty_memory,
                            sparc64_file_identity_policy_t identity_policy,
                            uint64_t child_task_id, sparc64_mm_view_t **out);

void sparc64_mm_join_image_destroy(sparc64_mm_join_image_t **owned);

/* Successful native exec's receive side only, after old clear-TID/wait replay
 * under this uninterrupted inherited lease. Require the caller's old member;
 * remove exactly this incarnation's <=4096 tasks while preserving all foreign
 * members and mapping/payload metadata. A commit error is infrastructure-fatal.
 * Local views of the departing image must not execute after this publication. */
int sparc64_mm_retire_exec_owner(sparc64_family_guard_t *guard, sparc64_family_mm_t mm,
                            uint64_t caller_task_id);

#endif
