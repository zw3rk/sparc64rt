/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SPARC64RT_RUNTIME_MM_VIEW_SPLIT_H
#define SPARC64RT_RUNTIME_MM_VIEW_SPLIT_H

/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#include "runtime/mm_view_internal.h"
#include "memory/family_file.h"
#include "runtime/family_file_index.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

/* Cross-part declarations (generated L0a split). */
int sparc64_mm_view_create(sparc64_mm_view_t **out, sparc64_family_mm_t mm, sparc64_family_backing_t *backing, sparc64_space_t *space, sparc64_linux_memory_t *memory);
int sparc64_mm_view_bind_family_sources(sparc64_mm_view_t *view, sparc64_family_guard_t *guard, sparc64_file_identity_policy_t policy);
bool same_key(sparc64_family_page_key_t a, sparc64_family_page_key_t b);
int sparc64_mm_view_adopt(sparc64_mm_view_t **out, sparc64_family_mm_t mm, sparc64_family_backing_t *backing, sparc64_family_guard_t *guard, sparc64_space_t *space, sparc64_linux_memory_t *memory);
int sparc64_mm_view_seed(sparc64_mm_view_t **out, sparc64_family_backing_t *backing, sparc64_family_guard_t *guard, sparc64_space_t *space, sparc64_linux_memory_t *memory, uint64_t initial_task_id);
sparc64_family_mm_t sparc64_mm_view_identity(const sparc64_mm_view_t *view);
bool sparc64_mm_view_has_member(const sparc64_mm_view_t *view, const sparc64_family_guard_t *guard, uint64_t task_id);
int space_error(const sparc64_space_t *space);
void sparc64_mm_view_plan_discard(sparc64_mm_view_plan_t *plan);
int sparc64_mm_view_plan_prepare(sparc64_mm_view_t *view, sparc64_family_mm_state_t *state, sparc64_mm_view_plan_t *plan);
void sparc64_mm_view_plan_apply(sparc64_mm_view_t *view, sparc64_mm_view_plan_t *plan);
int sparc64_mm_view_refresh(sparc64_mm_view_t *view, sparc64_family_guard_t *guard);
int sparc64_mm_view_mprotect(sparc64_mm_view_t *view, sparc64_family_guard_t *guard, uint64_t address, uint64_t length, uint64_t protection, uint64_t *guest_result);
int sparc64_mm_view_state_unmap(sparc64_family_mm_state_t *state, uint64_t start, uint64_t end);
int sparc64_mm_view_munmap(sparc64_mm_view_t *view, sparc64_family_guard_t *guard, uint64_t address, uint64_t length, uint64_t *guest_result);
int sparc64_mm_view_state_insert(sparc64_mm_view_t *view, sparc64_family_mm_state_t *state, sparc64_space_t *fresh, sparc64_vma_t added);
size_t origin_position(const sparc64_family_file_index_state_t *index, sparc64_family_page_key_t key);
size_t source_position(const sparc64_family_file_index_state_t *index, uint64_t id);
bool transaction_key(sparc64_mm_view_t *view, const sparc64_space_t *fresh, sparc64_family_page_key_t key);
int sparc64_mm_view_plan_admit_files(sparc64_mm_view_t *view, sparc64_family_guard_t *guard, sparc64_mm_view_plan_t *plan, const sparc64_space_t *fresh);
int sparc64_mm_view_map_file_private(sparc64_mm_view_t *view, sparc64_family_guard_t *guard, uint64_t address, uint64_t length, unsigned int permissions, unsigned int may_permissions, uint64_t source_id, uint64_t file_offset);
int sparc64_mm_view_map_file_readonly(sparc64_mm_view_t *view, sparc64_family_guard_t *guard, uint64_t address, uint64_t length, unsigned int permissions, uint64_t source_id, uint64_t file_offset);
int sparc64_mm_view_mmap_anon(sparc64_mm_view_t *view, sparc64_family_guard_t *guard, uint64_t address, uint64_t length, uint64_t protection, uint64_t flags, uint64_t offset, uint64_t *guest_result);
int sparc64_mm_view_mmap_file_private_fd(sparc64_mm_view_t *view, sparc64_family_guard_t *guard, uint64_t address, uint64_t length, uint64_t protection, uint64_t flags, int borrowed_readable_fd, uint64_t offset, uint64_t *guest_result);
int sparc64_mm_view_brk(sparc64_mm_view_t *view, sparc64_family_guard_t *guard, uint64_t address, uint64_t *guest_result);
uint64_t sparc64_mm_view_revision(const sparc64_mm_view_t *view);
void sparc64_mm_view_destroy(sparc64_mm_view_t **owned);

#endif /* SPARC64RT_RUNTIME_MM_VIEW_SPLIT_H */
