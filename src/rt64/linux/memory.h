/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SPARC64RT_LINUX_MEMORY_H
#define SPARC64RT_LINUX_MEMORY_H

#include "memory/space.h"

typedef enum {
    SPARC64_VMA_INITIAL, SPARC64_VMA_ANONYMOUS, SPARC64_VMA_BRK, SPARC64_VMA_FILE_PRIVATE,
    SPARC64_VMA_ANONYMOUS_SHARED
} sparc64_vma_kind_t;

typedef struct {
    uint64_t start, end, backing_id, offset;
    unsigned int permissions, may_permissions;
    sparc64_vma_kind_t kind;
} sparc64_vma_t;

typedef struct {
    sparc64_space_t *space;
    sparc64_vma_t *vmas;
    size_t count;
    uint64_t next_id, brk_id, minimum_break, current_break;
} sparc64_linux_memory_t;

/* Seed loader/stack coverage before any guest syscall. The context owns only
 * VMA records; space owns backing through its selected factory. Production
 * anonymous mappings use the managed family factory under the family guard.
 * Shared/private VMA kind remains explicit for later process inheritance;
 * accepting a shared anonymous mapping does not enable fork or file sharing. */
bool sparc64_linux_memory_init(sparc64_linux_memory_t *memory, sparc64_space_t *space,
                          uint64_t program_break);
void sparc64_linux_memory_destroy(sparc64_linux_memory_t *memory);
uint64_t sparc64_linux_mmap(sparc64_linux_memory_t *memory, uint64_t address,
                       uint64_t length, uint64_t protection, uint64_t flags,
                       uint64_t fd, uint64_t offset);
/* Caller owns one source ref independently. Mapping retains page references. */
uint64_t sparc64_linux_mmap_source(sparc64_linux_memory_t *memory, uint64_t address,
                              uint64_t length, uint64_t protection, uint64_t flags,
                              sparc64_file_source_t *source, uint64_t offset);
uint64_t sparc64_linux_munmap(sparc64_linux_memory_t *memory, uint64_t address, uint64_t length);
uint64_t sparc64_linux_mprotect(sparc64_linux_memory_t *memory, uint64_t address,
                           uint64_t length, uint64_t protection);
uint64_t sparc64_linux_brk(sparc64_linux_memory_t *memory, uint64_t address);
uint64_t sparc64_linux_mremap(sparc64_linux_memory_t *memory, uint64_t address,
                         uint64_t old_length, uint64_t new_length,
                         uint64_t flags, uint64_t new_address);

#endif
