/* src/os/mem_space_split.h -- ported from src/rt64/memory/space_split.h (Wave U1 coordinator).
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SPARC64RT_MEMORY_SPACE_SPLIT_H
#define SPARC64RT_MEMORY_SPACE_SPLIT_H

/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#include "os/mem_space.h"

#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    sparc64_page_payload_t payload;
    unsigned char bytes[SPARC64_PAGE_SIZE];
    uint64_t epochs[SPARC64_PAGE_GRANULES];
} heap_payload_t;

enum map_mode { MAP_EXCLUSIVE, MAP_MERGE, MAP_REPLACE };

typedef struct {
    sparc64_page_payload_t *payload;
    sparc64_backing_t *view;
    uint64_t address;
    size_t first, last;
    size_t amount;
} epoch_touch_t;

typedef struct {
    uint64_t address, binding_base;
    unsigned int permissions;
    sparc64_backing_t *backing;
} copyout_page_t;

struct sparc64_copyout {
    sparc64_space_t *space;
    uint64_t address, generation;
    size_t maximum, count;
    epoch_touch_t *touches;
    bool consumed;
    copyout_page_t pages[];
};

struct sparc64_io_copyout {
    sparc64_copyout_t *pinned;
    bool consumed;
    epoch_touch_t touches[];
};

/* Cross-part declarations (generated L0a split). */
bool fail(sparc64_space_t *space, uint64_t address, sparc64_fault_reason_t reason);
bool managed_guard(sparc64_space_t *space, uint64_t address);
void sparc64_space_init(sparc64_space_t *space, unsigned int xlen);
bool sparc64_space_set_page_factory(sparc64_space_t *space, sparc64_page_factory_t factory);
bool sparc64_space_set_managed_factory(sparc64_space_t *space, sparc64_page_factory_t factory, sparc64_managed_page_ops_t managed);
bool sparc64_backing_retain(sparc64_backing_t *backing);
void sparc64_backing_release(sparc64_backing_t *backing);
void sparc64_space_destroy(sparc64_space_t *space);
size_t page_position(const sparc64_space_t *space, uint64_t address);
bool sparc64_space_map(sparc64_space_t *space, uint64_t address, uint64_t size, unsigned int permissions, bool merge);
bool sparc64_space_map_bus(sparc64_space_t *space, uint64_t address, uint64_t size, unsigned int permissions, bool replace);
bool sparc64_space_replace(sparc64_space_t *space, uint64_t address, uint64_t size, unsigned int permissions);
bool sparc64_space_map_file(sparc64_space_t *space, uint64_t address, uint64_t size, unsigned int permissions, bool replace, sparc64_file_source_t *source, uint64_t file_offset);
bool sparc64_space_map_shared_payload(sparc64_space_t *space, uint64_t address, unsigned int permissions, sparc64_page_payload_t *payload);
bool sparc64_space_map_managed_file_payload(sparc64_space_t *space, uint64_t address, unsigned int permissions, sparc64_page_payload_t *payload, sparc64_file_source_t *source, uint64_t offset);
bool sparc64_space_stage_managed_file_payload(sparc64_space_t *space, uint64_t address, unsigned int permissions, sparc64_page_payload_t *payload, sparc64_file_source_t *source, uint64_t offset);
bool sparc64_space_alias(sparc64_space_t *space, uint64_t source, uint64_t destination, uint64_t size, unsigned int permissions);
bool sparc64_space_unmap(sparc64_space_t *space, uint64_t address, uint64_t size);
bool sparc64_space_protect(sparc64_space_t *space, uint64_t address, uint64_t size, unsigned int permissions);
bool sparc64_space_find_hole(const sparc64_space_t *space, uint64_t start, uint64_t size, uint64_t *address);
bool sparc64_space_remap(sparc64_space_t *space, uint64_t source, uint64_t old_size, uint64_t destination, uint64_t new_size, unsigned int permissions);
bool validate_access(sparc64_space_t *space, uint64_t address, size_t size, unsigned int permissions);
bool sparc64_space_read(sparc64_space_t *space, uint64_t address, void *bytes, size_t size, unsigned int permissions);
bool first_managed_file_write(const sparc64_backing_t *view);
int compare_epoch_touches(const void *left, const void *right);
bool sparc64_space_prepare_write(sparc64_space_t *space, uint64_t address, size_t size);
bool sparc64_space_cow_file_page(sparc64_space_t *space, uint64_t address);
sparc64_copyout_t *sparc64_space_copyout_prepare(sparc64_space_t *space, uint64_t address, size_t maximum);
void sparc64_space_copyout_discard(sparc64_copyout_t *copyout);
sparc64_io_copyout_t *sparc64_space_io_copyout_prepare(sparc64_space_t *space, uint64_t address, size_t maximum);
void sparc64_space_io_copyout_discard(sparc64_io_copyout_t *copyout);
bool sparc64_space_io_copyout_commit(sparc64_io_copyout_t *copyout, const void *bytes, size_t actual, size_t *committed);
bool sparc64_space_copyout_commit(sparc64_copyout_t *copyout, const void *bytes, size_t actual);
bool sparc64_space_write_word_commit(sparc64_space_t *space, uint64_t address, const unsigned char bytes[4], sparc64_space_word_commit_fn commit, void *context);
bool sparc64_space_write(sparc64_space_t *space, uint64_t address, const void *bytes, size_t size);
bool sparc64_space_write_initial(sparc64_space_t *space, uint64_t address, const void *bytes, size_t size);
bool sparc64_space_atomic(sparc64_space_t *space, const sparc64_atomic_request_t *request, sparc64_atomic_result_t *result);

#endif /* SPARC64RT_MEMORY_SPACE_SPLIT_H */
