/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SPARC64RT_MEMORY_FILE_BACKING_SPLIT_H
#define SPARC64RT_MEMORY_FILE_BACKING_SPLIT_H

/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L
#include "memory/file_backing.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

_Static_assert(sizeof(off_t) == 8, "file backing requires native 64-bit offsets");

struct sparc64_file_object {
    sparc64_file_source_t source;
    sparc64_file_registry_t *registry;
    sparc64_file_object_t *next;
    int fd;
    sparc64_file_identity_t identity;
    size_t references;
    uint64_t observed_size;
};

struct sparc64_file_prepared {
    sparc64_file_object_t file; /* Transfer this allocation on first admission. */
    sparc64_file_identity_policy_t policy;
};

struct sparc64_file_refresh_ticket {
    sparc64_backing_t *backing; /* Retained only while an active I/O flight blocks fork. */
    sparc64_space_t *space;
    sparc64_file_source_t *source;
    sparc64_page_payload_t *payload;
    int fd;
    uint64_t address, fault_address, binding, generation, offset, observed_size;
    unsigned int permissions;
    uint64_t notified[4];
    uint64_t epochs[SPARC64_PAGE_GRANULES];
    bool private_cow, sampled, native_failed, native_interrupted;
    uint64_t first_size, last_size;
    unsigned char bytes[SPARC64_PAGE_SIZE];
};
bool refresh(sparc64_file_source_t *source, sparc64_backing_t *backing, uint64_t address);

enum { SPARC64_REFRESH_SCOPE_MAX = 8 };
typedef struct {
    uint64_t address;
    unsigned int permissions;
    sparc64_file_refresh_ticket_t *ticket;
    size_t alias_of; /* Equal retained backing shares one native sample. */
    bool proved;
} sparc64_refresh_need_t;

struct sparc64_file_refresh_scope {
    sparc64_space_t *space;
    size_t count;
    bool entered;
    bool pending_sample;
    bool overflowed;
    sparc64_refresh_need_t needs[SPARC64_REFRESH_SCOPE_MAX];
};

typedef struct {
    sparc64_file_source_t *source;
    bool wide;
    uint64_t after_size;
} mutation_entry_t;

struct sparc64_file_mutation {
    sparc64_space_t *space;
    size_t count;
    uint64_t offset, size;
    unsigned int prepared; /* 0=capture only, 1=write, 2=resize. */
    mutation_entry_t entries[];
};

/* Cross-part declarations (generated L0a split). */
sparc64_file_object_t *object(sparc64_file_source_t *source);
void sparc64_file_registry_init(sparc64_file_registry_t *registry, sparc64_space_t *space);
int sparc64_file_registry_set_identity_policy(sparc64_file_registry_t *registry, sparc64_file_identity_policy_t policy);
void sparc64_file_registry_destroy(sparc64_file_registry_t *registry);
void retain(sparc64_file_source_t *source);
void release(sparc64_file_source_t *source);
bool sparc64_file_backing_fail(sparc64_file_source_t *source, uint64_t address, sparc64_fault_reason_t reason);
bool epoch_capacity(const sparc64_backing_t *backing, size_t first, size_t length);
void advance_epochs(sparc64_backing_t *backing, size_t first, size_t length);
size_t resize_start(const sparc64_backing_t *backing, uint64_t size);
bool sparc64_file_prepare_resize(sparc64_file_source_t *source, uint64_t size);
void sparc64_file_commit_resize(sparc64_file_source_t *source, uint64_t size);
bool observe_size(sparc64_file_source_t *source, uint64_t size, uint64_t address);
int measured_stat(sparc64_file_object_t *file, struct stat *status);
bool refresh(sparc64_file_source_t *source, sparc64_backing_t *backing, uint64_t address);
sparc64_file_refresh_ticket_t *sparc64_file_refresh_ticket_capture(sparc64_space_t *space, const sparc64_page_t *page, uint64_t fault_address, unsigned int permissions);
sparc64_refresh_result_t sparc64_space_refresh_capture(sparc64_space_t *space, uint64_t address, unsigned int permissions, sparc64_file_refresh_ticket_t **out);
void sparc64_file_refresh_sample(sparc64_file_refresh_ticket_t *ticket);
sparc64_refresh_result_t sparc64_file_refresh_ticket_apply(sparc64_space_t *space, sparc64_file_refresh_ticket_t *ticket);
sparc64_refresh_result_t sparc64_space_refresh_apply(sparc64_space_t *space, sparc64_file_refresh_ticket_t *ticket);
void sparc64_file_refresh_ticket_discard(sparc64_file_refresh_ticket_t **ticket);
sparc64_file_refresh_scope_t *sparc64_file_refresh_scope_create(sparc64_space_t *space);
bool sparc64_file_refresh_scope_enter(sparc64_file_refresh_scope_t *scope);
void sparc64_file_refresh_scope_leave(sparc64_file_refresh_scope_t *scope);
sparc64_refresh_result_t sparc64_file_refresh_scope_capture(sparc64_file_refresh_scope_t *scope);
void sparc64_file_refresh_scope_sample(sparc64_file_refresh_scope_t *scope);
sparc64_refresh_result_t sparc64_file_refresh_scope_resume(sparc64_file_refresh_scope_t *scope);
void sparc64_file_refresh_scope_reset(sparc64_file_refresh_scope_t *scope);
bool sparc64_file_refresh_scope_overflowed(const sparc64_file_refresh_scope_t *scope);
void sparc64_file_refresh_scope_destroy(sparc64_file_refresh_scope_t **scope);
sparc64_file_object_t *lookup(const sparc64_file_registry_t *registry, const sparc64_file_identity_t *identity);
sparc64_file_source_t *acquire(sparc64_file_registry_t *registry, int owned_fd, const sparc64_file_identity_t *proven);
sparc64_file_source_t *sparc64_file_source_acquire(sparc64_file_registry_t *registry, int owned_fd);
void sparc64_file_source_prepared_discard(sparc64_file_prepared_t **prepared);
int sparc64_file_source_prepare(int owned_fd, sparc64_file_identity_policy_t policy, sparc64_file_prepared_t **out);
sparc64_file_source_t *sparc64_file_source_admit(sparc64_file_registry_t *registry, sparc64_file_prepared_t **prepared);
sparc64_file_source_t *sparc64_file_source_find(sparc64_file_registry_t *registry, int native_fd);
sparc64_file_source_t *sparc64_file_source_clone_into(sparc64_file_registry_t *child, sparc64_file_source_t *parent);
int sparc64_file_source_identity(sparc64_file_source_t *source, sparc64_file_identity_t *out, int *borrowed_fd);
bool sparc64_file_prepare_write(sparc64_file_source_t *source, uint64_t offset, uint64_t size);
void sparc64_file_commit_write(sparc64_file_source_t *source, uint64_t offset, uint64_t size);
int sparc64_file_mutation_begin(sparc64_file_registry_t *registry, int native_fd, sparc64_file_mutation_t **out);
bool sparc64_file_mutation_needs_position(const sparc64_file_mutation_t *mutation);
bool sparc64_file_mutation_prepare_write(sparc64_file_mutation_t *mutation, uint64_t offset, uint64_t maximum_size);
void sparc64_file_mutation_commit_write(sparc64_file_mutation_t *mutation, uint64_t offset, uint64_t actual_size);
bool sparc64_file_mutation_prepare_resize(sparc64_file_mutation_t *mutation, uint64_t size);
bool sparc64_file_mutation_commit_resize(sparc64_file_mutation_t *mutation, uint64_t size);
void sparc64_file_mutation_destroy(sparc64_file_mutation_t **owned);
bool sparc64_file_registry_prepare_truncate(sparc64_file_registry_t *registry);
bool sparc64_file_registry_observe_resize(sparc64_file_registry_t *registry);

#endif /* SPARC64RT_MEMORY_FILE_BACKING_SPLIT_H */
