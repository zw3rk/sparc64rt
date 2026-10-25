/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SPARC64RT_MEMORY_FILE_BACKING_H
#define SPARC64RT_MEMORY_FILE_BACKING_H

#include "memory/space.h"
#include "memory/file_identity.h"

typedef struct sparc64_file_object sparc64_file_object_t;
typedef struct sparc64_file_mutation sparc64_file_mutation_t;
typedef struct sparc64_file_prepared sparc64_file_prepared_t;
typedef struct sparc64_file_refresh_scope sparc64_file_refresh_scope_t;
/* Internal counterpart of sparc64_space_refresh_capture/apply. sample performs
 * native I/O without consulting any registry, space, backing, or observer. */
sparc64_file_refresh_ticket_t *sparc64_file_refresh_ticket_capture(sparc64_space_t *space,
    const sparc64_page_t *page, uint64_t fault_address, unsigned int permissions);
void sparc64_file_refresh_sample(sparc64_file_refresh_ticket_t *ticket);
sparc64_refresh_result_t sparc64_file_refresh_ticket_apply(sparc64_space_t *space,
    sparc64_file_refresh_ticket_t *ticket);
void sparc64_file_refresh_ticket_discard(sparc64_file_refresh_ticket_t **ticket);
/* One engine attempt's bounded learned page set. enter/leave require the
 * family guard; leave clears the shared space callback BEFORE the guard can
 * be released, so no sibling can observe another worker's stack-local scope.
 * Captured tickets remain owned by the active unsuspended scheduler I/O
 * flight until resume/discard under the guard. */
sparc64_file_refresh_scope_t *sparc64_file_refresh_scope_create(sparc64_space_t *space);
bool sparc64_file_refresh_scope_enter(sparc64_file_refresh_scope_t *scope);
void sparc64_file_refresh_scope_leave(sparc64_file_refresh_scope_t *scope);
sparc64_refresh_result_t sparc64_file_refresh_scope_capture(sparc64_file_refresh_scope_t *scope);
void sparc64_file_refresh_scope_sample(sparc64_file_refresh_scope_t *scope);
sparc64_refresh_result_t sparc64_file_refresh_scope_resume(sparc64_file_refresh_scope_t *scope);
/* Forget value-only requirements when a retried instruction decodes a new
 * source. Requires the family guard; capacity overflow needs explicit caller
 * handling rather than silently erasing a live requirement. */
void sparc64_file_refresh_scope_reset(sparc64_file_refresh_scope_t *scope);
bool sparc64_file_refresh_scope_overflowed(const sparc64_file_refresh_scope_t *scope);
void sparc64_file_refresh_scope_destroy(sparc64_file_refresh_scope_t **scope);
typedef struct {
    sparc64_space_t *space;
    sparc64_file_object_t *head; /* Weak index; pages and temporary users own refs. */
    sparc64_file_identity_policy_t identity_policy;
} sparc64_file_registry_t;

void sparc64_file_registry_init(sparc64_file_registry_t *registry, sparc64_space_t *space);
/* Set before acquiring sources; setting the current policy is idempotent. */
int sparc64_file_registry_set_identity_policy(sparc64_file_registry_t *registry,
                                          sparc64_file_identity_policy_t policy);
/* Orphan still-mapped sources; their last page release closes the private FD. */
void sparc64_file_registry_destroy(sparc64_file_registry_t *registry);
/* Consumes owned_fd on every outcome, returns one retained source or NULL.
 * Only readable ordinary files are supported. Only proven equal identities
 * share a source; unknown sources remain distinct. Pathname replacement never
 * replaces a retained handle. */
sparc64_file_source_t *sparc64_file_source_acquire(sparc64_file_registry_t *registry, int owned_fd);
/* Split native metadata preparation from guarded registry publication. Prepare
 * consumes owned_fd on every outcome and owns a detached candidate: it never
 * touches a registry or guest space. Admit requires the matching fixed policy,
 * compares only cached identities, and never refreshes an existing source's
 * observed size or mutation state. On success it consumes *prepared; on
 * failure discard it after returning to the caller's cleanup path. */
int sparc64_file_source_prepare(int owned_fd, sparc64_file_identity_policy_t policy,
                            sparc64_file_prepared_t **out);
sparc64_file_source_t *sparc64_file_source_admit(sparc64_file_registry_t *registry,
                                       sparc64_file_prepared_t **prepared);
void sparc64_file_source_prepared_discard(sparc64_file_prepared_t **prepared);
/* Borrow a native fd only to find an already mapped source. A nonmapped inode
 * returns NULL with errno0. A returned source has one temporary reference. */
sparc64_file_source_t *sparc64_file_source_find(sparc64_file_registry_t *registry, int native_fd);
/* Duplicate a retained private source into another space's registry. The
 * child owns its native descriptor and refresh state; no parent source pointer
 * remains in the child. The returned reference must be released by caller. */
sparc64_file_source_t *sparc64_file_source_clone_into(sparc64_file_registry_t *child,
                                            sparc64_file_source_t *parent);
/* Copy the cached identity and borrow its exact retained FD. This is not an
 * independent provider query or a lifetime pin for a shared futex key. */
int sparc64_file_source_identity(sparc64_file_source_t *source,
                              sparc64_file_identity_t *out, int *borrowed_fd);

/* Retain every possibly aliasing source before native mutation. Known source
 * identity selects exact matches plus all unknown sources. An unknown writer
 * selects every source, with full-range conservative invalidation. Nonregular
 * FDs or no candidate sources return success with *out=NULL. Hold the same
 * memory/mapping ownership through capture, prepare, native I/O and commit.
 * Preparation checks aggregate generation capacity; commit allocates nothing.
 * Destroy releases retained references even after failed I/O. */
int sparc64_file_mutation_begin(sparc64_file_registry_t *registry, int native_fd,
                             sparc64_file_mutation_t **out);
bool sparc64_file_mutation_needs_position(const sparc64_file_mutation_t *mutation);
bool sparc64_file_mutation_prepare_write(sparc64_file_mutation_t *mutation,
                                      uint64_t offset, uint64_t maximum_size);
void sparc64_file_mutation_commit_write(sparc64_file_mutation_t *mutation,
                                     uint64_t offset, uint64_t actual_size);
bool sparc64_file_mutation_prepare_resize(sparc64_file_mutation_t *mutation, uint64_t size);
bool sparc64_file_mutation_commit_resize(sparc64_file_mutation_t *mutation, uint64_t size);
void sparc64_file_mutation_destroy(sparc64_file_mutation_t **mutation);
/* After O_TRUNC and its global preflight, refresh candidate baselines from
 * each retained FD. Never apply one inode's new size to an unknown other file.
 * No allocation occurs after the irreversible open side effect. */
bool sparc64_file_registry_observe_resize(sparc64_file_registry_t *registry);
bool sparc64_file_registry_prepare_truncate(sparc64_file_registry_t *registry);

/* The caller serializes guest memory, mapping and file mutations throughout
 * prepare/host-I/O/commit. Prepare is nonmutating; commit allocates nothing and
 * cannot fail after successful preparation under that ownership. Never commit
 * failed writes; pass only the actual positive byte range. These APIs apply to
 * the bounded single-process model until R5 adds managed-family ownership. */
bool sparc64_file_prepare_write(sparc64_file_source_t *source, uint64_t offset, uint64_t size);
void sparc64_file_commit_write(sparc64_file_source_t *source, uint64_t offset, uint64_t size);
bool sparc64_file_prepare_resize(sparc64_file_source_t *source, uint64_t size);
void sparc64_file_commit_resize(sparc64_file_source_t *source, uint64_t size);

#endif
