/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SPARC64RT_MEMORY_FAMILY_BACKING_H
#define SPARC64RT_MEMORY_FAMILY_BACKING_H

#include "memory/space.h"
#include "runtime/family.h"
#include "runtime/family_wait.h"

typedef struct sparc64_family_backing sparc64_family_backing_t;

/* Owns packed objects with the requested fixed slot count. Each object costs
 * one retained FD/view, irrespective of its page count. The backing and its
 * family must outlive every installed space and payload. */
int sparc64_family_backing_create(sparc64_family_backing_t **out, sparc64_family_t *family,
                             uint32_t slots_per_object);
/* Bind the active thread-bound guard for all managed memory operations.
 * Binding a stale/copied/wrong-family guard fails. Unbind after the operation. */
int sparc64_family_backing_bind(sparc64_family_backing_t *backing,
                           sparc64_family_guard_t *guard);
/* Verify exact current local guard ownership before inspecting parent keys. */
bool sparc64_family_backing_guard_matches(const sparc64_family_backing_t *backing,
                                      const sparc64_family_guard_t *guard);
void sparc64_family_backing_unbind(sparc64_family_backing_t *backing);
/* Install only on an empty space. Anonymous pages use packed managed objects;
 * legacy private file mappings retain heap payloads and their refresh/COW path.
 * Canonical file imports use the explicit managed-file mapping seams below.
 * Both kinds require the bound family guard for every access. */
bool sparc64_family_backing_install(sparc64_family_backing_t *backing, sparc64_space_t *space);
/* Allocate anonymous pages only in an installed, empty UNPUBLISHED candidate
 * under this backing's bound guard. Restore the ordinary factory on return.
 * Direct node/payload calloc failure is SPARC64_FAULT_RESOURCE; object creation,
 * observer, snapshot and guard failures remain SPARC64_FAULT_INTERNAL, irrespective
 * of errno. Never infer resumability from arbitrary custom-factory errno.
 * Failure preserves the empty page registry; private slots may be consumed. */
bool sparc64_family_backing_stage_anonymous(sparc64_family_backing_t *backing,
                                        sparc64_space_t *space, uint64_t address,
                                        uint64_t size, unsigned int permissions);
/* Convert an already-loaded private anonymous image while the bound family
 * guard is held, before guest execution or any copyout capability exists.
 * File-private pages keep their heap backing. Anonymous aliases retain one
 * shared managed payload, while each guest page receives a fresh binding.
 * All allocation and source validation finish before the page registry is
 * published. A failed conversion leaves the old space and its ownership
 * intact; newly created family objects remain private until cleanup. */
bool sparc64_family_backing_adopt(sparc64_family_backing_t *backing, sparc64_space_t *space);
/* Stable packed identity for serialization and checked external refresh tests.
 * Returns a key only for a payload owned by this backing. */
bool sparc64_family_backing_key(sparc64_family_backing_t *backing,
                           sparc64_page_payload_t *payload,
                           sparc64_family_page_key_t *out);
/* Intern an exact retained file identity using this backing's current guard.
 * The caller has obtained identity and fd from one live private file source.
 * A failure after family publication is EIO, never a resumable guest error. */
int sparc64_family_backing_file_intern(sparc64_family_backing_t *backing,
                                   const sparc64_file_identity_t *identity, int fd,
                                   uint64_t *file_id);
/* Commit waiter rows together with 0..2 prepared managed updates while this
 * backing's exact guard is held. Publish canonical local mirrors only after
 * the shared transaction succeeds. count=0 supports private heap/COW words.
 * ENOMEM denotes only a precommit allocation failure; a poisoned family or
 * other invalid transaction returns EIO and cannot be retried as a guest fault.
 * The table revision advances only on success. */
bool sparc64_family_backing_commit_wait(sparc64_family_backing_t *backing,
                                    sparc64_family_wait_table_t *table,
                                    const sparc64_managed_page_update_t *updates,
                                    size_t count);
/* Import one existing packed object slot into a vacant guest page. The space
 * must use this backing's managed factory and hold its bound family guard.
 * Repeated imports of one key share one local payload mirror; each mapping
 * receives a distinct view/binding. The object's actual slot count governs
 * validity. Failed mapping does not publish a view, consume a local factory
 * slot, seed bytes, or commit an object update. */
bool sparc64_family_backing_map_shared(sparc64_family_backing_t *backing,
                                  sparc64_space_t *space, uint64_t guest_page,
                                  unsigned int permissions,
                                  sparc64_family_page_key_t key);
/* Trusted managed-file adapter seams. Key/source/offset association must come
 * from validated canonical provenance; a bare payload key does not prove it.
 * Mapping stages source retention before publishing any live view. */
bool sparc64_family_backing_map_file(sparc64_family_backing_t *backing,
                                sparc64_space_t *space, uint64_t guest_page,
                                unsigned int permissions, sparc64_family_page_key_t key,
                                sparc64_file_source_t *source, uint64_t offset);
/* Unpublished candidate variant, source retains its stable final space owner.
 * Same guard/context/limit required; do not read candidate before apply. */
bool sparc64_family_backing_stage_file(sparc64_family_backing_t *backing,
                                  sparc64_space_t *space, uint64_t guest_page,
                                  unsigned int permissions, sparc64_family_page_key_t key,
                                  sparc64_file_source_t *source, uint64_t offset);
/* Hold the exact bound guard continuously from snapshot through commit. Commit
 * validates/publishes full absolute state before replacing its local mirror;
 * callers preflight local code-generation capacity before a changed target.
 * Publication failure may require family recovery, never blind guest retry. */
int sparc64_family_backing_snapshot(sparc64_family_backing_t *backing,
                                sparc64_page_payload_t *payload,
                                sparc64_family_page_state_t *out);
int sparc64_family_backing_commit_state(sparc64_family_backing_t *backing,
                                    sparc64_page_payload_t *payload,
                                    const sparc64_family_page_state_t *target);
/* Scoped clean-file notification consumption; same mirror/publication rules
 * above and sparc64_family_object_commit_file_refresh's prepaid-epoch contract. */
int sparc64_family_backing_commit_file_refresh(sparc64_family_backing_t *backing,
                                           sparc64_page_payload_t *payload,
                                           const sparc64_family_page_state_t *target);
/* Destroy after the space has released all payloads. Does not clean up the
 * family itself; creator cleanup remains a separate quiescent operation. */
int sparc64_family_backing_destroy(sparc64_family_backing_t *backing);

#endif
