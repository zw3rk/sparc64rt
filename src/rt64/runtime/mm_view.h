/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SPARC64RT_RUNTIME_MM_VIEW_H
#define SPARC64RT_RUNTIME_MM_VIEW_H

#include "memory/family_backing.h"
#include "runtime/family_mm.h"
#include "runtime/file_caps.h"

typedef struct sparc64_mm_view sparc64_mm_view_t;

/* Anonymous-MM cache foundation. Start with an empty space already installed
 * on backing and an empty memory registry whose space points there. All are
 * borrowed and must outlive the view. Only catalog refresh may change their
 * mappings; checked guest byte/atomic accesses and retained I/O are allowed.
 * This does not enable guest CLONE_VM, file-source sharing or JIT dispatch. */
int sparc64_mm_view_create(sparc64_mm_view_t **out, sparc64_family_mm_t mm,
                       sparc64_family_backing_t *backing, sparc64_space_t *space,
                       sparc64_linux_memory_t *memory);
/* Bind the exact file-service namespace owned by the view's family before
 * importing FILE_PRIVATE associations. The guarded family owns authority;
 * each view retains a duplicate of its immutable control/lifetime pair.
 * Capture the selected exact-FD identity provider once; failed/repeated bind
 * cannot replace that policy or the owned pair. */
int sparc64_mm_view_bind_family_sources(sparc64_mm_view_t *view,
                                    sparc64_family_guard_t *guard,
                                    sparc64_file_identity_policy_t policy);
/* Trusted fixed, vacant READ/EXEC file mapping under the exact family guard.
 * source_id names a previously acknowledged file-service registration. Fetch
 * validates it before root publication; associations persist after unmap.
 * This is a canonical component seam, not Linux mmap/CLI admission. */
int sparc64_mm_view_map_file_readonly(sparc64_mm_view_t *view, sparc64_family_guard_t *guard,
                                  uint64_t address, uint64_t length,
                                  unsigned int permissions, uint64_t source_id,
                                  uint64_t file_offset);
/* Same trusted fresh/vacant mapping transaction with explicit maximum ordinary
 * permissions. The native caller has checked the source/access policy; require
 * requested permissions to be a subset of may_permissions. Managed stores
 * perform a canonical first-COW transition and byte/epoch update together.
 * This is not Linux mmap/CLI, file-notification or source-fork admission. */
int sparc64_mm_view_map_file_private(sparc64_mm_view_t *view, sparc64_family_guard_t *guard,
                                  uint64_t address, uint64_t length,
                                  unsigned int permissions, unsigned int may_permissions,
                                  uint64_t source_id, uint64_t file_offset);
/* Associate an already installed anonymous image with its exact canonical
 * snapshot without remapping, changing bindings or taking extra backing refs.
 * Hold the backing's exact guard. Every VMA/key/permission and brk counter must
 * match; failure preserves the image and *out. This is the seed seam for later
 * session admission; it neither changes session mm_id nor admits guest tasks. */
int sparc64_mm_view_adopt(sparc64_mm_view_t **out, sparc64_family_mm_t mm,
                       sparc64_family_backing_t *backing, sparc64_family_guard_t *guard,
                       sparc64_space_t *space, sparc64_linux_memory_t *memory);
/* Seed a new private anonymous catalog from an installed, guarded image and adopt it.
 * Call before publishing a session/task. New mapping IDs are canonical IDs,
 * never copied local reservation ranges. Failure preserves the image/output;
 * unreachable metadata and consumed IDs may remain until family cleanup. A
 * shared VMA without its original manifest is rejected before staging: its
 * present size cannot safely reconstruct a formerly larger backing extent. */
int sparc64_mm_view_seed(sparc64_mm_view_t **out, sparc64_family_backing_t *backing,
                      sparc64_family_guard_t *guard, sparc64_space_t *space,
                      sparc64_linux_memory_t *memory, uint64_t initial_task_id);
sparc64_family_mm_t sparc64_mm_view_identity(const sparc64_mm_view_t *view);
/* After a successful refresh under the exact guard, check the applied member
 * tuple without another allocation or family-object read. */
bool sparc64_mm_view_has_member(const sparc64_mm_view_t *view,
                           const sparc64_family_guard_t *guard, uint64_t task_id);
/* Hold backing's exact family guard. Stage every allocation/view before
 * swapping maps/VMA metadata. An unchanged (mapping_id,mapping_generation)
 * retains the exact local backing AND binding range, so pending copyout stays
 * valid. Replaced/removed views stay pinned by their old I/O owners and cannot
 * receive copyout through a newly installed mapping. Preserve existing epoch
 * scratch capacity needed after irreversible I/O; allocate no scratch in the
 * completion path. ENOMEM leaves local maps/state untouched and may be retried;
 * never execute with an unapplied newer root. Other failures are infrastructure
 * errors. Managed payload bytes/epochs still refresh through normal accesses;
 * executable dependencies must be refreshed before future JIT dispatch. */
int sparc64_mm_view_refresh(sparc64_mm_view_t *view, sparc64_family_guard_t *guard);
/* Anonymous canonical permission transaction under one uninterrupted guard.
 * Prepares every caller-view allocation before root publication and applies
 * locally without allocation afterwards. 0 completes a guest outcome, including
 * negative Linux ENOMEM/EACCES after changing a valid prefix before a later
 * hole/denial. -1 leaves guest_result untouched: preparation failure leaves the
 * root/caller mapping unchanged (a preceding catch-up may have succeeded); EIO
 * during commit requires fatal/recovery policy, not ordinary syscall rollback.
 * Ordinary PROT_NONE/READ/WRITE/EXEC only; other bits deliberately return EINVAL.
 * No-op requested permissions keep revisions/bindings unchanged. Requested-only
 * changes with identical effective permissions retain local binding ranges. */
int sparc64_mm_view_mprotect(sparc64_mm_view_t *view, sparc64_family_guard_t *guard,
                          uint64_t address, uint64_t length, uint64_t protection,
                          uint64_t *guest_result);
/* Same guarded preparation/publication/result convention as mprotect.
 * Remove the rounded interval atomically; invalid bounds return guest EINVAL
 * without removing a prefix. Hole-only success preserves revision/bindings and
 * needs no successor plan. Removed payload keys remain owned by family lifetime
 * and any aliases or retained I/O; this operation never recycles them. */
int sparc64_mm_view_munmap(sparc64_mm_view_t *view, sparc64_family_guard_t *guard,
                        uint64_t address, uint64_t length, uint64_t *guest_result);
/* Anonymous-only mmap, with the same guarded/result convention. The supplied
 * Linux flags must contain MAP_ANONYMOUS and PRIVATE or SHARED. Fixed and
 * NOREPLACE placement are supported; unknown features/file mappings return
 * EOPNOTSUPP. Offset must be page aligned and is otherwise ignored. Fresh
 * payloads are staged before publication, including replacement of equal-byte
 * pages. Every replacement receives a new canonical mapping ID and local
 * binding; aliases outside the interval keep their old payload/identity.
 * Failed staging may consume unpublished family slots, never old-root data. */
int sparc64_mm_view_mmap_anon(sparc64_mm_view_t *view, sparc64_family_guard_t *guard,
                           uint64_t address, uint64_t length, uint64_t protection,
                           uint64_t flags, uint64_t offset, uint64_t *guest_result);
/* Linux private-file placement and atomic replacement. Caller pins and has
 * validated one readable regular native description; it remains borrowed.
 * Validate bounds/flags/placement before registering that exact descriptor in
 * the family source service. Fresh payloads and retained immutable origins
 * are staged before MM publication. Failed staging may consume source IDs or
 * unreachable origins, never replace the live root. WRITE implies effective
 * READ while requested permissions remain distinct in VMA metadata. Same
 * result/guard convention as mmap_anon; no file MAP_SHARED admission. */
int sparc64_mm_view_mmap_file_private_fd(sparc64_mm_view_t *view, sparc64_family_guard_t *guard,
    uint64_t address, uint64_t length, uint64_t protection, uint64_t flags,
    int borrowed_readable_fd, uint64_t offset, uint64_t *guest_result);
/* Byte-granular break transaction. Guest rejection returns the old break,
 * never a negative errno. Same-page changes update canonical metadata without
 * replacing maps/bindings or consuming code generations, including peer refresh.
 * Growth uses zeroed BRK pages with offsets from PAGE_ALIGN(minimum_break);
 * shrink removes all intersecting mapping kinds, and a hole-only shrink keeps
 * the old break. The selected one-page gap policy follows existing growth. */
int sparc64_mm_view_brk(sparc64_mm_view_t *view, sparc64_family_guard_t *guard,
                     uint64_t address, uint64_t *guest_result);
/* Anonymous remap transaction; same result/guard convention. In-place growth
 * preserves prefix IDs/bindings; moves retain payload keys but assign fresh
 * destination identities. Fixed equal-size multi-VMA moves preserve source
 * gaps at destination. Shared growth and zero-old-size duplication recover
 * the original manifest keys/epochs, with payload-free BUS pages beyond its
 * immutable extent. Duplication preserves source identities and creates fresh
 * destination identities. Private file moves retain exact origins/COW keys;
 * file growth allocates fresh payloads with source/offset associations before
 * publication, so full EOF pages still fault BUS. DONTUNMAP is not admitted.
 * Known later fixed errors (same-address duplication and nonwrapping oversized
 * shrink) first remove the destination, then report EFAULT/EINVAL, matching
 * Linux. Other moves prepare the whole operation atomically; generic partial
 * allocation/multi-VMA failures still need resolution before guest admission.
 * current_break/VMA IDs stay unchanged. */
int sparc64_mm_view_mremap(sparc64_mm_view_t *view, sparc64_family_guard_t *guard,
                        uint64_t address, uint64_t old_length, uint64_t new_length,
                        uint64_t flags, uint64_t destination, uint64_t *guest_result);
uint64_t sparc64_mm_view_revision(const sparc64_mm_view_t *view);
/* Frees catalog association only. Destroy/discard every retained I/O owner
 * under its guard, then destroy space/VMAs/backing through their own owners. */
void sparc64_mm_view_destroy(sparc64_mm_view_t **owned);

#endif
