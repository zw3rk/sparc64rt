/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SPARC64RT_RUNTIME_GUEST_MEMORY_H
#define SPARC64RT_RUNTIME_GUEST_MEMORY_H

#include "linux/resolve.h"
#include "memory/space.h"
#include "memory/family_backing.h"
#include "runtime/exec_state.h"
#include "runtime/process_memory.h"
#include "runtime/mm_view.h"
#include "memory/mm_fork.h"
#include "runtime/mm_join.h"

#include <stdbool.h>
#include <stdint.h>

typedef struct sparc64_guest_memory sparc64_guest_memory_t;
typedef struct sparc64_guest_memory_worker sparc64_guest_memory_worker_t;
typedef struct sparc64_guest_memory_fork_freeze sparc64_guest_memory_fork_freeze_t;
typedef struct sparc64_guest_memory_retirement sparc64_guest_memory_retirement_t;

/* Start only after image loading, guest stdio/file initialization, and all
 * initial stack/trampoline/VMA setup. The borrowed space must remain stable
 * until stop; the borrowed resolver storage remains stable through finish.
 * A failed call can still return an owned session: unless it is poisoned by
 * family lock-entry failure, the caller destroys its space, calls stop,
 * destroys its file resolver, then calls finish. A poisoned session requires
 * immediate process exit. Every failure is infrastructure-fatal (status 125). */
int sparc64_guest_memory_start(sparc64_guest_memory_t **out, sparc64_space_t *space,
                          sparc64_path_resolver_t *resolver,
                          uint32_t slots_per_object);
/* Fresh ordinary startup with an immutable exact-FD storage authority.
 * Non-AUTO is accepted only for inherited hard-zero backing and is not
 * transported through fork or exec in this bounded runtime profile. */
int sparc64_guest_memory_start_authority(sparc64_guest_memory_t **out, sparc64_space_t *space,
                          sparc64_path_resolver_t *resolver,
                          uint32_t slots_per_object,
                          sparc64_family_storage_authority_t authority);
/* Internal anonymous canonical-session foundation, before any task publication.
 * memory must already describe the exact installed space. Once *out is non-NULL,
 * the session owns the mapping/VMA CONTENTS in these borrowed stable structs,
 * including on setup failure: do not destroy them before stop. Stop destroys
 * them under its guard and accepts an idle initial worker after refresh ENOMEM,
 * reacquiring only for teardown without allocating a refresh or admitting guest
 * access. Resolver storage remains borrowed through finish as with start.
 * Worker reentry applies the latest root before successful HELD admission.
 * ENOMEM leaves the worker idle and may be retried or stopped; other entry
 * failures require fatal policy. Canonical workers require explicit
 * attach_task/admit; ordinary worker attach remains gated. Native fork needs
 * the separate canonical freeze/image/child-adoption path below.
 * Same-PID exec uses the separate exec-only freeze and exact old
 * MM member transport; failed native exec leaves the old image in place. File/shared
 * input without exact source manifests is rejected before taking ownership;
 * a current VMA size cannot reconstruct the original shared backing extent.
 * No CLI uses
 * this constructor yet, and it does not enable guest CLONE_VM or JIT admission. */
int sparc64_guest_memory_start_canonical(sparc64_guest_memory_t **out, sparc64_space_t *space,
                                    sparc64_path_resolver_t *resolver,
                                    uint32_t slots_per_object,
                                    sparc64_linux_memory_t *memory, uint64_t initial_task_id);
/* Source-capable canonical session foundation. Start the independent service
 * before family/guest workers and pass its trusted exact client pair. Consume
 * and clear *owned_sources on every outcome; never start or replace a service
 * here. Require *out=NULL; invalid inputs preserve output and image contents.
 * A published success/partial session owns the same image/stop/finish contract
 * as start_canonical, including the caller's original cancellation state.
 * Capture identity_policy once when binding the private view. Initial FILE or
 * SHARED VMAs still need original source/manifests and are rejected before
 * ownership; a held caller may subsequently use the canonical read-only file
 * mapping seam. No public CLI, ordinary worker attach or guest write
 * admission. Native fork requires the canonical frozen-image path below;
 * canonical workers require explicit attach_task/admit. */
int sparc64_guest_memory_start_canonical_sources(sparc64_guest_memory_t **out,
                                    sparc64_space_t *space, sparc64_path_resolver_t *resolver,
                                    uint32_t slots_per_object,
                                    sparc64_linux_memory_t *memory, uint64_t initial_task_id,
                                    sparc64_file_caps_client_t *owned_sources,
                                    sparc64_file_identity_policy_t identity_policy);
int sparc64_guest_memory_start_canonical_sources_authority(sparc64_guest_memory_t **out,
                                    sparc64_space_t *space, sparc64_path_resolver_t *resolver,
                                    uint32_t slots_per_object,
                                    sparc64_linux_memory_t *memory, uint64_t initial_task_id,
                                    sparc64_file_caps_client_t *owned_sources,
                                    sparc64_file_identity_policy_t identity_policy,
                                    sparc64_family_storage_authority_t authority);
/* Internal source-capable borrowed-space session for the compile-only runtime
 * profile. It consumes the exact pair, retains ordinary space/VMA teardown,
 * permits same-PID exec, and rejects additional workers and native fork.
 * It does not enable canonical MM mapping or public source mode. */
int sparc64_guest_memory_start_borrowed_sources(sparc64_guest_memory_t **out,
                                    sparc64_space_t *space, sparc64_path_resolver_t *resolver,
                                    uint32_t slots_per_object,
                                    sparc64_file_caps_client_t *owned_sources);
/* Fresh startup after same-PID native exec. Consume the exact inherited
 * family caps on every outcome; adopt only the new, already loaded space.
 * The original creator retains cleanup responsibility, while an attached
 * child remains a noncreator. Failure has the same partial-session cleanup
 * contract as start, but cannot return to the old guest image. */
int sparc64_guest_memory_exec_start(sparc64_guest_memory_t **out, sparc64_space_t *space,
                               sparc64_path_resolver_t *resolver,
                               uint32_t slots_per_object,
                               int owned_control_fd, int owned_directory_fd,
                               sparc64_inode_pins_t owned_pins,
                               const sparc64_family_exec_state_t *state);
/* Point-of-no-return resume split. Receive the sole family caps and replay
 * killed siblings' shared clear-tid stores immediately after state import,
 * before any new-image import, mapping, or file setup can fail. The returned
 * session owns a held guard but no resolver/backing; stop and finish accept
 * this partial state. Adopt only after a fresh resolver and space exist. */
int sparc64_guest_memory_exec_receive_clear(sparc64_guest_memory_t **out,
                               int owned_control_fd, int owned_directory_fd,
                               sparc64_inode_pins_t owned_pins,
                               const sparc64_family_exec_state_t *state,
                               const sparc64_exec_tid_clear_t *intents, size_t count);
/* Production self-exec supplies its exact old mm identity. Zero is reserved
 * for callers that have never registered family waiter rows. */
int sparc64_guest_memory_exec_receive_clear_mm(sparc64_guest_memory_t **out,
                               int owned_control_fd, int owned_directory_fd,
                               sparc64_inode_pins_t owned_pins,
                               const sparc64_family_exec_state_t *state,
                               uint64_t old_mm_id,
                               const sparc64_exec_tid_clear_t *intents, size_t count);
/* A resumed STARTING session has completed old-image replay but still holds
 * its inherited family guard. Run preguest cache filesystem work without that
 * guard, then reacquire it before new-image adoption. No guest task or
 * backing/view is admitted in this interval. Callback failure is returned
 * only after reentry; reentry uncertainty poisons the session. */
int sparc64_guest_memory_exec_outside_guard(sparc64_guest_memory_t *session,
                                      int (*operation)(void *), void *opaque);
/* Same lifecycle/early replay, requiring the original source request/lifetime
 * pair as two more consumed private capabilities. No source service is started
 * or replaced during resume. Anonymous callers use the four-cap API above. */
int sparc64_guest_memory_exec_receive_sources_mm(sparc64_guest_memory_t **out,
                               int owned_control_fd, int owned_directory_fd,
                               sparc64_inode_pins_t owned_pins,
                               sparc64_file_caps_client_t owned_sources,
                               const sparc64_family_exec_state_t *state,
                               uint64_t old_mm_id,
                               const sparc64_exec_tid_clear_t *intents, size_t count);
/* Canonical source resume additionally retires every exact outgoing MM member
 * under the inherited guard, after clear-TID replay and before fresh seeding.
 * The caller task must be among those members and no foreign owner is allowed.
 * No old-image pointers or old MM member survive native exec. */
int sparc64_guest_memory_exec_receive_sources_canonical_mm(sparc64_guest_memory_t **out,
                               int owned_control_fd, int owned_directory_fd,
                               sparc64_inode_pins_t owned_pins,
                               sparc64_file_caps_client_t owned_sources,
                               const sparc64_family_exec_state_t *state,
                               sparc64_family_mm_t old_mm, uint64_t old_task_id,
                               const sparc64_exec_tid_clear_t *intents, size_t count);
/* Race-safe canonical source resume. Consume the six caps exactly once,
 * require the clean exported journal, then replay old wait/TID/MM exit
 * effects before probing the service. Return 0 with a live STARTING session;
 * return 1 with a cleanup-only STARTING session when the peer is dead. The
 * caller must fail-stop after 1. Return -1 on error, possibly with a partial
 * session to stop/finish before fatal exit. Only a completed clean replay
 * gives the creator cleanup ownership; a pending-journal error must leave
 * journal evidence intact. None permits a second adoption of the caps. */
int sparc64_guest_memory_exec_receive_sources_canonical_mm_classified(
                               sparc64_guest_memory_t **out,
                               int owned_control_fd, int owned_directory_fd,
                               sparc64_inode_pins_t owned_pins,
                               sparc64_file_caps_client_t owned_sources,
                               const sparc64_family_exec_state_t *state,
                               sparc64_family_mm_t old_mm, uint64_t old_task_id,
                               const sparc64_exec_tid_clear_t *intents, size_t count);
#ifdef SPARC64_RUNTIME_TEST_ATTRIBUTED_FILE
/* Internal v7 state proved a service-owned cleanup registration before exec.
 * Source presence alone never selects this ownership path. */
int sparc64_guest_memory_exec_receive_sources_canonical_mm_classified_delegated(
                               sparc64_guest_memory_t **out,
                               int owned_control_fd, int owned_directory_fd,
                               sparc64_inode_pins_t owned_pins,
                               sparc64_file_caps_client_t owned_sources,
                               const sparc64_family_exec_state_t *state,
                               sparc64_family_mm_t old_mm, uint64_t old_task_id,
                               const sparc64_exec_tid_clear_t *intents, size_t count);
#endif
/* Terminal recovery after the inherited file service dies before ordinary
 * source-client adoption. Consume all six exact inherited caps, require the
 * same-PID lease and a clean file journal, then retire vanished wait rows,
 * replay captured clear-TIDs and retire all old canonical members. Return
 * a STARTING session solely for stop/finish and creator cleanup after clean
 * replay; it must never admit guest work. On error, *out may own a partial
 * session without creator cleanup rights. Always fail-stop afterwards. */
int sparc64_guest_memory_exec_replay_dead_sources(
                               sparc64_guest_memory_t **out,
                               int owned_control_fd, int owned_directory_fd,
                               sparc64_inode_pins_t owned_pins,
                               sparc64_file_caps_client_t owned_sources,
                               const sparc64_family_exec_state_t *state,
                               sparc64_family_mm_t old_mm, uint64_t old_task_id,
                               const sparc64_exec_tid_clear_t *intents, size_t count);
/* Optional creator cleanup after a successful terminal replay and before
 * stop releases the inherited guard. A trusted runtime may pass true only
 * after proving there are no other family processes or live views; current
 * internal source mode has native source fork/export gated and verifies its
 * inherited child inventory is empty. Without this grant, stop/finish close
 * local caps but preserve storage. Never call after a nonidle/error replay. */
int sparc64_guest_memory_terminal_cleanup(sparc64_guest_memory_t *session,
                                     bool proven_sole_family_owner);
int sparc64_guest_memory_exec_adopt(sparc64_guest_memory_t *session,
                               sparc64_space_t *space, sparc64_path_resolver_t *resolver,
                               uint32_t slots_per_object);
/* After early same-PID receive and clear-TID replay, adopt a fresh loaded
 * canonical image. Valid arguments leave ownership with the caller until this
 * call starts; once it accepts them, even a failed seed/bind leaves the
 * STARTING session owning space and VMA contents for stop. Source identity is
 * captured from the new image's file registry, never the retired image. */
int sparc64_guest_memory_exec_adopt_canonical(sparc64_guest_memory_t *session,
                               sparc64_space_t *space, sparc64_linux_memory_t *memory,
                               sparc64_path_resolver_t *resolver,
                               uint32_t slots_per_object, uint64_t initial_task_id,
                               sparc64_file_identity_policy_t identity_policy);
/* Exact ownership query for teardown, including a partial canonical adopt. */
bool sparc64_guest_memory_owns_image(const sparc64_guest_memory_t *session,
                                const sparc64_space_t *space,
                                const sparc64_linux_memory_t *memory);
/* The original family creator alone performs final source-service retirement
 * after its owned native descendants have finished and its client has closed.
 * This value survives same-PID exec; a fork child is always a noncreator. */
bool sparc64_guest_memory_family_creator(const sparc64_guest_memory_t *session);
bool sparc64_guest_memory_zero_backing(const sparc64_guest_memory_t *session);
/* Convenience wrapper retaining the original one-call ownership contract. */
int sparc64_guest_memory_exec_start_with_clear(sparc64_guest_memory_t **out,
                               sparc64_space_t *space, sparc64_path_resolver_t *resolver,
                               uint32_t slots_per_object,
                               int owned_control_fd, int owned_directory_fd,
                               sparc64_inode_pins_t owned_pins,
                               const sparc64_family_exec_state_t *state,
                               const sparc64_exec_tid_clear_t *intents, size_t count);

/* Stage a child image while the forking worker holds its family guard.
 * No child family view or copied pthread state enters the image. */
int sparc64_guest_memory_prepare_child(sparc64_guest_memory_t *parent,
                                  const sparc64_linux_memory_t *vmas,
                                  sparc64_process_memory_t **out);
/* After scheduler quiescence and while caller holds the family guard, seal
 * worker publication/disposal. Busy transitions fail without waiting for the
 * family token. The parent releases this seal after fork; the child passes its
 * copied seal to fork_child_start_frozen, never unlocking a copied mutex.
 * While held, use only prepare_child_frozen, fork_freeze_end, or the child
 * transfer; ordinary session/worker lifecycle calls are forbidden and fail
 * closed rather than recursively entering the held mutex. */
int sparc64_guest_memory_fork_freeze_begin(sparc64_guest_memory_worker_t *caller,
                                      sparc64_guest_memory_fork_freeze_t **out);
/* Same seal for exec; canonical sessions may use this entry but the token
 * cannot prepare/transfer a native fork child. Failed native exec thaws it. */
int sparc64_guest_memory_exec_freeze_begin(sparc64_guest_memory_worker_t *caller,
                                      sparc64_guest_memory_fork_freeze_t **out);
int sparc64_guest_memory_fork_freeze_end(sparc64_guest_memory_fork_freeze_t **owned);
/* The freeze owns this prepared family token; *out is borrowed through thaw.
 * Use its family exec getters/activate/deactivate only. Thaw destroys an
 * inactive token and rejects an active token without releasing any seal.
 * Do not call family_exec_destroy directly for this borrowed token. */
int sparc64_guest_memory_exec_prepare(sparc64_guest_memory_fork_freeze_t *freeze,
                                 sparc64_family_exec_t **out);
/* Under the exec seal, require the old root's complete same-owner member set
 * to equal the locally admitted task inventory. Other workers must be idle;
 * unadmitted/retired attached workers must be resolved before exec. Return
 * the executing caller's task ID, even when it is not the initial worker.
 * A returning native exec/thaw changes no membership. Borrowed sessions
 * report a zero handle/task. */
int sparc64_guest_memory_exec_canonical_identity(sparc64_guest_memory_fork_freeze_t *freeze,
                                 sparc64_family_mm_t *out_mm, uint64_t *out_task_id);
/* Borrow the sorted, exact old-owner task IDs after identity succeeds, through
 * thaw only. Runtime must account for every sibling; clear-TID destinations
 * are an optional subset and must not be counted as the member inventory. */
int sparc64_guest_memory_exec_canonical_members(sparc64_guest_memory_fork_freeze_t *freeze,
                                 const uint64_t **out_tasks, size_t *out_count);
/* After identity succeeds, report whether a foreign MM member has a live exact
 * process lease. Dead rows do not count. Lease-query failure poisons the session
 * for fatal teardown. Snapshot is valid under this uninterrupted seal only;
 * foreign process death after sampling still needs lifecycle linearization. */
int sparc64_guest_memory_exec_shared_owners(sparc64_guest_memory_fork_freeze_t *freeze,
                                      bool *out);
/* Under the same held lifecycle/family seal, resolve old guest TID words to
 * stable shared keys and check aggregate counter capacity before native exec. */
int sparc64_guest_memory_exec_capture_clear_tids(sparc64_guest_memory_fork_freeze_t *freeze,
                                  const sparc64_linux_memory_t *memory,
                                  const uint64_t *addresses, size_t count,
                                  sparc64_exec_tid_clear_t **out, size_t *out_count);
/* Explicit attributed roles preserve the caller/sibling distinction through
 * native exec. The caller role requires the frozen canonical shared-MM path;
 * replay still rechecks live peers immediately before its effect. */
int sparc64_guest_memory_exec_capture_clear_tids_tagged(
                                  sparc64_guest_memory_fork_freeze_t *freeze,
                                  const sparc64_linux_memory_t *memory,
                                  const sparc64_exec_tid_request_t *requests,
                                  size_t count,
                                  sparc64_exec_tid_clear_t **out, size_t *out_count);
int sparc64_guest_memory_prepare_child_frozen(sparc64_guest_memory_fork_freeze_t *freeze,
                                         const sparc64_linux_memory_t *vmas,
                                         sparc64_process_memory_t **out);
/* Canonical fork preparation under the same uninterrupted frozen guard.
 * The freeze owns the immutable zero-member child MM image through parent
 * thaw or child transfer; no copied local mapping/view enters that image. */
int sparc64_guest_memory_prepare_child_canonical_frozen(
    sparc64_guest_memory_fork_freeze_t *freeze);
/* Same-MM child preparation. Retain the existing root/private payload keys;
 * a fresh native child joins its current root under a new incarnation. Cannot
 * be mixed with a copy-fork image on the same seal. Parent thaw changes no
 * membership. This alone does not admit guest clone/vfork or suspend a parent. */
int sparc64_guest_memory_prepare_child_shared_frozen(
    sparc64_guest_memory_fork_freeze_t *freeze);
/* Child-only, after native fork. Consumes the copied parent VMA/space/file
 * registry views without consulting copied guards or pthread state. For a
 * child session that owns its image, these three pointers must be its exact
 * committed image members; that image and its backing are discarded once.
 * The caller supplies a freshly initialized resolver; its storage lives through
 * finish. Native workers must be gone and
 * cancellation must remain disabled. Preflight/allocation failure leaves the
 * copied session and prepared image unchanged with *out NULL. After ownership
 * moves, success or recoverable setup failure consumes *prepared and leaves
 * *out owning the child image. A failed family enter or copied-view ownership
 * violation is infrastructure-fatal (exit 125).
 * The copied session's mutex and guard are abandoned; its original cancellation
 * baseline transfers to the fresh session and is restored at finish. Its sole
 * inherited family descriptors are transferred, never duplicated. */
int sparc64_guest_memory_fork_child_start(sparc64_guest_memory_t **copied_parent,
                                     sparc64_linux_memory_t *copied_vmas,
                                     sparc64_space_t *copied_space,
                                     sparc64_file_registry_t *copied_files,
                                     sparc64_process_memory_t **prepared,
                                     sparc64_path_resolver_t *resolver,
                                     uint32_t slots_per_object,
                                     sparc64_guest_memory_t **out);
/* Child-only variant accepts the exact held caller, including a helper.
 * Copied worker records and lifecycle mutex are abandoned without pthread
 * operations; caller's cancellation baseline becomes the child initial one.
 * The caller must already have abandoned copied native flight capabilities
 * and every copied futex waiter's backing reference, and supplied a fresh
 * resolver. Pre-consumption errors require fatal child
 * exit; they cannot be repaired through copied ordinary session APIs. */
int sparc64_guest_memory_fork_child_start_frozen(
    sparc64_guest_memory_fork_freeze_t **freeze,
    sparc64_guest_memory_t **copied_parent, sparc64_linux_memory_t *copied_vmas,
    sparc64_space_t *copied_space, sparc64_file_registry_t *copied_files,
    sparc64_process_memory_t **prepared, sparc64_path_resolver_t *resolver,
    uint32_t slots_per_object, sparc64_guest_memory_t **out);
/* Native child of a canonical source session. The exact frozen image is
 * consumed once after family/source-cap transfer. Fresh child space, VMA,
 * registry, backing and view replace every copied local owner; failure after
 * transfer is fatal and cannot resume the copied guest image. */
int sparc64_guest_memory_fork_child_start_canonical_frozen(
    sparc64_guest_memory_fork_freeze_t **freeze,
    sparc64_guest_memory_t **copied_parent, sparc64_linux_memory_t *copied_vmas,
    sparc64_space_t *copied_space, sparc64_file_registry_t *copied_files,
    sparc64_path_resolver_t *resolver, uint32_t slots_per_object,
    uint64_t child_task_id, sparc64_guest_memory_t **out);
/* Same fresh-owner transfer, using a prepared shared-MM join image. Reject a
 * copy-fork image before disposing any copied owner. No parent wait/release
 * capability is owned by this memory component. */
int sparc64_guest_memory_fork_child_start_shared_frozen(
    sparc64_guest_memory_fork_freeze_t **freeze,
    sparc64_guest_memory_t **copied_parent, sparc64_linux_memory_t *copied_vmas,
    sparc64_space_t *copied_space, sparc64_file_registry_t *copied_files,
    sparc64_path_resolver_t *resolver, uint32_t slots_per_object,
    uint64_t child_task_id, sparc64_guest_memory_t **out);
/* Available only after a complete child commit. Borrowed through stop. */
sparc64_space_t *sparc64_guest_memory_child_space(sparc64_guest_memory_t *session);
sparc64_linux_memory_t *sparc64_guest_memory_child_vmas(sparc64_guest_memory_t *session);
sparc64_file_registry_t *sparc64_guest_memory_child_files(sparc64_guest_memory_t *session);

/* The initial worker is embedded in the session and borrowed by its creator.
 * Start enters its guard and preserves the existing single-worker behavior. */
sparc64_guest_memory_worker_t *sparc64_guest_memory_initial_worker(sparc64_guest_memory_t *session);
/* Attach a caller-owned additional native worker on that worker's thread.
 * It starts idle, inherits no family guard, and may attach while the creator
 * holds the token. Attach/enter/leave/detach keep cancellation disabled across
 * the worker lifetime; detach restores its previous cancellation state last.
 * The caller must stop guest work and discard copyouts before leaving. */
int sparc64_guest_memory_worker_attach(sparc64_guest_memory_t *session,
                                   sparc64_guest_memory_worker_t **out);
/* Internal canonical-source thread admission. The new thread calls attach_task
 * while the parent still holds the family guard; it creates only a local idle
 * handle and performs no family I/O. Task IDs increase strictly within this
 * session and a successfully attached ID is never reused, even if admission
 * later fails. The parent calls admit under its exact held guard and publishes
 * GO only after the member commit succeeds. Ordinary attach remains gated for
 * canonical sessions. out must point to NULL; rejection preserves an occupied
 * output. Native fork and multiworker exec remain gated. */
int sparc64_guest_memory_worker_attach_task(sparc64_guest_memory_t *session,
                                       uint64_t task_id,
                                       sparc64_guest_memory_worker_t **out);
int sparc64_guest_memory_worker_admit(sparc64_guest_memory_worker_t *caller,
                                  sparc64_guest_memory_worker_t *child);
/* Prepare removal of one exact member before clear-TID, futex wake and owned
 * wait cleanup. These effects and commit must run under caller's same held
 * guard, with no intervening canonical MM metadata transaction. Preparation
 * blocks target entry/detach. Successful commit consumes the ticket, then
 * permits the retired idle worker to detach. A commit failure is infrastructure-fatal;
 * the caller must not resume guest execution or retry the effect. out must
 * point to NULL; an occupied output retains the existing ticket. */
int sparc64_guest_memory_worker_retire_prepare(sparc64_guest_memory_worker_t *caller,
                                          sparc64_guest_memory_worker_t *target,
                                          sparc64_guest_memory_retirement_t **out);
int sparc64_guest_memory_worker_retire_commit(sparc64_guest_memory_retirement_t **owned);
int sparc64_guest_memory_worker_enter(sparc64_guest_memory_worker_t *worker);
/* A retired canonical initial worker may reacquire only for owner join/wait
 * cleanup. It holds the family guard but never satisfies worker_active or
 * worker_resources, and cannot run another guest instruction. */
int sparc64_guest_memory_worker_enter_cleanup(sparc64_guest_memory_worker_t *initial);
/* Borrow the cleanup-only held guard for bounded owner join/wait cleanup.
 * It grants no guest MM/view/resource access and ends at leave. */
bool sparc64_guest_memory_worker_cleanup_guard(sparc64_guest_memory_worker_t *initial,
                                           sparc64_family_guard_t **guard);
int sparc64_guest_memory_worker_leave(sparc64_guest_memory_worker_t *worker);
int sparc64_guest_memory_worker_detach(sparc64_guest_memory_worker_t **owned);
bool sparc64_guest_memory_worker_active(const sparc64_guest_memory_worker_t *worker);
/* Borrow current-thread resources for one uninterrupted held-guard operation.
 * No returned pointer may survive worker_leave or a fork/exec transition. */
bool sparc64_guest_memory_worker_resources(sparc64_guest_memory_worker_t *worker,
    sparc64_family_guard_t **guard, sparc64_family_backing_t **backing, uint64_t *mm_id);
/* Borrow canonical view only for the exact local current-thread HELD guard.
 * NULL for legacy, idle, stale, foreign-process or failed-admission workers. */
sparc64_mm_view_t *sparc64_guest_memory_worker_mm(sparc64_guest_memory_worker_t *worker);
/* Current creator-thread query only. Another worker's held guard is never
 * inspected by this function. The caller serializes all guest memory access
 * and copyout capabilities with its own held worker guard. */
bool sparc64_guest_memory_active(const sparc64_guest_memory_t *session);

/* Optional explicit token boundary. It releases the file lock, drains
 * quarantined descriptors before unlocking the local mutex, then re-enters
 * (including inode rescan/recovery) and rebinds.
 * Failure is fatal: do not resume the guest or attempt another boundary. */
int sparc64_guest_memory_round_trip(sparc64_guest_memory_t *session);

/* Two-phase quiescent cleanup. First stop guest work, discard every copyout,
 * and, for the creator session, destroy its borrowed VMA registry and space
 * while the guard remains held. The canonical constructor instead owns these
 * contents and destroys them during stop, including after idle-entry ENOMEM.
 * A child session instead owns and destroys its
 * committed image during stop.
 * The caller first joins helper threads and quiesces all attach attempts;
 * an attach that has not acquired the lifecycle mutex still has a borrowed
 * session pointer and is not pinned by the worker count. Stop then requires
 * all additional workers detached and
 * the initial guard held (except during partial setup, or an idle
 * canonical session, which re-enters the guard). It unbinds/destroys
 * backing, unobserves
 * inodes, and releases the guard
 * with post-unlock quarantine drain. Next destroy files/resolver. Only then
 * finish closes the sole control FD and frees the session. Only the original
 * creator, after all children are reaped, unlinks family files.
 * A failure leaves the session owned but unusable; caller exits status 125. */
int sparc64_guest_memory_stop(sparc64_guest_memory_t *session);
int sparc64_guest_memory_finish(sparc64_guest_memory_t **session);
/* The admitted source departure owns outer cancellation exclusion through
 * service disposition. Finish still consumes the session, but leaves native
 * cancellation disabled for that outer owner to restore after retirement. */
int sparc64_guest_memory_finish_keep_cancellation_disabled(sparc64_guest_memory_t **session,
                                                       int *prior_state);
/* Internal source-service startup only, before the first guest turn. A
 * possibly submitted final registration permanently moves creator unlink
 * responsibility out of this local session, even if its ACK was lost.
 * Failure is fatal to startup and may preserve the private directory. */
int sparc64_guest_memory_register_service_cleanup(sparc64_guest_memory_t *session);
/* True only after this image transferred terminal family cleanup to its
 * retained service. Persist this across native self-exec explicitly. */
bool sparc64_guest_memory_service_cleanup_delegated(const sparc64_guest_memory_t *session);
/* Called after the final guest turn with the initial family guard held and
 * all other local workers retired. PREPARE retains the exact source origin
 * until the caller finishes all local teardown and sends RELEASE. */
int sparc64_guest_memory_departure_begin(sparc64_guest_memory_t *session,
                                   sparc64_file_caps_departure_t *out);

/* Private creator path for diagnostics and focused identity tests. Never
 * expose it to guest path resolution as an ordinary directory. */
const char *sparc64_guest_memory_private_directory(const sparc64_guest_memory_t *session);

#ifdef SPARC64_GUEST_MEMORY_TEST_TRANSITION
/* Focused race discriminator: invoked after the leaving worker publishes
 * transitioning=true and releases the lifecycle mutex, while its family
 * guard remains held. Tests only; production has no callback or storage. */
void sparc64_guest_memory_test_set_transition_hook(sparc64_guest_memory_t *session,
                                              void (*hook)(void *), void *context);
#endif

#endif
