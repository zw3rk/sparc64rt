/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SPARC64RT_RUNTIME_GUEST_MEMORY_SPLIT_H
#define SPARC64RT_RUNTIME_GUEST_MEMORY_SPLIT_H

/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#include "runtime/guest_memory.h"
#include "runtime/family_file_index_internal.h"

#include "memory/family_backing.h"
#include "runtime/exec_tid.h"
#include "runtime/family.h"
#include "runtime/family_wait.h"
#include "runtime/mm_view.h"

#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef enum {
    SPARC64_GUEST_MEMORY_STARTING,
    SPARC64_GUEST_MEMORY_READY,
    SPARC64_GUEST_MEMORY_STOPPING,
    SPARC64_GUEST_MEMORY_STOPPED,
    SPARC64_GUEST_MEMORY_FATAL
} guest_memory_phase_t;

typedef enum {
    SPARC64_WORKER_IDLE,
    SPARC64_WORKER_WAITING,
    SPARC64_WORKER_HELD
} worker_phase_t;

struct sparc64_guest_memory_worker {
    sparc64_guest_memory_t *session;
    sparc64_family_guard_t guard;
    pthread_t owner;
    struct sparc64_guest_memory_worker *next;
    worker_phase_t phase;
    int previous_cancel_state;
    bool initial;
    bool admitted, retiring, retired, cleanup_only;
    uint64_t task_id;
};

struct sparc64_guest_memory {
    sparc64_family_t *family;
    sparc64_family_backing_t *backing;
    sparc64_process_memory_t *owned_image; /* Child owns backing through image. */
    sparc64_path_resolver_t *resolver; /* Borrowed through finish. */
    pid_t owner_pid;
    uint64_t mm_id;
    sparc64_mm_view_t *mm_view;
    sparc64_space_t *canonical_space; /* Owns contents, borrows stable storage. */
    sparc64_linux_memory_t *canonical_memory;
    pthread_mutex_t lock;
    pthread_cond_t changed;
    sparc64_guest_memory_worker_t initial;
    sparc64_guest_memory_worker_t *workers;
    sparc64_guest_memory_worker_t *held_worker;
    size_t extra_workers;
    uint64_t last_task_id;
    sparc64_guest_memory_retirement_t *retirement;
    guest_memory_phase_t phase;
    bool observing;
    bool bound;
    bool transitioning;
    bool owns_family_cleanup;
    bool cleanup_registration_attempted;
    bool cleanup_delegated; /* Accepted locally or inherited by fork/exec. */
    bool family_creator; /* Immutable family origin, including terminal exec. */
    bool fork_frozen;
    /* Ordinary attach and legacy fork remain gated for source sessions;
     * canonical sessions use explicit worker admission and fork images. */
    bool source_restricted;
    bool terminal_only; /* Clean replay returned after source-peer death. */
    bool terminal_replay_complete;
#ifdef SPARC64_GUEST_MEMORY_TEST_TRANSITION
    void (*test_transition_hook)(void *);
    void *test_transition_context;
#endif
};

struct sparc64_guest_memory_fork_freeze {
    sparc64_guest_memory_t *session;
    sparc64_guest_memory_worker_t *caller;
    pid_t parent_pid;
    int previous_cancel_state;
    sparc64_family_exec_t *exec;
    bool exec_only;
    bool canonical_checked;
    sparc64_family_mm_t canonical_mm;
    uint64_t canonical_caller_task;
    uint64_t *canonical_tasks; /* Owned here; callers borrow while sealed. */
    size_t canonical_task_count;
    sparc64_mm_fork_image_t *canonical_child;
    sparc64_mm_join_image_t *canonical_join;
    bool canonical_shared_owners;
};

struct sparc64_guest_memory_retirement {
    sparc64_guest_memory_t *session;
    sparc64_guest_memory_worker_t *caller, *target;
    sparc64_family_mm_t mm;
    sparc64_family_mm_state_t state;
};
extern _Thread_local sparc64_guest_memory_t *local_frozen_session;

/* Cross-part declarations (generated L0a split). */
bool local_session(const sparc64_guest_memory_t *session);
void lifecycle_lock(sparc64_guest_memory_t *session);
void lifecycle_unlock(sparc64_guest_memory_t *session);
#ifdef SPARC64_GUEST_MEMORY_TEST_TRANSITION
void sparc64_guest_memory_test_set_transition_hook(sparc64_guest_memory_t *session, void (*hook)(void *), void *context);
#endif

void lifecycle_signal(sparc64_guest_memory_t *session);
bool owned_by_current(const sparc64_guest_memory_worker_t *worker);
void restore_cancellation(int previous_state);
int observe_inode(void *context, const struct stat *status);
void poison(sparc64_guest_memory_t *session);
bool valid_start(sparc64_guest_memory_t **out, sparc64_space_t *space, sparc64_path_resolver_t *resolver, uint32_t slots_per_object);
int sparc64_guest_memory_start(sparc64_guest_memory_t **out, sparc64_space_t *space, sparc64_path_resolver_t *resolver, uint32_t slots_per_object);
int sparc64_guest_memory_start_authority(sparc64_guest_memory_t **out, sparc64_space_t *space, sparc64_path_resolver_t *resolver, uint32_t slots_per_object, sparc64_family_storage_authority_t authority);
int sparc64_guest_memory_start_canonical(sparc64_guest_memory_t **out, sparc64_space_t *space, sparc64_path_resolver_t *resolver, uint32_t slots_per_object, sparc64_linux_memory_t *memory, uint64_t initial_task_id);
int sparc64_guest_memory_start_canonical_sources(sparc64_guest_memory_t **out, sparc64_space_t *space, sparc64_path_resolver_t *resolver, uint32_t slots_per_object, sparc64_linux_memory_t *memory, uint64_t initial_task_id, sparc64_file_caps_client_t *owned_sources, sparc64_file_identity_policy_t identity_policy);
int sparc64_guest_memory_start_canonical_sources_authority(sparc64_guest_memory_t **out, sparc64_space_t *space, sparc64_path_resolver_t *resolver, uint32_t slots_per_object, sparc64_linux_memory_t *memory, uint64_t initial_task_id, sparc64_file_caps_client_t *owned_sources, sparc64_file_identity_policy_t identity_policy, sparc64_family_storage_authority_t authority);
int sparc64_guest_memory_start_borrowed_sources(sparc64_guest_memory_t **out, sparc64_space_t *space, sparc64_path_resolver_t *resolver, uint32_t slots_per_object, sparc64_file_caps_client_t *owned_sources);
int sparc64_guest_memory_exec_receive_clear_mm(sparc64_guest_memory_t **out, int owned_control_fd, int owned_directory_fd, sparc64_inode_pins_t owned_pins, const sparc64_family_exec_state_t *state, uint64_t old_mm_id, const sparc64_exec_tid_clear_t *intents, size_t count);
int sparc64_guest_memory_exec_outside_guard(sparc64_guest_memory_t *session, int (*operation)(void *), void *opaque);
int sparc64_guest_memory_exec_receive_sources_mm(sparc64_guest_memory_t **out, int owned_control_fd, int owned_directory_fd, sparc64_inode_pins_t owned_pins, sparc64_file_caps_client_t owned_sources, const sparc64_family_exec_state_t *state, uint64_t old_mm_id, const sparc64_exec_tid_clear_t *intents, size_t count);
int sparc64_guest_memory_exec_receive_sources_canonical_mm(sparc64_guest_memory_t **out, int owned_control_fd, int owned_directory_fd, sparc64_inode_pins_t owned_pins, sparc64_file_caps_client_t owned_sources, const sparc64_family_exec_state_t *state, sparc64_family_mm_t old_mm, uint64_t old_task_id, const sparc64_exec_tid_clear_t *intents, size_t count);
int sparc64_guest_memory_exec_receive_sources_canonical_mm_classified( sparc64_guest_memory_t **out, int owned_control_fd, int owned_directory_fd, sparc64_inode_pins_t owned_pins, sparc64_file_caps_client_t owned_sources, const sparc64_family_exec_state_t *state, sparc64_family_mm_t old_mm, uint64_t old_task_id, const sparc64_exec_tid_clear_t *intents, size_t count);
#ifdef SPARC64_RUNTIME_TEST_ATTRIBUTED_FILE
int sparc64_guest_memory_exec_receive_sources_canonical_mm_classified_delegated( sparc64_guest_memory_t **out, int owned_control_fd, int owned_directory_fd, sparc64_inode_pins_t owned_pins, sparc64_file_caps_client_t owned_sources, const sparc64_family_exec_state_t *state, sparc64_family_mm_t old_mm, uint64_t old_task_id, const sparc64_exec_tid_clear_t *intents, size_t count);
#endif

int sparc64_guest_memory_exec_replay_dead_sources( sparc64_guest_memory_t **out, int owned_control_fd, int owned_directory_fd, sparc64_inode_pins_t owned_pins, sparc64_file_caps_client_t owned_sources, const sparc64_family_exec_state_t *state, sparc64_family_mm_t old_mm, uint64_t old_task_id, const sparc64_exec_tid_clear_t *intents, size_t count);
int sparc64_guest_memory_terminal_cleanup(sparc64_guest_memory_t *session, bool proven_sole_family_owner);
int sparc64_guest_memory_exec_receive_clear(sparc64_guest_memory_t **out, int owned_control_fd, int owned_directory_fd, sparc64_inode_pins_t owned_pins, const sparc64_family_exec_state_t *state, const sparc64_exec_tid_clear_t *intents, size_t count);
int sparc64_guest_memory_exec_adopt(sparc64_guest_memory_t *session, sparc64_space_t *space, sparc64_path_resolver_t *resolver, uint32_t slots_per_object);
int sparc64_guest_memory_exec_adopt_canonical(sparc64_guest_memory_t *session, sparc64_space_t *space, sparc64_linux_memory_t *memory, sparc64_path_resolver_t *resolver, uint32_t slots_per_object, uint64_t initial_task_id, sparc64_file_identity_policy_t identity_policy);
bool sparc64_guest_memory_owns_image(const sparc64_guest_memory_t *session, const sparc64_space_t *space, const sparc64_linux_memory_t *memory);
bool sparc64_guest_memory_family_creator(const sparc64_guest_memory_t *session);
bool sparc64_guest_memory_zero_backing(const sparc64_guest_memory_t *session);
int sparc64_guest_memory_exec_start_with_clear(sparc64_guest_memory_t **out, sparc64_space_t *space, sparc64_path_resolver_t *resolver, uint32_t slots_per_object, int owned_control_fd, int owned_directory_fd, sparc64_inode_pins_t owned_pins, const sparc64_family_exec_state_t *state, const sparc64_exec_tid_clear_t *intents, size_t count);
int sparc64_guest_memory_exec_start(sparc64_guest_memory_t **out, sparc64_space_t *space, sparc64_path_resolver_t *resolver, uint32_t slots_per_object, int owned_control_fd, int owned_directory_fd, sparc64_inode_pins_t owned_pins, const sparc64_family_exec_state_t *state);
int sparc64_guest_memory_prepare_child(sparc64_guest_memory_t *parent, const sparc64_linux_memory_t *vmas, sparc64_process_memory_t **out);
int sparc64_guest_memory_fork_freeze_begin(sparc64_guest_memory_worker_t *caller, sparc64_guest_memory_fork_freeze_t **out);
int sparc64_guest_memory_exec_freeze_begin(sparc64_guest_memory_worker_t *caller, sparc64_guest_memory_fork_freeze_t **out);
int sparc64_guest_memory_fork_freeze_end(sparc64_guest_memory_fork_freeze_t **owned);
int sparc64_guest_memory_exec_prepare(sparc64_guest_memory_fork_freeze_t *freeze, sparc64_family_exec_t **out);
int sparc64_guest_memory_exec_canonical_identity(sparc64_guest_memory_fork_freeze_t *freeze, sparc64_family_mm_t *out_mm, uint64_t *out_task_id);
int sparc64_guest_memory_exec_canonical_members(sparc64_guest_memory_fork_freeze_t *freeze, const uint64_t **out_tasks, size_t *out_count);
int sparc64_guest_memory_exec_shared_owners(sparc64_guest_memory_fork_freeze_t *freeze, bool *out);
int sparc64_guest_memory_exec_capture_clear_tids(sparc64_guest_memory_fork_freeze_t *freeze, const sparc64_linux_memory_t *memory, const uint64_t *addresses, size_t count, sparc64_exec_tid_clear_t **out, size_t *out_count);
int sparc64_guest_memory_exec_capture_clear_tids_tagged( sparc64_guest_memory_fork_freeze_t *freeze, const sparc64_linux_memory_t *memory, const sparc64_exec_tid_request_t *requests, size_t count, sparc64_exec_tid_clear_t **out, size_t *out_count);
int sparc64_guest_memory_prepare_child_frozen(sparc64_guest_memory_fork_freeze_t *freeze, const sparc64_linux_memory_t *vmas, sparc64_process_memory_t **out);
int sparc64_guest_memory_prepare_child_canonical_frozen( sparc64_guest_memory_fork_freeze_t *freeze);
int sparc64_guest_memory_prepare_child_shared_frozen( sparc64_guest_memory_fork_freeze_t *freeze);
int sparc64_guest_memory_fork_child_start(sparc64_guest_memory_t **copied_parent, sparc64_linux_memory_t *copied_vmas, sparc64_space_t *copied_space, sparc64_file_registry_t *copied_files, sparc64_process_memory_t **prepared, sparc64_path_resolver_t *resolver, uint32_t slots_per_object, sparc64_guest_memory_t **out);
int sparc64_guest_memory_fork_child_start_frozen( sparc64_guest_memory_fork_freeze_t **freeze, sparc64_guest_memory_t **copied_parent, sparc64_linux_memory_t *copied_vmas, sparc64_space_t *copied_space, sparc64_file_registry_t *copied_files, sparc64_process_memory_t **prepared, sparc64_path_resolver_t *resolver, uint32_t slots_per_object, sparc64_guest_memory_t **out);
int sparc64_guest_memory_fork_child_start_canonical_frozen( sparc64_guest_memory_fork_freeze_t **frozen, sparc64_guest_memory_t **copied_parent, sparc64_linux_memory_t *copied_vmas, sparc64_space_t *copied_space, sparc64_file_registry_t *copied_files, sparc64_path_resolver_t *resolver, uint32_t slots_per_object, uint64_t child_task_id, sparc64_guest_memory_t **out);
int sparc64_guest_memory_fork_child_start_shared_frozen( sparc64_guest_memory_fork_freeze_t **frozen, sparc64_guest_memory_t **copied_parent, sparc64_linux_memory_t *copied_vmas, sparc64_space_t *copied_space, sparc64_file_registry_t *copied_files, sparc64_path_resolver_t *resolver, uint32_t slots_per_object, uint64_t child_task_id, sparc64_guest_memory_t **out);
sparc64_space_t *sparc64_guest_memory_child_space(sparc64_guest_memory_t *session);
sparc64_linux_memory_t *sparc64_guest_memory_child_vmas(sparc64_guest_memory_t *session);
sparc64_file_registry_t *sparc64_guest_memory_child_files(sparc64_guest_memory_t *session);
sparc64_guest_memory_worker_t *sparc64_guest_memory_initial_worker(sparc64_guest_memory_t *session);
bool sparc64_guest_memory_worker_active(const sparc64_guest_memory_worker_t *worker);
bool sparc64_guest_memory_active(const sparc64_guest_memory_t *session);
bool sparc64_guest_memory_worker_resources(sparc64_guest_memory_worker_t *worker, sparc64_family_guard_t **guard, sparc64_family_backing_t **backing, uint64_t *mm_id);
sparc64_mm_view_t *sparc64_guest_memory_worker_mm(sparc64_guest_memory_worker_t *worker);
int sparc64_guest_memory_worker_attach(sparc64_guest_memory_t *session, sparc64_guest_memory_worker_t **out);
int sparc64_guest_memory_worker_attach_task(sparc64_guest_memory_t *session, uint64_t task_id, sparc64_guest_memory_worker_t **out);
int sparc64_guest_memory_worker_admit(sparc64_guest_memory_worker_t *caller, sparc64_guest_memory_worker_t *child);
int sparc64_guest_memory_worker_retire_prepare(sparc64_guest_memory_worker_t *caller, sparc64_guest_memory_worker_t *target, sparc64_guest_memory_retirement_t **out);
int sparc64_guest_memory_worker_retire_commit(sparc64_guest_memory_retirement_t **owned);
int sparc64_guest_memory_worker_enter(sparc64_guest_memory_worker_t *worker);
int sparc64_guest_memory_worker_enter_cleanup(sparc64_guest_memory_worker_t *initial);
bool sparc64_guest_memory_worker_cleanup_guard(sparc64_guest_memory_worker_t *initial, sparc64_family_guard_t **guard);
int sparc64_guest_memory_worker_leave(sparc64_guest_memory_worker_t *worker);
int sparc64_guest_memory_worker_detach(sparc64_guest_memory_worker_t **owned);
int sparc64_guest_memory_round_trip(sparc64_guest_memory_t *session);
int sparc64_guest_memory_stop(sparc64_guest_memory_t *session);
int sparc64_guest_memory_finish(sparc64_guest_memory_t **owned);
int sparc64_guest_memory_finish_keep_cancellation_disabled(sparc64_guest_memory_t **owned, int *prior_state);
int sparc64_guest_memory_register_service_cleanup(sparc64_guest_memory_t *session);
bool sparc64_guest_memory_service_cleanup_delegated(const sparc64_guest_memory_t *session);
int sparc64_guest_memory_departure_begin(sparc64_guest_memory_t *session, sparc64_file_caps_departure_t *out);
const char *sparc64_guest_memory_private_directory(const sparc64_guest_memory_t *session);

#endif /* SPARC64RT_RUNTIME_GUEST_MEMORY_SPLIT_H */
