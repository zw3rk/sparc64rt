/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SPARC64RT_RUNTIME_NATIVE_SIGNAL_SPLIT_H
#define SPARC64RT_RUNTIME_NATIVE_SIGNAL_SPLIT_H

/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#define _GNU_SOURCE
#include "runtime/native_signal.h"

#include <errno.h>
#include <signal.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#if defined(__linux__) && defined(__aarch64__)
#include <sys/auxv.h>
#include <ucontext.h>
extern unsigned char sparc64_native_safe_syscall_begin[];
extern unsigned char sparc64_native_safe_syscall_after_svc[];
extern unsigned char sparc64_native_safe_syscall_abort[];
#endif

typedef struct {
    _Atomic unsigned int state; /* 0 empty, 1 filling, 2 published */
    sparc64_native_signal_event_t event;
    uint64_t child_generation;
} sparc64_native_signal_slot_t;

enum {
    NATIVE_SLOT_USR1_SHARED = 0,
    NATIVE_SLOT_USR2_SHARED = 1,
    NATIVE_SLOT_USR1_DIRECT = 2,
    NATIVE_SLOT_USR2_DIRECT = 3,
    NATIVE_SLOT_CHLD = 4,
    NATIVE_SLOT_TERM_SHARED = 5,
    NATIVE_SLOT_TERM_DIRECT = 6,
    NATIVE_SLOT_COUNT = 7
};

struct sparc64_native_signal_process {
    sigset_t carriers;
    sigset_t original_mask;
    struct sigaction original_actions[5];
    unsigned int actions_installed;
    unsigned int carrier_count;
    int stop_signal;
    _Atomic sparc64_native_child_policy_t child_policy;
    _Atomic uint64_t child_generation;
    pthread_mutex_t registration_lock;
    pid_t local_pid;
    sparc64_native_signal_fork_freeze_t *freeze; /* Protected by registration_lock. */
    uint64_t freeze_generation;
    sparc64_native_signals_t *workers;
    bool stopped; /* Protected by registration_lock; closes attach/stop race. */
    pthread_t creator;
    int creator_cancel_state;
    bool exec_resume;
    bool resume_guest_child_blocked;
    bool child_action_changed;
    bool mask_saved;
    bool teardown_only;
    _Atomic unsigned int attached_workers;
    uint64_t initial_mask;
    uint64_t initial_ignored;
};

struct sparc64_native_signal_fork_freeze {
    sparc64_native_signal_process_t *process;
    sparc64_native_signals_t *survivor;
    pid_t parent_pid;
    pthread_t owner;
    uint64_t generation;
};

struct sparc64_native_signals {
    sparc64_native_signal_process_t *process;
    sparc64_native_signals_t *registration_next;
    pthread_t owner;
    uint32_t guest_tid; /* Immutable after binding; protected by registration_lock. */
    int prior_cancel_state;
    sigset_t original_mask;
    bool creator_thread;
    bool pipe_active;
    bool child_guest_blocked;
    bool compatibility_owner;
    bool detached;
    bool teardown_only;
    stack_t original_stack;
    void *stack;
    size_t stack_size;
    bool stack_installed;
    bool open;
    sparc64_native_signal_slot_t slots[NATIVE_SLOT_COUNT];
    _Atomic unsigned int wake;
    _Atomic unsigned int kick_pending; /* One private RT instance at most. */
    _Atomic unsigned int stop;
    _Atomic unsigned int syscall_origin;
};
extern _Thread_local _Atomic(sparc64_native_signals_t *) native_signals;
extern _Thread_local sparc64_native_signal_fork_freeze_t *native_fork_freeze;
extern _Thread_local sparc64_native_signal_process_t *child_reset_process;
extern _Thread_local volatile sig_atomic_t child_reset_seen;
extern _Atomic(sparc64_native_signal_process_t *) process_owner;
_Static_assert(ATOMIC_INT_LOCK_FREE == 2, "native signal slots must be lock-free");
_Static_assert(ATOMIC_POINTER_LOCK_FREE == 2, "native signal TLS must be lock-free");
_Static_assert(sizeof(unsigned int) == 4, "safe SVC latch geometry");

/* Cross-part declarations (generated L0a split). */
bool local_process(const sparc64_native_signal_process_t *process);
bool local_worker(const sparc64_native_signals_t *signals);
int lock_registration(sparc64_native_signal_process_t *process);
int carrier_at(const sparc64_native_signal_process_t *process, unsigned int index);
bool child_default(sparc64_native_child_policy_t policy);
bool child_uncaptured(const sparc64_native_signal_process_t *process, sparc64_native_child_policy_t policy);
void child_reset_marker(int signal, siginfo_t *info, void *context);
bool sparc64_native_signals_pipe_begin(sparc64_native_signals_t *signals, bool *previously_blocked);
int sparc64_native_signals_take_pipe(sparc64_native_signals_t *signals);
bool sparc64_native_signals_pipe_end(sparc64_native_signals_t *signals, bool previously_blocked);
bool restore_worker_stack(const sparc64_native_signals_t *signals);
void capture(int signal, siginfo_t *info, void *context);
bool sparc64_native_signals_block(sparc64_native_signals_t *signals);
bool sparc64_native_signals_enter(sparc64_native_signals_t *signals);
bool sparc64_native_signals_take(sparc64_native_signals_t *signals, sparc64_native_signal_event_t *event);
_Atomic unsigned int *sparc64_native_signals_wake(sparc64_native_signals_t *signals);
_Atomic unsigned int *sparc64_native_signals_syscall_origin(sparc64_native_signals_t *signals);
uint64_t sparc64_native_signals_initial_mask(const sparc64_native_signals_t *signals);
uint64_t sparc64_native_signals_initial_ignored(const sparc64_native_signals_t *signals);
bool process_destroy_internal(sparc64_native_signal_process_t *process, bool restore_cancellation, bool restore_mask);
bool sparc64_native_signal_process_destroy(sparc64_native_signal_process_t *process);
bool sparc64_native_signal_process_destroy_terminal(sparc64_native_signal_process_t *process);
int sparc64_native_signal_fork_freeze_begin(sparc64_native_signal_process_t *process, sparc64_native_signals_t *survivor, sparc64_native_signal_fork_freeze_t **out);
bool sparc64_native_signal_fork_freeze_end(sparc64_native_signal_fork_freeze_t **owned);
bool captured_scan(const sparc64_native_signal_fork_freeze_t *seal, sparc64_native_signal_captured_t *records, size_t *out_count);
bool sparc64_native_signal_fork_captured_count( const sparc64_native_signal_fork_freeze_t *seal, size_t *out_count);
bool sparc64_native_signal_fork_captured_export( const sparc64_native_signal_fork_freeze_t *seal, sparc64_native_signal_captured_t *records, size_t capacity, size_t *out_count);
bool sparc64_native_signal_fork_child_rebase(sparc64_native_signal_process_t **owned, sparc64_native_signals_t **surviving, sparc64_native_signal_fork_freeze_t **sealed, uint32_t new_guest_tid);
sparc64_native_signal_process_t *sparc64_native_signal_process_create(void);
sparc64_native_signal_process_t *sparc64_native_signal_process_create_exec( sparc64_native_child_policy_t policy, bool guest_child_blocked);
bool sparc64_native_signal_process_set_child_policy( sparc64_native_signal_process_t *process, sparc64_native_child_policy_t policy, bool discard_pending);
bool sparc64_native_signal_process_reset_child_policy( sparc64_native_signal_process_t *process, sparc64_native_child_policy_t policy);
sparc64_native_child_policy_t sparc64_native_signal_process_child_policy( const sparc64_native_signal_process_t *process);
bool sparc64_native_signal_pending_child(sparc64_native_signal_process_t *process);
bool sparc64_native_signal_transition_block_child(sparc64_native_signal_process_t *process);
bool sparc64_native_signal_reconcile_child_mask(sparc64_native_signal_process_t *process, bool guest_blocked);
sparc64_native_signals_t *sparc64_native_signal_worker_attach(sparc64_native_signal_process_t *process);
bool sparc64_native_signal_worker_bind_tid(sparc64_native_signals_t *signals, uint32_t guest_tid);
bool sparc64_native_signal_process_request_wake(sparc64_native_signal_process_t *process, uint32_t guest_tid);
bool sparc64_native_signal_process_request_stop(sparc64_native_signal_process_t *process);
bool sparc64_native_signals_stop_requested(const sparc64_native_signals_t *signals);
bool sparc64_native_signal_worker_detach(sparc64_native_signals_t *signals);
sparc64_native_signals_t *sparc64_native_signals_create(void);
bool sparc64_native_signals_destroy(sparc64_native_signals_t *signals);

#endif /* SPARC64RT_RUNTIME_NATIVE_SIGNAL_SPLIT_H */
