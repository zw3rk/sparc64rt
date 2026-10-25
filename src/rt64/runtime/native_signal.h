/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SPARC64RT_RUNTIME_NATIVE_SIGNAL_H
#define SPARC64RT_RUNTIME_NATIVE_SIGNAL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdatomic.h>

typedef struct sparc64_native_signals sparc64_native_signals_t;
typedef struct sparc64_native_signal_process sparc64_native_signal_process_t;
typedef struct sparc64_native_signal_fork_freeze sparc64_native_signal_fork_freeze_t;
typedef struct {
    unsigned int signal;
    int32_t code;
    int32_t pid;
    uint32_t uid;
    int32_t status; /* SIGCHLD's si_status; zero for user carriers. */
} sparc64_native_signal_event_t;

typedef struct {
    sparc64_native_signal_event_t event;
    bool process_directed;
} sparc64_native_signal_captured_t;

typedef enum {
    SPARC64_NATIVE_CHILD_DEFAULT,
    SPARC64_NATIVE_CHILD_DEFAULT_NOCLDWAIT,
    SPARC64_NATIVE_CHILD_CAUGHT,
    SPARC64_NATIVE_CHILD_CAUGHT_NOCLDWAIT,
    SPARC64_NATIVE_CHILD_IGNORED
} sparc64_native_child_policy_t;

/* One process owner protects process-wide USR1/USR2/TERM/SIGCHLD sigactions. Create on the
 * creator thread before spawning helpers; carriers are blocked first. Only
 * one process owner may exist at a time. The caller serializes process
 * destruction against attachment, joins workers before destruction, and
 * retains each handle through successful teardown. Cancellation is disabled
 * while process or worker signal ownership is live. */
sparc64_native_signal_process_t *sparc64_native_signal_process_create(void);
/* Native self-exec startup only. The kernel has already retained SIG_IGN or
 * reset a caught SIGCHLD to SIG_DFL. Validate that inherited action before
 * changing any signal state, then adopt it without republishing sigaction or
 * changing the inherited SIGCHLD mask/pending queue. Attach the sole worker
 * and reconcile its effective guest mask before guest execution. */
sparc64_native_signal_process_t *sparc64_native_signal_process_create_exec(
    sparc64_native_child_policy_t policy, bool guest_child_blocked);
/* Mirror guest SIGCHLD disposition at the sigaction publication point. The
 * kernel decides zombie/autoreap ownership when each native child exits.
 * Caller holds the serialized guest guard; failure is infrastructure-fatal. */
bool sparc64_native_signal_process_set_child_policy(
    sparc64_native_signal_process_t *process, sparc64_native_child_policy_t policy,
    bool discard_pending);
/* Automatic guest SA_RESETHAND delivery is not sigaction(SIG_DFL): Linux
 * preserves a previously blocked SIGCHLD. After every receiver blocks and
 * acknowledges the transition, make the kernel itself perform the reset with
 * a private directed marker. No guest event or pending slot is consumed. */
bool sparc64_native_signal_process_reset_child_policy(
    sparc64_native_signal_process_t *process, sparc64_native_child_policy_t policy);
sparc64_native_child_policy_t sparc64_native_signal_process_child_policy(
    const sparc64_native_signal_process_t *process);
/* Nonconsuming current-thread/process kernel-pending SIGCHLD view. The guest
 * rt_sigpending path masks it with the caller's guest blocked set. */
bool sparc64_native_signal_pending_child(sparc64_native_signal_process_t *process);
/* Current native owner mirrors the guest SIGCHLD mask while DEFAULT is in
 * force. Caught dispositions keep the carrier blocked outside capture. */
bool sparc64_native_signal_reconcile_child_mask(sparc64_native_signal_process_t *process,
                                            bool guest_blocked);
/* Own-thread transition phase: block SIGCHLD before an old caught handler can
 * outlive a process-wide discard. Does not change the remembered guest mask. */
bool sparc64_native_signal_transition_block_child(sparc64_native_signal_process_t *process);
/* Attach on the receiving native thread while carriers are blocked. Each
 * worker owns its TLS, altstack, signal event slots, wake and syscall origin.
 * No worker handle may be used from a sibling thread. */
sparc64_native_signals_t *sparc64_native_signal_worker_attach(sparc64_native_signal_process_t *process);
/* Bind one immutable guest TID on its native owner before publishing worker
 * readiness. Zero is reserved for process-wide wake requests. */
bool sparc64_native_signal_worker_bind_tid(sparc64_native_signals_t *signals,
                                       uint32_t guest_tid);
/* Wake one bound guest TID, or all workers for guest_tid=0, without queuing a
 * guest event or setting the persistent termination latch. The caller has
 * already published guest signal state under the family guard. Registration
 * pins pthread identities; a pending private carrier coalesces further kicks.
 * ESRCH means a directed target no longer has an attached native owner. A
 * broadcast failure may follow partial fanout and is infrastructure-fatal;
 * the caller must not turn it into a guest-recoverable errno. */
bool sparc64_native_signal_process_request_wake(sparc64_native_signal_process_t *process,
                                            uint32_t guest_tid);
/* Detach on that worker thread. Carriers remain blocked; false retains a live
 * destroy-only worker handle. The caller must join detached helper threads. */
bool sparc64_native_signal_worker_detach(sparc64_native_signals_t *signals);
/* Creator thread only, after every worker detached and joined. Restore saved
 * actions and the creator's original mask last. False retains ownership for
 * retrying destruction; unrecoverable post-free restoration exits 125. */
bool sparc64_native_signal_process_destroy(sparc64_native_signal_process_t *process);
/* Final termination only: caller has blocked all blockable native signals,
 * detached workers, and will never resume guest execution. Restore actions
 * and release ownership as usual, but preserve the current blocked mask so
 * pending unrelated carriers cannot win before the chosen fatal signal. */
bool sparc64_native_signal_process_destroy_terminal(sparc64_native_signal_process_t *process);
/* After scheduler quiescence, with the family guard held, try to seal capture
 * and registration. 1 = sealed, 0 = a capture window is still open (retry or
 * abort), -1 = invalid/infrastructure failure. On success the caller retains
 * the registration mutex through native fork. No parent mailbox is drained.
 * The owner must not call other mutating native-signal APIs while sealed.
 * All ordinary native owners keep cancellation disabled. */
int sparc64_native_signal_fork_freeze_begin(sparc64_native_signal_process_t *process,
                                      sparc64_native_signals_t *survivor,
                                      sparc64_native_signal_fork_freeze_t **out);
/* Parent only: release capture seal BEFORE aborting the scheduler barrier.
 * Failure retains ownership. The fork child must use rebase instead. */
bool sparc64_native_signal_fork_freeze_end(sparc64_native_signal_fork_freeze_t **owned);
/* Read-only export while the exact current owner holds the native capture
 * seal, the family guard and scheduler quiescence. Count first, then supply
 * at least that many records. Captured shared
 * events from every worker and directed events of the survivor are included;
 * sibling-directed events and stale SIGCHLD generations are omitted. The
 * underlying slots and kernel-pending events are never consumed. Capacity or
 * validation failure leaves both caller outputs and native slots unchanged.
 * This is a native-exec staging view, not a guest pending-queue snapshot. */
bool sparc64_native_signal_fork_captured_count(
    const sparc64_native_signal_fork_freeze_t *seal, size_t *out_count);
bool sparc64_native_signal_fork_captured_export(
    const sparc64_native_signal_fork_freeze_t *seal,
    sparc64_native_signal_captured_t *records, size_t capacity,
    size_t *out_count);
/* Child-only native fork reset. All parent registration changes and native
 * signal capture must be sealed, with every carrier blocked before fork
 * and continuously through reset. Pass the exact copied process and the
 * calling thread's TLS worker, outside a handler/safe syscall/SIGPIPE flight.
 * All three handles stay owned on preflight/allocation failure; the child can only
 * retry reset or exit125, never use copied locks or ordinary destruction.
 * On success a fresh process owner replaces *process and *survivor remains
 * the sole worker with new_guest_tid and its owned altstack installed. Other
 * worker capture heaps/stacks are discarded without their destructors. This
 * does not dispose other runtime workers' staged I/O/memory capabilities.
 * Preserve original actions and calling-thread teardown mask/cancellation
 * baseline, but discard copied mailbox/kick/stop/origin state. Real pending
 * child signals are not drained. Guest masks/pending state belong to the
 * Linux ABI; startup mask/ignored facts remain unchanged by this reset. */
bool sparc64_native_signal_fork_child_rebase(sparc64_native_signal_process_t **process,
                                        sparc64_native_signals_t **survivor,
                                        sparc64_native_signal_fork_freeze_t **freeze,
                                        uint32_t new_guest_tid);
/* Latch process termination and kick every still-attached native worker.
 * The registration lock pins each pthread identity through pthread_kill;
 * callers do not retain worker handles. A failed kick is infrastructure
 * failure, and the caller must stop with status 125. */
bool sparc64_native_signal_process_request_stop(sparc64_native_signal_process_t *process);
/* Owner thread only. The stop latch is persistent, including after take(). */
bool sparc64_native_signals_stop_requested(const sparc64_native_signals_t *signals);
/* The owned pipe writer blocks SIGPIPE only for one native transaction.
 * begin reports whether it was blocked beforehand; end restores that bit,
 * leaving the independent USR/private-stop carrier mask unchanged. The writer
 * calls take with SIGPIPE and capture carriers blocked. */
bool sparc64_native_signals_pipe_begin(sparc64_native_signals_t *signals,
                                   bool *previously_blocked);
int sparc64_native_signals_take_pipe(sparc64_native_signals_t *signals);
bool sparc64_native_signals_pipe_end(sparc64_native_signals_t *signals,
                                 bool previously_blocked);
/* Compatibility single-worker path. Create calls process_create + attach;
 * destroy detaches the worker then destroys the process. On a failed destroy,
 * this pointer remains valid for destroy-only retry. */
sparc64_native_signals_t *sparc64_native_signals_create(void);
bool sparc64_native_signals_enter(sparc64_native_signals_t *signals);
bool sparc64_native_signals_block(sparc64_native_signals_t *signals);
/* Carriers must be blocked. A remaining event keeps the wake latch set. */
bool sparc64_native_signals_take(sparc64_native_signals_t *signals,
                             sparc64_native_signal_event_t *event);
_Atomic unsigned int *sparc64_native_signals_wake(sparc64_native_signals_t *signals);
/* Reset this per-flight origin while blocked before enabling carriers. Only
 * an abort before SVC or a captured kernel EINTR at its return sets it. */
_Atomic unsigned int *sparc64_native_signals_syscall_origin(sparc64_native_signals_t *signals);
uint64_t sparc64_native_signals_initial_mask(const sparc64_native_signals_t *signals);
uint64_t sparc64_native_signals_initial_ignored(const sparc64_native_signals_t *signals);
/* Receiving creator thread only, after helpers have detached and joined. */
bool sparc64_native_signals_destroy(sparc64_native_signals_t *signals);

/* AArch64 Linux raw syscall result, without libc errno translation. Abort
 * only before SVC; a completed zero/positive/negative result is preserved. */
int64_t sparc64_native_safe_syscall(_Atomic unsigned int *wake, uint64_t number,
                                const uint64_t arguments[6],
                                _Atomic unsigned int *origin);

#endif
