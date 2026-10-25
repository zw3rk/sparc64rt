/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SPARC64RT_LINUX_SIGNAL_H
#define SPARC64RT_LINUX_SIGNAL_H

#include "linux/signal_frame.h"

typedef struct {
    uint64_t handler, flags, mask;
} sparc64_signal_action_t;
typedef void (*sparc64_signal_child_action_sync_fn)(void *context,
                                                const sparc64_signal_action_t *action,
                                                bool child_blocked,
                                                bool explicit_install);
typedef void (*sparc64_signal_child_mask_sync_fn)(void *context, bool child_blocked);
typedef bool (*sparc64_signal_child_pending_fn)(void *context);

typedef struct sparc64_linux_signals sparc64_linux_signals_t;

typedef struct {
    sparc64_space_t *space;
    uint64_t trampoline;
    sparc64_linux_signals_t *workers; /* Borrowed until each worker detaches. */
    sparc64_signal_action_t actions[64];
    uint64_t pending;
    unsigned char information[64][128];
    uint64_t leader_blocked;
    uint32_t pid, uid;
    /* Optional native SIGCHLD disposition transaction. Called before guest
     * action publication, while the caller holds the family guard. A failed
     * native update is infrastructure-fatal in the runtime callback. */
    sparc64_signal_child_action_sync_fn child_action_sync;
    sparc64_signal_child_mask_sync_fn child_mask_sync;
    /* Nonconsuming native kernel-pending view while the worker holds the
     * family guard. DEFAULT+blocked SIGCHLD has no capture slot yet. */
    sparc64_signal_child_pending_fn child_pending;
    void *child_action_context;
} sparc64_signal_process_t;

typedef struct {
    uint64_t blocked;
    uint64_t pending;
    unsigned char information[64][128];
    sparc64_signal_stack_t alternate;
    uint64_t saved_mask; /* rt_sigsuspend's original mask for the next frame. */
    bool restore_mask;
} sparc64_signal_thread_t;

struct sparc64_linux_signals {
    sparc64_signal_process_t *process;
    sparc64_signal_thread_t thread;
    uint32_t guest_tid;
    sparc64_linux_signals_t *next;
};

typedef struct {
    uint64_t value;
    bool context_restored; /* Bypass ordinary syscall result/PC assignment. */
    bool waiting; /* rt_sigsuspend: wait for an actual caught/default action. */
    bool notify; /* Wake request. Not every newly queued signal sets this. */
    uint32_t notify_tid; /* Zero broadcasts a process-directed wake. */
} sparc64_signal_syscall_t;

typedef enum {
    SPARC64_SIGNAL_NONE, SPARC64_SIGNAL_CAUGHT, SPARC64_SIGNAL_FATAL
} sparc64_signal_next_kind_t;

typedef struct {
    sparc64_signal_next_kind_t kind;
    unsigned int signal;
    bool restart; /* Only a caught SA_RESTART action sets this. */
} sparc64_signal_next_t;

/* Caller-owned process storage must outlive every attached worker. Mapping,
 * queue/action changes, attachment and detachment require the guest execution
 * serialization guard once multiple workers exist. Map the RX sigreturn
 * trampoline once, before the VMA registry is seeded. No native signal handler
 * is installed here. */
bool sparc64_linux_signal_process_init(sparc64_signal_process_t *process, sparc64_space_t *space,
                                   uint32_t guest_pid, uint32_t guest_uid);
/* Attach a caller-owned view. A child worker inherits only its parent's mask;
 * pending directed signals, altstack and sigsuspend state start empty. Parent
 * must belong to process. The first worker passes NULL and normally TID=PID.
 * Call once per fresh view; detach before either borrowed storage expires. */
bool sparc64_linux_signal_worker_attach(sparc64_linux_signals_t *signals,
                                    sparc64_signal_process_t *process,
                                    const sparc64_linux_signals_t *parent,
                                    uint32_t guest_tid);
/* Fork into fresh, distinct process/worker storage after the child image is
 * committed. Keep current actions, trampoline VA/UID and the CALLING worker's
 * mask, raw altstack and saved-mask state; clear every inherited pending queue
 * and sibling link. No new trampoline is mapped and no guest frame is edited.
 * Runtime fork ECALL must already be outside sigsuspend (restore_mask=false);
 * do not restore saved_mask here or undo a handler's current autoblocking.
 * New child native events are drained only after this reset. */
bool sparc64_linux_signal_fork_child_init(sparc64_signal_process_t *child_process,
                                      sparc64_linux_signals_t *child_worker,
                                      const sparc64_signal_process_t *parent_process,
                                      const sparc64_linux_signals_t *calling_worker,
                                      sparc64_space_t *child_space, uint32_t child_pid);
/* Linux resets only the child's alternate stack for plain CLONE_VM without
 * CLONE_VFORK. The process mask/actions still follow the fork-child copy. */
bool sparc64_linux_signal_clone_vm_child_reset_altstack(sparc64_linux_signals_t *child);
bool sparc64_linux_signal_worker_detach(sparc64_linux_signals_t *signals);
/* A masked wait installs a temporary effective mask after validating its
 * timeout and signal arguments. A successful begin saves the prior mask for
 * a caught handler's frame. Finish with interrupted_for_delivery=true only
 * when the guarded syscall path selected a guest action; otherwise restore
 * the original mask before ordinary signal selection. */
bool sparc64_linux_signal_wait_mask_begin(sparc64_linux_signals_t *signals,
                                      uint64_t temporary_mask);
bool sparc64_linux_signal_wait_mask_finish(sparc64_linux_signals_t *signals,
                                       bool interrupted_for_delivery);
/* Handles guest masks/actions/altstack/return and same-process standard kill,
 * tkill and tgkill. kill sets notify, with notify_tid zero, when enqueue
 * stores a new process-pending bit. tkill and tgkill set notify, with
 * notify_tid equal to the target guest TID, only when that new directed bit
 * is stored for a different worker and that worker's blocked mask does not
 * contain the signal. A bit that is already pending is not queued and does
 * not set notify. An ignored signal is not queued when its bit is absent
 * from the admission mask; a blocked ignored signal can still be queued, and
 * kill then sets notify. Native handles never leave the host's TID registry.
 * RT queues and job control remain unsupported. Normal returns advance PC
 * before delivery. */
bool sparc64_linux_signal_dispatch(sparc64_linux_signals_t *signals, sparc64_cpu_t *cpu,
                               uint64_t number, const uint64_t args[6],
                               sparc64_signal_syscall_t *result);
/* Called before the next interpreter/JIT entry, with every register in cpu.
 * false means terminate with the guest signal returned through fatal_signal.
 * Guest handlers enter through ordinary checked RISC-V execution. */
bool sparc64_linux_signal_deliver(sparc64_linux_signals_t *signals, sparc64_cpu_t *cpu,
                             unsigned int *fatal_signal);
/* Queue a captured external standard user signal. SI_USER (0) is
 * process-directed; SI_TKILL (-6) is thread-directed. The first siginfo for
 * each pending standard signal wins. This native-relay slice accepts
 * SIGUSR1/SIGUSR2/SIGTERM. Ignored unblocked signals are dropped. */
bool sparc64_linux_signal_enqueue_external(sparc64_linux_signals_t *signals,
                                       unsigned int signal, int32_t code,
                                       uint32_t sender_pid, uint32_t sender_uid);
/* A FIFO write whose readers closed generates SIGPIPE for the writing guest
 * thread, including when a positive partial write completed. Linux reports
 * SI_USER with the guest TGID and real UID. The host translates EPIPE into
 * this event after the native I/O flight has reentered the family guard. */
bool sparc64_linux_signal_enqueue_pipe(sparc64_linux_signals_t *signals);
/* RLIMIT_FSIZE-generated SIGXFSZ is directed to the writing guest thread.
 * Linux reports SI_USER with the guest TGID and real UID; standard-signal
 * coalescing keeps the first siginfo already queued for that thread. */
bool sparc64_linux_signal_enqueue_fsize(sparc64_linux_signals_t *signals);
/* Native child exit notification, with Linux CLD_EXITED/KILLED/DUMPED
 * metadata. The native child remains a zombie until guest wait4 consumes it;
 * explicit SIG_IGN suppresses native notification at exit. */
bool sparc64_linux_signal_enqueue_child(sparc64_linux_signals_t *signals,
                                    int32_t code, uint32_t child_pid,
                                    uint32_t child_uid, int32_t status);
/* Pure query for the next actual handler/default action, skipping ignored
 * pending entries without consuming them or applying SA_RESETHAND. The caller
 * must serialize this query with queue/action/mask changes until delivery. */
bool sparc64_linux_signal_next(const sparc64_linux_signals_t *signals,
                          sparc64_signal_next_t *next);
/* Queue a precise architectural fault for this guest thread. The caller must
 * retain the faulting PC and enter signal delivery before another instruction.
 * A blocked or ignored synchronous signal follows Linux force_sig_fault:
 * its disposition becomes default and its block bit is cleared. */
bool sparc64_linux_signal_raise_trap(sparc64_linux_signals_t *signals,
                                 const sparc64_step_result_t *step);

#endif
