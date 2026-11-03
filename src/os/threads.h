/*
 * src/os/threads.h — host-pthread-backed CLONE_VM threads (Phase 4, L4b)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Declares the thread table (guest tid allocation, per-thread robust-list
 * state, SET_TID/CLEAR_TID addresses, exit-group status), the clone/futex/
 * gettid/robust-list syscall bodies in src/os/threads.c, the big guest
 * lock serializing interp/DBT execution across threads (the interp
 * winfile and the DBT window helper share process-global state), and the
 * host-__atomic fast path for CASA/CASXA/LDSTUB/SWAP shared by the interp
 * exec_atomic and the DBT s64_jrt_mem path.
 *
 * SPARC clone argument order (arch/sparc: o3 is tls, o4 is child_tidptr;
 * the qemu-sparc64 oracle maps o2=ptid, o3=tls, o4=ctid):
 *   o0 flags, o1 child stack, o2 parent_tidptr, o3 tls, o4 child_tidptr.
 */

#ifndef SPARC64RT_OS_THREADS_H
#define SPARC64RT_OS_THREADS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "core/cpu.h"
#include "interp/interp.h"
#include "os/syscalls_min.h"

/* Clone flags accepted: the pthreads subset. Anything else (VFORK, PARENT,
 * NEWNS/PID/..., UNTRACED, IO, ...) is rejected with -EINVAL, and a clone
 * without CLONE_VM is fork semantics (lane L4c owns it). Values are the
 * arch-independent linux/sched.h numbers. */
#define SPARC64_CLONE_VM UINT64_C(0x100)
#define SPARC64_CLONE_FS UINT64_C(0x200)
#define SPARC64_CLONE_FILES UINT64_C(0x400)
#define SPARC64_CLONE_SIGHAND UINT64_C(0x800)
#define SPARC64_CLONE_THREAD UINT64_C(0x10000)
#define SPARC64_CLONE_SYSVSEM UINT64_C(0x40000)
#define SPARC64_CLONE_SETTLS UINT64_C(0x80000)
#define SPARC64_CLONE_PARENT_SETTID UINT64_C(0x100000)
#define SPARC64_CLONE_CHILD_CLEARTID UINT64_C(0x200000)
#define SPARC64_CLONE_CHILD_SETTID UINT64_C(0x1000000)

/* Table capacity (slot 0 is the main thread). Moved here from
 * threads.c so the fork-child reset in threads_fork.c shares the
 * bound; storage still lives in threads.c. */
#define THR_MAX_THREADS 64U

/* One guest thread. ctx_ref points at the live context (the main thread's
 * runner-owned ctx, or ctx below for spawned threads); engine selects the
 * run loop the thread entry uses. */
typedef struct sparc64_thread sparc64_thread_t;
struct sparc64_thread {
    int used;
    int running;
    int done;
    int engine;
    long tid;
    uint64_t ctid_va;
    uint64_t robust_head;
    uint64_t robust_len;
    void *space_ctx;
    const sparc64_syscall_mem_t *ops;
    sparc64_ctx_t *ctx_ref;
    sparc64_ctx_t ctx;
};

/* Boot the layer (idempotent): records ops/engine and the main thread.
 * Called by the engine loops before any guest code runs. */
void sparc64_threads_boot(const sparc64_syscall_mem_t *ops, int engine,
    sparc64_ctx_t *main_ctx);

/* Table storage (threads.c). The fork-child reset below is the only
 * cross-TU writer. */
extern sparc64_thread_t thr_table[THR_MAX_THREADS];

/* Fork-child reset (threads_fork.c; proc.c calls this on the child leg
 * of fork/vfork/clone-noVM): drops every slot except the calling
 * context so ghost parent threads do not linger as used/running in
 * the child. space_ctx re-homes the survivor when it had no slot. */
void sparc64_threads_note_fork_child(sparc64_ctx_t *ctx, void *space_ctx);

/* Big guest lock: serializes interp/DBT execution (shared winfile and
 * shared space metadata). Held across whole engine runs; dropped only
 * while blocked in futex WAIT or blocking host I/O (read/write/readv/
 * writev, S64-R6-2). */
void sparc64_thread_big_lock(void);
void sparc64_thread_big_unlock(void);

/* Group-exit state (first exit_group wins the status). */
int sparc64_threads_group_exiting(long *status_out);
/* Record an exit_group syscall: arms group exit (first status wins) so
 * threads blocked in futex WAIT abort. A plain thread exit (NR exit)
 * must NOT call this; it ends only its own thread. */
void sparc64_threads_note_group_exit(long status);

/* Thread entry (defined in guest_engines.c): runs the slot's engine loop
 * on its own ctx, then finalizes (CLEARTID + wake, group-exit record). */
void *sparc64_thread_entry(void *arg);

/* Publish that a slot's host thread has started (entry bookkeeping). */
void sparc64_thread_entry_started(sparc64_thread_t *slot);

/* Finalize a slot after its engine loop returns (CLEARTID + wake, mark
 * done). status is the engine loop's exit status. Never arms group
 * exit: a thread returning here ended itself (NR exit); only an
 * exit_group syscall (via sparc64_threads_note_group_exit) ends all. */
void sparc64_thread_entry_done(sparc64_thread_t *slot, long status);

/* Syscall bodies (host-style results: >= 0 value, negative host errno). */
long sparc64_thread_clone(sparc64_ctx_t *ctx, const sparc64_syscall_mem_t *mem,
    uint64_t flags, uint64_t stack, uint64_t ptid, uint64_t tls,
    uint64_t ctid);
long sparc64_thread_futex(sparc64_ctx_t *ctx, const sparc64_syscall_mem_t *mem,
    uint64_t uaddr, uint64_t op, uint64_t val, uint64_t timeout_va,
    uint64_t uaddr2, uint64_t bitset);
long sparc64_thread_gettid(sparc64_ctx_t *ctx);
long sparc64_thread_set_robust_list(sparc64_ctx_t *ctx, uint64_t head,
    uint64_t len);
long sparc64_thread_get_robust_list(sparc64_ctx_t *ctx,
    const sparc64_syscall_mem_t *mem, uint64_t pid, uint64_t head_ptr,
    uint64_t len_ptr);

/* Host-__atomic fast path for LDSTUB/SWAP/CASA/CASXA (+A forms). Resolves
 * the guest address to a host pointer on the shared mapping and performs
 * a single-copy host atomic (big-endian guest words are byte-swapped
 * around the host operation; little-endian ASI forms pass through).
 * Returns true when handled (*out holds the step result, fault or
 * CONTINUE); false means fall back to the reservation path (unmapped,
 * page-crossing, misaligned, or non-data ASI), preserving exact traps. */
bool sparc64_threads_try_host_atomic(sparc64_cpu_t *cpu, void *mc,
    uint64_t pc, const sparc64_dec_t *d, sparc64_step_result_t *out);

#endif /* SPARC64RT_OS_THREADS_H */
