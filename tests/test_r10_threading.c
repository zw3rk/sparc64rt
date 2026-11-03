/*
 * tests/test_r10_threading.c — Round-10 threading/futex regression test.
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Covers S64-R10-2..R10-4 (S64-R10-1 is the proc_clone (ptid, tls,
 * ctid) parameter order; all u64 so no runtime type check can catch a
 * swap — it is pinned by inspection: proc.h/proc.c now declare
 * (flags, stack, ptid, tls, ctid), matching threads.h and both
 * syscalls_min.c call sites passing (o2, o3, o4) positionally):
 * - R10-2: SPARC64_CLONE_PARENT_SETTID is 0x100000 (proc.c PROC_
 *   mirror fixed from 0x10 in the same round).
 * - R10-3: sparc64_threads_has_live_peers reports no peers
 *   single-threaded, reports an injected running peer, and ignores
 *   done slots (the execve gate refuses with -EBUSY while peers live).
 * - R10-4: fork while a helper thread holds thr_table_lock still
 *   leaves the child lock free (atfork prepare takes the lock across
 *   fork; parent and child release it).
 *
 * Deterministic stdout; exit 0 with R10-THREADING-PASS iff every
 * check passed.
 *
 * Build (worktree root):
 *   cc -std=c11 -Werror -Werror=vla -pedantic -Wall -Wextra -Isrc \
 *     tests/test_r10_threading.c src/os/threads.c \
 *     src/os/threads_fork.c src/os/threads_darwin.c src/vm/vm64.c \
 *     src/os/backend_darwin_sync.c src/os/backend_darwin_futex.c \
 *     src/os/sync_sig.c src/os/mem_space.c \
 *     src/os/mem_space_write.c src/interp/all-TUs \
 *     -o _build/test_r10_threading -pthread
 */

#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "core/cpu.h"
#include "dbt/mem_sites.h"
#include "interp/interp.h"
#include "os/guest_run_priv.h"
#include "os/mem_space.h"
#include "os/threads.h"

/* R10-2: the public clone bit (proc.c PROC_CLONE_PARENT_SETTID mirrors
 * this value; it was 0x10U before the fix). */
_Static_assert(SPARC64_CLONE_PARENT_SETTID == UINT64_C(0x100000),
    "R10-2: PARENT_SETTID must be 0x100000");

/* ---- Test-only link stubs (same shape as test_thr_resolve_granule) -- */
static int stub_reached = 0;

static bool test_mem_read(void *ctx, uint64_t va, void *dst, size_t n,
    sparc64_access_t acc, sparc64_mem_fault_t *fault);
static bool test_mem_write(void *ctx, uint64_t va, const void *src, size_t n,
    sparc64_mem_fault_t *fault);

sparc64_tlb_entry_t sparc64_dbt_tlb[SPARC64_TLB_SIZE]
    __attribute__((aligned(32)));
const sparc64_mem_ops_t guest_mem_ops = {
    test_mem_read,
    test_mem_write,
    NULL
};

long sparc64_l2a_futex(sparc64_ctx_t *ctx, const sparc64_syscall_mem_t *mem,
    uint64_t uaddr, uint64_t op, uint64_t val, uint64_t timeout_va)
{
    (void)ctx;
    (void)mem;
    (void)uaddr;
    (void)op;
    (void)val;
    (void)timeout_va;
    stub_reached = 1;
    return -1L;
}

void *sparc64_thread_entry(void *arg)
{
    (void)arg;
    stub_reached = 1;
    return arg;
}

void sparc64_dbt_invalidate(sparc64_dbt_t *dbt, uint64_t va, uint64_t len)
{
    (void)dbt;
    (void)va;
    (void)len;
    stub_reached = 1;
}

#if !defined(__APPLE__) || !defined(__aarch64__)
int rt_host_preempt_worker(uint64_t host_tid)
{
    (void)host_tid;
    stub_reached = 1;
    return 0;
}

uint64_t rt_host_register_self(void)
{
    return UINT64_C(1);
}

void rt_host_unregister_self(void)
{
}
#endif

static bool test_mem_read(void *ctx, uint64_t va, void *dst, size_t n,
    sparc64_access_t acc, sparc64_mem_fault_t *fault)
{
    guest_state_t *g = (guest_state_t *)ctx;
    unsigned flags = (acc == SPARC64_ACCESS_FETCH) ?
        (unsigned)SPARC64_MEM_EXEC : (unsigned)SPARC64_MEM_READ;
    (void)fault;
    return sparc64_space_read(&g->space, va, dst, n, flags);
}

static bool test_mem_write(void *ctx, uint64_t va, const void *src, size_t n,
    sparc64_mem_fault_t *fault)
{
    guest_state_t *g = (guest_state_t *)ctx;
    (void)fault;
    return sparc64_space_write(&g->space, va, src, n);
}

static int fails = 0;

static void check(const char *ok, const char *bad, int passed)
{
    if (passed) {
        (void)printf("%s\n", ok);
    } else {
        (void)printf("%s\n", bad);
        fails++;
    }
}

/* R10-4 holder: holds the table lock across the main thread's fork
 * instant, then releases it so the atfork prepare can proceed. */
static int hold_pipe[2] = { -1, -1 };

static void *hold_table(void *arg)
{
    struct timespec snooze;
    char b = 'x';
    (void)arg;
    (void)pthread_mutex_lock(&thr_table_lock);
    (void)write(hold_pipe[1], &b, 1U);
    snooze.tv_sec = 0;
    snooze.tv_nsec = 200000000L;
    (void)nanosleep(&snooze, NULL);
    (void)pthread_mutex_unlock(&thr_table_lock);
    return NULL;
}

int main(void)
{
    static sparc64_ctx_t main_ctx;
    static sparc64_ctx_t peer_ctx;
    pthread_t holder;
    pid_t pid;
    int status = 0;
    char b = 0;
    ssize_t got;
    (void)memset(&main_ctx, 0, sizeof(main_ctx));
    (void)memset(&peer_ctx, 0, sizeof(peer_ctx));

    check("clone-parent-settid: ok", "clone-parent-settid: FAIL",
        SPARC64_CLONE_PARENT_SETTID == UINT64_C(0x100000));

    /* Single-threaded after boot: no live peers, so execve proceeds. */
    sparc64_threads_boot(NULL, 0, &main_ctx);
    sparc64_threads_fork_init();
    sparc64_threads_fork_init();
    check("no-peers-single: ok", "no-peers-single: FAIL",
        sparc64_threads_has_live_peers(&main_ctx) == 0);

    /* Injected running peer: the execve gate must see it. */
    (void)pthread_mutex_lock(&thr_table_lock);
    thr_table[1].used = 1;
    thr_table[1].running = 1;
    thr_table[1].done = 0;
    thr_table[1].ctx_ref = &peer_ctx;
    (void)pthread_mutex_unlock(&thr_table_lock);
    check("peer-detected: ok", "peer-detected: FAIL",
        sparc64_threads_has_live_peers(&main_ctx) == 1);

    /* Finished slots are not peers. */
    (void)pthread_mutex_lock(&thr_table_lock);
    thr_table[1].done = 1;
    (void)pthread_mutex_unlock(&thr_table_lock);
    check("done-ignored: ok", "done-ignored: FAIL",
        sparc64_threads_has_live_peers(&main_ctx) == 0);

    /* Clear the probe slot before the fork leg. */
    (void)pthread_mutex_lock(&thr_table_lock);
    (void)memset(&thr_table[1], 0, sizeof(thr_table[1]));
    (void)pthread_mutex_unlock(&thr_table_lock);
    check("peer-cleared: ok", "peer-cleared: FAIL",
        sparc64_threads_has_live_peers(&main_ctx) == 0);

    /* R10-4: fork while the holder owns the table lock. The atfork
     * prepare blocks until the holder releases, so the child must
     * inherit the lock free (trylock succeeds). */
    if (pipe(hold_pipe) != 0) {
        check("fork-quiescence: ok", "fork-quiescence: FAIL", 0);
    } else if (pthread_create(&holder, NULL, hold_table, NULL) != 0) {
        check("fork-quiescence: ok", "fork-quiescence: FAIL", 0);
    } else {
        int child_ok = 0;
        got = read(hold_pipe[0], &b, 1U);
        (void)fflush(NULL);
        pid = (got == 1) ? fork() : (pid_t)-1;
        if (pid == 0) {
            int rc = pthread_mutex_trylock(&thr_table_lock);
            int ok = (rc == 0);
            if (ok) {
                (void)pthread_mutex_unlock(&thr_table_lock);
            }
            _exit(ok ? 0 : 1);
        }
        if (pid > 0) {
            pid_t w = waitpid(pid, &status, 0);
            child_ok = (w == pid && WIFEXITED(status) &&
                WEXITSTATUS(status) == 0);
        }
        (void)pthread_join(holder, NULL);
        (void)close(hold_pipe[0]);
        (void)close(hold_pipe[1]);
        check("fork-quiescence: ok", "fork-quiescence: FAIL", child_ok);
    }

    check("stubs-quiet: ok", "stubs-quiet: FAIL", stub_reached == 0);
    if (fails != 0) {
        (void)printf("R10-THREADING-FAIL n=%d\n", fails);
        return 1;
    }
    (void)printf("R10-THREADING-PASS\n");
    return 0;
}
