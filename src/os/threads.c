/*
 * src/os/threads.c — host-pthread-backed CLONE_VM threads (Phase 4, L4b)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Host-thread-backed CLONE_VM threads sharing the one guest space mapping
 * (never copied), plus the real futex WAIT/WAKE on that shared mapping,
 * guest tid allocation, per-thread robust-list state, %g7 TLS install,
 * and the host-__atomic fast path for CASA/CASXA/LDSTUB/SWAP.
 *
 * Concurrency model: one big guest lock serializes execution; threads
 * time-slice at blocking points (futex WAIT drops the lock across the
 * host sleep). No true parallelism; mutex/condvar/TLS semantics exact.
 *
 * Futex words are big-endian guest u32s (host compares the swapped
 * view). Only WAIT/WAKE (+PRIVATE_FLAG) exist; the rest is -ENOSYS.
 * Robust lists are recorded, not recovered; rseq stays -ENOSYS.
 *
 * Needs _GNU_SOURCE: musl hides syscall(2) under -std=c11.
 */
#define _GNU_SOURCE

#include <errno.h>
#include <pthread.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#if defined(__linux__)
#include <sys/syscall.h>
#endif

#include "core/cpu.h"
#include "interp/interp_win.h"
#include "os/guest_run_priv.h"
#include "os/syscall_nr.h"
#include "os/syscalls_ext.h"
#include "os/syscalls_sig.h"
#include "os/threads.h"
#include "os/threads_darwin.h"
#include "os/mem_space_split.h"
#include "vm/vm64.h"

/* Clone subset (linux/sched.h numbers, documented in threads.h). */
#define THR_CLONE_MASK \
    (SPARC64_CLONE_VM | SPARC64_CLONE_FS | SPARC64_CLONE_FILES | \
     SPARC64_CLONE_SIGHAND | SPARC64_CLONE_THREAD | SPARC64_CLONE_SYSVSEM | \
     SPARC64_CLONE_SETTLS | SPARC64_CLONE_PARENT_SETTID | \
     SPARC64_CLONE_CHILD_CLEARTID | SPARC64_CLONE_CHILD_SETTID)

/* Futex op bits (Linux UAPI). WAIT_BITSET (absolute timeout) is what
 * glibc condvars use; the rest (REQUEUE family, etc.) stays -ENOSYS.
 * Results use fixed Linux numbers (-11/-38/-110; Darwin differs). */
#define THR_FUTEX_WAIT 0U
#define THR_FUTEX_WAKE 1U
#define THR_FUTEX_WAIT_BITSET 9U
#define THR_FUTEX_PRIVATE 128U
#define THR_FUTEX_CLOCK_REALTIME 256U
#define THR_FUTEX_CMD_MASK 127U
#define THR_FUTEX_FLAG_MASK \
    ((uint64_t)THR_FUTEX_PRIVATE | (uint64_t)THR_FUTEX_CLOCK_REALTIME)

/* Guest robust-list head size (glibc robust_head, 24 bytes). */
#define THR_ROBUST_LEN 24U

/* Max guest threads (slot 0 is the main thread). */
#define THR_MAX_THREADS 64U

/* First guest tid handed to spawned threads (real pids never reach it). */
#define THR_FIRST_TID 0x40000000UL

static pthread_mutex_t thr_table_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t thr_big_lock = PTHREAD_MUTEX_INITIALIZER;
static sparc64_thread_t thr_table[THR_MAX_THREADS];
static int thr_booted = 0;
static int thr_engine = 0;
static const sparc64_syscall_mem_t *thr_ops = NULL;
static unsigned long thr_next_tid = THR_FIRST_TID;
static int thr_group_exiting = 0;
static long thr_group_status = 0;

/* ---- boot / lookup ------------------------------------------------------ */

/* The loader maps one stack page; threaded guests overflow it. Extend
 * down toward the 8 MiB Linux default while that region is free. */
#define THR_STACK_GROW_SIZE UINT64_C(0x800000)

static void thr_grow_stack(void *mc)
{
    guest_state_t *g = (guest_state_t *)mc;
    /* Same top the loader uses in guest_stack.c (top tasks page). */
    uint64_t stack_top = SPARC64_TASK_SIZE - SPARC64_PAGE_SIZE;
    uint64_t want_base;
    uint64_t size;
    uint64_t hole = UINT64_C(0);
    if (g == NULL) {
        return;
    }
    if (THR_STACK_GROW_SIZE > stack_top) {
        return;
    }
    want_base = stack_top - THR_STACK_GROW_SIZE;
    want_base &= ~(GUEST_PAGE_SIZE - UINT64_C(1));
    /* Lowest mapped page at/above want_base; extend down from there. */
    {
        uint64_t i;
        uint64_t low = stack_top;
        for (i = 0U; i < g->space.count; i++) {
            uint64_t a = g->space.pages[i].address;
            if (a >= want_base && a < low) {
                low = a;
            }
        }
        size = (low > want_base) ? low - want_base : UINT64_C(0);
    }
    if (size == UINT64_C(0)) {
        return;
    }
    if (!sparc64_space_find_hole(&g->space, want_base, size, &hole) ||
        hole != want_base) {
        return;
    }
    (void)sparc64_space_map(&g->space, want_base, size,
        (unsigned)(SPARC64_MEM_READ | SPARC64_MEM_WRITE), false);
}

void sparc64_threads_boot(const sparc64_syscall_mem_t *ops, int engine,
    sparc64_ctx_t *main_ctx)
{
    (void)pthread_mutex_lock(&thr_table_lock);
    if (!thr_booted) {
        thr_booted = 1;
        thr_engine = engine;
        thr_ops = ops;
        memset(thr_table, 0, sizeof(thr_table));
        thr_table[0].used = 1;
        thr_table[0].running = 1;
        thr_table[0].engine = engine;
        thr_table[0].tid = (long)getpid();
        thr_table[0].space_ctx = (ops != NULL) ? ops->context : NULL;
        thr_table[0].ctx_ref = main_ctx;
        thr_grow_stack((ops != NULL) ? ops->context : NULL);
    }
    (void)pthread_mutex_unlock(&thr_table_lock);
}

/* Table lock held on entry. */
static sparc64_thread_t *thr_find_locked(sparc64_ctx_t *ctx)
{
    unsigned i;
    for (i = 0U; i < THR_MAX_THREADS; i++) {
        if (thr_table[i].used && thr_table[i].ctx_ref == ctx) {
            return &thr_table[i];
        }
    }
    return NULL;
}

static sparc64_thread_t *thr_find(sparc64_ctx_t *ctx)
{
    sparc64_thread_t *t;
    (void)pthread_mutex_lock(&thr_table_lock);
    t = thr_find_locked(ctx);
    (void)pthread_mutex_unlock(&thr_table_lock);
    return t;
}

void sparc64_thread_big_lock(void)
{
    (void)pthread_mutex_lock(&thr_big_lock);
}

void sparc64_thread_big_unlock(void)
{
    (void)pthread_mutex_unlock(&thr_big_lock);
}

int sparc64_threads_group_exiting(long *status_out)
{
    int exiting;
    (void)pthread_mutex_lock(&thr_table_lock);
    exiting = thr_group_exiting;
    if (status_out != NULL) {
        *status_out = thr_group_status;
    }
    (void)pthread_mutex_unlock(&thr_table_lock);
    return exiting;
}

void sparc64_threads_note_group_exit(long status)
{
    (void)pthread_mutex_lock(&thr_table_lock);
    if (!thr_group_exiting) {
        thr_group_exiting = 1;
        thr_group_status = status & 0xffL;
    }
    (void)pthread_mutex_unlock(&thr_table_lock);
}

/* Count live peers (table lock held). */
static unsigned thr_live_locked(void)
{
    unsigned i;
    unsigned n = 0U;
    for (i = 0U; i < THR_MAX_THREADS; i++) {
        if (thr_table[i].used && thr_table[i].running &&
            !thr_table[i].done) {
            n++;
        }
    }
    return n;
}

/* ---- shared-mapping host pointer ---------------------------------------- */

/* Resolve [va, va+size) to a host pointer on the shared mapping.
 * Single page only (atomics/futex words never cross one); NULL when
 * anything is off. A later mapping change is the caller's documented
 * race (futex re-resolves after every sleep chunk). */
static void *thr_resolve(void *mc, uint64_t va, size_t size,
    unsigned int perm)
{
    guest_state_t *g = (guest_state_t *)mc;
    uint64_t base;
    size_t pos;
    size_t off;
    sparc64_backing_t *backing;
    if (g == NULL || size == 0U || size > 8U) {
        return NULL;
    }
    if (size > SPARC64_TASK_SIZE ||
        va > SPARC64_TASK_SIZE - (uint64_t)size) {
        return NULL;
    }
    /* Wave U2: resolve at the 4 KiB granule, never the 8 KiB ABI page:
     * an 8 KiB base would land on the neighboring page and overread. */
    base = va & ~(SPARC64_PAGE_SIZE - UINT64_C(1));
    off = (size_t)(va - base);
    if (off + size > (size_t)SPARC64_PAGE_SIZE) {
        return NULL;
    }
    if (!validate_access(&g->space, va, size, perm)) {
        return NULL;
    }
    pos = page_position(&g->space, base);
    if (pos >= g->space.count || g->space.pages[pos].address != base) {
        return NULL;
    }
    backing = g->space.pages[pos].backing;
    if (backing == NULL || backing->bus_fault || backing->bytes == NULL) {
        return NULL;
    }
    return backing->bytes + off;
}

/* ---- futex -------------------------------------------------------------- */

#if defined(__linux__) && defined(SYS_futex)
static long thr_host_futex(void *hp, uint64_t op, uint32_t val,
    const struct timespec *ts, void *uaddr2, uint32_t bitset)
{
    long rc = syscall(SYS_futex, hp, (int)op, (int)val, ts, uaddr2,
        (int)bitset);
    return (rc < 0) ? -(long)errno : rc;
}
#endif

/* BE guest word load/store through the syscall copy layer. */
static int thr_read_u32(const sparc64_syscall_mem_t *mem, uint64_t va,
    uint32_t *out)
{
    uint8_t raw[4];
    if (l2a_range_ok(va, (uint64_t)sizeof(raw)) != 0) {
        return -EFAULT;
    }
    if (!mem->read(mem->context, va, raw, (uint64_t)sizeof(raw))) {
        return -EFAULT;
    }
    *out = l2a_get_be32(raw);
    return 0;
}

static int thr_write_u32(const sparc64_syscall_mem_t *mem, uint64_t va,
    uint32_t v)
{
    uint8_t raw[4];
    if (l2a_range_ok(va, (uint64_t)sizeof(raw)) != 0) {
        return -EFAULT;
    }
    l2a_put_be32(raw, v);
    if (!mem->prepare_write(mem->context, va, (uint64_t)sizeof(raw))) {
        return -EFAULT;
    }
    if (!mem->write(mem->context, va, raw, (uint64_t)sizeof(raw))) {
        return -EFAULT;
    }
    return 0;
}

/* Load a BE guest timespec {sec, nsec}. */
static int thr_read_ts(const sparc64_syscall_mem_t *mem, uint64_t va,
    struct timespec *out)
{
    uint8_t tp[16];
    int64_t sec;
    int64_t nsec;
    if (l2a_range_ok(va, (uint64_t)sizeof(tp)) != 0) {
        return -EFAULT;
    }
    if (!mem->read(mem->context, va, tp, (uint64_t)sizeof(tp))) {
        return -EFAULT;
    }
    sec = (int64_t)l2a_get_be64(tp);
    nsec = (int64_t)l2a_get_be64(tp + 8);
    if (sec < 0 || nsec < 0 || nsec >= 1000000000L) {
        return -EINVAL;
    }
    out->tv_sec = (time_t)sec;
    out->tv_nsec = (long)nsec;
    return 0;
}

/* Real WAIT/WAIT_BITSET on the shared mapping: big lock held on entry
 * and return, dropped across the sleep. Spurious wakeups re-verify;
 * EINTR during a group exit reports -EINTR. */
static long thr_futex_wait(sparc64_ctx_t *ctx,
    const sparc64_syscall_mem_t *mem, uint64_t uaddr, uint64_t op,
    uint32_t val, uint32_t bitset, const struct timespec *ts)
{
    uint64_t cmd = op & (uint64_t)THR_FUTEX_CMD_MASK;
    uint64_t flags = op & THR_FUTEX_FLAG_MASK;
    /* flags feeds only the Linux path below; cmd feeds the deadline. */
    (void)flags;
#if defined(__linux__) && defined(SYS_futex)
    uint32_t host_val = __builtin_bswap32(val);
#endif
    uint32_t cur = 0U;
    int rc;
    /* S64-R4-9: one monotonic deadline for relative WAIT retries. */
    int rel = (cmd == (uint64_t)THR_FUTEX_WAIT) ? 1 : 0;
    int have_dl = 0;
    struct timespec dl = { 0, 0 };
    struct timespec remain = { 0, 0 };
    const struct timespec *tp = ts;
    (void)ctx;
    rc = thr_read_u32(mem, uaddr, &cur);
    if (rc != 0) {
        return (long)rc;
    }
    if (cur != val) {
        return -11; /* Linux EAGAIN (Darwin: 35). */
    }
    /* Lock handoff: flush cached window images home and drop the cache;
     * a resuming thread refills from its own homes, never the cache. */
    {
        sparc64_step_result_t fres;
        if (!sparc64_win_flush_all(ctx, &guest_mem_ops, mem->context,
                &fres, ctx->pc)) {
            return -EFAULT;
        }
        sparc64_win_invalidate_all();
    }
    if (ts == NULL) {
        unsigned live;
        (void)pthread_mutex_lock(&thr_table_lock);
        live = thr_live_locked();
        (void)pthread_mutex_unlock(&thr_table_lock);
        if (live < 2U) {
            /* No peer can wake us: spurious wakeup, as before. */
            return 0;
        }
    }
    if (rel != 0 && ts != NULL &&
        clock_gettime(CLOCK_MONOTONIC, &dl) == 0) {
        have_dl = 1;
        dl.tv_sec += ts->tv_sec;
        dl.tv_nsec += ts->tv_nsec;
        if (dl.tv_nsec >= 1000000000L) {
            dl.tv_sec += 1;
            dl.tv_nsec -= 1000000000L;
        }
    }
    for (;;) {
        void *hp;
        long hrc;
        uint64_t epoch_before;
        if (sparc64_threads_group_exiting(NULL)) {
            return -EINTR;
        }
        if ((uaddr & UINT64_C(3)) != UINT64_C(0)) {
            return -EINVAL;
        }
        hp = thr_resolve(mem->context, uaddr, 4U, SPARC64_MEM_READ);
        if (hp == NULL) {
            return -EFAULT;
        }
        /* S64-R3-1: snapshot the code generation across the sleep. */
        epoch_before = vm64_code_epoch_get();
        /* S64-R4-9: sleep the remaining slice of the same deadline. */
        tp = ts;
        if (have_dl != 0) {
            struct timespec now;
            (void)clock_gettime(CLOCK_MONOTONIC, &now);
            if (now.tv_sec > dl.tv_sec ||
                (now.tv_sec == dl.tv_sec && now.tv_nsec >= dl.tv_nsec)) {
                return -110; /* Linux ETIMEDOUT. */
            }
            remain.tv_sec = dl.tv_sec - now.tv_sec;
            remain.tv_nsec = dl.tv_nsec - now.tv_nsec;
            if (remain.tv_nsec < 0) {
                remain.tv_sec -= 1;
                remain.tv_nsec += 1000000000L;
            }
            tp = &remain;
        }
#if defined(__linux__) && defined(SYS_futex)
        sparc64_thread_big_unlock();
        hrc = thr_host_futex(hp, cmd | flags, host_val, tp, NULL, bitset);
        sparc64_thread_big_lock();
#elif defined(__APPLE__) && defined(__aarch64__)
        /* S64-R3-4: the Darwin callee pins the backing under the held
         * lock and re-acquires before returning. */
        hrc = thr_darwin_futex_wait(ctx, mem, uaddr, op, val, bitset,
            tp);
#else
        (void)hp;
        (void)bitset;
        (void)tp;
        sparc64_thread_big_unlock();
        hrc = -38; /* Linux ENOSYS (Darwin: 78). */
        sparc64_thread_big_lock();
#endif
        /* Re-acquired: another thread may have cached images since. */
        sparc64_win_invalidate_all();
        /* S64-R3-1: a slept-through mapping change leaves every DBT
         * stale; flush the live instance before executing again. */
        if (vm64_code_epoch_get() != epoch_before) {
            guest_state_t *g = (guest_state_t *)mem->context;
            if (g != NULL && g->dbt != NULL) {
                sparc64_dbt_invalidate(g->dbt, 0U, SPARC64_TASK_SIZE);
            }
        }
        if (hrc == -38) {
            return -38;
        }
        if (hrc == 0L) {
            rc = thr_read_u32(mem, uaddr, &cur);
            if (rc != 0) {
                return (long)rc;
            }
            return 0;
        }
        if (hrc == -EINTR) {
            if (sparc64_threads_group_exiting(NULL)) {
                return -EINTR;
            }
            rc = thr_read_u32(mem, uaddr, &cur);
            if (rc != 0) {
                return (long)rc;
            }
            if (cur != val) {
                return -11;
            }
        } else if (hrc != -110) { /* Linux ETIMEDOUT. */
            return hrc;
        } else {
            return -110;
        }
    }
}

long sparc64_thread_futex(sparc64_ctx_t *ctx, const sparc64_syscall_mem_t *mem,
    uint64_t uaddr, uint64_t op, uint64_t val, uint64_t timeout_va,
    uint64_t uaddr2, uint64_t bitset)
{
    uint64_t cmd = op & (uint64_t)THR_FUTEX_CMD_MASK;
    struct timespec ts;
    const struct timespec *tsp = NULL;
    (void)uaddr2;
    if (!thr_booted) {
        return sparc64_l2a_futex(ctx, mem, uaddr, op, val, timeout_va);
    }
    if ((op & ~((uint64_t)THR_FUTEX_CMD_MASK | THR_FUTEX_FLAG_MASK)) !=
        UINT64_C(0)) {
        return -38;
    }
    if (cmd != (uint64_t)THR_FUTEX_WAIT &&
        cmd != (uint64_t)THR_FUTEX_WAKE &&
        cmd != (uint64_t)THR_FUTEX_WAIT_BITSET) {
        return -38;
    }
    if (l2a_range_ok(uaddr, 4U) != 0) {
        return -EFAULT;
    }
    if (cmd == (uint64_t)THR_FUTEX_WAKE) {
        void *hp;
#if defined(__linux__) && defined(SYS_futex)
        long hrc;
#endif
        (void)ctx;
        if ((uaddr & UINT64_C(3)) != UINT64_C(0)) {
            return -EINVAL;
        }
        hp = thr_resolve(mem->context, uaddr, 4U, SPARC64_MEM_READ);
        if (hp == NULL) {
            return -EFAULT;
        }
#if defined(__linux__) && defined(SYS_futex)
        hrc = thr_host_futex(hp, cmd | (op & THR_FUTEX_FLAG_MASK),
            (uint32_t)val, NULL, NULL, 0U);
        return hrc;
#elif defined(__APPLE__) && defined(__aarch64__)
        /* S64-R3-4: guest WAKE through the Darwin keyed backend. */
        return thr_darwin_futex_wake(mem, uaddr, val);
#else
        return -38;
#endif
    }
    if (cmd == (uint64_t)THR_FUTEX_WAIT_BITSET && bitset == UINT64_C(0)) {
        return -EINVAL;
    }
    if (timeout_va != UINT64_C(0)) {
        int rc = thr_read_ts(mem, timeout_va, &ts);
        if (rc != 0) {
            return (long)rc;
        }
        tsp = &ts;
    }
    return thr_futex_wait(ctx, mem, uaddr, op, (uint32_t)val,
        (uint32_t)bitset, tsp);
}

/* ---- clone -------------------------------------------------------------- */

long sparc64_thread_clone(sparc64_ctx_t *ctx, const sparc64_syscall_mem_t *mem,
    uint64_t flags, uint64_t stack, uint64_t ptid, uint64_t tls,
    uint64_t ctid)
{
    sparc64_thread_t *slot = NULL;
    sparc64_step_result_t res;
    unsigned i;
    unsigned long tid;
    int rc;
    if (!thr_booted || thr_engine == 2) {
        return -ENOSYS;
    }
    if ((flags & (uint64_t)~(uint64_t)THR_CLONE_MASK) != UINT64_C(0)) {
        return -EINVAL;
    }
    if ((flags & (uint64_t)SPARC64_CLONE_VM) == UINT64_C(0)) {
        return -EINVAL;
    }
    (void)pthread_mutex_lock(&thr_table_lock);
    for (i = 0U; i < THR_MAX_THREADS; i++) {
        if (!thr_table[i].used) {
            slot = &thr_table[i];
            break;
        }
        if (thr_table[i].done) {
            memset(&thr_table[i], 0, sizeof(thr_table[i]));
            slot = &thr_table[i];
            break;
        }
    }
    if (slot == NULL) {
        (void)pthread_mutex_unlock(&thr_table_lock);
        return -EAGAIN;
    }
    memset(slot, 0, sizeof(*slot));
    tid = __atomic_fetch_add(&thr_next_tid, 1UL, __ATOMIC_SEQ_CST);
    slot->used = 1;
    slot->engine = thr_engine;
    slot->tid = (long)tid;
    slot->space_ctx = mem->context;
    slot->ops = mem;
    slot->ctx_ref = &slot->ctx;
    slot->ctid_va = ((flags & (uint64_t)SPARC64_CLONE_CHILD_CLEARTID) !=
        UINT64_C(0)) ? ctid : UINT64_C(0);
    memcpy(&slot->ctx, ctx, sizeof(slot->ctx));
    /* S64-R4-8: the child inherits the parent's blocked mask with an
     * empty pending set and a disabled altstack. */
    sparc64_sync_sig_clone(&slot->ctx, ctx);
    /* The child starts after the trapping ta with %o0 = 0. */
    slot->ctx.pc = ctx->npc;
    slot->ctx.npc = ctx->npc + 4U;
    slot->ctx.r[SPARC64_O0] = UINT64_C(0);
    slot->ctx.ccr &= ~(SPARC64_CCR_ICC_C | SPARC64_CCR_XCC_C);
    if (stack != UINT64_C(0)) {
        slot->ctx.r[SPARC64_SP] = stack;
    }
    if ((flags & (uint64_t)SPARC64_CLONE_SETTLS) != UINT64_C(0)) {
        slot->ctx.r[SPARC64_G7] = tls;
    }
    (void)pthread_mutex_unlock(&thr_table_lock);
    /* Flush the parent's windows home before the child context copies. */
    if (!sparc64_win_flush_all(ctx, &guest_mem_ops, mem->context, &res,
            ctx->pc)) {
        (void)pthread_mutex_lock(&thr_table_lock);
        memset(slot, 0, sizeof(*slot));
        (void)pthread_mutex_unlock(&thr_table_lock);
        return -EFAULT;
    }
    if ((flags & (uint64_t)SPARC64_CLONE_PARENT_SETTID) != UINT64_C(0)) {
        rc = thr_write_u32(mem, ptid, (uint32_t)tid);
        if (rc != 0) {
            (void)pthread_mutex_lock(&thr_table_lock);
            memset(slot, 0, sizeof(*slot));
            (void)pthread_mutex_unlock(&thr_table_lock);
            return (long)rc;
        }
    }
    if ((flags & (uint64_t)SPARC64_CLONE_CHILD_SETTID) != UINT64_C(0)) {
        rc = thr_write_u32(mem, ctid, (uint32_t)tid);
        if (rc != 0) {
            (void)pthread_mutex_lock(&thr_table_lock);
            memset(slot, 0, sizeof(*slot));
            (void)pthread_mutex_unlock(&thr_table_lock);
            return (long)rc;
        }
    }
    {
        pthread_t host;
        int prc;
        /* The child blocks on the big lock, so creating it locked is safe. */
        prc = pthread_create(&host, NULL, sparc64_thread_entry, slot);
        if (prc != 0) {
            (void)pthread_mutex_lock(&thr_table_lock);
            memset(slot, 0, sizeof(*slot));
            (void)pthread_mutex_unlock(&thr_table_lock);
            return -EAGAIN;
        }
        (void)pthread_detach(host);
    }
    (void)pthread_mutex_lock(&thr_table_lock);
    slot->running = 1;
    (void)pthread_mutex_unlock(&thr_table_lock);
    /* SPARC parent/child discrimination: the __clone wrapper branches to
     * __thread_start on nonzero %o1, so the kernel (and this handler)
     * must return %o1 = 0 in the parent. The child keeps the nonzero
     * input and takes the branch. The generic commit only writes %o0. */
    ctx->r[SPARC64_O1] = UINT64_C(0);
    return (long)tid;
}

/* ---- identity / robust list --------------------------------------------- */

long sparc64_thread_gettid(sparc64_ctx_t *ctx)
{
    sparc64_thread_t *t;
    if (!thr_booted) {
        return (long)getpid();
    }
    t = thr_find(ctx);
    if (t == NULL) {
        return (long)getpid();
    }
    return t->tid;
}

long sparc64_thread_set_robust_list(sparc64_ctx_t *ctx, uint64_t head,
    uint64_t len)
{
    sparc64_thread_t *t;
    if (!thr_booted) {
        return -ENOSYS;
    }
    if (len != (uint64_t)THR_ROBUST_LEN &&
        !(head == UINT64_C(0) && len == UINT64_C(0))) {
        return -EINVAL;
    }
    (void)pthread_mutex_lock(&thr_table_lock);
    t = thr_find_locked(ctx);
    if (t == NULL) {
        (void)pthread_mutex_unlock(&thr_table_lock);
        return -ESRCH;
    }
    t->robust_head = head;
    t->robust_len = len;
    (void)pthread_mutex_unlock(&thr_table_lock);
    return 0;
}

long sparc64_thread_get_robust_list(sparc64_ctx_t *ctx,
    const sparc64_syscall_mem_t *mem, uint64_t pid, uint64_t head_ptr,
    uint64_t len_ptr)
{
    uint8_t raw[8];
    sparc64_thread_t *t = NULL;
    unsigned i;
    if (!thr_booted) {
        return -ENOSYS;
    }
    if (l2a_range_ok(head_ptr, (uint64_t)sizeof(raw)) != 0 ||
        l2a_range_ok(len_ptr, (uint64_t)sizeof(raw)) != 0) {
        return -EFAULT;
    }
    (void)pthread_mutex_lock(&thr_table_lock);
    if (pid == UINT64_C(0)) {
        t = thr_find_locked(ctx);
    } else {
        for (i = 0U; i < THR_MAX_THREADS; i++) {
            if (thr_table[i].used && (uint64_t)thr_table[i].tid == pid) {
                t = &thr_table[i];
                break;
            }
        }
    }
    if (t == NULL) {
        (void)pthread_mutex_unlock(&thr_table_lock);
        return -ESRCH;
    }
    l2a_put_be64(raw, t->robust_head);
    if (!mem->prepare_write(mem->context, head_ptr,
            (uint64_t)sizeof(raw)) ||
        !mem->write(mem->context, head_ptr, raw,
            (uint64_t)sizeof(raw))) {
        (void)pthread_mutex_unlock(&thr_table_lock);
        return -EFAULT;
    }
    l2a_put_be64(raw, t->robust_len);
    if (!mem->prepare_write(mem->context, len_ptr,
            (uint64_t)sizeof(raw)) ||
        !mem->write(mem->context, len_ptr, raw,
            (uint64_t)sizeof(raw))) {
        (void)pthread_mutex_unlock(&thr_table_lock);
        return -EFAULT;
    }
    (void)pthread_mutex_unlock(&thr_table_lock);
    return 0;
}

/* ---- thread entry bookkeeping (guest_engines.c calls in) ---------------- */

void sparc64_thread_entry_started(sparc64_thread_t *slot)
{
    if (slot == NULL) {
        return;
    }
    (void)pthread_mutex_lock(&thr_table_lock);
    slot->running = 1;
    (void)pthread_mutex_unlock(&thr_table_lock);
}

void sparc64_thread_entry_done(sparc64_thread_t *slot, long status)
{
    const sparc64_syscall_mem_t *ops;
    (void)status;
    if (slot == NULL) {
        return;
    }
    ops = thr_ops;
    sparc64_thread_big_lock();
    (void)pthread_mutex_lock(&thr_table_lock);
    if (slot->ctid_va != UINT64_C(0) && ops != NULL) {
        void *hp = thr_resolve(slot->space_ctx, slot->ctid_va, 4U,
            SPARC64_MEM_READ);
        if (thr_write_u32(ops, slot->ctid_va, 0U) == 0 && hp != NULL) {
            __atomic_thread_fence(__ATOMIC_SEQ_CST);
#if defined(__linux__) && defined(SYS_futex)
            (void)thr_host_futex(hp, (uint64_t)THR_FUTEX_WAKE, 1U, NULL,
                NULL, 0U);
#elif defined(__APPLE__) && defined(__aarch64__)
            (void)thr_darwin_futex_wake(ops, slot->ctid_va, UINT64_C(1));
#endif
        }
    }
    slot->running = 0;
    slot->done = 1;
    /* No group-exit arming here (NR exit ended only this slot). */
    (void)pthread_mutex_unlock(&thr_table_lock);
    sparc64_thread_big_unlock();
#if defined(__APPLE__) && defined(__aarch64__)
    /* S64-R3-5: release this exiting host thread's Darwin worker sync. */
    thr_darwin_ws_teardown();
#endif
}

/* ---- host-atomic fast path ---------------------------------------------- */

static uint32_t thr_swap32(uint32_t v, int little)
{
    return (little != 0) ? v : __builtin_bswap32(v);
}

static uint64_t thr_swap64(uint64_t v, int little)
{
    return (little != 0) ? v : __builtin_bswap64(v);
}

bool sparc64_threads_try_host_atomic(sparc64_cpu_t *cpu, void *mc,
    uint64_t pc, const sparc64_dec_t *d, sparc64_step_result_t *out)
{
    unsigned size = 0U;
    uint64_t expect = UINT64_C(0);
    uint64_t swap = UINT64_C(0);
    int is_swap = 0;
    unsigned asi;
    int little;
    uint64_t va;
    void *hp;
    uint64_t old = UINT64_C(0);
    if (cpu == NULL || mc == NULL || d == NULL || out == NULL) {
        return false;
    }
    if (d->cls != (uint8_t)SPARC64_ICLS_LDSTUB &&
        d->cls != (uint8_t)SPARC64_ICLS_SWAP &&
        d->cls != (uint8_t)SPARC64_ICLS_ATOMIC) {
        return false;
    }
    switch (d->op3) {
    case SPARC64_OP3_LDSTUB:
    case SPARC64_OP3_LDSTUBA:
        size = 1U;
        swap = UINT64_C(0xFF);
        is_swap = 1;
        break;
    case SPARC64_OP3_SWAP:
    case SPARC64_OP3_SWAPA:
        size = 4U;
        swap = sparc64_rreg(cpu, d->rd);
        is_swap = 1;
        break;
    case SPARC64_OP3_CASA:
        size = 4U;
        expect = sparc64_rreg(cpu, d->rs2);
        swap = sparc64_rreg(cpu, d->rd);
        break;
    case SPARC64_OP3_CASXA:
        size = 8U;
        expect = sparc64_rreg(cpu, d->rs2);
        swap = sparc64_rreg(cpu, d->rd);
        break;
    default:
        return false;
    }
    asi = d->asi;
    if (asi == (unsigned)SPARC64_ASI_P ||
        asi == (unsigned)SPARC64_ASI_PNF) {
        little = 0;
    } else if (asi == (unsigned)SPARC64_ASI_PL ||
        asi == (unsigned)SPARC64_ASI_PNFL) {
        little = 1;
    } else {
        return false;
    }
    if (d->op3 == (uint8_t)SPARC64_OP3_CASA ||
        d->op3 == (uint8_t)SPARC64_OP3_CASXA) {
        va = sparc64_rreg(cpu, d->rs1);
    } else {
        uint64_t b = (d->is_imm != 0U) ? (uint64_t)d->imm :
            sparc64_rreg(cpu, d->rs2);
        va = sparc64_rreg(cpu, d->rs1) + b;
    }
    if (size > 1U && (va & (uint64_t)(size - 1U)) != UINT64_C(0)) {
        return false;
    }
    hp = thr_resolve(mc, va, size, SPARC64_MEM_WRITE);
    if (hp == NULL) {
        return false;
    }
    if (is_swap != 0) {
        if (size == 1U) {
            uint8_t prev = __atomic_exchange_n((uint8_t *)hp,
                (uint8_t)swap, __ATOMIC_SEQ_CST);
            old = (uint64_t)prev;
        } else {
            uint32_t s = thr_swap32((uint32_t)swap, little);
            uint32_t p = __atomic_exchange_n((uint32_t *)hp, s,
                __ATOMIC_SEQ_CST);
            old = (uint64_t)thr_swap32(p, little);
        }
    } else if (size == 4U) {
        uint32_t e = thr_swap32((uint32_t)expect, little);
        uint32_t s = thr_swap32((uint32_t)swap, little);
        (void)__atomic_compare_exchange_n((uint32_t *)hp, &e, s, false,
            __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
        old = (uint64_t)thr_swap32(e, little);
    } else {
        uint64_t e = thr_swap64(expect, little);
        uint64_t s = thr_swap64(swap, little);
        (void)__atomic_compare_exchange_n((uint64_t *)hp, &e, s, false,
            __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
        old = thr_swap64(e, little);
    }
    sparc64_wreg(cpu, d->rd, old);
    *out = sparc64_step_ok(pc);
    return true;
}
