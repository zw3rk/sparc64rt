/*
 * src/os/backend_darwin_futex.c -- Darwin keyed futex wait/wake/requeue
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Split from src/os/backend_darwin_sync.c (S64-R3 line discipline) so
 * neither TU exceeds the 900-line limit: this file owns the keyed
 * futex waiter table and the wait_bitset/wake_bitset/requeue backend
 * contract (section 7). Worker registration, clocks, threads, and
 * signals stay in backend_darwin_sync.c. No guest data page is mapped
 * PROT_EXEC here and host register x18 is never touched.
 */
#if defined(__APPLE__) && defined(__aarch64__)
#include "os/backend.h"
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>

static int64_t futex_neg_errno(void) { return -(int64_t)errno; }


/* ---- Keyed futex waiter table (S64-5) ---- */
#define RT_FUTEX_WAITERS 256u
struct darwin_futex_waiter {
    int used;
    int woken;
    _Atomic uint32_t *uaddr;
    rt_futex_key_t key;
    int has_key;
    uint32_t bitset;
    pthread_cond_t cv;
};

static pthread_mutex_t g_futex_mu = PTHREAD_MUTEX_INITIALIZER;
static int g_futex_init = 0;
static struct darwin_futex_waiter g_futex_q[RT_FUTEX_WAITERS];

static void futex_lock(void)
{
    unsigned i;
    (void)pthread_mutex_lock(&g_futex_mu);
    if (!g_futex_init) {
        for (i = 0u; i < RT_FUTEX_WAITERS; i++) {
            g_futex_q[i].used = 0;
            (void)pthread_cond_init(&g_futex_q[i].cv, NULL);
        }
        g_futex_init = 1;
    }
}

static int futex_match(const struct darwin_futex_waiter *w,
    _Atomic uint32_t *uaddr, const rt_futex_key_t *key)
{
    if (key != NULL && w->has_key) {
        return w->key.kind == key->kind &&
            w->key.owner_id == key->owner_id &&
            w->key.mount_id == key->mount_id &&
            w->key.offset == key->offset;
    }
    if (w->has_key && w->uaddr == NULL) {
        return 0;
    }
    return w->uaddr == uaddr;
}

/* 7a. futex wait/wake/requeue (S64-5) */

/* Drain stale wake-pipe bytes after a signal-driven -EINTR (Section 3 #2):
 * the notifier writes one byte per signal, and a futex -EINTR return that
 * leaves the byte queued makes a later ppoll/epoll_pwait/clock_nanosleep
 * see POLLIN immediately and report a spurious -EINTR even when
 * sig_seq == expected_seq. The pipe read end is O_NONBLOCK, so this
 * never blocks. */
static void darwin_drain_wake_pipe(rt_worker_sync_t *ws)
{
    char tmp[32];
    ssize_t n;
    int saved_errno;
    if (ws == NULL || ws->wake_pipe_rd < 0) { return; }
    saved_errno = errno;
    do {
        n = read(ws->wake_pipe_rd, tmp, sizeof(tmp));
    } while (n > 0);
    errno = saved_errno;
}

int64_t rt_host_futex_wait_bitset(_Atomic uint32_t *pinned_host_uaddr,
    const rt_futex_key_t *key, uint32_t host_endian_val,
    const struct timespec *timeout, int is_abs_timeout, int clock_realtime,
    uint32_t bitset, rt_worker_sync_t *ws, uint32_t expected_seq)
{
    struct timespec abstime;
    int have_deadline = 0;
    unsigned i;
    int slot = -1;
    int64_t ret = 0;
    if (pinned_host_uaddr == NULL || bitset == 0u) { return -22; }
    if (timeout != NULL) {
        struct timespec now_rt;
        int64_t d_sec;
        long d_nsec;
        if (timeout->tv_nsec < 0 || timeout->tv_nsec >= 1000000000L) {
            return -22;
        }
        if (!is_abs_timeout && timeout->tv_sec < 0) {
            return -22;
        }
        if (clock_gettime(CLOCK_REALTIME, &now_rt) != 0) { return futex_neg_errno(); }
        if (is_abs_timeout) {
            struct timespec now_clk;
            uint64_t u_sec;
            int clk = clock_realtime ? CLOCK_REALTIME : CLOCK_MONOTONIC;
            if (clock_gettime((clockid_t)clk, &now_clk) != 0) { return futex_neg_errno(); }
            if (timeout->tv_sec < now_clk.tv_sec ||
                (timeout->tv_sec == now_clk.tv_sec &&
                 timeout->tv_nsec <= now_clk.tv_nsec)) {
                return -110;
            }
            u_sec = (uint64_t)timeout->tv_sec - (uint64_t)now_clk.tv_sec;
            d_nsec = timeout->tv_nsec - now_clk.tv_nsec;
            if (d_nsec < 0) {
                u_sec -= 1u;
                d_nsec += 1000000000L;
            }
            d_sec = u_sec > (uint64_t)INT64_MAX ? INT64_MAX : (int64_t)u_sec;
        } else {
            if (timeout->tv_sec == 0 && timeout->tv_nsec == 0) {
                return -110;
            }
            d_sec = (int64_t)timeout->tv_sec;
            d_nsec = timeout->tv_nsec;
        }
        {
            int64_t max_add = INT64_MAX - 1 - (int64_t)now_rt.tv_sec;
            if (d_sec > max_add) {
                abstime.tv_sec = (time_t)(INT64_MAX - 1);
                abstime.tv_nsec = 0;
            } else {
                abstime.tv_sec = (time_t)((int64_t)now_rt.tv_sec + d_sec);
                abstime.tv_nsec = now_rt.tv_nsec + d_nsec;
                if (abstime.tv_nsec >= 1000000000L) {
                    abstime.tv_sec += 1;
                    abstime.tv_nsec -= 1000000000L;
                }
            }
        }
        have_deadline = 1;
    }
    futex_lock();
    if (ws != NULL &&
        atomic_load_explicit(&ws->sig_seq, memory_order_acquire) != expected_seq) {
        (void)pthread_mutex_unlock(&g_futex_mu);
        darwin_drain_wake_pipe(ws);
        return -4;
    }
    if (atomic_load_explicit(pinned_host_uaddr, memory_order_seq_cst) != host_endian_val) {
        (void)pthread_mutex_unlock(&g_futex_mu);
        return -11;
    }
    for (i = 0u; i < RT_FUTEX_WAITERS; i++) {
        if (!g_futex_q[i].used) { slot = (int)i; break; }
    }
    if (slot < 0) {
        (void)pthread_mutex_unlock(&g_futex_mu);
        return -12;
    }
    g_futex_q[(unsigned)slot].used = 1;
    g_futex_q[(unsigned)slot].woken = 0;
    g_futex_q[(unsigned)slot].uaddr = pinned_host_uaddr;
    g_futex_q[(unsigned)slot].bitset = bitset;
    if (key != NULL) {
        g_futex_q[(unsigned)slot].key = *key;
        g_futex_q[(unsigned)slot].has_key = 1;
    } else {
        g_futex_q[(unsigned)slot].has_key = 0;
    }
    while (!g_futex_q[(unsigned)slot].woken) {
        int rc;
        if (ws != NULL &&
            atomic_load_explicit(&ws->sig_seq, memory_order_acquire) != expected_seq) {
            ret = -4;
            break;
        }
        if (have_deadline || ws != NULL) {
            struct timespec wait_ts;
            int slice_is_deadline = (ws == NULL);
            if (ws != NULL) {
                struct timespec now_rt;
                if (clock_gettime(CLOCK_REALTIME, &now_rt) != 0) {
                    ret = futex_neg_errno();
                    break;
                }
                wait_ts.tv_sec = now_rt.tv_sec;
                wait_ts.tv_nsec = now_rt.tv_nsec + 10000000L;
                if (wait_ts.tv_nsec >= 1000000000L) {
                    wait_ts.tv_sec += 1;
                    wait_ts.tv_nsec -= 1000000000L;
                }
                if (have_deadline &&
                    (abstime.tv_sec < wait_ts.tv_sec ||
                     (abstime.tv_sec == wait_ts.tv_sec &&
                      abstime.tv_nsec <= wait_ts.tv_nsec))) {
                    wait_ts = abstime;
                    slice_is_deadline = 1;
                }
            } else {
                wait_ts = abstime;
            }
            rc = pthread_cond_timedwait(&g_futex_q[(unsigned)slot].cv,
                &g_futex_mu, &wait_ts);
            if (rc == ETIMEDOUT && !g_futex_q[(unsigned)slot].woken &&
                slice_is_deadline) {
                ret = -110;
                break;
            }
        } else {
            (void)pthread_cond_wait(&g_futex_q[(unsigned)slot].cv, &g_futex_mu);
        }
    }
    g_futex_q[(unsigned)slot].used = 0;
    (void)pthread_mutex_unlock(&g_futex_mu);
    if (ret == -4) {
        darwin_drain_wake_pipe(ws);
    }
    return ret;
}

int64_t rt_host_futex_wake_bitset(_Atomic uint32_t *pinned_host_uaddr,
    const rt_futex_key_t *key, int count, uint32_t bitset)
{
    unsigned i;
    int woken = 0;
    if (pinned_host_uaddr == NULL || bitset == 0u) { return -22; }
    if (count <= 0) { return 0; }
    futex_lock();
    for (i = 0u; i < RT_FUTEX_WAITERS && woken < count; i++) {
        struct darwin_futex_waiter *w = &g_futex_q[i];
        if (w->used && !w->woken &&
            futex_match(w, pinned_host_uaddr, key) &&
            (w->bitset & bitset) != 0u) {
            w->woken = 1;
            (void)pthread_cond_signal(&w->cv);
            woken++;
        }
    }
    (void)pthread_mutex_unlock(&g_futex_mu);
    return (int64_t)woken;
}

int64_t rt_host_futex_requeue(_Atomic uint32_t *pinned_host_uaddr1,
    const rt_futex_key_t *key1, int wake_count, const rt_futex_key_t *key2,
    int requeue_count, const uint32_t *host_endian_cmp_val)
{
    unsigned i;
    int woken = 0;
    int requeued = 0;
    if (pinned_host_uaddr1 == NULL || wake_count < 0 || requeue_count < 0) {
        return -22;
    }
    if (requeue_count > 0 && (key1 == NULL || key2 == NULL)) {
        return -22;
    }
    futex_lock();
    if (host_endian_cmp_val != NULL) {
        uint32_t cur = atomic_load_explicit(pinned_host_uaddr1,
            memory_order_seq_cst);
        if (cur != *host_endian_cmp_val) {
            (void)pthread_mutex_unlock(&g_futex_mu);
            return -11;
        }
    }
    for (i = 0u; i < RT_FUTEX_WAITERS; i++) {
        struct darwin_futex_waiter *w = &g_futex_q[i];
        if (!w->used || w->woken || !futex_match(w, pinned_host_uaddr1, key1)) {
            continue;
        }
        if (woken < wake_count) {
            w->woken = 1;
            (void)pthread_cond_signal(&w->cv);
            woken++;
        } else if (requeued < requeue_count) {
            w->key = *key2;
            w->has_key = 1;
            w->uaddr = NULL;
            requeued++;
        } else {
            break;
        }
    }
    (void)pthread_mutex_unlock(&g_futex_mu);
    return (int64_t)woken + (int64_t)requeued;
}

#else /* not macOS-arm64: no symbols, keeps -pedantic quiet */
typedef int rt_host_darwin_futex_unused_t;
#endif /* defined(__APPLE__) && defined(__aarch64__) */
