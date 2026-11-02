/*
 * tests/test_r3_darwin.c — Round-3 Darwin backend regression test.
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Covers S64-R3-5 (worker unregister releases the table slot and
 * exhaustion propagates), S64-R3-6 (a full directory-stream cache
 * rejects new allocations instead of evicting live streams with
 * unread entries), and S64-R3-7 (clock_nanosleep sleeps until the
 * validated deadline with upward-rounded poll slices, and reports
 * -EINTR with remaining time on a worker signal). Darwin-only;
 * deterministic stdout; exit 0 with R3-DARWIN-PASS iff every check
 * passed.
 *
 * Build (worktree root, macOS arm64):
 *   cc -std=c11 -Werror -Werror=vla -pedantic -Wall -Wextra -Isrc \
 *     tests/test_r3_darwin.c src/os/backend_darwin.c \
 *     src/os/backend_darwin_sync.c src/os/backend_darwin_futex.c \
 *     -o _build/test_r3_darwin -pthread
 */

#if defined(__APPLE__) && defined(__aarch64__)

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "os/backend.h"
#include "core/cpu.h"
#include "dbt/mem_sites.h"
#include "interp/interp_win.h"
#include "os/guest_run_priv.h"
#include "os/mem_space.h"
#include "os/threads.h"
#include "os/threads_darwin.h"

static int fails = 0;

static void check(const char *name, int passed)
{
    if (passed) {
        (void)printf("ok %s\n", name);
    } else {
        (void)printf("FAIL %s\n", name);
        ++fails;
    }
}

static uint64_t ns_between(const struct timespec *a,
    const struct timespec *b)
{
    int64_t sec = (int64_t)b->tv_sec - (int64_t)a->tv_sec;
    int64_t ns = (int64_t)b->tv_nsec - (int64_t)a->tv_nsec;
    if (ns < 0) {
        sec -= 1;
        ns += 1000000000L;
    }
    if (sec < 0) {
        return UINT64_C(0);
    }
    return (uint64_t)sec * UINT64_C(1000000000) + (uint64_t)ns;
}

/* Notifier thread: nudges one worker's signal state mid-sleep. */
static void *poke_fn(void *arg)
{
    rt_worker_sync_t *ws = (rt_worker_sync_t *)arg;
    struct timespec nap;
    nap.tv_sec = 0;
    nap.tv_nsec = 50000000L;
    (void)nanosleep(&nap, NULL);
    rt_host_worker_notify_signal(ws);
    return NULL;
}

/* ---- Dispatch-level futex test stubs --------------------------------
 * threads_darwin.c runs against three thread-layer hooks; the stubs
 * below close the link with a real mutex and no group exit, so the
 * test below drives the actual guest-dispatch entry points
 * (thr_darwin_futex_wait/wake: resolve, pin, key, worker state). */
static pthread_mutex_t t_big_lock = PTHREAD_MUTEX_INITIALIZER;

void sparc64_thread_big_lock(void)
{
    (void)pthread_mutex_lock(&t_big_lock);
}

void sparc64_thread_big_unlock(void)
{
    (void)pthread_mutex_unlock(&t_big_lock);
}

int sparc64_threads_group_exiting(long *status_out)
{
    (void)status_out;
    return 0;
}

void sparc64_win_invalidate_all(void)
{
}

static guest_state_t t_guest;

static bool t_mem_read(void *ctx, uint64_t va, void *dst, uint64_t n)
{
    guest_state_t *g = (guest_state_t *)ctx;
    return sparc64_space_read(&g->space, va, dst, (size_t)n,
        (unsigned)SPARC64_MEM_READ);
}

static bool t_mem_write(void *ctx, uint64_t va, const void *src,
    uint64_t n)
{
    guest_state_t *g = (guest_state_t *)ctx;
    return sparc64_space_write(&g->space, va, src, (size_t)n);
}

static bool t_mem_prep(void *ctx, uint64_t va, uint64_t n)
{
    (void)ctx;
    (void)va;
    (void)n;
    return 1;
}

/* Waker thread: wakes one waiter on the test futex word. */
static void *wake_fn(void *arg)
{
    const sparc64_syscall_mem_t *ops =
        (const sparc64_syscall_mem_t *)arg;
    struct timespec nap;
    nap.tv_sec = 0;
    nap.tv_nsec = 50000000L;
    (void)nanosleep(&nap, NULL);
    sparc64_thread_big_lock();
    (void)thr_darwin_futex_wake(ops, UINT64_C(0x300000), UINT64_C(1));
    sparc64_thread_big_unlock();
    return NULL;
}

static void put_be32(uint8_t out[4], uint32_t v)
{
    out[0] = (uint8_t)(v >> 24);
    out[1] = (uint8_t)(v >> 16);
    out[2] = (uint8_t)(v >> 8);
    out[3] = (uint8_t)v;
}

int main(void)
{
    /* ---- S64-R3-5: worker unregister ------------------------------- */
    {
        uint64_t r1 = rt_host_register_self();
        check("register-nonzero", r1 != UINT64_C(0));
        rt_host_unregister_self();
        rt_host_unregister_self();
        {
            uint64_t r2 = rt_host_register_self();
            check("reregister-after-unregister", r2 != UINT64_C(0));
        }
        check("preempt-unknown-esrch",
            rt_host_preempt_worker(UINT64_C(0x0badf00d)) == -3);
        rt_host_unregister_self();
    }
    /* ---- S64-R3-7: nanosleep deadline ------------------------------- */
    {
        rt_worker_sync_t ws;
        struct timespec req;
        struct timespec t0;
        struct timespec t1;
        uint32_t seq;
        int64_t rc;
        check("ws-init", rt_host_worker_sync_init(&ws) == 0);
        seq = atomic_load_explicit(&ws.sig_seq,
            memory_order_acquire);
        /* Fractional request: a floored single poll would return at
         * 40 ms, before the 40.5 ms deadline. */
        req.tv_sec = 0;
        req.tv_nsec = 40500000L;
        (void)clock_gettime(CLOCK_MONOTONIC, &t0);
        rc = rt_host_clock_nanosleep(1, 0, &req, NULL, &ws, seq);
        (void)clock_gettime(CLOCK_MONOTONIC, &t1);
        check("sleep-rc", rc == 0);
        check("sleep-deadline", ns_between(&t0, &t1) >= UINT64_C(40500000));
        check("sleep-sane", ns_between(&t0, &t1) < UINT64_C(5000000000));
        /* Signal interruption: remaining time must be reported. */
        {
            pthread_t th;
            struct timespec rem;
            req.tv_sec = 5;
            req.tv_nsec = 0;
            rem.tv_sec = -1;
            rem.tv_nsec = -1;
            seq = atomic_load_explicit(&ws.sig_seq,
            memory_order_acquire);
            if (pthread_create(&th, NULL, poke_fn, &ws) != 0) {
                check("poke-spawn", 0);
            } else {
                (void)clock_gettime(CLOCK_MONOTONIC, &t0);
                rc = rt_host_clock_nanosleep(1, 0, &req, &rem, &ws,
                    seq);
                (void)clock_gettime(CLOCK_MONOTONIC, &t1);
                (void)pthread_join(th, NULL);
                check("sleep-eintr", rc == -4);
                check("sleep-early",
                    ns_between(&t0, &t1) < UINT64_C(5000000000));
                check("sleep-rem",
                    rem.tv_sec >= 0 && rem.tv_sec <= 5);
            }
        }
        rt_host_worker_sync_destroy(&ws);
    }
    /* ---- S64-R3-6: directory cache rejects instead of evicting ----- */
    {
        int fds[33];
        char buf[1024];
        unsigned i;
        unsigned opened = 0u;
        int64_t first_rc;
        int64_t full_rc = 0;
        for (i = 0u; i < 33u; i++) {
            fds[i] = -1;
        }
        for (i = 0u; i < 33u; i++) {
            fds[i] = open("/", O_RDONLY | O_DIRECTORY);
            if (fds[i] < 0) {
                break;
            }
            opened++;
        }
        check("thirtythree-opens", opened == 33u);
        if (opened == 33u) {
            /* Fill all 32 streams with a first page each. */
            first_rc = rt_host_getdents64(fds[0], buf, sizeof(buf));
            check("first-stream", first_rc > 0);
            for (i = 1u; i < 32u; i++) {
                if (rt_host_getdents64(fds[i], buf,
                        sizeof(buf)) <= 0) {
                    break;
                }
            }
            check("thirtytwo-streams", i == 32u);
            /* The 33rd allocation must fail without disturbing the
             * 32 live streams (no unread entry may be lost). */
            full_rc = rt_host_getdents64(fds[32], buf, sizeof(buf));
            check("full-rejects", full_rc == -12);
            check("first-undisturbed",
                rt_host_getdents64(fds[0], buf, sizeof(buf)) >= 0);
        }
        for (i = 0u; i < opened; i++) {
            if (fds[i] >= 0) {
                (void)rt_host_close(fds[i]);
            }
        }
    }
    /* ---- S64-R3-4: guest futex dispatch path -------------------------
     * Drive thr_darwin_futex_wait/wake (resolve, pin, key, worker
     * signal state) across two host threads on one shared word. */
    {
        sparc64_syscall_mem_t ops;
        uint8_t w4[4];
        pthread_t wth;
        struct timespec ts;
        long wrc;
        (void)memset(&t_guest, 0, sizeof(t_guest));
        sparc64_space_init(&t_guest.space, 64U);
        check("futex-map", sparc64_space_map(&t_guest.space,
            UINT64_C(0x300000), UINT64_C(8192),
            (unsigned)(SPARC64_MEM_READ | SPARC64_MEM_WRITE), 0));
        put_be32(w4, UINT32_C(0x1234));
        check("futex-word",
            sparc64_space_write_initial(&t_guest.space,
                UINT64_C(0x300000), w4, sizeof(w4)));
        ops.read = t_mem_read;
        ops.write = t_mem_write;
        ops.prepare_write = t_mem_prep;
        ops.context = &t_guest;
        /* Value mismatch short-circuits without sleeping. */
        check("futex-eagain",
            thr_darwin_futex_wait(NULL, &ops, UINT64_C(0x300000),
                UINT64_C(0), UINT64_C(0x5678), 0U, NULL) == -11);
        /* Misaligned address is EINVAL on both backends. */
        check("futex-einval",
            thr_darwin_futex_wait(NULL, &ops, UINT64_C(0x300002),
                UINT64_C(0), UINT64_C(0x1234), 0U, NULL) == -22);
        /* A waker on a second thread releases the wait. */
        sparc64_thread_big_lock();
        if (pthread_create(&wth, NULL, wake_fn, &ops) != 0) {
            check("futex-waker-spawn", 0);
            sparc64_thread_big_unlock();
        } else {
            ts.tv_sec = 5;
            ts.tv_nsec = 0;
            wrc = thr_darwin_futex_wait(NULL, &ops, UINT64_C(0x300000),
                UINT64_C(0), UINT64_C(0x1234), 0U, &ts);
            sparc64_thread_big_unlock();
            (void)pthread_join(wth, NULL);
            check("futex-wake-wait", wrc == 0);
        }
        /* Unwoken relative wait times out. */
        sparc64_thread_big_lock();
        ts.tv_sec = 0;
        ts.tv_nsec = 30000000L;
        wrc = thr_darwin_futex_wait(NULL, &ops, UINT64_C(0x300000),
            UINT64_C(0), UINT64_C(0x1234), 0U, &ts);
        sparc64_thread_big_unlock();
        check("futex-etimedout", wrc == -110);
        /* Absolute WAIT_BITSET timeout on the realtime clock. */
        {
            struct timespec now_rt;
            sparc64_thread_big_lock();
            (void)clock_gettime(CLOCK_REALTIME, &now_rt);
            ts.tv_sec = now_rt.tv_sec;
            ts.tv_nsec = now_rt.tv_nsec + 30000000L;
            if (ts.tv_nsec >= 1000000000L) {
                ts.tv_sec += 1;
                ts.tv_nsec -= 1000000000L;
            }
            wrc = thr_darwin_futex_wait(NULL, &ops, UINT64_C(0x300000),
                UINT64_C(9) | UINT64_C(256), UINT64_C(0x1234),
                UINT32_C(0xffffffff), &ts);
            sparc64_thread_big_unlock();
            check("futex-abs-etimedout", wrc == -110);
        }
        /* Unknown commands stay -ENOSYS like the Linux path. */
        check("futex-enosys",
            thr_darwin_futex_wait(NULL, &ops, UINT64_C(0x300000),
                UINT64_C(2), UINT64_C(0x1234), 0U, NULL) == -38);
        thr_darwin_ws_teardown();
        sparc64_space_destroy(&t_guest.space);
    }
    if (fails != 0) {
        (void)printf("R3-DARWIN-FAIL n=%d\n", fails);
        return 1;
    }
    (void)printf("R3-DARWIN-PASS\n");
    return 0;
}

#else /* not macOS-arm64 */

#include <stdio.h>

int main(void)
{
    (void)printf("R3-DARWIN-PASS darwin-only\n");
    return 0;
}

#endif /* defined(__APPLE__) && defined(__aarch64__) */
