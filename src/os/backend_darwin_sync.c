/*
 * src/os/backend_darwin_sync.c -- Darwin worker sync, futex, and threads
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Companion TU to src/os/backend_darwin.c (S64-5, S64-11, S64-14):
 * owns worker registration/preemption, keyed futex wait/wake/requeue,
 * worker thread spawning, process wait/exec, and host signal handlers.
 */
#if defined(__APPLE__) && defined(__aarch64__)
#include "os/backend.h"
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/event.h>
#include <sys/random.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static int64_t neg_errno(void) { return -(int64_t)errno; }
static int64_t libret(long r) { return r < 0L ? neg_errno() : (int64_t)r; }

int rt_darwin_signo(int linux_sig)
{
    static const int lin[] = {
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
        16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 31
    };
    static const int dar[] = {
        1, 2, 3, 4, 5, 6, 10, 8, 9, 30, 11, 31, 13, 14, 15,
        7, 20, 19, 17, 18, 21, 22, 16, 24, 25, 26, 27, 28, 23, 12
    };
    unsigned i;
    for (i = 0u; i < 30u; i++) {
        if (lin[i] == linux_sig) { return dar[i]; }
    }
    return -22;
}

static int linux_signo(int dar_sig)
{
    static const int dar[] = {
        1, 2, 3, 4, 5, 6, 10, 8, 9, 30, 11, 31, 13, 14, 15,
        7, 20, 19, 17, 18, 21, 22, 16, 24, 25, 26, 27, 28, 23, 12
    };
    static const int lin[] = {
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
        16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 31
    };
    unsigned i;
    for (i = 0u; i < 30u; i++) {
        if (dar[i] == dar_sig) { return lin[i]; }
    }
    return dar_sig;
}

/* ---- worker table (preempt without tid signals) ---- */
#define RT_DARWIN_WORKERS 256u
static struct {
    pthread_mutex_t mu;
    uint64_t ids[RT_DARWIN_WORKERS];
    pthread_t ths[RT_DARWIN_WORKERS];
} g_workers = { PTHREAD_MUTEX_INITIALIZER, { 0 }, { 0 } };

static void workers_lock(void)
{
    (void)pthread_mutex_lock(&g_workers.mu);
}

static void darwin_worker_register(uint64_t id, pthread_t th)
{
    unsigned i;
    workers_lock();
    for (i = 0u; i < RT_DARWIN_WORKERS; i++) {
        if (g_workers.ids[i] == id) {
            g_workers.ths[i] = th;
            (void)pthread_mutex_unlock(&g_workers.mu);
            return;
        }
    }
    for (i = 0u; i < RT_DARWIN_WORKERS; i++) {
        if (g_workers.ids[i] == 0u) {
            g_workers.ids[i] = id;
            g_workers.ths[i] = th;
            break;
        }
    }
    (void)pthread_mutex_unlock(&g_workers.mu);
}

static int darwin_worker_find(uint64_t id, pthread_t *out)
{
    unsigned i;
    int found = 0;
    workers_lock();
    for (i = 0u; i < RT_DARWIN_WORKERS; i++) {
        if (g_workers.ids[i] == id) {
            *out = g_workers.ths[i];
            found = 1;
            break;
        }
    }
    (void)pthread_mutex_unlock(&g_workers.mu);
    return found;
}

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

/* 4. worker sync + preemption */
int rt_host_worker_sync_init(rt_worker_sync_t *ws)
{
    int fds[2];
    uint64_t tid = 0u;
    if (ws == NULL) { return -22; }
    atomic_init(&ws->sig_seq, 0u);
    atomic_init(&ws->in_commit_window, 0u);
    atomic_init(&ws->ulock_wait_addr, (uintptr_t)0);
    ws->kqueue_fd = kqueue();
    ws->wake_pipe_rd = -1;
    ws->wake_pipe_wr = -1;
    (void)pthread_threadid_np(NULL, &tid);
    ws->host_tid = tid;
    if (pipe(fds) != 0) {
        if (ws->kqueue_fd >= 0) { (void)close(ws->kqueue_fd); ws->kqueue_fd = -1; }
        return -(int)errno;
    }
    (void)fcntl(fds[0], F_SETFD, FD_CLOEXEC);
    (void)fcntl(fds[1], F_SETFD, FD_CLOEXEC);
    (void)fcntl(fds[0], F_SETFL, O_NONBLOCK);
    (void)fcntl(fds[1], F_SETFL, O_NONBLOCK);
    ws->wake_pipe_rd = fds[0];
    ws->wake_pipe_wr = fds[1];
    return 0;
}

void rt_host_worker_sync_destroy(rt_worker_sync_t *ws)
{
    if (ws == NULL) { return; }
    if (ws->kqueue_fd >= 0) { (void)close(ws->kqueue_fd); }
    if (ws->wake_pipe_rd >= 0) { (void)close(ws->wake_pipe_rd); }
    if (ws->wake_pipe_wr >= 0) { (void)close(ws->wake_pipe_wr); }
    ws->kqueue_fd = -1;
    ws->wake_pipe_rd = -1;
    ws->wake_pipe_wr = -1;
}

void rt_host_worker_notify_signal(rt_worker_sync_t *ws)
{
    static const char one = 'x';
    int saved_errno = errno;
    if (ws == NULL || ws->wake_pipe_wr < 0) { return; }
    atomic_fetch_add_explicit(&ws->sig_seq, 1u, memory_order_release);
    (void)write(ws->wake_pipe_wr, &one, 1u);
    errno = saved_errno;
}

int rt_host_preempt_worker(uint64_t host_tid)
{
    pthread_t th;
    int r;
    if (!darwin_worker_find(host_tid, &th)) { return -3; }
    r = pthread_kill(th, SIGUSR2);
    if (r == 0 || r == ETIMEDOUT) { return 0; }
    return -r;
}

uint64_t rt_host_register_self(void)
{
    uint64_t tid = 0u;
    (void)pthread_threadid_np(NULL, &tid);
    if (tid != 0u) {
        darwin_worker_register(tid, pthread_self());
    }
    return tid;
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
        if (clock_gettime(CLOCK_REALTIME, &now_rt) != 0) { return neg_errno(); }
        if (is_abs_timeout) {
            struct timespec now_clk;
            uint64_t u_sec;
            int clk = clock_realtime ? CLOCK_REALTIME : CLOCK_MONOTONIC;
            if (clock_gettime((clockid_t)clk, &now_clk) != 0) { return neg_errno(); }
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
                    ret = neg_errno();
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

/* 7b. clocks + random */
int64_t rt_host_clock_gettime(int linux_clk_id, struct timespec *tp)
{
    if (tp == NULL) { return -22; }
    return libret(clock_gettime((clockid_t)linux_clk_id, tp));
}

int64_t rt_host_clock_getres(int linux_clk_id, struct timespec *res)
{
    if (res == NULL) { return -22; }
    return libret(clock_getres((clockid_t)linux_clk_id, res));
}

int64_t rt_host_clock_nanosleep(int linux_clk_id, int linux_flags,
    const struct timespec *req, struct timespec *rem, rt_worker_sync_t *ws,
    uint32_t expected_seq)
{
    struct timespec rel;
    if (req == NULL || req->tv_nsec < 0 || req->tv_nsec >= 1000000000L) {
        return -22;
    }
    if (ws != NULL &&
        atomic_load_explicit(&ws->sig_seq, memory_order_acquire) != expected_seq) {
        return -4;
    }
    if ((linux_flags & 1) != 0) {
        struct timespec now;
        if (clock_gettime((clockid_t)linux_clk_id, &now) != 0) { return neg_errno(); }
        rel.tv_sec = req->tv_sec - now.tv_sec;
        rel.tv_nsec = req->tv_nsec - now.tv_nsec;
        if (rel.tv_nsec < 0) { rel.tv_sec -= 1; rel.tv_nsec += 1000000000L; }
        if (rel.tv_sec < 0 || (rel.tv_sec == 0 && rel.tv_nsec == 0)) { return 0; }
    } else {
        if (req->tv_sec < 0) { return -22; }
        rel = *req;
    }
    if (ws != NULL && ws->wake_pipe_rd >= 0) {
        struct timespec start, after;
        struct pollfd pfd;
        int timeout_ms, r;
        (void)clock_gettime(CLOCK_MONOTONIC, &start);
        if (rel.tv_sec > 2147483) {
            timeout_ms = 2147483647;
        } else {
            int64_t ms = (int64_t)rel.tv_sec * 1000L + (int64_t)(rel.tv_nsec / 1000000L);
            if (ms == 0 && rel.tv_nsec > 0) { ms = 1; }
            timeout_ms = ms > 2147483647L ? 2147483647 : (int)ms;
        }
        pfd.fd = ws->wake_pipe_rd;
        pfd.events = POLLIN;
        pfd.revents = 0;
        r = poll(&pfd, 1u, timeout_ms);
        if (r > 0 && (pfd.revents & POLLIN) != 0) {
            char tmp[32];
            (void)read(ws->wake_pipe_rd, tmp, sizeof(tmp));
        }
        if ((r < 0 && errno == EINTR) || r > 0 ||
            atomic_load_explicit(&ws->sig_seq, memory_order_acquire) != expected_seq) {
            if ((linux_flags & 1) == 0 && rem != NULL &&
                clock_gettime(CLOCK_MONOTONIC, &after) == 0) {
                int64_t el_sec = (int64_t)after.tv_sec - (int64_t)start.tv_sec;
                long el_ns = after.tv_nsec - start.tv_nsec;
                if (el_ns < 0) { el_sec -= 1; el_ns += 1000000000L; }
                rem->tv_sec = rel.tv_sec - (time_t)el_sec;
                rem->tv_nsec = rel.tv_nsec - el_ns;
                if (rem->tv_nsec < 0) { rem->tv_sec -= 1; rem->tv_nsec += 1000000000L; }
                if (rem->tv_sec < 0) { rem->tv_sec = 0; rem->tv_nsec = 0; }
            }
            return -4;
        }
        return r < 0 ? neg_errno() : 0;
    }
    return nanosleep(&rel, (linux_flags & 1) != 0 ? NULL : rem) != 0 ? neg_errno() : 0;
}

int64_t rt_host_getrandom(void *buf, size_t buflen, unsigned int linux_flags)
{
    size_t off = 0u;
    (void)linux_flags;
    if (buf == NULL) { return -22; }
    while (off < buflen) {
        size_t want = buflen - off;
        if (want > 256u) { want = 256u; }
        if (getentropy((char *)buf + off, want) != 0) {
            return off != 0u ? (int64_t)off : neg_errno();
        }
        off += want;
    }
    return (int64_t)buflen;
}

/* 8. processes, threads, signals */
int rt_host_worker_altstack_init(void **out_stack_mem, size_t *out_stack_size)
{
    stack_t ss;
    void *mem;
    if (out_stack_mem == NULL || out_stack_size == NULL) { return -22; }
    mem = malloc(65536u);
    if (mem == NULL) { return -12; }
    ss.ss_sp = mem;
    ss.ss_size = 65536u;
    ss.ss_flags = 0;
    if (sigaltstack(&ss, NULL) != 0) {
        int e = errno;
        free(mem);
        return -e;
    }
    *out_stack_mem = mem;
    *out_stack_size = 65536u;
    return 0;
}

void rt_host_worker_altstack_destroy(void *stack_mem, size_t stack_size)
{
    stack_t off;
    (void)stack_size;
    off.ss_sp = NULL;
    off.ss_size = 0u;
    off.ss_flags = SS_DISABLE;
    (void)sigaltstack(&off, NULL);
    free(stack_mem);
}

struct worker_start {
    void *(*fn)(void *);
    void *arg;
    pthread_mutex_t mu;
    pthread_cond_t cv;
    uint64_t tid;
    int ready;
};

/* S64-11: copy st->fn and st->arg into locals before signaling st->ready. */
static void *worker_tramp(void *p)
{
    struct worker_start *st = (struct worker_start *)p;
    void *(*fn)(void *);
    void *arg;
    uint64_t tid = 0u;
    (void)pthread_mutex_lock(&st->mu);
    (void)pthread_threadid_np(NULL, &tid);
    fn = st->fn;
    arg = st->arg;
    st->tid = tid;
    st->ready = 1;
    darwin_worker_register(tid, pthread_self());
    (void)pthread_cond_signal(&st->cv);
    (void)pthread_mutex_unlock(&st->mu);
    return fn(arg);
}

int rt_host_spawn_worker(void *(*fn)(void *), void *arg, uint64_t *out_host_tid)
{
    struct worker_start st;
    pthread_t th;
    if (fn == NULL || out_host_tid == NULL) { return -22; }
    st.fn = fn;
    st.arg = arg;
    st.tid = 0u;
    st.ready = 0;
    (void)pthread_mutex_init(&st.mu, NULL);
    (void)pthread_cond_init(&st.cv, NULL);
    if (pthread_create(&th, NULL, worker_tramp, &st) != 0) {
        int e = errno;
        (void)pthread_mutex_destroy(&st.mu);
        (void)pthread_cond_destroy(&st.cv);
        return -e;
    }
    (void)pthread_detach(th);
    (void)pthread_mutex_lock(&st.mu);
    while (!st.ready) {
        (void)pthread_cond_wait(&st.cv, &st.mu);
    }
    *out_host_tid = st.tid;
    (void)pthread_mutex_unlock(&st.mu);
    (void)pthread_mutex_destroy(&st.mu);
    (void)pthread_cond_destroy(&st.cv);
    return 0;
}

int64_t rt_host_fork(void)
{
    pid_t p = fork();
    return p < 0 ? neg_errno() : (int64_t)p;
}

int64_t rt_host_execve(const char *path, char *const argv[], char *const envp[])
{
    if (path == NULL) { return -22; }
    execve(path, argv, envp);
    return neg_errno();
}

int64_t rt_host_wait4(int64_t pid, int *linux_status_out, int linux_options,
    void *rusage_out, rt_worker_sync_t *ws, uint32_t expected_seq)
{
    for (;;) {
        pid_t r = wait4((pid_t)pid, linux_status_out, linux_options,
            (struct rusage *)rusage_out);
        if (r < 0 && errno == EINTR) {
            if (ws != NULL &&
                atomic_load_explicit(&ws->sig_seq, memory_order_acquire) != expected_seq) {
                return -4;
            }
            continue;
        }
        return r < 0 ? neg_errno() : (int64_t)r;
    }
}

int64_t rt_host_waitid(int idtype, int64_t id, void *linux_siginfo_out,
    int linux_options, void *rusage_out, rt_worker_sync_t *ws,
    uint32_t expected_seq)
{
    (void)ws;
    (void)expected_seq;
    if (rusage_out != NULL) { return -22; }
    return waitid((idtype_t)idtype, (id_t)id, (siginfo_t *)linux_siginfo_out,
        linux_options) != 0 ? neg_errno() : 0;
}

int64_t rt_host_kill(int64_t pid, int linux_sig)
{
    int d = rt_darwin_signo(linux_sig);
    if (d < 0) { return -22; }
    return libret(kill((pid_t)pid, d));
}

int64_t rt_host_tgkill(int64_t tgid, int64_t tid, int linux_sig)
{
    int d = rt_darwin_signo(linux_sig);
    pthread_t th;
    (void)tgid;
    if (d < 0) { return -22; }
    if (d == SIGUSR2) { return rt_host_preempt_worker((uint64_t)tid); }
    if (!darwin_worker_find((uint64_t)tid, &th)) { return -3; }
    return pthread_kill(th, d) != 0 ? -(int)errno : 0;
}

int rt_host_sigprocmask(int linux_how, const uint64_t *new_set,
    uint64_t *old_set)
{
    sigset_t in, out;
    sigset_t *inp = NULL, *outp = NULL;
    if (new_set != NULL) {
        uint32_t low = (uint32_t)(*new_set & 0xffffffffULL);
        (void)memset(&in, 0, sizeof(in));
        (void)memcpy(&in, &low, sizeof(low) < sizeof(in) ? sizeof(low) : sizeof(in));
        inp = &in;
    }
    if (old_set != NULL) { outp = &out; }
    if (pthread_sigmask(linux_how, inp, outp) != 0) { return -(int)errno; }
    if (old_set != NULL) {
        uint64_t v = 0u;
        (void)memcpy(&v, &out, sizeof(out) < sizeof(v) ? sizeof(out) : sizeof(v));
        *old_set = v;
    }
    return 0;
}

void rt_host_exit_thread(int status)
{
    pthread_exit((void *)(uintptr_t)(uint32_t)status);
    __builtin_unreachable();
}

void rt_host_exit_group(int status)
{
    _exit(status);
    __builtin_unreachable();
}

static rt_host_sync_fault_fn g_on_sync = NULL;
static rt_host_async_sig_fn g_on_async = NULL;
static rt_host_preempt_fn g_on_preempt = NULL;

static void backend_segv_handler(int sig, siginfo_t *info, void *uc)
{
    rt_host_sync_fault_t f;
    ucontext_t *ctx = (ucontext_t *)uc;
    (void)memset(&f, 0, sizeof(f));
    f.linux_si_signo = linux_signo(sig);
    f.linux_si_code = info != NULL ? info->si_code : 0;
    f.fault_addr = info != NULL ? (uintptr_t)info->si_addr : (uintptr_t)0;
    f.host_pc = (uintptr_t)ctx->uc_mcontext->__ss.__pc;
    f.host_ucontext = uc;
    if (g_on_sync != NULL) { g_on_sync(&f); }
}

static void backend_preempt_handler(int sig, siginfo_t *info, void *uc)
{
    (void)sig;
    (void)info;
    if (g_on_preempt != NULL) { g_on_preempt(uc); }
}

static void backend_async_handler(int sig, siginfo_t *info, void *uc)
{
    rt_host_async_siginfo_t s;
    (void)uc;
    (void)memset(&s, 0, sizeof(s));
    s.linux_si_signo = linux_signo(sig);
    s.linux_si_code = info != NULL ? info->si_code : 0;
    s.sender_pid = info != NULL ? (int32_t)info->si_pid : 0;
    s.sender_uid = info != NULL ? (uint32_t)info->si_uid : 0u;
    if (g_on_async != NULL) { g_on_async(&s); }
}

int rt_host_install_signal_handlers(rt_host_sync_fault_fn on_sync_fault,
    rt_host_async_sig_fn on_async_sig, rt_host_preempt_fn on_preempt)
{
    struct sigaction sa;
    g_on_sync = on_sync_fault;
    g_on_async = on_async_sig;
    g_on_preempt = on_preempt;
    (void)memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = backend_segv_handler;
    sa.sa_flags = SA_SIGINFO | SA_ONSTACK;
    (void)sigemptyset(&sa.sa_mask);
    if (sigaction(SIGSEGV, &sa, NULL) != 0) { return -(int)errno; }
    if (sigaction(SIGBUS, &sa, NULL) != 0) { return -(int)errno; }
    (void)memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = backend_preempt_handler;
    sa.sa_flags = SA_SIGINFO | SA_ONSTACK;
    (void)sigemptyset(&sa.sa_mask);
    if (sigaction(SIGUSR2, &sa, NULL) != 0) { return -(int)errno; }
    (void)memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = backend_async_handler;
    sa.sa_flags = SA_SIGINFO | SA_ONSTACK;
    (void)sigemptyset(&sa.sa_mask);
    if (sigaction(SIGCHLD, &sa, NULL) != 0) { return -(int)errno; }
    if (sigaction(SIGALRM, &sa, NULL) != 0) { return -(int)errno; }
    return 0;
}
#else /* not macOS-arm64: no symbols, keeps -pedantic quiet */
typedef int rt_host_darwin_sync_unused_t;
#endif /* defined(__APPLE__) && defined(__aarch64__) */
