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

/* Returns 0 on success, -12 (ENOMEM) when the fixed table is full
 * (S64-R3-5: the caller propagates exhaustion instead of running
 * unregistered while preemption silently misses the thread). */
static int darwin_worker_register(uint64_t id, pthread_t th)
{
    unsigned i;
    int rc = -12;
    workers_lock();
    for (i = 0u; i < RT_DARWIN_WORKERS; i++) {
        if (g_workers.ids[i] == id) {
            g_workers.ths[i] = th;
            rc = 0;
            break;
        }
    }
    if (rc != 0) {
        for (i = 0u; i < RT_DARWIN_WORKERS; i++) {
            if (g_workers.ids[i] == 0u) {
                g_workers.ids[i] = id;
                g_workers.ths[i] = th;
                rc = 0;
                break;
            }
        }
    }
    (void)pthread_mutex_unlock(&g_workers.mu);
    return rc;
}

/* Release a worker-table slot (S64-R3-5): every thread lifetime that
 * registered must unregister on exit, or the fixed table fills with
 * dead ids and new live workers become unreachable to preemption. */
static void darwin_worker_unregister(uint64_t id)
{
    unsigned i;
    if (id == 0u) {
        return;
    }
    workers_lock();
    for (i = 0u; i < RT_DARWIN_WORKERS; i++) {
        if (g_workers.ids[i] == id) {
            g_workers.ids[i] = 0u;
            (void)memset(&g_workers.ths[i], 0, sizeof(g_workers.ths[i]));
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

/* Keyed futex table + wait/wake/requeue live in
 * src/os/backend_darwin_futex.c (S64-R3 split). */

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
        /* S64-R3-5: a full table reports exhaustion as id 0 (the
         * vm64 layer treats 0 as unregistered) instead of handing
         * back an id preemption can never resolve. */
        if (darwin_worker_register(tid, pthread_self()) != 0) {
            return 0u;
        }
    }
    return tid;
}

void rt_host_unregister_self(void)
{
    uint64_t tid = 0u;
    (void)pthread_threadid_np(NULL, &tid);
    darwin_worker_unregister(tid);
}

/* Keyed futex wait/wake/requeue live in
 * src/os/backend_darwin_futex.c (S64-R3 split). */

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
        /* S64-R3-7: sleep until the validated deadline, not until one
         * bounded poll finishes. Each poll interval rounds UP to the
         * next millisecond (a floored interval returns early on
         * fractional requests) and caps at INT_MAX; a poll timeout
         * then recomputes the remainder and sleeps again, so capped
         * long waits still run to the full deadline. Only a signal
         * (wake-pipe readiness, EINTR, or a sig_seq step) escapes
         * early with -EINTR and the remaining time. */
        struct timespec start;
        struct timespec deadline;
        int is_abs = (linux_flags & 1) != 0;
        (void)clock_gettime(CLOCK_MONOTONIC, &start);
        if (!is_abs) {
            deadline.tv_sec = start.tv_sec + rel.tv_sec;
            deadline.tv_nsec = start.tv_nsec + rel.tv_nsec;
            if (deadline.tv_nsec >= 1000000000L) {
                deadline.tv_sec += 1;
                deadline.tv_nsec -= 1000000000L;
            }
        } else {
            deadline.tv_sec = 0;
            deadline.tv_nsec = 0;
        }
        for (;;) {
            struct timespec left;
            struct pollfd pfd;
            int64_t ms;
            int timeout_ms;
            int r;
            if (is_abs) {
                struct timespec now_clk;
                if (clock_gettime((clockid_t)linux_clk_id,
                        &now_clk) != 0) {
                    return neg_errno();
                }
                left.tv_sec = req->tv_sec - now_clk.tv_sec;
                left.tv_nsec = req->tv_nsec - now_clk.tv_nsec;
                if (left.tv_nsec < 0) {
                    left.tv_sec -= 1;
                    left.tv_nsec += 1000000000L;
                }
            } else {
                struct timespec now_m;
                if (clock_gettime(CLOCK_MONOTONIC, &now_m) != 0) {
                    return neg_errno();
                }
                left.tv_sec = deadline.tv_sec - now_m.tv_sec;
                left.tv_nsec = deadline.tv_nsec - now_m.tv_nsec;
                if (left.tv_nsec < 0) {
                    left.tv_sec -= 1;
                    left.tv_nsec += 1000000000L;
                }
            }
            if (left.tv_sec < 0 ||
                (left.tv_sec == 0 && left.tv_nsec <= 0)) {
                return 0;
            }
            if (left.tv_sec > (time_t)2147483) {
                ms = (int64_t)2147483647;
            } else {
                ms = (int64_t)left.tv_sec * 1000L +
                    (int64_t)((left.tv_nsec + 999999L) / 1000000L);
                if (ms <= 0) {
                    ms = 1;
                }
                if (ms > (int64_t)2147483647) {
                    ms = (int64_t)2147483647;
                }
            }
            timeout_ms = (int)ms;
            pfd.fd = ws->wake_pipe_rd;
            pfd.events = POLLIN;
            pfd.revents = 0;
            r = poll(&pfd, 1u, timeout_ms);
            if (r > 0 && (pfd.revents & POLLIN) != 0) {
                char tmp[32];
                (void)read(ws->wake_pipe_rd, tmp, sizeof(tmp));
            }
            if ((r < 0 && errno == EINTR) || r > 0 ||
                atomic_load_explicit(&ws->sig_seq,
                    memory_order_acquire) != expected_seq) {
                if (!is_abs && rem != NULL) {
                    struct timespec now_m;
                    if (clock_gettime(CLOCK_MONOTONIC, &now_m) == 0) {
                        rem->tv_sec = deadline.tv_sec - now_m.tv_sec;
                        rem->tv_nsec = deadline.tv_nsec - now_m.tv_nsec;
                        if (rem->tv_nsec < 0) {
                            rem->tv_sec -= 1;
                            rem->tv_nsec += 1000000000L;
                        }
                        if (rem->tv_sec < 0) {
                            rem->tv_sec = 0;
                            rem->tv_nsec = 0;
                        }
                    } else {
                        rem->tv_sec = 0;
                        rem->tv_nsec = 0;
                    }
                }
                return -4;
            }
            if (r < 0) {
                return neg_errno();
            }
        }
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
    (void)darwin_worker_register(tid, pthread_self());
    (void)pthread_cond_signal(&st->cv);
    (void)pthread_mutex_unlock(&st->mu);
    {
        void *ret = fn(arg);
        /* S64-R3-5: the worker lifetime ends here; release the table
         * slot so later thread lifetimes can register. */
        darwin_worker_unregister(tid);
        return ret;
    }
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
