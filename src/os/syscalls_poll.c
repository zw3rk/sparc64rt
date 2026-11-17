/*
 * src/os/syscalls_poll.c — poll/select/nanosleep/record-lock syscalls
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Split from syscalls_fs.c. Guest structs are big-endian. Blocking
 * host calls drop the big guest lock so sibling threads and the
 * SIGUSR2 quiescence handshake can proceed. Guest handlers only run at
 * synchronous points, so a host EINTR here is translator-internal
 * (quiescence) unless a guest signal is deliverable; it is retried with
 * the remaining time taken from a CLOCK_MONOTONIC deadline.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "os/syscalls_poll.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/select.h>
#include <time.h>

#include "os/syscalls_ext.h"
#include "os/syscalls_sig.h"
#include "os/threads.h"

#define POLL_NFDS_MAX 65536U
/* Darwin select(2) rejects tv_sec above 100000000; clamp there. */
#define POLL_SEC_MAX 100000000
#define POLL_LOCK_FLOCK_NB 4
#define POLL_LOCK_FLOCK_UN 8

typedef const sparc64_syscall_mem_t *memp_t;

static long poll_rd(memp_t mem, uint64_t va, void *buf, uint64_t len)
{
    if (l2a_range_ok(va, len) != 0 || !mem->read(mem->context, va, buf, len)) {
        return -EFAULT;
    }
    return 0;
}

/* SPARC signal numbers (BSD-style) to host signals. SIGKILL/SIGSTOP
 * are omitted: they can never be blocked. */
static const struct {
    int sparc;
    int host;
} poll_sigmap[] = {
    { 1, SIGHUP }, { 2, SIGINT }, { 3, SIGQUIT }, { 4, SIGILL },
    { 5, SIGTRAP }, { 6, SIGABRT }, { 8, SIGFPE }, { 10, SIGBUS },
    { 11, SIGSEGV }, { 12, SIGSYS }, { 13, SIGPIPE }, { 14, SIGALRM },
    { 15, SIGTERM }, { 16, SIGURG }, { 18, SIGTSTP }, { 19, SIGCONT },
    { 20, SIGCHLD }, { 21, SIGTTIN }, { 22, SIGTTOU }, { 23, SIGIO },
    { 24, SIGXCPU }, { 25, SIGXFSZ }, { 26, SIGVTALRM }, { 27, SIGPROF },
    { 28, SIGWINCH },
#ifdef SIGPWR
    { 29, SIGPWR },
#endif
    { 30, SIGUSR1 }, { 31, SIGUSR2 },
};

/* Host signals the translator owns: never blocked by a guest mask. */
static const int poll_reserved[] = {
    SIGUSR2, SIGSEGV, SIGBUS, SIGILL, SIGFPE, SIGTRAP, SIGSYS,
};

/* Read a guest sigset (BE64) into a host sigset_t. A NULL pointer
 * means "no mask" (*have = 0); otherwise sigsetsize must be 8. */
static long poll_sigmask(memp_t mem, uint64_t sigva, uint64_t sigsetsize,
                         sigset_t *out, int *have, uint64_t *guest)
{
    uint8_t raw[8];
    uint64_t bits;
    size_t i;
    long rc;

    *have = 0;
    if (sigva == 0U) {
        return 0;
    }
    if (sigsetsize != 8U) {
        return -EINVAL;
    }
    rc = poll_rd(mem, sigva, raw, sizeof raw);
    if (rc != 0) {
        return rc;
    }
    bits = l2a_get_be64(raw);
    *guest = bits & ~(SPARC64_SIGKILL_BIT | SPARC64_SIGSTOP_BIT);
    sigemptyset(out);
    for (i = 0U; i < sizeof poll_sigmap / sizeof poll_sigmap[0]; i++) {
        if (((bits >> (poll_sigmap[i].sparc - 1)) & 1U) != 0U) {
            (void)sigaddset(out, poll_sigmap[i].host);
        }
    }
#if defined(SIGRTMIN) && defined(SIGRTMAX)
    /* Realtime SPARC signals 32..64 map onto SIGRTMIN+0..32. */
    for (i = 32U; i <= 64U; i++) {
        int host = SIGRTMIN + (int)(i - 32U);

        if (host <= SIGRTMAX && ((bits >> (i - 1U)) & 1U) != 0U) {
            (void)sigaddset(out, host);
        }
    }
    /* SIGRTMIN+1 is the translator's preemption signal. */
    (void)sigdelset(out, SIGRTMIN + 1);
#endif
    for (i = 0U; i < sizeof poll_reserved / sizeof poll_reserved[0]; i++) {
        (void)sigdelset(out, poll_reserved[i]);
    }
    *have = 1;
    return 0;
}

/* Guest timespec/timeval (two BE words) to a host timespec. Negative
 * or out-of-range fields are -EINVAL like the kernel; *has = 0 means
 * block forever. Huge values clamp to POLL_SEC_MAX. */
static long poll_timeout(memp_t mem, uint64_t va, int is_usec,
                         struct timespec *ts, int *has)
{
    uint8_t g[16];
    uint64_t sec;
    uint64_t sub;
    long rc;

    *has = 0;
    if (va == 0U) {
        return 0;
    }
    rc = poll_rd(mem, va, g, sizeof g);
    if (rc != 0) {
        return rc;
    }
    sec = l2a_get_be64(g);
    sub = l2a_get_be64(g + 8);
    if ((int64_t)sec < 0 || (int64_t)sub < 0 ||
        sub >= (is_usec ? 1000000U : 1000000000U)) {
        return -EINVAL;
    }
    if (sec > (uint64_t)POLL_SEC_MAX) {
        sec = (uint64_t)POLL_SEC_MAX;
        sub = 0U;
    }
    ts->tv_sec = (time_t)sec;
    ts->tv_nsec = (long)(is_usec ? sub * 1000U : sub);
    *has = 1;
    return 0;
}

static void poll_deadline(const struct timespec *ts, struct timespec *dl)
{
    clock_gettime(CLOCK_MONOTONIC, dl);
    dl->tv_sec += ts->tv_sec;
    dl->tv_nsec += ts->tv_nsec;
    if (dl->tv_nsec >= 1000000000L) {
        dl->tv_sec++;
        dl->tv_nsec -= 1000000000L;
    }
}

static void poll_remaining(const struct timespec *dl, struct timespec *out)
{
    struct timespec now;

    clock_gettime(CLOCK_MONOTONIC, &now);
    out->tv_sec = dl->tv_sec - now.tv_sec;
    out->tv_nsec = dl->tv_nsec - now.tv_nsec;
    if (out->tv_nsec < 0) {
        out->tv_sec--;
        out->tv_nsec += 1000000000L;
    }
    if (out->tv_sec < 0) {
        out->tv_sec = 0;
        out->tv_nsec = 0;
    }
}

/* True when a host EINTR must reach the guest: a deliverable guest
 * signal is queued or the thread group is exiting. */
static int poll_interrupted(const sparc64_ctx_t *ctx)
{
    if (sparc64_threads_group_exiting(NULL) != 0) {
        return 1;
    }
    return ctx != NULL && (sparc64_sync_sig_pending_get(ctx) &
                           ~sparc64_sync_sig_blocked_get(ctx)) != UINT64_C(0);
}

/* Temporary ppoll/pselect6 guest blocked mask. The mask is installed in
 * the ctx for the whole wait so poll_interrupted() and the pending
 * check before the first sleep see it (no lost wakeup). It is restored
 * on every return, -EINTR included: this engine has no post-syscall
 * async delivery, so an interrupting signal stays queued and delivers
 * at the next unblock point with the original mask recorded in its
 * frame (the Linux restore_saved_sigmask outcome). */
static uint64_t poll_mask_enter(const sparc64_ctx_t *ctx, uint64_t temp)
{
    uint64_t prev = 0U;

    if (ctx != NULL) {
        prev = sparc64_sync_sig_blocked_get(ctx);
        sparc64_sync_sig_blocked_set(ctx, temp);
    }
    return prev;
}

static void poll_mask_leave(const sparc64_ctx_t *ctx, uint64_t prev)
{
    if (ctx != NULL) {
        sparc64_sync_sig_blocked_set(ctx, prev);
    }
}

/* One host ppoll. Darwin has none: swap the mask around poll() (the
 * mask/wait window is not atomic there; documented limitation). */
static int poll_host(struct pollfd *pf, nfds_t n, const struct timespec *ts,
                     const sigset_t *sm)
{
#if defined(__APPLE__)
    sigset_t old;
    int ms = -1;
    int r;
    int e;

    if (ts != NULL) {
        int64_t t = (int64_t)ts->tv_sec * 1000 +
                    ((int64_t)ts->tv_nsec + 999999) / 1000000;

        ms = t > 2000000000 ? 2000000000 : (int)t;
    }
    if (sm != NULL) {
        (void)pthread_sigmask(SIG_SETMASK, sm, &old);
    }
    r = poll(pf, n, ms);
    e = errno;
    if (sm != NULL) {
        (void)pthread_sigmask(SIG_SETMASK, &old, NULL);
    }
    errno = e;
    return r;
#else
    return ppoll(pf, n, ts, sm);
#endif
}

/* poll core: nfds {int fd; short events; short revents}, big-endian. */
static long poll_core(const sparc64_ctx_t *ctx, memp_t mem, uint64_t va,
                      uint64_t nfds, const struct timespec *ts,
                      const sigset_t *sm)
{
    struct pollfd *pf;
    struct timespec dl = { 0, 0 };
    uint8_t *img;
    uint64_t i;
    long ret;
    int n;
    int e;

    if (nfds > POLL_NFDS_MAX) {
        return -EINVAL;
    }
    pf = (struct pollfd *)calloc((size_t)nfds + 1U, sizeof *pf);
    img = (uint8_t *)malloc((size_t)nfds * 8U + 1U);
    if (pf == NULL || img == NULL) {
        free(pf);
        free(img);
        return -ENOMEM;
    }
    ret = nfds == 0U ? 0L : poll_rd(mem, va, img, nfds * 8U);
    if (ret == 0) {
        for (i = 0U; i < nfds; i++) {
            pf[i].fd = (int)(int32_t)l2a_get_be32(img + i * 8U);
            pf[i].events = (short)(((unsigned)img[i * 8U + 4U] << 8) |
                                   img[i * 8U + 5U]);
        }
        if (ts != NULL) {
            poll_deadline(ts, &dl);
        }
        for (;;) {
            struct timespec left;

            if (ts != NULL) {
                poll_remaining(&dl, &left);
            }
            sparc64_thread_big_unlock();
            n = poll_host(pf, (nfds_t)nfds, ts != NULL ? &left : NULL, sm);
            e = errno;
            sparc64_thread_big_lock();
            if (n >= 0 || e != EINTR || poll_interrupted(ctx)) {
                break;
            }
        }
        if (n < 0) {
            ret = -(long)e;
        } else {
            for (i = 0U; i < nfds; i++) {
                l2a_put_be16(img + i * 8U + 6U, (uint16_t)pf[i].revents);
            }
            ret = nfds != 0U ? l2a_store_buf(mem, va, img, nfds * 8U) : 0L;
            if (ret == 0) {
                ret = n;
            }
        }
    }
    free(pf);
    free(img);
    return ret;
}

long sparc64_fs_poll(const sparc64_ctx_t *ctx, memp_t mem, uint64_t fds,
                     uint64_t nfds, int timeout_ms)
{
    struct timespec ts;

    ts.tv_sec = timeout_ms / 1000;
    ts.tv_nsec = (long)(timeout_ms % 1000) * 1000000L;
    return poll_core(ctx, mem, fds, nfds, timeout_ms < 0 ? NULL : &ts, NULL);
}

long sparc64_fs_ppoll(const sparc64_ctx_t *ctx, memp_t mem, uint64_t fds,
                      uint64_t nfds, uint64_t tva, uint64_t sigva,
                      uint64_t sigsetsize)
{
    struct timespec ts;
    sigset_t sm;
    uint64_t temp = 0U;
    uint64_t prev;
    int has_ts;
    int has_sm;
    long rc = poll_timeout(mem, tva, 0, &ts, &has_ts);

    if (rc != 0) {
        return rc;
    }
    rc = poll_sigmask(mem, sigva, sigsetsize, &sm, &has_sm, &temp);
    if (rc != 0) {
        return rc;
    }
    if (!has_sm) {
        return poll_core(ctx, mem, fds, nfds, has_ts ? &ts : NULL, NULL);
    }
    prev = poll_mask_enter(ctx, temp);
    rc = poll_interrupted(ctx) ? -EINTR
                               : poll_core(ctx, mem, fds, nfds,
                                           has_ts ? &ts : NULL, &sm);
    poll_mask_leave(ctx, prev);
    return rc;
}

/* select/pselect6 share a body; bitmaps are BE 64-bit words. */
static long select_core(const sparc64_ctx_t *ctx, memp_t mem, uint64_t nfds,
                        const uint64_t va[3], const struct timespec *ts,
                        const sigset_t *sm)
{
    fd_set orig[3];
    fd_set sets[3];
    uint8_t buf[sizeof(fd_set)];
    uint64_t nbytes = ((nfds + 63U) / 64U) * 8U;
    struct timespec dl = { 0, 0 };
    long rc;
    int i;
    int ret;
    int e;

    if (nfds > FD_SETSIZE) {
        return -EINVAL;
    }
    for (i = 0; i < 3; i++) {
        uint64_t k;

        FD_ZERO(&orig[i]);
        if (va[i] == 0U) {
            continue;
        }
        rc = poll_rd(mem, va[i], buf, nbytes);
        if (rc != 0) {
            return rc;
        }
        for (k = 0U; k < nfds; k++) {
            if (((l2a_get_be64(buf + (k / 64U) * 8U) >> (k % 64U)) & 1U) != 0U) {
                FD_SET((int)k, &orig[i]);
            }
        }
    }
    if (ts != NULL) {
        poll_deadline(ts, &dl);
    }
    for (;;) {
        struct timespec left;

        if (ts != NULL) {
            poll_remaining(&dl, &left);
        }
        memcpy(sets, orig, sizeof sets);
        sparc64_thread_big_unlock();
        ret = pselect((int)nfds, va[0] ? &sets[0] : NULL,
                      va[1] ? &sets[1] : NULL, va[2] ? &sets[2] : NULL,
                      ts != NULL ? &left : NULL, sm);
        e = errno;
        sparc64_thread_big_lock();
        if (ret >= 0 || e != EINTR || poll_interrupted(ctx)) {
            break;
        }
    }
    if (ret < 0) {
        return -(long)e;
    }
    for (i = 0; i < 3; i++) {
        uint64_t k;

        if (va[i] == 0U) {
            continue;
        }
        memset(buf, 0, sizeof buf);
        for (k = 0U; k < nfds; k++) {
            if (FD_ISSET((int)k, &sets[i])) {
                uint8_t *wp = buf + (k / 64U) * 8U;

                l2a_put_be64(wp, l2a_get_be64(wp) | ((uint64_t)1U << (k % 64U)));
            }
        }
        rc = l2a_store_buf(mem, va[i], buf, nbytes);
        if (rc != 0) {
            return rc;
        }
    }
    return ret;
}

long sparc64_fs_select(const sparc64_ctx_t *ctx, memp_t mem, uint64_t nfds,
                       uint64_t r, uint64_t w, uint64_t x, uint64_t tva)
{
    uint64_t va[3];
    struct timespec ts;
    int has_ts;
    long rc = poll_timeout(mem, tva, 1, &ts, &has_ts);

    va[0] = r;
    va[1] = w;
    va[2] = x;
    return rc != 0 ? rc : select_core(ctx, mem, nfds, va,
                                      has_ts ? &ts : NULL, NULL);
}

long sparc64_fs_pselect6(const sparc64_ctx_t *ctx, memp_t mem, uint64_t nfds,
                         uint64_t r, uint64_t w, uint64_t x, uint64_t tva,
                         uint64_t sigarg)
{
    uint64_t va[3];
    uint8_t pair[16];
    struct timespec ts;
    sigset_t sm;
    uint64_t temp = 0U;
    uint64_t prev;
    int has_ts;
    int has_sm = 0;
    long rc = poll_timeout(mem, tva, 0, &ts, &has_ts);

    if (rc != 0) {
        return rc;
    }
    if (sigarg != 0U) {
        rc = poll_rd(mem, sigarg, pair, sizeof pair);
        if (rc == 0) {
            rc = poll_sigmask(mem, l2a_get_be64(pair),
                              l2a_get_be64(pair + 8), &sm, &has_sm, &temp);
        }
        if (rc != 0) {
            return rc;
        }
    }
    va[0] = r;
    va[1] = w;
    va[2] = x;
    if (!has_sm) {
        return select_core(ctx, mem, nfds, va, has_ts ? &ts : NULL, NULL);
    }
    prev = poll_mask_enter(ctx, temp);
    rc = poll_interrupted(ctx) ? -EINTR
                               : select_core(ctx, mem, nfds, va,
                                             has_ts ? &ts : NULL, &sm);
    poll_mask_leave(ctx, prev);
    return rc;
}

long sparc64_fs_nanosleep(const sparc64_ctx_t *ctx, memp_t mem, uint64_t req,
                          uint64_t rem)
{
    uint8_t g[16];
    struct timespec rq;
    struct timespec rm;
    long rc = poll_rd(mem, req, g, sizeof g);
    int r;
    int e;

    if (rc != 0) {
        return rc;
    }
    rq.tv_sec = (time_t)l2a_get_be64(g);
    rq.tv_nsec = (long)l2a_get_be64(g + 8);
    if (rq.tv_sec < 0 || rq.tv_nsec < 0 || rq.tv_nsec >= 1000000000L) {
        return -EINVAL;
    }
    for (;;) {
        sparc64_thread_big_unlock();
        r = nanosleep(&rq, &rm);
        e = errno;
        sparc64_thread_big_lock();
        if (r == 0 || e != EINTR || poll_interrupted(ctx)) {
            break;
        }
        rq = rm; /* internal interruption: sleep out the remainder */
    }
    if (r != 0 && e == EINTR && rem != 0U) {
        l2a_put_be64(g, (uint64_t)rm.tv_sec);
        l2a_put_be64(g + 8, (uint64_t)rm.tv_nsec);
        (void)l2a_store_buf(mem, rem, g, sizeof g);
    }
    return r != 0 ? -(long)e : 0L;
}

long sparc64_fs_flock(const sparc64_ctx_t *ctx, uint64_t fd, uint64_t op)
{
    int hop = (int)(int32_t)op;
    int blocking = (hop & POLL_LOCK_FLOCK_NB) == 0 &&
                   (hop & 0xf) != POLL_LOCK_FLOCK_UN;
    int r;
    int e;

    for (;;) {
        if (blocking) {
            sparc64_thread_big_unlock();
        }
        r = flock((int)(int32_t)fd, hop);
        e = errno;
        if (blocking) {
            sparc64_thread_big_lock();
        }
        if (r == 0) {
            return 0;
        }
        if (!blocking || e != EINTR || poll_interrupted(ctx)) {
            return -(long)e;
        }
    }
}

/* Host fcntl for a record lock; the blocking forms drop the big lock
 * and retry internal EINTR. */
static long lock_call(const sparc64_ctx_t *ctx, int fd, int hcmd,
                      struct flock *fl, int blocking)
{
    int r;
    int e;

    for (;;) {
        if (blocking) {
            sparc64_thread_big_unlock();
        }
        r = fcntl(fd, hcmd, fl);
        e = errno;
        if (blocking) {
            sparc64_thread_big_lock();
        }
        if (r == 0) {
            return 0;
        }
        if (!blocking || e != EINTR || poll_interrupted(ctx)) {
            return -(long)e;
        }
    }
}

/* Guest struct flock is 32 bytes: s16 type, s16 whence, s64 start,
 * s64 len, s32 pid; lock types RDLCK 1, WRLCK 2, UNLCK 3. Translated
 * to the host struct flock, whose type constants differ per host. */
long sparc64_fs_fcntl_lock(const sparc64_ctx_t *ctx, memp_t mem, uint64_t fd,
                           uint64_t cmd, uint64_t arg)
{
    uint8_t g[32];
    struct flock fl;
    int hcmd;
    int is_get;
    int blocking;
    int16_t t;
    long rc;

    switch (cmd) {
    case 7U: hcmd = F_GETLK; break;
    case 8U: hcmd = F_SETLK; break;
    case 9U: hcmd = F_SETLKW; break;
#if defined(F_OFD_GETLK) && defined(F_OFD_SETLK) && defined(F_OFD_SETLKW)
    case 36U: hcmd = F_OFD_GETLK; break;
    case 37U: hcmd = F_OFD_SETLK; break;
    case 38U: hcmd = F_OFD_SETLKW; break;
#endif
    default: return -EINVAL;
    }
    is_get = cmd == 7U || cmd == 36U;
    blocking = cmd == 9U || cmd == 38U;
    rc = poll_rd(mem, arg, g, sizeof g);
    if (rc != 0) {
        return rc;
    }
    memset(&fl, 0, sizeof fl);
    t = (int16_t)(((unsigned)g[0] << 8) | g[1]);
    fl.l_type = t == 1 ? F_RDLCK : (t == 2 ? F_WRLCK : F_UNLCK);
    fl.l_whence = (short)(((unsigned)g[2] << 8) | g[3]);
    fl.l_start = (off_t)l2a_get_be64(g + 8);
    fl.l_len = (off_t)l2a_get_be64(g + 16);
    /* OFD locks require l_pid == 0; the host enforces it. */
    fl.l_pid = (pid_t)(int32_t)l2a_get_be32(g + 24);
    rc = lock_call(ctx, (int)(int32_t)fd, hcmd, &fl, blocking);
    if (rc != 0) {
        return rc;
    }
    if (is_get) {
        memset(g, 0, sizeof g);
        t = fl.l_type == F_RDLCK ? 1 : (fl.l_type == F_WRLCK ? 2 : 3);
        g[0] = (uint8_t)((unsigned)t >> 8);
        g[1] = (uint8_t)t;
        g[3] = (uint8_t)fl.l_whence;
        l2a_put_be64(g + 8, (uint64_t)fl.l_start);
        l2a_put_be64(g + 16, (uint64_t)fl.l_len);
        l2a_put_be32(g + 24, (uint32_t)fl.l_pid);
        return l2a_store_buf(mem, arg, g, sizeof g);
    }
    return 0;
}
