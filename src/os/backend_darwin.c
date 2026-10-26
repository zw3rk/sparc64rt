/*
 * src/os/backend_darwin.c -- Standalone macOS arm64 host backend (Lane M3)
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 * Backend 2 (UNIFICATION-PLAN Rev 4 section 6): native macOS Mach-O, no
 * Hypervisor.framework. MAP_JIT + pthread_jit_write_protect_np for W^X;
 * kevent on {target_fd, wake_pipe_rd} before non-blocking I/O;
 * __ulock_wait / ULF_WAKE_ALL futexes; pthread_kill SIGUSR2 preemption
 * via an id->pthread_t table. All linux_* inputs are Linux UAPI values,
 * translated below (open flags, AF_/SOL_/SO_, signals, AT_*). No Darwin
 * equivalent -> fail closed with -38 (-ENOSYS).
 */
#if defined(__APPLE__) && defined(__aarch64__)
#include "os/backend.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/event.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/random.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
/* Absent from the macOS SDK; stable libSystem ABI (link+run probed). */
extern int __ulock_wait(uint32_t operation, void *addr, uint64_t value, uint32_t timeout_us);
extern int __ulock_wake(uint32_t operation, void *addr, uint64_t wake_value);
extern void pthread_jit_write_protect_np(int enabled);
#define RT_UL_COMPARE_AND_WAIT 1u
#define RT_ULF_WAKE_ALL 0x100u
static int64_t neg_errno(void) { return -(int64_t)errno; }
static int64_t libret(long r) { return r < 0L ? neg_errno() : (int64_t)r; }
/* ---- Linux UAPI -> Darwin translation (values verified on host) ---- */
#define RT_LINUX_AT_FDCWD (-100)
#define RT_LINUX_AT_SYMLINK_NOFOLLOW 0x100
static int darwin_dirfd(int d) { return d == RT_LINUX_AT_FDCWD ? AT_FDCWD : d; }
static int darwin_atflag(int f) {
    if ((f & ~RT_LINUX_AT_SYMLINK_NOFOLLOW) != 0) { return -1; }
    return (f & RT_LINUX_AT_SYMLINK_NOFOLLOW) != 0 ? AT_SYMLINK_NOFOLLOW : 0;
}
/* Linux open(2) bits (octal, aarch64 UAPI) -> Darwin. Unknown bits fail
 * closed; dropped bits (DSYNC/DIRECT/LARGEFILE/NOCTTY) are APFS no-ops. */
static int darwin_open_flags(int lf, int *out) {
    static const int known = 03 | 0100 | 0200 | 0400 | 01000 | 02000 | 04000 | 0100000 | 04010000 | 00040000 | 00100000 | 00200000 | 00400000 | 02000000;
    int df;
    if ((lf & ~known) != 0) { return -22; }
    df = lf & 03;
    if ((lf & 0100) != 0) { df |= O_CREAT; }
    if ((lf & 0200) != 0) { df |= O_EXCL; }
    if ((lf & 01000) != 0) { df |= O_TRUNC; }
    if ((lf & 02000) != 0) { df |= O_APPEND; }
    if ((lf & 04000) != 0) { df |= O_NONBLOCK; }
    if ((lf & 04010000) != 0) { df |= O_SYNC; }
    if ((lf & 00400000) != 0) { df |= O_NOFOLLOW; }
    if ((lf & 00200000) != 0) { df |= O_DIRECTORY; }
    if ((lf & 02000000) != 0) { df |= O_CLOEXEC; }
    *out = df; return 0;
}
static int darwin_domain(int d) {
    switch (d) { case 1: return AF_UNIX; case 2: return AF_INET; case 10: return AF_INET6; default: return -1; }
}
static int darwin_socktype(int t, int *cloexec, int *nonblock) { /* strip SOCK_CLOEXEC/SOCK_NONBLOCK */
    int s = t & ~(02000000 | 04000);
    *cloexec = (t & 02000000) != 0 ? 1 : 0; *nonblock = (t & 04000) != 0 ? 1 : 0;
    return (s == 1 || s == 2 || s == 3) ? s : -1;
}
static void darwin_flag_fd(int fd, int cloexec, int nonblock) {
    int f;
    if (cloexec) { f = fcntl(fd, F_GETFD); if (f >= 0) { (void)fcntl(fd, F_SETFD, f | FD_CLOEXEC); } }
    if (nonblock) { f = fcntl(fd, F_GETFL); if (f >= 0) { (void)fcntl(fd, F_SETFL, f | O_NONBLOCK); } }
}
static int darwin_socklevel(int l) { return l == 1 ? SOL_SOCKET : l; }
static int darwin_sockopt(int l, int o) {
    static const int lin[] = { 2, 9, 6, 7, 8, 20, 21, 4, 3, 13 };
    static const int dar[] = { 4, 8, 0x20, 0x1001, 0x1002, 0x1006, 0x1005, 0x1007, 0x1008, 0x80 };
    unsigned i;
    if (l != 1) { return o; }
    for (i = 0u; i < 10u; i++) { if (lin[i] == o) { return dar[i]; } }
    return o;
}
/* Signal numbers diverge (7=BUS vs 10, 10=USR1 vs 30, 12=USR2 vs 31, 17=CHLD vs 20, 18/19/20 vs 19/17/18, 23 vs 16, 29 vs 23, 31 vs 12). */
static int darwin_signo(int linux_sig) {
    static const int lin[] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 31 };
    static const int dar[] = { 1, 2, 3, 4, 5, 6, 10, 8, 9, 30, 11, 31, 13, 14, 15, 7, 20, 19, 17, 18, 21, 22, 16, 24, 25, 26, 27, 28, 23, 12 };
    unsigned i;
    for (i = 0u; i < 30u; i++) { if (lin[i] == linux_sig) { return dar[i]; } }
    return -22;
}
static int linux_signo(int dar_sig) {
    static const int dar[] = { 1, 2, 3, 4, 5, 6, 10, 8, 9, 30, 11, 31, 13, 14, 15, 7, 20, 19, 17, 18, 21, 22, 16, 24, 25, 26, 27, 28, 23, 12 };
    static const int lin[] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 31 };
    unsigned i;
    for (i = 0u; i < 30u; i++) { if (dar[i] == dar_sig) { return lin[i]; } }
    return dar_sig;
}
/* ---- kevent readiness (plan section 6.4a) ---- */
static int darwin_wait_fd(int fd, int want_write, rt_worker_sync_t *ws, uint32_t expected_seq) {
    struct kevent changes[2], events[2];
    int n = 1, kq, r, i;
    if (ws != NULL && atomic_load_explicit(&ws->sig_seq, memory_order_acquire) != expected_seq) { return -4; }
    kq = kqueue();
    if (kq < 0) { return -(int)errno; }
    EV_SET(&changes[0], (uintptr_t)fd, want_write ? EVFILT_WRITE : EVFILT_READ, EV_ADD | EV_ENABLE, 0, 0, NULL);
    if (ws != NULL && ws->wake_pipe_rd >= 0) {
        EV_SET(&changes[1], (uintptr_t)ws->wake_pipe_rd, EVFILT_READ, EV_ADD | EV_ENABLE, 0, 0, NULL); n = 2;
    }
    if (kevent(kq, changes, n, NULL, 0, NULL) != 0) { int e = errno; (void)close(kq); return -e; }
    for (;;) {
        int fd_ready = 0;
        r = kevent(kq, NULL, 0, events, 2, NULL);
        if (r < 0) { if (errno == EINTR) { continue; } { int e = errno; (void)close(kq); return -e; } }
        for (i = 0; i < r; i++) {
            if ((int)events[i].ident == fd) { fd_ready = 1; }
            else if (ws != NULL) { char tmp[32]; (void)read(ws->wake_pipe_rd, tmp, sizeof(tmp)); (void)close(kq); return -4; }
        }
        if (fd_ready) { (void)close(kq); return 0; }
        if (ws != NULL && atomic_load_explicit(&ws->sig_seq, memory_order_acquire) != expected_seq) { (void)close(kq); return -4; }
    }
}
struct darwin_fdop { int fd, flags, kind; void *buf; size_t len; const void *addr; uint32_t addrlen; uint32_t *addrlenp; };
#define RT_FDOP_READ 0
#define RT_FDOP_WRITE 1
#define RT_FDOP_READV 2
#define RT_FDOP_WRITEV 3
#define RT_FDOP_CONNECT 4
#define RT_FDOP_ACCEPT 5
#define RT_FDOP_SENDTO 6
#define RT_FDOP_RECVFROM 7
static void darwin_nonblock(int fd) {
    int f = fcntl(fd, F_GETFL);
    if (f >= 0 && (f & O_NONBLOCK) == 0) { (void)fcntl(fd, F_SETFL, f | O_NONBLOCK); }
}
static int64_t darwin_do_fdop(void *p) {
    struct darwin_fdop *a = (struct darwin_fdop *)p;
    switch (a->kind) {
    case RT_FDOP_READ: return libret(read(a->fd, a->buf, a->len));
    case RT_FDOP_WRITE: return libret(write(a->fd, a->buf, a->len));
    case RT_FDOP_READV: return libret(readv(a->fd, (struct iovec *)a->buf, (int)a->len));
    case RT_FDOP_WRITEV: return libret(writev(a->fd, a->addr, (int)a->len));
    case RT_FDOP_CONNECT: {
        int r;
        darwin_nonblock(a->fd);
        r = connect(a->fd, (const struct sockaddr *)a->addr, (socklen_t)a->addrlen);
        if (r == 0 || errno == EISCONN) { return 0; }
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINPROGRESS || errno == EALREADY) { return -35; }
        return neg_errno();
    }
    case RT_FDOP_ACCEPT: {
        int f = accept(a->fd, (struct sockaddr *)a->addr, (socklen_t *)a->addrlenp);
        if (f < 0) { if (errno == EAGAIN || errno == EWOULDBLOCK) { return -35; } return neg_errno(); }
        darwin_nonblock(a->fd); return (int64_t)f;
    }
    case RT_FDOP_SENDTO:
        return libret(sendto(a->fd, a->buf, a->len, a->flags, (const struct sockaddr *)a->addr, (socklen_t)a->addrlen));
    default:
        return libret(recvfrom(a->fd, a->buf, a->len, a->flags, (struct sockaddr *)a->addr, (socklen_t *)a->addrlenp));
    }
}
static int64_t darwin_spin_fd(int fd, int want_write, rt_worker_sync_t *ws, uint32_t expected_seq, struct darwin_fdop *a) {
    for (;;) { int64_t r = darwin_do_fdop(a); int w; if (r != -35) { return r; } w = darwin_wait_fd(fd, want_write, ws, expected_seq); if (w != 0) { return (int64_t)w; } }
}
/* ---- worker table (preempt without tid signals) ---- */
#define RT_DARWIN_WORKERS 256u
static struct { pthread_mutex_t mu; int init; uint64_t ids[RT_DARWIN_WORKERS]; pthread_t ths[RT_DARWIN_WORKERS]; } g_workers;
static void workers_lock(void) {
    if (!g_workers.init) { (void)pthread_mutex_init(&g_workers.mu, NULL); g_workers.init = 1; }
    (void)pthread_mutex_lock(&g_workers.mu);
}
static void darwin_worker_register(uint64_t id, pthread_t th) {
    unsigned i; workers_lock();
    for (i = 0u; i < RT_DARWIN_WORKERS; i++) { if (g_workers.ids[i] == 0u) { g_workers.ids[i] = id; g_workers.ths[i] = th; break; } }
    (void)pthread_mutex_unlock(&g_workers.mu);
}
static int darwin_worker_find(uint64_t id, pthread_t *out) {
    unsigned i; int found = 0; workers_lock();
    for (i = 0u; i < RT_DARWIN_WORKERS; i++) { if (g_workers.ids[i] == id) { *out = g_workers.ths[i]; found = 1; break; } }
    (void)pthread_mutex_unlock(&g_workers.mu); return found;
}
/* 1. identity */
rt_backend_kind_t rt_host_backend_kind(void) { return RT_BACKEND_DARWIN; }
int rt_host_is_hyper_linux(void) { return 0; }
size_t rt_host_page_size(void) {
    static long cached = 0L; long v;
    if (cached != 0L) { return (size_t)cached; }
    v = sysconf(_SC_PAGESIZE); cached = v <= 0L ? 16384L : v; return (size_t)cached;
}
/* 2. memory */
int rt_host_map_anon(void *hint_addr, size_t len, int linux_prot, int fixed, int noreplace, void **out_host_addr) {
    int flags = MAP_PRIVATE | MAP_ANONYMOUS; void *p;
    if (len == 0U || out_host_addr == NULL) { return -22; }
    if (fixed) { flags |= MAP_FIXED; }
    if (noreplace && !fixed) { /* No MAP_FIXED_NOREPLACE: best-effort mincore probe (racy). */
        size_t off, ps = rt_host_page_size();
        for (off = 0u; off < len; off += ps) { char vec = 0; if (mincore((char *)hint_addr + off, ps, &vec) == 0) { return -17; } }
        flags |= MAP_FIXED;
    }
    p = mmap(hint_addr, len, linux_prot, flags, -1, 0);
    if (p == MAP_FAILED) { return -(int)errno; }
    *out_host_addr = p; return 0;
}
int rt_host_map_file(void *hint_addr, size_t len, int linux_prot, int shared, int fixed, int host_fd, uint64_t aligned_file_offset, void **out_host_addr) {
    int flags = shared ? MAP_SHARED : MAP_PRIVATE; void *p;
    if (len == 0U || out_host_addr == NULL || host_fd < 0) { return -22; }
    if (fixed) { flags |= MAP_FIXED; }
    p = mmap(hint_addr, len, linux_prot, flags, host_fd, (off_t)aligned_file_offset);
    if (p == MAP_FAILED) { return -(int)errno; }
    *out_host_addr = p; return 0;
}
int rt_host_create_shared_mem(const char *name, size_t size, int *out_host_fd) {
    char shm_name[64]; size_t i = 0u, o = 0u; int fd; /* shm_open names share one flat namespace; prefix ours. */
    static const char prefix[] = "/rt.";
    if (name == NULL || out_host_fd == NULL) { return -22; }
    for (i = 0u; prefix[i] != '\0' && o + 1u < sizeof(shm_name); i++) { shm_name[o++] = prefix[i]; }
    for (i = 0u; name[i] != '\0' && o + 1u < sizeof(shm_name); i++) { shm_name[o++] = name[i] == '/' ? '.' : name[i]; }
    shm_name[o] = '\0';
    fd = shm_open(shm_name, O_RDWR | O_CREAT | O_EXCL, 0600);
    if (fd < 0 && errno == EEXIST) { fd = shm_open(shm_name, O_RDWR, 0600); }
    if (fd < 0) { return -(int)errno; }
    if (size != 0U && ftruncate(fd, (off_t)size) != 0) { int e = errno; (void)close(fd); return -e; }
    *out_host_fd = fd; return 0;
}
int rt_host_protect(void *host_addr, size_t len, int linux_prot) { return mprotect(host_addr, len, linux_prot) != 0 ? -(int)errno : 0; }
int rt_host_unmap(void *host_addr, size_t len) { return munmap(host_addr, len) != 0 ? -(int)errno : 0; }
int rt_host_msync(void *host_addr, size_t len, int linux_flags) { return msync(host_addr, len, linux_flags) != 0 ? -(int)errno : 0; }
int rt_host_madvise(void *host_addr, size_t len, int linux_advice) { return madvise(host_addr, len, linux_advice) != 0 ? -(int)errno : 0; }
/* 3. JIT W^X */
void *rt_host_jit_alloc(size_t size) {
    void *p;
    if (size == 0U) { return NULL; }
    p = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_JIT, -1, 0);
    if (p == MAP_FAILED) { return NULL; }
    pthread_jit_write_protect_np(1); return p;
}
void rt_host_jit_thread_init(void) { pthread_jit_write_protect_np(1); }
void rt_host_jit_begin_write(void *buf, size_t size) { (void)size; if (buf == NULL) { return; } pthread_jit_write_protect_np(0); }
int rt_host_jit_seal_rx(void *buf, size_t size) {
    if (buf == NULL || size == 0U) { return -22; }
    __builtin___clear_cache((char *)buf, (char *)buf + size);
    pthread_jit_write_protect_np(1);
    return mprotect(buf, size, PROT_READ | PROT_EXEC) != 0 ? -(int)errno : 0;
}
void rt_host_jit_free(void *buf, size_t size) { if (buf == NULL || size == 0U) { return; } (void)munmap(buf, size); }
/* 4. worker sync + preemption */
int rt_host_worker_sync_init(rt_worker_sync_t *ws) {
    int fds[2]; uint64_t tid = 0u;
    if (ws == NULL) { return -22; }
    atomic_init(&ws->sig_seq, 0u); atomic_init(&ws->in_commit_window, 0u); atomic_init(&ws->ulock_wait_addr, (uintptr_t)0);
    ws->kqueue_fd = kqueue(); ws->wake_pipe_rd = -1; ws->wake_pipe_wr = -1;
    (void)pthread_threadid_np(NULL, &tid); ws->host_tid = tid;
    if (pipe(fds) != 0) { if (ws->kqueue_fd >= 0) { (void)close(ws->kqueue_fd); ws->kqueue_fd = -1; } return -(int)errno; }
    (void)fcntl(fds[0], F_SETFD, FD_CLOEXEC); (void)fcntl(fds[1], F_SETFD, FD_CLOEXEC);
    (void)fcntl(fds[0], F_SETFL, O_NONBLOCK); (void)fcntl(fds[1], F_SETFL, O_NONBLOCK);
    ws->wake_pipe_rd = fds[0]; ws->wake_pipe_wr = fds[1]; return 0;
}
void rt_host_worker_sync_destroy(rt_worker_sync_t *ws) {
    if (ws == NULL) { return; }
    if (ws->kqueue_fd >= 0) { (void)close(ws->kqueue_fd); }
    if (ws->wake_pipe_rd >= 0) { (void)close(ws->wake_pipe_rd); }
    if (ws->wake_pipe_wr >= 0) { (void)close(ws->wake_pipe_wr); }
    ws->kqueue_fd = -1; ws->wake_pipe_rd = -1; ws->wake_pipe_wr = -1;
}
void rt_host_worker_notify_signal(rt_worker_sync_t *ws) {
    static const char one = 'x';
    if (ws == NULL || ws->wake_pipe_wr < 0) { return; }
    atomic_fetch_add_explicit(&ws->sig_seq, 1u, memory_order_release);
    (void)write(ws->wake_pipe_wr, &one, 1u);
}
int rt_host_preempt_worker(uint64_t host_tid) {
    pthread_t th;
    int r;
    if (!darwin_worker_find(host_tid, &th)) { return -3; }
    r = pthread_kill(th, SIGUSR2);
    if (r == 0) { return 0; }
    /* ETIMEDOUT means the (detached) thread already exited: parking is
     * vacuous, report success. Observed on macOS for dead threads. */
    if (r == ETIMEDOUT) { return 0; }
    return -r;
}
uint64_t rt_host_register_self(void) {
    /* pthread_threadid_np value doubles as the worker-table key;
     * register self so preemption can find this thread. */
    uint64_t tid = 0u;
    (void)pthread_threadid_np(NULL, &tid);
    if (tid != 0u) {
        darwin_worker_register(tid, pthread_self());
    }
    return tid;
}
/* 5. filesystem */
int64_t rt_host_openat(int dirfd, const char *path, int linux_flags, uint32_t mode, rt_worker_sync_t *ws, uint32_t expected_seq) {
    struct stat st; int df, was_nonblock, f; int64_t r;
    if (path == NULL) { return -22; }
    if (darwin_open_flags(linux_flags, &df) != 0) { return -22; }
    was_nonblock = (df & O_NONBLOCK) != 0 ? 1 : 0; df |= O_NONBLOCK; /* FIFOs without a peer park on kevent below. */
    r = libret(openat(darwin_dirfd(dirfd), path, df, (mode_t)mode));
    if (r < 0) { return r; }
    if (!was_nonblock) {
        if (fstat((int)r, &st) == 0 && S_ISFIFO(st.st_mode)) { int w = darwin_wait_fd((int)r, 0, ws, expected_seq); if (w != 0) { (void)close((int)r); return (int64_t)w; } }
        f = fcntl((int)r, F_GETFL); if (f >= 0) { (void)fcntl((int)r, F_SETFL, f & ~O_NONBLOCK); }
    }
    return r;
}
int64_t rt_host_close(int fd) { return libret(close(fd)); }
int64_t rt_host_read(int fd, void *buf, size_t count, rt_worker_sync_t *ws, uint32_t expected_seq) {
    struct darwin_fdop a = { fd, 0, RT_FDOP_READ, buf, count, NULL, 0u, NULL };
    return darwin_spin_fd(fd, 0, ws, expected_seq, &a);
}
int64_t rt_host_write(int fd, const void *buf, size_t count, rt_worker_sync_t *ws, uint32_t expected_seq) {
    struct darwin_fdop a = { fd, 0, RT_FDOP_WRITE, (void *)buf, count, NULL, 0u, NULL };
    return darwin_spin_fd(fd, 1, ws, expected_seq, &a);
}
int64_t rt_host_pread64(int fd, void *buf, size_t count, int64_t offset) { return libret(pread(fd, buf, count, (off_t)offset)); }
int64_t rt_host_pwrite64(int fd, const void *buf, size_t count, int64_t offset) { return libret(pwrite(fd, buf, count, (off_t)offset)); }
int64_t rt_host_readv(int fd, const struct iovec *iov, int iovcnt, rt_worker_sync_t *ws, uint32_t expected_seq) {
    struct darwin_fdop a = { fd, 0, RT_FDOP_READV, (void *)iov, (size_t)iovcnt, NULL, 0u, NULL };
    return darwin_spin_fd(fd, 0, ws, expected_seq, &a);
}
int64_t rt_host_writev(int fd, const struct iovec *iov, int iovcnt, rt_worker_sync_t *ws, uint32_t expected_seq) {
    struct darwin_fdop a = { fd, 0, RT_FDOP_WRITEV, NULL, (size_t)iovcnt, (const void *)iov, 0u, NULL };
    return darwin_spin_fd(fd, 1, ws, expected_seq, &a);
}
int64_t rt_host_lseek(int fd, int64_t offset, int linux_whence) { return libret(lseek(fd, (off_t)offset, linux_whence)); }
/* Linux struct statx stable prefix: 128 bytes through stx_dev_minor; the 256-byte caller buffer tail is zeroed. */
struct rt_linux_statx {
    uint32_t stx_mask, stx_blksize; uint64_t stx_attributes; uint32_t stx_nlink, stx_uid, stx_gid;
    uint16_t stx_mode, pad0; uint64_t stx_ino, stx_size, stx_blocks, stx_attributes_mask;
    int64_t atime_sec, mtime_sec, ctime_sec; uint32_t atime_nsec; int32_t atime_pad;
    uint32_t mtime_nsec; int32_t mtime_pad; uint32_t ctime_nsec; int32_t ctime_pad;
    uint32_t stx_rdev_major, stx_rdev_minor, stx_dev_major, stx_dev_minor;
};
#define RT_LINUX_STATX_SIZE 256u
#define RT_STATX_BASIC_STATS 0x7ffu
int64_t rt_host_fstatat(int dirfd, const char *path, void *linux_statx_out, int linux_flags) {
    struct rt_linux_statx *stx; struct stat st; int at;
    if (path == NULL || linux_statx_out == NULL) { return -22; }
    at = darwin_atflag(linux_flags); if (at < 0) { return -22; }
    if (fstatat(darwin_dirfd(dirfd), path, &st, at) != 0) { return neg_errno(); }
    (void)memset(linux_statx_out, 0, RT_LINUX_STATX_SIZE); stx = (struct rt_linux_statx *)linux_statx_out;
    stx->stx_mask = RT_STATX_BASIC_STATS; stx->stx_blksize = (uint32_t)st.st_blksize;
    stx->stx_nlink = (uint32_t)st.st_nlink; stx->stx_uid = (uint32_t)st.st_uid; stx->stx_gid = (uint32_t)st.st_gid;
    stx->stx_mode = (uint16_t)st.st_mode; stx->stx_ino = (uint64_t)st.st_ino;
    stx->stx_size = (uint64_t)st.st_size; stx->stx_blocks = (uint64_t)st.st_blocks;
    stx->atime_sec = (int64_t)st.st_atimespec.tv_sec; stx->atime_nsec = (uint32_t)st.st_atimespec.tv_nsec;
    stx->mtime_sec = (int64_t)st.st_mtimespec.tv_sec; stx->mtime_nsec = (uint32_t)st.st_mtimespec.tv_nsec;
    stx->ctime_sec = (int64_t)st.st_ctimespec.tv_sec; stx->ctime_nsec = (uint32_t)st.st_ctimespec.tv_nsec;
    stx->stx_dev_major = (uint32_t)(((uint64_t)st.st_dev >> 24) & 0xffffffffULL);
    stx->stx_dev_minor = (uint32_t)((uint64_t)st.st_dev & 0xffffffULL);
    return 0;
}
int64_t rt_host_ftruncate(int fd, int64_t length) { return libret(ftruncate(fd, (off_t)length)); }
int64_t rt_host_fallocate(int fd, int mode, int64_t offset, int64_t len) {
    fstore_t store;
    if (mode != 0) { return -38; } /* PUNCH_HOLE has no APFS equivalent. */
    store.fst_flags = (u_int32_t)0; store.fst_posmode = F_PEOFPOSMODE; store.fst_offset = 0;
    store.fst_length = (off_t)(offset + len); store.fst_bytesalloc = 0;
    (void)fcntl(fd, F_PREALLOCATE, &store);
    return libret(ftruncate(fd, (off_t)(offset + len)));
}
static int64_t darwin_copy_loop(int fd_in, int64_t *inout_in, int fd_out, int64_t out_base, int is_sendfile, size_t len) {
    static const size_t chunk = 65536u; char *buf = (char *)malloc(chunk);
    size_t left = len; int64_t in_off, done = 0;
    if (buf == NULL) { return -12; }
    if (inout_in == NULL) { free(buf); return -22; }
    in_off = *inout_in;
    while (left != 0u) {
        size_t want = left < chunk ? left : chunk, woff = 0u; ssize_t r = pread(fd_in, buf, want, (off_t)in_off);
        if (r < 0) { int e = errno; free(buf); *inout_in = in_off; return done != 0 ? done : -(int64_t)e; }
        if (r == 0) { break; }
        while (woff < (size_t)r) {
            ssize_t w = is_sendfile ? write(fd_out, buf + woff, (size_t)r - woff) : pwrite(fd_out, buf + woff, (size_t)r - woff, (off_t)(out_base + done + (int64_t)woff));
            if (w < 0) { int e = errno; free(buf); *inout_in = in_off; return done != 0 ? done : -(int64_t)e; }
            woff += (size_t)w;
        }
        in_off += r; done += r; left -= (size_t)r;
    }
    free(buf); *inout_in = in_off; return done;
}
int64_t rt_host_sendfile(int out_fd, int in_fd, int64_t *offset, size_t count) {
    if (offset == NULL) { return -22; } /* Darwin sendfile is socket-only; copy loop. */
    return darwin_copy_loop(in_fd, offset, out_fd, 0, 1, count);
}
int64_t rt_host_copy_file_range(int fd_in, int64_t *off_in, int fd_out, int64_t *off_out, size_t len, unsigned int flags) {
    int64_t save_out, r;
    if (off_in == NULL || off_out == NULL || flags != 0u) { return -22; }
    save_out = *off_out; r = darwin_copy_loop(fd_in, off_in, fd_out, save_out, 0, len);
    if (r >= 0) { *off_out = save_out + r; return r; }
    return r;
}
int64_t rt_host_fsync(int fd, int datasync_only) {
    (void)datasync_only;
    return fcntl(fd, F_FULLFSYNC) != 0 ? libret(fsync(fd)) : 0;
}
struct rt_linux_dirent64 { uint64_t d_ino; int64_t d_off; uint16_t d_reclen; uint8_t d_type; char d_name[]; }; /* packed, 8B-aligned records */
int64_t rt_host_getdents64(int fd, void *linux_dirent64_buf, size_t buf_size) {
    char *out = (char *)linux_dirent64_buf; size_t used = 0u; int dupfd; DIR *dir; struct dirent *de;
    if (out == NULL || buf_size == 0U) { return -22; }
    dupfd = dup(fd); /* shares the file offset, like getdents64 */
    if (dupfd < 0) { return neg_errno(); }
    dir = fdopendir(dupfd);
    if (dir == NULL) { int e = errno; (void)close(dupfd); return -(int64_t)e; }
    while ((de = readdir(dir)) != NULL) {
        struct rt_linux_dirent64 *rec; size_t namlen = 0u, reclen, i;
        while (de->d_name[namlen] != '\0') { namlen++; }
        reclen = (size_t)((19u + namlen + 1u + 7u) & ~7u);
        if (used + reclen > buf_size) { break; }
        rec = (struct rt_linux_dirent64 *)(out + used);
        rec->d_ino = (uint64_t)de->d_ino; rec->d_off = (int64_t)telldir(dir);
        rec->d_reclen = (uint16_t)reclen; rec->d_type = de->d_type;
        for (i = 0u; i <= namlen; i++) { rec->d_name[i] = de->d_name[i]; }
        for (i = namlen + 1u; i < reclen - 19u; i++) { rec->d_name[i] = '\0'; }
        used += reclen;
    }
    (void)closedir(dir);
    return used == 0u ? 0 : (int64_t)used;
}
int64_t rt_host_fcntl(int fd, int linux_cmd, uint64_t arg) {
    if (linux_cmd == 1030) { /* F_DUPFD_CLOEXEC (Darwin value is 67, contract is Linux). */
        long r = fcntl(fd, F_DUPFD, (int)arg);
        if (r < 0) { return neg_errno(); }
        (void)fcntl((int)r, F_SETFD, FD_CLOEXEC); return r;
    }
    if (linux_cmd < 0 || linux_cmd > 4) { return -22; }
    return libret(fcntl(fd, linux_cmd, (int)arg));
}
int64_t rt_host_ioctl(int fd, uint64_t linux_req, void *arg) { return libret(ioctl(fd, (unsigned long)linux_req, arg)); }
int64_t rt_host_dup(int oldfd) { return libret(dup(oldfd)); }
int64_t rt_host_dup3(int oldfd, int newfd, int linux_flags) {
    int r;
    if ((linux_flags & ~02000000) != 0) { return -22; }
    r = dup2(oldfd, newfd); if (r < 0) { return neg_errno(); }
    if ((linux_flags & 02000000) != 0) { (void)fcntl(r, F_SETFD, FD_CLOEXEC); }
    return (int64_t)r;
}
int64_t rt_host_pipe2(int fds[2], int linux_flags) {
    if (fds == NULL) { return -22; }
    if (linux_flags != 0 && linux_flags != 02000000 && linux_flags != 04000 && linux_flags != (02000000 | 04000)) { return -22; }
    if (pipe(fds) != 0) { return neg_errno(); }
    if ((linux_flags & 02000000) != 0) { (void)fcntl(fds[0], F_SETFD, FD_CLOEXEC); (void)fcntl(fds[1], F_SETFD, FD_CLOEXEC); }
    if ((linux_flags & 04000) != 0) { (void)fcntl(fds[0], F_SETFL, O_NONBLOCK); (void)fcntl(fds[1], F_SETFL, O_NONBLOCK); }
    return 0;
}
int64_t rt_host_readlinkat(int dirfd, const char *path, char *buf, size_t bufsiz) {
    if (path == NULL || buf == NULL) { return -22; }
    return libret(readlinkat(darwin_dirfd(dirfd), path, buf, bufsiz));
}
int64_t rt_host_unlinkat(int dirfd, const char *path, int linux_flags) {
    int at; if (path == NULL) { return -22; }
    at = darwin_atflag(linux_flags); if (at < 0) { return -22; }
    return libret(unlinkat(darwin_dirfd(dirfd), path, at));
}
int64_t rt_host_mkdirat(int dirfd, const char *path, uint32_t mode) {
    if (path == NULL) { return -22; }
    return libret(mkdirat(darwin_dirfd(dirfd), path, (mode_t)mode));
}
int64_t rt_host_renameat2(int olddirfd, const char *oldpath, int newdirfd, const char *newpath, unsigned int flags) {
    if (oldpath == NULL || newpath == NULL) { return -22; }
    if (flags != 0u) { return -38; } /* No RENAME_* equivalent. */
    return libret(renameat(darwin_dirfd(olddirfd), oldpath, darwin_dirfd(newdirfd), newpath));
}
int64_t rt_host_symlinkat(const char *target, int newdirfd, const char *linkpath) {
    if (target == NULL || linkpath == NULL) { return -22; }
    return libret(symlinkat(target, darwin_dirfd(newdirfd), linkpath));
}
int64_t rt_host_linkat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath, int flags) {
    int at; if (oldpath == NULL || newpath == NULL) { return -22; }
    at = darwin_atflag(flags); if (at < 0) { return -22; }
    return libret(linkat(darwin_dirfd(olddirfd), oldpath, darwin_dirfd(newdirfd), newpath, at));
}
int64_t rt_host_faccessat2(int dirfd, const char *path, int mode, int flags) {
    if (path == NULL) { return -22; }
    if (flags != 0 && flags != RT_LINUX_AT_SYMLINK_NOFOLLOW) { return -22; }
    return libret(faccessat(darwin_dirfd(dirfd), path, mode, 0));
}
int64_t rt_host_fchmodat(int dirfd, const char *path, uint32_t mode, int flags) {
    int at; if (path == NULL) { return -22; }
    at = darwin_atflag(flags); if (at < 0) { return -22; }
    return libret(fchmodat(darwin_dirfd(dirfd), path, (mode_t)mode, at));
}
int64_t rt_host_fchownat(int dirfd, const char *path, uint32_t uid, uint32_t gid, int flags) {
    int at; if (path == NULL) { return -22; }
    at = darwin_atflag(flags); if (at < 0) { return -22; }
    return libret(fchownat(darwin_dirfd(dirfd), path, (uid_t)uid, (gid_t)gid, at));
}
int64_t rt_host_utimensat(int dirfd, const char *path, const struct timespec times[2], int flags) {
    struct timeval tv[2];
    if (path == NULL) { return -22; }
    if (dirfd != RT_LINUX_AT_FDCWD || flags != 0) { return -38; } /* No utimensat on macOS. */
    if (times == NULL) { return libret(utimes(path, NULL)); }
    tv[0].tv_sec = times[0].tv_sec; tv[0].tv_usec = (int)(times[0].tv_nsec / 1000L);
    tv[1].tv_sec = times[1].tv_sec; tv[1].tv_usec = (int)(times[1].tv_nsec / 1000L);
    return libret(utimes(path, tv));
}
int64_t rt_host_getcwd(char *buf, size_t size) {
    if (buf == NULL || size == 0U) { return -22; }
    return getcwd(buf, size) == NULL ? neg_errno() : 0;
}
int64_t rt_host_chdir(const char *path) { if (path == NULL) { return -22; } return libret(chdir(path)); }
int64_t rt_host_fchdir(int fd) { return libret(fchdir(fd)); }
/* 6. networking */
int64_t rt_host_socket(int linux_domain, int linux_type, int protocol) {
    int dom, type, cloexec, nonblock, fd;
    dom = darwin_domain(linux_domain); type = darwin_socktype(linux_type, &cloexec, &nonblock);
    if (dom < 0 || type < 0) { return -97; }
    fd = socket(dom, type, protocol); if (fd < 0) { return neg_errno(); }
    darwin_flag_fd(fd, cloexec, nonblock); return (int64_t)fd;
}
int64_t rt_host_socketpair(int linux_domain, int linux_type, int protocol, int sv[2]) {
    int dom, type, cloexec, nonblock;
    if (sv == NULL) { return -22; }
    dom = darwin_domain(linux_domain); type = darwin_socktype(linux_type, &cloexec, &nonblock);
    if (dom < 0 || type < 0) { return -97; }
    if (socketpair(dom, type, protocol, sv) != 0) { return neg_errno(); }
    darwin_flag_fd(sv[0], cloexec, nonblock); darwin_flag_fd(sv[1], cloexec, nonblock); return 0;
}
int64_t rt_host_bind(int fd, const void *linux_addr, uint32_t addrlen) {
    if (linux_addr == NULL) { return -22; }
    return libret(bind(fd, (const struct sockaddr *)linux_addr, (socklen_t)addrlen));
}
int64_t rt_host_connect(int fd, const void *linux_addr, uint32_t addrlen, rt_worker_sync_t *ws, uint32_t expected_seq) {
    struct darwin_fdop a = { fd, 0, RT_FDOP_CONNECT, NULL, 0u, linux_addr, addrlen, NULL };
    int64_t r; int err = 0; socklen_t errlen = (socklen_t)sizeof(err);
    if (linux_addr == NULL) { return -22; }
    r = darwin_spin_fd(fd, 1, ws, expected_seq, &a);
    if (r != 0) { return r; }
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &errlen) == 0 && err != 0) { return -(int64_t)err; } /* writable != connected */
    return 0;
}
int64_t rt_host_listen(int fd, int backlog) { return libret(listen(fd, backlog)); }
int64_t rt_host_accept4(int fd, void *linux_addr_out, uint32_t *addrlen_inout, int linux_flags, rt_worker_sync_t *ws, uint32_t expected_seq) {
    struct darwin_fdop a = { fd, 0, RT_FDOP_ACCEPT, NULL, 0u, linux_addr_out, 0u, addrlen_inout };
    int64_t r; int cloexec, nonblock;
    if ((linux_flags & ~(02000000 | 04000)) != 0) { return -22; }
    if (darwin_socktype(linux_flags | 1, &cloexec, &nonblock) < 0) { return -22; }
    darwin_nonblock(fd);
    r = darwin_spin_fd(fd, 0, ws, expected_seq, &a);
    if (r >= 0) { darwin_flag_fd((int)r, cloexec, nonblock); }
    return r;
}
int64_t rt_host_sendto(int fd, const void *buf, size_t len, int linux_flags, const void *linux_dest_addr, uint32_t addrlen, rt_worker_sync_t *ws, uint32_t expected_seq) {
    struct darwin_fdop a = { fd, linux_flags, RT_FDOP_SENDTO, (void *)buf, len, linux_dest_addr, addrlen, NULL };
    return darwin_spin_fd(fd, 1, ws, expected_seq, &a);
}
int64_t rt_host_recvfrom(int fd, void *buf, size_t len, int linux_flags, void *linux_src_addr_out, uint32_t *addrlen_inout, rt_worker_sync_t *ws, uint32_t expected_seq) {
    struct darwin_fdop a = { fd, linux_flags, RT_FDOP_RECVFROM, buf, len, linux_src_addr_out, 0u, addrlen_inout };
    return darwin_spin_fd(fd, 0, ws, expected_seq, &a);
}
int64_t rt_host_getsockname(int fd, void *linux_addr_out, uint32_t *addrlen_inout) {
    if (linux_addr_out == NULL || addrlen_inout == NULL) { return -22; }
    return libret(getsockname(fd, (struct sockaddr *)linux_addr_out, (socklen_t *)addrlen_inout));
}
int64_t rt_host_getpeername(int fd, void *linux_addr_out, uint32_t *addrlen_inout) {
    if (linux_addr_out == NULL || addrlen_inout == NULL) { return -22; }
    return libret(getpeername(fd, (struct sockaddr *)linux_addr_out, (socklen_t *)addrlen_inout));
}
int64_t rt_host_setsockopt(int fd, int linux_level, int linux_optname, const void *optval, uint32_t optlen) {
    if (optval == NULL) { return -22; }
    return libret(setsockopt(fd, darwin_socklevel(linux_level), darwin_sockopt(linux_level, linux_optname), optval, (socklen_t)optlen));
}
int64_t rt_host_getsockopt(int fd, int linux_level, int linux_optname, void *optval, uint32_t *optlen_inout) {
    if (optval == NULL || optlen_inout == NULL) { return -22; }
    return libret(getsockopt(fd, darwin_socklevel(linux_level), darwin_sockopt(linux_level, linux_optname), optval, (socklen_t *)optlen_inout));
}
int64_t rt_host_shutdown(int fd, int how) { return libret(shutdown(fd, how)); }
int64_t rt_host_ppoll(void *linux_pollfds, size_t nfds, const struct timespec *rel_timeout, const uint64_t *linux_sigmask, rt_worker_sync_t *ws, uint32_t expected_seq) {
    struct pollfd *fds; int timeout_ms = -1, r, has_wake = 0; size_t i, total = nfds;
    (void)linux_sigmask;
    if (ws != NULL && atomic_load_explicit(&ws->sig_seq, memory_order_acquire) != expected_seq) { return -4; }
    if (ws != NULL && ws->wake_pipe_rd >= 0) { total++; has_wake = 1; }
    if (total == 0u) { return 0; }
    fds = (struct pollfd *)malloc(total * sizeof(*fds));
    if (fds == NULL) { return -12; }
    for (i = 0u; i < nfds; i++) { (void)memcpy(&fds[i], (const char *)linux_pollfds + i * sizeof(*fds), sizeof(*fds)); }
    if (has_wake) { fds[nfds].fd = ws->wake_pipe_rd; fds[nfds].events = POLLIN; fds[nfds].revents = 0; }
    if (rel_timeout != NULL) { int64_t ms = (int64_t)rel_timeout->tv_sec * 1000L + (int64_t)rel_timeout->tv_nsec / 1000000L; timeout_ms = ms > 2147483647L ? 2147483647 : (int)ms; }
    r = poll(fds, (nfds_t)total, timeout_ms);
    if (r < 0) { int e = errno; free(fds); return -(int64_t)e; }
    if (has_wake && (fds[nfds].revents & POLLIN) != 0) { char tmp[32]; (void)read(ws->wake_pipe_rd, tmp, sizeof(tmp)); free(fds); return -4; }
    if (r > 0) { for (i = 0u; i < nfds; i++) { (void)memcpy((char *)linux_pollfds + i * sizeof(*fds), &fds[i], sizeof(*fds)); } }
    free(fds); return (int64_t)r;
}
/* Minimal epoll-over-kqueue emulation (level-triggered; EPOLLET -> EV_CLEAR for edge-ish delivery). */
#define RT_EPOLL_SLOTS 64u
#define RT_EPOLL_INTERESTS 128u
#define RT_EPOLL_CTL_ADD 1
#define RT_EPOLL_CTL_DEL 2
#define RT_EPOLL_CTL_MOD 3
struct rt_epoll_interest { int fd; uint32_t events; uint64_t data; };
struct rt_epoll_slot { int used, kq; struct rt_epoll_interest interests[RT_EPOLL_INTERESTS]; };
static struct rt_epoll_slot g_epoll[RT_EPOLL_SLOTS];
static struct rt_epoll_slot *epoll_lookup(int epfd) {
    unsigned i;
    for (i = 0u; i < RT_EPOLL_SLOTS; i++) { if (g_epoll[i].used && g_epoll[i].kq == epfd) { return &g_epoll[i]; } }
    return NULL;
}
int64_t rt_host_epoll_create1(int linux_flags) {
    unsigned i, j; int kq;
    if (linux_flags != 0 && linux_flags != 02000000) { return -22; }
    kq = kqueue(); if (kq < 0) { return neg_errno(); }
    if ((linux_flags & 02000000) != 0) { (void)fcntl(kq, F_SETFD, FD_CLOEXEC); }
    for (i = 0u; i < RT_EPOLL_SLOTS; i++) {
        if (!g_epoll[i].used) {
            g_epoll[i].used = 1; g_epoll[i].kq = kq;
            for (j = 0u; j < RT_EPOLL_INTERESTS; j++) { g_epoll[i].interests[j].fd = -1; }
            return (int64_t)kq;
        }
    }
    (void)close(kq); return -23;
}
int64_t rt_host_epoll_ctl(int epfd, int op, int fd, const void *linux_epoll_event) {
    /* Packed Linux struct epoll_event: u32 events @0, u64 data @4. */
    const unsigned char *ev = (const unsigned char *)linux_epoll_event;
    struct rt_epoll_slot *slot = epoll_lookup(epfd);
    struct kevent changes[2]; uint32_t events = 0u, flags, e32; uint64_t data = 0u, d64;
    unsigned i; int slot_idx = -1;
    if (slot == NULL) { return -9; }
    if (op == RT_EPOLL_CTL_ADD || op == RT_EPOLL_CTL_MOD) {
        if (ev == NULL) { return -22; }
        (void)memcpy(&e32, ev, sizeof(e32)); (void)memcpy(&d64, ev + 4u, sizeof(d64)); events = e32; data = d64;
    }
    for (i = 0u; i < RT_EPOLL_INTERESTS; i++) {
        if (slot->interests[i].fd == fd) { slot_idx = (int)i; break; }
        if (slot_idx < 0 && slot->interests[i].fd < 0) { slot_idx = (int)i; }
    }
    flags = EV_ADD | EV_ENABLE; if ((events & 0x80000000u) != 0u) { flags |= EV_CLEAR; }
    if (op == RT_EPOLL_CTL_DEL) {
        EV_SET(&changes[0], (uintptr_t)fd, EVFILT_READ, EV_DELETE, 0, 0, NULL);
        EV_SET(&changes[1], (uintptr_t)fd, EVFILT_WRITE, EV_DELETE, 0, 0, NULL);
        (void)kevent(slot->kq, changes, 2, NULL, 0, NULL);
        if (slot_idx >= 0) { slot->interests[(unsigned)slot_idx].fd = -1; }
        return 0;
    }
    if (slot_idx < 0) { return -28; }
    if ((events & 0x1u) != 0u) {
        EV_SET(&changes[0], (uintptr_t)fd, EVFILT_READ, flags, 0, 0, NULL);
        if (kevent(slot->kq, changes, 1, NULL, 0, NULL) != 0) { return neg_errno(); }
    }
    if ((events & 0x4u) != 0u) {
        EV_SET(&changes[0], (uintptr_t)fd, EVFILT_WRITE, flags, 0, 0, NULL);
        if (kevent(slot->kq, changes, 1, NULL, 0, NULL) != 0) { return neg_errno(); }
    }
    slot->interests[(unsigned)slot_idx].fd = fd;
    slot->interests[(unsigned)slot_idx].events = events;
    slot->interests[(unsigned)slot_idx].data = data; return 0;
}
int64_t rt_host_epoll_pwait(int epfd, void *linux_epoll_events_out, int maxevents, int timeout_ms, const uint64_t *linux_sigmask, rt_worker_sync_t *ws, uint32_t expected_seq) {
    struct rt_epoll_slot *slot = epoll_lookup(epfd);
    struct kevent *evlist; struct timespec ts, *tsp = NULL; int n, got = 0; unsigned i, j;
    (void)linux_sigmask;
    if (slot == NULL || linux_epoll_events_out == NULL || maxevents <= 0) { return -22; }
    if (maxevents > 1024) { maxevents = 1024; }
    if (ws != NULL && atomic_load_explicit(&ws->sig_seq, memory_order_acquire) != expected_seq) { return -4; }
    evlist = (struct kevent *)malloc((size_t)maxevents * sizeof(*evlist));
    if (evlist == NULL) { return -12; }
    if (timeout_ms >= 0) { ts.tv_sec = timeout_ms / 1000; ts.tv_nsec = (long)(timeout_ms % 1000) * 1000000L; tsp = &ts; }
    n = kevent(slot->kq, NULL, 0, evlist, maxevents, tsp);
    if (n < 0) { int e = errno; free(evlist); return -(int64_t)e; }
    for (i = 0u; i < (unsigned)n; i++) {
        unsigned char *dst = (unsigned char *)linux_epoll_events_out + (size_t)got * 12u;
        uint32_t e32 = 0u; uint64_t d64 = 0u; int fd = (int)evlist[i].ident;
        for (j = 0u; j < RT_EPOLL_INTERESTS; j++) { if (slot->interests[j].fd == fd) { d64 = slot->interests[j].data; break; } }
        if (evlist[i].filter == EVFILT_READ) { e32 |= 0x1u; } else if (evlist[i].filter == EVFILT_WRITE) { e32 |= 0x4u; }
        if ((evlist[i].flags & EV_ERROR) != 0u) { e32 |= 0x8u | 0x10u; }
        (void)memcpy(dst, &e32, sizeof(e32)); (void)memcpy(dst + 4u, &d64, sizeof(d64)); got++;
    }
    free(evlist);
    if (ws != NULL && atomic_load_explicit(&ws->sig_seq, memory_order_acquire) != expected_seq) { return -4; }
    return (int64_t)got;
}
/* 7. futex + clocks */
int64_t rt_host_futex_wait_bitset(_Atomic uint32_t *pinned_host_uaddr, const rt_futex_key_t *key, uint32_t host_endian_val, const struct timespec *timeout, int is_abs_timeout, int clock_realtime, uint32_t bitset, rt_worker_sync_t *ws, uint32_t expected_seq) {
    uint32_t timeout_us = 0u; int r;
    (void)key; (void)bitset;
    if (pinned_host_uaddr == NULL) { return -22; }
    if (ws != NULL && atomic_load_explicit(&ws->sig_seq, memory_order_acquire) != expected_seq) { return -4; }
    if (timeout != NULL) {
        struct timespec now; int64_t delta_ns; uint64_t us; int clk = clock_realtime ? CLOCK_REALTIME : CLOCK_MONOTONIC;
        if (clock_gettime((clockid_t)clk, &now) != 0) { return neg_errno(); }
        if (is_abs_timeout) { delta_ns = ((int64_t)timeout->tv_sec - (int64_t)now.tv_sec) * 1000000000L + ((int64_t)timeout->tv_nsec - (int64_t)now.tv_nsec); }
        else { delta_ns = (int64_t)timeout->tv_sec * 1000000000L + (int64_t)timeout->tv_nsec; }
        if (delta_ns <= 0) { return -110; }
        us = (uint64_t)delta_ns / 1000ULL; timeout_us = us > 0xffffffffULL ? 0xffffffffu : (uint32_t)us;
    }
    if (ws != NULL) { atomic_store_explicit(&ws->ulock_wait_addr, (uintptr_t)pinned_host_uaddr, memory_order_release); }
    r = __ulock_wait(RT_UL_COMPARE_AND_WAIT, (void *)pinned_host_uaddr, (uint64_t)host_endian_val, timeout_us);
    if (ws != NULL) { atomic_store_explicit(&ws->ulock_wait_addr, (uintptr_t)0, memory_order_release); }
    if (r == 0) { return 0; }
    if (r == -1) { /* Timeout surfaces as -1/ETIMEDOUT (observed). */
        int e = errno;
        return e == ETIMEDOUT ? -110 : -(int64_t)e;
    }
    if (r == 60 || r == 35) { return -110; } /* timeout tokens */
    return -(int64_t)r;
}
int64_t rt_host_futex_wake_bitset(_Atomic uint32_t *pinned_host_uaddr, const rt_futex_key_t *key, int count, uint32_t bitset) {
    int r; (void)key; (void)bitset; (void)count;
    if (pinned_host_uaddr == NULL) { return -22; }
    r = __ulock_wake(RT_UL_COMPARE_AND_WAIT | RT_ULF_WAKE_ALL, (void *)pinned_host_uaddr, 0u); /* plan 6.4b */
    return r < 0 ? neg_errno() : (int64_t)r;
}
int64_t rt_host_futex_requeue(_Atomic uint32_t *pinned_host_uaddr1, const rt_futex_key_t *key1, int wake_count, const rt_futex_key_t *key2, int requeue_count, const uint32_t *host_endian_cmp_val) {
    (void)key2; (void)requeue_count; (void)host_endian_cmp_val; /* No requeue primitive on Darwin. */
    return rt_host_futex_wake_bitset(pinned_host_uaddr1, key1, wake_count, 0u);
}
int64_t rt_host_clock_gettime(int linux_clk_id, struct timespec *tp) {
    if (tp == NULL) { return -22; }
    return libret(clock_gettime((clockid_t)linux_clk_id, tp));
}
int64_t rt_host_clock_getres(int linux_clk_id, struct timespec *res) {
    if (res == NULL) { return -22; }
    return libret(clock_getres((clockid_t)linux_clk_id, res));
}
int64_t rt_host_clock_nanosleep(int linux_clk_id, int linux_flags, const struct timespec *req, struct timespec *rem, rt_worker_sync_t *ws, uint32_t expected_seq) {
    struct timespec rel; (void)ws; (void)expected_seq;
    if (req == NULL) { return -22; }
    if ((linux_flags & 1) != 0) { /* TIMER_ABSTIME: sleep the delta to the absolute target. */
        struct timespec now;
        if (clock_gettime((clockid_t)linux_clk_id, &now) != 0) { return neg_errno(); }
        rel.tv_sec = req->tv_sec - now.tv_sec; rel.tv_nsec = req->tv_nsec - now.tv_nsec;
        if (rel.tv_nsec < 0) { rel.tv_sec -= 1; rel.tv_nsec += 1000000000L; }
        if (rel.tv_sec < 0) { return 0; }
        req = &rel;
    }
    return nanosleep(req, rem) != 0 ? neg_errno() : 0;
}
int64_t rt_host_getrandom(void *buf, size_t buflen, unsigned int linux_flags) {
    size_t off = 0u; (void)linux_flags;
    if (buf == NULL) { return -22; }
    while (off < buflen) {
        size_t want = buflen - off; if (want > 256u) { want = 256u; }
        if (getentropy((char *)buf + off, want) != 0) { return off != 0u ? (int64_t)off : neg_errno(); }
        off += want;
    }
    return (int64_t)buflen;
}
/* 8. processes, threads, signals */
int rt_host_worker_altstack_init(void **out_stack_mem, size_t *out_stack_size) {
    stack_t ss; void *mem;
    if (out_stack_mem == NULL || out_stack_size == NULL) { return -22; }
    mem = malloc(65536u); if (mem == NULL) { return -12; }
    ss.ss_sp = mem; ss.ss_size = 65536u; ss.ss_flags = 0;
    if (sigaltstack(&ss, NULL) != 0) { int e = errno; free(mem); return -e; }
    *out_stack_mem = mem; *out_stack_size = 65536u; return 0;
}
void rt_host_worker_altstack_destroy(void *stack_mem, size_t stack_size) {
    stack_t off; (void)stack_size;
    off.ss_sp = NULL; off.ss_size = 0u; off.ss_flags = SS_DISABLE;
    (void)sigaltstack(&off, NULL); free(stack_mem);
}
struct worker_start { void *(*fn)(void *); void *arg; pthread_mutex_t mu; pthread_cond_t cv; uint64_t tid; int ready; };
static void *worker_tramp(void *p) {
    struct worker_start *st = (struct worker_start *)p;
    void *(*fn)(void *); void *arg; uint64_t tid = 0u;
    (void)pthread_mutex_lock(&st->mu);
    (void)pthread_threadid_np(NULL, &tid); st->tid = tid; st->ready = 1;
    (void)pthread_cond_signal(&st->cv); (void)pthread_mutex_unlock(&st->mu);
    darwin_worker_register(tid, pthread_self()); fn = st->fn; arg = st->arg;
    return fn(arg);
}
int rt_host_spawn_worker(void *(*fn)(void *), void *arg, uint64_t *out_host_tid) {
    struct worker_start st; pthread_t th;
    if (fn == NULL || out_host_tid == NULL) { return -22; }
    st.fn = fn; st.arg = arg; st.tid = 0u; st.ready = 0;
    (void)pthread_mutex_init(&st.mu, NULL); (void)pthread_cond_init(&st.cv, NULL);
    if (pthread_create(&th, NULL, worker_tramp, &st) != 0) {
        int e = errno; (void)pthread_mutex_destroy(&st.mu); (void)pthread_cond_destroy(&st.cv); return -e;
    }
    (void)pthread_detach(th);
    (void)pthread_mutex_lock(&st.mu);
    while (!st.ready) { (void)pthread_cond_wait(&st.cv, &st.mu); }
    *out_host_tid = st.tid;
    (void)pthread_mutex_unlock(&st.mu); (void)pthread_mutex_destroy(&st.mu); (void)pthread_cond_destroy(&st.cv);
    return 0;
}
int64_t rt_host_fork(void) { pid_t p = fork(); return p < 0 ? neg_errno() : (int64_t)p; }
int64_t rt_host_execve(const char *path, char *const argv[], char *const envp[]) {
    if (path == NULL) { return -22; }
    execve(path, argv, envp); return neg_errno();
}
int64_t rt_host_wait4(int64_t pid, int *linux_status_out, int linux_options, void *rusage_out, rt_worker_sync_t *ws, uint32_t expected_seq) {
    (void)ws; (void)expected_seq;
    for (;;) {
        pid_t r = wait4((pid_t)pid, linux_status_out, linux_options, (struct rusage *)rusage_out);
        if (r < 0 && errno == EINTR) {
            if (ws != NULL && atomic_load_explicit(&ws->sig_seq, memory_order_acquire) != expected_seq) { return -4; }
            continue;
        }
        return r < 0 ? neg_errno() : (int64_t)r;
    }
}
int64_t rt_host_waitid(int idtype, int64_t id, void *linux_siginfo_out, int linux_options, void *rusage_out, rt_worker_sync_t *ws, uint32_t expected_seq) {
    (void)ws; (void)expected_seq;
    if (rusage_out != NULL) { return -22; }
    return waitid((idtype_t)idtype, (id_t)id, (siginfo_t *)linux_siginfo_out, linux_options) != 0 ? neg_errno() : 0;
}
int64_t rt_host_kill(int64_t pid, int linux_sig) {
    int d = darwin_signo(linux_sig); if (d < 0) { return -22; }
    return libret(kill((pid_t)pid, d));
}
int64_t rt_host_tgkill(int64_t tgid, int64_t tid, int linux_sig) {
    int d = darwin_signo(linux_sig); pthread_t th; (void)tgid; /* no tid-targeted kill outside pthreads */
    if (d < 0) { return -22; }
    if (d == SIGUSR2) { return rt_host_preempt_worker((uint64_t)tid); }
    if (!darwin_worker_find((uint64_t)tid, &th)) { return -3; }
    return pthread_kill(th, d) != 0 ? -(int)errno : 0;
}
int rt_host_sigprocmask(int linux_how, const uint64_t *new_set, uint64_t *old_set) {
    sigset_t in, out; sigset_t *inp = NULL, *outp = NULL;
    if (new_set != NULL) {
        uint32_t low = (uint32_t)(*new_set & 0xffffffffULL);
        (void)memset(&in, 0, sizeof(in));
        (void)memcpy(&in, &low, sizeof(low) < sizeof(in) ? sizeof(low) : sizeof(in)); inp = &in;
    }
    if (old_set != NULL) { outp = &out; }
    if (pthread_sigmask(linux_how, inp, outp) != 0) { return -(int)errno; }
    if (old_set != NULL) { uint64_t v = 0u; (void)memcpy(&v, &out, sizeof(out) < sizeof(v) ? sizeof(out) : sizeof(v)); *old_set = v; }
    return 0;
}
void rt_host_exit_thread(int status) { pthread_exit((void *)(uintptr_t)(uint32_t)status); __builtin_unreachable(); }
void rt_host_exit_group(int status) { _exit(status); __builtin_unreachable(); }
static rt_host_sync_fault_fn g_on_sync = NULL;
static rt_host_async_sig_fn g_on_async = NULL;
static rt_host_preempt_fn g_on_preempt = NULL;
static void backend_segv_handler(int sig, siginfo_t *info, void *uc) {
    rt_host_sync_fault_t f; ucontext_t *ctx = (ucontext_t *)uc;
    (void)memset(&f, 0, sizeof(f));
    f.linux_si_signo = linux_signo(sig); f.linux_si_code = info != NULL ? info->si_code : 0;
    f.fault_addr = info != NULL ? (uintptr_t)info->si_addr : (uintptr_t)0;
    f.host_pc = (uintptr_t)ctx->uc_mcontext->__ss.__pc; f.host_ucontext = uc;
    if (g_on_sync != NULL) { g_on_sync(&f); }
}
static void backend_preempt_handler(int sig, siginfo_t *info, void *uc) {
    (void)sig; (void)info; if (g_on_preempt != NULL) { g_on_preempt(uc); }
}
static void backend_async_handler(int sig, siginfo_t *info, void *uc) {
    rt_host_async_siginfo_t s; (void)uc; (void)memset(&s, 0, sizeof(s));
    s.linux_si_signo = linux_signo(sig); s.linux_si_code = info != NULL ? info->si_code : 0;
    s.sender_pid = info != NULL ? (int32_t)info->si_pid : 0;
    s.sender_uid = info != NULL ? (uint32_t)info->si_uid : 0u;
    if (g_on_async != NULL) { g_on_async(&s); }
}
int rt_host_install_signal_handlers(rt_host_sync_fault_fn on_sync_fault, rt_host_async_sig_fn on_async_sig, rt_host_preempt_fn on_preempt) {
    struct sigaction sa;
    g_on_sync = on_sync_fault; g_on_async = on_async_sig; g_on_preempt = on_preempt;
    (void)memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = backend_segv_handler; sa.sa_flags = SA_SIGINFO | SA_ONSTACK; (void)sigemptyset(&sa.sa_mask);
    if (sigaction(SIGSEGV, &sa, NULL) != 0) { return -(int)errno; }
    if (sigaction(SIGBUS, &sa, NULL) != 0) { return -(int)errno; }
    (void)memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = backend_preempt_handler; sa.sa_flags = SA_SIGINFO | SA_ONSTACK; (void)sigemptyset(&sa.sa_mask);
    if (sigaction(SIGUSR2, &sa, NULL) != 0) { return -(int)errno; }
    (void)memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = backend_async_handler; sa.sa_flags = SA_SIGINFO | SA_ONSTACK; (void)sigemptyset(&sa.sa_mask);
    if (sigaction(SIGCHLD, &sa, NULL) != 0) { return -(int)errno; }
    if (sigaction(SIGALRM, &sa, NULL) != 0) { return -(int)errno; }
    return 0;
}
#else /* not macOS-arm64: no symbols, keeps -pedantic quiet */
typedef int rt_host_darwin_unused_t;
#endif /* defined(__APPLE__) && defined(__aarch64__) */
