/*
 * src/os/backend_darwin.c -- Standalone macOS arm64 host backend (Lane M3)
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Backend 2 (UNIFICATION-PLAN Rev 4 section 6): native macOS Mach-O, no
 * Hypervisor.framework. Owns identity, host memory mapping, JIT W^X,
 * filesystem, networking (with Linux <-> Darwin sockaddr translation),
 * and I/O multiplexing (ppoll/epoll). Worker sync, keyed futexes,
 * clocks/random, threads, processes, and signals live in
 * src/os/backend_darwin_sync.c.
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
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>

extern void pthread_jit_write_protect_np(int enabled);
int rt_darwin_signo(int linux_sig);

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
static int darwin_open_flags(int lf, int *out) {
    static const int known = 03 | 0100 | 0200 | 0400 | 01000 | 02000 | 04000 |
        0100000 | 04010000 | 00040000 | 00100000 | 00200000 | 00400000 | 02000000;
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
static int darwin_socktype(int t, int *cloexec, int *nonblock) {
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

/* S64-4: Linux sockaddr (uint16_t sa_family at offset 0, AF_INET6=10)
 * <-> Darwin sockaddr (uint8_t sa_len, uint8_t sa_family, AF_INET6=30). */
static int darwin_sockaddr_from_linux(const void *lin, uint32_t lin_len,
    struct sockaddr_storage *dar_out, socklen_t *dar_len_out) {
    uint16_t lfam = 0u; uint8_t dfam; uint32_t copy_len;
    if (lin == NULL || dar_out == NULL || dar_len_out == NULL ||
        lin_len < 2u || lin_len > (uint32_t)sizeof(*dar_out)) { return -22; }
    (void)memcpy(&lfam, lin, sizeof(lfam));
    switch (lfam) {
    case 1u: dfam = (uint8_t)AF_UNIX; copy_len = lin_len; break;
    case 2u: if (lin_len < 16u) { return -22; } dfam = (uint8_t)AF_INET; copy_len = 16u; break;
    case 10u: if (lin_len < 28u) { return -22; } dfam = (uint8_t)AF_INET6; copy_len = 28u; break;
    default: return -97;
    }
    (void)memset(dar_out, 0, sizeof(*dar_out));
    (void)memcpy(dar_out, lin, copy_len);
    ((uint8_t *)dar_out)[0] = (uint8_t)(copy_len > 255u ? 255u : copy_len);
    ((uint8_t *)dar_out)[1] = dfam;
    *dar_len_out = (socklen_t)copy_len;
    return 0;
}
static void darwin_sockaddr_to_linux(const struct sockaddr_storage *dar,
    socklen_t dar_len, void *lin_out, uint32_t *lin_len_inout) {
    struct sockaddr_storage tmp; uint16_t lfam; uint8_t dfam;
    uint32_t full_len, avail, copy_len;
    if (lin_out == NULL || lin_len_inout == NULL) { return; }
    if (dar == NULL || dar_len < 2u) { *lin_len_inout = 0u; return; }
    dfam = ((const uint8_t *)dar)[1];
    switch (dfam) {
    case AF_UNIX: lfam = 1u; full_len = (uint32_t)dar_len; break;
    case AF_INET: lfam = 2u; full_len = 16u; break;
    case AF_INET6: lfam = 10u; full_len = 28u; break;
    default: lfam = (uint16_t)dfam; full_len = (uint32_t)dar_len; break;
    }
    (void)memset(&tmp, 0, sizeof(tmp));
    copy_len = (uint32_t)dar_len < (uint32_t)sizeof(tmp) ? (uint32_t)dar_len : (uint32_t)sizeof(tmp);
    (void)memcpy(&tmp, dar, copy_len);
    (void)memcpy(&tmp, &lfam, sizeof(lfam));
    avail = *lin_len_inout;
    copy_len = avail < full_len ? avail : full_len;
    if (copy_len > (uint32_t)sizeof(tmp)) { copy_len = (uint32_t)sizeof(tmp); }
    (void)memcpy(lin_out, &tmp, copy_len);
    *lin_len_inout = full_len;
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
struct darwin_fdop { int fd, flags, kind; void *buf; size_t len; const void *addr; socklen_t addrlen; socklen_t *addrlenp; };
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
        int r; darwin_nonblock(a->fd);
        r = connect(a->fd, (const struct sockaddr *)a->addr, a->addrlen);
        if (r == 0 || errno == EISCONN) { return 0; }
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINPROGRESS || errno == EALREADY) { return -35; }
        return neg_errno();
    }
    case RT_FDOP_ACCEPT: {
        int f = accept(a->fd, (struct sockaddr *)a->buf, a->addrlenp);
        if (f < 0) { if (errno == EAGAIN || errno == EWOULDBLOCK) { return -35; } return neg_errno(); }
        darwin_nonblock(a->fd); return (int64_t)f;
    }
    case RT_FDOP_SENDTO:
        return libret(sendto(a->fd, a->buf, a->len, a->flags, (const struct sockaddr *)a->addr, a->addrlen));
    default:
        return libret(recvfrom(a->fd, a->buf, a->len, a->flags, (struct sockaddr *)a->addr, a->addrlenp));
    }
}
static int64_t darwin_spin_fd(int fd, int want_write, rt_worker_sync_t *ws, uint32_t expected_seq, struct darwin_fdop *a) {
    for (;;) { int64_t r = darwin_do_fdop(a); int w; if (r != -35) { return r; } w = darwin_wait_fd(fd, want_write, ws, expected_seq); if (w != 0) { return (int64_t)w; } }
}

/* 1. identity */
rt_backend_kind_t rt_host_backend_kind(void) { return RT_BACKEND_DARWIN; }
int rt_host_is_hyper_linux(void) { return 0; }
size_t rt_host_page_size(void) {
    static long cached = 0L; long v;
    if (cached != 0L) { return (size_t)cached; }
    v = sysconf(_SC_PAGESIZE); cached = v <= 0L ? 16384L : v; return (size_t)cached;
}

/* 2. memory (S64-6: check noreplace before fixed under lock) */
static pthread_mutex_t g_map_noreplace_mu = PTHREAD_MUTEX_INITIALIZER;
int rt_host_map_anon(void *hint_addr, size_t len, int linux_prot, int fixed, int noreplace, void **out_host_addr) {
    int flags = MAP_PRIVATE | MAP_ANONYMOUS; void *p;
    if (len == 0U || out_host_addr == NULL) { return -22; }
    if (noreplace) {
        size_t off, ps = rt_host_page_size();
        if (hint_addr == NULL) { return -22; }
        (void)pthread_mutex_lock(&g_map_noreplace_mu);
        for (off = 0u; off < len; off += ps) {
            char vec = 0;
            if (mincore((char *)hint_addr + off, ps, &vec) == 0) {
                (void)pthread_mutex_unlock(&g_map_noreplace_mu);
                return -17;
            }
        }
        p = mmap(hint_addr, len, linux_prot, flags, -1, 0);
        if (p == MAP_FAILED) { int e = errno; (void)pthread_mutex_unlock(&g_map_noreplace_mu); return -e; }
        if (p != hint_addr) { (void)munmap(p, len); (void)pthread_mutex_unlock(&g_map_noreplace_mu); return -17; }
        (void)pthread_mutex_unlock(&g_map_noreplace_mu);
        *out_host_addr = p; return 0;
    }
    if (fixed) { flags |= MAP_FIXED; }
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
    char shm_name[64]; size_t i = 0u, o = 0u; int fd;
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

/* 5. filesystem */
int64_t rt_host_openat(int dirfd, const char *path, int linux_flags, uint32_t mode, rt_worker_sync_t *ws, uint32_t expected_seq) {
    struct stat st; int df, was_nonblock, f; int64_t r;
    if (path == NULL) { return -22; }
    if (darwin_open_flags(linux_flags, &df) != 0) { return -22; }
    was_nonblock = (df & O_NONBLOCK) != 0 ? 1 : 0; df |= O_NONBLOCK;
    r = libret(openat(darwin_dirfd(dirfd), path, df, (mode_t)mode));
    if (r < 0) { return r; }
    if (!was_nonblock) {
        if (fstat((int)r, &st) == 0 && S_ISFIFO(st.st_mode)) { int w = darwin_wait_fd((int)r, 0, ws, expected_seq); if (w != 0) { (void)close((int)r); return (int64_t)w; } }
        f = fcntl((int)r, F_GETFL); if (f >= 0) { (void)fcntl((int)r, F_SETFL, f & ~O_NONBLOCK); }
    }
    return r;
}
/* S64-R2-6: per-fd cached DIR* stream for paginated getdents64. */
#define RT_DIR_SLOTS 32u
struct rt_dir_slot {
    int used;
    int fd;
    dev_t dev;
    ino_t ino;
    DIR *dir;
    int has_pending;
    struct dirent pending;
    int64_t pending_off;
};
static pthread_mutex_t g_dir_mu = PTHREAD_MUTEX_INITIALIZER;
static struct rt_dir_slot g_dirs[RT_DIR_SLOTS];
static void darwin_dir_invalidate(int fd) {
    unsigned i;
    if (fd < 0) { return; }
    (void)pthread_mutex_lock(&g_dir_mu);
    for (i = 0u; i < RT_DIR_SLOTS; i++) {
        if (g_dirs[i].used && g_dirs[i].fd == fd) {
            if (g_dirs[i].dir != NULL) { (void)closedir(g_dirs[i].dir); }
            g_dirs[i].dir = NULL;
            g_dirs[i].used = 0;
            g_dirs[i].has_pending = 0;
        }
    }
    (void)pthread_mutex_unlock(&g_dir_mu);
}
static void darwin_dir_seek(int fd, int64_t offset, int linux_whence) {
    unsigned i;
    if (fd < 0 || linux_whence != 0 || offset < 0) { return; }
    (void)pthread_mutex_lock(&g_dir_mu);
    for (i = 0u; i < RT_DIR_SLOTS; i++) {
        if (g_dirs[i].used && g_dirs[i].fd == fd && g_dirs[i].dir != NULL) {
            if (offset == 0) { rewinddir(g_dirs[i].dir); }
            else { seekdir(g_dirs[i].dir, (long)offset); }
            g_dirs[i].has_pending = 0;
        }
    }
    (void)pthread_mutex_unlock(&g_dir_mu);
}
int64_t rt_host_close(int fd) { darwin_dir_invalidate(fd); return libret(close(fd)); }
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
int64_t rt_host_lseek(int fd, int64_t offset, int linux_whence) {
    darwin_dir_seek(fd, offset, linux_whence);
    return libret(lseek(fd, (off_t)offset, linux_whence));
}
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
    if (mode != 0) { return -38; }
    store.fst_flags = (u_int32_t)0; store.fst_posmode = F_PEOFPOSMODE; store.fst_offset = 0;
    store.fst_length = (off_t)(offset + len); store.fst_bytesalloc = 0;
    (void)fcntl(fd, F_PREALLOCATE, &store);
    return libret(ftruncate(fd, (off_t)(offset + len)));
}
/* S64-7: advance *inout_in, *inout_out, and done after each write/pwrite. */
static int64_t darwin_copy_loop(int fd_in, int64_t *inout_in, int fd_out, int64_t *inout_out, int is_sendfile, size_t len) {
    static const size_t chunk = 65536u; char *buf = (char *)malloc(chunk);
    size_t left = len; int64_t done = 0;
    if (buf == NULL) { return -12; }
    if (inout_in == NULL) { free(buf); return -22; }
    while (left != 0u) {
        size_t want = left < chunk ? left : chunk, woff = 0u;
        ssize_t r = pread(fd_in, buf, want, (off_t)(*inout_in));
        if (r < 0) { if (errno == EINTR) { continue; } { int e = errno; free(buf); return done != 0 ? done : -(int64_t)e; } }
        if (r == 0) { break; }
        while (woff < (size_t)r) {
            ssize_t w = is_sendfile ? write(fd_out, buf + woff, (size_t)r - woff)
                                    : pwrite(fd_out, buf + woff, (size_t)r - woff, (off_t)(*inout_out));
            if (w < 0) { if (errno == EINTR) { continue; } { int e = errno; free(buf); return done != 0 ? done : -(int64_t)e; } }
            if (w == 0) { free(buf); return done; }
            woff += (size_t)w; *inout_in += (int64_t)w;
            if (!is_sendfile && inout_out != NULL) { *inout_out += (int64_t)w; }
            done += (int64_t)w;
        }
        left -= (size_t)r;
    }
    free(buf); return done;
}
int64_t rt_host_sendfile(int out_fd, int in_fd, int64_t *offset, size_t count) {
    if (offset == NULL) { return -22; }
    return darwin_copy_loop(in_fd, offset, out_fd, NULL, 1, count);
}
int64_t rt_host_copy_file_range(int fd_in, int64_t *off_in, int fd_out, int64_t *off_out, size_t len, unsigned int flags) {
    if (off_in == NULL || off_out == NULL || flags != 0u) { return -22; }
    return darwin_copy_loop(fd_in, off_in, fd_out, off_out, 0, len);
}
int64_t rt_host_fsync(int fd, int datasync_only) { (void)datasync_only; return fcntl(fd, F_FULLFSYNC) != 0 ? libret(fsync(fd)) : 0; }
struct rt_linux_dirent64 { uint64_t d_ino; int64_t d_off; uint16_t d_reclen; uint8_t d_type; char d_name[]; };
int64_t rt_host_getdents64(int fd, void *linux_dirent64_buf, size_t buf_size) {
    char *out = (char *)linux_dirent64_buf; size_t used = 0u;
    struct stat st; struct rt_dir_slot *slot = NULL; unsigned i; int free_idx = -1;
    if (out == NULL || buf_size == 0U) { return -22; }
    if (fstat(fd, &st) != 0) { return neg_errno(); }
    if (!S_ISDIR(st.st_mode)) { return -20; }
    (void)pthread_mutex_lock(&g_dir_mu);
    for (i = 0u; i < RT_DIR_SLOTS; i++) {
        if (g_dirs[i].used && g_dirs[i].fd == fd) {
            if (g_dirs[i].dev == st.st_dev && g_dirs[i].ino == st.st_ino) {
                slot = &g_dirs[i];
            } else {
                if (g_dirs[i].dir != NULL) { (void)closedir(g_dirs[i].dir); }
                g_dirs[i].dir = NULL; g_dirs[i].used = 0; g_dirs[i].has_pending = 0;
                if (free_idx < 0) { free_idx = (int)i; }
            }
            break;
        }
        if (!g_dirs[i].used && free_idx < 0) { free_idx = (int)i; }
    }
    if (slot == NULL) {
        int dupfd = dup(fd);
        DIR *dir;
        if (dupfd < 0) { int e = errno; (void)pthread_mutex_unlock(&g_dir_mu); return -(int64_t)e; }
        (void)fcntl(dupfd, F_SETFD, FD_CLOEXEC);
        dir = fdopendir(dupfd);
        if (dir == NULL) { int e = errno; (void)close(dupfd); (void)pthread_mutex_unlock(&g_dir_mu); return -(int64_t)e; }
        if (free_idx < 0) {
            free_idx = 0;
            if (g_dirs[0].used && g_dirs[0].dir != NULL) { (void)closedir(g_dirs[0].dir); }
        }
        slot = &g_dirs[(unsigned)free_idx];
        slot->used = 1; slot->fd = fd; slot->dev = st.st_dev; slot->ino = st.st_ino;
        slot->dir = dir; slot->has_pending = 0; slot->pending_off = 0;
    }
    for (;;) {
        const struct dirent *de; int64_t d_off; struct rt_linux_dirent64 *rec;
        size_t namlen = 0u, reclen, k;
        if (slot->has_pending) {
            de = &slot->pending; d_off = slot->pending_off;
        } else {
            struct dirent *rde = readdir(slot->dir);
            if (rde == NULL) { break; }
            d_off = (int64_t)telldir(slot->dir);
            slot->pending = *rde; slot->pending_off = d_off; slot->has_pending = 1;
            de = &slot->pending;
        }
        while (de->d_name[namlen] != '\0') { namlen++; }
        reclen = (size_t)((19u + namlen + 1u + 7u) & ~7u);
        if (used + reclen > buf_size) {
            if (used == 0u) { (void)pthread_mutex_unlock(&g_dir_mu); return -22; }
            break;
        }
        slot->has_pending = 0;
        rec = (struct rt_linux_dirent64 *)(out + used);
        rec->d_ino = (uint64_t)de->d_ino; rec->d_off = d_off;
        rec->d_reclen = (uint16_t)reclen; rec->d_type = de->d_type;
        for (k = 0u; k <= namlen; k++) { rec->d_name[k] = de->d_name[k]; }
        for (k = namlen + 1u; k < reclen - 19u; k++) { rec->d_name[k] = '\0'; }
        used += reclen;
    }
    (void)pthread_mutex_unlock(&g_dir_mu);
    return (int64_t)used;
}
int64_t rt_host_fcntl(int fd, int linux_cmd, uint64_t arg) {
    if (linux_cmd == 1030) {
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
    darwin_dir_invalidate(newfd);
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
    if (flags != 0u) { return -38; }
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
    if (dirfd != RT_LINUX_AT_FDCWD || flags != 0) { return -38; }
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

/* 6. networking (S64-4: sockaddr conversions) */
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
    struct sockaddr_storage dar; socklen_t dlen = 0u;
    int rc = darwin_sockaddr_from_linux(linux_addr, addrlen, &dar, &dlen);
    return rc != 0 ? rc : libret(bind(fd, (const struct sockaddr *)&dar, dlen));
}
int64_t rt_host_connect(int fd, const void *linux_addr, uint32_t addrlen, rt_worker_sync_t *ws, uint32_t expected_seq) {
    struct sockaddr_storage dar; socklen_t dlen = 0u;
    struct darwin_fdop a; int64_t r; int err = 0; socklen_t errlen = (socklen_t)sizeof(err);
    int rc = darwin_sockaddr_from_linux(linux_addr, addrlen, &dar, &dlen);
    if (rc != 0) { return rc; }
    a.fd = fd; a.flags = 0; a.kind = RT_FDOP_CONNECT;
    a.buf = NULL; a.len = 0u; a.addr = &dar; a.addrlen = dlen; a.addrlenp = NULL;
    r = darwin_spin_fd(fd, 1, ws, expected_seq, &a);
    if (r != 0) { return r; }
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &errlen) == 0 && err != 0) { return -(int64_t)err; }
    return 0;
}
int64_t rt_host_listen(int fd, int backlog) { return libret(listen(fd, backlog)); }
int64_t rt_host_accept4(int fd, void *linux_addr_out, uint32_t *addrlen_inout, int linux_flags, rt_worker_sync_t *ws, uint32_t expected_seq) {
    struct sockaddr_storage dar; socklen_t dlen = (socklen_t)sizeof(dar);
    struct darwin_fdop a = { fd, 0, RT_FDOP_ACCEPT, linux_addr_out != NULL ? &dar : NULL, 0u, NULL, 0u, linux_addr_out != NULL ? &dlen : NULL };
    int64_t r; int cloexec, nonblock;
    if ((linux_flags & ~(02000000 | 04000)) != 0) { return -22; }
    if (darwin_socktype(linux_flags | 1, &cloexec, &nonblock) < 0) { return -22; }
    darwin_nonblock(fd);
    r = darwin_spin_fd(fd, 0, ws, expected_seq, &a);
    if (r >= 0) {
        darwin_flag_fd((int)r, cloexec, nonblock);
        if (linux_addr_out != NULL && addrlen_inout != NULL) { darwin_sockaddr_to_linux(&dar, dlen, linux_addr_out, addrlen_inout); }
    }
    return r;
}
int64_t rt_host_sendto(int fd, const void *buf, size_t len, int linux_flags, const void *linux_dest_addr, uint32_t addrlen, rt_worker_sync_t *ws, uint32_t expected_seq) {
    struct sockaddr_storage dar; socklen_t dlen = 0u; const void *dptr = NULL; struct darwin_fdop a;
    if (linux_dest_addr != NULL) {
        int rc = darwin_sockaddr_from_linux(linux_dest_addr, addrlen, &dar, &dlen);
        if (rc != 0) { return rc; }
        dptr = &dar;
    }
    a.fd = fd; a.flags = linux_flags; a.kind = RT_FDOP_SENDTO;
    a.buf = (void *)buf; a.len = len; a.addr = dptr; a.addrlen = dlen; a.addrlenp = NULL;
    return darwin_spin_fd(fd, 1, ws, expected_seq, &a);
}
int64_t rt_host_recvfrom(int fd, void *buf, size_t len, int linux_flags, void *linux_src_addr_out, uint32_t *addrlen_inout, rt_worker_sync_t *ws, uint32_t expected_seq) {
    struct sockaddr_storage dar; socklen_t dlen = (socklen_t)sizeof(dar);
    struct darwin_fdop a = { fd, linux_flags, RT_FDOP_RECVFROM, buf, len, linux_src_addr_out != NULL ? &dar : NULL, 0u, linux_src_addr_out != NULL ? &dlen : NULL };
    int64_t r = darwin_spin_fd(fd, 0, ws, expected_seq, &a);
    if (r >= 0 && linux_src_addr_out != NULL && addrlen_inout != NULL) { darwin_sockaddr_to_linux(&dar, dlen, linux_src_addr_out, addrlen_inout); }
    return r;
}
int64_t rt_host_getsockname(int fd, void *linux_addr_out, uint32_t *addrlen_inout) {
    struct sockaddr_storage dar; socklen_t dlen = (socklen_t)sizeof(dar);
    if (linux_addr_out == NULL || addrlen_inout == NULL) { return -22; }
    if (getsockname(fd, (struct sockaddr *)&dar, &dlen) != 0) { return neg_errno(); }
    darwin_sockaddr_to_linux(&dar, dlen, linux_addr_out, addrlen_inout); return 0;
}
int64_t rt_host_getpeername(int fd, void *linux_addr_out, uint32_t *addrlen_inout) {
    struct sockaddr_storage dar; socklen_t dlen = (socklen_t)sizeof(dar);
    if (linux_addr_out == NULL || addrlen_inout == NULL) { return -22; }
    if (getpeername(fd, (struct sockaddr *)&dar, &dlen) != 0) { return neg_errno(); }
    darwin_sockaddr_to_linux(&dar, dlen, linux_addr_out, addrlen_inout); return 0;
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

/* S64-8: honor timeout when nfds==0 and apply/restore linux_sigmask. */
static void darwin_sigmask_enter(const uint64_t *linux_sigmask, sigset_t *saved_out, int *have_saved_out) {
    sigset_t set; unsigned sig;
    *have_saved_out = 0;
    if (linux_sigmask == NULL) { return; }
    (void)sigemptyset(&set);
    for (sig = 1u; sig <= 64u; sig++) {
        if ((*linux_sigmask & (UINT64_C(1) << (sig - 1u))) != 0u) {
            int dsig = rt_darwin_signo((int)sig);
            if (dsig > 0) { (void)sigaddset(&set, dsig); }
        }
    }
    if (pthread_sigmask(SIG_SETMASK, &set, saved_out) == 0) { *have_saved_out = 1; }
}
static void darwin_sigmask_leave(const sigset_t *saved, int have_saved) {
    if (have_saved) { (void)pthread_sigmask(SIG_SETMASK, saved, NULL); }
}
int64_t rt_host_ppoll(void *linux_pollfds, size_t nfds, const struct timespec *rel_timeout, const uint64_t *linux_sigmask, rt_worker_sync_t *ws, uint32_t expected_seq) {
    struct pollfd *fds = NULL; sigset_t saved_mask; int have_saved = 0, timeout_ms = -1, r, has_wake = 0; size_t i, total = nfds;
    if (linux_sigmask != NULL && (ws == NULL || ws->wake_pipe_rd < 0)) { return -22; }
    if (ws != NULL && atomic_load_explicit(&ws->sig_seq, memory_order_acquire) != expected_seq) { return -4; }
    if (ws != NULL && ws->wake_pipe_rd >= 0) { total++; has_wake = 1; }
    if (rel_timeout != NULL) {
        if (rel_timeout->tv_nsec < 0 || rel_timeout->tv_nsec >= 1000000000L) { return -22; }
        if (rel_timeout->tv_sec < 0) {
            timeout_ms = 0;
        } else if (rel_timeout->tv_sec > 2147483) {
            timeout_ms = 2147483647;
        } else {
            int64_t ms = (int64_t)rel_timeout->tv_sec * 1000L + (int64_t)rel_timeout->tv_nsec / 1000000L;
            if (ms == 0 && rel_timeout->tv_nsec > 0) { ms = 1; }
            timeout_ms = ms > 2147483647L ? 2147483647 : (int)ms;
        }
    }
    if (total > 0u) {
        fds = (struct pollfd *)malloc(total * sizeof(*fds));
        if (fds == NULL) { return -12; }
        for (i = 0u; i < nfds; i++) { (void)memcpy(&fds[i], (const char *)linux_pollfds + i * sizeof(*fds), sizeof(*fds)); }
        if (has_wake) { fds[nfds].fd = ws->wake_pipe_rd; fds[nfds].events = POLLIN; fds[nfds].revents = 0; }
    }
    darwin_sigmask_enter(linux_sigmask, &saved_mask, &have_saved);
    if (ws != NULL && atomic_load_explicit(&ws->sig_seq, memory_order_acquire) != expected_seq) {
        darwin_sigmask_leave(&saved_mask, have_saved);
        free(fds);
        return -4;
    }
    r = poll(fds, (nfds_t)total, timeout_ms);
    darwin_sigmask_leave(&saved_mask, have_saved);
    if (r < 0) { int e = errno; free(fds); return -(int64_t)e; }
    if (has_wake && (fds[nfds].revents & POLLIN) != 0) { char tmp[32]; (void)read(ws->wake_pipe_rd, tmp, sizeof(tmp)); free(fds); return -4; }
    if (ws != NULL && atomic_load_explicit(&ws->sig_seq, memory_order_acquire) != expected_seq) { free(fds); return -4; }
    if (r > 0 && nfds > 0u) { for (i = 0u; i < nfds; i++) { (void)memcpy((char *)linux_pollfds + i * sizeof(*fds), &fds[i], sizeof(*fds)); } }
    free(fds); return (int64_t)r;
}
/* Minimal epoll-over-kqueue emulation */
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
    struct kevent *evlist, wake_ev; struct timespec ts, *tsp = NULL; sigset_t saved_mask;
    int have_saved = 0, has_wake = 0, n, got = 0; unsigned i, j;
    if (slot == NULL || linux_epoll_events_out == NULL || maxevents <= 0) { return -22; }
    if (linux_sigmask != NULL && (ws == NULL || ws->wake_pipe_rd < 0)) { return -22; }
    if (maxevents > 1024) { maxevents = 1024; }
    if (ws != NULL && atomic_load_explicit(&ws->sig_seq, memory_order_acquire) != expected_seq) { return -4; }
    evlist = (struct kevent *)malloc((size_t)maxevents * sizeof(*evlist));
    if (evlist == NULL) { return -12; }
    if (ws != NULL && ws->wake_pipe_rd >= 0) {
        EV_SET(&wake_ev, (uintptr_t)ws->wake_pipe_rd, EVFILT_READ, EV_ADD | EV_ENABLE, 0, 0, NULL);
        if (kevent(slot->kq, &wake_ev, 1, NULL, 0, NULL) == 0) { has_wake = 1; }
    }
    if (timeout_ms >= 0) { ts.tv_sec = timeout_ms / 1000; ts.tv_nsec = (long)(timeout_ms % 1000) * 1000000L; tsp = &ts; }
    darwin_sigmask_enter(linux_sigmask, &saved_mask, &have_saved);
    if (ws != NULL && atomic_load_explicit(&ws->sig_seq, memory_order_acquire) != expected_seq) {
        darwin_sigmask_leave(&saved_mask, have_saved);
        if (has_wake) { EV_SET(&wake_ev, (uintptr_t)ws->wake_pipe_rd, EVFILT_READ, EV_DELETE, 0, 0, NULL); (void)kevent(slot->kq, &wake_ev, 1, NULL, 0, NULL); }
        free(evlist);
        return -4;
    }
    n = kevent(slot->kq, NULL, 0, evlist, maxevents, tsp);
    darwin_sigmask_leave(&saved_mask, have_saved);
    if (has_wake) { EV_SET(&wake_ev, (uintptr_t)ws->wake_pipe_rd, EVFILT_READ, EV_DELETE, 0, 0, NULL); (void)kevent(slot->kq, &wake_ev, 1, NULL, 0, NULL); }
    if (n < 0) { int e = errno; free(evlist); return -(int64_t)e; }
    for (i = 0u; i < (unsigned)n; i++) {
        unsigned char *dst = (unsigned char *)linux_epoll_events_out + (size_t)got * 12u;
        uint32_t e32 = 0u; uint64_t d64 = 0u; int fd = (int)evlist[i].ident, matched = 0;
        for (j = 0u; j < RT_EPOLL_INTERESTS; j++) { if (slot->interests[j].fd == fd) { d64 = slot->interests[j].data; matched = 1; break; } }
        if (!matched && has_wake && fd == ws->wake_pipe_rd) {
            char tmp[32]; (void)read(ws->wake_pipe_rd, tmp, sizeof(tmp)); free(evlist); return -4;
        }
        if (evlist[i].filter == EVFILT_READ) { e32 |= 0x1u; } else if (evlist[i].filter == EVFILT_WRITE) { e32 |= 0x4u; }
        if ((evlist[i].flags & EV_ERROR) != 0u) { e32 |= 0x8u | 0x10u; }
        (void)memcpy(dst, &e32, sizeof(e32)); (void)memcpy(dst + 4u, &d64, sizeof(d64)); got++;
    }
    free(evlist);
    if (ws != NULL && atomic_load_explicit(&ws->sig_seq, memory_order_acquire) != expected_seq) { return -4; }
    return (int64_t)got;
}
#else /* not macOS-arm64: no symbols, keeps -pedantic quiet */
typedef int rt_host_darwin_unused_t;
#endif /* defined(__APPLE__) && defined(__aarch64__) */
