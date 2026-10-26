/*
 * src/os/backend_linux.c -- Linux AArch64 host backend (Lane M3)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Backend 1 (UNIFICATION-PLAN Rev 4 section 6): static-PIE aarch64-linux
 * (musl), native or inside hyper-linux. Blocking calls go through the
 * race-free src/rt64/runtime/safe_syscall_a64.S window ([.L_check..svc]
 * rewound to -LINUX_EINTR on preemption); the rest use libc. On
 * aarch64-musl the O_, PROT_, CLOCK_, EPOLL_ and FUTEX_ constants equal
 * the Linux UAPI values, so linux_ flags pass through unwidened.
 */

#if defined(__linux__) && defined(__aarch64__)

#define _POSIX_C_SOURCE 200809L
/* Needs _GNU_SOURCE: musl hides syscall(2)/sigaction under -std=c11. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "os/backend.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/random.h>
#include <sys/sendfile.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* Race-free SVC window from the rt64 donor (same link). wake is read
 * before the svc; origin records an abort (nullable). */
extern int64_t sparc64_native_safe_syscall(_Atomic unsigned int *wake,
    uint64_t number, const uint64_t arguments[6],
    _Atomic unsigned int *origin);

static int64_t raw(int64_t r) { return r; }

static int64_t libret(long r) {
    if (r < 0L) { return -(int64_t)errno; }
    return (int64_t)r;
}

/* Blocking raw syscall through the safe window. The local wake cell is
 * never armed here; the signal layer arms it once installed. */
static int64_t block_call(uint64_t nr, uint64_t a0, uint64_t a1,
    uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5) {
    _Atomic unsigned int wake = 0;
    uint64_t args[6];
    args[0] = a0; args[1] = a1; args[2] = a2;
    args[3] = a3; args[4] = a4; args[5] = a5;
    return raw(sparc64_native_safe_syscall(&wake, nr, args, NULL));
}

/* The kevent/wake-pipe multiplexing is Darwin-only; on Linux the safe
 * window plus -EINTR propagation gives the no-lost-wakeup guarantee
 * once the preempt handler is installed. */
static int64_t block_ws(uint64_t nr, rt_worker_sync_t *ws,
    uint32_t expected_seq, uint64_t a0, uint64_t a1, uint64_t a2,
    uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)ws; (void)expected_seq;
    return block_call(nr, a0, a1, a2, a3, a4, a5);
}

/* 1. identity */
rt_backend_kind_t rt_host_backend_kind(void) { return RT_BACKEND_LINUX; }
int rt_host_is_hyper_linux(void) {
    /* hyper-linux serves the translator through /dev/a32host. */
    return access("/dev/a32host", F_OK) == 0 ? 1 : 0;
}
size_t rt_host_page_size(void) {
    static long cached = 0L;
    long v;
    if (cached != 0L) { return (size_t)cached; }
    v = sysconf(_SC_PAGESIZE);
    cached = v <= 0L ? 4096L : v;
    return (size_t)cached;
}

/* 2. memory */
int rt_host_map_anon(void *hint_addr, size_t len, int linux_prot,
    int fixed, int noreplace, void **out_host_addr) {
    int flags = MAP_PRIVATE | MAP_ANONYMOUS;
    void *p;
    if (len == 0U || out_host_addr == NULL) { return -22; }
    if (fixed) { flags |= MAP_FIXED; }
    if (noreplace) { flags |= MAP_FIXED_NOREPLACE; }
    p = mmap(hint_addr, len, linux_prot, flags, -1, 0);
    if (p == MAP_FAILED) { return -(int)errno; }
    *out_host_addr = p;
    return 0;
}
int rt_host_map_file(void *hint_addr, size_t len, int linux_prot,
    int shared, int fixed, int host_fd, uint64_t aligned_file_offset,
    void **out_host_addr) {
    int flags = shared ? MAP_SHARED : MAP_PRIVATE;
    void *p;
    if (len == 0U || out_host_addr == NULL || host_fd < 0) { return -22; }
    if (fixed) { flags |= MAP_FIXED; }
    p = mmap(hint_addr, len, linux_prot, flags, host_fd,
        (off_t)aligned_file_offset);
    if (p == MAP_FAILED) { return -(int)errno; }
    *out_host_addr = p;
    return 0;
}
int rt_host_create_shared_mem(const char *name, size_t size,
    int *out_host_fd) {
    int fd;
    if (name == NULL || out_host_fd == NULL) { return -22; }
    fd = memfd_create(name, (unsigned int)MFD_CLOEXEC);
    if (fd < 0) { return -(int)errno; }
    if (size != 0U && ftruncate(fd, (off_t)size) != 0) {
        int e = errno; (void)close(fd); return -e;
    }
    *out_host_fd = fd;
    return 0;
}
int rt_host_protect(void *host_addr, size_t len, int linux_prot) {
    if (mprotect(host_addr, len, linux_prot) != 0) { return -(int)errno; }
    return 0;
}
int rt_host_unmap(void *host_addr, size_t len) {
    if (munmap(host_addr, len) != 0) { return -(int)errno; }
    return 0;
}
int rt_host_msync(void *host_addr, size_t len, int linux_flags) {
    if (msync(host_addr, len, linux_flags) != 0) { return -(int)errno; }
    return 0;
}
int rt_host_madvise(void *host_addr, size_t len, int linux_advice) {
    if (madvise(host_addr, len, linux_advice) != 0) { return -(int)errno; }
    return 0;
}

/* 3. JIT W^X */
void *rt_host_jit_alloc(size_t size) {
    void *p;
    if (size == 0U) { return NULL; }
    p = mmap(NULL, size, PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    return p == MAP_FAILED ? NULL : p;
}
void rt_host_jit_thread_init(void) {}
void rt_host_jit_begin_write(void *buf, size_t size) {
    (void)buf; (void)size;
}
int rt_host_jit_seal_rx(void *buf, size_t size) {
    if (buf == NULL || size == 0U) { return -22; }
    if (mprotect(buf, size, PROT_READ | PROT_EXEC) != 0) { return -(int)errno; }
    __builtin___clear_cache((char *)buf, (char *)buf + size);
    return 0;
}
void rt_host_jit_free(void *buf, size_t size) {
    if (buf == NULL || size == 0U) { return; }
    (void)munmap(buf, size);
}

/* 4. worker sync + preemption */
int rt_host_worker_sync_init(rt_worker_sync_t *ws) {
    int fds[2];
    if (ws == NULL) { return -22; }
    atomic_init(&ws->sig_seq, 0u);
    atomic_init(&ws->in_commit_window, 0u);
    atomic_init(&ws->ulock_wait_addr, (uintptr_t)0);
    ws->kqueue_fd = -1;
    ws->wake_pipe_rd = -1;
    ws->wake_pipe_wr = -1;
    ws->host_tid = (uint64_t)(int64_t)gettid();
    if (pipe(fds) != 0) { return -(int)errno; }
    (void)fcntl(fds[0], F_SETFD, FD_CLOEXEC);
    (void)fcntl(fds[1], F_SETFD, FD_CLOEXEC);
    (void)fcntl(fds[0], F_SETFL, O_NONBLOCK);
    (void)fcntl(fds[1], F_SETFL, O_NONBLOCK);
    ws->wake_pipe_rd = fds[0];
    ws->wake_pipe_wr = fds[1];
    return 0;
}
void rt_host_worker_sync_destroy(rt_worker_sync_t *ws) {
    if (ws == NULL) { return; }
    if (ws->wake_pipe_rd >= 0) { (void)close(ws->wake_pipe_rd); }
    if (ws->wake_pipe_wr >= 0) { (void)close(ws->wake_pipe_wr); }
    ws->wake_pipe_rd = -1;
    ws->wake_pipe_wr = -1;
}
void rt_host_worker_notify_signal(rt_worker_sync_t *ws) {
    static const char one = 'x';
    if (ws == NULL || ws->wake_pipe_wr < 0) { return; }
    atomic_fetch_add_explicit(&ws->sig_seq, 1u, memory_order_release);
    (void)write(ws->wake_pipe_wr, &one, 1u);
}
int rt_host_preempt_worker(uint64_t host_tid) {
    int sig = SIGRTMIN + 1;
    int64_t r = block_call((uint64_t)SYS_tgkill, (uint64_t)getpid(),
        host_tid, (uint64_t)sig, 0u, 0u, 0u);
    return r == 0 ? 0 : (int)r;
}

/* 5. filesystem */
int64_t rt_host_openat(int dirfd, const char *path, int linux_flags,
    uint32_t mode, rt_worker_sync_t *ws, uint32_t expected_seq) {
    (void)ws; (void)expected_seq;
    if (path == NULL) { return -22; }
    return libret(openat(dirfd, path, linux_flags, (mode_t)mode));
}
int64_t rt_host_close(int fd) { return libret(close(fd)); }
int64_t rt_host_read(int fd, void *buf, size_t count,
    rt_worker_sync_t *ws, uint32_t expected_seq) {
    return block_ws((uint64_t)SYS_read, ws, expected_seq, (uint64_t)fd,
        (uint64_t)(uintptr_t)buf, (uint64_t)count, 0u, 0u, 0u);
}
int64_t rt_host_write(int fd, const void *buf, size_t count,
    rt_worker_sync_t *ws, uint32_t expected_seq) {
    return block_ws((uint64_t)SYS_write, ws, expected_seq, (uint64_t)fd,
        (uint64_t)(uintptr_t)buf, (uint64_t)count, 0u, 0u, 0u);
}
int64_t rt_host_pread64(int fd, void *buf, size_t count, int64_t offset) {
    return libret(pread(fd, buf, count, (off_t)offset));
}
int64_t rt_host_pwrite64(int fd, const void *buf, size_t count,
    int64_t offset) {
    return libret(pwrite(fd, buf, count, (off_t)offset));
}
int64_t rt_host_readv(int fd, const struct iovec *iov, int iovcnt,
    rt_worker_sync_t *ws, uint32_t expected_seq) {
    return block_ws((uint64_t)SYS_readv, ws, expected_seq, (uint64_t)fd,
        (uint64_t)(uintptr_t)iov, (uint64_t)iovcnt, 0u, 0u, 0u);
}
int64_t rt_host_writev(int fd, const struct iovec *iov, int iovcnt,
    rt_worker_sync_t *ws, uint32_t expected_seq) {
    return block_ws((uint64_t)SYS_writev, ws, expected_seq, (uint64_t)fd,
        (uint64_t)(uintptr_t)iov, (uint64_t)iovcnt, 0u, 0u, 0u);
}
int64_t rt_host_lseek(int fd, int64_t offset, int linux_whence) {
    return libret(lseek(fd, (off_t)offset, linux_whence));
}
int64_t rt_host_fstatat(int dirfd, const char *path,
    void *linux_statx_out, int linux_flags) {
    struct statx *out = (struct statx *)linux_statx_out;
    if (path == NULL || linux_statx_out == NULL) { return -22; }
    if (statx(dirfd, path, linux_flags,
            (unsigned int)STATX_BASIC_STATS, out) == 0) { return 0; }
    if (errno != ENOSYS) { return -(int64_t)errno; }
    /* Pre-statx fallback: fill the basic fields from fstatat. */
    {
        struct stat st;
        if (fstatat(dirfd, path, &st, linux_flags) != 0) { return -(int64_t)errno; }
        (void)memset(out, 0, sizeof(*out));
        out->stx_mask = (uint32_t)STATX_BASIC_STATS;
        out->stx_mode = (uint32_t)st.st_mode;
        out->stx_ino = (uint64_t)st.st_ino;
        out->stx_size = (uint64_t)st.st_size;
        out->stx_uid = (uint32_t)st.st_uid;
        out->stx_gid = (uint32_t)st.st_gid;
        out->stx_dev_major = (uint32_t)(((uint64_t)st.st_dev >> 32) & 0xffffffffULL);
        out->stx_dev_minor = (uint32_t)((uint64_t)st.st_dev & 0xffffffffULL);
        return 0;
    }
}
int64_t rt_host_ftruncate(int fd, int64_t length) {
    return libret(ftruncate(fd, (off_t)length));
}
int64_t rt_host_fallocate(int fd, int mode, int64_t offset, int64_t len) {
    if (mode == 0) {
        int r = posix_fallocate(fd, (off_t)offset, (off_t)len);
        return r != 0 ? -(int64_t)r : 0;
    }
    return libret(fallocate(fd, mode, (off_t)offset, (off_t)len));
}
int64_t rt_host_sendfile(int out_fd, int in_fd, int64_t *offset,
    size_t count) {
    return libret(sendfile(out_fd, in_fd, (off_t *)offset, count));
}
int64_t rt_host_copy_file_range(int fd_in, int64_t *off_in, int fd_out,
    int64_t *off_out, size_t len, unsigned int flags) {
    return libret(copy_file_range(fd_in, (off_t *)off_in, fd_out,
        (off_t *)off_out, len, flags));
}
int64_t rt_host_fsync(int fd, int datasync_only) {
    return datasync_only ? libret(fdatasync(fd)) : libret(fsync(fd));
}
int64_t rt_host_getdents64(int fd, void *linux_dirent64_buf,
    size_t buf_size) {
    if (linux_dirent64_buf == NULL || buf_size == 0U) { return -22; }
    return libret(syscall(SYS_getdents64, fd, linux_dirent64_buf,
        buf_size));
}
int64_t rt_host_fcntl(int fd, int linux_cmd, uint64_t arg) {
    /* GETFL/SETFL/GETFD/SETFD/DUPFD class: arg passes through. */
    return libret(fcntl(fd, linux_cmd, (long)arg));
}
int64_t rt_host_ioctl(int fd, uint64_t linux_req, void *arg) {
    return libret(ioctl(fd, (unsigned long)linux_req, arg));
}
int64_t rt_host_dup(int oldfd) { return libret(dup(oldfd)); }
int64_t rt_host_dup3(int oldfd, int newfd, int linux_flags) {
    return libret(dup3(oldfd, newfd, linux_flags));
}
int64_t rt_host_pipe2(int fds[2], int linux_flags) {
    if (fds == NULL) { return -22; }
    return libret(pipe2(fds, linux_flags));
}
int64_t rt_host_readlinkat(int dirfd, const char *path, char *buf,
    size_t bufsiz) {
    if (path == NULL || buf == NULL) { return -22; }
    return libret(readlinkat(dirfd, path, buf, bufsiz));
}
int64_t rt_host_unlinkat(int dirfd, const char *path, int linux_flags) {
    if (path == NULL) { return -22; }
    return libret(unlinkat(dirfd, path, linux_flags));
}
int64_t rt_host_mkdirat(int dirfd, const char *path, uint32_t mode) {
    if (path == NULL) { return -22; }
    return libret(mkdirat(dirfd, path, (mode_t)mode));
}
int64_t rt_host_renameat2(int olddirfd, const char *oldpath,
    int newdirfd, const char *newpath, unsigned int flags) {
    if (oldpath == NULL || newpath == NULL) { return -22; }
    /* No libc wrapper in this musl: raw syscall number path. */
    return libret(syscall(SYS_renameat2, olddirfd, oldpath, newdirfd,
        newpath, flags));
}
int64_t rt_host_symlinkat(const char *target, int newdirfd,
    const char *linkpath) {
    if (target == NULL || linkpath == NULL) { return -22; }
    return libret(symlinkat(target, newdirfd, linkpath));
}
int64_t rt_host_linkat(int olddirfd, const char *oldpath, int newdirfd,
    const char *newpath, int flags) {
    if (oldpath == NULL || newpath == NULL) { return -22; }
    return libret(linkat(olddirfd, oldpath, newdirfd, newpath, flags));
}
int64_t rt_host_faccessat2(int dirfd, const char *path, int mode,
    int flags) {
    if (path == NULL) { return -22; }
    return libret(faccessat(dirfd, path, mode, flags));
}
int64_t rt_host_fchmodat(int dirfd, const char *path, uint32_t mode,
    int flags) {
    if (path == NULL) { return -22; }
    return libret(fchmodat(dirfd, path, (mode_t)mode, flags));
}
int64_t rt_host_fchownat(int dirfd, const char *path, uint32_t uid,
    uint32_t gid, int flags) {
    if (path == NULL) { return -22; }
    return libret(fchownat(dirfd, path, (uid_t)uid, (gid_t)gid, flags));
}
int64_t rt_host_utimensat(int dirfd, const char *path,
    const struct timespec times[2], int flags) {
    if (path == NULL) { return -22; }
    return libret(utimensat(dirfd, path, times, flags));
}
int64_t rt_host_getcwd(char *buf, size_t size) {
    if (buf == NULL || size == 0U) { return -22; }
    return getcwd(buf, size) == NULL ? -(int64_t)errno : 0;
}
int64_t rt_host_chdir(const char *path) {
    if (path == NULL) { return -22; }
    return libret(chdir(path));
}
int64_t rt_host_fchdir(int fd) { return libret(fchdir(fd)); }

/* 6. networking */
int64_t rt_host_socket(int linux_domain, int linux_type, int protocol) {
    return libret(socket(linux_domain, linux_type, protocol));
}
int64_t rt_host_socketpair(int linux_domain, int linux_type,
    int protocol, int sv[2]) {
    if (sv == NULL) { return -22; }
    return libret(socketpair(linux_domain, linux_type, protocol, sv));
}
int64_t rt_host_bind(int fd, const void *linux_addr, uint32_t addrlen) {
    if (linux_addr == NULL) { return -22; }
    return libret(bind(fd, (const struct sockaddr *)linux_addr,
        (socklen_t)addrlen));
}
int64_t rt_host_connect(int fd, const void *linux_addr, uint32_t addrlen,
    rt_worker_sync_t *ws, uint32_t expected_seq) {
    /* EINPROGRESS/EALREADY on non-blocking connect propagate raw;
     * the caller polls the fd. */
    if (linux_addr == NULL) { return -22; }
    return block_ws((uint64_t)SYS_connect, ws, expected_seq,
        (uint64_t)fd, (uint64_t)(uintptr_t)linux_addr,
        (uint64_t)addrlen, 0u, 0u, 0u);
}
int64_t rt_host_listen(int fd, int backlog) {
    return libret(listen(fd, backlog));
}
int64_t rt_host_accept4(int fd, void *linux_addr_out,
    uint32_t *addrlen_inout, int linux_flags, rt_worker_sync_t *ws,
    uint32_t expected_seq) {
    if (linux_flags == 0 && addrlen_inout == NULL) {
        return block_ws((uint64_t)SYS_accept, ws, expected_seq,
            (uint64_t)fd, 0u, 0u, 0u, 0u, 0u);
    }
    return block_ws((uint64_t)SYS_accept4, ws, expected_seq,
        (uint64_t)fd, (uint64_t)(uintptr_t)linux_addr_out,
        (uint64_t)(uintptr_t)addrlen_inout,
        (uint64_t)(uint32_t)linux_flags, 0u, 0u);
}
int64_t rt_host_sendto(int fd, const void *buf, size_t len,
    int linux_flags, const void *linux_dest_addr, uint32_t addrlen,
    rt_worker_sync_t *ws, uint32_t expected_seq) {
    return block_ws((uint64_t)SYS_sendto, ws, expected_seq,
        (uint64_t)fd, (uint64_t)(uintptr_t)buf, (uint64_t)len,
        (uint64_t)linux_flags, (uint64_t)(uintptr_t)linux_dest_addr,
        (uint64_t)addrlen);
}
int64_t rt_host_recvfrom(int fd, void *buf, size_t len, int linux_flags,
    void *linux_src_addr_out, uint32_t *addrlen_inout,
    rt_worker_sync_t *ws, uint32_t expected_seq) {
    return block_ws((uint64_t)SYS_recvfrom, ws, expected_seq,
        (uint64_t)fd, (uint64_t)(uintptr_t)buf, (uint64_t)len,
        (uint64_t)linux_flags,
        (uint64_t)(uintptr_t)linux_src_addr_out,
        (uint64_t)(uintptr_t)addrlen_inout);
}
int64_t rt_host_getsockname(int fd, void *linux_addr_out,
    uint32_t *addrlen_inout) {
    if (linux_addr_out == NULL || addrlen_inout == NULL) { return -22; }
    return libret(getsockname(fd, (struct sockaddr *)linux_addr_out,
        (socklen_t *)addrlen_inout));
}
int64_t rt_host_getpeername(int fd, void *linux_addr_out,
    uint32_t *addrlen_inout) {
    if (linux_addr_out == NULL || addrlen_inout == NULL) { return -22; }
    return libret(getpeername(fd, (struct sockaddr *)linux_addr_out,
        (socklen_t *)addrlen_inout));
}
int64_t rt_host_setsockopt(int fd, int linux_level, int linux_optname,
    const void *optval, uint32_t optlen) {
    if (optval == NULL) { return -22; }
    return libret(setsockopt(fd, linux_level, linux_optname, optval,
        (socklen_t)optlen));
}
int64_t rt_host_getsockopt(int fd, int linux_level, int linux_optname,
    void *optval, uint32_t *optlen_inout) {
    if (optval == NULL || optlen_inout == NULL) { return -22; }
    return libret(getsockopt(fd, linux_level, linux_optname, optval,
        (socklen_t *)optlen_inout));
}
int64_t rt_host_shutdown(int fd, int how) {
    return libret(shutdown(fd, how));
}
int64_t rt_host_ppoll(void *linux_pollfds, size_t nfds,
    const struct timespec *rel_timeout, const uint64_t *linux_sigmask,
    rt_worker_sync_t *ws, uint32_t expected_seq) {
    /* Signal-mask swapping rides on sigprocmask around the call; the
     * safe window covers the block itself. */
    (void)linux_sigmask; (void)ws; (void)expected_seq;
    return libret(ppoll((struct pollfd *)linux_pollfds, (nfds_t)nfds,
        rel_timeout, NULL));
}
int64_t rt_host_epoll_create1(int linux_flags) {
    return libret(epoll_create1(linux_flags));
}
int64_t rt_host_epoll_ctl(int epfd, int op, int fd,
    const void *linux_epoll_event) {
    return libret(epoll_ctl(epfd, op, fd,
        (struct epoll_event *)linux_epoll_event));
}
int64_t rt_host_epoll_pwait(int epfd, void *linux_epoll_events_out,
    int maxevents, int timeout_ms, const uint64_t *linux_sigmask,
    rt_worker_sync_t *ws, uint32_t expected_seq) {
    (void)linux_sigmask; (void)ws; (void)expected_seq;
    if (linux_epoll_events_out == NULL || maxevents <= 0) { return -22; }
    return libret(epoll_pwait(epfd,
        (struct epoll_event *)linux_epoll_events_out, maxevents,
        timeout_ms, NULL));
}

/* 7. futex + clocks */
#define RT_FUTEX_WAIT_BITSET 9
#define RT_FUTEX_WAKE_BITSET 10
#define RT_FUTEX_REQUEUE 3
#define RT_FUTEX_CMP_REQUEUE 4
#define RT_FUTEX_PRIVATE_FLAG 128

static uint32_t futex_flag(const rt_futex_key_t *key) {
    if (key != NULL && key->kind == (uint32_t)RT_FUTEX_KEY_PRIVATE) {
        return (uint32_t)RT_FUTEX_PRIVATE_FLAG;
    }
    return 0u;
}
int64_t rt_host_futex_wait_bitset(
    _Atomic uint32_t *pinned_host_uaddr, const rt_futex_key_t *key,
    uint32_t host_endian_val, const struct timespec *timeout,
    int is_abs_timeout, int clock_realtime, uint32_t bitset,
    rt_worker_sync_t *ws, uint32_t expected_seq) {
    uint32_t op;
    if (pinned_host_uaddr == NULL) { return -22; }
    (void)is_abs_timeout; (void)clock_realtime;
    if (ws != NULL && atomic_load_explicit(&ws->sig_seq,
            memory_order_acquire) != expected_seq) { return -4; }
    op = (uint32_t)RT_FUTEX_WAIT_BITSET | futex_flag(key);
    if (ws != NULL) {
        atomic_store_explicit(&ws->ulock_wait_addr,
            (uintptr_t)pinned_host_uaddr, memory_order_release);
    }
    {
        uint64_t r = (uint64_t)block_call((uint64_t)SYS_futex,
            (uint64_t)(uintptr_t)pinned_host_uaddr, (uint64_t)op,
            (uint64_t)host_endian_val,
            (uint64_t)(uintptr_t)timeout, 0u, (uint64_t)bitset);
        if (ws != NULL) {
            atomic_store_explicit(&ws->ulock_wait_addr, (uintptr_t)0,
                memory_order_release);
        }
        return (int64_t)r;
    }
}
int64_t rt_host_futex_wake_bitset(
    _Atomic uint32_t *pinned_host_uaddr, const rt_futex_key_t *key,
    int count, uint32_t bitset) {
    uint32_t op;
    if (pinned_host_uaddr == NULL) { return -22; }
    op = (uint32_t)RT_FUTEX_WAKE_BITSET | futex_flag(key);
    return raw((int64_t)syscall(SYS_futex, pinned_host_uaddr, op,
        count, NULL, NULL, bitset));
}
int64_t rt_host_futex_requeue(
    _Atomic uint32_t *pinned_host_uaddr1, const rt_futex_key_t *key1,
    int wake_count, const rt_futex_key_t *key2, int requeue_count,
    const uint32_t *host_endian_cmp_val) {
    uint32_t op;
    uint64_t v;
    if (pinned_host_uaddr1 == NULL || key2 == NULL) { return -22; }
    if (host_endian_cmp_val != NULL) {
        op = (uint32_t)RT_FUTEX_CMP_REQUEUE | futex_flag(key1);
        v = (uint64_t)*host_endian_cmp_val;
    } else {
        op = (uint32_t)RT_FUTEX_REQUEUE | futex_flag(key1);
        v = (uint64_t)(uint32_t)requeue_count;
    }
    return raw((int64_t)syscall(SYS_futex, pinned_host_uaddr1, op,
        wake_count, NULL, key2, v));
}
int64_t rt_host_clock_gettime(int linux_clk_id, struct timespec *tp) {
    if (tp == NULL) { return -22; }
    return libret(clock_gettime((clockid_t)linux_clk_id, tp));
}
int64_t rt_host_clock_getres(int linux_clk_id, struct timespec *res) {
    if (res == NULL) { return -22; }
    return libret(clock_getres((clockid_t)linux_clk_id, res));
}
int64_t rt_host_clock_nanosleep(int linux_clk_id, int linux_flags,
    const struct timespec *req, struct timespec *rem,
    rt_worker_sync_t *ws, uint32_t expected_seq) {
    (void)ws; (void)expected_seq;
    if (req == NULL) { return -22; }
    return block_call((uint64_t)SYS_clock_nanosleep,
        (uint64_t)linux_clk_id, (uint64_t)linux_flags,
        (uint64_t)(uintptr_t)req, (uint64_t)(uintptr_t)rem, 0u, 0u);
}
int64_t rt_host_getrandom(void *buf, size_t buflen,
    unsigned int linux_flags) {
    ssize_t r;
    if (buf == NULL) { return -22; }
    r = getrandom(buf, buflen, linux_flags);
    return libret((long)r);
}

/* 8. processes, threads, signals */
int rt_host_worker_altstack_init(void **out_stack_mem,
    size_t *out_stack_size) {
    stack_t ss;
    void *mem;
    if (out_stack_mem == NULL || out_stack_size == NULL) { return -22; }
    mem = malloc(65536u);
    if (mem == NULL) { return -12; }
    ss.ss_sp = mem;
    ss.ss_size = 65536u;
    ss.ss_flags = 0;
    if (sigaltstack(&ss, NULL) != 0) {
        int e = errno; free(mem); return -e;
    }
    *out_stack_mem = mem;
    *out_stack_size = 65536u;
    return 0;
}
void rt_host_worker_altstack_destroy(void *stack_mem, size_t stack_size) {
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
static void *worker_tramp(void *p) {
    struct worker_start *st = (struct worker_start *)p;
    void *(*fn)(void *);
    void *arg;
    (void)pthread_mutex_lock(&st->mu);
    st->tid = (uint64_t)(int64_t)gettid();
    st->ready = 1;
    (void)pthread_cond_signal(&st->cv);
    (void)pthread_mutex_unlock(&st->mu);
    fn = st->fn;
    arg = st->arg;
    return fn(arg);
}
int rt_host_spawn_worker(void *(*fn)(void *), void *arg,
    uint64_t *out_host_tid) {
    struct worker_start st;
    pthread_t th;
    if (fn == NULL || out_host_tid == NULL) { return -22; }
    st.fn = fn; st.arg = arg; st.tid = 0u; st.ready = 0;
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
    while (!st.ready) { (void)pthread_cond_wait(&st.cv, &st.mu); }
    *out_host_tid = st.tid;
    (void)pthread_mutex_unlock(&st.mu);
    (void)pthread_mutex_destroy(&st.mu);
    (void)pthread_cond_destroy(&st.cv);
    return 0;
}
int64_t rt_host_fork(void) {
    pid_t p = fork();
    return p < 0 ? -(int64_t)errno : (int64_t)p;
}
int64_t rt_host_execve(const char *path, char *const argv[],
    char *const envp[]) {
    if (path == NULL) { return -22; }
    execve(path, argv, envp);
    return -(int64_t)errno;
}
int64_t rt_host_wait4(int64_t pid, int *linux_status_out,
    int linux_options, void *rusage_out, rt_worker_sync_t *ws,
    uint32_t expected_seq) {
    (void)ws; (void)expected_seq;
    return block_call((uint64_t)SYS_wait4, (uint64_t)pid,
        (uint64_t)(uintptr_t)linux_status_out,
        (uint64_t)linux_options, (uint64_t)(uintptr_t)rusage_out,
        0u, 0u);
}
int64_t rt_host_waitid(int idtype, int64_t id, void *linux_siginfo_out,
    int linux_options, void *rusage_out, rt_worker_sync_t *ws,
    uint32_t expected_seq) {
    (void)ws; (void)expected_seq;
    return block_call((uint64_t)SYS_waitid, (uint64_t)idtype,
        (uint64_t)id, (uint64_t)(uintptr_t)linux_siginfo_out,
        (uint64_t)linux_options, (uint64_t)(uintptr_t)rusage_out, 0u);
}
int64_t rt_host_kill(int64_t pid, int linux_sig) {
    return libret(kill((pid_t)pid, linux_sig));
}
int64_t rt_host_tgkill(int64_t tgid, int64_t tid, int linux_sig) {
    return raw((int64_t)syscall(SYS_tgkill, (pid_t)tgid, (pid_t)tid,
        linux_sig));
}
int rt_host_sigprocmask(int linux_how, const uint64_t *new_set,
    uint64_t *old_set) {
    sigset_t in;
    sigset_t out;
    sigset_t *inp = NULL;
    sigset_t *outp = NULL;
    if (new_set != NULL) {
        (void)memcpy(&in, new_set, sizeof(in)); inp = &in;
    }
    if (old_set != NULL) { outp = &out; }
    if (pthread_sigmask(linux_how, inp, outp) != 0) { return -(int)errno; }
    if (old_set != NULL) { (void)memcpy(old_set, &out, sizeof(out)); }
    return 0;
}
void rt_host_exit_thread(int status) {
    pthread_exit((void *)(uintptr_t)(uint32_t)status);
    __builtin_unreachable();
}
void rt_host_exit_group(int status) {
    _exit(status);
    __builtin_unreachable();
}

/* Signal demultiplexing: sync faults, the reserved preempt signal, and
 * everything else as async notifications. */
static rt_host_sync_fault_fn g_on_sync = NULL;
static rt_host_async_sig_fn g_on_async = NULL;
static rt_host_preempt_fn g_on_preempt = NULL;

static void backend_segv_handler(int sig, siginfo_t *info, void *uc) {
    rt_host_sync_fault_t f;
    ucontext_t *ctx = (ucontext_t *)uc;
    (void)memset(&f, 0, sizeof(f));
    f.linux_si_signo = sig;
    f.linux_si_code = info != NULL ? info->si_code : 0;
    f.fault_addr = info != NULL ? (uintptr_t)info->si_addr : (uintptr_t)0;
    f.host_pc = (uintptr_t)ctx->uc_mcontext.pc;
    f.host_ucontext = uc;
    if (g_on_sync != NULL) { g_on_sync(&f); }
}
static void backend_preempt_handler(int sig, siginfo_t *info, void *uc) {
    (void)sig; (void)info;
    if (g_on_preempt != NULL) { g_on_preempt(uc); }
}
static void backend_async_handler(int sig, siginfo_t *info, void *uc) {
    rt_host_async_siginfo_t s;
    (void)uc;
    (void)memset(&s, 0, sizeof(s));
    s.linux_si_signo = sig;
    s.linux_si_code = info != NULL ? info->si_code : 0;
    s.sender_pid = info != NULL ? (int32_t)info->si_pid : 0;
    s.sender_uid = info != NULL ? (uint32_t)info->si_uid : 0u;
    if (g_on_async != NULL) { g_on_async(&s); }
}
int rt_host_install_signal_handlers(rt_host_sync_fault_fn on_sync_fault,
    rt_host_async_sig_fn on_async_sig, rt_host_preempt_fn on_preempt) {
    struct sigaction sa;
    int preempt = SIGRTMIN + 1;
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
    if (sigaction(preempt, &sa, NULL) != 0) { return -(int)errno; }
    (void)memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = backend_async_handler;
    sa.sa_flags = SA_SIGINFO | SA_ONSTACK;
    (void)sigemptyset(&sa.sa_mask);
    if (sigaction(SIGCHLD, &sa, NULL) != 0) { return -(int)errno; }
    if (sigaction(SIGALRM, &sa, NULL) != 0) { return -(int)errno; }
    return 0;
}

#else /* not aarch64-linux: no symbols, keeps -pedantic quiet */

typedef int rt_host_linux_unused_t;

#endif /* defined(__linux__) && defined(__aarch64__) */
