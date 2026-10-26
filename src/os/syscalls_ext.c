/*
 * src/os/syscalls_ext.c — Phase-2 static-libc syscalls (lane L2a).
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Extends the Phase-1 dispatch in src/os/syscalls_min.c (frozen numbers
 * in src/os/syscall_nr.h, E02 dual-carry convention: success clears both
 * carry bits, error sets both, pc = npc; npc += 4). Handlers return
 * host-style results (>= 0 value, negative host errno); the commit in
 * syscalls_min.c applies unchanged, so this file needs no errno table.
 * Guest memory moves only through the mem callbacks (no host pointer
 * ever leaks to the guest); every struct field is big-endian.
 *
 * Needs _GNU_SOURCE: musl hides syscall(2)/clock_gettime under -std=c11.
 */
#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>

#if defined(__linux__)
#include <sys/syscall.h>
#endif

/* macOS <sys/stat.h> #defines st_atime/mtime/ctime over the frozen
 * sigframe header field names; drop them here (this TU only). */
#ifdef st_atime
#undef st_atime
#endif
#ifdef st_mtime
#undef st_mtime
#endif
#ifdef st_ctime
#undef st_ctime
#endif

#include "core/cpu.h"
#include "os/guest_proc.h"
#include "os/guest_interp_map.h"
#include "os/sigframe_sparc64rt.h"
#include "os/syscall_nr.h"
#include "os/syscalls_ext.h"
#include "os/syscalls_min.h"

/* SPARC open flags (arch/sparc fcntl.h, shared 32/64-bit); low 2 access
 * bits match the host. */
#define SP_O_APPEND 0x0008U
#define SP_O_CREAT 0x0200U
#define SP_O_TRUNC 0x0400U
#define SP_O_EXCL 0x0800U
#define SP_O_DSYNC 0x2000U
#define SP_O_SYNC 0x802000U
#define SP_O_NONBLOCK 0x4000U
#define SP_O_NDELAY 0x4004U
#define SP_O_NOCTTY 0x8000U
#define SP_O_LARGEFILE 0x40000U
#define SP_O_DIRECTORY 0x10000U
#define SP_O_NOFOLLOW 0x20000U
#define SP_O_DIRECT 0x100000U
#define SP_O_NOATIME 0x200000U
#define SP_O_CLOEXEC 0x400000U
#define SP_O_PATH 0x1000000U
#define SP_O_TMPFILE 0x2010000U

#define SP_F_DUPFD 0U
#define SP_F_GETFD 1U
#define SP_F_SETFD 2U
#define SP_F_GETFL 3U
#define SP_F_SETFL 4U

/* TCGETS on sparc encodes the 36-byte termios (_IOR('T', 8)); TIOCGWINSZ
 * is uniform across Linux architectures. */
#define SP_TCGETS 0x80245408U
#define SP_TIOCGWINSZ 0x40087468U

#define SP_FUTEX_WAIT 0U
#define SP_FUTEX_WAKE 1U

/* SPARC rt_sigprocmask how values (NOT the generic 0/1/2). */
#define SP_SIG_BLOCK 1U
#define SP_SIG_UNBLOCK 2U
#define SP_SIG_SETMASK 4U

/* SP_AT_* live in syscalls_ext.h (shared with syscalls_dirent.c). */

#define SP_CLOCK_REALTIME 0U
#define SP_CLOCK_MONOTONIC 1U

#define SP_GRND_NONBLOCK 0x0001U
#define SP_GRND_RANDOM 0x0002U
#define SP_GRND_INSECURE 0x0004U

/* L2A_PATH_MAX and SP_AT_* live in syscalls_ext.h now. */
#define L2A_IOV_MAX 1024U
#define L2A_CHUNK 4096U

/* Blocked mask is file-static (single-threaded); delivery stays Phase
 * 1/4 machinery in src/os/sync_sig.c. */
static uint64_t l2a_blocked = UINT64_C(0);

/* Host stat times: macOS uses st_*timespec, Linux st_*tim. */
static void host_times(const struct stat *h, int which, int64_t *sec,
    int64_t *nsec)
{
#if defined(__APPLE__)
    const struct timespec *t = (which == 0) ? &h->st_atimespec :
        ((which == 1) ? &h->st_mtimespec : &h->st_ctimespec);
#else
    const struct timespec *t = (which == 0) ? &h->st_atim :
        ((which == 1) ? &h->st_mtim : &h->st_ctim);
#endif
    *sec = (int64_t)t->tv_sec;
    *nsec = (int64_t)t->tv_nsec;
}

/* SPARC O_* -> host O_*. Unknown bits are EINVAL; O_DSYNC maps to O_SYNC. */
static long open_flags_to_host(uint64_t guest, int *host_out)
{
    uint64_t rest = guest & ~3U;
    size_t i;
    int h = (int)(guest & 3U);
    static const struct {
        uint64_t guest;
        int host;
    } map[] = {
        { SP_O_APPEND, O_APPEND }, { SP_O_CREAT, O_CREAT },
        { SP_O_TRUNC, O_TRUNC }, { SP_O_EXCL, O_EXCL },
        { SP_O_NONBLOCK, O_NONBLOCK }, { SP_O_NDELAY, O_NONBLOCK },
        { SP_O_NOCTTY, O_NOCTTY }, { SP_O_DIRECTORY, O_DIRECTORY },
        { SP_O_NOFOLLOW, O_NOFOLLOW }, { SP_O_CLOEXEC, O_CLOEXEC },
#ifdef O_LARGEFILE
        { SP_O_LARGEFILE, O_LARGEFILE },
#endif
#ifdef O_DIRECT
        { SP_O_DIRECT, O_DIRECT },
#endif
#ifdef O_NOATIME
        { SP_O_NOATIME, O_NOATIME },
#endif
#ifdef O_PATH
        { SP_O_PATH, O_PATH },
#endif
#ifdef O_TMPFILE
        { SP_O_TMPFILE, O_TMPFILE },
#endif
    };
    if ((rest & (SP_O_SYNC | SP_O_DSYNC)) != 0U) {
#ifdef O_SYNC
        h |= O_SYNC;
        rest &= ~(uint64_t)(SP_O_SYNC | SP_O_DSYNC);
#else
        return -EINVAL;
#endif
    }
    for (i = 0U; i < sizeof(map) / sizeof(map[0]); i++) {
        if ((rest & map[i].guest) != 0U) {
            h |= map[i].host;
            rest &= ~map[i].guest;
        }
    }
#ifndef O_LARGEFILE
    rest &= ~(uint64_t)SP_O_LARGEFILE; /* 64-bit hosts: always largefile */
#endif
    if (rest != 0U) {
        return -EINVAL;
    }
    *host_out = h;
    return 0;
}

long sparc64_l2a_openat(sparc64_ctx_t *ctx, const sparc64_syscall_mem_t *mem,
    uint64_t dirfd, uint64_t path_va, uint64_t flags, uint64_t mode)
{
    char path[L2A_PATH_MAX];
    long rc = l2a_copy_cstring(mem, path_va, path, (uint64_t)L2A_PATH_MAX);
    int host_flags;
    int host_dirfd;
    int fd;
    (void)ctx;
    if (rc != 0) {
        return rc;
    }
    rc = open_flags_to_host(flags, &host_flags);
    if (rc != 0) {
        return rc;
    }
    /* Phase 5 L5a: /proc/self files are synthetic (exe/maps/cmdline/
     * stat/auxv); anything else falls through to the host. */
    if (sparc64_guest_proc_handles(path)) {
        return sparc64_guest_proc_openat(mem->context, mem, path,
            host_flags);
    }
    host_dirfd = ((int64_t)dirfd == SP_AT_FDCWD) ? AT_FDCWD : (int)dirfd;
    /* Absolute guest paths try SPARC64RT_SYSROOT first (qemu -L). */
    if (sparc64_sysroot_try_open(host_dirfd, path, host_flags,
            (unsigned)(mode & 0777U), &fd)) {
        return (fd < 0) ? -(long)errno : (long)fd;
    }
    fd = openat(host_dirfd, path, host_flags, (mode_t)(mode & 0777U));
    return (fd < 0) ? -(long)errno : (long)fd;
}

/* open(5) is openat(AT_FDCWD) (same interception included). */
long sparc64_l2a_open(sparc64_ctx_t *ctx, const sparc64_syscall_mem_t *mem,
    uint64_t path_va, uint64_t flags, uint64_t mode)
{
    return sparc64_l2a_openat(ctx, mem, (uint64_t)(int64_t)SP_AT_FDCWD,
        path_va, flags, mode);
}

/* readlinkat(294): synthetic paths served by src/os/guest_proc.c
 * (exe yields argv[0], other synthetic files are EINVAL), the rest
 * is the host readlinkat. */
long sparc64_l2a_readlinkat(sparc64_ctx_t *ctx,
    const sparc64_syscall_mem_t *mem, uint64_t dirfd, uint64_t path_va,
    uint64_t buf_va, uint64_t bufsz)
{
    (void)ctx;
    return sparc64_guest_proc_readlinkat(mem->context, mem, dirfd,
        path_va, buf_va, bufsz);
}

long sparc64_l2a_getpid(void) { return (long)getpid(); }

long sparc64_l2a_getuid(void) { return (long)getuid(); }

long sparc64_l2a_getgid(void) { return (long)getgid(); }

/* readv/writev over guest iovec chains ({BE u64 base, BE u64 len}).
 * Guest pages move through a fixed bounce chunk; a short count ends the
 * walk and partial progress reads as the result, like sys_read/write. */
static long sys_rwvec(sparc64_ctx_t *ctx, const sparc64_syscall_mem_t *mem,
    uint64_t fd, uint64_t iov_va, uint64_t iovcnt, int is_write)
{
    uint8_t chunk[L2A_CHUNK];
    uint64_t total = 0;
    uint64_t i = 0;
    (void)ctx;
    if (iovcnt > (uint64_t)L2A_IOV_MAX) {
        return -EINVAL;
    }
    if (iovcnt == 0U) {
        return 0;
    }
    if (l2a_range_ok(iov_va, iovcnt * 16U) != 0) {
        return -EFAULT;
    }
    for (i = 0U; i < iovcnt; i++) {
        uint8_t e[16];
        uint64_t base;
        uint64_t len;
        uint64_t done = 0;
        if (!mem->read(mem->context, iov_va + i * 16U, e, (uint64_t)sizeof(e))) {
            return (total != 0U) ? (long)total : -EFAULT;
        }
        base = l2a_get_be64(e);
        len = l2a_get_be64(e + 8);
        if (l2a_range_ok(base, len) != 0) {
            return (total != 0U) ? (long)total : -EFAULT;
        }
        while (done < len) {
            uint64_t want = len - done;
            ssize_t got;
            if (want > (uint64_t)sizeof(chunk)) {
                want = (uint64_t)sizeof(chunk);
            }
            if (is_write) {
                if (!mem->read(mem->context, base + done, chunk, want)) {
                    return (total != 0U) ? (long)total : -EFAULT;
                }
                /* S2 hook point: host op runs first (Step 3); the
                 * coordinator lands vm_file_commit_resize here (Step 4)
                 * once the family table + truncate dispatch exist. */
                got = write((int)fd, chunk, (size_t)want);
                if (got <= 0) {
                    if (got == 0) {
                        return (long)total;
                    }
                    return (total != 0U) ? (long)total : -(long)errno;
                }
            } else {
                if (!mem->prepare_write(mem->context, base + done, want)) {
                    return (total != 0U) ? (long)total : -EFAULT;
                }
                got = read((int)fd, chunk, (size_t)want);
                if (got < 0) {
                    return (total != 0U) ? (long)total : -(long)errno;
                }
                if (got == 0) {
                    return (long)total;
                }
                if (!mem->write(mem->context, base + done, chunk,
                        (uint64_t)got)) {
                    return (total != 0U) ? (long)total : -EFAULT;
                }
            }
            done += (uint64_t)got;
            total += (uint64_t)got;
            if ((uint64_t)got < want) {
                return (long)total;
            }
        }
    }
    return (long)total;
}

long sparc64_l2a_readv(sparc64_ctx_t *ctx, const sparc64_syscall_mem_t *mem,
    uint64_t fd, uint64_t iov_va, uint64_t iovcnt)
{
    return sys_rwvec(ctx, mem, fd, iov_va, iovcnt, 0);
}

long sparc64_l2a_writev(sparc64_ctx_t *ctx, const sparc64_syscall_mem_t *mem,
    uint64_t fd, uint64_t iov_va, uint64_t iovcnt)
{
    return sys_rwvec(ctx, mem, fd, iov_va, iovcnt, 1);
}

/* stat family: host fstatat/fstat converted into the frozen BE layouts. */
#define PUT16(off, expr) do { long _v = (expr); \
    if (_v < 0) { return _v; } l2a_put_be16(b + (off), (uint16_t)_v); } while (0)
#define PUT32(off, expr) do { long _v = (expr); \
    if (_v < 0) { return _v; } l2a_put_be32(b + (off), (uint32_t)_v); } while (0)

static long store_stat(const sparc64_syscall_mem_t *mem, uint64_t va,
    const struct stat *h)
{
    uint8_t b[sizeof(sparc64_stat_t)];
    int64_t sec;
    int64_t nsec;
    memset(b, 0, sizeof(b));
    PUT32(offsetof(sparc64_stat_t, st_dev), l2a_narrow_u32((uint64_t)h->st_dev));
    l2a_put_be64(b + offsetof(sparc64_stat_t, st_ino), (uint64_t)h->st_ino);
    l2a_put_be32(b + offsetof(sparc64_stat_t, st_mode), (uint32_t)h->st_mode);
    PUT16(offsetof(sparc64_stat_t, st_nlink),
        l2a_narrow_s16((int64_t)h->st_nlink));
    PUT32(offsetof(sparc64_stat_t, st_uid), l2a_narrow_u32((uint64_t)h->st_uid));
    PUT32(offsetof(sparc64_stat_t, st_gid), l2a_narrow_u32((uint64_t)h->st_gid));
    PUT32(offsetof(sparc64_stat_t, st_rdev),
        l2a_narrow_u32((uint64_t)h->st_rdev));
    l2a_put_be64(b + offsetof(sparc64_stat_t, st_size),
        (uint64_t)(int64_t)h->st_size);
    host_times(h, 0, &sec, &nsec);
    l2a_put_be64(b + offsetof(sparc64_stat_t, st_atime), (uint64_t)sec);
    host_times(h, 1, &sec, &nsec);
    l2a_put_be64(b + offsetof(sparc64_stat_t, st_mtime), (uint64_t)sec);
    host_times(h, 2, &sec, &nsec);
    l2a_put_be64(b + offsetof(sparc64_stat_t, st_ctime), (uint64_t)sec);
    l2a_put_be64(b + offsetof(sparc64_stat_t, st_blksize),
        (uint64_t)(int64_t)h->st_blksize);
    l2a_put_be64(b + offsetof(sparc64_stat_t, st_blocks),
        (uint64_t)(int64_t)h->st_blocks);
    return l2a_store_buf(mem, va, b, (uint64_t)sizeof(b));
}

static long store_stat64(const sparc64_syscall_mem_t *mem, uint64_t va,
    const struct stat *h)
{
    uint8_t b[sizeof(sparc64_stat64_t)];
    int64_t sec;
    int64_t nsec;
    memset(b, 0, sizeof(b));
    l2a_put_be64(b + offsetof(sparc64_stat64_t, st_dev), (uint64_t)h->st_dev);
    l2a_put_be64(b + offsetof(sparc64_stat64_t, st_ino), (uint64_t)h->st_ino);
    l2a_put_be64(b + offsetof(sparc64_stat64_t, st_nlink), (uint64_t)h->st_nlink);
    l2a_put_be32(b + offsetof(sparc64_stat64_t, st_mode), (uint32_t)h->st_mode);
    l2a_put_be32(b + offsetof(sparc64_stat64_t, st_uid), (uint32_t)h->st_uid);
    l2a_put_be32(b + offsetof(sparc64_stat64_t, st_gid), (uint32_t)h->st_gid);
    l2a_put_be64(b + offsetof(sparc64_stat64_t, st_rdev), (uint64_t)h->st_rdev);
    l2a_put_be64(b + offsetof(sparc64_stat64_t, st_size),
        (uint64_t)(int64_t)h->st_size);
    l2a_put_be64(b + offsetof(sparc64_stat64_t, st_blksize),
        (uint64_t)(int64_t)h->st_blksize);
    l2a_put_be64(b + offsetof(sparc64_stat64_t, st_blocks),
        (uint64_t)(int64_t)h->st_blocks);
    host_times(h, 0, &sec, &nsec);
    l2a_put_be64(b + offsetof(sparc64_stat64_t, st_atime), (uint64_t)sec);
    l2a_put_be64(b + offsetof(sparc64_stat64_t, st_atime_nsec), (uint64_t)nsec);
    host_times(h, 1, &sec, &nsec);
    l2a_put_be64(b + offsetof(sparc64_stat64_t, st_mtime), (uint64_t)sec);
    l2a_put_be64(b + offsetof(sparc64_stat64_t, st_mtime_nsec), (uint64_t)nsec);
    host_times(h, 2, &sec, &nsec);
    l2a_put_be64(b + offsetof(sparc64_stat64_t, st_ctime), (uint64_t)sec);
    l2a_put_be64(b + offsetof(sparc64_stat64_t, st_ctime_nsec), (uint64_t)nsec);
    return l2a_store_buf(mem, va, b, (uint64_t)sizeof(b));
}

static long sys_stat_path(const sparc64_syscall_mem_t *mem, const char *path,
    int dirfd, int nofollow, uint64_t buf_va, int is64)
{
    struct stat h;
    if (fstatat(dirfd, path, &h, nofollow ? AT_SYMLINK_NOFOLLOW : 0) != 0) {
        return -(long)errno;
    }
    return is64 ? store_stat64(mem, buf_va, &h) : store_stat(mem, buf_va, &h);
}

static long sys_stat_fd(const sparc64_syscall_mem_t *mem, uint64_t fd,
    uint64_t buf_va, int is64)
{
    struct stat h;
    if (fstat((int)fd, &h) != 0) {
        return -(long)errno;
    }
    return is64 ? store_stat64(mem, buf_va, &h) : store_stat(mem, buf_va, &h);
}

long sparc64_l2a_stat(sparc64_ctx_t *ctx, const sparc64_syscall_mem_t *mem,
    uint64_t path_va, uint64_t buf_va)
{
    char path[L2A_PATH_MAX];
    long rc = l2a_copy_cstring(mem, path_va, path, (uint64_t)L2A_PATH_MAX);
    (void)ctx;
    return (rc != 0) ? rc : sys_stat_path(mem, path, AT_FDCWD, 0, buf_va, 0);
}

long sparc64_l2a_lstat(sparc64_ctx_t *ctx, const sparc64_syscall_mem_t *mem,
    uint64_t path_va, uint64_t buf_va)
{
    char path[L2A_PATH_MAX];
    long rc = l2a_copy_cstring(mem, path_va, path, (uint64_t)L2A_PATH_MAX);
    (void)ctx;
    return (rc != 0) ? rc : sys_stat_path(mem, path, AT_FDCWD, 1, buf_va, 0);
}

long sparc64_l2a_fstat(sparc64_ctx_t *ctx, const sparc64_syscall_mem_t *mem,
    uint64_t fd, uint64_t buf_va)
{
    (void)ctx;
    return sys_stat_fd(mem, fd, buf_va, 0);
}

long sparc64_l2a_stat64(sparc64_ctx_t *ctx, const sparc64_syscall_mem_t *mem,
    uint64_t path_va, uint64_t buf_va)
{
    char path[L2A_PATH_MAX];
    long rc = l2a_copy_cstring(mem, path_va, path, (uint64_t)L2A_PATH_MAX);
    (void)ctx;
    return (rc != 0) ? rc : sys_stat_path(mem, path, AT_FDCWD, 0, buf_va, 1);
}

long sparc64_l2a_lstat64(sparc64_ctx_t *ctx, const sparc64_syscall_mem_t *mem,
    uint64_t path_va, uint64_t buf_va)
{
    char path[L2A_PATH_MAX];
    long rc = l2a_copy_cstring(mem, path_va, path, (uint64_t)L2A_PATH_MAX);
    (void)ctx;
    return (rc != 0) ? rc : sys_stat_path(mem, path, AT_FDCWD, 1, buf_va, 1);
}

long sparc64_l2a_fstat64(sparc64_ctx_t *ctx, const sparc64_syscall_mem_t *mem,
    uint64_t fd, uint64_t buf_va)
{
    (void)ctx;
    return sys_stat_fd(mem, fd, buf_va, 1);
}

long sparc64_l2a_fstatat64(sparc64_ctx_t *ctx,
    const sparc64_syscall_mem_t *mem, uint64_t dirfd, uint64_t path_va,
    uint64_t buf_va, uint64_t flags)
{
    char path[L2A_PATH_MAX];
    long rc = l2a_copy_cstring(mem, path_va, path, (uint64_t)L2A_PATH_MAX);
    int host_flags = 0;
    int host_dirfd;
    (void)ctx;
    if (rc != 0) {
        return rc;
    }
    if ((flags & ~(uint64_t)(SP_AT_SYMLINK_NOFOLLOW | SP_AT_NO_AUTOMOUNT |
            SP_AT_EMPTY_PATH)) != 0U) {
        return -EINVAL;
    }
    if ((flags & (uint64_t)SP_AT_SYMLINK_NOFOLLOW) != 0U) {
        host_flags |= AT_SYMLINK_NOFOLLOW;
    }
#ifdef AT_NO_AUTOMOUNT
    if ((flags & (uint64_t)SP_AT_NO_AUTOMOUNT) != 0U) {
        host_flags |= AT_NO_AUTOMOUNT;
    }
#endif
#ifdef AT_EMPTY_PATH
    if ((flags & (uint64_t)SP_AT_EMPTY_PATH) != 0U) {
        host_flags |= AT_EMPTY_PATH;
    }
#endif
    host_dirfd = ((int64_t)dirfd == SP_AT_FDCWD) ? AT_FDCWD : (int)dirfd;
    return sys_stat_path(mem, path, host_dirfd,
        (host_flags & AT_SYMLINK_NOFOLLOW) != 0, buf_va, 1);
}

/* statx: guest is the asm-generic 256 B layout; host via raw SYS_statx. */
enum {
    STX_OFF_MASK = 0, STX_OFF_BLKSIZE = 4, STX_OFF_ATTR = 8,
    STX_OFF_NLINK = 16, STX_OFF_UID = 20, STX_OFF_GID = 24, STX_OFF_MODE = 28,
    STX_OFF_INO = 32, STX_OFF_SIZE = 40, STX_OFF_BLOCKS = 48,
    STX_OFF_ATTRMASK = 56, STX_OFF_ATIME = 64, STX_OFF_BTIME = 80,
    STX_OFF_CTIME = 96, STX_OFF_MTIME = 112, STX_OFF_RDEVMAJ = 128,
    STX_OFF_RDEVMIN = 132, STX_OFF_DEVMAJ = 136, STX_OFF_DEVMIN = 140,
    STX_OFF_MNTID = 144, STX_SIZE = 256
};

#if defined(__linux__) && defined(SYS_statx)
struct l2a_host_statx_ts {
    int64_t tv_sec;
    uint32_t tv_nsec;
    int32_t reserved;
};

struct l2a_host_statx {
    uint32_t stx_mask, stx_blksize;
    uint64_t stx_attributes;
    uint32_t stx_nlink, stx_uid, stx_gid;
    uint16_t stx_mode, spare0[1];
    uint64_t stx_ino, stx_size, stx_blocks, stx_attributes_mask;
    struct l2a_host_statx_ts stx_atime, stx_btime, stx_ctime, stx_mtime;
    uint32_t stx_rdev_major, stx_rdev_minor, stx_dev_major, stx_dev_minor;
    uint64_t stx_mnt_id, spare2, spare3[12];
};

static void put_statx_ts(uint8_t *b, uint64_t off, int64_t sec, uint64_t nsec)
{
    l2a_put_be64(b + off, (sec < 0) ? 0U : (uint64_t)sec);
    l2a_put_be32(b + off + 8U, (uint32_t)nsec);
    l2a_put_be32(b + off + 12U, 0U);
}
#endif

long sparc64_l2a_statx(sparc64_ctx_t *ctx, const sparc64_syscall_mem_t *mem,
    uint64_t dirfd, uint64_t path_va, uint64_t flags, uint64_t mask,
    uint64_t buf_va)
{
#if defined(__linux__) && defined(SYS_statx)
    char path[L2A_PATH_MAX];
    struct l2a_host_statx h;
    uint8_t b[STX_SIZE];
    long rc = l2a_copy_cstring(mem, path_va, path, (uint64_t)L2A_PATH_MAX);
    int host_flags = 0;
    int host_dirfd;
    (void)ctx;
    if (rc != 0) {
        return rc;
    }
    if ((flags & ~(uint64_t)(SP_AT_SYMLINK_NOFOLLOW | SP_AT_NO_AUTOMOUNT |
            SP_AT_EMPTY_PATH | SP_AT_STATX_SYNC_TYPE)) != 0U) {
        return -EINVAL;
    }
    if ((flags & (uint64_t)SP_AT_SYMLINK_NOFOLLOW) != 0U) {
        host_flags |= AT_SYMLINK_NOFOLLOW;
    }
#ifdef AT_NO_AUTOMOUNT
    if ((flags & (uint64_t)SP_AT_NO_AUTOMOUNT) != 0U) {
        host_flags |= AT_NO_AUTOMOUNT;
    }
#endif
#ifdef AT_EMPTY_PATH
    if ((flags & (uint64_t)SP_AT_EMPTY_PATH) != 0U) {
        host_flags |= AT_EMPTY_PATH;
    }
#endif
    host_flags |= (int)(flags & (uint64_t)SP_AT_STATX_SYNC_TYPE);
    host_dirfd = ((int64_t)dirfd == SP_AT_FDCWD) ? AT_FDCWD : (int)dirfd;
    memset(&h, 0, sizeof(h));
    if (syscall(SYS_statx, host_dirfd, path, host_flags, (unsigned int)mask,
            &h) != 0) {
        return ((long)errno == 0) ? -ENOSYS : -(long)errno;
    }
    memset(b, 0, sizeof(b));
    l2a_put_be32(b + STX_OFF_MASK, h.stx_mask);
    l2a_put_be32(b + STX_OFF_BLKSIZE, h.stx_blksize);
    l2a_put_be64(b + STX_OFF_ATTR, h.stx_attributes);
    l2a_put_be32(b + STX_OFF_NLINK, h.stx_nlink);
    l2a_put_be32(b + STX_OFF_UID, h.stx_uid);
    l2a_put_be32(b + STX_OFF_GID, h.stx_gid);
    l2a_put_be16(b + STX_OFF_MODE, h.stx_mode);
    l2a_put_be64(b + STX_OFF_INO, h.stx_ino);
    l2a_put_be64(b + STX_OFF_SIZE, h.stx_size);
    l2a_put_be64(b + STX_OFF_BLOCKS, h.stx_blocks);
    l2a_put_be64(b + STX_OFF_ATTRMASK, h.stx_attributes_mask);
    put_statx_ts(b, STX_OFF_ATIME, h.stx_atime.tv_sec, h.stx_atime.tv_nsec);
    put_statx_ts(b, STX_OFF_BTIME, h.stx_btime.tv_sec, h.stx_btime.tv_nsec);
    put_statx_ts(b, STX_OFF_CTIME, h.stx_ctime.tv_sec, h.stx_ctime.tv_nsec);
    put_statx_ts(b, STX_OFF_MTIME, h.stx_mtime.tv_sec, h.stx_mtime.tv_nsec);
    l2a_put_be32(b + STX_OFF_RDEVMAJ, h.stx_rdev_major);
    l2a_put_be32(b + STX_OFF_RDEVMIN, h.stx_rdev_minor);
    l2a_put_be32(b + STX_OFF_DEVMAJ, h.stx_dev_major);
    l2a_put_be32(b + STX_OFF_DEVMIN, h.stx_dev_minor);
    l2a_put_be64(b + STX_OFF_MNTID, h.stx_mnt_id);
    return l2a_store_buf(mem, buf_va, b, (uint64_t)sizeof(b));
#else
    (void)ctx; (void)mem; (void)dirfd; (void)path_va;
    (void)flags; (void)mask; (void)buf_va;
    return -ENOSYS;
#endif
}

static long flags_host_to_guest(int host)
{
    uint64_t g = (uint64_t)(host & 3);
    if ((host & O_APPEND) != 0) {
        g |= (uint64_t)SP_O_APPEND;
    }
    if ((host & O_NONBLOCK) != 0) {
        g |= (uint64_t)SP_O_NONBLOCK;
    }
#ifdef O_SYNC
    if ((host & O_SYNC) != 0) {
        g |= (uint64_t)SP_O_SYNC;
    }
#endif
    return (long)g;
}

long sparc64_l2a_fcntl(uint64_t fd, uint64_t cmd, uint64_t arg)
{
    int rc;
    switch (cmd) {
    case SP_F_DUPFD:
        rc = fcntl((int)fd, F_DUPFD, (int)arg);
        return (rc < 0) ? -(long)errno : (long)rc;
    case SP_F_GETFD:
        rc = fcntl((int)fd, F_GETFD);
        return (rc < 0) ? -(long)errno : (long)rc;
    case SP_F_SETFD:
        return (fcntl((int)fd, F_SETFD, (int)arg) != 0) ? -(long)errno : 0;
    case SP_F_GETFL:
        rc = fcntl((int)fd, F_GETFL);
        return (rc < 0) ? -(long)errno : flags_host_to_guest(rc);
    case SP_F_SETFL: {
        int host = 0;
        if ((arg & ~((uint64_t)SP_O_NONBLOCK | (uint64_t)SP_O_APPEND)) != 0U) {
            return -EINVAL; /* only O_NONBLOCK|O_APPEND are settable */
        }
        if ((arg & (uint64_t)SP_O_APPEND) != 0U) {
            host |= O_APPEND;
        }
        if ((arg & (uint64_t)SP_O_NONBLOCK) != 0U) {
            host |= O_NONBLOCK;
        }
        return (fcntl((int)fd, F_SETFL, host) != 0) ? -(long)errno : 0;
    }
    default:
        return -EINVAL;
    }
}

/* Guest timespec is BE s64 tv_sec + BE s64 tv_nsec (16 B, 64-bit). */
static long store_timespec(const sparc64_syscall_mem_t *mem, uint64_t tp_va,
    const struct timespec *ts)
{
    uint8_t b[16];
    if (ts->tv_sec < 0) {
        return -EOVERFLOW;
    }
    memset(b, 0, sizeof(b));
    l2a_put_be64(b, (uint64_t)ts->tv_sec);
    l2a_put_be64(b + 8U, (uint64_t)ts->tv_nsec);
    return l2a_store_buf(mem, tp_va, b, (uint64_t)sizeof(b));
}

static long sys_clock_get(sparc64_ctx_t *ctx, const sparc64_syscall_mem_t *mem,
    uint64_t clk_id, uint64_t tp_va, int is_res)
{
    struct timespec ts;
    clockid_t host_clk;
    (void)ctx;
    switch (clk_id) {
    case SP_CLOCK_REALTIME: host_clk = CLOCK_REALTIME; break;
    case SP_CLOCK_MONOTONIC: host_clk = CLOCK_MONOTONIC; break;
    default: return -EINVAL;
    }
    if (l2a_range_ok(tp_va, 16U) != 0) {
        return -EFAULT;
    }
    if (is_res ? clock_getres(host_clk, &ts) != 0 :
            clock_gettime(host_clk, &ts) != 0) {
        return -(long)errno;
    }
    return store_timespec(mem, tp_va, &ts);
}

long sparc64_l2a_clock_gettime(sparc64_ctx_t *ctx,
    const sparc64_syscall_mem_t *mem, uint64_t clk_id, uint64_t tp_va)
{
    return sys_clock_get(ctx, mem, clk_id, tp_va, 0);
}

long sparc64_l2a_clock_getres(sparc64_ctx_t *ctx,
    const sparc64_syscall_mem_t *mem, uint64_t clk_id, uint64_t tp_va)
{
    return sys_clock_get(ctx, mem, clk_id, tp_va, 1);
}

/* Guest timeval is BE s64 tv_sec + BE s64 tv_usec (16 B, 64-bit); the
 * obsolete tz pointer is accepted and ignored like Linux. */
long sparc64_l2a_gettimeofday(sparc64_ctx_t *ctx,
    const sparc64_syscall_mem_t *mem, uint64_t tv_va, uint64_t tz_va)
{
    struct timeval tv;
    uint8_t b[16];
    (void)ctx;
    (void)tz_va;
    if (tv_va == 0U) {
        return 0;
    }
    if (l2a_range_ok(tv_va, (uint64_t)sizeof(b)) != 0) {
        return -EFAULT;
    }
    if (gettimeofday(&tv, NULL) != 0) {
        return -(long)errno;
    }
    if (tv.tv_sec < 0 || tv.tv_usec < 0) {
        return -EOVERFLOW;
    }
    memset(b, 0, sizeof(b));
    l2a_put_be64(b, (uint64_t)tv.tv_sec);
    l2a_put_be64(b + 8U, (uint64_t)tv.tv_usec);
    return l2a_store_buf(mem, tv_va, b, (uint64_t)sizeof(b));
}

long sparc64_l2a_getrandom(sparc64_ctx_t *ctx,
    const sparc64_syscall_mem_t *mem, uint64_t buf_va, uint64_t len,
    uint64_t flags)
{
#if defined(__linux__) && defined(SYS_getrandom)
    uint8_t chunk[L2A_CHUNK];
    uint64_t done = 0;
    (void)ctx;
    if ((flags & ~(uint64_t)(SP_GRND_NONBLOCK | SP_GRND_RANDOM |
            SP_GRND_INSECURE)) != 0U) {
        return -EINVAL;
    }
    if (l2a_range_ok(buf_va, len) != 0) {
        return -EFAULT;
    }
    while (done < len) {
        uint64_t want = len - done;
        long rc;
        if (want > (uint64_t)sizeof(chunk)) {
            want = (uint64_t)sizeof(chunk);
        }
        rc = syscall(SYS_getrandom, chunk, (size_t)want, (unsigned int)flags);
        if (rc < 0) {
            return (done != 0U) ? (long)done : -(long)errno;
        }
        if (rc == 0) {
            return (long)done;
        }
        if (!mem->prepare_write(mem->context, buf_va + done, (uint64_t)rc)) {
            return (done != 0U) ? (long)done : -EFAULT;
        }
        if (!mem->write(mem->context, buf_va + done, chunk, (uint64_t)rc)) {
            return (done != 0U) ? (long)done : -EFAULT;
        }
        done += (uint64_t)rc;
    }
    return (long)done;
#else
    (void)ctx; (void)mem; (void)buf_va; (void)len; (void)flags;
    return -ENOSYS;
#endif
}

/* futex WAIT/WAKE via the host futex on a single-threaded mirror word.
 * The guest word is BE; WAIT compares the decoded value against val. */
long sparc64_l2a_futex(sparc64_ctx_t *ctx, const sparc64_syscall_mem_t *mem,
    uint64_t uaddr, uint64_t op, uint64_t val, uint64_t timeout_va)
{
#if defined(__linux__) && defined(SYS_futex)
    uint8_t raw[4];
    uint32_t cur;
    uint32_t mirror;
    uint64_t cmd = op & 127U;
    (void)ctx;
    if (cmd != (uint64_t)SP_FUTEX_WAIT && cmd != (uint64_t)SP_FUTEX_WAKE) {
        return -ENOSYS;
    }
    if (l2a_range_ok(uaddr, (uint64_t)sizeof(raw)) != 0) {
        return -EFAULT;
    }
    if (!mem->read(mem->context, uaddr, raw, (uint64_t)sizeof(raw))) {
        return -EFAULT;
    }
    cur = l2a_get_be32(raw);
    mirror = cur;
    if (cmd == (uint64_t)SP_FUTEX_WAKE) {
        long rc = syscall(SYS_futex, &mirror, (int)op, (int)val, NULL,
            NULL, 0);
        return (rc < 0) ? -(long)errno : rc;
    }
    if (cur != (uint32_t)val) {
        return -EAGAIN;
    }
    if (timeout_va != 0U) {
        uint8_t tp[16];
        int64_t sec;
        int64_t nsec;
        struct timespec ts;
        long rc;
        if (l2a_range_ok(timeout_va, (uint64_t)sizeof(tp)) != 0) {
            return -EFAULT;
        }
        if (!mem->read(mem->context, timeout_va, tp, (uint64_t)sizeof(tp))) {
            return -EFAULT;
        }
        sec = (int64_t)l2a_get_be64(tp);
        nsec = (int64_t)l2a_get_be64(tp + 8);
        if (sec < 0 || nsec < 0 || nsec >= 1000000000L) {
            return -EINVAL;
        }
        ts.tv_sec = (time_t)sec;
        ts.tv_nsec = (long)nsec;
        rc = syscall(SYS_futex, &mirror, (int)op, (int)val, &ts, NULL, 0);
        return (rc < 0) ? -(long)errno : rc;
    }
    /* No timeout and no other thread can wake us: a spurious wakeup. */
    return 0;
#else
    (void)ctx; (void)mem; (void)uaddr; (void)op; (void)val;
    (void)timeout_va;
    return -ENOSYS;
#endif
}

/* rt_sigprocmask bookkeeping only; delivery stays Phase 1/4 machinery. */
long sparc64_l2a_rt_sigprocmask(sparc64_ctx_t *ctx,
    const sparc64_syscall_mem_t *mem, uint64_t how, uint64_t set_va,
    uint64_t oset_va, uint64_t sigsetsize)
{
    uint8_t old[8];
    (void)ctx;
    if (sigsetsize != 8U) {
        return -EINVAL;
    }
    l2a_put_be64(old, l2a_blocked);
    if (set_va != 0U) {
        uint8_t raw[8];
        uint64_t next;
        if (l2a_range_ok(set_va, (uint64_t)sizeof(raw)) != 0) {
            return -EFAULT;
        }
        if (!mem->read(mem->context, set_va, raw, (uint64_t)sizeof(raw))) {
            return -EFAULT;
        }
        next = l2a_get_be64(raw);
        switch (how) {
        case SP_SIG_BLOCK: l2a_blocked |= next; break;
        case SP_SIG_UNBLOCK: l2a_blocked &= ~next; break;
        case SP_SIG_SETMASK: l2a_blocked = next; break;
        default: return -EINVAL;
        }
    } else if (how != (uint64_t)SP_SIG_BLOCK &&
        how != (uint64_t)SP_SIG_UNBLOCK &&
        how != (uint64_t)SP_SIG_SETMASK) {
        return -EINVAL;
    }
    return (oset_va != 0U) ?
        l2a_store_buf(mem, oset_va, old, (uint64_t)sizeof(old)) : 0;
}

/* TCGETS answers as an isatty query (no termios copy: the sparc layout
 * differs from the host); TIOCGWINSZ fills the BE winsize. */
long sparc64_l2a_ioctl(sparc64_ctx_t *ctx, const sparc64_syscall_mem_t *mem,
    uint64_t fd, uint64_t request, uint64_t arg_va)
{
    (void)ctx;
    if (request == (uint64_t)SP_TIOCGWINSZ) {
        struct winsize ws;
        uint8_t b[8];
        if (l2a_range_ok(arg_va, (uint64_t)sizeof(b)) != 0) {
            return -EFAULT;
        }
        if (ioctl((int)fd, TIOCGWINSZ, &ws) != 0) {
            return -(long)errno;
        }
        l2a_put_be16(b, ws.ws_row);
        l2a_put_be16(b + 2U, ws.ws_col);
        l2a_put_be16(b + 4U, ws.ws_xpixel);
        l2a_put_be16(b + 6U, ws.ws_ypixel);
        return l2a_store_buf(mem, arg_va, b, (uint64_t)sizeof(b));
    }
    return (request == (uint64_t)SP_TCGETS) ?
        (isatty((int)fd) ? 0 : -ENOTTY) : -ENOTTY;
}
