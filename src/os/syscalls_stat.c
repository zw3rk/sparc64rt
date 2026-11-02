/*
 * src/os/syscalls_stat.c — SPARC64 stat/stat64/statx syscalls (S64-14 split)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Extracted from src/os/syscalls_ext.c so every TU stays well under the
 * 900-line ceiling. Converts host fstatat/fstat/statx into the big-endian
 * SPARC64 stat, stat64, and asm-generic statx layouts.
 */
#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
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
#include "os/sigframe_sparc64rt.h"
#include "os/syscalls_ext.h"
#include "os/syscalls_min.h"

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
