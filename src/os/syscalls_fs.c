/*
 * src/os/syscalls_fs.c — Path-mutation, attribute, limit, wait, and
 * accounting syscalls for a real userland (T14 qualification).
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * SPARC64 glibc uses the legacy non-*at numbers (mkdir, rename, link,
 * chmod, ...) plus cwd, poll/select, rlimit, and time-accounting calls
 * that dash, coreutils, tar, git, and gcc all exercise. Handlers
 * return host-style results (>= 0 value, negative host errno); the
 * dual-carry commit in syscalls_min.c applies unchanged. Guest structs
 * are big-endian. Blocking waits drop the big guest lock.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/resource.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/times.h>
#include <time.h>
#include <unistd.h>

#if defined(__APPLE__)
#include <sys/mount.h>
#else
#include <sys/statfs.h>
#endif

#include "core/cpu.h"
#include "os/syscall_nr.h"
#include "os/syscalls_ext.h"
#include "os/syscalls_fs.h"
#include "os/syscalls_poll.h"
#include "os/syscalls_min.h"
#include "os/threads.h"

#define FS_AT_REMOVEDIR 0x200U
#define FS_NFDS_MAX 65536U
#define FS_O_WRONLY 0x1U
#define FS_O_CREAT 0x200U
#define FS_O_TRUNC 0x400U

typedef const sparc64_syscall_mem_t *memp_t;

static long fs_path(memp_t mem, uint64_t va, char *out)
{
    return l2a_copy_cstring(mem, va, out, (uint64_t)L2A_PATH_MAX);
}

static long fs_rd(memp_t mem, uint64_t va, void *buf, uint64_t len)
{
    if (l2a_range_ok(va, len) != 0 || !mem->read(mem->context, va, buf, len)) {
        return -EFAULT;
    }
    return 0;
}

static int fs_dirfd(uint64_t g)
{
    int32_t fd = (int32_t)g; /* the kernel takes an int */

    return fd == (int32_t)SP_AT_FDCWD ? AT_FDCWD : (int)fd;
}

static long fs_ret(int rc)
{
    return rc != 0 ? -(long)errno : 0L;
}

static int fs_nofollow(uint64_t flags)
{
    return (flags & SP_AT_SYMLINK_NOFOLLOW) != 0U ? AT_SYMLINK_NOFOLLOW : 0;
}

static long fs_mkdirat(memp_t mem, uint64_t dirfd, uint64_t pva, uint64_t mode)
{
    char p[L2A_PATH_MAX];
    long rc = fs_path(mem, pva, p);

    return rc != 0 ? rc : fs_ret(mkdirat(fs_dirfd(dirfd), p, (mode_t)mode));
}

/* mknodat: FIFOs and regular files only; the guest dev_t is passed
 * through unchanged (device nodes need privileges the host rarely has). */
static long fs_mknodat(memp_t mem, uint64_t dirfd, uint64_t pva,
                       uint64_t mode, uint64_t dev)
{
    char p[L2A_PATH_MAX];
    long rc = fs_path(mem, pva, p);

    return rc != 0 ? rc : fs_ret(mknodat(fs_dirfd(dirfd), p, (mode_t)mode,
                                         (dev_t)dev));
}

static long fs_unlinkat(memp_t mem, uint64_t dirfd, uint64_t pva,
                        uint64_t flags)
{
    char p[L2A_PATH_MAX];
    long rc = fs_path(mem, pva, p);

    if (rc != 0) {
        return rc;
    }
    if ((flags & ~(uint64_t)FS_AT_REMOVEDIR) != 0U) {
        return -EINVAL;
    }
    return fs_ret(unlinkat(fs_dirfd(dirfd), p,
                           (flags & FS_AT_REMOVEDIR) != 0U ? AT_REMOVEDIR : 0));
}

static long fs_renameat(memp_t mem, uint64_t od, uint64_t op, uint64_t nd,
                        uint64_t np, uint64_t flags)
{
    char a[L2A_PATH_MAX];
    char b[L2A_PATH_MAX];
    long rc = fs_path(mem, op, a);

    if (rc == 0) {
        rc = fs_path(mem, np, b);
    }
    if (rc != 0) {
        return rc;
    }
    if (flags != 0U) {
        return -EINVAL;
    }
    return fs_ret(renameat(fs_dirfd(od), a, fs_dirfd(nd), b));
}

static long fs_linkat(memp_t mem, uint64_t od, uint64_t op, uint64_t nd,
                      uint64_t np, uint64_t flags)
{
    char a[L2A_PATH_MAX];
    char b[L2A_PATH_MAX];
    long rc = fs_path(mem, op, a);

    if (rc == 0) {
        rc = fs_path(mem, np, b);
    }
    if (rc != 0) {
        return rc;
    }
    return fs_ret(linkat(fs_dirfd(od), a, fs_dirfd(nd), b,
                         (flags & 0x400U) != 0U ? AT_SYMLINK_FOLLOW : 0));
}

static long fs_symlinkat(memp_t mem, uint64_t target, uint64_t nd,
                         uint64_t np)
{
    char a[L2A_PATH_MAX];
    char b[L2A_PATH_MAX];
    long rc = fs_path(mem, target, a);

    if (rc == 0) {
        rc = fs_path(mem, np, b);
    }
    return rc != 0 ? rc : fs_ret(symlinkat(a, fs_dirfd(nd), b));
}

static long fs_chmodat(memp_t mem, uint64_t dirfd, uint64_t pva,
                       uint64_t mode)
{
    char p[L2A_PATH_MAX];
    long rc = fs_path(mem, pva, p);

    return rc != 0 ? rc : fs_ret(fchmodat(fs_dirfd(dirfd), p, (mode_t)mode, 0));
}

static long fs_chownat(memp_t mem, uint64_t dirfd, uint64_t pva, uint64_t uid,
                       uint64_t gid, uint64_t flags)
{
    char p[L2A_PATH_MAX];
    long rc = fs_path(mem, pva, p);

    return rc != 0 ? rc
                   : fs_ret(fchownat(fs_dirfd(dirfd), p, (uid_t)uid,
                                     (gid_t)gid, fs_nofollow(flags)));
}

static long fs_chdir(memp_t mem, uint64_t pva)
{
    char p[L2A_PATH_MAX];
    long rc = fs_path(mem, pva, p);

    return rc != 0 ? rc : fs_ret(chdir(p));
}

/* getcwd(2): returns the byte count including the NUL. */
static long fs_getcwd(memp_t mem, uint64_t buf, uint64_t size)
{
    char cwd[L2A_PATH_MAX];
    size_t n;
    long rc;

    if (getcwd(cwd, sizeof cwd) == NULL) {
        return -(long)errno;
    }
    n = strlen(cwd) + 1U;
    if (n > size) {
        return -ERANGE;
    }
    rc = l2a_store_buf(mem, buf, (const uint8_t *)cwd, (uint64_t)n);
    return rc != 0 ? rc : (long)n;
}

/* utimensat(dirfd, path|NULL, struct timespec[2], flags). */
static long fs_utimensat(memp_t mem, uint64_t dirfd, uint64_t pva,
                         uint64_t tva, uint64_t flags)
{
    char p[L2A_PATH_MAX];
    struct timespec ts[2];
    uint8_t g[32];
    long rc = 0;
    int i;

    if (pva != 0U) {
        rc = fs_path(mem, pva, p);
        if (rc != 0) {
            return rc;
        }
    }
    if (tva != 0U) {
        rc = fs_rd(mem, tva, g, sizeof g);
        if (rc != 0) {
            return rc;
        }
        for (i = 0; i < 2; i++) {
            ts[i].tv_sec = (time_t)l2a_get_be64(g + 16 * i);
            ts[i].tv_nsec = (long)l2a_get_be64(g + 16 * i + 8);
        }
    }
    if (pva == 0U) {
        return fs_ret(futimens((int)dirfd, tva != 0U ? ts : NULL));
    }
    return fs_ret(utimensat(fs_dirfd(dirfd), p, tva != 0U ? ts : NULL,
                            fs_nofollow(flags)));
}

/* utimes(path, struct timeval[2]). */
static long fs_utimes(memp_t mem, uint64_t pva, uint64_t tva)
{
    char p[L2A_PATH_MAX];
    struct timeval tv[2];
    uint8_t g[32];
    long rc = fs_path(mem, pva, p);
    int i;

    if (rc != 0) {
        return rc;
    }
    if (tva == 0U) {
        return fs_ret(utimes(p, NULL));
    }
    rc = fs_rd(mem, tva, g, sizeof g);
    if (rc != 0) {
        return rc;
    }
    for (i = 0; i < 2; i++) {
        tv[i].tv_sec = (time_t)l2a_get_be64(g + 16 * i);
        tv[i].tv_usec = (suseconds_t)l2a_get_be64(g + 16 * i + 8);
    }
    return fs_ret(utimes(p, tv));
}

/* struct statfs (asm-generic): 8-byte longs, 2x4-byte fsid. */
static long fs_put_statfs(memp_t mem, uint64_t va, const struct statfs *s)
{
    uint8_t img[120];

    memset(img, 0, sizeof img);
    l2a_put_be64(img + 0, (uint64_t)s->f_type);
    l2a_put_be64(img + 8, (uint64_t)s->f_bsize);
    l2a_put_be64(img + 16, (uint64_t)s->f_blocks);
    l2a_put_be64(img + 24, (uint64_t)s->f_bfree);
    l2a_put_be64(img + 32, (uint64_t)s->f_bavail);
    l2a_put_be64(img + 40, (uint64_t)s->f_files);
    l2a_put_be64(img + 48, (uint64_t)s->f_ffree);
#if defined(__APPLE__)
    l2a_put_be64(img + 64, 255U);
    l2a_put_be64(img + 72, (uint64_t)s->f_bsize);
#else
    l2a_put_be64(img + 64, (uint64_t)s->f_namelen);
    l2a_put_be64(img + 72, (uint64_t)s->f_frsize);
    l2a_put_be64(img + 80, (uint64_t)s->f_flags);
#endif
    return l2a_store_buf(mem, va, img, sizeof img);
}

static long fs_statfs(memp_t mem, uint64_t pva, uint64_t buf)
{
    char p[L2A_PATH_MAX];
    struct statfs s;
    long rc = fs_path(mem, pva, p);

    if (rc != 0) {
        return rc;
    }
    return statfs(p, &s) != 0 ? -(long)errno : fs_put_statfs(mem, buf, &s);
}

static long fs_fstatfs(memp_t mem, uint64_t fd, uint64_t buf)
{
    struct statfs s;

    return fstatfs((int)fd, &s) != 0 ? -(long)errno
                                     : fs_put_statfs(mem, buf, &s);
}

/* SPARC RLIMIT_NOFILE/NPROC are 6/7 (swapped vs asm-generic). */
static int fs_rlimit_res(uint64_t g)
{
    switch (g) {
    case 0: return RLIMIT_CPU;
    case 1: return RLIMIT_FSIZE;
    case 2: return RLIMIT_DATA;
    case 3: return RLIMIT_STACK;
    case 4: return RLIMIT_CORE;
    case 5: return RLIMIT_RSS;
    case 6: return RLIMIT_NOFILE;
    case 7: return RLIMIT_NPROC;
    case 8: return RLIMIT_MEMLOCK;
    case 9: return RLIMIT_AS;
    default: return -1;
    }
}

static long fs_prlimit(memp_t mem, uint64_t pid, uint64_t res, uint64_t nva,
                       uint64_t ova)
{
    struct rlimit rl;
    int hr = fs_rlimit_res(res);
    uint8_t img[16];

    if (hr < 0) {
        return -EINVAL;
    }
    if (pid != 0U && pid != (uint64_t)getpid()) {
        return -ESRCH;
    }
    if (getrlimit((__typeof__(RLIMIT_CPU))hr, &rl) != 0) {
        return -(long)errno;
    }
    if (ova != 0U) {
        long rc;

        l2a_put_be64(img, rl.rlim_cur == RLIM_INFINITY ? ~(uint64_t)0
                                                       : (uint64_t)rl.rlim_cur);
        l2a_put_be64(img + 8, rl.rlim_max == RLIM_INFINITY
                                  ? ~(uint64_t)0 : (uint64_t)rl.rlim_max);
        rc = l2a_store_buf(mem, ova, img, sizeof img);
        if (rc != 0) {
            return rc;
        }
    }
    if (nva != 0U) {
        struct rlimit nl;
        uint64_t c;
        uint64_t m;
        long rc = fs_rd(mem, nva, img, sizeof img);

        if (rc != 0) {
            return rc;
        }
        c = l2a_get_be64(img);
        m = l2a_get_be64(img + 8);
        nl.rlim_cur = c == ~(uint64_t)0 ? RLIM_INFINITY : (rlim_t)c;
        nl.rlim_max = m == ~(uint64_t)0 ? RLIM_INFINITY : (rlim_t)m;
        if (setrlimit((__typeof__(RLIMIT_CPU))hr, &nl) != 0) {
            return -(long)errno;
        }
    }
    return 0L;
}

static long fs_times(memp_t mem, uint64_t buf)
{
    struct tms t;
    uint8_t img[32];
    clock_t r = times(&t);
    long rc;

    if (r == (clock_t)-1) {
        return -(long)errno;
    }
    if (buf != 0U) {
        l2a_put_be64(img, (uint64_t)t.tms_utime);
        l2a_put_be64(img + 8, (uint64_t)t.tms_stime);
        l2a_put_be64(img + 16, (uint64_t)t.tms_cutime);
        l2a_put_be64(img + 24, (uint64_t)t.tms_cstime);
        rc = l2a_store_buf(mem, buf, img, sizeof img);
        if (rc != 0) {
            return rc;
        }
    }
    return (long)r;
}

static long fs_getrusage(memp_t mem, uint64_t who, uint64_t buf)
{
    struct rusage ru;
    uint8_t img[144];
    int32_t w = (int32_t)who; /* the kernel takes an int */
    int hw = w == 0 ? RUSAGE_SELF : (w == -1 ? RUSAGE_CHILDREN : -99);

    if (hw == -99) {
        return -EINVAL;
    }
    if (getrusage(hw, &ru) != 0) {
        return -(long)errno;
    }
    memset(img, 0, sizeof img);
    l2a_put_be64(img + 0, (uint64_t)ru.ru_utime.tv_sec);
    l2a_put_be64(img + 8, (uint64_t)ru.ru_utime.tv_usec);
    l2a_put_be64(img + 16, (uint64_t)ru.ru_stime.tv_sec);
    l2a_put_be64(img + 24, (uint64_t)ru.ru_stime.tv_usec);
#if defined(__APPLE__)
    /* Darwin reports ru_maxrss in bytes; Linux (the guest) in KiB. */
    l2a_put_be64(img + 32, (uint64_t)ru.ru_maxrss / 1024U);
#else
    l2a_put_be64(img + 32, (uint64_t)ru.ru_maxrss);
#endif
    l2a_put_be64(img + 64, (uint64_t)ru.ru_minflt);
    l2a_put_be64(img + 72, (uint64_t)ru.ru_majflt);
    l2a_put_be64(img + 88, (uint64_t)ru.ru_inblock);
    l2a_put_be64(img + 96, (uint64_t)ru.ru_oublock);
    l2a_put_be64(img + 128, (uint64_t)ru.ru_nvcsw);
    l2a_put_be64(img + 136, (uint64_t)ru.ru_nivcsw);
    return l2a_store_buf(mem, buf, img, sizeof img);
}

/* sysinfo(2): modest synthetic figures (uptime from the host clock). */
static long fs_sysinfo(memp_t mem, uint64_t buf)
{
    uint8_t img[112];
    struct timespec ts;
    long pg = sysconf(_SC_PAGESIZE);
    long np = sysconf(_SC_PHYS_PAGES);
    uint64_t total = (uint64_t)(np > 0 ? np : 1) * (uint64_t)(pg > 0 ? pg : 4096);

    memset(img, 0, sizeof img);
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        ts.tv_sec = 0;
    }
    l2a_put_be64(img + 0, (uint64_t)ts.tv_sec);
    l2a_put_be64(img + 32, total);
    l2a_put_be64(img + 40, total / 2U);
    l2a_put_be16(img + 80, 1U);
    l2a_put_be32(img + 104, 1U);
    return l2a_store_buf(mem, buf, img, sizeof img);
}

static long fs_getgroups(memp_t mem, uint64_t n, uint64_t va)
{
    gid_t gl[256];
    uint8_t img[256 * 4];
    int cnt = getgroups(256, gl);
    int i;

    if (cnt < 0) {
        return -(long)errno;
    }
    if (n == 0U) {
        return cnt;
    }
    if (n < (uint64_t)cnt) {
        return -EINVAL;
    }
    for (i = 0; i < cnt; i++) {
        l2a_put_be32(img + 4 * i, (uint32_t)gl[i]);
    }
    if (cnt > 0) {
        long rc = l2a_store_buf(mem, va, img, (uint64_t)cnt * 4U);

        if (rc != 0) {
            return rc;
        }
    }
    return cnt;
}

static long fs_getaffinity(memp_t mem, uint64_t len, uint64_t va)
{
    uint8_t img[128];
    long ncpu = sysconf(_SC_NPROCESSORS_ONLN);
    long i;
    long rc;

    if (len < 8U) {
        return -EINVAL;
    }
    if (len > sizeof img) {
        len = sizeof img;
    }
    len &= ~(uint64_t)7U;
    memset(img, 0, sizeof img);
    for (i = 0; i < (ncpu > 0 ? ncpu : 1) && (uint64_t)i < len * 8U; i++) {
        /* Kernel masks are arrays of native (big-endian) 64-bit words. */
        img[(i / 64) * 8 + 7 - (i % 64) / 8] |= (uint8_t)(1U << (i % 8));
    }
    rc = l2a_store_buf(mem, va, img, len);
    return rc != 0 ? rc : (long)len;
}

/* prctl: PR_GET_NAME is served; every other option is a no-op success. */
static long fs_prctl(memp_t mem, uint64_t opt, uint64_t a1)
{
    if (opt == 16U) {
        uint8_t name[16] = "sparc64rt";

        return l2a_store_buf(mem, a1, name, sizeof name);
    }
    return 0L;
}

/* lseek(fd, off, whence): SEEK_* values are generic. */
static long fs_lseek(uint64_t fd, uint64_t off, uint64_t whence)
{
    off_t r = lseek((int)fd, (off_t)off, (int)whence);

    return r < 0 ? -(long)errno : (long)r;
}

/* pread64/pwrite64 through a bounded staging buffer. */
static long fs_pio(memp_t mem, uint64_t fd, uint64_t va, uint64_t count,
                   uint64_t off, int is_write)
{
    uint8_t chunk[4096];
    uint64_t done = 0;

    while (done < count) {
        uint64_t want = count - done;
        ssize_t n;

        if (want > sizeof chunk) {
            want = sizeof chunk;
        }
        if (is_write) {
            long rc = fs_rd(mem, va + done, chunk, want);

            if (rc != 0) {
                return done != 0U ? (long)done : rc;
            }
            n = pwrite((int)fd, chunk, (size_t)want, (off_t)(off + done));
        } else {
            n = pread((int)fd, chunk, (size_t)want, (off_t)(off + done));
            if (n > 0) {
                long rc = l2a_store_buf(mem, va + done, chunk, (uint64_t)n);

                if (rc != 0) {
                    return done != 0U ? (long)done : rc;
                }
            }
        }
        if (n < 0) {
            return done != 0U ? (long)done : -(long)errno;
        }
        done += (uint64_t)n;
        if ((uint64_t)n < want) {
            break;
        }
    }
    return (long)done;
}

#define CASE(n) case (long)SPARC64__NR_##n

long sparc64_l2a_fs_extra(sparc64_ctx_t *ctx, const sparc64_syscall_mem_t *mem,
                          long nr, uint64_t o0, uint64_t o1, uint64_t o2,
                          uint64_t o3, uint64_t o4, uint64_t o5, int *claimed,
                          int *delivered)
{
    const uint64_t cwd = (uint64_t)SP_AT_FDCWD;

    *claimed = 1;
    *delivered = 0;
    switch (nr) {
    CASE(chdir): return fs_chdir(mem, o0);
    CASE(fchdir): return fs_ret(fchdir((int)o0));
    CASE(getcwd): return fs_getcwd(mem, o0, o1);
    CASE(mkdir): return fs_mkdirat(mem, cwd, o0, o1);
    CASE(mkdirat): return fs_mkdirat(mem, o0, o1, o2);
    CASE(mknod): return fs_mknodat(mem, cwd, o0, o1, o2);
    CASE(mknodat): return fs_mknodat(mem, o0, o1, o2, o3);
    CASE(rmdir): return fs_unlinkat(mem, cwd, o0, FS_AT_REMOVEDIR);
    CASE(unlink): return fs_unlinkat(mem, cwd, o0, 0U);
    CASE(unlinkat): return fs_unlinkat(mem, o0, o1, o2);
    CASE(rename): return fs_renameat(mem, cwd, o0, cwd, o1, 0U);
    CASE(renameat): return fs_renameat(mem, o0, o1, o2, o3, 0U);
    CASE(renameat2): return fs_renameat(mem, o0, o1, o2, o3, o4);
    CASE(link): return fs_linkat(mem, cwd, o0, cwd, o1, 0U);
    CASE(linkat): return fs_linkat(mem, o0, o1, o2, o3, o4);
    CASE(symlink): return fs_symlinkat(mem, o0, cwd, o1);
    CASE(symlinkat): return fs_symlinkat(mem, o0, o1, o2);
    CASE(chmod): return fs_chmodat(mem, cwd, o0, o1);
    CASE(fchmodat): return fs_chmodat(mem, o0, o1, o2);
    CASE(fchmod): return fs_ret(fchmod((int)o0, (mode_t)o1));
    CASE(chown): return fs_chownat(mem, cwd, o0, o1, o2, 0U);
    CASE(lchown): return fs_chownat(mem, cwd, o0, o1, o2,
                                    SP_AT_SYMLINK_NOFOLLOW);
    CASE(fchownat): return fs_chownat(mem, o0, o1, o2, o3, o4);
    CASE(fchown): return fs_ret(fchown((int)o0, (uid_t)o1, (gid_t)o2));
    CASE(umask): return (long)umask((mode_t)o0);
    CASE(creat): return sparc64_l2a_openat(ctx, mem, cwd, o0,
        FS_O_CREAT | FS_O_TRUNC | FS_O_WRONLY, o1);
    CASE(utimensat): return fs_utimensat(mem, o0, o1, o2, o3);
    CASE(utimes): return fs_utimes(mem, o0, o1);
    CASE(statfs): return fs_statfs(mem, o0, o1);
    CASE(fstatfs): return fs_fstatfs(mem, o0, o1);
    CASE(getrlimit): return fs_prlimit(mem, 0U, o0, 0U, o1);
    CASE(setrlimit): return fs_prlimit(mem, 0U, o0, o1, 0U);
    CASE(prlimit64): return fs_prlimit(mem, o0, o1, o2, o3);
    CASE(times): return fs_times(mem, o0);
    CASE(getrusage): return fs_getrusage(mem, o0, o1);
    CASE(sysinfo): return fs_sysinfo(mem, o0);
    CASE(poll): return sparc64_fs_poll(ctx, mem, o0, o1, (int)(int32_t)o2);
    CASE(ppoll): return sparc64_fs_ppoll(ctx, mem, o0, o1, o2, o3, o4,
                                         delivered);
    CASE(_newselect): return sparc64_fs_select(ctx, mem, o0, o1, o2, o3, o4);
    CASE(pselect6_time64):
    CASE(pselect6): return sparc64_fs_pselect6(ctx, mem, o0, o1, o2, o3, o4,
                                               o5, delivered);
    CASE(getppid): return (long)getppid();
    CASE(geteuid): return (long)geteuid();
    CASE(getegid): return (long)getegid();
    CASE(getpgrp): return (long)getpgrp();
    CASE(getpgid): { pid_t r = getpgid((pid_t)o0);
        return r < 0 ? -(long)errno : (long)r; }
    CASE(setpgid): return fs_ret(setpgid((pid_t)o0, (pid_t)o1));
    CASE(setsid): { pid_t r = setsid();
        return r < 0 ? -(long)errno : (long)r; }
    CASE(getsid): { pid_t r = getsid((pid_t)o0);
        return r < 0 ? -(long)errno : (long)r; }
    CASE(getgroups): return fs_getgroups(mem, o0, o1);
    CASE(sched_getaffinity): return fs_getaffinity(mem, o1, o2);
    CASE(prctl): return fs_prctl(mem, o0, o1);
    CASE(fsync):
    CASE(fdatasync): return fs_ret(fsync((int)o0));
    CASE(flock): return sparc64_fs_flock(ctx, o0, o1);
    CASE(sched_yield): return fs_ret(sched_yield());
    CASE(lseek): return fs_lseek(o0, o1, o2);
    CASE(_llseek): {
        off_t r = lseek((int)o0, (off_t)((o1 << 32) | (o2 & 0xffffffffU)),
                        (int)o4);
        uint8_t img[8];

        if (r < 0) {
            return -(long)errno;
        }
        l2a_put_be64(img, (uint64_t)r);
        return l2a_store_buf(mem, o3, img, sizeof img);
    }
    CASE(access): return sparc64_l2a_faccessat(ctx, mem, cwd, o0, o1, 0U);
    CASE(pread64): return fs_pio(mem, o0, o1, o2, o3, 0);
    CASE(pwrite64): return fs_pio(mem, o0, o1, o2, o3, 1);
    CASE(nanosleep): return sparc64_fs_nanosleep(ctx, mem, o0, o1);
    CASE(msync):
    CASE(mlock):
    CASE(fadvise64):
    CASE(readahead):
    CASE(sched_setaffinity): return 0L;
    CASE(getxattr):
    CASE(lgetxattr): return -EOPNOTSUPP;
    default:
        break;
    }
    *claimed = 0;
    return -ENOSYS;
}
