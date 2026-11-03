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
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <termios.h>
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
/* macOS <sys/signal.h> (reached via <stdlib.h>) #defines sa_handler and
 * sa_sigaction over the frozen guest sparc64_sigaction_t field names
 * (same pattern as src/os/syscalls_sig.h); drop them here (this TU
 * only, which never uses the host struct sigaction). */
#ifdef sa_handler
#undef sa_handler
#endif
#ifdef sa_sigaction
#undef sa_sigaction
#endif

#include "core/cpu.h"
#include "os/guest_proc.h"
#include "os/guest_interp_map.h"
#include "os/sigframe_sparc64rt.h"
#include "os/syscall_nr.h"
#include "os/syscalls_ext.h"
#include "os/syscalls_min.h"
#include "os/threads.h"

/* SPARC open flags (arch/sparc fcntl.h, shared 32/64-bit); low 2 access
 * bits match the host. */
#define SP_O_FASYNC 0x0040U
#define SP_O_ASYNC SP_O_FASYNC
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

/* SP_AT_* live in syscalls_ext.h (shared with syscalls_dirent.c). */

#define SP_CLOCK_REALTIME 0U
#define SP_CLOCK_MONOTONIC 1U

#define SP_GRND_NONBLOCK 0x0001U
#define SP_GRND_RANDOM 0x0002U
#define SP_GRND_INSECURE 0x0004U

/* L2A_PATH_MAX and SP_AT_* live in syscalls_ext.h now. */
#define L2A_IOV_MAX 1024U
#define L2A_CHUNK 4096U

/* SPARC O_* -> host O_*. Unknown bits are EINVAL; O_DSYNC maps to O_SYNC.
 * Composite multi-bit flags (TMPFILE, NDELAY, SYNC) use full mask equality
 * and are ordered before their single-bit subsets so SP_O_DIRECTORY alone
 * never sets O_TMPFILE and lone 0x0004 maps to O_NONBLOCK accurately. */
static long open_flags_to_host(uint64_t guest, int *host_out)
{
    uint64_t rest = guest & ~3U;
    size_t i;
    int h = (int)(guest & 3U);
    static const struct {
        uint64_t guest;
        int host;
    } map[] = {
#ifdef O_TMPFILE
        { SP_O_TMPFILE, O_TMPFILE },
#endif
        { SP_O_NDELAY, O_NONBLOCK },
        { 0x0004U, O_NONBLOCK },
        { SP_O_APPEND, O_APPEND }, { SP_O_CREAT, O_CREAT },
        { SP_O_TRUNC, O_TRUNC }, { SP_O_EXCL, O_EXCL },
        { SP_O_NONBLOCK, O_NONBLOCK },
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
    };
    if ((rest & SP_O_SYNC) == SP_O_SYNC) {
#ifdef O_SYNC
        h |= O_SYNC;
        rest &= ~(uint64_t)SP_O_SYNC;
#else
        return -EINVAL;
#endif
    } else if ((rest & SP_O_DSYNC) == SP_O_DSYNC) {
#ifdef O_SYNC
        h |= O_SYNC;
        rest &= ~(uint64_t)SP_O_DSYNC;
#else
        return -EINVAL;
#endif
    }
    for (i = 0U; i < sizeof(map) / sizeof(map[0]); i++) {
        if ((rest & map[i].guest) == map[i].guest) {
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

/* Permission-checked range helper (S64-R6-3): bounds first, then the
 * writability pin for readv destinations. Readability for writev sources
 * is proven by the staging copy before any host I/O. */
static int l2a_range_prot_ok(const sparc64_syscall_mem_t *mem, uint64_t va,
    uint64_t len, int prot)
{
    if (l2a_range_ok(va, len) != 0) {
        return -EFAULT;
    }
    if (len == 0U) {
        return 0;
    }
    if ((prot & PROT_WRITE) != 0) {
        if (!mem->prepare_write(mem->context, va, len)) {
            return -EFAULT;
        }
    }
    return 0;
}

/* readv/writev over guest iovec chains ({BE u64 base, BE u64 len}).
 * All entries are validated first, the bytes are staged into a single
 * contiguous host buffer, and exactly one host read/write call runs so
 * pipe atomicity holds and a partial readv never blocks for more data.
 * Short counts scatter back to the guest and read as the result.
 * S64-R6-2: the big lock is dropped across the single blocking host
 * call (inputs already staged, destinations pre-validated). S64-R6-3:
 * readv destinations are permission-checked before any host input is
 * consumed; a leading-invalid chain fails with -EFAULT, a later-invalid
 * chain caps to the valid prefix. */
static long sys_rwvec(sparc64_ctx_t *ctx, const sparc64_syscall_mem_t *mem,
    uint64_t fd, uint64_t iov_va, uint64_t iovcnt, int is_write)
{
    struct l2a_iov_entry {
        uint64_t base;
        uint64_t len;
    };
    uint64_t total = 0;
    uint64_t i = 0;
    uint8_t *buf = NULL;
    struct l2a_iov_entry *vec = NULL;
    uint64_t off = 0;
    ssize_t got;
    (void)ctx;
    if (iovcnt > (uint64_t)L2A_IOV_MAX) {
        return -EINVAL;
    }
    if (iovcnt == 0U) {
        return 0;
    }
    if (iovcnt > UINT64_C(0) && iovcnt > UINT64_MAX / 16U) {
        return -EINVAL;
    }
    if (l2a_range_ok(iov_va, iovcnt * 16U) != 0) {
        return -EFAULT;
    }
    vec = (struct l2a_iov_entry *)malloc((size_t)iovcnt *
        sizeof(struct l2a_iov_entry));
    if (vec == NULL) {
        return -ENOMEM;
    }
    for (i = 0U; i < iovcnt; i++) {
        uint8_t e[16];
        uint64_t len;
        uint64_t base;
        if (!mem->read(mem->context, iov_va + i * 16U, e,
                (uint64_t)sizeof(e))) {
            free(vec);
            return -EFAULT;
        }
        base = l2a_get_be64(e);
        len = l2a_get_be64(e + 8);
        if (l2a_range_ok(base, len) != 0) {
            free(vec);
            return -EFAULT;
        }
        if (len > UINT64_C(0) && total > UINT64_MAX - len) {
            free(vec);
            return -EINVAL;
        }
        total += len;
        vec[i].base = base;
        vec[i].len = len;
    }
    if (total == 0U) {
        free(vec);
        return 0;
    }
    if (total > (uint64_t)SIZE_MAX) {
        free(vec);
        return -EINVAL;
    }
    buf = (uint8_t *)malloc((size_t)total);
    if (buf == NULL) {
        free(vec);
        return -ENOMEM;
    }
    if (is_write) {
        for (i = 0U; i < iovcnt; i++) {
            if (vec[i].len == 0U) {
                continue;
            }
            if (l2a_range_prot_ok(mem, vec[i].base, vec[i].len,
                    PROT_READ) != 0) {
                free(buf);
                free(vec);
                return -EFAULT;
            }
        }
        for (i = 0U; i < iovcnt; i++) {
            uint64_t base = vec[i].base;
            uint64_t len = vec[i].len;
            if (len == 0U) {
                continue;
            }
            if (!mem->read(mem->context, base, buf + off, len)) {
                free(buf);
                free(vec);
                return -EFAULT;
            }
            off += len;
        }
        /* S2 hook point: host op runs first (Step 3); the coordinator
         * lands vm_file_commit_resize here (Step 4) once the family
         * table + truncate dispatch exist. S64-R6-2: inputs are staged
         * above, so drop the big lock across the blocking host call. */
        sparc64_thread_big_unlock();
        got = write((int)fd, buf, (size_t)total);
        sparc64_thread_big_lock();
        free(buf);
        free(vec);
        if (got < 0) {
            return -(long)errno;
        }
        return (long)got;
    }
    {
        uint64_t valid_total = 0U;
        uint64_t valid_cnt = iovcnt;
        uint64_t k;
        for (k = 0U; k < iovcnt; k++) {
            if (vec[k].len == 0U) {
                continue;
            }
            if (l2a_range_prot_ok(mem, vec[k].base, vec[k].len,
                    PROT_WRITE) != 0) {
                valid_cnt = k;
                break;
            }
            valid_total += vec[k].len;
        }
        if (valid_cnt != iovcnt) {
            if (valid_total == 0U) {
                free(buf);
                free(vec);
                return -EFAULT;
            }
            total = valid_total;
            iovcnt = valid_cnt;
        }
        sparc64_thread_big_unlock();
        got = read((int)fd, buf, (size_t)total);
        sparc64_thread_big_lock();
    }
    if (got < 0) {
        free(buf);
        free(vec);
        return -(long)errno;
    }
    if (got == 0) {
        free(buf);
        free(vec);
        return 0;
    }
    off = 0;
    for (i = 0U; i < iovcnt && off < (uint64_t)got; i++) {
        uint64_t base = vec[i].base;
        uint64_t len = vec[i].len;
        uint64_t want;
        if (len == 0U) {
            continue;
        }
        want = len;
        if (want > (uint64_t)got - off) {
            want = (uint64_t)got - off;
        }
        if (!mem->prepare_write(mem->context, base, want) ||
            !mem->write(mem->context, base, buf + off, want)) {
            free(buf);
            free(vec);
            return (off != 0U) ? (long)off : -EFAULT;
        }
        off += want;
    }
    free(buf);
    free(vec);
    return (long)off;
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

static long flags_host_to_guest(int host)
{
    uint64_t g = (uint64_t)(host & 3);
    if ((host & O_APPEND) != 0) {
        g |= (uint64_t)SP_O_APPEND;
    }
    if ((host & O_NONBLOCK) != 0) {
        g |= (uint64_t)SP_O_NONBLOCK;
    }
#ifdef O_DIRECTORY
    if ((host & O_DIRECTORY) != 0) {
        g |= (uint64_t)SP_O_DIRECTORY;
    }
#endif
#ifdef O_PATH
    if ((host & O_PATH) != 0) {
        g |= (uint64_t)SP_O_PATH;
    }
#endif
#ifdef O_SYNC
    if ((host & O_SYNC) == O_SYNC) {
        g |= (uint64_t)SP_O_SYNC;
    }
#ifdef O_DSYNC
    else if ((host & O_DSYNC) != 0) {
        g |= (uint64_t)SP_O_DSYNC;
    }
#endif
#elif defined(O_DSYNC)
    if ((host & O_DSYNC) != 0) {
        g |= (uint64_t)SP_O_DSYNC;
    }
#endif
#ifdef O_ASYNC
    if ((host & O_ASYNC) != 0) {
        g |= (uint64_t)SP_O_ASYNC;
    }
#endif
#ifdef O_DIRECT
    if ((host & O_DIRECT) != 0) {
        g |= (uint64_t)SP_O_DIRECT;
    }
#endif
#ifdef O_NOATIME
    if ((host & O_NOATIME) != 0) {
        g |= (uint64_t)SP_O_NOATIME;
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
        uint64_t rest = arg;
        /* Linux fcntl(F_SETFL) ignores the access mode and the
         * creation/status bits; only the mutable status flags are
         * translated below. */
        rest &= ~(uint64_t)3U;
        rest &= ~((uint64_t)SP_O_CREAT | (uint64_t)SP_O_TRUNC |
            (uint64_t)SP_O_EXCL | (uint64_t)SP_O_NOCTTY |
            (uint64_t)SP_O_LARGEFILE | (uint64_t)SP_O_DIRECTORY |
            (uint64_t)SP_O_NOFOLLOW | (uint64_t)SP_O_CLOEXEC |
            (uint64_t)SP_O_SYNC | (uint64_t)SP_O_DSYNC);
        if ((rest & (uint64_t)SP_O_APPEND) != 0U) {
            host |= O_APPEND;
            rest &= ~(uint64_t)SP_O_APPEND;
        }
        if (((rest & (uint64_t)SP_O_NDELAY) == (uint64_t)SP_O_NDELAY) ||
            ((rest & (uint64_t)SP_O_NONBLOCK) != 0U) ||
            (((rest & (uint64_t)0x0004U) != 0U))) {
            host |= O_NONBLOCK;
            rest &= ~((uint64_t)SP_O_NDELAY | (uint64_t)SP_O_NONBLOCK |
                (uint64_t)0x0004U);
        }
        if ((rest & (uint64_t)SP_O_ASYNC) != 0U) {
#ifdef O_ASYNC
            host |= O_ASYNC;
#else
            return -EINVAL;
#endif
            rest &= ~(uint64_t)SP_O_ASYNC;
        }
        if ((rest & (uint64_t)SP_O_DIRECT) != 0U) {
#ifdef O_DIRECT
            host |= O_DIRECT;
#else
            return -EINVAL;
#endif
            rest &= ~(uint64_t)SP_O_DIRECT;
        }
        if ((rest & (uint64_t)SP_O_NOATIME) != 0U) {
#ifdef O_NOATIME
            host |= O_NOATIME;
#else
            return -EINVAL;
#endif
            rest &= ~(uint64_t)SP_O_NOATIME;
        }
        if (rest != 0U) {
            return -EINVAL;
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
    if (is_res == 0 && tp_va == 0U) {
        if (l2a_range_ok(tp_va, 16U) != 0) {
            return -EFAULT;
        }
    } else if (tp_va != 0U) {
        if (l2a_range_ok(tp_va, 16U) != 0) {
            return -EFAULT;
        }
    }
    if (is_res ? clock_getres(host_clk, &ts) != 0 :
            clock_gettime(host_clk, &ts) != 0) {
        return -(long)errno;
    }
    if (is_res != 0 && tp_va == 0U) {
        return 0;
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

/* TCGETS fills the 36-byte SPARC Linux termios (BE flags, line + cc);
 * TIOCGWINSZ fills the BE winsize. */
long sparc64_l2a_ioctl(sparc64_ctx_t *ctx, const sparc64_syscall_mem_t *mem,
    uint64_t fd, uint64_t request, uint64_t arg_va)
{
    (void)ctx;
    if (request == (uint64_t)SP_TCGETS) {
        struct termios ht;
        uint8_t b[36];
        if (l2a_range_ok(arg_va, (uint64_t)sizeof(b)) != 0) {
            return -EFAULT;
        }
        if (tcgetattr((int)fd, &ht) != 0) {
            int e = errno;
            return (e == EBADF) ? -EBADF : -ENOTTY;
        }
        memset(b, 0, sizeof(b));
        l2a_put_be32(b, (uint32_t)ht.c_iflag);
        l2a_put_be32(b + 4U, (uint32_t)ht.c_oflag);
        l2a_put_be32(b + 8U, (uint32_t)ht.c_cflag);
        l2a_put_be32(b + 12U, (uint32_t)ht.c_lflag);
#if defined(__linux__)
        b[16] = (uint8_t)ht.c_line;
#else
        b[16] = 0;
#endif
        b[17U + 0U] = (uint8_t)ht.c_cc[VINTR];
        b[17U + 1U] = (uint8_t)ht.c_cc[VQUIT];
        b[17U + 2U] = (uint8_t)ht.c_cc[VERASE];
        b[17U + 3U] = (uint8_t)ht.c_cc[VKILL];
#if defined(VEOF) && defined(VMIN)
        if ((ht.c_lflag & (tcflag_t)ICANON) != 0) {
            b[17U + 4U] = (uint8_t)ht.c_cc[VEOF];
        } else {
            b[17U + 4U] = (uint8_t)ht.c_cc[VMIN];
        }
#elif defined(VEOF)
        b[17U + 4U] = (uint8_t)ht.c_cc[VEOF];
#elif defined(VMIN)
        b[17U + 4U] = (uint8_t)ht.c_cc[VMIN];
#endif
#if defined(VEOL) && defined(VTIME)
        if ((ht.c_lflag & (tcflag_t)ICANON) != 0) {
            b[17U + 5U] = (uint8_t)ht.c_cc[VEOL];
        } else {
            b[17U + 5U] = (uint8_t)ht.c_cc[VTIME];
        }
#elif defined(VEOL)
        b[17U + 5U] = (uint8_t)ht.c_cc[VEOL];
#elif defined(VTIME)
        b[17U + 5U] = (uint8_t)ht.c_cc[VTIME];
#endif
#ifdef VEOL2
        b[17U + 6U] = (uint8_t)ht.c_cc[VEOL2];
#endif
#ifdef VSTART
        b[17U + 8U] = (uint8_t)ht.c_cc[VSTART];
#endif
#ifdef VSTOP
        b[17U + 9U] = (uint8_t)ht.c_cc[VSTOP];
#endif
#ifdef VSUSP
        b[17U + 10U] = (uint8_t)ht.c_cc[VSUSP];
#endif
#ifdef VREPRINT
        b[17U + 12U] = (uint8_t)ht.c_cc[VREPRINT];
#endif
#ifdef VDISCARD
        b[17U + 13U] = (uint8_t)ht.c_cc[VDISCARD];
#endif
#ifdef VWERASE
        b[17U + 14U] = (uint8_t)ht.c_cc[VWERASE];
#endif
#ifdef VLNEXT
        b[17U + 15U] = (uint8_t)ht.c_cc[VLNEXT];
#endif
        return l2a_store_buf(mem, arg_va, b, (uint64_t)sizeof(b));
    }
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
    return -ENOTTY;
}
