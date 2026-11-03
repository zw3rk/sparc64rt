/*
 * src/os/syscalls_ext.h — Extended SPARC64 Linux syscall layer (Phase 2, L2a)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Declares the Phase-2 static-libc subset implemented in
 * src/os/syscalls_ext.c: stat/stat64/statx/lstat (+fstat/fstat64/
 * lstat64/fstatat64 siblings static glibc needs), readv/writev, openat,
 * fcntl/fcntl64, clock_gettime/clock_getres/gettimeofday, getrandom,
 * futex (single-threaded WAIT/WAKE via the host futex),
 * ioctl (TCGETS/TIOCGWINSZ only, ENOTTY otherwise), and
 * getpid/getuid/getgid. Handlers return host-style results (>= 0 value,
 * negative host errno); the dual-carry commit in src/os/syscalls_min.c
 * applies unchanged. Guest structs are big-endian; translation lives in
 * the .c file and never exposes a host pointer to the guest.
 */

#ifndef SPARC64RT_OS_SYSCALLS_EXT_H
#define SPARC64RT_OS_SYSCALLS_EXT_H

#include <errno.h>
#include <stdint.h>

#include "core/cpu.h"
#include "os/syscalls_min.h"

/* Shared guest-access helpers (static inline so TUs that only need the
 * declarations below, such as src/os/syscalls_min.c, compile clean).
 * Big-endian words, the 47-bit guest range model, and host-time views. */
#define L2A_PATH_MAX 4096U
#define SP_AT_FDCWD ((int64_t)-100)
#define SP_AT_SYMLINK_NOFOLLOW 0x100U
#define SP_AT_EACCESS 0x200U
#define SP_AT_NO_AUTOMOUNT 0x800U
#define SP_AT_EMPTY_PATH 0x1000U
#define SP_AT_STATX_SYNC_TYPE 0x6000U
static inline void l2a_put_be16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
}

static inline void l2a_put_be32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

static inline void l2a_put_be64(uint8_t *p, uint64_t v)
{
    l2a_put_be32(p, (uint32_t)(v >> 32));
    l2a_put_be32(p + 4, (uint32_t)v);
}

static inline uint32_t l2a_get_be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
        ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static inline uint64_t l2a_get_be64(const uint8_t *p)
{
    return ((uint64_t)l2a_get_be32(p) << 32) | (uint64_t)l2a_get_be32(p + 4);
}

/* Bounds check for [va, va+len): reject 64-bit wrap and anything above
 * the 47-bit guest task size (zero-length ranges always pass). */
static inline int l2a_range_ok(uint64_t va, uint64_t len)
{
    if (len == 0U) {
        return 0;
    }
    if (len > SPARC64_TASK_SIZE || va > SPARC64_TASK_SIZE - len) {
        return -EFAULT;
    }
    return 0;
}

/* Store a fully encoded buffer at the guest address. */
static inline long l2a_store_buf(const sparc64_syscall_mem_t *mem,
    uint64_t va, const uint8_t *src, uint64_t len)
{
    if (l2a_range_ok(va, len) != 0) {
        return -EFAULT;
    }
    if (len != 0U) {
        if (!mem->prepare_write(mem->context, va, len)) {
            return -EFAULT;
        }
        if (!mem->write(mem->context, va, src, len)) {
            return -EFAULT;
        }
    }
    return 0;
}

/* NUL-terminated guest string -> out (0 ok, -EFAULT/-ENAMETOOLONG).
 * Fast 256 B chunks first; a chunk that faults (e.g. argv packed
 * against the top of the stack) falls back to byte-wise reads so a
 * string ending just before an unmapped page still copies. */
static inline long l2a_copy_cstring(const sparc64_syscall_mem_t *mem,
    uint64_t va, char *out, uint64_t cap)
{
    uint64_t done = 0;
    uint8_t chunk[256];
    if (cap == 0U) {
        return -ENAMETOOLONG;
    }
    if (l2a_range_ok(va, 1U) != 0) {
        return -EFAULT;
    }
    while (done < cap) {
        uint64_t want = cap - done;
        uint64_t i;
        if (want > (uint64_t)sizeof(chunk)) {
            want = (uint64_t)sizeof(chunk);
        }
        if (l2a_range_ok(va + done, want) == 0 &&
                mem->read(mem->context, va + done, chunk, want)) {
            for (i = 0U; i < want; i++) {
                out[done] = (char)chunk[i];
                done++;
                if (chunk[i] == 0U) {
                    return 0;
                }
                if (done == cap) {
                    out[cap - 1U] = '\0';
                    return -ENAMETOOLONG;
                }
            }
            continue;
        }
        {
            uint8_t c = 0;
            if (!mem->read(mem->context, va + done, &c, 1U)) {
                out[done] = '\0';
                return -EFAULT;
            }
            out[done] = (char)c;
            done++;
            if (c == 0U) {
                return 0;
            }
        }
    }
    out[cap - 1U] = '\0';
    return -ENAMETOOLONG;
}

/* Narrowing checks with EOVERFLOW fallback (old-stat semantics). */
static inline long l2a_narrow_s16(int64_t v)
{
    return (v >= -32768L && v <= 32767L) ? (long)v : -EOVERFLOW;
}

static inline long l2a_narrow_u32(uint64_t v)
{
    return (v <= 0xffffffffU) ? (long)(uint32_t)v : -EOVERFLOW;
}

/* Path-based status into the frozen BE layouts (stat 104 B, stat64 144 B). */
long sparc64_l2a_stat(sparc64_ctx_t *ctx, const sparc64_syscall_mem_t *mem,
    uint64_t path_va, uint64_t buf_va);
long sparc64_l2a_lstat(sparc64_ctx_t *ctx, const sparc64_syscall_mem_t *mem,
    uint64_t path_va, uint64_t buf_va);
long sparc64_l2a_fstat(sparc64_ctx_t *ctx, const sparc64_syscall_mem_t *mem,
    uint64_t fd, uint64_t buf_va);
long sparc64_l2a_stat64(sparc64_ctx_t *ctx, const sparc64_syscall_mem_t *mem,
    uint64_t path_va, uint64_t buf_va);
long sparc64_l2a_lstat64(sparc64_ctx_t *ctx, const sparc64_syscall_mem_t *mem,
    uint64_t path_va, uint64_t buf_va);
long sparc64_l2a_fstat64(sparc64_ctx_t *ctx, const sparc64_syscall_mem_t *mem,
    uint64_t fd, uint64_t buf_va);
long sparc64_l2a_fstatat64(sparc64_ctx_t *ctx,
    const sparc64_syscall_mem_t *mem, uint64_t dirfd, uint64_t path_va,
    uint64_t buf_va, uint64_t flags);
long sparc64_l2a_statx(sparc64_ctx_t *ctx, const sparc64_syscall_mem_t *mem,
    uint64_t dirfd, uint64_t path_va, uint64_t flags, uint64_t mask,
    uint64_t buf_va);

/* Scatter/gather over guest iovec chains ({BE u64 base, BE u64 len}). */
long sparc64_l2a_readv(sparc64_ctx_t *ctx, const sparc64_syscall_mem_t *mem,
    uint64_t fd, uint64_t iov_va, uint64_t iovcnt);
long sparc64_l2a_writev(sparc64_ctx_t *ctx, const sparc64_syscall_mem_t *mem,
    uint64_t fd, uint64_t iov_va, uint64_t iovcnt);

/* Path open with SPARC O_* flag translation (/proc/self files are
 * synthetic per src/os/guest_proc.h). */
long sparc64_l2a_openat(sparc64_ctx_t *ctx, const sparc64_syscall_mem_t *mem,
    uint64_t dirfd, uint64_t path_va, uint64_t flags, uint64_t mode);

/* open(5): openat(AT_FDCWD), same interception. */
long sparc64_l2a_open(sparc64_ctx_t *ctx, const sparc64_syscall_mem_t *mem,
    uint64_t path_va, uint64_t flags, uint64_t mode);

/* getdents64(154): host records with BE-swapped d_ino/d_off/d_reclen;
 * d_type/d_name copied verbatim. Returns the byte count. */
long sparc64_l2a_getdents64(sparc64_ctx_t *ctx,
    const sparc64_syscall_mem_t *mem, uint64_t fd, uint64_t buf_va,
    uint64_t count);

/* faccessat(296): mode bits match the host; AT_EACCESS accepted and
 * ignored; absolute paths try the sysroot first (qemu -L). */
long sparc64_l2a_faccessat(sparc64_ctx_t *ctx,
    const sparc64_syscall_mem_t *mem, uint64_t dirfd, uint64_t path_va,
    uint64_t mode, uint64_t flags);

/* readlinkat(294): /proc/self/exe yields the absolute load path;
 * other synthetic files are EINVAL; the rest is the host
 * readlinkat. */
long sparc64_l2a_readlinkat(sparc64_ctx_t *ctx,
    const sparc64_syscall_mem_t *mem, uint64_t dirfd, uint64_t path_va,
    uint64_t buf_va, uint64_t bufsz);

/* Descriptor control (SPARC F_* numbers match the host F_* numbers). */
long sparc64_l2a_fcntl(uint64_t fd, uint64_t cmd, uint64_t arg);

/* Clocks: __kernel_timespec {BE s64 sec, BE s64 nsec}; timeval {BE s64
 * sec, BE s64 usec}. A NULL guest pointer is a successful no-op. */
long sparc64_l2a_clock_gettime(sparc64_ctx_t *ctx,
    const sparc64_syscall_mem_t *mem, uint64_t clk_id, uint64_t tp_va);
long sparc64_l2a_clock_getres(sparc64_ctx_t *ctx,
    const sparc64_syscall_mem_t *mem, uint64_t clk_id, uint64_t tp_va);
long sparc64_l2a_gettimeofday(sparc64_ctx_t *ctx,
    const sparc64_syscall_mem_t *mem, uint64_t tv_va, uint64_t tz_va);

/* Entropy into a guest buffer (Linux only, -ENOSYS elsewhere). */
long sparc64_l2a_getrandom(sparc64_ctx_t *ctx,
    const sparc64_syscall_mem_t *mem, uint64_t buf_va, uint64_t len,
    uint64_t flags);

/* Single-threaded futex: WAIT mismatches fail with -EAGAIN, matches sleep
 * through the host futex until the relative timeout (-ETIMEDOUT) or wake
 * spuriously when no timeout is given; WAKE wakes nobody and returns 0. */
long sparc64_l2a_futex(sparc64_ctx_t *ctx, const sparc64_syscall_mem_t *mem,
    uint64_t uaddr, uint64_t op, uint64_t val, uint64_t timeout_va);

/* TCGETS answers as an isatty query, TIOCGWINSZ fills the BE winsize,
 * everything else is -ENOTTY. */
long sparc64_l2a_ioctl(sparc64_ctx_t *ctx, const sparc64_syscall_mem_t *mem,
    uint64_t fd, uint64_t request, uint64_t arg_va);

/* Identity queries. */
long sparc64_l2a_getpid(void);
long sparc64_l2a_getuid(void);
long sparc64_l2a_getgid(void);

#endif /* SPARC64RT_OS_SYSCALLS_EXT_H */
