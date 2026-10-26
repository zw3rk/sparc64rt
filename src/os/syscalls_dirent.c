/* src/os/syscalls_dirent.c — getdents64 for the SPARC64 guest (RC5)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * BusyBox `ls` (and glibc opendir/readdir) needs getdents64 (SPARC
 * NR 154). The host linux_dirent64 layout matches, but the record
 * headers (d_ino, d_off, d_reclen) are host-endian: byte-swap them to
 * big-endian in the staging buffer before committing to guest
 * memory. d_type and d_name are byte strings, copied verbatim.
 */

/* Needs _GNU_SOURCE: musl hides syscall(2) under -std=c11. */
#define _GNU_SOURCE 1

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#if defined(__linux__)
#include <sys/syscall.h>
#endif

#include "core/cpu.h"
#include "os/syscalls_ext.h"
#include "os/guest_interp_map.h"

/* Single-call staging cap (short reads are legal; the shared directory
 * cursor continues on the next call). */
#define DIRENT_STAGE_MAX (64U * 1024U)

long sparc64_l2a_getdents64(sparc64_ctx_t *ctx,
    const sparc64_syscall_mem_t *mem, uint64_t fd, uint64_t buf_va,
    uint64_t count)
{
#if !defined(__linux__)
    (void)ctx;
    (void)mem;
    (void)fd;
    (void)buf_va;
    (void)count;
    return -ENOSYS;
#else
    uint32_t want = (uint32_t)count;
    uint8_t *stage;
    long got;
    size_t at = 0;
    long rc;
    (void)ctx;
    if (want == 0U) {
        return -EINVAL;
    }
    if (want > (uint32_t)DIRENT_STAGE_MAX) {
        want = (uint32_t)DIRENT_STAGE_MAX;
    }
    stage = (uint8_t *)malloc(want);
    if (stage == NULL) {
        return -ENOMEM;
    }
    got = syscall(SYS_getdents64, (int)fd, stage, (size_t)want);
    if (got < 0) {
        int e = errno;
        free(stage);
        return -(long)e;
    }
    while (at < (size_t)got) {
        uint64_t ino;
        uint64_t off;
        uint16_t reclen;
        uint16_t wire;
        if ((size_t)got - at < (size_t)19) {
            break;
        }
        memcpy(&ino, stage + at, sizeof(ino));
        memcpy(&off, stage + at + 8U, sizeof(off));
        memcpy(&reclen, stage + at + 16U, sizeof(reclen));
        if (reclen < (uint16_t)19 ||
                (size_t)reclen > (size_t)got - at) {
            break;
        }
        ino = __builtin_bswap64(ino);
        off = __builtin_bswap64(off);
        wire = __builtin_bswap16(reclen);
        memcpy(stage + at, &ino, sizeof(ino));
        memcpy(stage + at + 8U, &off, sizeof(off));
        memcpy(stage + at + 16U, &wire, sizeof(wire));
        at += (size_t)reclen;
    }
    rc = l2a_store_buf(mem, buf_va, stage, (uint64_t)got);
    free(stage);
    return (rc != 0) ? rc : got;
#endif
}

/* faccessat(296): mode bits match the host (F_OK/X_OK/W_OK/R_OK).
 * AT_EACCESS is accepted and ignored (the translator is not set-id);
 * other flags are EINVAL. Absolute paths try SPARC64RT_SYSROOT
 * first (qemu -L), ENOENT falls back to raw. */
long sparc64_l2a_faccessat(sparc64_ctx_t *ctx,
    const sparc64_syscall_mem_t *mem, uint64_t dirfd, uint64_t path_va,
    uint64_t mode, uint64_t flags)
{
    char path[L2A_PATH_MAX];
    char joined[L2A_PATH_MAX];
    long rc;
    int host_dirfd;
    int host_flags = 0;
    (void)ctx;
    rc = l2a_copy_cstring(mem, path_va, path, (uint64_t)L2A_PATH_MAX);
    if (rc != 0) {
        return rc;
    }
    if ((flags & ~(uint64_t)((uint64_t)SP_AT_SYMLINK_NOFOLLOW |
            (uint64_t)SP_AT_EACCESS)) != 0U) {
        return -EINVAL;
    }
    if ((flags & (uint64_t)SP_AT_SYMLINK_NOFOLLOW) != 0U) {
        host_flags |= AT_SYMLINK_NOFOLLOW;
    }
    host_dirfd = ((int64_t)dirfd == SP_AT_FDCWD) ? AT_FDCWD : (int)dirfd;
    if (path[0] == '/' &&
            sparc64_interp_resolve(path, getenv("SPARC64RT_SYSROOT"),
                joined, sizeof(joined)) == 0) {
        if (faccessat(host_dirfd, joined, (int)mode, host_flags) == 0) {
            return 0;
        }
        if (errno != ENOENT && errno != ENOTDIR) {
            return -(long)errno;
        }
    }
    if (faccessat(host_dirfd, path, (int)mode, host_flags) != 0) {
        return -(long)errno;
    }
    return 0;
}
