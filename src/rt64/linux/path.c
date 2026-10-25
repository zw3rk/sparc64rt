/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#if defined(__APPLE__)
#define _DARWIN_C_SOURCE 1
#endif

#include "linux/path.h"

#include <errno.h>
#include <fcntl.h>
#include <string.h>

int sparc64_linux_copy_path(sparc64_space_t *space, uint64_t guest_address,
                       char output[SPARC64_LINUX_PATH_MAX]) {
    if (space == NULL || output == NULL) {
        errno = EINVAL;
        return -1;
    }
    for (size_t index = 0; index < SPARC64_LINUX_PATH_MAX; index++) {
        if (guest_address > UINT64_MAX - (uint64_t)index) {
            errno = EFAULT;
            return -1;
        }
        unsigned char byte = 0;
        if (!sparc64_space_read(space, guest_address + (uint64_t)index, &byte, 1,
                           SPARC64_MEM_READ)) {
            errno = sparc64_fault_is_runtime(space->fault_reason) ? ENOMEM : EFAULT;
            return -1;
        }
        output[index] = (char)byte;
        if (byte == 0)
            return 0;
    }
    errno = ENAMETOOLONG;
    return -1;
}

static bool bounded_length(const char *text, size_t limit, size_t *length) {
    if (text == NULL)
        return false;
    for (size_t index = 0; index < limit; index++) {
        if (text[index] == '\0') {
            *length = index;
            return true;
        }
    }
    return false;
}

int sparc64_linux_path_join(const char *sysroot, const char *guest_path,
                       char output[SPARC64_LINUX_HOST_PATH_MAX]) {
    size_t path_length = 0;
    if (output == NULL || !bounded_length(guest_path, SPARC64_LINUX_PATH_MAX,
                                          &path_length)) {
        errno = guest_path == NULL || output == NULL ? EINVAL : ENAMETOOLONG;
        return -1;
    }
    if (guest_path[0] != '/' || sysroot == NULL) {
        memcpy(output, guest_path, path_length + 1);
        return 0;
    }

    size_t root_length = 0;
    if (!bounded_length(sysroot, SPARC64_LINUX_HOST_PATH_MAX, &root_length)) {
        errno = ENAMETOOLONG;
        return -1;
    }
    while (root_length > 1 && sysroot[root_length - 1] == '/')
        root_length--;
    size_t path_offset = 1;
    size_t suffix_length = path_length - path_offset;
    bool root_is_slash = root_length == 1 && sysroot[0] == '/';
    size_t separator = root_is_slash || suffix_length == 0 ? 0 : 1;
    if (root_length > SIZE_MAX - separator ||
        root_length + separator > SIZE_MAX - suffix_length ||
        root_length + separator + suffix_length >= SPARC64_LINUX_HOST_PATH_MAX) {
        errno = ENAMETOOLONG;
        return -1;
    }
    memcpy(output, sysroot, root_length);
    size_t cursor = root_length;
    if (separator != 0)
        output[cursor++] = '/';
    memcpy(output + cursor, guest_path + path_offset, suffix_length);
    output[cursor + suffix_length] = '\0';
    return 0;
}

static int unsupported_flags(void) {
    errno = EOPNOTSUPP;
    return -1;
}

int sparc64_linux_open_flags(uint32_t guest_flags, int *native_flags,
                        bool *guest_cloexec) {
    if (native_flags == NULL || guest_cloexec == NULL) {
        errno = EINVAL;
        return -1;
    }

    /* Linux v6.18 include/uapi/asm-generic/fcntl.h open bit assignments. */
    const uint32_t access_mask = UINT32_C(3);
    const uint32_t o_creat = UINT32_C(00000100);
    const uint32_t o_excl = UINT32_C(00000200);
    const uint32_t o_noctty = UINT32_C(00000400);
    const uint32_t o_trunc = UINT32_C(00001000);
    const uint32_t o_append = UINT32_C(00002000);
    const uint32_t o_nonblock = UINT32_C(00004000);
    const uint32_t o_dsync = UINT32_C(00010000);
    const uint32_t o_async = UINT32_C(00020000);
    const uint32_t o_direct = UINT32_C(00040000);
    const uint32_t o_largefile = UINT32_C(00100000);
    const uint32_t o_directory = UINT32_C(00200000);
    const uint32_t o_nofollow = UINT32_C(00400000);
    const uint32_t o_noatime = UINT32_C(01000000);
    const uint32_t o_cloexec = UINT32_C(02000000);
    const uint32_t o_sync_extra = UINT32_C(04000000);
    const uint32_t o_sync = o_sync_extra | o_dsync;
    const uint32_t o_path = UINT32_C(010000000);
    const uint32_t o_tmpfile = UINT32_C(020000000);
    /* Legacy Linux openat normalizes O_PATH before access-mode/other flags.
     * In particular, ignored O_CREAT/O_TRUNC must never cause side effects. */
    if ((guest_flags & o_path) != 0)
        guest_flags &= o_path | o_directory | o_nofollow | o_cloexec;
    if ((guest_flags & (o_creat | o_directory)) == (o_creat | o_directory)) {
        errno = EINVAL;
        return -1;
    }
    const uint32_t reject = o_async | o_direct | o_noatime | o_tmpfile;
    const uint32_t accepted = access_mask | o_creat | o_excl | o_noctty |
        o_trunc | o_append | o_nonblock | o_dsync | o_largefile | o_directory |
        o_nofollow | o_cloexec | o_sync | o_path;
    if ((guest_flags & reject) != 0 || (guest_flags & ~accepted) != 0)
        return unsupported_flags();

    int result = O_CLOEXEC;
    switch (guest_flags & access_mask) {
    case 0: result |= O_RDONLY; break;
    case 1: result |= O_WRONLY; break;
    case 2: result |= O_RDWR; break;
    default: return unsupported_flags();
    }
#define SPARC64_MAP_OPEN_FLAG(guest_bit, host_flag) \
    do { if ((guest_flags & (guest_bit)) != 0) { \
        result |= (host_flag); } } while (0)
    SPARC64_MAP_OPEN_FLAG(o_creat, O_CREAT);
    SPARC64_MAP_OPEN_FLAG(o_excl, O_EXCL);
    SPARC64_MAP_OPEN_FLAG(o_noctty, O_NOCTTY);
    SPARC64_MAP_OPEN_FLAG(o_trunc, O_TRUNC);
    SPARC64_MAP_OPEN_FLAG(o_append, O_APPEND);
    SPARC64_MAP_OPEN_FLAG(o_nonblock, O_NONBLOCK);
#ifdef O_DSYNC
    SPARC64_MAP_OPEN_FLAG(o_dsync, O_DSYNC);
#else
    if ((guest_flags & o_dsync) != 0) return unsupported_flags();
#endif
#ifdef O_DIRECTORY
    SPARC64_MAP_OPEN_FLAG(o_directory, O_DIRECTORY);
#else
    if ((guest_flags & o_directory) != 0) return unsupported_flags();
#endif
#ifdef O_NOFOLLOW
    SPARC64_MAP_OPEN_FLAG(o_nofollow, O_NOFOLLOW);
#else
    if ((guest_flags & o_nofollow) != 0) return unsupported_flags();
#endif
#ifdef O_SYNC
    SPARC64_MAP_OPEN_FLAG(o_sync_extra, O_SYNC);
#else
    if ((guest_flags & o_sync_extra) != 0) return unsupported_flags();
#endif
#ifdef O_PATH
    SPARC64_MAP_OPEN_FLAG(o_path, O_PATH);
#else
    if ((guest_flags & o_path) != 0) return unsupported_flags();
#endif
#undef SPARC64_MAP_OPEN_FLAG
    *native_flags = result;
    *guest_cloexec = (guest_flags & o_cloexec) != 0;
    return 0;
}

uint32_t sparc64_linux_getfl(int native_flags) {
    uint32_t result;
    switch (native_flags & O_ACCMODE) {
    case O_WRONLY: result = 1; break;
    case O_RDWR: result = 2; break;
    default: result = 0; break;
    }
    if ((native_flags & O_APPEND) != 0)
        result |= UINT32_C(00002000);
    if ((native_flags & O_NONBLOCK) != 0)
        result |= UINT32_C(00004000);
#ifdef O_DSYNC
    if ((native_flags & O_DSYNC) != 0)
        result |= UINT32_C(00010000);
#endif
#ifdef O_SYNC
    if ((native_flags & O_SYNC) == O_SYNC && O_SYNC != O_DSYNC)
        result |= UINT32_C(04010000);
#endif
#ifdef O_DIRECTORY
    if ((native_flags & O_DIRECTORY) != 0)
        result |= UINT32_C(00200000);
#endif
#ifdef O_NOFOLLOW
    if ((native_flags & O_NOFOLLOW) != 0)
        result |= UINT32_C(00400000);
#endif
#ifdef O_LARGEFILE
    if ((native_flags & O_LARGEFILE) != 0)
        result |= UINT32_C(00100000);
#endif
#ifdef O_PATH
    if ((native_flags & O_PATH) != 0)
        result |= UINT32_C(010000000);
#endif
    return result;
}
