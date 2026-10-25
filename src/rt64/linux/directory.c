/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#define _GNU_SOURCE 1
#define _POSIX_C_SOURCE 200809L
#if defined(__APPLE__)
#define _DARWIN_C_SOURCE 1
#endif
#include "linux/directory.h"
#include "linux/error.h"
#include "linux/path.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#if defined(__linux__)
#include <sys/syscall.h>
#endif
#include <unistd.h>

#define SPARC64_AT_FDCWD UINT32_C(0xffffff9c)
#define SPARC64_DIRENT_STAGE ((size_t)65536)

#if defined(SPARC64_DIRECTORY_SYSCALL_SPY) && defined(__linux__)
extern long sparc64_directory_test_getdents64(int host_fd, void *bytes, size_t size);
#endif

static uint64_t fail_guest(unsigned int guest_errno)
{
    return UINT64_C(0) - guest_errno;
}

static uint64_t fail_errno(int host_errno)
{
    return fail_guest(sparc64_linux_errno(host_errno == 0 ? EIO : host_errno));
}

#if defined(__linux__)
static long native_getdents64(int host_fd, void *bytes, size_t size)
{
#if defined(SPARC64_DIRECTORY_SYSCALL_SPY)
    return sparc64_directory_test_getdents64(host_fd, bytes, size);
#else
    return syscall(SYS_getdents64, host_fd, bytes, size);
#endif
}

static uint64_t output_failure(sparc64_space_t *space, uint64_t address, size_t size)
{
    bool in_domain = address >= SPARC64_PAGE_SIZE && address < space->limit &&
                     size <= space->limit - address;
    return fail_guest(sparc64_fault_is_runtime(space->fault_reason) && in_domain ? 12 : 14);
}

static bool valid_linux_dirents(const unsigned char *bytes, size_t size)
{
    size_t cursor = 0;
    while (cursor < size) {
        if (size - cursor < 24)
            return false;
        unsigned int record = (unsigned int)bytes[cursor + 16] |
                              (unsigned int)bytes[cursor + 17] << 8;
        if (record < 24 || record % 8 != 0 || record > size - cursor)
            return false;
        if (memchr(bytes + cursor + 19, 0, record - 19) == NULL)
            return false;
        cursor += record;
    }
    return true;
}
#endif

static uint64_t directory_entries(sparc64_linux_file_t *files, const uint64_t args[6])
{
#if !defined(__linux__)
    (void)files;
    (void)args;
    return fail_guest(38);
#else
    sparc64_fd_borrow_t borrowed = {0};
    if (sparc64_fd_borrow(&files->descriptors, (uint32_t)args[0], &borrowed) != 0)
        return fail_errno(errno);
    int status_flags = fcntl(borrowed.host_fd, F_GETFL);
    int status_error = errno;
    if (status_flags < 0) {
        (void)sparc64_fd_unborrow(&borrowed);
        return fail_errno(status_error);
    }
#ifdef O_PATH
    if ((status_flags & O_PATH) != 0) {
        (void)sparc64_fd_unborrow(&borrowed);
        return fail_guest(9);
    }
#endif
    struct stat status;
    if (fstat(borrowed.host_fd, &status) < 0) {
        int saved = errno;
        (void)sparc64_fd_unborrow(&borrowed);
        return fail_errno(saved);
    }
    if (!S_ISDIR(status.st_mode)) {
        (void)sparc64_fd_unborrow(&borrowed);
        return fail_guest(20);
    }
    /* count is an unsigned int Linux syscall formal; high register bits are
     * discarded before the kernel interprets it. */
    uint32_t requested = (uint32_t)args[2];
    /* The kernel checks count and the output pointer only while emitting a
     * record. A zero-length probe leaves the shared directory cursor intact
     * and distinguishes EOF from a bad count or output address. */
    unsigned char probe[24];
    long eof_probe = native_getdents64(borrowed.host_fd, probe, 0);
    if (eof_probe == 0) {
        (void)sparc64_fd_unborrow(&borrowed);
        return 0;
    }
    if (eof_probe < 0 && errno != EINVAL) {
        int saved = errno;
        (void)sparc64_fd_unborrow(&borrowed);
        return fail_errno(saved);
    }
    if (requested == 0) {
        (void)sparc64_fd_unborrow(&borrowed);
        return fail_guest(22);
    }
    size_t size = requested < SPARC64_DIRENT_STAGE ? (size_t)requested : SPARC64_DIRENT_STAGE;
    /* Linux filldir64 need not initialize the alignment bytes following a
     * name. Never copy stale runtime heap contents into guest memory. */
    unsigned char *staged = calloc(1, size);
    if (staged == NULL) {
        (void)sparc64_fd_unborrow(&borrowed);
        return fail_guest(12);
    }
    size_t prepared = 0;
    while (prepared < size) {
        uint64_t at = args[1] + prepared;
        if (at < args[1]) {
            if (prepared == 0) {
                free(staged);
                (void)sparc64_fd_unborrow(&borrowed);
                return fail_guest(14);
            }
            break;
        }
        size_t part = SPARC64_PAGE_SIZE - (size_t)(at % SPARC64_PAGE_SIZE);
        if (part > size - prepared)
            part = size - prepared;
        if (!sparc64_space_prepare_write(files->space, at, part)) {
            if (sparc64_fault_is_runtime(files->space->fault_reason) || prepared == 0) {
                uint64_t failed = output_failure(files->space, at, part);
                free(staged);
                (void)sparc64_fd_unborrow(&borrowed);
                return failed;
            }
            break;
        }
        prepared += part;
    }
    /* Preserve the native cursor when aliases exhaust aggregate write
     * capacity. Individual-page probes alone cannot count repeated epochs. */
    if (!sparc64_space_prepare_write(files->space, args[1], prepared)) {
        uint64_t failed = output_failure(files->space, args[1], prepared);
        free(staged);
        (void)sparc64_fd_unborrow(&borrowed);
        return failed;
    }
    long read_count = native_getdents64(borrowed.host_fd, staged, prepared);
    int saved = errno;
    uint64_t short_result = 0;
    bool checked_short = false;
    if (read_count < 0 && saved == EINVAL && prepared < size) {
        /* EINVAL can mean either that the original count cannot hold the
         * next record or that the valid output prefix ends before it. Peek
         * using the original count and restore the directory cookie. */
        off_t cookie = lseek(borrowed.host_fd, 0, SEEK_CUR);
        if (cookie < 0) {
            short_result = fail_errno(errno);
        } else {
            long full = native_getdents64(borrowed.host_fd, staged, size);
            int full_error = errno;
            if (lseek(borrowed.host_fd, cookie, SEEK_SET) < 0)
                short_result = fail_errno(errno);
            else if (full < 0)
                short_result = fail_errno(full_error);
            else
                short_result = full == 0 ? 0 : fail_guest(14);
        }
        checked_short = true;
    }
    (void)sparc64_fd_unborrow(&borrowed);
    uint64_t result;
    if (checked_short)
        result = short_result;
    else if (read_count < 0)
        result = fail_errno(saved);
    else if ((size_t)read_count > prepared ||
             !valid_linux_dirents(staged, (size_t)read_count))
        result = fail_guest(5);
    else if (read_count != 0 &&
             !sparc64_space_write(files->space, args[1], staged, (size_t)read_count))
        result = output_failure(files->space, args[1], (size_t)read_count);
    else
        result = (uint64_t)read_count;
    free(staged);
    return result;
#endif
}

static uint64_t create_directory(sparc64_linux_file_t *files, const uint64_t args[6])
{
    char guest_path[SPARC64_LINUX_PATH_MAX], path[SPARC64_LINUX_HOST_PATH_MAX];
    if (sparc64_linux_copy_path(files->space, args[1], guest_path) != 0)
        return fail_errno(errno);
    if (guest_path[0] == '\0')
        return fail_guest(2);
    if (sparc64_linux_path_join(files->sysroot, guest_path, path) != 0)
        return fail_errno(errno);
    int lease = -1, directory_fd = AT_FDCWD;
    if (guest_path[0] != '/' && (uint32_t)args[0] != SPARC64_AT_FDCWD) {
        lease = sparc64_fd_acquire(&files->descriptors, (uint32_t)args[0]);
        if (lease < 0)
            return fail_errno(errno);
        directory_fd = lease;
    }
    sparc64_path_leaf_t leaf;
    int walked = sparc64_path_resolve_leaf(&files->paths, directory_fd, path,
                                      false, false, &leaf);
    int saved = errno;
    if (lease >= 0)
        (void)sparc64_fd_release(lease);
    if (walked < 0)
        return fail_errno(saved);
    int created = mkdirat(leaf.parent_fd, leaf.component, (mode_t)(uint32_t)args[2]);
    saved = errno;
    (void)close(leaf.parent_fd);
    return created < 0 ? fail_errno(saved) : 0;
}

static uint64_t create_fifo(sparc64_linux_file_t *files, const uint64_t args[6])
{
    /* This first managed-FIFO path accepts only FIFO nodes. Other mknodat
     * device and regular-file forms need their own codecs. */
    if (((uint32_t)args[2] & S_IFMT) != S_IFIFO)
        return fail_guest(38);
    char guest_path[SPARC64_LINUX_PATH_MAX], path[SPARC64_LINUX_HOST_PATH_MAX];
    if (sparc64_linux_copy_path(files->space, args[1], guest_path) != 0)
        return fail_errno(errno);
    if (guest_path[0] == '\0')
        return fail_guest(2);
    if (sparc64_linux_path_join(files->sysroot, guest_path, path) != 0)
        return fail_errno(errno);
    int lease = -1, directory_fd = AT_FDCWD;
    if (guest_path[0] != '/' && (uint32_t)args[0] != SPARC64_AT_FDCWD) {
        lease = sparc64_fd_acquire(&files->descriptors, (uint32_t)args[0]);
        if (lease < 0)
            return fail_errno(errno);
        directory_fd = lease;
    }
    sparc64_path_leaf_t leaf;
    int walked = sparc64_path_resolve_leaf(&files->paths, directory_fd, path,
                                      false, false, &leaf);
    int saved = errno;
    if (lease >= 0)
        (void)sparc64_fd_release(lease);
    if (walked < 0)
        return fail_errno(saved);
    /* mknodat does not create through a trailing slash. The resolved leaf
     * omits that slash, so reject it before mkfifoat or registry publication. */
    if (leaf.trailing_slash) {
        struct stat existing;
        int checked = fstatat(leaf.parent_fd, leaf.component, &existing,
                              AT_SYMLINK_NOFOLLOW);
        int check_errno = errno;
        (void)close(leaf.parent_fd);
        return checked == 0 ? fail_guest(17) : fail_errno(check_errno);
    }
    if (!sparc64_linux_file_reserve_fifo(files)) {
        saved = errno;
        (void)close(leaf.parent_fd);
        return fail_errno(saved);
    }
    int created = mkfifoat(leaf.parent_fd, leaf.component,
                           (mode_t)((uint32_t)args[2] & 07777u));
    saved = errno;
    if (created == 0)
        sparc64_linux_file_record_fifo(files, leaf.parent_fd, leaf.component);
    (void)close(leaf.parent_fd);
    return created < 0 ? fail_errno(saved) : 0;
}

bool sparc64_linux_directory_dispatch(sparc64_linux_file_t *files, uint64_t number,
                                 const uint64_t arguments[6], uint64_t *result)
{
    if (files == NULL || arguments == NULL || result == NULL)
        return false;
    switch (number) {
    case 33: *result = create_fifo(files, arguments); break;
    case 34: *result = create_directory(files, arguments); break;
    case 61: *result = directory_entries(files, arguments); break;
    default: return false;
    }
    return true;
}
