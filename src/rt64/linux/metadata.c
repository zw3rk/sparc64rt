/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L
#if defined(__APPLE__)
#define _DARWIN_C_SOURCE 1
#endif
#include "linux/metadata.h"
#include "linux/codec.h"
#include "linux/error.h"
#include "linux/path.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#if defined(__linux__)
#include <sys/syscall.h>
#endif

/* Linux 6.18 asm-generic UAPI, independent of host AT_* bit assignments. */
#define SPARC64_AT_FDCWD UINT32_C(0xffffff9c)
#define SPARC64_AT_SYMLINK_NOFOLLOW UINT32_C(0x100)
#define SPARC64_AT_REMOVEDIR UINT32_C(0x200)
#define SPARC64_AT_NO_AUTOMOUNT UINT32_C(0x800)
#define SPARC64_AT_EMPTY_PATH UINT32_C(0x1000)

static uint64_t fail_errno(int host_errno)
{
    unsigned int guest_errno = sparc64_linux_errno(host_errno == 0 ? EIO : host_errno);
    return UINT64_C(0) - guest_errno;
}

static uint64_t fail_guest(unsigned int guest_errno)
{
    return UINT64_C(0) - guest_errno;
}

static int guest_path(sparc64_linux_file_t *files, uint64_t address,
                      char path[SPARC64_LINUX_PATH_MAX])
{
    return sparc64_linux_copy_path(files->space, address, path);
}

/* The guest descriptor is leased only while finding a pinned parent. The
 * returned parent has its own lifetime and must be closed by the caller. */
static int metadata_leaf(sparc64_linux_file_t *files, uint32_t guest_directory,
                         const char *path, bool follow_final,
                         bool follow_trailing_symlink,
                         sparc64_path_leaf_t *leaf)
{
    char resolved[SPARC64_LINUX_HOST_PATH_MAX];
    if (sparc64_linux_path_join(files->sysroot, path, resolved) != 0)
        return -1;
    int lease = -1, native_directory = AT_FDCWD;
    if (path[0] != '/' && guest_directory != SPARC64_AT_FDCWD) {
        lease = sparc64_fd_acquire(&files->descriptors, guest_directory);
        if (lease < 0)
            return -1;
        native_directory = lease;
    }
    int walked = sparc64_path_resolve_leaf(&files->paths, native_directory,
                                      resolved, follow_final,
                                      follow_trailing_symlink, leaf);
    int saved = errno;
    if (lease >= 0)
        (void)sparc64_fd_release(lease);
    errno = saved;
    return walked;
}

static uint64_t encoded_stat(sparc64_linux_file_t *files, const struct stat *status,
                             uint64_t guest_address)
{
    unsigned char encoded[128];
    if (sparc64_codec_stat64(encoded, status) != 0)
        return fail_errno(errno);
    /* Keep runtime-managed copyout faults distinct from bad guest pointers. */
    return sparc64_space_write(files->space, guest_address, encoded, sizeof(encoded)) ?
           0 : fail_guest(sparc64_fault_is_runtime(files->space->fault_reason) ? 12 : 14);
}

/* fchmod acts on the retained open description. It must not reopen a path
 * that may have been replaced after the guest obtained its descriptor. */
static uint64_t chmod_fd(sparc64_linux_file_t *files, const uint64_t args[6])
{
    int lease = sparc64_fd_acquire(&files->descriptors, (uint32_t)args[0]);
    if (lease < 0)
        return fail_errno(errno);
    mode_t mode = (mode_t)(args[1] & UINT64_C(07777));
#if defined(__linux__)
    /* libc may implement fchmod through an empty-path fallback and return a
     * different errno for O_PATH. Match the Linux syscall ABI directly. */
    int changed = (int)syscall(SYS_fchmod, lease, mode);
#else
    int changed = fchmod(lease, mode);
#endif
    int saved = errno;
    (void)sparc64_fd_release(lease);
    return changed < 0 ? fail_errno(saved) : 0;
}

static uint64_t stat_at(sparc64_linux_file_t *files, const uint64_t args[6])
{
    uint32_t flags = (uint32_t)args[3];
    const uint32_t accepted = SPARC64_AT_SYMLINK_NOFOLLOW | SPARC64_AT_NO_AUTOMOUNT |
                              SPARC64_AT_EMPTY_PATH;
    if ((flags & ~accepted) != 0)
        return fail_guest(22);
    char path[SPARC64_LINUX_PATH_MAX];
    if (args[1] == 0 && (flags & SPARC64_AT_EMPTY_PATH) != 0)
        path[0] = '\0'; /* Linux 6.11 also permits NULL with AT_EMPTY_PATH. */
    else if (guest_path(files, args[1], path) != 0)
        return fail_errno(errno);
    struct stat status;
    if (path[0] == '\0') {
        if ((flags & SPARC64_AT_EMPTY_PATH) == 0)
            return fail_guest(2);
        if ((uint32_t)args[0] != SPARC64_AT_FDCWD) {
            int lease = sparc64_fd_acquire(&files->descriptors, (uint32_t)args[0]);
            if (lease < 0)
                return fail_errno(errno);
            int stated = fstat(lease, &status), saved = errno;
            (void)sparc64_fd_release(lease);
            if (stated < 0)
                return fail_errno(saved);
        } else {
            sparc64_path_leaf_t leaf;
            if (metadata_leaf(files, SPARC64_AT_FDCWD, ".", true, true, &leaf) != 0)
                return fail_errno(errno);
            int stated = fstatat(leaf.parent_fd, leaf.component, &status,
                                 AT_SYMLINK_NOFOLLOW), saved = errno;
            (void)close(leaf.parent_fd);
            if (stated < 0)
                return fail_errno(saved);
        }
        return encoded_stat(files, &status, args[2]);
    }
    sparc64_path_leaf_t leaf;
    bool follow = (flags & SPARC64_AT_SYMLINK_NOFOLLOW) == 0;
    if (metadata_leaf(files, (uint32_t)args[0], path, follow, true, &leaf) != 0)
        return fail_errno(errno);
    int stated = fstatat(leaf.parent_fd, leaf.component, &status,
                         AT_SYMLINK_NOFOLLOW), saved = errno;
    (void)close(leaf.parent_fd);
    if (stated < 0)
        return fail_errno(saved);
    /* A final name can be exchanged after the userspace symlink walk. Do
     * not report link metadata as a followed target in that race. */
    if (follow && S_ISLNK(status.st_mode))
        return fail_guest(11);
    if (leaf.trailing_slash && !S_ISDIR(status.st_mode))
        return fail_guest(20);
    return encoded_stat(files, &status, args[2]);
}

static uint64_t access_at(sparc64_linux_file_t *files, const uint64_t args[6])
{
    uint32_t mode = (uint32_t)args[2];
    if ((mode & ~UINT32_C(7)) != 0)
        return fail_guest(22);
    char path[SPARC64_LINUX_PATH_MAX];
    if (guest_path(files, args[1], path) != 0)
        return fail_errno(errno);
    if (path[0] == '\0')
        return fail_guest(2);
    sparc64_path_leaf_t leaf;
    if (metadata_leaf(files, (uint32_t)args[0], path, true, true, &leaf) != 0)
        return fail_errno(errno);
    if (leaf.trailing_slash) {
        struct stat status;
        int stated = fstatat(leaf.parent_fd, leaf.component, &status,
                             AT_SYMLINK_NOFOLLOW), saved = errno;
        if (stated < 0 || !S_ISDIR(status.st_mode)) {
            (void)close(leaf.parent_fd);
            return stated < 0 ? fail_errno(saved) : fail_guest(20);
        }
    }
    int accessed = faccessat(leaf.parent_fd, leaf.component, (int)mode,
                             AT_SYMLINK_NOFOLLOW), saved = errno;
    struct stat after;
    int checked = accessed == 0 ?
                  fstatat(leaf.parent_fd, leaf.component, &after,
                           AT_SYMLINK_NOFOLLOW) : 0;
    int check_errno = errno;
    (void)close(leaf.parent_fd);
    if (accessed == 0 && checked < 0)
        return fail_errno(check_errno);
    if (accessed == 0 && S_ISLNK(after.st_mode))
        return fail_guest(11);
    return accessed < 0 ? fail_errno(saved) : 0;
}

static uint64_t link_at(sparc64_linux_file_t *files, const uint64_t args[6])
{
    /* The kernel argument is signed int, not size_t. */
    uint32_t count = (uint32_t)args[3];
    if (count == 0 || count > INT_MAX)
        return fail_guest(22);
    char path[SPARC64_LINUX_PATH_MAX];
    if (guest_path(files, args[1], path) != 0)
        return fail_errno(errno);
    int lease = -1;
    sparc64_path_leaf_t leaf;
    int parent;
    const char *component;
    if (path[0] == '\0') {
        if ((uint32_t)args[0] == SPARC64_AT_FDCWD || !files->paths.native_path_supported)
            return fail_guest(2);
        lease = sparc64_fd_acquire(&files->descriptors, (uint32_t)args[0]);
        if (lease < 0)
            return fail_errno(errno);
        parent = lease;
        component = "";
    } else {
        if (metadata_leaf(files, (uint32_t)args[0], path, false, true, &leaf) != 0)
            return fail_errno(errno);
        parent = leaf.parent_fd;
        component = leaf.component;
        if (leaf.trailing_slash) {
            struct stat status;
            int stated = fstatat(parent, component, &status,
                                 AT_SYMLINK_NOFOLLOW), saved = errno;
            if (stated < 0 || !S_ISDIR(status.st_mode)) {
                (void)close(parent);
                return stated < 0 ? fail_errno(saved) : fail_guest(20);
            }
        }
    }
    /* A symlink target cannot exceed Linux PATH_MAX. Host views can have a
     * larger caller buffer, but one bounded staging allocation suffices. */
    unsigned char staging[SPARC64_LINUX_PATH_MAX];
    size_t capacity = count < sizeof(staging) ? (size_t)count : sizeof(staging);
    ssize_t copied = readlinkat(parent, component, (char *)staging, capacity);
    int saved = errno;
    struct stat after;
    int checked = copied >= 0 && path[0] != '\0' && leaf.trailing_slash ?
                  fstatat(parent, component, &after, AT_SYMLINK_NOFOLLOW) : 0;
    int check_errno = errno;
    (void)close(parent);
    if (copied < 0)
        return fail_errno(saved);
    if (checked < 0)
        return fail_errno(check_errno);
    if (path[0] != '\0' && leaf.trailing_slash && !S_ISDIR(after.st_mode))
        return fail_guest(11);
    if (!sparc64_space_write(files->space, args[2], staging, (size_t)copied))
        return fail_guest(14);
    return (uint64_t)copied;
}

static uint64_t remove_at(sparc64_linux_file_t *files, const uint64_t args[6])
{
    uint32_t flags = (uint32_t)args[2];
    if ((flags & ~SPARC64_AT_REMOVEDIR) != 0)
        return fail_guest(22);
    char path[SPARC64_LINUX_PATH_MAX];
    if (guest_path(files, args[1], path) != 0)
        return fail_errno(errno);
    if (path[0] == '\0')
        return fail_guest(2);
    sparc64_path_leaf_t leaf;
    if (metadata_leaf(files, (uint32_t)args[0], path, false, false, &leaf) != 0)
        return fail_errno(errno);
    const char *component = leaf.component;
    if (leaf.trailing_slash) {
        /* hl's AArch64 Linux syscall route inherits Darwin's behavior:
         * unlinkat(link/, AT_REMOVEDIR) follows and removes the target.
         * Check the final inode without following on both hosts. An ordinary
         * unlink is rejected; AT_REMOVEDIR cannot remove a replacement
         * non-directory after this check. */
        struct stat status;
        int stated = fstatat(leaf.parent_fd, component, &status,
                             AT_SYMLINK_NOFOLLOW), saved = errno;
        if (stated < 0 || !S_ISDIR(status.st_mode)) {
            (void)close(leaf.parent_fd);
            return stated < 0 ? fail_errno(saved) : fail_guest(20);
        }
        if ((flags & SPARC64_AT_REMOVEDIR) == 0) {
            (void)close(leaf.parent_fd);
            return fail_guest(21);
        }
    }
    int removed = unlinkat(leaf.parent_fd, component,
                           (flags & SPARC64_AT_REMOVEDIR) != 0 ? AT_REMOVEDIR : 0);
    int saved = errno;
    (void)close(leaf.parent_fd);
    return removed < 0 ? fail_errno(saved) : 0;
}

bool sparc64_linux_metadata_dispatch(sparc64_linux_file_t *files, uint64_t number,
                                const uint64_t arguments[6], uint64_t *result)
{
    if (files == NULL || arguments == NULL || result == NULL)
        return false;
    switch (number) {
    case 35: *result = remove_at(files, arguments); break; /* unlinkat */
    case 48: *result = access_at(files, arguments); break; /* faccessat */
    case 52: *result = chmod_fd(files, arguments); break; /* fchmod */
    case 78: *result = link_at(files, arguments); break; /* readlinkat */
    case 79: *result = stat_at(files, arguments); break; /* newfstatat */
    default: return false;
    }
    return true;
}
