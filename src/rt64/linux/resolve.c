/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L
#if defined(__APPLE__)
#define _DARWIN_C_SOURCE 1
#endif
#include "linux/resolve.h"
#include "linux/path.h"

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#if defined(__linux__)
#include <sys/vfs.h>
#endif

struct sparc64_path_identity {
    dev_t device;
    ino_t inode;
    size_t temporary_refs;
    bool permanent;
};

struct sparc64_path_registration {
    sparc64_path_resolver_t *resolver;
    dev_t device;
    ino_t inode;
};

struct sparc64_path_quarantine {
    int fd;
    sparc64_path_quarantine_t *next;
};

static bool allowed_identity(const sparc64_path_resolver_t *resolver,
                              const struct stat *status)
{
    for (size_t i = 0; i < resolver->protected_count; ++i) {
        const sparc64_path_identity_t *identity = &resolver->protected_inodes[i];
        if (identity->device == status->st_dev && identity->inode == status->st_ino) {
            errno = EACCES;
            return false;
        }
    }
    return true;
}

int sparc64_path_protect_fd(sparc64_path_resolver_t *resolver, int borrowed_fd)
{
    if (resolver == NULL || !resolver->initialized || borrowed_fd < 0) {
        errno = EINVAL;
        return -1;
    }
    struct stat status;
    if (fstat(borrowed_fd, &status) != 0)
        return -1;
    return sparc64_path_protect_identity(resolver, status.st_dev, status.st_ino);
}

static sparc64_path_identity_t *identity_slot(sparc64_path_resolver_t *resolver,
                                          dev_t device, ino_t inode)
{
    for (size_t i = 0; i < resolver->protected_count; ++i)
        if (resolver->protected_inodes[i].device == device &&
            resolver->protected_inodes[i].inode == inode)
            return &resolver->protected_inodes[i];
    if (resolver->protected_count == resolver->protected_capacity) {
        size_t capacity = resolver->protected_capacity == 0 ? 8 :
                          resolver->protected_capacity * 2;
        if (capacity < resolver->protected_capacity ||
            capacity > SIZE_MAX / sizeof(*resolver->protected_inodes)) {
            errno = EOVERFLOW;
            return NULL;
        }
        sparc64_path_identity_t *grown = realloc(resolver->protected_inodes,
                                            capacity * sizeof(*grown));
        if (grown == NULL)
            return NULL;
        resolver->protected_inodes = grown;
        resolver->protected_capacity = capacity;
    }
    sparc64_path_identity_t *slot = &resolver->protected_inodes[resolver->protected_count++];
    *slot = (sparc64_path_identity_t){.device = device, .inode = inode};
    return slot;
}

int sparc64_path_protect_identity(sparc64_path_resolver_t *resolver, dev_t device,
                              ino_t inode)
{
    if (resolver == NULL || !resolver->initialized) {
        errno = EINVAL;
        return -1;
    }
    sparc64_path_identity_t *slot = identity_slot(resolver, device, inode);
    if (slot == NULL)
        return -1;
    slot->permanent = true;
    return 0;
}

int sparc64_path_protect_temporary(sparc64_path_resolver_t *resolver, dev_t device,
                               ino_t inode, sparc64_path_registration_t **out)
{
    if (out == NULL) {
        errno = EINVAL;
        return -1;
    }
    *out = NULL;
    if (resolver == NULL || !resolver->initialized) {
        errno = EINVAL;
        return -1;
    }
    sparc64_path_registration_t *registration = malloc(sizeof(*registration));
    if (registration == NULL)
        return -1;
    sparc64_path_identity_t *slot = identity_slot(resolver, device, inode);
    if (slot == NULL || slot->temporary_refs == SIZE_MAX) {
        int saved = slot == NULL ? errno : EOVERFLOW;
        free(registration);
        errno = saved;
        return -1;
    }
    ++slot->temporary_refs;
    *registration = (sparc64_path_registration_t){resolver, device, inode};
    *out = registration;
    return 0;
}

void sparc64_path_retire_temporary(sparc64_path_registration_t **registration)
{
    if (registration == NULL || *registration == NULL)
        return;
    int saved = errno;
    sparc64_path_registration_t *entry = *registration;
    sparc64_path_resolver_t *resolver = entry->resolver;
    if (resolver == NULL || !resolver->initialized)
        _exit(125);
    bool found = false;
    for (size_t i = 0; i < resolver->protected_count; ++i) {
        sparc64_path_identity_t *slot = &resolver->protected_inodes[i];
        if (slot->device != entry->device || slot->inode != entry->inode)
            continue;
        if (slot->temporary_refs == 0)
            _exit(125);
        --slot->temporary_refs;
        if (slot->temporary_refs == 0 && !slot->permanent) {
            --resolver->protected_count;
            memmove(slot, slot + 1, (resolver->protected_count - i) * sizeof(*slot));
        }
        found = true;
        break;
    }
    if (!found)
        _exit(125);
    free(entry);
    *registration = NULL;
    errno = saved;
}

void sparc64_path_drain_quarantine(void *context)
{
    sparc64_path_resolver_t *resolver = context;
    if (resolver == NULL)
        return;
    int saved = errno;
    while (resolver->quarantine != NULL) {
        sparc64_path_quarantine_t *entry = resolver->quarantine;
        resolver->quarantine = entry->next;
        /* Do not retry close(EINTR): that can close a reused descriptor. */
        (void)close(entry->fd);
        free(entry);
    }
    errno = saved;
}

static int private_directory(int directory, const char *name, bool native_path)
{
    int flags = O_RDONLY;
#ifdef O_PATH
    if (native_path)
        flags = O_PATH;
#else
    (void)native_path;
#endif
    int opened = openat(directory, name, flags | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (opened < 0)
        return -1;
#ifdef O_PATH
    if (native_path) {
        int actual_flags = fcntl(opened, F_GETFL);
        if (actual_flags < 0 || (actual_flags & O_PATH) == 0) {
            int saved = actual_flags < 0 ? errno : EOPNOTSUPP;
            (void)close(opened);
            errno = saved;
            return -1;
        }
    }
#endif
    int private_fd = fcntl(opened, F_DUPFD_CLOEXEC, 3);
    int saved = errno;
    (void)close(opened);
    errno = saved;
    return private_fd;
}

void sparc64_path_resolver_destroy(sparc64_path_resolver_t *resolver)
{
    if (resolver == NULL)
        return;
    for (size_t i = 0; i < resolver->protected_count; ++i)
        if (resolver->protected_inodes[i].temporary_refs != 0)
            _exit(125); /* An owner must retire before releasing its inode pin. */
    sparc64_path_drain_quarantine(resolver);
    free(resolver->protected_inodes);
    if (resolver->initialized && resolver->root_fd >= 0)
        (void)close(resolver->root_fd);
    for (size_t i = 0; i < 2; ++i)
        if (resolver->initialized && resolver->denied_fds[i] >= 0)
            (void)close(resolver->denied_fds[i]);
    *resolver = (sparc64_path_resolver_t){.root_fd = -1, .denied_fds = {-1, -1}};
}

int sparc64_path_resolver_init(sparc64_path_resolver_t *resolver)
{
    if (resolver == NULL) {
        errno = EINVAL;
        return -1;
    }
    *resolver = (sparc64_path_resolver_t){.root_fd = -1, .denied_fds = {-1, -1}};
    resolver->root_fd = private_directory(AT_FDCWD, "/", false);
    if (resolver->root_fd < 0)
        return -1;
    resolver->initialized = true;
#ifdef O_PATH
    /* Probe before retaining denied identities. Hosts may drop unknown flags;
     * every path-only pin is also checked individually in private_directory.
     * A readable proc directory has cursor state that cannot be value-copied
     * across a host's spawn-based fork implementation. */
    int probe = private_directory(resolver->root_fd, ".", true);
    if (probe < 0) {
        int saved = errno;
        sparc64_path_resolver_destroy(resolver);
        errno = saved;
        return -1;
    }
    (void)close(probe);
    resolver->native_path_supported = true;
#endif
    const char *denied[2] = {"/proc", "/dev/fd"};
    for (size_t i = 0; i < 2; ++i) {
        resolver->denied_fds[i] = private_directory(AT_FDCWD, denied[i],
                                                  resolver->native_path_supported);
        if (resolver->denied_fds[i] < 0 && errno != ENOENT && errno != ENOTDIR && errno != ELOOP) {
            int saved = errno;
            sparc64_path_resolver_destroy(resolver);
            errno = saved;
            return -1;
        }
    }
    return 0;
}

static bool allowed_directory(const sparc64_path_resolver_t *resolver, int directory)
{
    struct stat status;
    if (fstat(directory, &status) < 0)
        return false;
    if (!allowed_identity(resolver, &status))
        return false;
    if (!S_ISDIR(status.st_mode)) {
        errno = ENOTDIR;
        return false;
    }
#if defined(__linux__)
    struct statfs filesystem;
    if (fstatfs(directory, &filesystem) < 0)
        return false;
    /* Includes procfs bind subtrees and all PID/task/fd aliases. hl reports
     * native filesystem types, so retained directory identities also matter. */
    if ((unsigned long)filesystem.f_type == 0x9fa0UL) {
        errno = EOPNOTSUPP;
        return false;
    }
#endif
    for (size_t i = 0; i < 2; ++i) {
        if (resolver->denied_fds[i] >= 0) {
            struct stat denied;
            if (fstat(resolver->denied_fds[i], &denied) < 0)
                return false;
            if (denied.st_dev == status.st_dev && denied.st_ino == status.st_ino) {
                errno = EOPNOTSUPP;
                return false;
            }
        }
    }
    return true;
}

static int path_walk(sparc64_path_resolver_t *resolver, int directory_fd,
                     const char *path, bool follow_final,
                     bool follow_trailing_symlink, bool creating,
                     bool check_final_directory,
                     sparc64_path_leaf_t *leaf)
{
    if (resolver == NULL || !resolver->initialized || path == NULL || leaf == NULL) {
        errno = EINVAL;
        return -1;
    }
    leaf->parent_fd = -1;
    leaf->component[0] = '\0';
    leaf->trailing_slash = false;
    size_t length = strnlen(path, SPARC64_LINUX_HOST_PATH_MAX);
    if (length == 0 || length == SPARC64_LINUX_HOST_PATH_MAX) {
        errno = length == 0 ? ENOENT : ENAMETOOLONG;
        return -1;
    }
    char pending[SPARC64_LINUX_HOST_PATH_MAX];
    memcpy(pending, path, length + 1);
    struct stat initial;
    int stated_initial = path[0] == '/' ? fstat(resolver->root_fd, &initial) :
                         fstatat(directory_fd, ".", &initial, AT_SYMLINK_NOFOLLOW);
    if (stated_initial != 0 || !allowed_identity(resolver, &initial))
        return -1;
    int directory = path[0] == '/' ? fcntl(resolver->root_fd, F_DUPFD_CLOEXEC, 3) :
                    private_directory(directory_fd, ".", resolver->native_path_supported);
    if (directory < 0)
        return -1;
    unsigned int followed = 0;
    for (;;) {
        if (!allowed_directory(resolver, directory))
            break;
        size_t first = 0;
        while (pending[first] == '/')
            ++first;
        size_t end = first;
        while (pending[end] != '/' && pending[end] != '\0')
            ++end;
        size_t remaining = end;
        while (pending[remaining] == '/')
            ++remaining;
        bool final = pending[remaining] == '\0';
        bool trailing_slash = final && pending[end] == '/';
        char component[SPARC64_LINUX_PATH_MAX];
        size_t component_length = end - first;
        if (component_length >= sizeof(component)) {
            errno = ENAMETOOLONG;
            break;
        }
        if (component_length == 0) {
            component[0] = '.';
            component_length = 1;
        } else
            memcpy(component, pending + first, component_length);
        component[component_length] = '\0';
        struct stat status;
        /* Linux namei checks slash-implied creation after walking the parent,
         * before final lookup. It differs from caller O_DIRECTORY|O_CREAT. */
        if (final && trailing_slash && creating) {
            errno = EISDIR;
            break;
        }
        int stated = fstatat(directory, component, &status, AT_SYMLINK_NOFOLLOW);
        if (stated < 0 && (!final || errno != ENOENT))
            break;
        /* Covers regular final leaves as well as directory and hard-link
         * aliases, before publishing a leaf to metadata or unlink callers. */
        if (stated == 0 && !allowed_identity(resolver, &status))
            break;
        if (stated == 0 && S_ISLNK(status.st_mode) &&
            (!final || follow_final ||
             (trailing_slash && follow_trailing_symlink))) {
            if (++followed > 40) {
                errno = ELOOP;
                break;
            }
            char target[SPARC64_LINUX_HOST_PATH_MAX];
            ssize_t size = readlinkat(directory, component, target, sizeof(target));
            if (size < 0)
                break;
            size_t suffix = strlen(pending + end);
            if (size == 0 || (size_t)size >= sizeof(target) ||
                (size_t)size + suffix >= sizeof(pending)) {
                errno = size == 0 ? ENOENT : ENAMETOOLONG;
                break;
            }
            memcpy(target + size, pending + end, suffix + 1);
            memcpy(pending, target, (size_t)size + suffix + 1);
            if (pending[0] == '/') {
                int root = fcntl(resolver->root_fd, F_DUPFD_CLOEXEC, 3);
                if (root < 0)
                    break;
                (void)close(directory);
                directory = root;
            }
            continue;
        }
        if (final) {
            if (check_final_directory && stated == 0 && S_ISDIR(status.st_mode)) {
                /* A final directory may itself be a native descriptor
                 * namespace. Check its pinned identity before publishing
                 * this leaf to a metadata operation. */
                int checked = private_directory(directory, component,
                                                resolver->native_path_supported);
                if (checked < 0)
                    break;
                bool allowed = allowed_directory(resolver, checked);
                int saved = errno;
                (void)close(checked);
                if (!allowed) {
                    errno = saved;
                    break;
                }
            }
            memcpy(leaf->component, component, component_length + 1);
            leaf->parent_fd = directory;
            leaf->trailing_slash = trailing_slash;
            return 0;
        }
        int next = private_directory(directory, component, resolver->native_path_supported);
        if (next < 0)
            break;
        (void)close(directory);
        directory = next;
        memmove(pending, pending + remaining, strlen(pending + remaining) + 1);
    }
    int saved = errno;
    (void)close(directory);
    errno = saved;
    return -1;
}

int sparc64_path_resolve_leaf(sparc64_path_resolver_t *resolver, int directory_fd,
                         const char *path, bool follow_final,
                         bool follow_trailing_symlink,
                         sparc64_path_leaf_t *leaf)
{
    return path_walk(resolver, directory_fd, path, follow_final,
                     follow_trailing_symlink, false, true, leaf);
}

static int path_open(sparc64_path_resolver_t *resolver, int directory_fd,
                     const char *path, int flags, mode_t mode,
                     sparc64_path_open_result_t *guest_result,
                     sparc64_path_truncate_fn truncate, void *truncate_context)
{
    if (resolver == NULL || !resolver->initialized || path == NULL) {
        errno = EINVAL;
        return -1;
    }
#ifdef O_PATH
    if ((flags & O_PATH) != 0 && !resolver->native_path_supported) {
        errno = EOPNOTSUPP;
        return -1;
    }
#endif
    bool follow_final = (flags & O_NOFOLLOW) == 0 &&
                        (flags & (O_CREAT | O_EXCL)) != (O_CREAT | O_EXCL);
    bool truncating = (flags & O_TRUNC) != 0;
#ifdef O_PATH
    if ((flags & O_PATH) != 0)
        truncating = false; /* Linux O_PATH ignores O_TRUNC. */
#endif
    bool guest_ro_trunc = guest_result != NULL && truncating &&
                          (flags & O_ACCMODE) == O_RDONLY;
    sparc64_path_leaf_t leaf;
    if (path_walk(resolver, directory_fd, path, follow_final, true,
                  (flags & O_CREAT) != 0, !guest_ro_trunc, &leaf) != 0)
        return -1;
    bool protected = resolver->protected_count != 0;
    if (protected && truncating && (flags & O_ACCMODE) == O_RDONLY &&
        !guest_ro_trunc) {
        (void)close(leaf.parent_fd);
        errno = EOPNOTSUPP;
        return -1;
    }
    /* Type selection uses no extra open/close on the target inode. If a
     * concurrent replacement changes a nonregular candidate into a regular
     * one, the post-open check fails closed before any truncation. */
    bool upgrade = false;
    bool checked_nonregular = false;
    struct stat nonregular_identity;
    if (guest_ro_trunc) {
        struct stat candidate;
        bool exclusive_create = (flags & (O_CREAT | O_EXCL)) ==
                                (O_CREAT | O_EXCL);
        if (fstatat(leaf.parent_fd, leaf.component, &candidate,
                    AT_SYMLINK_NOFOLLOW) == 0) {
            if (!exclusive_create && S_ISDIR(candidate.st_mode)) {
                (void)close(leaf.parent_fd);
                errno = EISDIR;
                return -1;
            }
            upgrade = S_ISREG(candidate.st_mode);
            /* Linux's O_TRUNC adds MAY_WRITE even when opening a FIFO or
             * device read-only. Keep its native open mode unchanged, but
             * check that extra permission on the pinned final component.
             * Recheck identity because this access query uses a pathname. */
            if (!exclusive_create && !upgrade) {
                int allowed = faccessat(leaf.parent_fd, leaf.component, W_OK,
                                        AT_EACCESS | AT_SYMLINK_NOFOLLOW);
                int saved = errno;
                struct stat after;
                int stated = fstatat(leaf.parent_fd, leaf.component, &after,
                                     AT_SYMLINK_NOFOLLOW);
                if (stated != 0 || candidate.st_dev != after.st_dev ||
                    candidate.st_ino != after.st_ino) {
                    (void)close(leaf.parent_fd);
                    errno = EAGAIN;
                    return -1;
                }
                if (allowed != 0) {
                    (void)close(leaf.parent_fd);
                    errno = saved;
                    return -1;
                }
                nonregular_identity = after;
                checked_nonregular = true;
            }
        } else if (errno == ENOENT && (flags & O_CREAT) != 0)
            upgrade = true;
    }
    /* Allocation must precede any open. Even closing a rejected descriptor
     * for a locked inode would release all this process's locks on it. */
    sparc64_path_quarantine_t *reserved = protected ? malloc(sizeof(*reserved)) : NULL;
    if (protected && reserved == NULL) {
        int saved = errno;
        (void)close(leaf.parent_fd);
        errno = saved;
        return -1;
    }
    int native_flags = protected || guest_ro_trunc || truncate != NULL ?
                       flags & ~O_TRUNC : flags;
    if (upgrade)
        native_flags = (native_flags & ~O_ACCMODE) | O_RDWR;
#ifdef SPARC64_PATH_TESTING
    if (resolver->test_before_open != NULL)
        resolver->test_before_open(leaf.parent_fd, leaf.component, resolver->test_context);
#endif
    int result = openat(leaf.parent_fd, leaf.component,
                        native_flags | O_NOFOLLOW |
                        (leaf.trailing_slash ? O_DIRECTORY : 0), mode);
    int saved = errno;
    if (result >= 0) {
        struct stat opened;
        int stated = fstat(result, &opened);
#ifdef SPARC64_PATH_TESTING
        if (resolver->test_fail_open_stat) {
            stated = -1;
            errno = EIO;
        }
#endif
        bool changed_nonregular = stated == 0 && checked_nonregular &&
            (nonregular_identity.st_dev != opened.st_dev ||
             nonregular_identity.st_ino != opened.st_ino ||
             nonregular_identity.st_mode != opened.st_mode);
        if (stated < 0 || !allowed_identity(resolver, &opened)) {
            saved = errno;
            if (reserved != NULL) {
                reserved->fd = result;
                reserved->next = resolver->quarantine;
                resolver->quarantine = reserved;
                reserved = NULL;
            } else
                (void)close(result);
            result = -1;
        } else {
            bool reject = changed_nonregular ||
                          (guest_ro_trunc && S_ISDIR(opened.st_mode)) ||
                          (guest_ro_trunc && upgrade != S_ISREG(opened.st_mode)) ||
                          (S_ISDIR(opened.st_mode) &&
                           !allowed_directory(resolver, result));
            if (reject) {
                saved = changed_nonregular ? EAGAIN :
                        (guest_ro_trunc && S_ISDIR(opened.st_mode)) ? EISDIR :
                        (guest_ro_trunc && upgrade != S_ISREG(opened.st_mode)) ?
                        EOPNOTSUPP : errno;
                (void)close(result); /* Known unprotected inode. */
                result = -1;
            } else if (truncating && S_ISREG(opened.st_mode) &&
                       truncate != NULL) {
                int native_errno = -1;
                int applied = truncate(result, &native_errno, truncate_context);
                if (applied != 0 || native_errno < 0 || native_errno >= 4096) {
                    saved = EIO;
                    (void)close(result);
                    result = -1;
                } else if (native_errno != 0) {
                    saved = native_errno;
                    (void)close(result);
                    result = -1;
                }
            } else if (truncating && S_ISREG(opened.st_mode) &&
                       (protected || guest_ro_trunc) &&
                       ftruncate(result, 0) != 0) {
                saved = errno;
                (void)close(result);
                result = -1;
            }
        }
    }
    free(reserved);
    (void)close(leaf.parent_fd);
    errno = saved;
    if (result >= 0 && guest_result != NULL)
        *guest_result = (sparc64_path_open_result_t){result, upgrade};
    return result;
}

int sparc64_path_open(sparc64_path_resolver_t *resolver, int directory_fd,
                 const char *path, int flags, mode_t mode)
{
    return path_open(resolver, directory_fd, path, flags, mode, NULL, NULL, NULL);
}

int sparc64_path_open_guest(sparc64_path_resolver_t *resolver, int directory_fd,
                       const char *path, int flags, mode_t mode,
                       sparc64_path_open_result_t *out)
{
    if (out == NULL) {
        errno = EINVAL;
        return -1;
    }
    return path_open(resolver, directory_fd, path, flags, mode, out, NULL, NULL);
}

int sparc64_path_open_guest_with_truncate(sparc64_path_resolver_t *resolver,
                                     int directory_fd, const char *path,
                                     int flags, mode_t mode,
                                     sparc64_path_open_result_t *out,
                                     sparc64_path_truncate_fn truncate,
                                     void *context)
{
    if (out == NULL) {
        errno = EINVAL;
        return -1;
    }
    return path_open(resolver, directory_fd, path, flags, mode, out,
                     truncate, context);
}
