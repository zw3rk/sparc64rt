/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SPARC64RT_LINUX_RESOLVE_H
#define SPARC64RT_LINUX_RESOLVE_H

#include <stdbool.h>
#include <stddef.h>
#include <sys/types.h>

#include "linux/path.h"

typedef struct sparc64_path_identity sparc64_path_identity_t;
typedef struct sparc64_path_quarantine sparc64_path_quarantine_t;
typedef struct sparc64_path_registration sparc64_path_registration_t;

typedef struct {
    int root_fd;
    int denied_fds[2];
    bool native_path_supported;
    bool initialized;
    sparc64_path_identity_t *protected_inodes;
    size_t protected_count;
    size_t protected_capacity;
    sparc64_path_quarantine_t *quarantine;
#ifdef SPARC64_PATH_TESTING
    void (*test_before_open)(int directory_fd, const char *component, void *context);
    void *test_context;
    bool test_fail_open_stat;
#endif
} sparc64_path_resolver_t;

/* Initialize unused or destroyed storage after importing guest stdio; never
 * reinitialize a live resolver. All retained FDs are private >=3.
 * On Linux, denied directory identities require verified cursor-free O_PATH
 * pins; initialization fails if the host does not honor that capability.
 * Native procfs and descriptor namespaces are deliberately unsupported until
 * a guest view exists. Ordinary symlinks are expanded in userspace; the kernel
 * only sees single components with O_NOFOLLOW. This is not a sandbox. */
int sparc64_path_resolver_init(sparc64_path_resolver_t *resolver);
/* Quiescent teardown only: no concurrent callers, temporary registrations or
 * protected process record lock held. Also drains quarantined descriptors. */
void sparc64_path_resolver_destroy(sparc64_path_resolver_t *resolver);
/* Register a borrowed descriptor's inode without opening, duplicating or
 * closing it. The owner pins that inode until resolver destruction. Register
 * before guest exposure; serialize registration and complete guest path
 * operations under the family's token. This is not protection against native
 * processes concurrently replacing names. */
int sparc64_path_protect_fd(sparc64_path_resolver_t *resolver, int borrowed_fd);
/* Same registration for a trusted nofollow stat fact from an owner-pinned
 * family inode. The family retains its directory entry until this resolver
 * is quiescent and destroyed; never use this for unpinned native paths. */
int sparc64_path_protect_identity(sparc64_path_resolver_t *resolver, dev_t device,
                              ino_t inode);
/* Scoped private inode ownership. The caller pins the inode until retiring
 * every registration, before resolver destruction. Serialize both operations
 * and guest path access under the family token or global quiescence. Permanent
 * family registrations remain protected after temporary references retire. */
int sparc64_path_protect_temporary(sparc64_path_resolver_t *resolver, dev_t device,
                               ino_t inode, sparc64_path_registration_t **out);
void sparc64_path_retire_temporary(sparc64_path_registration_t **registration);
/* Close uncertain/protected opens only AFTER successfully releasing record
 * locks and BEFORE another local thread can acquire them. Suitable for the
 * family's post-unlock callback, or globally quiescent teardown. Never call
 * while any protected inode's process record lock must remain held. */
void sparc64_path_drain_quarantine(void *resolver);
typedef struct {
    int host_fd;
    bool logical_read_only; /* Native RW only to perform Linux RO|TRUNC. */
} sparc64_path_open_result_t;

/* Optional protected open-time truncate. The resolver calls this only for a
 * checked regular-file descriptor, after identity and type validation, and
 * before publishing the descriptor. Return 0 with native_errno set to zero
 * for success or a positive errno for a definite native failure. A nonzero
 * return means the effect is uncertain; the resolver closes the unpublished
 * descriptor and reports EIO. The callback must not close descriptor. */
typedef int (*sparc64_path_truncate_fn)(int descriptor, int *native_errno,
                                    void *context);

/* Absolute paths, including absolute symlink targets, restart at native '/'.
 * A sysroot prefix is applied by the caller before this walk. directory_fd is
 * a borrowed private lease or AT_FDCWD. Returns an owned native descriptor.
 * With registered private inodes, O_RDONLY|O_TRUNC deliberately returns
 * EOPNOTSUPP before open until logical guest FD access modes are implemented.
 * Other O_TRUNC opens defer truncation until the opened identity is checked. */
int sparc64_path_open(sparc64_path_resolver_t *resolver, int directory_fd,
                 const char *path, int flags, mode_t mode);
/* Guest-open variant carries a logical access mode whenever a single native
 * RDWR open is required to implement Linux O_RDONLY|O_TRUNC. The caller must
 * retain the logical mode on the shared guest open-description. */
int sparc64_path_open_guest(sparc64_path_resolver_t *resolver, int directory_fd,
                       const char *path, int flags, mode_t mode,
                       sparc64_path_open_result_t *out);
/* As above, but routes regular-file O_TRUNC through truncate/context after
 * protected-identity checks. A NULL callback preserves legacy behavior. */
int sparc64_path_open_guest_with_truncate(sparc64_path_resolver_t *resolver,
                                     int directory_fd, const char *path,
                                     int flags, mode_t mode,
                                     sparc64_path_open_result_t *out,
                                     sparc64_path_truncate_fn truncate,
                                     void *context);

typedef struct {
    int parent_fd; /* Owned private descriptor; close after the *at operation. */
    char component[SPARC64_LINUX_PATH_MAX];
    bool trailing_slash;
} sparc64_path_leaf_t;

/* Walk every preceding component beneath pinned directory descriptors.
 * follow_final expands an ordinary final symlink; follow_trailing_symlink
 * selects whether a final symlink followed by '/' is expanded. unlinkat
 * requires false, while stat/access/readlink require true. Final native
 * operations use parent_fd and component only, with no-follow where possible. */
int sparc64_path_resolve_leaf(sparc64_path_resolver_t *resolver, int directory_fd,
                         const char *path, bool follow_final,
                         bool follow_trailing_symlink,
                         sparc64_path_leaf_t *leaf);

#endif
