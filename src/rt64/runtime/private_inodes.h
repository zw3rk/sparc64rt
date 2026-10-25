/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SPARC64RT_RUNTIME_PRIVATE_INODES_H
#define SPARC64RT_RUNTIME_PRIVATE_INODES_H

#include <stdbool.h>
#include <sys/stat.h>

typedef int (*sparc64_family_inode_observer_t)(void *context, const struct stat *status);

bool sparc64_family_owned_entry_name(const char *name);
/* Enumerates the pinned directory by nofollow stat only. In particular it
 * never opens or closes the control inode or any path alias to it. */
int sparc64_family_scan_inodes(int control_fd, int directory_fd,
                           sparc64_family_inode_observer_t observer, void *context);
/* Reject a managed-looking name that actually aliases the control inode
 * before any openat on that name. Native concurrent name replacement remains
 * outside this controlled-family interface. */
int sparc64_family_reject_control_alias(int control_fd, int directory_fd,
                                    const char *name);

#endif
