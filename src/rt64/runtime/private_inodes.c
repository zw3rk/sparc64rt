/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L
#include "runtime/private_inodes.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

static bool hex_digit(char value)
{
    return (value >= '0' && value <= '9') ||
           (value >= 'a' && value <= 'f') ||
           (value >= 'A' && value <= 'F');
}

bool sparc64_family_owned_entry_name(const char *name)
{
    if (name == NULL)
        return false;
    if (strcmp(name, "control") == 0)
        return true;
    if (strlen(name) == 15 && memcmp(name, "control-frag-", 13) == 0 &&
        hex_digit(name[13]) && hex_digit(name[14]))
        return true;
    if (strlen(name) == 23 && memcmp(name, "object-", 7) == 0) {
        for (size_t i = 7; i < 23; ++i)
            if (!hex_digit(name[i]))
                return false;
        return true;
    }
    if (strlen(name) != 38 || memcmp(name, "page-", 5) != 0 || name[21] != '-')
        return false;
    for (size_t i = 5; i < 21; ++i)
        if (!hex_digit(name[i]))
            return false;
    for (size_t i = 22; i < 38; ++i)
        if (!hex_digit(name[i]))
            return false;
    return true;
}

int sparc64_family_reject_control_alias(int control_fd, int directory_fd,
                                    const char *name)
{
    struct stat control, candidate;
    if (fstat(control_fd, &control) != 0 ||
        fstatat(directory_fd, name, &candidate, AT_SYMLINK_NOFOLLOW) != 0)
        return -1;
    if (control.st_dev == candidate.st_dev && control.st_ino == candidate.st_ino) {
        errno = EACCES;
        return -1;
    }
    return 0;
}

int sparc64_family_scan_inodes(int control_fd, int directory_fd,
                           sparc64_family_inode_observer_t observer, void *context)
{
    if (control_fd < 0 || directory_fd < 0 || observer == NULL) {
        errno = EINVAL;
        return -1;
    }
    struct stat control, directory;
    if (fstat(control_fd, &control) != 0 || fstat(directory_fd, &directory) != 0)
        return -1;
    if (observer(context, &directory) != 0 || observer(context, &control) != 0) {
        if (errno == 0)
            errno = EIO;
        return -1;
    }

    int scan_fd = fcntl(directory_fd, F_DUPFD_CLOEXEC, 3);
    if (scan_fd < 0)
        return -1;
    DIR *stream = fdopendir(scan_fd);
    if (stream == NULL) {
        int saved = errno;
        (void)close(scan_fd);
        errno = saved;
        return -1;
    }
    rewinddir(stream);
    int result = 0, saved = 0;
    for (;;) {
        errno = 0;
        struct dirent *entry = readdir(stream);
        if (entry == NULL) {
            saved = errno;
            result = saved == 0 ? 0 : -1;
            break;
        }
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0 ||
            strcmp(entry->d_name, "control") == 0)
            continue;
        if (!sparc64_family_owned_entry_name(entry->d_name)) {
            saved = EBUSY; /* Unknown entry is never opened or adopted. */
            result = -1;
            break;
        }
        struct stat status;
        if (fstatat(directory_fd, entry->d_name, &status,
                    AT_SYMLINK_NOFOLLOW) != 0) {
            saved = errno;
            result = -1;
            break;
        }
        if (!S_ISREG(status.st_mode) ||
            (status.st_dev == control.st_dev && status.st_ino == control.st_ino)) {
            saved = EACCES;
            result = -1;
            break;
        }
        if (observer(context, &status) != 0) {
            saved = errno == 0 ? EIO : errno;
            result = -1;
            break;
        }
    }
    if (closedir(stream) != 0 && result == 0) {
        saved = errno;
        result = -1;
    }
    if (result != 0)
        errno = saved;
    return result;
}
