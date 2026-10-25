/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#define _GNU_SOURCE 1
#include "aot/authority.h"

#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>

#if defined(__linux__)
#include <sys/vfs.h>
#include <sys/xattr.h>

#define SPARC64_AOT_EXT4_MAGIC UINT32_C(0xef53)
#define SPARC64_AOT_TMPFS_MAGIC UINT32_C(0x01021994)

static uint16_t little16(const unsigned char *p)
{
    return (uint16_t)p[0] | (uint16_t)((uint16_t)p[1] << 8);
}

static uint32_t little32(const unsigned char *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

/* Linux POSIX ACL xattr v2: version plus exactly USER_OBJ, GROUP_OBJ, OTHER.
 * The host companion synthesizes this only after proving no native APFS
 * filesec ACL and no ignored-ownership mount. A generic xattr is insufficient. */
static bool base_acl_matches(const unsigned char acl[28], mode_t mode)
{
    static const uint16_t tags[3] = {1, 4, 32};
    if (little32(acl) != 2)
        return false;
    for (unsigned i = 0; i < 3; ++i) {
        const unsigned char *entry = acl + 4 + i * 8;
        unsigned shift = 6u - i * 3u;
        if (little16(entry) != tags[i] ||
            little16(entry + 2) != ((mode >> shift) & 7u) ||
            little32(entry + 4) != UINT32_MAX)
            return false;
    }
    return true;
}

static bool absent_acl(int fd, const char *name)
{
    unsigned char byte;
    ssize_t size;
    do { size = fgetxattr(fd, name, &byte, sizeof(byte)); }
    while (size < 0 && errno == EINTR);
    return size < 0 && errno == ENODATA;
}

static bool exact_base_acl(int fd, mode_t mode)
{
    unsigned char acl[28];
    ssize_t size;
    do { size = fgetxattr(fd, "system.posix_acl_access", acl, sizeof(acl)); }
    while (size < 0 && errno == EINTR);
    return size == (ssize_t)sizeof(acl) && base_acl_matches(acl, mode);
}
#endif

bool sparc64_aot_authorize_fd(int fd, bool directory,
                         sparc64_aot_authority_policy_t policy)
{
    if (fd < 0 || (policy != SPARC64_AOT_AUTHORITY_AUTO &&
                   policy != SPARC64_AOT_AUTHORITY_HYPER_LINUX_APFS_ACL_V1)) {
        errno = EINVAL;
        return false;
    }
#if defined(__linux__)
    struct stat status;
    struct statfs filesystem;
    if (fstat(fd, &status) != 0 || fstatfs(fd, &filesystem) != 0 ||
        (directory ? !S_ISDIR(status.st_mode) : !S_ISREG(status.st_mode)))
        return false;
    if (policy == SPARC64_AOT_AUTHORITY_AUTO) {
        if ((uint64_t)filesystem.f_type != SPARC64_AOT_EXT4_MAGIC &&
            (uint64_t)filesystem.f_type != SPARC64_AOT_TMPFS_MAGIC)
            return false;
        if (!absent_acl(fd, "system.posix_acl_access"))
            return false;
    } else if (!exact_base_acl(fd, status.st_mode))
        return false;
    return !directory || absent_acl(fd, "system.posix_acl_default");
#else
    (void)directory;
    (void)policy;
    return false;
#endif
}
