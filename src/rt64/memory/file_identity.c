/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#define _GNU_SOURCE 1
#define _DARWIN_C_SOURCE 1
#define _POSIX_C_SOURCE 200809L
#include "memory/file_identity.h"

#include <errno.h>
#include <stddef.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#if defined(__linux__)
#include <sys/syscall.h>
#include <sys/vfs.h>
#elif defined(__APPLE__)
#include <sys/attr.h>
#include <sys/mount.h>
#endif

int sparc64_file_identity_policy_parse(const char *text, sparc64_file_identity_policy_t *out)
{
    if (text == NULL || out == NULL) {
        errno = EINVAL;
        return -1;
    }
    if (strcmp(text, "auto") == 0)
        *out = SPARC64_FILE_IDENTITY_AUTO;
    else if (strcmp(text, "hyper-linux-apfs-v1") == 0)
        *out = SPARC64_FILE_IDENTITY_HYPER_LINUX_APFS_V1;
    else {
        errno = EINVAL;
        return -1;
    }
    return 0;
}

static bool unavailable(int error)
{
    return error == ENOSYS || error == EOPNOTSUPP || error == ENOTSUP ||
           error == EINVAL || error == EPERM || error == EACCES ||
           error == EOVERFLOW;
}

#if defined(__linux__) && defined(SYS_name_to_handle_at)
static int linux_handle(int fd, bool hyper_linux, sparc64_file_identity_t *out)
{
    /* Linux UAPI, fixed8-byte prefix followed by an explicitly bounded
     * payload. Kernel reads/writes user bytes; no flexible-array C aliasing. */
    struct native_handle {
        uint32_t handle_bytes;
        int32_t handle_type;
        unsigned char payload[SPARC64_FILE_IDENTITY_MAX_BYTES];
    } handle = {.handle_bytes = SPARC64_FILE_IDENTITY_MAX_BYTES};
    _Static_assert(offsetof(struct native_handle, payload) == 8,
                   "native Linux handle prefix has eight bytes");
    uint64_t mount_id = 0; /* AT_HANDLE_MNT_ID_UNIQUE writes eight bytes. */
    long result;
    do {
        /* EMPTY_PATH|HANDLE_FID|HANDLE_MNT_ID_UNIQUE, Linux v6.18 UAPI.
         * Mount ID is output provenance only, never part of equality. */
        result = syscall(SYS_name_to_handle_at, fd, "", &handle, &mount_id,
                           UINT32_C(0x1201));
    } while (result < 0 && errno == EINTR);
    if (result < 0) {
        if (unavailable(errno))
            return 0;
        return -1;
    }
    if (result != 0 || handle.handle_bytes > SPARC64_FILE_IDENTITY_MAX_BYTES) {
        errno = EIO;
        return -1;
    }
    if (hyper_linux) {
        if ((uint32_t)handle.handle_type != SPARC64_FILE_HANDLE_HL_APFS_V1 ||
            handle.handle_bytes != 16)
            return 0;
        out->provider = SPARC64_FILE_ID_HYPER_LINUX_APFS;
    } else {
        /* Pinned shmem export provider: type1, generation and full64 inode.
         * Keep all twelve bytes opaque; never replace with stat st_ino. */
        if (handle.handle_type != 1 || handle.handle_bytes != 12)
            return 0;
        out->provider = SPARC64_FILE_ID_LINUX_TMPFS;
    }
    out->format = (uint32_t)handle.handle_type;
    out->length = handle.handle_bytes;
    out->mapped_key_eligible = true;
    memcpy(out->bytes, handle.payload, handle.handle_bytes);
    return 0;
}
#endif

#if defined(__APPLE__)
static int native_apfs(int fd, sparc64_file_identity_t *out)
{
    struct statfs filesystem;
    if (fstatfs(fd, &filesystem) != 0)
        return -1;
    if (strncmp(filesystem.f_fstypename, "apfs",
                   sizeof(filesystem.f_fstypename)) != 0)
        return 0;
    struct attrlist requested = {.bitmapcount = ATTR_BIT_MAP_COUNT,
        .commonattr = ATTR_CMN_RETURNED_ATTRS | ATTR_CMN_FSID | ATTR_CMN_FILEID};
    /* attrlist output is packed native ABI. Decode with checked offsets and
     * memcpy, never dereference potentially unaligned attribute fields. */
    unsigned char buffer[4 + sizeof(attribute_set_t) + 16] = {0};
    int result;
    do { result = fgetattrlist(fd, &requested, buffer, sizeof(buffer), 0); }
    while (result != 0 && errno == EINTR);
    if (result != 0) {
        if (unavailable(errno))
            return 0;
        return -1;
    }
    uint32_t length;
    attribute_set_t returned;
    memcpy(&length, buffer, sizeof(length));
    memcpy(&returned, buffer + 4, sizeof(returned));
    if (length != sizeof(buffer) || returned.commonattr != requested.commonattr ||
        returned.volattr != 0 || returned.dirattr != 0 ||
        returned.fileattr != 0 || returned.forkattr != 0) {
        errno = EIO;
        return -1;
    }
    out->provider = SPARC64_FILE_ID_NATIVE_APFS;
    out->format = 1;
    out->length = 16;
    out->mapped_key_eligible = false; /* Native unit/source identity only. */
    memcpy(out->bytes, buffer + 4 + sizeof(returned), 16);
    return 0;
}
#endif

int sparc64_file_identity_query(int fd, sparc64_file_identity_policy_t policy,
                             sparc64_file_identity_t *out)
{
    if (out == NULL || !sparc64_file_identity_policy_valid(policy)) {
        errno = EINVAL;
        return -1;
    }
    *out = (sparc64_file_identity_t){0};
    struct stat status;
    int result;
    do { result = fstat(fd, &status); } while (result != 0 && errno == EINTR);
    if (result != 0)
        return -1;
    if (!S_ISREG(status.st_mode)) {
        errno = ENODEV;
        return -1;
    }
#if defined(__linux__) && defined(SYS_name_to_handle_at)
    bool selected = policy == SPARC64_FILE_IDENTITY_HYPER_LINUX_APFS_V1;
    if (!selected) {
        struct statfs filesystem;
        do { result = fstatfs(fd, &filesystem); }
        while (result != 0 && errno == EINTR);
        if (result != 0)
            return -1;
        selected = (uint64_t)(unsigned long)filesystem.f_type == UINT64_C(0x01021994);
    }
    if (selected && linux_handle(fd,
            policy == SPARC64_FILE_IDENTITY_HYPER_LINUX_APFS_V1, out) != 0)
        return -1;
#elif defined(__APPLE__)
    if (policy == SPARC64_FILE_IDENTITY_AUTO && native_apfs(fd, out) != 0)
        return -1;
#endif
    if (out->provider != SPARC64_FILE_ID_UNKNOWN)
        out->device = (uint64_t)status.st_dev;
    errno = 0;
    return 0;
}
