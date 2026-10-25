/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#define _GNU_SOURCE
#include "runtime/family_zero_blob.h"
#include "aot/authority.h"
#include "aot/digest.h"
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/xattr.h>
#include <unistd.h>

#ifndef RENAME_NOREPLACE
#define RENAME_NOREPLACE 1u
#endif

#define MANIFEST_SIZE 64u
#define MANIFEST_VERSION 1u
#define MANIFEST_ATTRIBUTE "user.sparc64rt.zero_blob.manifest"
#define CHUNK_ATTRIBUTE "user.sparc64rt.zero_blob.chunk"

static void store32(uint8_t *out, uint32_t value)
{
    for (unsigned i = 0; i < 4; ++i)
        out[i] = (uint8_t)(value >> (8u * i));
}

static void store64(uint8_t *out, uint64_t value)
{
    for (unsigned i = 0; i < 8; ++i)
        out[i] = (uint8_t)(value >> (8u * i));
}

static uint32_t load32(const uint8_t *in)
{
    uint32_t result = 0;
    for (unsigned i = 0; i < 4; ++i)
        result |= (uint32_t)in[i] << (8u * i);
    return result;
}

static uint64_t load64(const uint8_t *in)
{
    uint64_t result = 0;
    for (unsigned i = 0; i < 8; ++i)
        result |= (uint64_t)in[i] << (8u * i);
    return result;
}

static int manifest_name(char out[64], uint64_t id, bool stage)
{
    int count = snprintf(out, 64, stage ? "blob-%016llx-stage" :
                         "blob-%016llx", (unsigned long long)id);
    if (count < 0 || count >= 64) {
        errno = EOVERFLOW;
        return -1;
    }
    return 0;
}

static int chunk_name(char out[64], uint64_t id, unsigned index)
{
    int count = snprintf(out, 64, "blob-%016llx-%02u",
                         (unsigned long long)id, index);
    if (count < 0 || count >= 64) {
        errno = EOVERFLOW;
        return -1;
    }
    return 0;
}

static int check_directory(int fd)
{
    struct stat status;
    if (fstat(fd, &status) != 0)
        return -1;
    if (!S_ISDIR(status.st_mode) || status.st_uid != geteuid() ||
        (status.st_mode & 07777) != 0700) {
        errno = EACCES;
        return -1;
    }
    if (!sparc64_aot_authorize_fd(fd, true, SPARC64_AOT_AUTHORITY_AUTO)) {
        errno = EACCES;
        return -1;
    }
    return 0;
}

static int check_file(int fd)
{
    struct stat status;
    if (fstat(fd, &status) != 0)
        return -1;
    if (!S_ISREG(status.st_mode) || status.st_uid != geteuid() ||
        (status.st_mode & 07777) != 0600 || status.st_nlink != 1 ||
        status.st_size != 0) {
        errno = EACCES;
        return -1;
    }
    if (!sparc64_aot_authorize_fd(fd, false, SPARC64_AOT_AUTHORITY_AUTO)) {
        errno = EACCES;
        return -1;
    }
    return 0;
}

typedef struct owned_leaf {
    char name[64];
    dev_t device;
    ino_t inode;
    bool owned;
} owned_leaf_t;

static int remember_leaf(int fd, const char *name, owned_leaf_t *leaf)
{
    struct stat status;
    if (fstat(fd, &status) != 0)
        return -1;
    size_t length = strlen(name);
    if (length >= sizeof(leaf->name)) {
        errno = EOVERFLOW;
        return -1;
    }
    memcpy(leaf->name, name, length + 1);
    leaf->device = status.st_dev;
    leaf->inode = status.st_ino;
    leaf->owned = true;
    return 0;
}

static int named_leaf_matches(int directory_fd, const owned_leaf_t *leaf)
{
    struct stat status;
    if (!leaf->owned ||
        fstatat(directory_fd, leaf->name, &status, AT_SYMLINK_NOFOLLOW) != 0)
        return -1;
    if (status.st_dev != leaf->device || status.st_ino != leaf->inode ||
        !S_ISREG(status.st_mode) || status.st_nlink != 1 ||
        status.st_size != 0) {
        errno = ESTALE;
        return -1;
    }
    return 0;
}

static void unlink_owned(int directory_fd, const owned_leaf_t *leaf)
{
    if (named_leaf_matches(directory_fd, leaf) == 0)
        (void)unlinkat(directory_fd, leaf->name, 0);
}

static int create_file(int directory_fd, const char *name)
{
    int fd = openat(directory_fd, name,
                    O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                    0600);
    if (fd < 0)
        return -1;
    if (check_file(fd) == 0)
        return fd;
    int saved = errno;
    owned_leaf_t created = {0};
    (void)remember_leaf(fd, name, &created);
    (void)close(fd);
    unlink_owned(directory_fd, &created);
    errno = saved;
    return -1;
}

static int open_file(int directory_fd, const char *name)
{
    int fd = openat(directory_fd, name,
                    O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0)
        return -1;
    if (check_file(fd) == 0)
        return fd;
    int saved = errno;
    (void)close(fd);
    errno = saved;
    return -1;
}

int sparc64_family_zero_blob_publish(int directory_fd, uint64_t id,
                                const uint8_t *bytes, size_t size)
{
    if (directory_fd < 0 || id == 0 || size > SPARC64_FAMILY_ZERO_BLOB_MAX_SIZE ||
        (size != 0 && bytes == NULL)) {
        errno = EINVAL;
        return -1;
    }
    if (check_directory(directory_fd) != 0)
        return -1;
    const unsigned count = (unsigned)(size / SPARC64_FAMILY_ZERO_BLOB_CHUNK_SIZE +
                           (size % SPARC64_FAMILY_ZERO_BLOB_CHUNK_SIZE != 0));
    char final[64], stage[64], leaf[64];
    if (manifest_name(final, id, false) != 0 ||
        manifest_name(stage, id, true) != 0)
        return -1;
    /* Do not create any chunks if the immutable ID is already published. */
    struct stat existing;
    if (fstatat(directory_fd, final, &existing, AT_SYMLINK_NOFOLLOW) == 0) {
        errno = EEXIST;
        return -1;
    }
    if (errno != ENOENT)
        return -1;
    owned_leaf_t chunks[SPARC64_FAMILY_ZERO_BLOB_MAX_CHUNKS];
    memset(chunks, 0, sizeof(chunks));
    owned_leaf_t stage_leaf = {0};
    unsigned owned_chunks = 0;
    int fd = -1;
    for (unsigned i = 0; i < count; ++i) {
        if (chunk_name(leaf, id, i) != 0)
            goto fail;
        fd = create_file(directory_fd, leaf);
        if (fd < 0)
            goto fail;
        if (remember_leaf(fd, leaf, &chunks[i]) != 0)
            goto fail;
        owned_chunks = i + 1;
        size_t offset = (size_t)i * SPARC64_FAMILY_ZERO_BLOB_CHUNK_SIZE;
        size_t length = size - offset;
        if (length > SPARC64_FAMILY_ZERO_BLOB_CHUNK_SIZE)
            length = SPARC64_FAMILY_ZERO_BLOB_CHUNK_SIZE;
        if (fsetxattr(fd, CHUNK_ATTRIBUTE, bytes + offset, length, 0) != 0 ||
            fsync(fd) != 0)
            goto fail;
        int closed = close(fd);
        fd = -1;
        if (closed != 0)
            goto fail;
    }
    uint8_t manifest[MANIFEST_SIZE] = {0};
    memcpy(manifest, "RVZBLOB1", 8);
    store32(manifest + 8, MANIFEST_VERSION);
    store64(manifest + 16, id);
    store32(manifest + 24, (uint32_t)size);
    store32(manifest + 28, count);
    const sparc64_aot_span_t spans[2] = {
        {manifest, 32}, {bytes, size}
    };
    if (sparc64_aot_sha256_spans(spans, 2, manifest + 32) != 0)
        goto fail;
    fd = create_file(directory_fd, stage);
    if (fd < 0)
        goto fail;
    if (remember_leaf(fd, stage, &stage_leaf) != 0)
        goto fail;
    if (fsetxattr(fd, MANIFEST_ATTRIBUTE, manifest, sizeof(manifest), 0) != 0 ||
        fsync(fd) != 0)
        goto fail;
    int closed = close(fd);
    fd = -1;
    if (closed != 0 || fsync(directory_fd) != 0)
        goto fail;
    for (unsigned i = 0; i < count; ++i)
        if (named_leaf_matches(directory_fd, &chunks[i]) != 0)
            goto fail;
    if (named_leaf_matches(directory_fd, &stage_leaf) != 0)
        goto fail;
    if (syscall(SYS_renameat2, directory_fd, stage, directory_fd, final,
                RENAME_NOREPLACE) != 0)
        goto fail;
    /* After rename, a failed directory fsync leaves a possibly durable ID.
     * Never retry or remove it as an ordinary prepublication failure. */
    owned_leaf_t final_leaf = stage_leaf;
    if (manifest_name(final_leaf.name, id, false) != 0 ||
        named_leaf_matches(directory_fd, &final_leaf) != 0 ||
        fsync(directory_fd) != 0) {
        errno = EIO;
        return -2;
    }
    return 0;

fail: {
    int saved = errno;
    if (fd >= 0)
        (void)close(fd);
    unlink_owned(directory_fd, &stage_leaf);
    for (unsigned i = 0; i < owned_chunks; ++i)
        unlink_owned(directory_fd, &chunks[i]);
    errno = saved;
    return -1;
}
}

static int read_held(int directory_fd, uint64_t id, int manifest_fd,
                     size_t capacity, uint8_t staged[SPARC64_FAMILY_ZERO_BLOB_MAX_SIZE],
                     size_t *staged_size)
{
    uint8_t manifest[MANIFEST_SIZE];
    ssize_t got = fgetxattr(manifest_fd, MANIFEST_ATTRIBUTE, manifest,
                            sizeof(manifest));
    int saved = errno;
    if (got != (ssize_t)sizeof(manifest)) {
        errno = got < 0 ? saved : EBADMSG;
        return -1;
    }
    size_t size = load32(manifest + 24);
    unsigned count = load32(manifest + 28);
    unsigned expected = (unsigned)(size / SPARC64_FAMILY_ZERO_BLOB_CHUNK_SIZE +
                        (size % SPARC64_FAMILY_ZERO_BLOB_CHUNK_SIZE != 0));
    if (memcmp(manifest, "RVZBLOB1", 8) != 0 ||
        load32(manifest + 8) != MANIFEST_VERSION ||
        load32(manifest + 12) != 0 || load64(manifest + 16) != id ||
        size > SPARC64_FAMILY_ZERO_BLOB_MAX_SIZE ||
        count > SPARC64_FAMILY_ZERO_BLOB_MAX_CHUNKS || count != expected) {
        errno = EBADMSG;
        return -1;
    }
    if (capacity < size) {
        errno = ENOSPC;
        return -1;
    }
    char leaf[64];
    for (unsigned i = 0; i < count; ++i) {
        if (chunk_name(leaf, id, i) != 0)
            return -1;
        int chunk_fd = open_file(directory_fd, leaf);
        if (chunk_fd < 0)
            return -1;
        size_t offset = (size_t)i * SPARC64_FAMILY_ZERO_BLOB_CHUNK_SIZE;
        size_t length = size - offset;
        if (length > SPARC64_FAMILY_ZERO_BLOB_CHUNK_SIZE)
            length = SPARC64_FAMILY_ZERO_BLOB_CHUNK_SIZE;
        got = fgetxattr(chunk_fd, CHUNK_ATTRIBUTE, staged + offset, length);
        saved = errno;
        if (close(chunk_fd) != 0 && got == (ssize_t)length) {
            errno = EIO;
            return -1;
        }
        if (got != (ssize_t)length) {
            errno = got < 0 ? saved : EBADMSG;
            return -1;
        }
    }
    uint8_t digest[SPARC64_AOT_SHA256_BYTES];
    const sparc64_aot_span_t spans[2] = {
        {manifest, 32}, {staged, size}
    };
    if (sparc64_aot_sha256_spans(spans, 2, digest) != 0)
        return -1;
    if (memcmp(digest, manifest + 32, sizeof(digest)) != 0) {
        errno = EBADMSG;
        return -1;
    }
    /* Keep the exact manifest open while following its chunk graph. Detect a
     * replaced name or metadata before handing the staged bytes to caller. */
    struct stat held, named;
    if (check_file(manifest_fd) != 0 ||
        fstat(manifest_fd, &held) != 0 ||
        manifest_name(leaf, id, false) != 0 ||
        fstatat(directory_fd, leaf, &named, AT_SYMLINK_NOFOLLOW) != 0)
        return -1;
    if (held.st_dev != named.st_dev || held.st_ino != named.st_ino) {
        errno = ESTALE;
        return -1;
    }
    uint8_t current[MANIFEST_SIZE];
    got = fgetxattr(manifest_fd, MANIFEST_ATTRIBUTE, current,
                    sizeof(current));
    if (got != (ssize_t)sizeof(current) ||
        memcmp(current, manifest, sizeof(current)) != 0) {
        errno = EBADMSG;
        return -1;
    }
    *staged_size = size;
    return 0;
}

int sparc64_family_zero_blob_read(int directory_fd, uint64_t id,
                             uint8_t *out, size_t capacity,
                             size_t *out_size)
{
    if (directory_fd < 0 || id == 0 || out_size == NULL ||
        (capacity != 0 && out == NULL)) {
        errno = EINVAL;
        return -1;
    }
    if (check_directory(directory_fd) != 0)
        return -1;
    char leaf[64];
    if (manifest_name(leaf, id, false) != 0)
        return -1;
    int manifest_fd = open_file(directory_fd, leaf);
    if (manifest_fd < 0)
        return -1;
    uint8_t staged[SPARC64_FAMILY_ZERO_BLOB_MAX_SIZE];
    size_t size = 0;
    int result = read_held(directory_fd, id, manifest_fd, capacity,
                           staged, &size);
    int saved = errno;
    if (close(manifest_fd) != 0 && result == 0) {
        errno = EIO;
        return -1;
    }
    if (result != 0) {
        errno = saved;
        return -1;
    }
    if (size != 0)
        memcpy(out, staged, size);
    *out_size = size;
    return 0;
}
