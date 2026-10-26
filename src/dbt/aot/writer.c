/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#if defined(__APPLE__)
#define _DARWIN_C_SOURCE 1
#endif
#define _POSIX_C_SOURCE 200809L
#include "dbt/aot/writer.h"
#include "dbt/aot/reader.h"
#include "dbt/aot/digest.h"

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#if defined(__APPLE__)
#include <sys/stdio.h>
#endif

#if defined(SPARC64_AOT_WRITER_TESTING)
extern void sparc64_aot_writer_test_before_name_validation(int directory_fd,
                                                      const char *temporary_leaf);
extern ssize_t sparc64_aot_writer_test_write(int fd, const void *bytes, size_t size);
extern int sparc64_aot_writer_test_fsync(int fd);
#endif

static bool leaf_valid(const char *leaf)
{
    if (leaf == NULL || leaf[0] == '\0')
        return false;
    size_t count = 0;
    while (count <= 255 && leaf[count] != '\0') {
        if (leaf[count] == '/')
            return false;
        ++count;
    }
    return count <= 255 && !(count == 1 && leaf[0] == '.') &&
           !(count == 2 && leaf[0] == '.' && leaf[1] == '.');
}

static bool directory_safe(const struct stat *st, uid_t owner)
{
    return S_ISDIR(st->st_mode) && st->st_uid == owner &&
           (st->st_mode & 07777) == 0700;
}

static bool directory_same(const struct stat *before, const struct stat *after,
                           uid_t owner)
{
    return directory_safe(after, owner) && before->st_dev == after->st_dev &&
           before->st_ino == after->st_ino;
}

static bool file_safe(const struct stat *st, uid_t owner, size_t expected_size)
{
    return S_ISREG(st->st_mode) && st->st_uid == owner &&
           (st->st_mode & 07777) == 0600 && st->st_nlink == 1 &&
           st->st_size == (off_t)expected_size &&
           st->st_size >= (off_t)SPARC64_AOT_HEADER_V2_BYTES &&
           st->st_size <= (off_t)SPARC64_AOT_MAX_FILE_BYTES;
}

static bool empty_file_safe(const struct stat *st, uid_t owner)
{
    return S_ISREG(st->st_mode) && st->st_uid == owner &&
           (st->st_mode & 07777) == 0600 && st->st_nlink == 1 &&
           st->st_size == 0;
}

static bool write_all(int fd, const uint8_t *bytes, size_t size)
{
    size_t offset = 0;
    while (offset < size) {
#if defined(SPARC64_AOT_WRITER_TESTING)
        ssize_t written = sparc64_aot_writer_test_write(fd, bytes + offset,
                                                   size - offset);
#else
        ssize_t written = write(fd, bytes + offset, size - offset);
#endif
        if (written < 0 && errno == EINTR)
            continue;
        if (written <= 0) {
            if (written == 0)
                errno = EIO;
            return false;
        }
        offset += (size_t)written;
    }
    return true;
}

static bool sync_fd(int fd)
{
    int result;
    do {
#if defined(SPARC64_AOT_WRITER_TESTING)
        result = sparc64_aot_writer_test_fsync(fd);
#else
        result = fsync(fd);
#endif
    } while (result != 0 && errno == EINTR);
    return result == 0;
}

static sparc64_aot_write_result_t snapshot_write(
    int directory_fd, const char *final_leaf, const char *temporary_leaf,
    const sparc64_aot_image_t *image, bool authorized,
    sparc64_aot_authority_policy_t policy)
{
    if (directory_fd < 0 || !leaf_valid(final_leaf) ||
        !leaf_valid(temporary_leaf) || strcmp(final_leaf, temporary_leaf) == 0 ||
        image == NULL) {
        errno = EINVAL;
        return SPARC64_AOT_WRITE_ERROR;
    }
    uid_t owner = geteuid();
    if (getuid() != owner || getgid() != getegid())
        return SPARC64_AOT_WRITE_DECLINE;

    struct stat directory_before;
    if (fstat(directory_fd, &directory_before) != 0)
        return SPARC64_AOT_WRITE_ERROR;
    if (!directory_safe(&directory_before, owner))
        return SPARC64_AOT_WRITE_DECLINE;
    if (authorized && !sparc64_aot_authorize_fd(directory_fd, true, policy))
        return SPARC64_AOT_WRITE_DECLINE;

    uint8_t *encoded = malloc(SPARC64_AOT_MAX_FILE_BYTES);
    if (encoded == NULL)
        return SPARC64_AOT_WRITE_ERROR;
    uint8_t digest[SPARC64_AOT_DIGEST_BYTES] = {0};
    size_t encoded_size = 0;
    if (sparc64_aot_encode_v2(image, digest, encoded, SPARC64_AOT_MAX_FILE_BYTES,
                         &encoded_size) != 0 ||
        sparc64_aot_record_digest(encoded, encoded_size, digest) != 0) {
        int saved_errno = errno;
        free(encoded);
        errno = saved_errno;
        return SPARC64_AOT_WRITE_ERROR;
    }
    memcpy(encoded + SPARC64_AOT_RECORD_DIGEST_OFFSET, digest, sizeof(digest));

    int fd = openat(directory_fd, temporary_leaf,
                    O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
                    0600);
    if (fd < 0) {
        int saved_errno = errno;
        free(encoded);
        errno = saved_errno;
        return SPARC64_AOT_WRITE_ERROR;
    }
    bool temporary_owned = true;
    bool temporary_identity_valid = false;
    struct stat temporary_identity;
    sparc64_aot_write_result_t result = SPARC64_AOT_WRITE_ERROR;
    int saved_errno = 0;
    struct stat created;
    if (fchmod(fd, 0600) != 0 || fstat(fd, &created) != 0)
        goto done;
    temporary_identity = created;
    temporary_identity_valid = true;
    if (!empty_file_safe(&created, owner)) {
        errno = EINVAL;
        goto done;
    }
    if (authorized && !sparc64_aot_authorize_fd(fd, false, policy)) {
        result = SPARC64_AOT_WRITE_DECLINE;
        goto done;
    }
    if (!write_all(fd, encoded, encoded_size) || !sync_fd(fd))
        goto done;
    if (fstat(fd, &created) != 0)
        goto done;
    if (!file_safe(&created, owner, encoded_size)) {
        errno = EIO;
        goto done;
    }
    if (authorized && !sparc64_aot_authorize_fd(fd, false, policy)) {
        result = SPARC64_AOT_WRITE_DECLINE;
        goto done;
    }
    if (close(fd) != 0) {
        fd = -1;
        goto done;
    }
    fd = -1;

    struct stat directory_after;
    if (fstat(directory_fd, &directory_after) != 0)
        goto done;
    if (!directory_same(&directory_before, &directory_after, owner)) {
        errno = ESTALE;
        goto done;
    }
    if (authorized && !sparc64_aot_authorize_fd(directory_fd, true, policy)) {
        result = SPARC64_AOT_WRITE_DECLINE;
        goto done;
    }
#if defined(SPARC64_AOT_WRITER_TESTING)
    sparc64_aot_writer_test_before_name_validation(directory_fd, temporary_leaf);
#endif
    struct stat named_file;
    if (fstatat(directory_fd, temporary_leaf, &named_file,
                AT_SYMLINK_NOFOLLOW) != 0)
        goto done;
    if (!file_safe(&named_file, owner, encoded_size) ||
        named_file.st_dev != created.st_dev || named_file.st_ino != created.st_ino) {
        errno = ESTALE;
        goto done;
    }
    if (renameat(directory_fd, temporary_leaf, directory_fd, final_leaf) != 0)
        goto done;
    temporary_owned = false;
    if (fstat(directory_fd, &directory_after) != 0)
        goto done;
    if (!directory_same(&directory_before, &directory_after, owner)) {
        errno = ESTALE;
        goto done;
    }
    if (!sync_fd(directory_fd))
        goto done;
    result = SPARC64_AOT_WRITE_STORED;

done:
    saved_errno = errno;
    if (fd >= 0 && !temporary_identity_valid && fstat(fd, &temporary_identity) == 0)
        temporary_identity_valid = true;
    if (fd >= 0 && close(fd) != 0 && saved_errno == 0)
        saved_errno = errno;
    if (temporary_owned && temporary_identity_valid) {
        struct stat named_temp;
        if (fstatat(directory_fd, temporary_leaf, &named_temp,
                    AT_SYMLINK_NOFOLLOW) == 0 &&
            named_temp.st_dev == temporary_identity.st_dev &&
            named_temp.st_ino == temporary_identity.st_ino) {
            if (unlinkat(directory_fd, temporary_leaf, 0) != 0 &&
                saved_errno == 0)
                saved_errno = errno;
        } else if (errno != ENOENT && saved_errno == 0) {
            saved_errno = errno != 0 ? errno : ESTALE;
        }
    }
    free(encoded);
    errno = saved_errno;
    return result;
}

sparc64_aot_write_result_t sparc64_aot_snapshot_write(
    int directory_fd, const char *final_leaf, const char *temporary_leaf,
    const sparc64_aot_image_t *image)
{
    return snapshot_write(directory_fd, final_leaf, temporary_leaf, image,
                          false, SPARC64_AOT_AUTHORITY_AUTO);
}

sparc64_aot_write_result_t sparc64_aot_snapshot_write_authorized(
    int directory_fd, const char *final_leaf, const char *temporary_leaf,
    const sparc64_aot_image_t *image, sparc64_aot_authority_policy_t policy)
{
    return snapshot_write(directory_fd, final_leaf, temporary_leaf, image,
                          true, policy);
}
