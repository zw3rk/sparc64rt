/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#define _POSIX_C_SOURCE 200809L
#include "loader/image_internal.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define IMAGE_RECORD_HEADER 48u
#define IMAGE_RECORD_MAX (IMAGE_RECORD_HEADER + 2u * SPARC64_IMAGE_MAX_SIZE)

struct sparc64_program_export {
    sparc64_path_registration_t *registration;
    int metadata;
    int old_flags;
    bool active, poisoned;
};

static uint32_t get32(const unsigned char *p)
{
    uint32_t value = 0;
    for (unsigned int i = 0; i < 4; ++i)
        value |= (uint32_t)p[i] << (8u * i);
    return value;
}

static uint64_t get64(const unsigned char *p)
{
    uint64_t value = 0;
    for (unsigned int i = 0; i < 8; ++i)
        value |= (uint64_t)p[i] << (8u * i);
    return value;
}

static void put32(unsigned char *p, uint32_t value)
{
    for (unsigned int i = 0; i < 4; ++i)
        p[i] = (unsigned char)(value >> (8u * i));
}

static void put64(unsigned char *p, uint64_t value)
{
    for (unsigned int i = 0; i < 8; ++i)
        p[i] = (unsigned char)(value >> (8u * i));
}

static bool record_error(char *error, size_t error_size, const char *message)
{
    if (error != NULL && error_size != 0) {
        int written = snprintf(error, error_size, "%s", message);
        if (written < 0 || (size_t)written >= error_size)
            error[0] = '\0';
    }
    return false;
}

static bool private_metadata(int fd, struct stat *status)
{
    return fd >= 3 && fstat(fd, status) == 0 && S_ISREG(status->st_mode) &&
           status->st_uid == geteuid() && status->st_nlink == 0 &&
           (status->st_mode & 07777) == 0600;
}

static bool same_record_stat(const struct stat *before, const struct stat *after)
{
#ifdef __APPLE__
    struct timespec before_mtime = {before->st_mtime, before->st_mtimensec};
    struct timespec after_mtime = {after->st_mtime, after->st_mtimensec};
    struct timespec before_ctime = {before->st_ctime, before->st_ctimensec};
    struct timespec after_ctime = {after->st_ctime, after->st_ctimensec};
#else
    struct timespec before_mtime = before->st_mtim, after_mtime = after->st_mtim;
    struct timespec before_ctime = before->st_ctim, after_ctime = after->st_ctim;
#endif
    return before->st_dev == after->st_dev && before->st_ino == after->st_ino &&
           before->st_size == after->st_size &&
           before_mtime.tv_sec == after_mtime.tv_sec &&
           before_mtime.tv_nsec == after_mtime.tv_nsec &&
           before_ctime.tv_sec == after_ctime.tv_sec &&
           before_ctime.tv_nsec == after_ctime.tv_nsec;
}

static int write_all(int fd, const unsigned char *bytes, size_t length,
                     size_t start)
{
    size_t done = 0;
    while (done < length) {
        ssize_t count = pwrite(fd, bytes + done, length - done,
                                (off_t)(start + done));
        if (count < 0 && errno == EINTR)
            continue;
        if (count <= 0) {
            if (count == 0)
                errno = EIO;
            return -1;
        }
        done += (size_t)count;
    }
    return 0;
}

static int read_all(int fd, unsigned char *bytes, size_t length)
{
    size_t done = 0;
    while (done < length) {
        ssize_t count = pread(fd, bytes + done, length - done, (off_t)done);
        if (count < 0 && errno == EINTR)
            continue;
        if (count <= 0) {
            if (count == 0)
                errno = EINVAL;
            return -1;
        }
        done += (size_t)count;
    }
    return 0;
}

void sparc64_program_export_destroy(sparc64_program_export_t **handle)
{
    if (handle == NULL || *handle == NULL)
        return;
    int saved = errno;
    sparc64_program_export_t *owner = *handle;
    sparc64_path_retire_temporary(&owner->registration);
    if (owner->metadata >= 3)
        (void)close(owner->metadata);
    free(owner);
    *handle = NULL;
    errno = saved;
}

int sparc64_program_export_create(const sparc64_prepared_program_t *prepared,
                              sparc64_path_resolver_t *resolver,
                              sparc64_program_export_t **out)
{
    if (out == NULL) {
        errno = EINVAL;
        return -1;
    }
    *out = NULL;
    if (prepared == NULL || prepared->target.bytes == NULL ||
        prepared->target.size < 64 || prepared->target.size > SPARC64_IMAGE_MAX_SIZE ||
        (prepared->has_interpreter &&
         (prepared->interpreter.bytes == NULL || prepared->interpreter.size < 64 ||
          prepared->interpreter.size > SPARC64_IMAGE_MAX_SIZE)) ||
        (!prepared->has_interpreter && prepared->interpreter.size != 0) ||
        resolver == NULL || !resolver->initialized) {
        errno = EINVAL;
        return -1;
    }
    sparc64_program_export_t *owner = calloc(1, sizeof(*owner));
    if (owner == NULL)
        return -1;
    owner->metadata = -1;
    char path[] = "/tmp/sparc64rt-image-handoff-XXXXXX";
    int fd = mkstemp(path);
    if (fd < 0)
        goto fail;
    if (unlink(path) != 0) {
        int saved = errno;
        (void)close(fd);
        errno = saved;
        goto fail;
    }
    owner->metadata = fcntl(fd, F_DUPFD_CLOEXEC, 3);
    int saved = errno;
    (void)close(fd);
    errno = saved;
    if (owner->metadata < 0 || fchmod(owner->metadata, 0600) != 0)
        goto fail;
    struct stat before, after;
    if (!private_metadata(owner->metadata, &before)) {
        errno = EINVAL;
        goto fail;
    }
    if (sparc64_path_protect_temporary(resolver, before.st_dev, before.st_ino,
                                  &owner->registration) != 0)
        goto fail;
    size_t length = IMAGE_RECORD_HEADER + prepared->target.size +
                    prepared->interpreter.size;
    unsigned char header[IMAGE_RECORD_HEADER] = {0};
    memcpy(header, "RVIMEX01", 8);
    put32(header + 8, 1);
    put32(header + 12, IMAGE_RECORD_HEADER);
    put64(header + 16, length);
    put64(header + 24, prepared->target.size);
    put64(header + 32, prepared->interpreter.size);
    put32(header + 40, prepared->has_interpreter ? 1u : 0u);
    if (write_all(owner->metadata, header, sizeof(header), 0) != 0 ||
        write_all(owner->metadata, prepared->target.bytes,
                  prepared->target.size, IMAGE_RECORD_HEADER) != 0 ||
        (prepared->has_interpreter &&
         write_all(owner->metadata, prepared->interpreter.bytes,
                   prepared->interpreter.size,
                   IMAGE_RECORD_HEADER + prepared->target.size) != 0))
        goto fail;
    if (!private_metadata(owner->metadata, &after) ||
        after.st_dev != before.st_dev || after.st_ino != before.st_ino ||
        after.st_size < 0 || (uint64_t)after.st_size != length) {
        errno = EINVAL;
        goto fail;
    }
    *out = owner;
    return 0;
fail: {
        int failure = errno;
        sparc64_program_export_destroy(&owner);
        errno = failure;
        return -1;
    }
}

int sparc64_program_export_fd(const sparc64_program_export_t *owner)
{
    if (owner == NULL) {
        errno = EINVAL;
        return -1;
    }
    return owner->metadata;
}

int sparc64_program_export_deactivate(sparc64_program_export_t *owner)
{
    if (owner == NULL || owner->poisoned) {
        errno = EIO;
        return -1;
    }
    if (owner->active && fcntl(owner->metadata, F_SETFD, owner->old_flags) < 0) {
        owner->poisoned = true;
        return -1;
    }
    owner->active = false;
    return 0;
}

int sparc64_program_export_activate(sparc64_program_export_t *owner)
{
    if (owner == NULL || owner->poisoned || owner->active) {
        errno = owner != NULL && owner->active ? EALREADY : EINVAL;
        return -1;
    }
    int flags = fcntl(owner->metadata, F_GETFD);
    if (flags < 0 || fcntl(owner->metadata, F_SETFD,
                           flags & ~FD_CLOEXEC) < 0)
        return -1;
    owner->old_flags = flags;
    owner->active = true;
    return 0;
}

static bool decode_record(const unsigned char *data, size_t length,
                           sparc64_prepared_program_t **out, char *error,
                           size_t error_size)
{
    if (length < IMAGE_RECORD_HEADER || memcmp(data, "RVIMEX01", 8) != 0 ||
        get32(data + 8) != 1 || get32(data + 12) != IMAGE_RECORD_HEADER ||
        get64(data + 16) != length || get32(data + 44) != 0) {
        errno = EINVAL;
        return record_error(error, error_size, "invalid image transport header");
    }
    uint64_t target_size = get64(data + 24);
    uint64_t interpreter_size = get64(data + 32);
    uint32_t flags = get32(data + 40);
    if (target_size < 64 || target_size > SPARC64_IMAGE_MAX_SIZE ||
        interpreter_size > SPARC64_IMAGE_MAX_SIZE || flags > 1 ||
        (flags == 0 && interpreter_size != 0) ||
        (flags == 1 && interpreter_size < 64) ||
        target_size + interpreter_size + IMAGE_RECORD_HEADER != length) {
        errno = EINVAL;
        return record_error(error, error_size, "invalid image transport lengths");
    }
    sparc64_prepared_program_t *prepared = calloc(1, sizeof(*prepared));
    if (prepared == NULL)
        return record_error(error, error_size, "cannot allocate image transport");
    prepared->target.size = (size_t)target_size;
    prepared->target.bytes = malloc(prepared->target.size);
    prepared->has_interpreter = flags == 1;
    if (prepared->has_interpreter) {
        prepared->interpreter.size = (size_t)interpreter_size;
        prepared->interpreter.bytes = malloc(prepared->interpreter.size);
    }
    if (prepared->target.bytes == NULL ||
        (prepared->has_interpreter && prepared->interpreter.bytes == NULL)) {
        int saved = errno;
        sparc64_program_prepared_destroy(prepared);
        errno = saved;
        return record_error(error, error_size, "cannot allocate image transport");
    }
    memcpy(prepared->target.bytes, data + IMAGE_RECORD_HEADER,
           prepared->target.size);
    if (prepared->has_interpreter)
        memcpy(prepared->interpreter.bytes,
               data + IMAGE_RECORD_HEADER + prepared->target.size,
               prepared->interpreter.size);
    if (!sparc64_prepared_validate(prepared, error, error_size)) {
        sparc64_program_prepared_destroy(prepared);
        errno = EINVAL;
        return false;
    }
    *out = prepared;
    return true;
}

bool sparc64_program_import(int owned_fd, sparc64_prepared_program_t **out,
                        char *error, size_t error_size)
{
    if (out == NULL || owned_fd < 3) {
        if (owned_fd >= 3)
            (void)close(owned_fd);
        errno = EINVAL;
        return record_error(error, error_size, "invalid image transport arguments");
    }
    *out = NULL;
    unsigned char *data = NULL;
    bool success = false;
    const char *failure = NULL;
    int flags = fcntl(owned_fd, F_GETFD);
    if (flags < 0 || fcntl(owned_fd, F_SETFD, flags | FD_CLOEXEC) < 0) {
        failure = "cannot restore image transport CLOEXEC";
        goto done;
    }
    struct stat before, after;
    if (!private_metadata(owned_fd, &before) ||
        before.st_size < (off_t)IMAGE_RECORD_HEADER ||
        (uint64_t)before.st_size > IMAGE_RECORD_MAX) {
        errno = EINVAL;
        failure = "invalid image transport file";
        goto done;
    }
    size_t length = (size_t)before.st_size;
    data = malloc(length);
    if (data == NULL) {
        failure = "cannot allocate image transport";
        goto done;
    }
    if (read_all(owned_fd, data, length) != 0) {
        failure = "cannot read complete image transport";
        goto done;
    }
    if (!private_metadata(owned_fd, &after) ||
        !same_record_stat(&before, &after)) {
        errno = EINVAL;
        failure = "image transport changed while importing";
        goto done;
    }
    success = decode_record(data, length, out, error, error_size);
done: {
        int saved = errno;
        free(data);
        if (close(owned_fd) != 0 && success) {
            saved = errno;
            sparc64_program_prepared_destroy(*out);
            *out = NULL;
            success = record_error(error, error_size,
                                   "cannot close image transport descriptor");
        }
        if (!success && failure != NULL)
            (void)record_error(error, error_size, failure);
        errno = saved;
        return success;
    }
}
