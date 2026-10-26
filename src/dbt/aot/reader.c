/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#if defined(__APPLE__)
#define _DARWIN_C_SOURCE 1
#endif
#define _POSIX_C_SOURCE 200809L
#include "dbt/aot/reader.h"
#include "dbt/aot/digest.h"
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

int sparc64_aot_record_digest(const uint8_t *bytes, size_t size,
                          uint8_t out[SPARC64_AOT_DIGEST_BYTES])
{
    sparc64_aot_view_t view;
    if (out == NULL || sparc64_aot_decode(bytes, size, &view) != 0 ||
        view.format_version != SPARC64_AOT_FORMAT_V2) {
        errno = EINVAL;
        return -1;
    }
    static const uint8_t domain[] = "sparc64rt-cache-record-v2";
    static const uint8_t zeros[SPARC64_AOT_DIGEST_BYTES] = {0};
    const sparc64_aot_span_t spans[] = {
        {domain, sizeof(domain) - 1},
        {bytes, SPARC64_AOT_RECORD_DIGEST_OFFSET},
        {zeros, sizeof(zeros)},
        {bytes + SPARC64_AOT_HEADER_V2_BYTES, size - SPARC64_AOT_HEADER_V2_BYTES}
    };
    return sparc64_aot_sha256_spans(spans, sizeof(spans)/sizeof(spans[0]), out);
}

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

static bool file_safe(const struct stat *st, uid_t owner)
{
    return S_ISREG(st->st_mode) && st->st_uid == owner &&
           (st->st_mode & 07777) == 0600 && st->st_nlink == 1 &&
           st->st_size >= (off_t)SPARC64_AOT_HEADER_V2_BYTES &&
           st->st_size <= (off_t)SPARC64_AOT_MAX_FILE_BYTES;
}

static bool metadata_same(const struct stat *a, const struct stat *b)
{
    bool same = a->st_dev == b->st_dev && a->st_ino == b->st_ino &&
        a->st_mode == b->st_mode && a->st_uid == b->st_uid &&
        a->st_gid == b->st_gid && a->st_nlink == b->st_nlink &&
        a->st_size == b->st_size;
#if defined(__APPLE__)
    return same && a->st_mtimespec.tv_sec == b->st_mtimespec.tv_sec &&
        a->st_mtimespec.tv_nsec == b->st_mtimespec.tv_nsec &&
        a->st_ctimespec.tv_sec == b->st_ctimespec.tv_sec &&
        a->st_ctimespec.tv_nsec == b->st_ctimespec.tv_nsec;
#else
    return same && a->st_mtim.tv_sec == b->st_mtim.tv_sec &&
        a->st_mtim.tv_nsec == b->st_mtim.tv_nsec &&
        a->st_ctim.tv_sec == b->st_ctim.tv_sec &&
        a->st_ctim.tv_nsec == b->st_ctim.tv_nsec;
#endif
}

static bool identity_matches(const sparc64_aot_view_t *v, const sparc64_aot_identity_t *e)
{
    return memcmp(v->input_digest, e->input_digest, SPARC64_AOT_DIGEST_BYTES) == 0 &&
        memcmp(v->runtime_digest, e->runtime_digest, SPARC64_AOT_DIGEST_BYTES) == 0 &&
        memcmp(v->emitter_digest, e->emitter_digest, SPARC64_AOT_DIGEST_BYTES) == 0 &&
        memcmp(v->profile_digest, e->profile_digest, SPARC64_AOT_DIGEST_BYTES) == 0 &&
        v->guest_extensions == e->guest_extensions &&
        v->a64_host_requirements == e->a64_host_requirements &&
        v->guest_page_size == e->guest_page_size &&
        v->a64_host_page_size == e->a64_host_page_size &&
        v->memory_model == e->memory_model && v->xlen == e->xlen &&
        v->abi == e->abi;
}

static sparc64_aot_read_result_t snapshot_read(int directory_fd, const char *leaf,
                                          const sparc64_aot_identity_t *expected,
                                          bool authorized,
                                          sparc64_aot_authority_policy_t policy,
                                          sparc64_aot_snapshot_t *out)
{
    if (directory_fd < 0 || !leaf_valid(leaf) || expected == NULL || out == NULL ||
        out->bytes != NULL || out->size != 0 || out->view.encoded != NULL) {
        errno = EINVAL;
        return SPARC64_AOT_READ_ERROR;
    }
    uid_t owner = geteuid();
    if (getuid() != owner || getgid() != getegid())
        return SPARC64_AOT_READ_MISS;
    struct stat directory;
    if (fstat(directory_fd, &directory) != 0)
        return SPARC64_AOT_READ_ERROR;
    if (!directory_safe(&directory, owner))
        return SPARC64_AOT_READ_MISS;
    if (authorized && !sparc64_aot_authorize_fd(directory_fd, true, policy))
        return SPARC64_AOT_READ_MISS;
    int fd = openat(directory_fd, leaf, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0) {
        if (errno == ENOENT || errno == ELOOP || errno == EACCES ||
            errno == ENOTDIR || errno == ENXIO)
            return SPARC64_AOT_READ_MISS;
        return SPARC64_AOT_READ_ERROR;
    }
    sparc64_aot_read_result_t result = SPARC64_AOT_READ_ERROR;
    sparc64_aot_snapshot_t candidate = {0};
    struct stat before, after, directory_after;
    if (fstat(fd, &before) != 0)
        goto done;
    if (!file_safe(&before, owner) ||
        (authorized && !sparc64_aot_authorize_fd(fd, false, policy))) {
        result = SPARC64_AOT_READ_MISS;
        goto done;
    }
    candidate.size = (size_t)before.st_size;
    candidate.bytes = malloc(candidate.size);
    if (candidate.bytes == NULL)
        goto done;
    size_t offset = 0;
    while (offset < candidate.size) {
        size_t amount = candidate.size - offset;
        if (amount > 65536)
            amount = 65536;
        ssize_t got = pread(fd, candidate.bytes + offset, amount, (off_t)offset);
        if (got < 0 && errno == EINTR)
            continue;
        if (got < 0)
            goto done;
        if (got == 0) {
            result = SPARC64_AOT_READ_MISS;
            goto done;
        }
        offset += (size_t)got;
    }
    if (fstat(fd, &after) != 0 || fstat(directory_fd, &directory_after) != 0)
        goto done;
    if (!file_safe(&after, owner) || !metadata_same(&before, &after) ||
        !directory_safe(&directory_after, owner) ||
        directory.st_dev != directory_after.st_dev ||
        directory.st_ino != directory_after.st_ino ||
        (authorized && (!sparc64_aot_authorize_fd(fd, false, policy) ||
                        !sparc64_aot_authorize_fd(directory_fd, true, policy)))) {
        result = SPARC64_AOT_READ_MISS;
        goto done;
    }
    uint8_t digest[SPARC64_AOT_DIGEST_BYTES];
    if (sparc64_aot_decode(candidate.bytes, candidate.size, &candidate.view) != 0 ||
        candidate.view.format_version != SPARC64_AOT_FORMAT_V2) {
        result = SPARC64_AOT_READ_MISS;
        goto done;
    }
    if (sparc64_aot_record_digest(candidate.bytes, candidate.size, digest) != 0)
        goto done;
    if (memcmp(digest, candidate.view.record_digest, sizeof(digest)) != 0 ||
        !identity_matches(&candidate.view, expected)) {
        result = SPARC64_AOT_READ_MISS;
        goto done;
    }
    result = SPARC64_AOT_READ_HIT;
done:;
    int saved_errno = errno;
    if (close(fd) != 0 && result == SPARC64_AOT_READ_HIT) {
        result = SPARC64_AOT_READ_ERROR;
        saved_errno = errno;
    }
    if (result == SPARC64_AOT_READ_HIT)
        *out = candidate;
    else
        free(candidate.bytes);
    errno = saved_errno;
    return result;
}

sparc64_aot_read_result_t sparc64_aot_snapshot_read(int directory_fd, const char *leaf,
                                          const sparc64_aot_identity_t *expected,
                                          sparc64_aot_snapshot_t *out)
{
    return snapshot_read(directory_fd, leaf, expected, false,
                         SPARC64_AOT_AUTHORITY_AUTO, out);
}

sparc64_aot_read_result_t sparc64_aot_snapshot_read_authorized(
    int directory_fd, const char *leaf, const sparc64_aot_identity_t *expected,
    sparc64_aot_authority_policy_t policy, sparc64_aot_snapshot_t *out)
{
    return snapshot_read(directory_fd, leaf, expected, true, policy, out);
}

void sparc64_aot_snapshot_destroy(sparc64_aot_snapshot_t *snapshot)
{
    if (snapshot != NULL) {
        free(snapshot->bytes);
        memset(snapshot, 0, sizeof(*snapshot));
    }
}
