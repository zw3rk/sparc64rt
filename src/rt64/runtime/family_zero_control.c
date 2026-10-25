/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#define _GNU_SOURCE
#include "runtime/family_zero_control.h"
#include "aot/authority.h"
#include "aot/digest.h"
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <unistd.h>

#define CONTROL_NAME "zero-control"
#define HIGH_ATTRIBUTE "user.sparc64rt.zero_control.high"
#define HEAD_ATTRIBUTE "user.sparc64rt.zero_control.head"
#define HIGH_SIZE 56u
#define HEAD_SIZE 144u
#define CONTROL_VERSION 1u

struct sparc64_family_zero_control {
    int directory_fd;
    int control_fd;
    pthread_mutex_t mutex;
    dev_t control_device;
    ino_t control_inode;
    pid_t process_id;
    pthread_t creator_thread;
    int creator_cancel_state;
    bool guard_held;
    bool poisoned;
};

/* A second local control owner could close an alias to the same inode and
 * release every POSIX lock held by this process. This finite component admits
 * one owner per process, reserving the slot before any control open. A later
 * multi-family registry may relax that without weakening inode uniqueness. */
static _Atomic(sparc64_family_zero_control_t *) local_owner;
#define OWNER_RESERVED ((sparc64_family_zero_control_t *)(uintptr_t)1)

#ifdef SPARC64_FAMILY_ZERO_CONTROL_TEST_HOOKS
static sparc64_family_zero_control_test_hook_t test_hook;
void sparc64_family_zero_control_test_set_hook(
    sparc64_family_zero_control_test_hook_t hook)
{
    test_hook = hook;
}
int sparc64_family_zero_control_test_control_fd(
    const sparc64_family_zero_control_t *owner)
{
    return owner == NULL ? -1 : owner->control_fd;
}
static void test_cut(unsigned phase)
{
    if (test_hook != NULL)
        test_hook(phase);
}
#else
static void test_cut(unsigned phase) { (void)phase; }
#endif

typedef struct head_record {
    uint64_t generation;
    uint64_t root_id;
    uint64_t previous_id;
    uint32_t root_size;
    uint32_t previous_size;
    uint8_t root_digest[SPARC64_AOT_SHA256_BYTES];
    uint8_t previous_digest[SPARC64_AOT_SHA256_BYTES];
    uint8_t root[SPARC64_FAMILY_ZERO_BLOB_MAX_SIZE];
} head_record_t;

typedef struct owned_stage {
    char name[64];
    dev_t device;
    ino_t inode;
    bool created;
} owned_stage_t;

static void put32(uint8_t *out, uint32_t value)
{
    for (unsigned i = 0; i < 4; ++i)
        out[i] = (uint8_t)(value >> (8u * i));
}

static void put64(uint8_t *out, uint64_t value)
{
    for (unsigned i = 0; i < 8; ++i)
        out[i] = (uint8_t)(value >> (8u * i));
}

static uint32_t get32(const uint8_t *in)
{
    uint32_t value = 0;
    for (unsigned i = 0; i < 4; ++i)
        value |= (uint32_t)in[i] << (8u * i);
    return value;
}

static uint64_t get64(const uint8_t *in)
{
    uint64_t value = 0;
    for (unsigned i = 0; i < 8; ++i)
        value |= (uint64_t)in[i] << (8u * i);
    return value;
}

static int check_directory(int fd)
{
    struct stat status;
    if (fstat(fd, &status) != 0)
        return -1;
    if (!S_ISDIR(status.st_mode) || status.st_uid != geteuid() ||
        (status.st_mode & 07777) != 0700 ||
        !sparc64_aot_authorize_fd(fd, true, SPARC64_AOT_AUTHORITY_AUTO)) {
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
        status.st_size != 0 ||
        !sparc64_aot_authorize_fd(fd, false, SPARC64_AOT_AUTHORITY_AUTO)) {
        errno = EACCES;
        return -1;
    }
    return 0;
}

static int same_named_control(const sparc64_family_zero_control_t *owner)
{
    struct stat held, named;
    if (check_directory(owner->directory_fd) != 0 ||
        check_file(owner->control_fd) != 0 ||
        fstat(owner->control_fd, &held) != 0 ||
        fstatat(owner->directory_fd, CONTROL_NAME, &named,
                AT_SYMLINK_NOFOLLOW) != 0)
        return -1;
    if (held.st_dev != owner->control_device ||
        held.st_ino != owner->control_inode ||
        named.st_dev != held.st_dev || named.st_ino != held.st_ino ||
        !S_ISREG(named.st_mode) || named.st_nlink != 1) {
        errno = ESTALE;
        return -1;
    }
    return 0;
}

static int reserve_owner_slot(void)
{
    sparc64_family_zero_control_t *expected = NULL;
    if (!atomic_compare_exchange_strong(&local_owner, &expected,
                                         OWNER_RESERVED)) {
        errno = EBUSY;
        return -1;
    }
    return 0;
}

static void clear_owner_slot(void)
{
    atomic_store(&local_owner, NULL);
}

static void discard_owner(sparc64_family_zero_control_t *owner)
{
    if (owner == NULL)
        return;
    if (owner->control_fd >= 0)
        (void)close(owner->control_fd);
    if (owner->directory_fd >= 0)
        (void)close(owner->directory_fd);
    (void)pthread_mutex_destroy(&owner->mutex);
    free(owner);
}

static int initialize_owner_mutex(pthread_mutex_t *mutex)
{
    pthread_mutexattr_t attributes;
    int rc = pthread_mutexattr_init(&attributes);
    if (rc != 0)
        return rc;
    rc = pthread_mutexattr_settype(&attributes, PTHREAD_MUTEX_ERRORCHECK);
    if (rc == 0)
        rc = pthread_mutex_init(mutex, &attributes);
    (void)pthread_mutexattr_destroy(&attributes);
    return rc;
}

static int make_owner(int directory_fd, bool create,
                      sparc64_family_zero_control_t **out)
{
    if (directory_fd < 0 || out == NULL || *out != NULL) {
        errno = EINVAL;
        return -1;
    }
    if (reserve_owner_slot() != 0)
        return -1;
    sparc64_family_zero_control_t *owner = calloc(1, sizeof(*owner));
    if (owner == NULL) {
        clear_owner_slot();
        return -1;
    }
    owner->directory_fd = -1;
    owner->control_fd = -1;
    int rc = initialize_owner_mutex(&owner->mutex);
    if (rc != 0) {
        free(owner);
        clear_owner_slot();
        errno = rc;
        return -1;
    }
    if (check_directory(directory_fd) != 0)
        goto fail;
    owner->directory_fd = fcntl(directory_fd, F_DUPFD_CLOEXEC, 3);
    if (owner->directory_fd < 0)
        goto fail;
    int flags = O_RDWR | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC;
    if (create)
        flags |= O_CREAT | O_EXCL;
    owner->control_fd = openat(owner->directory_fd, CONTROL_NAME,
                               flags, 0600);
    if (owner->control_fd < 0 || check_file(owner->control_fd) != 0)
        goto fail;
    struct stat status;
    if (fstat(owner->control_fd, &status) != 0)
        goto fail;
    owner->control_device = status.st_dev;
    owner->control_inode = status.st_ino;
    owner->process_id = getpid();
    owner->creator_thread = pthread_self();
    atomic_store(&local_owner, owner);
    *out = owner;
    return 0;
fail: {
    int saved = errno;
    discard_owner(owner);
    clear_owner_slot();
    errno = saved;
    return -1;
}
}

static int write_highwater(sparc64_family_zero_control_t *owner, uint64_t value)
{
    uint8_t wire[HIGH_SIZE] = {0};
    memcpy(wire, "RVZHIGH1", 8);
    put32(wire + 8, CONTROL_VERSION);
    put64(wire + 16, value);
    if (sparc64_aot_sha256(wire, 24, wire + 24) != 0)
        return -1;
    if (fsetxattr(owner->control_fd, HIGH_ATTRIBUTE, wire,
                  sizeof(wire), 0) != 0 || fsync(owner->control_fd) != 0)
        return -1;
    return 0;
}

static int read_highwater(sparc64_family_zero_control_t *owner,
                          uint64_t *out)
{
    uint8_t wire[HIGH_SIZE], digest[SPARC64_AOT_SHA256_BYTES];
    ssize_t got = fgetxattr(owner->control_fd, HIGH_ATTRIBUTE, wire,
                            sizeof(wire));
    if (got != (ssize_t)sizeof(wire) ||
        memcmp(wire, "RVZHIGH1", 8) != 0 ||
        get32(wire + 8) != CONTROL_VERSION || get32(wire + 12) != 0 ||
        sparc64_aot_sha256(wire, 24, digest) != 0 ||
        memcmp(digest, wire + 24, sizeof(digest)) != 0) {
        errno = EBADMSG;
        return -1;
    }
    *out = get64(wire + 16);
    return 0;
}

static int head_name(char out[16], unsigned slot)
{
    int count = snprintf(out, 16, "head.%u", slot);
    if (count < 0 || count >= 16) {
        errno = EOVERFLOW;
        return -1;
    }
    return 0;
}

static int stage_name(char out[64], uint64_t id)
{
    int count = snprintf(out, 64, "head-stage-%016llx",
                         (unsigned long long)id);
    if (count < 0 || count >= 64) {
        errno = EOVERFLOW;
        return -1;
    }
    return 0;
}

static int remember_stage(int fd, const char *name, owned_stage_t *stage)
{
    struct stat status;
    if (fstat(fd, &status) != 0)
        return -1;
    size_t length = strlen(name);
    if (length >= sizeof(stage->name)) {
        errno = EOVERFLOW;
        return -1;
    }
    memcpy(stage->name, name, length + 1);
    stage->device = status.st_dev;
    stage->inode = status.st_ino;
    stage->created = true;
    return 0;
}

static int stage_matches(sparc64_family_zero_control_t *owner,
                         const owned_stage_t *stage)
{
    struct stat status;
    if (!stage->created || fstatat(owner->directory_fd, stage->name,
        &status, AT_SYMLINK_NOFOLLOW) != 0)
        return -1;
    if (status.st_dev != stage->device || status.st_ino != stage->inode ||
        !S_ISREG(status.st_mode) || status.st_nlink != 1 ||
        status.st_size != 0) {
        errno = ESTALE;
        return -1;
    }
    return 0;
}

static void cleanup_stage(sparc64_family_zero_control_t *owner,
                          const owned_stage_t *stage)
{
    if (stage_matches(owner, stage) == 0)
        (void)unlinkat(owner->directory_fd, stage->name, 0);
}

static int make_head_wire(uint8_t out[HEAD_SIZE], unsigned slot,
                          const head_record_t *head)
{
    memset(out, 0, HEAD_SIZE);
    memcpy(out, "RVZHEAD1", 8);
    put32(out + 8, CONTROL_VERSION);
    put32(out + 12, slot);
    put64(out + 16, head->generation);
    put64(out + 24, head->root_id);
    put64(out + 32, head->previous_id);
    put32(out + 40, head->root_size);
    put32(out + 44, head->previous_size);
    memcpy(out + 48, head->root_digest, SPARC64_AOT_SHA256_BYTES);
    memcpy(out + 80, head->previous_digest, SPARC64_AOT_SHA256_BYTES);
    return sparc64_aot_sha256(out, 112, out + 112);
}

/* The inactive slot's old inode is replaced atomically. All blob data and
 * the stage directory entry were durably sealed before this rename. */
static int publish_head(sparc64_family_zero_control_t *owner,
                        const head_record_t *head)
{
    char stage_name_text[64], final_name[16];
    unsigned slot = (unsigned)(head->generation & 1u);
    if (stage_name(stage_name_text, head->root_id) != 0 ||
        head_name(final_name, slot) != 0)
        return -1;
    owned_stage_t stage = {0};
    int fd = openat(owner->directory_fd, stage_name_text,
                    O_RDWR | O_CREAT | O_EXCL | O_NONBLOCK | O_NOFOLLOW |
                    O_CLOEXEC, 0600);
    if (fd < 0)
        return -1;
    int result = -1;
    if (remember_stage(fd, stage_name_text, &stage) != 0 ||
        check_file(fd) != 0)
        goto failed;
    uint8_t wire[HEAD_SIZE];
    if (make_head_wire(wire, slot, head) != 0 ||
        fsetxattr(fd, HEAD_ATTRIBUTE, wire, sizeof(wire), 0) != 0 ||
        fsync(fd) != 0)
        goto failed;
    if (close(fd) != 0) {
        fd = -1;
        goto failed;
    }
    fd = -1;
    if (fsync(owner->directory_fd) != 0 ||
        stage_matches(owner, &stage) != 0)
        goto failed;
    test_cut(3);
    if (renameat(owner->directory_fd, stage_name_text,
                 owner->directory_fd, final_name) != 0)
        goto failed;
    test_cut(4);
    /* From here a caller may observe either complete head after a crash.
     * An error is uncertain, never a recoverable prepublication failure. */
    owned_stage_t final = stage;
    size_t name_length = strlen(final_name);
    memcpy(final.name, final_name, name_length + 1);
    if (stage_matches(owner, &final) != 0 ||
        fsync(owner->directory_fd) != 0) {
        owner->poisoned = true;
        errno = EIO;
        return -2;
    }
    return 0;
failed: {
    int saved = errno;
    if (fd >= 0)
        (void)close(fd);
    cleanup_stage(owner, &stage);
    errno = saved;
    return result;
}
}

static int load_head(sparc64_family_zero_control_t *owner, unsigned slot,
                     head_record_t *out)
{
    char name[16];
    if (head_name(name, slot) != 0)
        return -1;
    int fd = openat(owner->directory_fd, name,
                    O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) {
        if (errno == ENOENT)
            return 0;
        return -1;
    }
    uint8_t wire[HEAD_SIZE], digest[SPARC64_AOT_SHA256_BYTES];
    bool valid = check_file(fd) == 0;
    ssize_t got = valid ? fgetxattr(fd, HEAD_ATTRIBUTE, wire,
                                    sizeof(wire)) : -1;
    struct stat held, named;
    bool matched = valid && got == (ssize_t)sizeof(wire) &&
        fstat(fd, &held) == 0 &&
        fstatat(owner->directory_fd, name, &named,
                AT_SYMLINK_NOFOLLOW) == 0 &&
        held.st_dev == named.st_dev && held.st_ino == named.st_ino;
    if (!matched) {
        (void)close(fd);
        errno = EBADMSG;
        return -1;
    }
    if (memcmp(wire, "RVZHEAD1", 8) != 0 ||
        get32(wire + 8) != CONTROL_VERSION || get32(wire + 12) != slot ||
        sparc64_aot_sha256(wire, 112, digest) != 0 ||
        memcmp(digest, wire + 112, sizeof(digest)) != 0) {
        goto malformed;
    }
    head_record_t parsed = {0};
    parsed.generation = get64(wire + 16);
    parsed.root_id = get64(wire + 24);
    parsed.previous_id = get64(wire + 32);
    parsed.root_size = get32(wire + 40);
    parsed.previous_size = get32(wire + 44);
    memcpy(parsed.root_digest, wire + 48, SPARC64_AOT_SHA256_BYTES);
    memcpy(parsed.previous_digest, wire + 80, SPARC64_AOT_SHA256_BYTES);
    if (parsed.generation == 0 || (parsed.generation & 1u) != slot ||
        parsed.root_id == 0 ||
        parsed.root_size > SPARC64_FAMILY_ZERO_BLOB_MAX_SIZE ||
        parsed.previous_size > SPARC64_FAMILY_ZERO_BLOB_MAX_SIZE ||
        (parsed.generation == 1) != (parsed.previous_id == 0) ||
        (parsed.previous_id != 0 && parsed.previous_id >= parsed.root_id)) {
        goto malformed;
    }
    size_t actual = 0;
    if (sparc64_family_zero_blob_read(owner->directory_fd, parsed.root_id,
        parsed.root, sizeof(parsed.root), &actual) != 0 ||
        actual != parsed.root_size ||
        sparc64_aot_sha256(parsed.root, actual, digest) != 0 ||
        memcmp(digest, parsed.root_digest, sizeof(digest)) != 0) {
        goto malformed;
    }
    if (parsed.previous_id != 0) {
        uint8_t previous[SPARC64_FAMILY_ZERO_BLOB_MAX_SIZE];
        if (sparc64_family_zero_blob_read(owner->directory_fd,
            parsed.previous_id, previous, sizeof(previous), &actual) != 0 ||
            actual != parsed.previous_size ||
            sparc64_aot_sha256(previous, actual, digest) != 0 ||
            memcmp(digest, parsed.previous_digest, sizeof(digest)) != 0) {
            goto malformed;
        }
    } else {
        static const uint8_t zero[SPARC64_AOT_SHA256_BYTES];
        if (parsed.previous_size != 0 ||
            memcmp(parsed.previous_digest, zero, sizeof(zero)) != 0) {
            goto malformed;
        }
    }
    uint8_t current[HEAD_SIZE];
    ssize_t again = fgetxattr(fd, HEAD_ATTRIBUTE, current,
                              sizeof(current));
    if (check_file(fd) != 0 || again != (ssize_t)sizeof(current) ||
        memcmp(current, wire, sizeof(current)) != 0 ||
        fstat(fd, &held) != 0 ||
        fstatat(owner->directory_fd, name, &named,
                AT_SYMLINK_NOFOLLOW) != 0 ||
        held.st_dev != named.st_dev || held.st_ino != named.st_ino)
        goto malformed;
    if (close(fd) != 0) {
        errno = EIO;
        return -1;
    }
    *out = parsed;
    return 1;
malformed:
    (void)close(fd);
    errno = EBADMSG;
    return -1;
}

static int read_current(sparc64_family_zero_control_t *owner,
                        sparc64_family_zero_snapshot_t *out)
{
    head_record_t one = {0}, zero = {0};
    int first = load_head(owner, 0, &zero);
    if (first < 0)
        return -1;
    int second = load_head(owner, 1, &one);
    if (second < 0)
        return -1;
    if (first == 0 && second == 0) {
        errno = ENOENT;
        return -1;
    }
    const head_record_t *current;
    if (first != 0 && second != 0) {
        const head_record_t *newer = zero.generation > one.generation ?
            &zero : &one;
        const head_record_t *older = newer == &zero ? &one : &zero;
        if (older->generation == UINT64_MAX ||
            newer->generation != older->generation + 1 ||
            newer->root_id <= older->root_id ||
            newer->previous_id != older->root_id ||
            newer->previous_size != older->root_size ||
            memcmp(newer->previous_digest, older->root_digest,
                   SPARC64_AOT_SHA256_BYTES) != 0) {
            errno = EBADMSG;
            return -1;
        }
        current = newer;
    } else {
        current = first != 0 ? &zero : &one;
        if (current->generation != 1) {
            errno = EBADMSG;
            return -1;
        }
    }
    uint64_t high = 0;
    if (read_highwater(owner, &high) != 0 ||
        high < current->root_id || high < current->previous_id) {
        errno = EBADMSG;
        return -1;
    }
    sparc64_family_zero_snapshot_t next = {0};
    next.generation = current->generation;
    next.root_id = current->root_id;
    next.size = current->root_size;
    if (next.size != 0)
        memcpy(next.bytes, current->root, next.size);
    *out = next;
    return 0;
}

static int native_lock(int fd, short type, int command)
{
    struct flock lock = {.l_type = type, .l_whence = SEEK_SET,
                         .l_start = 0, .l_len = 1};
    int result;
    do { result = fcntl(fd, command, &lock); }
    while (result < 0 && errno == EINTR);
    return result;
}

int sparc64_family_zero_control_begin(sparc64_family_zero_control_t *owner,
                                  sparc64_family_zero_guard_t *guard,
                                  sparc64_family_zero_snapshot_t *out)
{
    if (owner == NULL || guard == NULL || out == NULL || guard->held ||
        owner->process_id != getpid() ||
        atomic_load(&local_owner) != owner) {
        errno = EINVAL;
        return -1;
    }
    int previous;
    int rc = pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &previous);
    if (rc != 0) {
        errno = rc;
        return -1;
    }
    rc = pthread_mutex_lock(&owner->mutex);
    if (rc != 0) {
        (void)pthread_setcancelstate(previous, NULL);
        errno = rc;
        return -1;
    }
    if (owner->poisoned ||
        native_lock(owner->control_fd, F_WRLCK, F_SETLKW) != 0) {
        int saved = owner->poisoned ? EIO : errno;
        (void)pthread_mutex_unlock(&owner->mutex);
        (void)pthread_setcancelstate(previous, NULL);
        errno = saved;
        return -1;
    }
    sparc64_family_zero_snapshot_t current;
    if (same_named_control(owner) != 0 || read_current(owner, &current) != 0) {
        int saved = errno;
        if (native_lock(owner->control_fd, F_UNLCK, F_SETLK) != 0)
            _exit(125);
        (void)pthread_mutex_unlock(&owner->mutex);
        (void)pthread_setcancelstate(previous, NULL);
        errno = saved;
        return -1;
    }
    guard->owner = owner;
    guard->current = current;
    guard->previous_cancel_state = previous;
    guard->thread = pthread_self();
    guard->held = true;
    owner->guard_held = true;
    *out = current;
    return 0;
}

int sparc64_family_zero_control_leave(sparc64_family_zero_guard_t *guard)
{
    if (guard == NULL || !guard->held || guard->owner == NULL) {
        errno = EINVAL;
        return -1;
    }
    if (!pthread_equal(guard->thread, pthread_self())) {
        errno = EPERM;
        return -1;
    }
    sparc64_family_zero_control_t *owner = guard->owner;
    owner->guard_held = false;
    if (native_lock(owner->control_fd, F_UNLCK, F_SETLK) != 0 ||
        pthread_mutex_unlock(&owner->mutex) != 0)
        _exit(125);
    guard->held = false;
    guard->owner = NULL;
    if (pthread_setcancelstate(guard->previous_cancel_state, NULL) != 0)
        _exit(125);
    return 0;
}

int sparc64_family_zero_control_commit(sparc64_family_zero_guard_t *guard,
                                   const uint8_t *bytes, size_t size,
                                   sparc64_family_zero_snapshot_t *out)
{
    if (guard == NULL || !guard->held || guard->owner == NULL ||
        out == NULL || size > SPARC64_FAMILY_ZERO_BLOB_MAX_SIZE ||
        (size != 0 && bytes == NULL)) {
        errno = EINVAL;
        return -1;
    }
    sparc64_family_zero_control_t *owner = guard->owner;
    if (!pthread_equal(guard->thread, pthread_self())) {
        errno = EPERM;
        return -1;
    }
    if (owner->process_id != getpid() || owner->poisoned ||
        !owner->guard_held || same_named_control(owner) != 0) {
        errno = EIO;
        return -1;
    }
    sparc64_family_zero_snapshot_t actual;
    if (read_current(owner, &actual) != 0 ||
        actual.generation != guard->current.generation ||
        actual.root_id != guard->current.root_id ||
        actual.size != guard->current.size ||
        memcmp(actual.bytes, guard->current.bytes, actual.size) != 0) {
        errno = ESTALE;
        return -1;
    }
    if (actual.generation == UINT64_MAX) {
        errno = EOVERFLOW;
        return -1;
    }
    uint64_t high;
    if (read_highwater(owner, &high) != 0)
        return -1;
    if (high == UINT64_MAX) {
        errno = EOVERFLOW;
        return -1;
    }
    uint64_t id = high + 1;
    if (write_highwater(owner, id) != 0)
        return -1;
    test_cut(1);
    if (sparc64_family_zero_blob_publish(owner->directory_fd, id,
                                     bytes, size) != 0)
        return -1;
    test_cut(2);
    head_record_t next = {0};
    next.generation = actual.generation + 1;
    next.root_id = id;
    next.root_size = (uint32_t)size;
    next.previous_id = actual.root_id;
    next.previous_size = (uint32_t)actual.size;
    if (sparc64_aot_sha256(bytes, size, next.root_digest) != 0 ||
        sparc64_aot_sha256(actual.bytes, actual.size,
                      next.previous_digest) != 0)
        return -1;
    int published = publish_head(owner, &next);
    if (published != 0)
        return published;
    sparc64_family_zero_snapshot_t committed = {0};
    committed.generation = next.generation;
    committed.root_id = id;
    committed.size = size;
    if (size != 0)
        memcpy(committed.bytes, bytes, size);
    guard->current = committed;
    *out = committed;
    return 0;
}

int sparc64_family_zero_control_create(int directory_fd, const uint8_t *initial,
                                   size_t initial_size,
                                   sparc64_family_zero_control_t **out)
{
    if (out == NULL || *out != NULL ||
        initial_size > SPARC64_FAMILY_ZERO_BLOB_MAX_SIZE ||
        (initial_size != 0 && initial == NULL)) {
        errno = EINVAL;
        return -1;
    }
    int previous;
    int cancel_rc = pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &previous);
    if (cancel_rc != 0) {
        errno = cancel_rc;
        return -1;
    }
    sparc64_family_zero_control_t *owner = NULL;
    if (make_owner(directory_fd, true, &owner) != 0) {
        int saved = errno;
        (void)pthread_setcancelstate(previous, NULL);
        errno = saved;
        return -1;
    }
    owner->creator_cancel_state = previous;
    head_record_t genesis = {0};
    genesis.generation = 1;
    genesis.root_id = 1;
    genesis.root_size = (uint32_t)initial_size;
    int result = write_highwater(owner, 1);
    if (result == 0)
        result = sparc64_family_zero_blob_publish(owner->directory_fd, 1,
                                              initial, initial_size);
    if (result == -2)
        result = -1; /* An orphan blob does not publish a family head. */
    if (result == 0)
        result = sparc64_aot_sha256(initial, initial_size, genesis.root_digest);
    if (result == 0)
        result = publish_head(owner, &genesis);
    if (result != 0) {
        int saved = errno;
        sparc64_family_zero_control_destroy(owner);
        errno = saved;
        return result == -2 ? -2 : -1;
    }
    *out = owner;
    return 0;
}

int sparc64_family_zero_control_adopt(int directory_fd,
                                  sparc64_family_zero_control_t **out)
{
    if (out == NULL || *out != NULL) {
        errno = EINVAL;
        return -1;
    }
    int previous;
    int cancel_rc = pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &previous);
    if (cancel_rc != 0) {
        errno = cancel_rc;
        return -1;
    }
    sparc64_family_zero_control_t *owner = NULL;
    if (make_owner(directory_fd, false, &owner) != 0) {
        int saved = errno;
        (void)pthread_setcancelstate(previous, NULL);
        errno = saved;
        return -1;
    }
    owner->creator_cancel_state = previous;
    sparc64_family_zero_guard_t guard = {0};
    sparc64_family_zero_snapshot_t snapshot;
    if (sparc64_family_zero_control_begin(owner, &guard, &snapshot) != 0) {
        int saved = errno;
        sparc64_family_zero_control_destroy(owner);
        errno = saved;
        return -1;
    }
    sparc64_family_zero_control_leave(&guard);
    *out = owner;
    return 0;
}

int sparc64_family_zero_control_child_rebase(sparc64_family_zero_control_t **inout)
{
    if (inout == NULL || *inout == NULL ||
        atomic_load(&local_owner) != *inout ||
        (*inout)->process_id == getpid() || (*inout)->guard_held ||
        !pthread_equal((*inout)->creator_thread, pthread_self())) {
        errno = EINVAL;
        return -1;
    }
    sparc64_family_zero_control_t *old = *inout;
    sparc64_family_zero_control_t *fresh = calloc(1, sizeof(*fresh));
    if (fresh == NULL)
        return -1;
    int rc = initialize_owner_mutex(&fresh->mutex);
    if (rc != 0) {
        free(fresh);
        errno = rc;
        return -1;
    }
    fresh->directory_fd = old->directory_fd;
    fresh->control_fd = old->control_fd;
    fresh->control_device = old->control_device;
    fresh->control_inode = old->control_inode;
    fresh->process_id = getpid();
    fresh->creator_thread = pthread_self();
    fresh->creator_cancel_state = old->creator_cancel_state;
    fresh->poisoned = old->poisoned;
    old->directory_fd = -1;
    old->control_fd = -1;
    /* The copied pthread mutex may be locked by a vanished native thread.
     * Free the copied storage without inspecting or destroying that mutex. */
    free(old);
    atomic_store(&local_owner, fresh);
    *inout = fresh;
    return 0;
}

void sparc64_family_zero_control_destroy(sparc64_family_zero_control_t *owner)
{
    if (owner == NULL)
        return;
    if (owner->process_id != getpid() || owner->guard_held ||
        !pthread_equal(owner->creator_thread, pthread_self()) ||
        atomic_load(&local_owner) != owner)
        _exit(125);
    int previous = owner->creator_cancel_state;
    discard_owner(owner);
    clear_owner_slot();
    if (pthread_setcancelstate(previous, NULL) != 0)
        _exit(125);
}
