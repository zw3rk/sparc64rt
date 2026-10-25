/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#define _GNU_SOURCE
#include "runtime/initial_children.h"
#include "runtime/proc_inventory.h"

#include <errno.h>

static void checkpoint(const char **stage, const char *name)
{
    if (stage != NULL)
        *stage = name;
}

#if defined(__linux__)
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/vfs.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef P_PIDFD
#define P_PIDFD 3
#endif
#ifndef __WALL
#define __WALL 0x40000000
#endif

#define PROC_MAGIC 0x9fa0
#define PROC_TEXT_MAX (1024u * 1024u)
#define STATX_BASIC_MASK 0x07ffu
#define STATX_MOUNT_MASK 0x1000u

typedef struct {
    sparc64_process_child_cap_t *records;
    size_t count;
    size_t capacity;
} staged_t;

static uint64_t load_le(const unsigned char *bytes, size_t length)
{
    uint64_t result = 0;
    for (size_t i = 0; i < length; ++i)
        result |= (uint64_t)bytes[i] << (i * 8u);
    return result;
}

static void staged_close(staged_t *staged)
{
    int saved = errno;
    for (size_t i = 0; i < staged->count; ++i)
        (void)close(staged->records[i].cap_fd);
    free(staged->records);
    *staged = (staged_t){0};
    errno = saved;
}

/* Every internal descriptor stays outside the missing standard-FD slots.
 * Never retry close: Linux has already released its number on EINTR. */
static int private_fd(int owned)
{
    if (owned < 0)
        return -1;
    if (owned < 3) {
        int high = fcntl(owned, F_DUPFD_CLOEXEC, 3);
        int saved = errno;
        (void)close(owned);
        if (high < 0) {
            errno = saved;
            return -1;
        }
        owned = high;
    }
    int flags = fcntl(owned, F_GETFD);
    if (flags < 0 || fcntl(owned, F_SETFD, flags | FD_CLOEXEC) != 0) {
        int saved = errno;
        (void)close(owned);
        errno = saved;
        return -1;
    }
    return owned;
}

static int proc_instance(int fd, sparc64_proc_instance_t *out)
{
    struct statfs fs;
    if (fstatfs(fd, &fs) != 0)
        return -1;
    if (fs.f_type != PROC_MAGIC) {
        errno = EOPNOTSUPP;
        return -1;
    }
    /* Use the stable Linux wire prefix, including the mount ID at144. This
     * avoids depending on newer names for musl's reserved statx fields. */
    unsigned char wire[256] = {0};
    if (syscall(SYS_statx, fd, "", AT_EMPTY_PATH,
                STATX_BASIC_MASK | STATX_MOUNT_MASK, wire) != 0)
        return -1;
    if ((load_le(wire, 4) & STATX_MOUNT_MASK) == 0) {
        errno = EOPNOTSUPP;
        return -1;
    }
    *out = (sparc64_proc_instance_t){
        .mount_id = load_le(wire + 144, 8),
        .dev_major = (uint32_t)load_le(wire + 136, 4),
        .dev_minor = (uint32_t)load_le(wire + 140, 4),
    };
    if (out->mount_id == 0) {
        errno = EOPNOTSUPP;
        return -1;
    }
    return 0;
}

static int same_instance(int fd, const sparc64_proc_instance_t *expected)
{
    sparc64_proc_instance_t actual;
    if (proc_instance(fd, &actual) != 0)
        return -1;
    if (actual.mount_id != expected->mount_id ||
        actual.dev_major != expected->dev_major ||
        actual.dev_minor != expected->dev_minor) {
        errno = EOPNOTSUPP;
        return -1;
    }
    return 0;
}

static int read_proc(int directory, const char *path,
                     const sparc64_proc_instance_t *instance,
                     char **text, size_t *length)
{
    /* Verify before reading, and do not let an overlaid FIFO block open
     * before its non-proc provenance can be rejected. */
    int fd = private_fd(openat(directory, path,
        O_RDONLY | O_NONBLOCK | O_CLOEXEC | O_NOFOLLOW));
    if (fd < 0)
        return -1;
    size_t capacity = 4096, used = 0;
    char *data = NULL;
    struct stat metadata;
    if (fstat(fd, &metadata) != 0 || same_instance(fd, instance) != 0)
        goto fail;
    if (!S_ISREG(metadata.st_mode)) {
        errno = EOPNOTSUPP;
        goto fail;
    }
    data = malloc(capacity);
    if (data == NULL)
        goto fail;
    for (;;) {
        if (used == capacity) {
            if (capacity == PROC_TEXT_MAX) {
                char extra;
                ssize_t n = read(fd, &extra, 1);
                if (n < 0 && errno == EINTR)
                    continue;
                if (n < 0)
                    goto fail;
                if (n != 0) {
                    errno = EFBIG;
                    goto fail;
                }
                break; /* Exact-capacity input still needs verified EOF. */
            }
            size_t next = capacity * 2u;
            char *grown = realloc(data, next);
            if (grown == NULL)
                goto fail;
            data = grown;
            capacity = next;
        }
        ssize_t n = read(fd, data + used, capacity - used);
        if (n < 0 && errno == EINTR)
            continue;
        if (n < 0)
            goto fail;
        if (n == 0)
            break;
        if ((size_t)n > capacity - used) {
            errno = EIO;
            goto fail;
        }
        used += (size_t)n;
    }
    if (same_instance(fd, instance) != 0)
        goto fail;
    if (close(fd) != 0) {
        int saved = errno;
        free(data);
        errno = saved;
        return -1;
    }
    *text = data;
    *length = used;
    return 0;
fail: {
        int saved = errno;
        free(data);
        (void)close(fd);
        errno = saved;
        return -1;
    }
}

static int observe(idtype_t kind, id_t id, int extra, pid_t expected)
{
    siginfo_t info = {0};
    int result;
    do {
        result = waitid(kind, id, &info,
                         WEXITED | WNOHANG | WNOWAIT | extra);
    } while (result < 0 && errno == EINTR);
    if (result == 0 && expected > 0 && info.si_pid != 0 &&
        (info.si_pid != expected ||
         (info.si_code != CLD_EXITED && info.si_code != CLD_KILLED &&
          info.si_code != CLD_DUMPED))) {
        errno = EOPNOTSUPP;
        return -1;
    }
    return result;
}

static int stage(staged_t *staged, pid_t pid, const char **step)
{
    checkpoint(step, "pidfd-open");
    int fd = private_fd((int)syscall(SYS_pidfd_open, pid, 0u));
    if (fd < 0)
        return errno == ESRCH ? 0 : -1;
    checkpoint(step, "pidfd-wait");
    if (observe(P_PIDFD, (id_t)fd, 0, pid) != 0) {
        int saved = errno;
        if (saved == ECHILD) {
            checkpoint(step, "pidfd-clone-wait");
            if (observe(P_PIDFD, (id_t)fd, __WALL, pid) == 0)
                saved = EOPNOTSUPP; /* Clone-only child is not ordinary. */
            else
                saved = errno;
        }
        (void)close(fd);
        if (saved == ECHILD)
            return 0; /* Exact relationship disappeared before capture. */
        errno = saved;
        return -1;
    }
    if (staged->count == staged->capacity) {
        checkpoint(step, "cap-vector");
        size_t next = staged->capacity == 0 ? 8u : staged->capacity * 2u;
        if (next < staged->capacity ||
            next > SIZE_MAX / sizeof(*staged->records)) {
            (void)close(fd);
            errno = EOVERFLOW;
            return -1;
        }
        sparc64_process_child_cap_t *grown = realloc(staged->records,
                                                 next * sizeof(*grown));
        if (grown == NULL) {
            int saved = errno;
            (void)close(fd);
            errno = saved;
            return -1;
        }
        staged->records = grown;
        staged->capacity = next;
    }
    staged->records[staged->count++] = (sparc64_process_child_cap_t){
        .pid = pid, .cap_fd = fd, .role = SPARC64_PROCESS_CHILD_EXTERNAL};
    return 0;
}

static int candidate(int root, const sparc64_proc_instance_t *instance,
                      const char *name, pid_t pid, pid_t owner,
                      staged_t *staged, const char **step)
{
    checkpoint(step, "candidate-open");
    int directory = private_fd(openat(root, name,
        O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW));
    if (directory < 0)
        return errno == ENOENT || errno == ESRCH ? 0 : -1;
    char *text = NULL;
    size_t length = 0;
    checkpoint(step, "candidate-instance");
    int result = same_instance(directory, instance);
    if (result == 0) {
        checkpoint(step, "candidate-stat-read");
        result = read_proc(directory, "stat", instance, &text, &length);
    }
    int saved = errno;
    (void)close(directory);
    if (result != 0) {
        free(text);
        errno = saved;
        return saved == ENOENT || saved == ESRCH ? 0 : -1;
    }
    pid_t parent;
    checkpoint(step, "candidate-stat-parse");
    int parsed = sparc64_proc_inventory_parent(text, length, pid, &parent);
    free(text);
    if (parsed != 0) {
        errno = parsed;
        return -1;
    }
    return parent == owner ? stage(staged, pid, step) : 0;
}

static int enumerate(int root, const sparc64_proc_instance_t *instance,
                      pid_t owner, staged_t *staged, const char **step)
{
    unsigned char entries[16384];
    for (;;) {
        checkpoint(step, "directory-read");
        long count = syscall(SYS_getdents64, root, entries, sizeof(entries));
        if (count < 0 && errno == EINTR)
            continue;
        if (count < 0)
            return -1;
        if (count == 0)
            return 0;
        if ((uint64_t)count > sizeof(entries)) {
            errno = EIO;
            return -1;
        }
        size_t cursor = 0;
        while (cursor < (size_t)count) {
            checkpoint(step, "directory-entry");
            if ((size_t)count - cursor < 20u) {
                errno = EIO;
                return -1;
            }
            size_t size = (size_t)load_le(entries + cursor + 16, 2);
            if (size < 20u || size > (size_t)count - cursor) {
                errno = EIO;
                return -1;
            }
            const char *name = (const char *)entries + cursor + 19;
            const char *end = memchr(name, '\0', size - 19u);
            if (end == NULL) {
                errno = EIO;
                return -1;
            }
            uint64_t value = 0;
            bool numeric = end != name;
            for (const char *digit = name; digit != end; ++digit) {
                if (*digit < '0' || *digit > '9') {
                    numeric = false;
                    break;
                }
                unsigned int next = (unsigned int)(*digit - '0');
                if (value > ((uint64_t)INT32_MAX - next) / 10u) {
                    errno = EOVERFLOW;
                    return -1;
                }
                value = value * 10u + next;
            }
            if (numeric && value > 0 && value != (uint64_t)owner &&
                candidate(root, instance, name, (pid_t)value, owner, staged, step) != 0)
                return -1;
            cursor += size;
        }
    }
}
#endif

int sparc64_process_children_discover_initial_diagnostic(
    sparc64_process_children_t *children, const char **step)
{
#if defined(__linux__)
    checkpoint(step, "registry");
    size_t count;
    if (sparc64_process_children_count(children, &count) != 0)
        return -1;
    if (count != 0) {
        errno = EBUSY;
        return -1;
    }
    pid_t owner = getpid();
    int subreaper = 0;
    checkpoint(step, "subreaper");
    if (prctl(PR_GET_CHILD_SUBREAPER, &subreaper, 0, 0, 0) != 0)
        return -1;
    if (subreaper != 0) {
        errno = EOPNOTSUPP;
        return -1;
    }
    checkpoint(step, "empty-wait");
    if (observe(P_ALL, 0, __WALL, 0) != 0)
        return errno == ECHILD ? 0 : -1;
    if (owner == 1) {
        checkpoint(step, "init-profile");
        errno = EOPNOTSUPP;
        return -1;
    }
    checkpoint(step, "proc-open");
    int root = private_fd(open("/proc", O_RDONLY | O_DIRECTORY | O_CLOEXEC));
    if (root < 0)
        return -1;
    sparc64_proc_instance_t instance;
    staged_t staged = {0};
    char *text = NULL;
    size_t length = 0;
    int error = 0;
    checkpoint(step, "proc-instance");
    if (proc_instance(root, &instance) != 0)
        goto fail;
    checkpoint(step, "status-read");
    if (read_proc(root, "self/status", &instance, &text, &length) != 0)
        goto fail;
    checkpoint(step, "namespace-parse");
    error = sparc64_proc_inventory_namespace(text, length, owner);
    free(text);
    text = NULL;
    if (error != 0) {
        errno = error;
        goto fail;
    }
    checkpoint(step, "mountinfo-read");
    if (read_proc(root, "self/mountinfo", &instance, &text, &length) != 0)
        goto fail;
    checkpoint(step, "mountinfo-parse");
    error = sparc64_proc_inventory_mount(text, length, &instance);
    free(text);
    text = NULL;
    if (error != 0) {
        errno = error;
        goto fail;
    }
    if (enumerate(root, &instance, owner, &staged, step) != 0)
        goto fail;
    if (staged.count == 0) {
        checkpoint(step, "empty-recheck");
        if (observe(P_ALL, 0, __WALL, 0) == 0) {
            errno = EOPNOTSUPP; /* Existing inventory lacks ordinary proof. */
            goto fail;
        }
        if (errno != ECHILD)
            goto fail;
    }
    checkpoint(step, "proc-recheck");
    if (same_instance(root, &instance) != 0)
        goto fail;
    checkpoint(step, "registry-import");
    if (sparc64_process_children_import(children, staged.records,
                                    staged.count, owner) != 0)
        goto fail;
    free(staged.records); /* Descriptor ownership transferred atomically. */
    (void)close(root);
    checkpoint(step, "complete");
    return 0;
fail: {
        int saved = errno;
        free(text);
        staged_close(&staged);
        (void)close(root);
        errno = saved;
        return -1;
    }
#else
    (void)children;
    checkpoint(step, "unsupported-host");
    errno = ENOSYS;
    return -1;
#endif
}

int sparc64_process_children_discover_initial(sparc64_process_children_t *children)
{
    return sparc64_process_children_discover_initial_diagnostic(children, NULL);
}
