/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#include "process_children_split.h"


static int pidfd_signal(int cap_fd, int signal_number);

static int pidfd_open_self(void)
{
#if defined(__linux__)
    int fd = (int)syscall(SYS_pidfd_open, getpid(), 0u);
    if (fd < 0)
        return -1;
    int flags = fcntl(fd, F_GETFD);
    if (flags < 0) {
        int saved = errno;
        (void)close(fd);
        errno = saved;
        return -1;
    }
    if (fd >= 3) {
        if (fcntl(fd, F_SETFD, flags | FD_CLOEXEC) != 0) {
            int saved = errno;
            (void)close(fd);
            errno = saved;
            return -1;
        }
        return fd;
    }
    int moved = fcntl(fd, F_DUPFD_CLOEXEC, 3);
    if (moved < 0) {
        int saved = errno;
        (void)close(fd);
        errno = saved;
        return -1;
    }
    if (close(fd) != 0) {
        int saved = errno;
        (void)close(moved);
        errno = saved;
        return -1;
    }
    return moved;
#else
    errno = ENOSYS;
    return -1;
#endif
}

void sparc64_process_parent_init(sparc64_process_parent_t *parent)
{
    if (parent != NULL)
        *parent = (sparc64_process_parent_t){.pid = 0, .cap_fd = -1};
}

void sparc64_process_parent_close(sparc64_process_parent_t *parent)
{
    if (parent == NULL) return;
    if (parent->cap_fd >= 3) (void)close(parent->cap_fd);
    sparc64_process_parent_init(parent);
}

static int parent_private_fd(int *fd)
{
    if (*fd < 3) {
        int high = fcntl(*fd, F_DUPFD_CLOEXEC, 3);
        int saved = errno;
        (void)close(*fd);
        if (high < 0) { *fd = -1; errno = saved; return -1; }
        *fd = high;
    }
    int flags = fcntl(*fd, F_GETFD);
    if (flags < 0 || fcntl(*fd, F_SETFD, flags | FD_CLOEXEC) != 0)
        return -1;
    return 0;
}

int sparc64_process_parent_bind_current(sparc64_process_parent_t *parent)
{
    if (parent == NULL || parent->cap_fd != -1) { errno = EINVAL; return -1; }
    pid_t candidate = getppid();
    if (candidate <= 0) return 0;
    int cap = -1;
#if defined(__linux__)
    cap = (int)syscall(SYS_pidfd_open, candidate, 0u);
#else
    errno = ENOSYS;
    return -1;
#endif
    if (cap < 0) return errno == ESRCH ? 0 : -1;
    if (parent_private_fd(&cap) != 0) {
        int saved = errno;
        if (cap >= 3) (void)close(cap);
        errno = saved;
        return -1;
    }
    int changed = getppid() != candidate;
    if (changed || pidfd_signal(cap, 0) != 0) {
        int saved = changed ? ESRCH : errno;
        (void)close(cap);
        if (saved == ESRCH) return 0;
        errno = saved;
        return -1;
    }
    *parent = (sparc64_process_parent_t){.pid = candidate, .cap_fd = cap};
    return 0;
}

pid_t sparc64_process_parent_fork(sparc64_process_parent_t *parent,
                              pid_t (*fork_call)(void))
{
    if (parent == NULL || fork_call == NULL) { errno = EINVAL; return -1; }
    pid_t child = fork_call();
    if (child != 0) return child; /* Parent success and failure retain cap. */
    sparc64_process_parent_close(parent);
    if (sparc64_process_parent_bind_current(parent) != 0)
        _exit(125); /* No child guest work with an unbound parent cap. */
    return 0;
}

int sparc64_process_parent_adopt(sparc64_process_parent_t *parent, int owned_fd,
                            pid_t expected_pid)
{
    if (parent == NULL || parent->cap_fd != -1 || owned_fd < 3 ||
        expected_pid <= 0) { errno = EINVAL; return -1; }
    if (parent_private_fd(&owned_fd) != 0) {
        int saved = errno;
        (void)close(owned_fd);
        errno = saved;
        return -1;
    }
    /* The transported descriptor is a private, live handoff witness, not
     * proof that it targets expected_pid. A different live pidfd can pass
     * signal 0. Consume it and acquire the current parent afresh, so a
     * substituted self/child capability never gains parent authority. */
    int probe = pidfd_signal(owned_fd, 0);
    int probe_error = errno;
    int changed = getppid() != expected_pid;
    (void)close(owned_fd);
    if (changed || (probe != 0 && probe_error == ESRCH)) return 0;
    if (probe != 0) { errno = probe_error; return -1; }
    if (sparc64_process_parent_bind_current(parent) != 0) return -1;
    /* A reparent between the first comparison and acquisition must not
     * replace the recorded self-exec relationship with the new parent. */
    if (parent->pid != expected_pid)
        sparc64_process_parent_close(parent);
    return 0;
}

int sparc64_process_parent_signal(const sparc64_process_parent_t *parent, pid_t pid,
                              int signum)
{
    if (parent == NULL || parent->cap_fd < 3 || parent->pid != pid ||
        getppid() != pid) { errno = ESRCH; return -1; }
    if (signum != 0 && signum != SIGUSR1 && signum != SIGUSR2 &&
        signum != SIGTERM) {
        errno = EOPNOTSUPP; return -1;
    }
    return pidfd_signal(parent->cap_fd, signum);
}

static int pidfd_signal(int cap_fd, int signal_number)
{
#if defined(__linux__)
    return (int)syscall(SYS_pidfd_send_signal, cap_fd, signal_number,
                        NULL, 0u);
#else
    (void)cap_fd;
    (void)signal_number;
    errno = ENOSYS;
    return -1;
#endif
}

static void put32(unsigned char bytes[4], uint32_t value)
{
    for (unsigned int i = 0; i < 4; ++i)
        bytes[i] = (unsigned char)(value >> (8u * i));
}

static uint32_t get32(const unsigned char bytes[4])
{
    uint32_t value = 0;
    for (unsigned int i = 0; i < 4; ++i)
        value |= (uint32_t)bytes[i] << (8u * i);
    return value;
}

static int read_exact(int fd, unsigned char *bytes, size_t length)
{
    size_t done = 0;
    while (done < length) {
        ssize_t amount = read(fd, bytes + done, length - done);
        if (amount < 0 && errno == EINTR)
            continue;
        if (amount <= 0) {
            if (amount == 0)
                errno = EPIPE;
            return -1;
        }
        done += (size_t)amount;
    }
    return 0;
}

static int write_exact(int fd, const unsigned char *bytes, size_t length)
{
    size_t done = 0;
    while (done < length) {
        ssize_t amount = send(fd, bytes + done, length - done, MSG_NOSIGNAL);
        if (amount < 0 && errno == EINTR)
            continue;
        if (amount <= 0) {
            if (amount == 0)
                errno = EPIPE;
            return -1;
        }
        done += (size_t)amount;
    }
    return 0;
}

static int private_cloexec_fd(int *owned_fd)
{
    if (owned_fd == NULL) {
        errno = EINVAL;
        return -1;
    }
    int fd = *owned_fd;
    if (fd < 0) {
        errno = EBADF;
        return -1;
    }
    int flags = fcntl(fd, F_GETFD);
    if (flags < 0)
        return -1;
    if (fd >= 3) {
        if (fcntl(fd, F_SETFD, flags | FD_CLOEXEC) != 0)
            return -1;
        return 0;
    }
    int moved = fcntl(fd, F_DUPFD_CLOEXEC, 3);
    if (moved < 0)
        return -1;
    /* A failed close may already have consumed the descriptor.  Clear the
     * owner slot before attempting it so callers cannot close a reused FD. */
    *owned_fd = -1;
    if (close(fd) != 0) {
        int saved = errno;
        (void)close(moved);
        errno = saved;
        return -1;
    }
    *owned_fd = moved;
    return 0;
}

void child_free(sparc64_process_child_t *child)
{
    if (child == NULL)
        return;
    if (child->cap_fd >= 0)
        (void)close(child->cap_fd);
    free(child);
}

static int compare_pid(const void *left, const void *right)
{
    pid_t a = *(const pid_t *)left;
    pid_t b = *(const pid_t *)right;
    return (a > b) - (a < b);
}

void sparc64_process_children_init(sparc64_process_children_t *children)
{
    if (children != NULL)
        *children = (sparc64_process_children_t){.owner_pid = getpid()};
}

int sparc64_process_children_count(const sparc64_process_children_t *children,
                              size_t *count)
{
    if (children == NULL || count == NULL || children->owner_pid != getpid()) {
        errno = EINVAL;
        return -1;
    }
    size_t amount = 0;
    for (const sparc64_process_child_t *child = children->head;
         child != NULL; child = child->next) {
        if (amount == SIZE_MAX) {
            errno = EOVERFLOW;
            return -1;
        }
        ++amount;
    }
    *count = amount;
    return 0;
}

int sparc64_process_children_export(const sparc64_process_children_t *children,
                               sparc64_process_child_cap_t *records,
                               size_t capacity, size_t *count)
{
    if (count == NULL || (records == NULL && capacity != 0)) {
        errno = EINVAL;
        return -1;
    }
    size_t required = 0;
    if (sparc64_process_children_count(children, &required) != 0)
        return -1;
    *count = required;
    if (capacity < required) {
        errno = ERANGE;
        return -1;
    }
    size_t index = 0;
    for (const sparc64_process_child_t *child = children->head;
         child != NULL; child = child->next)
        records[index++] = (sparc64_process_child_cap_t){
            .pid = child->pid, .cap_fd = child->cap_fd, .role = child->role};
    return 0;
}

int sparc64_process_children_import(sparc64_process_children_t *children,
                               const sparc64_process_child_cap_t *records,
                               size_t count,
                               pid_t original_owner)
{
    if (children == NULL || children->owner_pid != getpid() ||
        original_owner != getpid()) {
        errno = EINVAL;
        return -1;
    }
    if (children->head != NULL) {
        errno = EBUSY;
        return -1;
    }
    if ((records == NULL && count != 0)) {
        errno = EINVAL;
        return -1;
    }
    if (count > SIZE_MAX / sizeof(*records)) {
        errno = EOVERFLOW;
        return -1;
    }
    if (count == 0)
        return 0;

    pid_t *sorted = malloc(count * sizeof(*sorted));
    int *old_flags = malloc(count * sizeof(*old_flags));
    sparc64_process_child_t **staged = calloc(count, sizeof(*staged));
    if (sorted == NULL || old_flags == NULL || staged == NULL) {
        free(sorted);
        free(old_flags);
        free(staged);
        errno = ENOMEM;
        return -1;
    }
    for (size_t i = 0; i < count; ++i) {
        if (records[i].pid <= 0 || records[i].cap_fd < 3 ||
            (records[i].role != SPARC64_PROCESS_CHILD_FAMILY &&
             records[i].role != SPARC64_PROCESS_CHILD_EXTERNAL)) {
            errno = EINVAL;
            goto fail;
        }
        for (size_t j = 0; j < i; ++j)
            if (records[j].pid == records[i].pid ||
                records[j].cap_fd == records[i].cap_fd) {
                errno = EINVAL;
                goto fail;
            }
        sorted[i] = records[i].pid;
        old_flags[i] = fcntl(records[i].cap_fd, F_GETFD);
        if (old_flags[i] < 0)
            goto fail;
        staged[i] = calloc(1, sizeof(*staged[i]));
        if (staged[i] == NULL) {
            errno = ENOMEM;
            goto fail;
        }
    }
    qsort(sorted, count, sizeof(*sorted), compare_pid);
    for (size_t i = 1; i < count; ++i) {
        if (sorted[i - 1] == sorted[i]) {
            errno = EINVAL;
            goto fail;
        }
    }
    size_t changed = 0;
    for (size_t i = 0; i < count; ++i) {
        if (fcntl(records[i].cap_fd, F_SETFD,
                  old_flags[i] | FD_CLOEXEC) != 0) {
            int saved = errno;
            bool rollback_failed = false;
            while (changed != 0) {
                --changed;
                if (fcntl(records[changed].cap_fd, F_SETFD,
                          old_flags[changed]) != 0)
                    rollback_failed = true;
            }
            errno = rollback_failed ? EIO : saved;
            goto fail;
        }
        ++changed;
    }
    for (size_t i = 0; i < count; ++i) {
        staged[i]->pid = records[i].pid;
        staged[i]->cap_fd = records[i].cap_fd;
        staged[i]->role = records[i].role;
        staged[i]->next = i + 1 < count ? staged[i + 1] : NULL;
    }
    children->head = staged[0];
    free(sorted);
    free(staged);
    free(old_flags);
    return 0;
fail: {
        int saved = errno;
        free(sorted);
        free(old_flags);
        if (staged != NULL)
            for (size_t i = 0; i < count; ++i)
                free(staged[i]);
        free(staged);
        errno = saved;
        return -1;
    }
}

int sparc64_process_children_drop_external(sparc64_process_children_t *children)
{
    if (children == NULL || children->owner_pid != getpid()) {
        errno = EINVAL;
        return -1;
    }
    sparc64_process_child_t **link = &children->head;
    while (*link != NULL) {
        sparc64_process_child_t *child = *link;
        if (child->role == SPARC64_PROCESS_CHILD_EXTERNAL) {
            *link = child->next;
            child_free(child);
        } else {
            link = &child->next;
        }
    }
    return 0;
}

int sparc64_process_child_handoff_pair(int endpoints[2])
{
    if (endpoints == NULL) {
        errno = EINVAL;
        return -1;
    }
    endpoints[0] = endpoints[1] = -1;
    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, endpoints) != 0)
        return -1;
    for (size_t i = 0; i < 2; ++i) {
        if (private_cloexec_fd(&endpoints[i]) != 0) {
            int saved = errno;
            if (endpoints[0] >= 0)
                (void)close(endpoints[0]);
            if (endpoints[1] >= 0)
                (void)close(endpoints[1]);
            endpoints[0] = endpoints[1] = -1;
            errno = saved;
            return -1;
        }
    }
    return 0;
}

int sparc64_process_child_handoff_send(int endpoint)
{
    if (endpoint < 0) {
        errno = EINVAL;
        return -1;
    }
    int cap_fd = pidfd_open_self();
    if (cap_fd < 0)
        return -1;
    if (private_cloexec_fd(&cap_fd) != 0) {
        int saved = errno;
        if (cap_fd >= 0)
            (void)close(cap_fd);
        errno = saved;
        return -1;
    }
    unsigned char frame[8];
    put32(frame, 1u);
    put32(frame + 4, (uint32_t)getpid());
    struct iovec vector = {.iov_base = frame, .iov_len = sizeof(frame)};
    union {
        struct cmsghdr alignment;
        unsigned char bytes[CMSG_SPACE(sizeof(int))];
    } control = {0};
    struct msghdr message = {0};
    message.msg_iov = &vector;
    message.msg_iovlen = 1;
    message.msg_control = control.bytes;
    message.msg_controllen = sizeof(control.bytes);
    struct cmsghdr *header = CMSG_FIRSTHDR(&message);
    header->cmsg_level = SOL_SOCKET;
    header->cmsg_type = SCM_RIGHTS;
    header->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(header), &cap_fd, sizeof(cap_fd));
    ssize_t sent;
    do {
        sent = sendmsg(endpoint, &message, MSG_NOSIGNAL);
    } while (sent < 0 && errno == EINTR);
    int saved = errno;
    close(cap_fd);
    if (sent <= 0) {
        if (sent == 0)
            saved = EPIPE;
        errno = saved;
        return -1;
    }
    if ((size_t)sent < sizeof(frame) &&
        write_exact(endpoint, frame + sent, sizeof(frame) - (size_t)sent) != 0)
        return -1;
    unsigned char ack;
    if (read_exact(endpoint, &ack, 1) != 0)
        return -1;
    if (ack != 1) {
        errno = EPROTO;
        return -1;
    }
    return 0;
}

int sparc64_process_child_handoff_receive(int endpoint, pid_t expected_pid,
                                     int *cap_fd)
{
    if (endpoint < 0 || expected_pid <= 0 || cap_fd == NULL) {
        errno = EINVAL;
        return -1;
    }
    *cap_fd = -1;
    unsigned char frame[8] = {0};
    union {
        struct cmsghdr alignment;
        unsigned char bytes[CMSG_SPACE(sizeof(int) * 2)];
    } control = {0};
    struct iovec vector = {.iov_base = frame, .iov_len = sizeof(frame)};
    struct msghdr message = {0};
    message.msg_iov = &vector;
    message.msg_iovlen = 1;
    message.msg_control = control.bytes;
    message.msg_controllen = sizeof(control.bytes);
    ssize_t received;
    do {
        received = recvmsg(endpoint, &message, MSG_CMSG_CLOEXEC);
    } while (received < 0 && errno == EINTR);
    if (received <= 0) {
        if (received == 0)
            errno = EPIPE;
        return -1;
    }
    int received_fd = -1;
    size_t descriptors = 0;
    bool malformed_control = false;
    for (struct cmsghdr *header = CMSG_FIRSTHDR(&message); header != NULL;
         header = sparc64_native_cmsg_next(&message, header)) {
        if (header->cmsg_level != SOL_SOCKET || header->cmsg_type != SCM_RIGHTS ||
            header->cmsg_len < CMSG_LEN(sizeof(int))) {
            malformed_control = true;
            continue;
        }
        size_t bytes = header->cmsg_len - CMSG_LEN(0);
        if (bytes % sizeof(int) != 0) {
            malformed_control = true;
            continue;
        }
        size_t amount = bytes / sizeof(int);
        const int *fds = (const int *)CMSG_DATA(header);
        for (size_t i = 0; i < amount; ++i) {
            if (descriptors == 0)
                received_fd = fds[i];
            else
                close(fds[i]);
            ++descriptors;
        }
    }
    if ((message.msg_flags & (MSG_CTRUNC | MSG_TRUNC)) != 0 ||
        malformed_control || descriptors != 1) {
        if (received_fd >= 0)
            close(received_fd);
        errno = EPROTO;
        return -1;
    }
    if ((size_t)received < sizeof(frame) &&
        read_exact(endpoint, frame + received, sizeof(frame) - (size_t)received) != 0) {
        int saved = errno;
        close(received_fd);
        errno = saved;
        return -1;
    }
    if (get32(frame) != 1u || get32(frame + 4) != (uint32_t)expected_pid) {
        close(received_fd);
        errno = EPROTO;
        return -1;
    }
    if (private_cloexec_fd(&received_fd) != 0) {
        int saved = errno;
        if (received_fd >= 0)
            (void)close(received_fd);
        errno = saved;
        return -1;
    }
    *cap_fd = received_fd;
    return 0;
}

int sparc64_process_child_handoff_ack(int endpoint, bool accepted)
{
    if (endpoint < 0) {
        errno = EINVAL;
        return -1;
    }
    unsigned char ack = accepted ? 1u : 0u;
    return write_exact(endpoint, &ack, 1);
}

sparc64_process_child_t *sparc64_process_child_reserve(void)
{
    sparc64_process_child_t *child = calloc(1, sizeof(*child));
    if (child != NULL)
        child->cap_fd = -1;
    return child;
}

void sparc64_process_child_discard(sparc64_process_child_t *child)
{
    child_free(child);
}

int sparc64_process_child_publish(sparc64_process_children_t *children,
                             sparc64_process_child_t *child, pid_t pid, int cap_fd)
{
    if (children == NULL || child == NULL || pid <= 0 || cap_fd < 3 ||
        children->owner_pid != getpid() || child->pid != 0) {
        errno = EINVAL;
        return -1;
    }
    int flags = fcntl(cap_fd, F_GETFD);
    if (flags < 0 || (flags & FD_CLOEXEC) == 0) {
        if (flags >= 0)
            errno = EINVAL;
        return -1;
    }
    for (sparc64_process_child_t *existing = children->head; existing != NULL;
         existing = existing->next)
        if (existing->cap_fd == cap_fd) {
            errno = EINVAL;
            return -1;
        }
    /* A freshly returned native child PID cannot still name an older child.
     * Explicit-ignore/NOCLDWAIT may have auto-reaped that older child after
     * our last WNOWAIT scan, so retire its stale record before publication. */
    sparc64_process_child_t **position = &children->head;
    while (*position != NULL) {
        if ((*position)->pid != pid) {
            position = &(*position)->next;
            continue;
        }
        sparc64_process_child_t *stale = *position;
        *position = stale->next;
        child_free(stale);
        break;
    }
    child->pid = pid;
    child->cap_fd = cap_fd;
    child->role = SPARC64_PROCESS_CHILD_FAMILY;
    child->next = children->head;
    children->head = child;
    return 0;
}

int sparc64_process_children_signal(sparc64_process_children_t *children, pid_t pid,
                               int signal_number)
{
    if (children == NULL || children->owner_pid != getpid() || pid <= 0 ||
        signal_number < 0 || signal_number > 64) {
        errno = EINVAL;
        return -1;
    }
    for (sparc64_process_child_t *child = children->head; child != NULL;
         child = child->next) {
        if (child->pid == pid) {
            if (signal_number != 0 && signal_number != SIGKILL &&
                signal_number != SIGTERM) {
                errno = EOPNOTSUPP;
                return -1;
            }
            return pidfd_signal(child->cap_fd, signal_number);
        }
    }
    errno = ESRCH;
    return -1;
}

int sparc64_process_child_cap_signal(int cap_fd, int signal_number)
{
    if (cap_fd < 3 || signal_number < 0 || signal_number > 64) {
        errno = EINVAL;
        return -1;
    }
    if (signal_number != 0 && signal_number != SIGKILL &&
        signal_number != SIGTERM) {
        errno = EOPNOTSUPP;
        return -1;
    }
    return pidfd_signal(cap_fd, signal_number);
}

int sparc64_process_child_cap_exited(int cap_fd, pid_t expected_pid)
{
    if (cap_fd < 3 || expected_pid <= 0) {
        errno = EINVAL;
        return -1;
    }
    siginfo_t info = {0};
    int result;
    do {
        result = waitid(P_PIDFD, (id_t)cap_fd, &info,
                        WEXITED | WNOHANG | WNOWAIT);
    } while (result != 0 && errno == EINTR);
    if (result != 0) {
        if (errno == ECHILD)
            return 1; /* Already auto-reaped under SIG_IGN/SA_NOCLDWAIT. */
        return -1;
    }
    if (info.si_pid == 0)
        return 0;
    if (info.si_pid != expected_pid) {
        errno = EIO;
        return -1;
    }
    return 1;
}

int sparc64_process_children_prune_autoreaped(sparc64_process_children_t *children)
{
    if (children == NULL || children->owner_pid != getpid()) {
        errno = EINVAL;
        return -1;
    }
    sparc64_process_child_t **position = &children->head;
    while (*position != NULL) {
        siginfo_t info = {0};
        if (waitid(P_PIDFD, (id_t)(*position)->cap_fd, &info,
                   WEXITED | WNOHANG | WNOWAIT) == 0) {
            position = &(*position)->next;
            continue;
        }
        if (errno != ECHILD)
            return -1;
        sparc64_process_child_t *stale = *position;
        *position = stale->next;
        child_free(stale);
    }
    return 0;
}
