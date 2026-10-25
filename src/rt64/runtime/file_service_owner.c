/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#define _GNU_SOURCE 1
#include "runtime/file_service_owner.h"
#include "runtime/native_cmsg.h"
#include "runtime/family.h"

#include "runtime/process_children.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef SYS_pidfd_open
#define SYS_pidfd_open 434
#endif
#ifndef SYS_close_range
#define SYS_close_range 436
#endif
#ifndef __WCLONE
#define __WCLONE 0x80000000
#endif

enum { OWNER_WAIT_MS = 5000 };

static int64_t monotonic_ms(void)
{
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
        return -1;
    if (now.tv_sec < 0 || now.tv_sec > (INT64_MAX - 1000) / 1000) {
        errno = EOVERFLOW;
        return -1;
    }
    return (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000;
}

static int64_t deadline_ms(void)
{
    int64_t now = monotonic_ms();
    if (now < 0 || now > INT64_MAX - OWNER_WAIT_MS) {
        if (now >= 0) errno = EOVERFLOW;
        return -1;
    }
    return now + OWNER_WAIT_MS;
}

static int private_fd(int *fd)
{
    if (*fd < 3) {
        int raised = fcntl(*fd, F_DUPFD_CLOEXEC, 3);
        if (raised < 0) return -1;
        (void)close(*fd);
        *fd = raised;
    }
    int flags = fcntl(*fd, F_GETFD);
    if (flags < 0 || fcntl(*fd, F_SETFD, flags | FD_CLOEXEC) != 0)
        return -1;
    return 0;
}

/* The server never inherits family control, guest descriptors, or parent
 * pipe ends. A numeric RLIMIT_NOFILE scan is unsound when an inherited FD
 * exceeds a subsequently lowered hard limit, so unsupported close_range
 * fails service startup before it can accept requests. */
static int close_unrelated(int a, int b, int c)
{
    int keep[3] = {a, b, c};
    for (int i = 0; i < 3; ++i)
        for (int j = i + 1; j < 3; ++j)
            if (keep[j] < keep[i]) {
                int swap = keep[i]; keep[i] = keep[j]; keep[j] = swap;
            }
    if (keep[0] < 3 || keep[0] == keep[1] || keep[1] == keep[2]) {
        errno = EINVAL;
        return -1;
    }
    unsigned int start = 0;
    for (int i = 0; i < 3; ++i) {
        unsigned int end = (unsigned int)keep[i] - 1u;
        if (start <= end && syscall(SYS_close_range, start, end, 0u) != 0)
            return -1;
        start = (unsigned int)keep[i] + 1u;
    }
    return syscall(SYS_close_range, start, UINT_MAX, 0u) == 0 ? 0 : -1;
}

static int send_self_pidfd(int socket_fd)
{
    int cap = (int)syscall(SYS_pidfd_open, getpid(), 0u);
    if (cap < 0) return -1;
    unsigned char frame[8] = {'P'};
    struct iovec iov = {.iov_base = frame, .iov_len = sizeof(frame)};
    union {
        struct cmsghdr align;
        unsigned char bytes[CMSG_SPACE(sizeof(int))];
    } control = {0};
    struct msghdr message = {.msg_iov = &iov, .msg_iovlen = 1,
                             .msg_control = control.bytes,
                             .msg_controllen = sizeof(control.bytes)};
    struct cmsghdr *item = CMSG_FIRSTHDR(&message);
    item->cmsg_level = SOL_SOCKET;
    item->cmsg_type = SCM_RIGHTS;
    item->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(item), &cap, sizeof(cap));
    ssize_t sent = sendmsg(socket_fd, &message, MSG_NOSIGNAL);
    int saved = errno;
    (void)close(cap);
    errno = saved;
    return sent == (ssize_t)sizeof(frame) ? 0 : -1;
}

static int recv_self_pidfd(int socket_fd)
{
    unsigned char frame[8] = {0};
    struct iovec iov = {.iov_base = frame, .iov_len = sizeof(frame)};
    union {
        struct cmsghdr align;
        unsigned char bytes[CMSG_SPACE(sizeof(int))];
    } control = {0};
    struct msghdr message = {.msg_iov = &iov, .msg_iovlen = 1,
                             .msg_control = control.bytes,
                             .msg_controllen = sizeof(control.bytes)};
    ssize_t received = recvmsg(socket_fd, &message,
                               MSG_CMSG_CLOEXEC | MSG_DONTWAIT);
    struct cmsghdr *item = CMSG_FIRSTHDR(&message);
    int cap = -1;
    size_t delivered = 0;
    if (item && item->cmsg_level == SOL_SOCKET &&
        item->cmsg_type == SCM_RIGHTS &&
        item->cmsg_len >= CMSG_LEN(sizeof(int))) {
        size_t bounded = item->cmsg_len < message.msg_controllen ?
            item->cmsg_len : message.msg_controllen;
        if (bounded >= CMSG_LEN(0)) {
            delivered = (bounded - CMSG_LEN(0)) / sizeof(int);
            if (delivered > 0)
                memcpy(&cap, CMSG_DATA(item), sizeof(cap));
        }
    }
    if (received != (ssize_t)sizeof(frame) || frame[0] != 'P' ||
        (message.msg_flags & (MSG_CTRUNC | MSG_TRUNC)) != 0 ||
        !item || item->cmsg_len != CMSG_LEN(sizeof(int)) ||
        delivered != 1 ||
        sparc64_native_cmsg_next(&message, item) != NULL || cap < 0) {
        for (size_t i = 0; i < delivered; ++i) {
            int received_fd;
            memcpy(&received_fd, CMSG_DATA(item) + i * sizeof(int),
                   sizeof(received_fd));
            if (received_fd >= 0) (void)close(received_fd);
        }
        errno = EPROTO;
        return -1;
    }
    if (private_fd(&cap) < 0) {
        (void)close(cap);
        return -1;
    }
    return cap;
}

static int wait_fd(int fd, int64_t deadline)
{
    for (;;) {
        int64_t now = monotonic_ms();
        if (now < 0) return -1;
        if (now >= deadline) { errno = ETIMEDOUT; return -1; }
        struct pollfd observed = {.fd = fd, .events = POLLIN | POLLHUP};
        int result = poll(&observed, 1, (int)(deadline - now));
        if (result < 0 && errno == EINTR) continue;
        if (result < 0) return -1;
        if (result > 0) {
            if (observed.revents & (POLLIN | POLLHUP)) return 0;
            errno = EIO;
            return -1;
        }
    }
}

/* 1: reaped successfully; 0: still owned at deadline; -1: reaped with a
 * failure or native wait ownership was lost. Only the still-owned 0 case
 * enters exact-pidfd abort; no numeric PID is ever signaled. */
static int wait_bootstrap(pid_t child, int64_t deadline)
{
    for (;;) {
        int status = 0;
        pid_t seen = waitpid(child, &status, __WCLONE | WNOHANG);
        if (seen == child)
            return WIFEXITED(status) && WEXITSTATUS(status) == 0 ? 1 : -1;
        if (seen < 0 && errno != EINTR) return -1;
        int64_t now = monotonic_ms();
        if (now < 0) return 0; /* Still unreaped; exact-cap abort follows. */
        if (now >= deadline) { errno = ETIMEDOUT; return 0; }
        struct timespec pause = {.tv_nsec = 1000000};
        (void)nanosleep(&pause, NULL);
    }
}

static void run_service(sparc64_file_caps_client_t *client,
                        sparc64_file_caps_server_t *server,
                        int handoff_parent, int handoff_child,
                        int observer_parent, int observer_child,
                        sparc64_family_storage_authority_t authority)
{
    sparc64_file_caps_client_close(client);
    (void)close(handoff_parent);
    (void)close(observer_parent);
    if (send_self_pidfd(handoff_child) != 0)
        _exit(125);
    (void)close(handoff_child);
    if (close_unrelated(server->request_fd, server->lifetime_fd,
                        observer_child) != 0)
        _exit(125);
    const sparc64_file_caps_retained_cleanup_t cleanup = {
        .prepare_context = sparc64_family_cleanup_service_prepare_context,
        .context = &authority,
        .terminal = sparc64_family_cleanup_service_retained,
        .release = sparc64_family_cleanup_service_release
    };
    int result = sparc64_file_caps_serve_with_retained_cleanup(server, &cleanup);
    if (result == 0)
        (void)send(observer_child, "S", 1, MSG_NOSIGNAL);
    (void)close(observer_child);
#ifdef SPARC64_FILE_SERVICE_OWNER_TEST_DELAY_EXIT
    /* Test the gap between protocol EOF and actual process death. */
    struct timespec delay = {.tv_nsec = 200000000};
    while (nanosleep(&delay, &delay) != 0)
        if (errno != EINTR)
            _exit(125);
#endif
    _exit(result == 0 ? 0 : 125);
}

static int observer_eof(int fd)
{
    char byte;
    ssize_t count = recv(fd, &byte, 1, MSG_DONTWAIT);
    if (count == 0) return 1;
    if (count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return 0;
    errno = EIO;
    return -1;
}

static int await_observer_close(int fd, int64_t deadline)
{
    for (int i = 0; i < 2; ++i) {
        if (wait_fd(fd, deadline) != 0) return -1;
        char byte;
        ssize_t count = recv(fd, &byte, 1, MSG_DONTWAIT);
        if (count == 0) return 0;
        if (count != 1 || byte != 'S') {
            errno = EPROTO;
            return -1;
        }
    }
    errno = EPROTO;
    return -1;
}

int sparc64_file_service_owner_check(const sparc64_file_service_owner_t *owner)
{
    if (!owner || owner->pidfd < 3 || owner->observer_fd < 3) {
        errno = EINVAL;
        return -1;
    }
    int state = observer_eof(owner->observer_fd);
    if (state == 0) return 0;
    errno = EIO;
    return -1;
}

int sparc64_file_service_owner_adopt_classified(sparc64_file_service_owner_t *owner,
                                int owned_pidfd, int owned_observer_fd)
{
    if (!owner || owner->pidfd != -1 || owner->observer_fd != -1 ||
        owned_pidfd < 3 || owned_observer_fd < 3 ||
        owned_pidfd == owned_observer_fd) {
        errno = EINVAL;
        goto failed;
    }
    if (private_fd(&owned_pidfd) < 0 ||
        private_fd(&owned_observer_fd) < 0)
        goto failed;
    *owner = (sparc64_file_service_owner_t){owned_pidfd, owned_observer_fd};
    if (sparc64_file_service_owner_check(owner) == 0)
        return 0;
    return 1; /* Retain final-death authority even when the peer is dead. */
failed: {
        int saved = errno;
        if (owned_pidfd >= 3) (void)close(owned_pidfd);
        if (owned_observer_fd >= 3 && owned_observer_fd != owned_pidfd)
            (void)close(owned_observer_fd);
        errno = saved;
        return -1;
    }
}

int sparc64_file_service_owner_adopt(sparc64_file_service_owner_t *owner,
                                int owned_pidfd, int owned_observer_fd)
{
    int result = sparc64_file_service_owner_adopt_classified(owner, owned_pidfd,
                                                        owned_observer_fd);
    if (result <= 0)
        return result;
    int saved = errno;
    sparc64_file_service_owner_close_local(owner);
    errno = saved;
    return -1;
}

void sparc64_file_service_owner_close_local(sparc64_file_service_owner_t *owner)
{
    if (!owner) return;
    if (owner->pidfd >= 3) (void)close(owner->pidfd);
    if (owner->observer_fd >= 3) (void)close(owner->observer_fd);
    *owner = (sparc64_file_service_owner_t)SPARC64_FILE_SERVICE_OWNER_INITIALIZER;
}

/* Linux pidfs distinguishes an exited zombie (POLLIN) from a fully detached
 * task (POLLHUP). An orphan's observer can close before either. Ask only for
 * HUP so an exited-but-unreaped task cannot spin the poll loop on POLLIN.
 * This is standard pidfd poll, including when hosted by hyper-linux. */
static int await_service_reaped(int pidfd, int64_t deadline)
{
    for (;;) {
        int64_t now = monotonic_ms();
        if (now < 0) return -1;
        if (now >= deadline) { errno = ETIMEDOUT; return -1; }
        struct pollfd observed = {.fd = pidfd, .events = 0};
        int result = poll(&observed, 1, (int)(deadline - now));
        if (result < 0 && errno == EINTR) continue;
        if (result < 0) return -1;
        if (result > 0) {
            if ((observed.revents & POLLHUP) != 0 &&
                (observed.revents & (POLLERR | POLLNVAL)) == 0)
                return 0;
            errno = EIO;
            return -1;
        }
    }
}

int sparc64_file_service_owner_retire_last(sparc64_file_service_owner_t *owner)
{
    if (!owner || owner->pidfd < 3 || owner->observer_fd < 3) {
        errno = EINVAL;
        return -1;
    }
    int64_t deadline = deadline_ms();
    if (deadline < 0) return -1;
    char terminal = 0;
    int clean = wait_fd(owner->observer_fd, deadline) == 0 &&
                recv(owner->observer_fd, &terminal, 1, MSG_DONTWAIT) == 1 &&
                terminal == 'S' &&
                wait_fd(owner->observer_fd, deadline) == 0 &&
                observer_eof(owner->observer_fd) == 1;
    if (!clean) {
        if (sparc64_process_child_cap_signal(owner->pidfd, SIGKILL) != 0 &&
            errno != ESRCH)
            return -1;
        deadline = deadline_ms();
        if (deadline < 0 || wait_fd(owner->observer_fd, deadline) != 0 ||
            observer_eof(owner->observer_fd) != 1)
            return -1;
    }
    if (await_service_reaped(owner->pidfd, deadline) != 0)
        return -1;
    sparc64_file_service_owner_close_local(owner);
    if (!clean) { errno = EIO; return -1; }
    return 0;
}

int sparc64_file_service_owner_start_with_authority(
    sparc64_file_service_owner_t *owner, sparc64_file_caps_client_t *client,
    sparc64_family_storage_authority_t authority)
{
    if (!owner || owner->pidfd != -1 || owner->observer_fd != -1 ||
        !client || client->request_fd != -1 || client->lifetime_fd != -1 ||
        (authority != SPARC64_FAMILY_AUTHORITY_AUTO &&
         authority != SPARC64_FAMILY_AUTHORITY_HYPER_LINUX_APFS_ACL_V1)) {
        errno = EINVAL;
        return -1;
    }
    /* An inherited native subreaper would adopt the orphan back into this
     * process and can turn its post-exec exit into SIGCHLD. Linux reports
     * the state here; HL does not implement Linux subreapers and answers
     * EINVAL. Fail closed if a real subreaper is present. */
    int subreaper = 0;
    if (prctl(PR_GET_CHILD_SUBREAPER, &subreaper, 0, 0, 0) == 0) {
        if (subreaper != 0) { errno = EOPNOTSUPP; return -1; }
    } else if (errno != EINVAL && errno != ENOSYS) {
        return -1;
    }
    sparc64_file_caps_client_t created = SPARC64_FILE_CAPS_CLIENT_INITIALIZER;
    sparc64_file_caps_server_t server = SPARC64_FILE_CAPS_SERVER_INITIALIZER;
    int handoff[2] = {-1, -1}, observer[2] = {-1, -1};
    if (sparc64_file_caps_pair_create(&created, &server) != 0)
        return -1;
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, handoff) != 0 ||
        socketpair(AF_UNIX, SOCK_STREAM, 0, observer) != 0)
        goto failed;
    if (private_fd(&handoff[0]) != 0 ||
        private_fd(&handoff[1]) != 0 ||
        private_fd(&observer[0]) != 0 ||
        private_fd(&observer[1]) != 0)
        goto failed;
    long bootstrap = syscall(SYS_clone, 0UL, NULL, NULL, NULL, NULL);
    if (bootstrap < 0) goto failed;
    if (bootstrap == 0) {
        (void)close(handoff[0]);
        (void)close(observer[0]);
        pid_t service = fork();
        if (service < 0) _exit(125);
        if (service == 0)
            run_service(&created, &server, -1, handoff[1], -1, observer[1],
                        authority);
        sparc64_file_caps_client_close(&created);
        sparc64_file_caps_server_close(&server);
        (void)close(handoff[1]);
        (void)close(observer[1]);
        _exit(0);
    }
    /* The bootstrap is still waitable, so its PID cannot be recycled.
     * Take exact native signal authority before any bounded wait. Losing
     * that authority after clone cannot safely return to guest execution. */
    int bootstrap_cap = (int)syscall(SYS_pidfd_open, (pid_t)bootstrap, 0u);
    if (bootstrap_cap < 0 || private_fd(&bootstrap_cap) != 0)
        _exit(125);
    sparc64_file_caps_server_close(&server);
    (void)close(handoff[1]); handoff[1] = -1;
    (void)close(observer[1]); observer[1] = -1;
    int64_t deadline = deadline_ms();
    int cap = -1;
    int saved = 0;
    if (deadline >= 0 && wait_fd(handoff[0], deadline) == 0)
        cap = recv_self_pidfd(handoff[0]);
    if (cap < 0) saved = errno;
    int reaped = deadline >= 0 ?
        wait_bootstrap((pid_t)bootstrap, deadline) : 0;
    if (reaped == 0) {
        if (sparc64_process_child_cap_signal(bootstrap_cap, SIGKILL) != 0 &&
            errno != ESRCH)
            _exit(125);
        int64_t abort_deadline = deadline_ms();
        reaped = abort_deadline >= 0 ?
            wait_bootstrap((pid_t)bootstrap, abort_deadline) : 0;
        if (reaped == 0) _exit(125); /* Never return with an owned zombie. */
    }
    (void)close(bootstrap_cap);
    if (reaped != 1) saved = EIO;
    (void)close(handoff[0]); handoff[0] = -1;
    if (saved != 0) {
        sparc64_file_caps_client_close(&created);
        if (cap >= 3) (void)sparc64_process_child_cap_signal(cap, SIGKILL);
        if (cap >= 3) (void)close(cap);
        int64_t retire_deadline = deadline_ms();
        if (retire_deadline < 0 ||
            await_observer_close(observer[0], retire_deadline) != 0)
            _exit(125);
        errno = saved;
        goto failed;
    }
    *owner = (sparc64_file_service_owner_t){cap, observer[0]};
    observer[0] = -1;
    if (sparc64_file_service_owner_check(owner) != 0) {
        saved = errno;
        sparc64_file_caps_client_close(&created);
        (void)sparc64_process_child_cap_signal(owner->pidfd, SIGKILL);
        int64_t retire_deadline = deadline_ms();
        if (retire_deadline < 0 ||
            await_observer_close(owner->observer_fd, retire_deadline) != 0)
            _exit(125);
        sparc64_file_service_owner_close_local(owner);
        errno = saved;
        goto failed;
    }
    /* Receiving the exact pidfd precedes service initialization. A real
     * fetch reply proves allocation, socket validation, and the serve loop
     * are live before either owned cap or the client pair is published. */
    int absent = -1;
    errno = 0;
    if (sparc64_file_caps_fetch(&created, 1, &absent) != -1 ||
        errno != ENOENT || absent != -1) {
        saved = errno != 0 ? errno : EPROTO;
        sparc64_file_caps_client_close(&created);
        (void)sparc64_process_child_cap_signal(owner->pidfd, SIGKILL);
        int64_t retire_deadline = deadline_ms();
        if (retire_deadline < 0 ||
            await_observer_close(owner->observer_fd, retire_deadline) != 0)
            _exit(125);
        sparc64_file_service_owner_close_local(owner);
        errno = saved;
        goto failed;
    }
    *client = created;
    return 0;
failed: {
        int error = errno;
        if (handoff[0] >= 0) (void)close(handoff[0]);
        if (handoff[1] >= 0) (void)close(handoff[1]);
        if (observer[0] >= 0) (void)close(observer[0]);
        if (observer[1] >= 0) (void)close(observer[1]);
        sparc64_file_caps_server_close(&server);
        sparc64_file_caps_client_close(&created);
        errno = error;
        return -1;
    }
}

int sparc64_file_service_owner_start(sparc64_file_service_owner_t *owner,
                                sparc64_file_caps_client_t *client)
{
    return sparc64_file_service_owner_start_with_authority(owner, client,
                                                      SPARC64_FAMILY_AUTHORITY_AUTO);
}
