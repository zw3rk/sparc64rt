/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#include "process_children_split.h"


int sparc64_process_children_probe(sparc64_process_children_t *children, pid_t requested,
                               pid_t *reaped, int *status)
{
    if (children == NULL || reaped == NULL || status == NULL ||
        children->owner_pid != getpid() ||
        (requested <= 0 && requested != -1)) {
        errno = EINVAL;
        return -1;
    }
    *reaped = 0;
    *status = 0;
    bool running = false;
    sparc64_process_child_t **position = &children->head;
    while (*position != NULL) {
        sparc64_process_child_t *child = *position;
        if (requested > 0 && child->pid != requested) {
            position = &child->next;
            continue;
        }
        /* Guest P_ALL scans only owned capabilities. P_PIDFD prevents stale
         * numeric identifiers from selecting a replacement process. */
        siginfo_t native = {0};
        if (waitid(P_PIDFD, (id_t)child->cap_fd, &native,
                   WEXITED | WNOHANG) != 0) {
            if (errno != ECHILD)
                return -1;
            *position = child->next;
            child_free(child);
            continue;
        }
        if (native.si_pid == 0) {
            running = true;
            position = &child->next;
            continue;
        }
        if (native.si_pid != child->pid ||
            (native.si_code != CLD_EXITED && native.si_code != CLD_KILLED &&
             native.si_code != CLD_DUMPED)) {
            errno = EIO;
            return -1;
        }
        int native_status = native.si_code == CLD_EXITED ?
            (native.si_status & 0xff) << 8 :
            (native.si_status & 0x7f) |
                (native.si_code == CLD_DUMPED ? 0x80 : 0);
        *position = child->next;
        child_free(child);
        *reaped = native.si_pid;
        *status = native_status;
        return 1;
    }
    if (running)
        return 0;
    errno = ECHILD;
    return -1;
}

int sparc64_process_children_waitid(sparc64_process_children_t *children, pid_t requested,
                                bool nowait, sparc64_linux_waitid_info_t *info)
{
    if (children == NULL || info == NULL ||
        children->owner_pid != getpid() ||
        (requested <= 0 && requested != -1)) {
        errno = EINVAL;
        return -1;
    }
    *info = (sparc64_linux_waitid_info_t){0};
    int options = WEXITED | WNOHANG | (nowait ? WNOWAIT : 0);
    bool running = false;
    sparc64_process_child_t **position = &children->head;
    while (*position != NULL) {
        sparc64_process_child_t *child = *position;
        if (requested > 0 && child->pid != requested) {
            position = &child->next;
            continue;
        }
        siginfo_t native = {0};
        if (waitid(P_PIDFD, (id_t)child->cap_fd, &native, options) != 0) {
            if (errno != ECHILD)
                return -1;
            *position = child->next;
            child_free(child);
            continue;
        }
        if (native.si_pid == 0) {
            running = true;
            position = &child->next;
            continue;
        }
        if (native.si_pid != child->pid ||
            (native.si_code != CLD_EXITED && native.si_code != CLD_KILLED &&
             native.si_code != CLD_DUMPED)) {
            errno = EIO;
            return -1;
        }
        *info = (sparc64_linux_waitid_info_t){
            .pid = (int32_t)native.si_pid,
            .uid = (uint32_t)native.si_uid,
            .cause = native.si_code == CLD_EXITED ? 1u :
                     native.si_code == CLD_KILLED ? 2u : 3u,
            .status = native.si_status
        };
        if (!nowait) {
            *position = child->next;
            child_free(child);
        }
        return 1;
    }
    if (running)
        return 0;
    errno = ECHILD;
    return -1;
}

bool sparc64_process_children_live(const sparc64_process_children_t *children)
{
    return children != NULL && children->head != NULL;
}

int sparc64_process_children_abandon_child(sparc64_process_children_t *children)
{
    if (children == NULL || children->owner_pid == getpid()) {
        errno = EPERM;
        return -1;
    }
    sparc64_process_child_t *child = children->head;
    while (child != NULL) {
        sparc64_process_child_t *next = child->next;
        child_free(child);
        child = next;
    }
    sparc64_process_children_init(children);
    return 0;
}
