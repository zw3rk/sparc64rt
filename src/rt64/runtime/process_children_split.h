/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SPARC64RT_RUNTIME_PROCESS_CHILDREN_SPLIT_H
#define SPARC64RT_RUNTIME_PROCESS_CHILDREN_SPLIT_H

/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#define _GNU_SOURCE
#include "runtime/process_children.h"
#include "runtime/native_cmsg.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef P_PIDFD
#define P_PIDFD 3
#endif
#ifndef SYS_pidfd_send_signal
#define SYS_pidfd_send_signal 424
#endif
#ifndef SYS_pidfd_open
#define SYS_pidfd_open 434
#endif
#ifndef SOCK_CLOEXEC
#define SOCK_CLOEXEC 0
#endif
#ifndef MSG_CMSG_CLOEXEC
#define MSG_CMSG_CLOEXEC 0
#endif
#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

struct sparc64_process_child {
    struct sparc64_process_child *next;
    pid_t pid;
    int cap_fd;
    sparc64_process_child_role_t role;
};

/* Cross-part declarations (generated L0a split). */
void sparc64_process_parent_init(sparc64_process_parent_t *parent);
void sparc64_process_parent_close(sparc64_process_parent_t *parent);
int sparc64_process_parent_bind_current(sparc64_process_parent_t *parent);
pid_t sparc64_process_parent_fork(sparc64_process_parent_t *parent, pid_t (*fork_call)(void));
int sparc64_process_parent_adopt(sparc64_process_parent_t *parent, int owned_fd, pid_t expected_pid);
int sparc64_process_parent_signal(const sparc64_process_parent_t *parent, pid_t pid, int signum);
void child_free(sparc64_process_child_t *child);
void sparc64_process_children_init(sparc64_process_children_t *children);
int sparc64_process_children_count(const sparc64_process_children_t *children, size_t *count);
int sparc64_process_children_export(const sparc64_process_children_t *children, sparc64_process_child_cap_t *records, size_t capacity, size_t *count);
int sparc64_process_children_import(sparc64_process_children_t *children, const sparc64_process_child_cap_t *records, size_t count, pid_t original_owner);
int sparc64_process_children_drop_external(sparc64_process_children_t *children);
int sparc64_process_child_handoff_pair(int endpoints[2]);
int sparc64_process_child_handoff_send(int endpoint);
int sparc64_process_child_handoff_receive(int endpoint, pid_t expected_pid, int *cap_fd);
int sparc64_process_child_handoff_ack(int endpoint, bool accepted);
sparc64_process_child_t *sparc64_process_child_reserve(void);
void sparc64_process_child_discard(sparc64_process_child_t *child);
int sparc64_process_child_publish(sparc64_process_children_t *children, sparc64_process_child_t *child, pid_t pid, int cap_fd);
int sparc64_process_children_signal(sparc64_process_children_t *children, pid_t pid, int signal_number);
int sparc64_process_child_cap_signal(int cap_fd, int signal_number);
int sparc64_process_child_cap_exited(int cap_fd, pid_t expected_pid);
int sparc64_process_children_prune_autoreaped(sparc64_process_children_t *children);
int sparc64_process_children_probe(sparc64_process_children_t *children, pid_t requested, pid_t *reaped, int *status);
int sparc64_process_children_waitid(sparc64_process_children_t *children, pid_t requested, bool nowait, sparc64_linux_waitid_info_t *info);
bool sparc64_process_children_live(const sparc64_process_children_t *children);
int sparc64_process_children_abandon_child(sparc64_process_children_t *children);

#endif /* SPARC64RT_RUNTIME_PROCESS_CHILDREN_SPLIT_H */
