/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SPARC64RT_RUNTIME_PROCESS_CHILDREN_H
#define SPARC64RT_RUNTIME_PROCESS_CHILDREN_H

#include <stdbool.h>
#include <stddef.h>
#include <sys/types.h>
#include "linux/wait.h"

typedef struct sparc64_process_child sparc64_process_child_t;
typedef enum {
    SPARC64_PROCESS_CHILD_FAMILY = 0,
    SPARC64_PROCESS_CHILD_EXTERNAL = 1
} sparc64_process_child_role_t;
typedef struct {
    sparc64_process_child_t *head;
    pid_t owner_pid;
} sparc64_process_children_t;

/* Pointer-free metadata for the same-PID exec record. cap_fd is an owned,
 * CLOEXEC pidfd in this process, not a PID-derived substitute. FAMILY children
 * may depend on sparc64rt family storage; captured EXTERNAL native children do not.
 * Both roles remain visible to guest wait/signal selection. */
typedef struct {
    pid_t pid;
    int cap_fd;
    sparc64_process_child_role_t role;
} sparc64_process_child_cap_t;

/* Private current-parent capability. Never placed in the guest FD table or
 * child registry. A fork child rebinds to its own parent after bootstrap.
 * Same-PID exec transports a live witness FD, then reacquires the recorded
 * current parent; the transported FD itself grants no signal authority. */
typedef struct {
    pid_t pid;
    int cap_fd;
} sparc64_process_parent_t;
void sparc64_process_parent_init(sparc64_process_parent_t *parent);
void sparc64_process_parent_close(sparc64_process_parent_t *parent);
int sparc64_process_parent_bind_current(sparc64_process_parent_t *parent);
/* Keep the parent's exact cap across both fork outcomes. The child consumes
 * its copied descriptor and binds its actual parent before guest execution.
 * fork_call is injectable only so the native failure path can be tested. */
pid_t sparc64_process_parent_fork(sparc64_process_parent_t *parent,
                              pid_t (*fork_call)(void));
int sparc64_process_parent_adopt(sparc64_process_parent_t *parent, int owned_fd,
                            pid_t expected_pid);
/* Parent capabilities permit probes plus the initial user relays and TERM. */
int sparc64_process_parent_signal(const sparc64_process_parent_t *parent, pid_t pid,
                              int signum);

void sparc64_process_children_init(sparc64_process_children_t *children);
/* Export and import the exact registered child-capability inventory across
 * same-PID exec.
 * Callers serialize access under the family guard and quiesce native helper
 * operations before export. Export only copies registered (PID, pidfd) pairs;
 * it never probes or consumes children. The snapshot contains no pointers or
 * mutexes, but its descriptor numbers are meaningful only in this same
 * process. Import trusts the transported pairs and does not probe the kernel.
 * It requires an initialized, empty registry owned by the current PID and an
 * original-owner PID equal to getpid(); this API is for same-PID exec. Failed
 * import leaves the registry and descriptor flags unchanged, except that EIO
 * reports a failed CLOEXEC rollback; callers must fail closed on EIO. */
int sparc64_process_children_count(const sparc64_process_children_t *children,
                              size_t *count);
/* On ERANGE, export sets *count to the required capacity and leaves records
 * untouched. */
int sparc64_process_children_export(const sparc64_process_children_t *children,
                               sparc64_process_child_cap_t *records,
                               size_t capacity, size_t *count);
int sparc64_process_children_import(sparc64_process_children_t *children,
                               const sparc64_process_child_cap_t *records,
                               size_t count,
                               pid_t original_owner);
/* Reserve before the irreversible native fork; publish only in the parent. */
sparc64_process_child_t *sparc64_process_child_reserve(void);
void sparc64_process_child_discard(sparc64_process_child_t *child);
int sparc64_process_child_publish(sparc64_process_children_t *children,
                             sparc64_process_child_t *child, pid_t pid, int cap_fd);
/* Stream handoff endpoints are created before fork. The child sends its
 * self-opened pidfd and waits for the parent's one-byte ACK. The parent
 * validates the exact child PID and takes ownership of the received cap. */
int sparc64_process_child_handoff_pair(int endpoints[2]);
int sparc64_process_child_handoff_send(int endpoint);
int sparc64_process_child_handoff_receive(int endpoint, pid_t expected_pid,
                                     int *cap_fd);
int sparc64_process_child_handoff_ack(int endpoint, bool accepted);
/* Signal only through the registered capability. Supported child signals are
 * 0 (probe), SIGTERM, and SIGKILL. */
int sparc64_process_children_signal(sparc64_process_children_t *children, pid_t pid,
                               int signal_number);
int sparc64_process_child_cap_signal(int cap_fd, int signal_number);
/* Nonconsuming P_PIDFD exit observation: 1=exited or auto-reaped,
 * 0=still running, -1=observation error. expected_pid protects callers from
 * malformed transport metadata; no numeric-PID wait is performed. */
int sparc64_process_child_cap_exited(int cap_fd, pid_t expected_pid);
/* Before another native fork, discard records whose children were already
 * auto-reaped by SIG_IGN/SA_NOCLDWAIT. WNOWAIT leaves ordinary zombies and
 * their pidfd ownership intact. */
int sparc64_process_children_prune_autoreaped(sparc64_process_children_t *children);
/* Probe only with WNOHANG on each registered pidfd. 1=reaped,
 * 0=known child still running,
 * -1=error. ECHILD also removes known auto-reaped records. A positive pid
 * absent from the registry reports ECHILD. A -1 selector scans only registered
 * PIDs, leaving private native helper children untouched. Caller serializes
 * all registry operations under the family guard. */
int sparc64_process_children_probe(sparc64_process_children_t *children, pid_t requested,
                               pid_t *reaped, int *status);
/* Observe a known native child with WEXITED|WNOHANG. WNOWAIT leaves both the
 * kernel zombie and registry record intact; a consuming positive result
 * retires exactly that record before guest copyout. */
int sparc64_process_children_waitid(sparc64_process_children_t *children, pid_t requested,
                                bool nowait, sparc64_linux_waitid_info_t *info);
bool sparc64_process_children_live(const sparc64_process_children_t *children);
/* Teardown only: close captured native-child capabilities without observing,
 * reaping or signalling their processes. They do not own sparc64rt family storage.
 * Keep runtime-family records for the existing family retirement protocol. */
int sparc64_process_children_drop_external(sparc64_process_children_t *children);
/* Child-only: parent bookkeeping is copied but no copied native child belongs
 * to the new process. No pthread state or native wait is touched. */
int sparc64_process_children_abandon_child(sparc64_process_children_t *children);

#endif
