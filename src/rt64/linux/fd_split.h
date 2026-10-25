/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SPARC64RT_LINUX_FD_SPLIT_H
#define SPARC64RT_LINUX_FD_SPLIT_H

/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#define _GNU_SOURCE 1
#define _POSIX_C_SOURCE 200809L
#include "linux/fd.h"
#include "linux/fd_initial.h"
#include "linux/fd_snapshot_internal.h"

#include <errno.h>
#include <fcntl.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

struct sparc64_fd_description {
    int host_fd;
    size_t refs; /* Guest slots plus in-flight borrows, under table mutex. */
    uint64_t id;
    bool logical_read_only;
    bool owned_pipe_writer;
    bool owned_pipe_endpoint;
    bool managed_fifo_writer;
    bool managed_fifo_endpoint;
};

struct sparc64_fd_fork_child {
    sparc64_fd_table_t *source;
    sparc64_fd_snapshot_t *snapshot;
    pid_t creator_pid;
};

_Static_assert(sizeof(sparc64_fd_snapshot_entry_t) == 16u,
               "snapshot entry record must stay pointer-free");
_Static_assert(sizeof(sparc64_fd_snapshot_description_t) == 16u,
               "snapshot description record must stay pointer-free");
sparc64_fd_entry_t make_entry(sparc64_fd_description_t *description,
                                bool cloexec, bool reserved, uint32_t hidden);
int lock_table(sparc64_fd_table_t *table);
void unlock_table(sparc64_fd_table_t *table);
bool entry_is_guest(const sparc64_fd_entry_t *entry);

/* Cross-part declarations (generated L0a split). */
sparc64_fd_description_t *new_description(int host_fd, uint64_t id);
sparc64_fd_entry_t make_entry(sparc64_fd_description_t *description, bool cloexec, bool reserved, uint32_t hidden);
sparc64_fd_description_t *drop_reference(sparc64_fd_description_t *description);
int destroy_description(sparc64_fd_description_t *description);
int duplicate_private(int host_fd);
void sparc64_fd_snapshot_destroy(sparc64_fd_snapshot_t *snapshot);
int sparc64_fd_snapshot_create(sparc64_fd_table_t *table, sparc64_fd_snapshot_t **out);
int sparc64_fd_snapshot_restore(const sparc64_fd_snapshot_t *snapshot, sparc64_fd_table_t *destination);
int sparc64_fd_fork_child_prepare(sparc64_fd_table_t *table, sparc64_fd_fork_child_t **out);
void sparc64_fd_fork_child_destroy(sparc64_fd_fork_child_t **owned);
int sparc64_fd_fork_child_rebase(sparc64_fd_fork_child_t **owned, sparc64_fd_table_t *copied_table);
int lock_table(sparc64_fd_table_t *table);
void unlock_table(sparc64_fd_table_t *table);
int add_description(sparc64_fd_table_t *table, uint64_t *description_id);
int free_guest_slot(const sparc64_fd_table_t *table, unsigned int minimum);
bool entry_is_guest(const sparc64_fd_entry_t *entry);
int create_placeholder(void);
int sparc64_fd_table_init_initial(sparc64_fd_table_t *table, sparc64_fd_initial_t **owned);
int sparc64_fd_table_init(sparc64_fd_table_t *table);
void sparc64_fd_table_destroy(sparc64_fd_table_t *table);
int sparc64_fd_install(sparc64_fd_table_t *table, int owned_host_fd, bool cloexec);
int sparc64_fd_reserve(sparc64_fd_table_t *table);
int sparc64_fd_commit(sparc64_fd_table_t *table, unsigned int guest_fd, int owned_host_fd, bool cloexec, uint32_t hidden_status_flags);
int sparc64_fd_commit_with_access(sparc64_fd_table_t *table, unsigned int guest_fd, int owned_host_fd, bool cloexec, uint32_t hidden_status_flags, bool logical_read_only);
int sparc64_fd_commit_managed_fifo(sparc64_fd_table_t *table, unsigned int guest_fd, int owned_host_fd, bool cloexec, uint32_t hidden_status_flags, bool logical_read_only, bool writer);
int sparc64_fd_commit_pipe_reader(sparc64_fd_table_t *table, unsigned int guest_fd, int owned_host_fd, bool cloexec);
int sparc64_fd_commit_pipe_writer(sparc64_fd_table_t *table, unsigned int guest_fd, int owned_host_fd, bool cloexec);
int sparc64_fd_is_pipe_writer(sparc64_fd_table_t *table, unsigned int guest_fd);
int sparc64_fd_is_pipe_endpoint(sparc64_fd_table_t *table, unsigned int guest_fd);
int sparc64_fd_is_fifo_writer(sparc64_fd_table_t *table, unsigned int guest_fd);
int sparc64_fd_is_fifo_endpoint(sparc64_fd_table_t *table, unsigned int guest_fd);
int sparc64_fd_is_managed_fifo_writer(sparc64_fd_table_t *table, unsigned int guest_fd);
int sparc64_fd_is_managed_fifo_endpoint(sparc64_fd_table_t *table, unsigned int guest_fd);
int sparc64_fd_cancel(sparc64_fd_table_t *table, unsigned int guest_fd);
int sparc64_fd_acquire(sparc64_fd_table_t *table, unsigned int guest_fd);
int sparc64_fd_acquire_status(sparc64_fd_table_t *table, unsigned int guest_fd, uint32_t *hidden_status_flags);
int sparc64_fd_acquire_mode(sparc64_fd_table_t *table, unsigned int guest_fd, uint32_t *hidden_status_flags, bool *logical_read_only);
int sparc64_fd_release(int lease_fd);
int sparc64_fd_borrow(sparc64_fd_table_t *table, unsigned int guest_fd, sparc64_fd_borrow_t *borrow);
int sparc64_fd_unborrow(sparc64_fd_borrow_t *borrow);
int sparc64_fd_close(sparc64_fd_table_t *table, unsigned int guest_fd);
int sparc64_fd_dup(sparc64_fd_table_t *table, unsigned int old_fd, unsigned int minimum, bool cloexec);
int sparc64_fd_dup3(sparc64_fd_table_t *table, unsigned int old_fd, unsigned int new_fd, bool cloexec);
int sparc64_fd_get_cloexec(sparc64_fd_table_t *table, unsigned int guest_fd);
int sparc64_fd_set_cloexec(sparc64_fd_table_t *table, unsigned int guest_fd, bool cloexec);

#endif /* SPARC64RT_LINUX_FD_SPLIT_H */
