/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SPARC64RT_LINUX_FD_H
#define SPARC64RT_LINUX_FD_H

#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#define SPARC64_FD_TABLE_LIMIT 1024u

typedef struct sparc64_fd_description sparc64_fd_description_t;
typedef struct sparc64_fd_table sparc64_fd_table_t;
typedef struct sparc64_fd_snapshot sparc64_fd_snapshot_t;
typedef struct sparc64_fd_fork_child sparc64_fd_fork_child_t;

typedef struct {
    int host_fd;
    bool guest_cloexec;
    bool reserved; /* Placeholder exists but is not guest-visible. */
    uint32_t hidden_status_flags; /* Native resolver-only flags masked from F_GETFL. */
    uint64_t description_id;
    sparc64_fd_description_t *description; /* Shared by guest dup/dup3 aliases. */
} sparc64_fd_entry_t;

struct sparc64_fd_table {
    pthread_mutex_t mutex;
    sparc64_fd_entry_t entries[SPARC64_FD_TABLE_LIMIT];
    uint64_t next_description_id;
    size_t active_borrows;
    pid_t owner_pid;
    bool initialized;
};

typedef struct {
    sparc64_fd_table_t *table;
    sparc64_fd_description_t *description;
    int host_fd;
    uint32_t hidden_status_flags; /* Snapshot from the borrowed guest entry. */
    bool logical_read_only; /* Native descriptor may be RW for RO|TRUNC. */
} sparc64_fd_borrow_t;

/* Initialize guest 0..2 from currently open host standard descriptors. Closed
 * host standard descriptors remain closed in the virtual table. */
int sparc64_fd_table_init(sparc64_fd_table_t *table);
/* No table operation or borrow may be in flight while destroying it. The
 * table models one process; fork inheritance is deferred to R5. */
void sparc64_fd_table_destroy(sparc64_fd_table_t *table);

/* Create an opaque in-process snapshot object. Its metadata records are
 * pointer-free; native descriptor leases are owned separately and are not a
 * wire format or cross-process descriptor encoding. The snapshot owns one
 * private CLOEXEC native descriptor per distinct open description. The table
 * must be quiescent with respect to native I/O; active borrows and reservations
 * are rejected with EBUSY. The source table is never modified. */
int sparc64_fd_snapshot_create(sparc64_fd_table_t *table, sparc64_fd_snapshot_t **out);
/* Restore into zero-initialized storage that has never had a mutex initialized.
 * On success the destination owns its own native leases and the snapshot stays
 * valid. On failure the destination remains uninitialized and the snapshot
 * remains valid and destroyable. Restore preserves guest numbers, aliases,
 * description IDs, CLOEXEC, hidden flags, logical access, pipe provenance, and
 * next-description ID. Caller must ensure no native operation is in flight. */
int sparc64_fd_snapshot_restore(const sparc64_fd_snapshot_t *snapshot,
                           sparc64_fd_table_t *destination);
/* Closes only the snapshot's native leases. */
void sparc64_fd_snapshot_destroy(sparc64_fd_snapshot_t *snapshot);

/* Prepare under the family guard after all native file callbacks have
 * completed or suspended, native registration is sealed, and the table has
 * no active borrows/reservations. Do not mutate the table before native fork.
 * The owner retains one private CLOEXEC lease per distinct description. */
int sparc64_fd_fork_child_prepare(sparc64_fd_table_t *table, sparc64_fd_fork_child_t **out);
/* Parent cleanup, or child preflight-failure cleanup. Never changes the table. */
void sparc64_fd_fork_child_destroy(sparc64_fd_fork_child_t **owned);
/* Child-only after native fork. Rejects the creator PID and the wrong copied
 * table before touching any copied mutex. Verifies that the table still names
 * the prepared descriptions, closes/frees each inherited description once,
 * abandons copied mutex bytes, then restores fresh leases and a fresh mutex.
 * Success consumes *owned. A failure after inherited descriptions are closed
 * leaves the child table unusable and requires immediate infrastructure exit;
 * it still consumes *owned. Parent table and owner remain unchanged. */
int sparc64_fd_fork_child_rebase(sparc64_fd_fork_child_t **owned,
                           sparc64_fd_table_t *copied_table);

/* Install consumes owned_host_fd on success and failure. Returns the guest fd
 * or -1 with errno set. The table owns a private host descriptor >= 3. */
int sparc64_fd_install(sparc64_fd_table_t *table, int owned_host_fd, bool cloexec);
/* Reserve the lowest free guest fd and a private native placeholder >=3 before
 * any externally visible open side effect. Returns the guest fd or -1/errno.
 * Each reservation is one-shot; callers must not race cancel/commit for it. */
int sparc64_fd_reserve(sparc64_fd_table_t *table);
/* With a valid owned_host_fd, commit consumes both it and the reservation on
 * every outcome. A negative source is rejected without changing the table. */
int sparc64_fd_commit(sparc64_fd_table_t *table, unsigned int guest_fd,
                 int owned_host_fd, bool cloexec,
                 uint32_t hidden_status_flags);
int sparc64_fd_commit_with_access(sparc64_fd_table_t *table, unsigned int guest_fd,
                              int owned_host_fd, bool cloexec,
                              uint32_t hidden_status_flags,
                              bool logical_read_only);
int sparc64_fd_commit_managed_fifo(sparc64_fd_table_t *table, unsigned int guest_fd,
                               int owned_host_fd, bool cloexec,
                               uint32_t hidden_status_flags,
                               bool logical_read_only, bool writer);
/* pipe2's write endpoint carries immutable origin on the shared description.
 * Dup aliases retain it; resolver/SCM/imported FIFO descriptors do not gain it. */
int sparc64_fd_commit_pipe_writer(sparc64_fd_table_t *table, unsigned int guest_fd,
                             int owned_host_fd, bool cloexec);
int sparc64_fd_commit_pipe_reader(sparc64_fd_table_t *table, unsigned int guest_fd,
                             int owned_host_fd, bool cloexec);
/* Returns 1 for an owned pipe2 write endpoint, 0 for another open entry, or
 * -1/errno for an invalid guest descriptor. */
int sparc64_fd_is_pipe_writer(sparc64_fd_table_t *table, unsigned int guest_fd);
int sparc64_fd_is_pipe_endpoint(sparc64_fd_table_t *table, unsigned int guest_fd);
/* Inspect the exact table-owned description without opening a pathname or
 * releasing a POSIX record lock. Includes inherited and opened FIFO entries;
 * sockets, regular files, and O_PATH handles are excluded. Guest workers hold
 * the family token across classification and dispatch. */
int sparc64_fd_is_fifo_writer(sparc64_fd_table_t *table, unsigned int guest_fd);
int sparc64_fd_is_fifo_endpoint(sparc64_fd_table_t *table, unsigned int guest_fd);
/* Immutable origin from this guest's successful FIFO mknodat and an exact
 * opened-inode match. Imported FIFO descriptors never acquire these bits. */
int sparc64_fd_is_managed_fifo_writer(sparc64_fd_table_t *table, unsigned int guest_fd);
int sparc64_fd_is_managed_fifo_endpoint(sparc64_fd_table_t *table, unsigned int guest_fd);
/* Cancel releases an unused reservation and its private placeholder. */
int sparc64_fd_cancel(sparc64_fd_table_t *table, unsigned int guest_fd);
/* Return a temporary F_DUPFD_CLOEXEC lease; caller releases it after use. */
int sparc64_fd_acquire(sparc64_fd_table_t *table, unsigned int guest_fd);
/* Acquire a lease and return immutable resolver-only status bits atomically. */
int sparc64_fd_acquire_status(sparc64_fd_table_t *table, unsigned int guest_fd,
                         uint32_t *hidden_status_flags);
/* Atomic status/mode snapshot with the temporary native lease. */
int sparc64_fd_acquire_mode(sparc64_fd_table_t *table, unsigned int guest_fd,
                       uint32_t *hidden_status_flags, bool *logical_read_only);
int sparc64_fd_release(int lease_fd);
/* Pin the one native open-description object without duplicating its host fd.
 * This preserves hl's directory stream across calls and virtual guest dup.
 * Pass a zero-initialized handle. It is stable through close/reuse/dup3 until
 * unborrow, which clears it. */
int sparc64_fd_borrow(sparc64_fd_table_t *table, unsigned int guest_fd,
                 sparc64_fd_borrow_t *borrow);
int sparc64_fd_unborrow(sparc64_fd_borrow_t *borrow);
int sparc64_fd_close(sparc64_fd_table_t *table, unsigned int guest_fd);
int sparc64_fd_dup(sparc64_fd_table_t *table, unsigned int old_fd,
              unsigned int minimum, bool cloexec);
int sparc64_fd_dup3(sparc64_fd_table_t *table, unsigned int old_fd,
               unsigned int new_fd, bool cloexec);
/* Returns 0 or 1, or -1 with errno set. */
int sparc64_fd_get_cloexec(sparc64_fd_table_t *table, unsigned int guest_fd);
int sparc64_fd_set_cloexec(sparc64_fd_table_t *table, unsigned int guest_fd,
                      bool cloexec);

#endif
