/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SPARC64RT_FAMILY_ZERO_CONTROL_H
#define SPARC64RT_FAMILY_ZERO_CONTROL_H

#include "runtime/family_zero_blob.h"
#include <stdbool.h>
#include <stddef.h>
#include <pthread.h>
#include <stdint.h>

typedef struct sparc64_family_zero_control sparc64_family_zero_control_t;

typedef struct sparc64_family_zero_snapshot {
    uint64_t generation;
    uint64_t root_id;
    size_t size;
    uint8_t bytes[SPARC64_FAMILY_ZERO_BLOB_MAX_SIZE];
} sparc64_family_zero_snapshot_t;

typedef struct sparc64_family_zero_guard {
    sparc64_family_zero_control_t *owner;
    sparc64_family_zero_snapshot_t current;
    int previous_cancel_state;
    pthread_t thread;
    bool held;
} sparc64_family_zero_guard_t;

/* Linux ext4/tmpfs-only component. The directory must already be a private
 * exact FD (owner/effective UID, mode 0700, certified AUTO authority). The
 * component retains its own directory FD and one stable zero-length control
 * FD. It never reopens that control inode while holding its POSIX byte lock.
 * One owner per native process is enforced until a later multi-family
 * registry exists. External aliases to the control inode are prohibited:
 * closing any such alias can release process-wide POSIX locks.
 *
 * create starts at generation 1; adopt accepts only a complete existing head.
 * Output pointers remain unchanged on failure. A failed partial create can
 * leave unreachable private files requiring separate owned cleanup.
 * A successful create/adopt owns its creating thread's cancellation state:
 * cancellation stays disabled until that same thread destroys the owner.
 * This also protects construction and output transfer from pending cancellation.
 */
int sparc64_family_zero_control_create(int directory_fd, const uint8_t *initial,
                                   size_t initial_size,
                                   sparc64_family_zero_control_t **out);
int sparc64_family_zero_control_adopt(int directory_fd,
                                  sparc64_family_zero_control_t **out);

/* begin acquires a local mutex and the exact control FD's POSIX byte-0 write
 * lock with cancellation disabled. Present malformed heads/root blobs are
 * fatal, never silently rolled back. guard and snapshot are published only
 * on success; leave releases the native lock before restoring cancellation.
 * A guard belongs to its acquiring pthread; nested begin is rejected.
 * A caller must not fork/exec while a guard is held.
 */
int sparc64_family_zero_control_begin(sparc64_family_zero_control_t *owner,
                                  sparc64_family_zero_guard_t *guard,
                                  sparc64_family_zero_snapshot_t *out);
int sparc64_family_zero_control_leave(sparc64_family_zero_guard_t *guard);

/* Under a held guard, reserve/fsync a monotonic blob ID, seal the blob, write
 * the inactive head, then atomically rename it into place and fsync the dir.
 * 0 = durable new root, -1 = no head publication, -2 = rename happened but
 * durability is uncertain; -2 poisons the owner and requires process exit.
 * A failed pre-head commit may leave unreachable blob IDs; never reuse them.
 * out is unchanged unless the return is 0.
 */
int sparc64_family_zero_control_commit(sparc64_family_zero_guard_t *guard,
                                   const uint8_t *bytes, size_t size,
                                   sparc64_family_zero_snapshot_t *out);

/* The creator pthread alone may native-fork this owner. Its sole surviving
 * child thread calls rebase before touching any copied owner mutex. Transfers
 * inherited FDs and the disabled cancellation baseline to a fresh owner and
 * mutex. Failure requires child fail-stop. */
int sparc64_family_zero_control_child_rebase(sparc64_family_zero_control_t **inout);

/* Only on the creator thread with no held guard or concurrent user. Restores
 * its original cancellation state after closing all owned capabilities.
 * Never close another alias to this control inode while a guard is held. */
void sparc64_family_zero_control_destroy(sparc64_family_zero_control_t *owner);

#ifdef SPARC64_FAMILY_ZERO_CONTROL_TEST_HOOKS
/* Fixture-only owner-death cuts. The callback may _exit from its native child.
 * Production builds contain neither hook nor mutable phase state. */
typedef void (*sparc64_family_zero_control_test_hook_t)(unsigned phase);
void sparc64_family_zero_control_test_set_hook(
    sparc64_family_zero_control_test_hook_t hook);
int sparc64_family_zero_control_test_control_fd(
    const sparc64_family_zero_control_t *owner);
#define SPARC64_ZERO_CUT_AFTER_RESERVE 1u
#define SPARC64_ZERO_CUT_AFTER_BLOB 2u
#define SPARC64_ZERO_CUT_BEFORE_HEAD_RENAME 3u
#define SPARC64_ZERO_CUT_AFTER_HEAD_RENAME 4u
#endif

#endif
