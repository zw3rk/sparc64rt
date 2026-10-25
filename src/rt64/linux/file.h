/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SPARC64RT_LINUX_FILE_H
#define SPARC64RT_LINUX_FILE_H

#include "linux/fd.h"
#include "linux/fd_initial.h"
#include "linux/io.h"
#include "linux/resolve.h"
#include "linux/memory.h"
#include "memory/file_backing.h"
#include "memory/space.h"
#include <sys/types.h>
#include <poll.h>

/* The caller holds a descriptor lease and owns the prepared native staging
 * buffer for the whole call. A runtime may provide a reviewed interruptible
 * read boundary; NULL keeps the ordinary libc path used by native units. */
typedef ssize_t (*sparc64_linux_read_fn)(int descriptor, void *buffer, size_t size,
                                    void *context);
/* Regular-file positioned write callback runs after fd/offset/access
 * validation and guest input staging, while the caller's guard remains held.
 * The full Linux-capped
 * count is checked against max_pwrite before staging; a later guest-copy fault
 * may submit one valid prefix. The descriptor borrow stays live until return.
 * A negative result with errno is a definite native no-effect failure; any
 * uncertain post-intent outcome must be poisoned by the owner before it
 * returns. Nonregular descriptors retain the native positioned-I/O route.
 * The callback must not close the borrowed descriptor or release or rebind
 * the guard. */
typedef ssize_t (*sparc64_linux_pwrite_fn)(int descriptor, const void *buffer,
                                      size_t size, uint64_t offset,
                                      void *context);
/* Optional canonical ftruncate operation. The caller holds its family guard
 * and borrows the exact native description through this call; the callback
 * must not close it or release the guard. Return0 only for a confirmed native
 * outcome, with *native_errno=0 on success or the native error on definite
 * failure. A nonzero return is infrastructure/uncertain: the dispatcher marks
 * sticky INTERNAL and never presents callback errno as a retryable guest
 * failure. Do not modify *native_errno on that path. */
typedef int (*sparc64_linux_truncate_fn)(int descriptor, uint64_t length,
                                    int *native_errno, void *context);
/* After an open's truncate callback confirms its native outcome, report the
 * final open result once, after descriptor commit/cancellation. This maps the
 * native truncate result to the reserved guest FD or final Linux error. It
 * never runs if no truncate was attempted or its outcome is uncertain. A
 * nonzero return poisons the dispatcher's memory state before guest resume. */
typedef int (*sparc64_linux_open_truncate_result_fn)(uint32_t reserved_guest_fd,
                                               uint64_t guest_result,
                                               void *context);
typedef int (*sparc64_linux_poll_fn)(struct pollfd *descriptors, nfds_t count,
                                 int timeout, void *context);
/* pselect6 installs a temporary guest mask only after argument and timeout
 * import, before select validates descriptors. The runtime supplies these
 * guarded callbacks for the calling signal view. An explained interruption
 * keeps the saved mask until immediate guest signal delivery. */
typedef bool (*sparc64_linux_wait_mask_begin_fn)(uint64_t mask, void *context);
typedef bool (*sparc64_linux_wait_mask_finish_fn)(bool interrupted_for_delivery,
                                              void *context);
typedef bool (*sparc64_linux_poll_guest_interrupt_fn)(void *context);
typedef bool (*sparc64_linux_poll_cancelled_fn)(void *context);
typedef struct sparc64_owned_io_registry sparc64_owned_io_registry_t;
typedef struct sparc64_owned_io_flight sparc64_owned_io_flight_t;

/* Immutable per-call worker selection. Dispatch snapshots this record before
 * invoking a callback, so another worker need not mutate process defaults.
 * Context storage must outlive the call, including any unlocked native I/O.
 * A releasing read callback must reacquire its own family guard before every
 * return. A releasing write callback has the same leave/re-enter obligation
 * on every return. Releasing writes currently require a FIFO so the
 * open-description position/coherence remains outside this unlocked
 * operation. Poll callbacks may release ownership while retaining only their
 * private native arrays and descriptor leases. Every return reacquires the
 * guard; poll_cancelled reports terminal admission before the codec can write
 * guest memory, finish a temporary mask, or publish a result. */
typedef struct {
    sparc64_linux_read_fn read;
    void *read_context;
    bool read_releases_guard;
    sparc64_linux_write_fn write;
    void *write_context;
    sparc64_linux_write_request_fn write_request;
    void *write_request_context;
    /* A regular-file write callback executed under the caller's held guard.
     * The dispatcher keeps an exact descriptor borrow live across it and
     * bypasses the legacy managed_write mutation wrapper. The full Linux-
     * capped count is checked against max_canonical_write before staging;
     * after a later guest-copy fault one valid prefix is submitted once.
     * Nonregular descriptors retain the existing callback/lease route. */
    sparc64_linux_write_request_fn canonical_write_request;
    void *canonical_write_request_context;
    size_t max_canonical_write; /* Zero permits only a zero-byte request. */
    sparc64_linux_pwrite_fn pwrite;
    void *pwrite_context;
    size_t max_pwrite; /* Required callback bound; zero permits only size0. */
    sparc64_linux_truncate_fn truncate;
    void *truncate_context;
    sparc64_linux_open_truncate_result_fn open_truncate_result;
    void *open_truncate_result_context;
    bool write_releases_guard;
    size_t max_write; /* Zero means no cap; checked before payload staging. */
    bool full_write; /* Preserve one logical callback call beyond 64 KiB. */
    sparc64_owned_io_registry_t *owned_io; /* Releasing callback flight owner. */
    sparc64_owned_io_flight_t **flight_slot; /* Borrowed callback's current flight. */
    sparc64_linux_poll_fn poll;
    void *poll_context;
    sparc64_linux_poll_cancelled_fn poll_cancelled;
    sparc64_linux_wait_mask_begin_fn wait_mask_begin;
    sparc64_linux_wait_mask_finish_fn wait_mask_finish;
    sparc64_linux_poll_guest_interrupt_fn poll_guest_interrupt;
    void *wait_mask_context;
} sparc64_linux_file_io_t;

typedef struct {
    uint32_t device_major;
    uint32_t device_minor;
    uint64_t inode;
    int64_t birth_seconds;
    uint32_t birth_nanoseconds;
} sparc64_linux_fifo_identity_t;

typedef struct {
    sparc64_space_t *space;
    sparc64_fd_table_t descriptors;
    sparc64_path_resolver_t paths;
    sparc64_file_registry_t backings;
    sparc64_file_registry_t *active_backings; /* Embedded, or child-image borrowed. */
    bool backings_borrowed;
    pid_t creator_pid;
    sparc64_linux_fifo_identity_t *created_fifos;
    size_t created_fifo_count;
    size_t created_fifo_capacity;
    char *sysroot;
    sparc64_linux_read_fn read;
    void *read_context;
    /* Only non-positioned callback reads may release the family guard. When
     * enabled the callback must reacquire it before returning, including on
     * error. The descriptor lease and staging remain private and live; owned
     * copyout rebases only the completed prefix and never retries native I/O. */
    bool read_releases_guard;
    sparc64_linux_poll_fn poll;
    void *poll_context;
} sparc64_linux_file_t;

/* Reserve registry capacity before mknodat publishes a FIFO, then record the
 * exact inode after creation. Missing birthtime leaves it unqualified. */
bool sparc64_linux_file_reserve_fifo(sparc64_linux_file_t *files);
void sparc64_linux_file_record_fifo(sparc64_linux_file_t *files, int directory_fd,
                               const char *leaf);

/* Call after consuming private image FDs and before any persistent internal
 * open could occupy missing standard descriptors. Absolute guest paths use
 * sysroot; relative paths use the current native cwd or a guest directory FD.
 * This is translation inside the runtime's host filesystem, not confinement. */
bool sparc64_linux_file_init(sparc64_linux_file_t *files, sparc64_space_t *space, const char *sysroot);
/* Runtime startup: prepare other resources before consuming the plain initial
 * FD owner. Failure leaves *initial intact for startup diagnostics/cleanup. */
bool sparc64_linux_file_init_initial(sparc64_linux_file_t *files, sparc64_space_t *space,
                                 const char *sysroot, sparc64_fd_initial_t **initial);
void sparc64_linux_file_destroy(sparc64_linux_file_t *files);
/* Child-only after native fork and descriptor rebase. Reset copied resolver
 * resources without copied pthread operations; then child-memory start may
 * register its fresh family observer on files->paths. On successful memory
 * commit, bind the image-owned file registry. The wrapper borrows that
 * registry until guest-memory stop destroys the image. */
int sparc64_linux_file_fork_child_resolver_rebase(sparc64_linux_file_t *files);
int sparc64_linux_file_bind_child_image(sparc64_linux_file_t *files, sparc64_space_t *space,
                                   sparc64_file_registry_t *registry);
/* True means this syscall belongs to the implemented file dispatch surface,
 * including deliberate errors for unsupported commands/flags. */
bool sparc64_linux_file_dispatch(sparc64_linux_file_t *files, uint64_t number,
                            const uint64_t arguments[6], uint64_t *result);
/* Explicit worker I/O; NULL selects a snapshot of the process defaults.
 * All descriptor/path/memory operations still require the caller's guard.
 * Only callbacks explicitly marked releasing may drop that ownership. */
bool sparc64_linux_file_dispatch_io(sparc64_linux_file_t *files,
                               const sparc64_linux_file_io_t *io, uint64_t number,
                               const uint64_t arguments[6], uint64_t *result);
uint64_t sparc64_linux_file_mmap(sparc64_linux_file_t *files, sparc64_linux_memory_t *memory,
                           const uint64_t arguments[6]);

#endif
