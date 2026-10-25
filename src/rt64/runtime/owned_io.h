/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SPARC64RT_RUNTIME_OWNED_IO_H
#define SPARC64RT_RUNTIME_OWNED_IO_H

#include "memory/space.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <poll.h>
#include <sys/types.h>

typedef struct sparc64_owned_io_flight sparc64_owned_io_flight_t;
typedef struct sparc64_owned_io_registry {
    sparc64_owned_io_flight_t *head;
    pid_t creator_pid;
} sparc64_owned_io_registry_t;

/* The creator serializes begin/finish under its family guard. The record owns
 * the exact native descriptor lease, immutable staging, pinned destination
 * plan and optional native fault suffix after begin succeeds. Worker callback
 * frames borrow these resources and must finish under the guard. No registry
 * mutex or worker stack is needed for child-only disposal after fork. */
void sparc64_owned_io_registry_init(sparc64_owned_io_registry_t *registry);
bool sparc64_owned_io_registry_empty(const sparc64_owned_io_registry_t *registry);
int sparc64_owned_io_begin(sparc64_owned_io_registry_t *registry, int lease,
                      void *staging, sparc64_copyout_t *copyout,
                      sparc64_io_copyout_t *io_copyout,
                      sparc64_owned_io_flight_t **out);
/* Transfer an allocated poll vector, all its nonnegative descriptor leases,
 * and optional wire/bitset staging only on success. Negative entries must
 * equal -1; each nonnegative entry owns one distinct native duplicate.
 * Register before any poll callback releases the family guard, and finish
 * after its final return under that guard. Zero-count/null vectors are valid. */
int sparc64_owned_io_begin_poll(sparc64_owned_io_registry_t *registry,
                           struct pollfd *descriptors, size_t count,
                           void *staging, sparc64_owned_io_flight_t **out);
int sparc64_owned_io_adopt_staging(sparc64_owned_io_flight_t *flight, void *staging);
int sparc64_owned_io_adopt_mapping(sparc64_owned_io_flight_t *flight,
                              void *mapping, size_t length);
/* Finish consumes the record on its creator process with the family guard.
 * Any post-free native cleanup error is fatal because I/O may be committed. */
void sparc64_owned_io_finish(sparc64_owned_io_flight_t **owned);
/* Child-only, after native capture registration is sealed across fork and
 * all other native threads are gone. No copied callback may resume in the
 * child. Discard copied capabilities BEFORE copied space/file/backing owners.
 * This cannot touch inherited pthread locks, guards, callbacks or stacks.
 * The registry's creator PID rejects same-process abandonment; the caller
 * must enforce the native registration seal and child teardown order.
 * The parent COW copy and its suspended callbacks stay live and resumable. */
int sparc64_owned_io_abandon_child(sparc64_owned_io_registry_t *registry);

#ifdef SPARC64_RUNTIME_TEST_EXEC_SUSPENDED_IO
typedef struct {
    uintptr_t flight;
    uintptr_t staging;
    uintptr_t copyout;
    uintptr_t mapping;
    size_t mapping_length;
    int lease;
    dev_t device;
    ino_t inode;
} sparc64_owned_io_test_read_t;
/* Compile-only observation under the family guard and complete exec seals.
 * Validate exact retained FIFO read leases and pinned destination plans. */
int sparc64_owned_io_test_reads(const sparc64_owned_io_registry_t *registry,
                           uint32_t *count, sparc64_owned_io_test_read_t *first);
#endif

#endif
