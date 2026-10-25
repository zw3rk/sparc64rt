/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SPARC64RT_RUNTIME_INODE_PINS_H
#define SPARC64RT_RUNTIME_INODE_PINS_H

#include <stdint.h>

/* A private kernel queue retains regular-file references for a managed family.
 * All attachments must retain BOTH ends through fork and same-PID exec. No
 * production caller may receive from either end, export it to guest code, or
 * shut it down. The final endpoint close releases the kernel-owned references.
 * This owner supplies lifetime only, never an inode-equivalence test. */
typedef struct {
    int sender;
    int receiver;
} sparc64_inode_pins_t;

#define SPARC64_INODE_PINS_INITIALIZER {-1, -1}
#define SPARC64_INODE_PINS_MAX_ATTEMPTS UINT64_C(4096)

/* Initialize a fresh owner. Private descriptors are CLOEXEC and >=3 even when
 * native stdio is closed. On failure the destination stays empty. */
int sparc64_inode_pins_create(sparc64_inode_pins_t *out);
/* Consume distinct owned queue endpoints on every outcome. This is a trusted
 * fork/exec capability handoff, not discovery or authentication of arbitrary
 * native sockets. Restore CLOEXEC before returning the fresh owner. */
int sparc64_inode_pins_adopt(sparc64_inode_pins_t *out, int sender, int receiver);
void sparc64_inode_pins_close(sparc64_inode_pins_t *pins);

/* Caller holds the family's uninterrupted guard. attempts must point to its
 * shared, persistent, monotonic attempt counter, never a process-local copy.
 * Charge BEFORE sendmsg, including failures and interrupted/crashed producers.
 * Never refund a charge: a killed producer may have queued an unrecorded pin.
 * The queue is also bounded by native socket/in-flight-FD limits. This call
 * does not wait for capacity, retry, allocate, duplicate, or close source_fd.
 * A successful return pins the exact regular file while any receiver survives.
 * Publish its inode-key record only AFTER success. Returned native errors must
 * remain visible; exhaustion must not fall back to an unpinned identity. */
int sparc64_inode_pins_keep(const sparc64_inode_pins_t *pins, int source_fd,
                       uint64_t *attempts);

#ifdef SPARC64_INODE_PINS_TESTING
typedef enum {
    SPARC64_INODE_PINS_CHARGED,
    SPARC64_INODE_PINS_ENQUEUED
} sparc64_inode_pins_test_point_t;
typedef void (*sparc64_inode_pins_test_hook_t)(sparc64_inode_pins_test_point_t, void *);
void sparc64_inode_pins_test_set_hook(sparc64_inode_pins_test_hook_t hook, void *context);
#endif

#endif
