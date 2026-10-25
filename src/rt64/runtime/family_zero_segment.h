/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SPARC64RT_FAMILY_ZERO_SEGMENT_H
#define SPARC64RT_FAMILY_ZERO_SEGMENT_H

#include <stddef.h>
#include <stdint.h>

#define SPARC64_FAMILY_ZERO_SEGMENT_WIRE_SIZE 56u
#define SPARC64_FAMILY_ZERO_SEGMENT_PREFIX 4096u
#define SPARC64_FAMILY_ZERO_SEGMENT_CONTROL 1u
#define SPARC64_FAMILY_ZERO_SEGMENT_OBJECT 2u
#define SPARC64_FAMILY_ZERO_SEGMENT_CONTROL_FRAGMENT 3u

typedef struct sparc64_family_zero_segment {
    int shmid;
    void *base;
    void *payload;
    size_t payload_size;
    uint8_t descriptor[SPARC64_FAMILY_ZERO_SEGMENT_WIRE_SIZE];
} sparc64_family_zero_segment_t;

/* Linux-only initial backend. A successful creator marks the segment for
 * removal while retaining its own attachment; a live attachment is required
 * before another process can attach by the nonce-bound descriptor. This does not
 * claim power-loss durability or cleanup of SIGKILL between shmget and shmat.
 * The caller must retain an owner attachment while any canonical key names
 * this segment. No guest-controlled descriptor is accepted. */
int sparc64_family_zero_segment_create(uint32_t kind, uint64_t object_id,
                                  size_t payload_size,
                                  sparc64_family_zero_segment_t *out);
int sparc64_family_zero_segment_attach(
    const uint8_t descriptor[SPARC64_FAMILY_ZERO_SEGMENT_WIRE_SIZE],
    uint32_t kind, uint64_t object_id, size_t payload_size,
    sparc64_family_zero_segment_t *out);
void sparc64_family_zero_segment_detach(sparc64_family_zero_segment_t *segment);

/* The caller owns an exact zero-length inode FD. Publish once before the
 * canonical root names the segment; a failed publication leaves an unreachable
 * marked segment that is removed when its retained attachment is detached.
 * Neither function opens or closes the caller's FD. */
int sparc64_family_zero_segment_publish_fd(int fd,
                                      const sparc64_family_zero_segment_t *segment);
int sparc64_family_zero_segment_attach_fd(int fd, uint32_t kind,
                                     uint64_t object_id, size_t payload_size,
                                     sparc64_family_zero_segment_t *out);

#endif
