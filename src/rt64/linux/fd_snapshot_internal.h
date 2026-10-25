/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SPARC64RT_LINUX_FD_SNAPSHOT_INTERNAL_H
#define SPARC64RT_LINUX_FD_SNAPSHOT_INTERNAL_H

/* Private representation shared only by the table snapshot and exec codec.
 * Public callers keep sparc64_fd_snapshot_t opaque. Native leases are capabilities,
 * never integers decoded from untrusted metadata. */
#include "linux/fd.h"

#define SPARC64_FD_SNAPSHOT_VERSION UINT32_C(2)

typedef struct {
    uint32_t guest_fd;
    uint32_t description_index;
    uint32_t hidden_status_flags;
    uint8_t guest_cloexec;
    uint8_t reserved[3];
} sparc64_fd_snapshot_entry_t;

typedef struct {
    uint64_t id;
    uint8_t logical_read_only;
    uint8_t pipe_writer;
    uint8_t pipe_endpoint;
    uint8_t fifo_writer;
    uint8_t fifo_endpoint;
    uint8_t reserved[3];
} sparc64_fd_snapshot_description_t;

struct sparc64_fd_snapshot {
    uint32_t version;
    uint32_t entry_count;
    uint32_t description_count;
    uint32_t reserved;
    uint64_t next_description_id;
    sparc64_fd_snapshot_entry_t *entries;
    sparc64_fd_snapshot_description_t *descriptions;
    int *leases;
};

#endif
