/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SPARC64RT_LINUX_IO_H
#define SPARC64RT_LINUX_IO_H

#include "memory/space.h"

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

typedef ssize_t (*sparc64_linux_write_fn)(int fd, const void *bytes, size_t size,
                                    void *context);
typedef struct sparc64_owned_io_registry sparc64_owned_io_registry_t;
typedef struct sparc64_owned_io_flight sparc64_owned_io_flight_t;

/* One logical write, even if a mapped source fault ended the captured prefix.
 * bytes remains owned and immutable until the callback returns. An ordinary
 * source fault may make valid_size zero; numeric and resource failures never
 * invoke the callback. The callback may publish only the valid prefix. */
typedef struct {
    const void *bytes;
    size_t valid_size;
    size_t logical_size;
} sparc64_linux_write_request_t;
typedef ssize_t (*sparc64_linux_write_request_fn)(int fd,
                                              const sparc64_linux_write_request_t *request,
                                              void *context);

/* Current short-write slice: stdout/stderr only, at most 64 KiB is staged
 * and passed to one host write. R4/R5 will extend the I/O lifecycle. */
uint64_t sparc64_linux_writev(sparc64_space_t *space, uint64_t fd,
                         uint64_t iov_address, uint64_t iov_count);
/* The caller owns a private native descriptor lease. No guest integer may be
 * passed here without resolving it through the virtual descriptor table. */
uint64_t sparc64_linux_writev_fd(sparc64_space_t *space, int native_fd,
                            uint64_t iov_address, uint64_t iov_count);
/* Production writer hook after validation/staging, for mapped-file coherence. */
uint64_t sparc64_linux_writev_fd_with_writer(sparc64_space_t *space, int native_fd,
                                        uint64_t iov_address, uint64_t iov_count,
                                        sparc64_linux_write_fn writer, void *context);
/* Same importer with a logical total limit, checked before payload staging or
 * writer invocation. full_stage preserves a complete logical pipe write as
 * one callback transaction; false keeps the current 64 KiB staging prefix. */
uint64_t sparc64_linux_writev_fd_with_writer_limit(sparc64_space_t *space, int native_fd,
                                               uint64_t iov_address,
                                               uint64_t iov_count,
                                               sparc64_linux_write_fn writer,
                                               void *context, size_t maximum,
                                               bool full_stage);
/* The request callback receives the original capped total after an ordinary
 * mapped fault; it takes precedence over the legacy byte callback and forces
 * full logical staging even when full_stage is false. */
uint64_t sparc64_linux_writev_fd_with_request_limit(sparc64_space_t *space, int native_fd,
                                                uint64_t iov_address,
                                                uint64_t iov_count,
                                                sparc64_linux_write_fn writer,
                                                void *writer_context,
                                                sparc64_linux_write_request_fn request,
                                                void *request_context,
                                                size_t maximum, bool full_stage);
/* Same import with an owned token-free callback flight. Numeric/vector
 * validation occurs before registry publication. A published *flight_slot
 * owns the native_fd and staging until the outer file dispatcher finishes it
 * after guarded callback completion. */
uint64_t sparc64_linux_writev_fd_with_request_limit_owned(
    sparc64_space_t *space, int native_fd, uint64_t iov_address, uint64_t iov_count,
    sparc64_linux_write_fn writer, void *writer_context,
    sparc64_linux_write_request_fn request, void *request_context,
    size_t maximum, bool full_stage,
    sparc64_owned_io_registry_t *registry, sparc64_owned_io_flight_t **flight_slot);

/* Test seam: identical guest validation and staging with a controlled writer.
 * The caller supplies a sink already validated for write access. */
uint64_t sparc64_linux_writev_with_writer(sparc64_space_t *space, uint64_t fd,
                                     uint64_t iov_address, uint64_t iov_count,
                                     sparc64_linux_write_fn writer, void *context);

#endif
