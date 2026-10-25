/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SPARC64RT_LINUX_FILE_SPLIT_H
#define SPARC64RT_LINUX_FILE_SPLIT_H

/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L
#define _XOPEN_SOURCE 700
#if defined(__APPLE__)
#define _DARWIN_C_SOURCE 1
#endif
#include "linux/file.h"
#include "runtime/owned_io.h"
#include "linux/codec.h"
#include "linux/error.h"
#include "linux/io.h"
#include "linux/metadata.h"
#include "linux/directory.h"
#include "linux/path.h"
#include "linux/pipe.h"
#include "linux/poll.h"
#include "linux/socket.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>

#define G_AT_FDCWD UINT32_C(0xffffff9c)
#define IO_STAGE ((size_t)65536)
#define MAX_RW_COUNT UINT64_C(0x7ffff000)

_Static_assert(sizeof(off_t) == 8, "runtime requires native 64-bit file offsets");

typedef struct {
    sparc64_linux_file_t *files;
    const sparc64_linux_file_io_t *io;
    bool confirmed;
} open_truncate_context_t;

typedef struct {
    sparc64_linux_file_t *files;
    bool positioned;
    int64_t position;
    sparc64_linux_write_fn writer;
    void *writer_context;
} managed_write_t;

typedef struct {
    sparc64_linux_write_request_fn callback;
    void *context;
} canonical_writev_context_t;

/* Cross-part declarations (generated L0a split). */
bool sparc64_linux_file_reserve_fifo(sparc64_linux_file_t *files);
void sparc64_linux_file_record_fifo(sparc64_linux_file_t *files, int directory_fd, const char *leaf);
uint64_t failure(unsigned int linux_errno);
uint64_t host_failure(int host_errno);
int duplicate_borrowed_fd(const sparc64_fd_borrow_t *borrowed);
int64_t signed_word(uint64_t word);
bool sparc64_linux_file_init(sparc64_linux_file_t *files, sparc64_space_t *space, const char *sysroot);
bool sparc64_linux_file_init_initial(sparc64_linux_file_t *files, sparc64_space_t *space, const char *sysroot, sparc64_fd_initial_t **initial);
void sparc64_linux_file_destroy(sparc64_linux_file_t *files);
int sparc64_linux_file_fork_child_resolver_rebase(sparc64_linux_file_t *files);
int sparc64_linux_file_bind_child_image(sparc64_linux_file_t *files, sparc64_space_t *space, sparc64_file_registry_t *registry);
uint64_t sparc64_linux_file_mmap(sparc64_linux_file_t *files, sparc64_linux_memory_t *memory, const uint64_t arguments[6]);
uint64_t open_file(sparc64_linux_file_t *files, const sparc64_linux_file_io_t *io, const uint64_t arguments[6]);
uint64_t change_directory(sparc64_linux_file_t *files, uint64_t address);
bool path_descriptor(int flags);
ssize_t managed_write(int native_fd, const void *bytes, size_t size, void *opaque);
uint64_t transfer(sparc64_linux_file_t *files, const sparc64_linux_file_io_t *io, const uint64_t arguments[6], bool writing, bool positioned);
bool sparc64_linux_file_dispatch(sparc64_linux_file_t *files, uint64_t number, const uint64_t arguments[6], uint64_t *result);
bool sparc64_linux_file_dispatch_io(sparc64_linux_file_t *files, const sparc64_linux_file_io_t *io, uint64_t number, const uint64_t arguments[6], uint64_t *result);

#endif /* SPARC64RT_LINUX_FILE_SPLIT_H */
