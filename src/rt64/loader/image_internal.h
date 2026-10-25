/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SPARC64RT_LOADER_IMAGE_INTERNAL_H
#define SPARC64RT_LOADER_IMAGE_INTERNAL_H

#include "loader/image.h"
#include <limits.h>
#include <sys/stat.h>

#define SPARC64_IMAGE_MAX_SIZE ((size_t)64 * 1024 * 1024)
#define SPARC64_IMAGE_LINUX_ERRNO_FROM_HOST UINT_MAX

typedef struct {
    unsigned char *bytes;
    size_t size;
} sparc64_object_snapshot_t;

typedef int (*sparc64_image_path_open_fn)(void *context, const char *path);

/* Reads one bounded regular object, including short script files, consumes
 * image_fd on every outcome. The caller owns snapshot.bytes on success. */
bool sparc64_object_snapshot_read(const char *path, int image_fd,
                            sparc64_object_snapshot_t *snapshot,
                            const struct stat *expected_version,
                            sparc64_image_path_open_fn open_path, void *open_context,
                            bool precise_errno, bool interpreter_object,
                            unsigned int *linux_error, char *error, size_t error_size);
/* Does not consume fd. Zero-padded first256 bytes, no script body size limit.
 * Final ELF snapshot must pass this version to detect intervening changes. */
bool sparc64_object_header_read(int fd, unsigned char header[256], struct stat *version);
/* Takes snapshot bytes once allocated; any bytes left in snapshot on failure
 * remain caller-owned. Validates final ELF and PT_INTERP without rereading it. */
bool sparc64_program_prepare_snapshot(sparc64_object_snapshot_t *snapshot, const char *sysroot,
                            bool validate_combined_placement,
                            sparc64_image_path_open_fn open_path, void *open_context,
                            bool precise_errno, sparc64_prepared_program_t **out,
                            unsigned int *linux_error,
                            char *error, size_t error_size);
int sparc64_image_open_guest_path(void *context, const char *path);

/* Internal loader entry used by protected guest paths. The callback returns
 * an owned descriptor or -1 with errno preserved. */
bool sparc64_program_prepare_with_opener(const char *path, int owned_image_fd,
                                    const char *sysroot,
                                    sparc64_image_path_open_fn open_path,
                                    void *open_context,
                                    sparc64_prepared_program_t **out,
                                    unsigned int *linux_error,
                                    char *error, size_t error_size);

struct sparc64_prepared_program {
    sparc64_object_snapshot_t target;
    sparc64_object_snapshot_t interpreter;
    bool has_interpreter;
};

/* Validate imported owned bytes jointly in a disposable fresh RV64 space.
 * On failure the caller still owns and must destroy the prepared object. */
bool sparc64_prepared_validate(const sparc64_prepared_program_t *prepared,
                           char *error, size_t error_size);

#endif
