/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SPARC64RT_RUNTIME_INITIAL_IMAGE_H
#define SPARC64RT_RUNTIME_INITIAL_IMAGE_H

#include "linux/exec_args.h"
#include "loader/image.h"
#include "runtime/image_expectation.h"

typedef struct {
    sparc64_linux_exec_args_t args;
    sparc64_prepared_program_t *program;
} sparc64_initial_image_t;

/* Consumes a nonnegative owned_image_fd, including 0, except the borrowed
 * runtime_fd, which is left open. Otherwise opens
 * target_path literally. Initial explicit sources need read access, while
 * interpreters require execute access. Never reopen a supplied image path.
 * execfn NULL defaults to literal target_path, independent of argv[0].
 * The borrowed runtime_fd is private >=3 and protected in the temporary
 * resolver. out must be {0}/destroyed. On failure out is empty. */
bool sparc64_initial_image_prepare(const char *target_path, int owned_image_fd,
                               const char *execfn, const char *sysroot,
                               int runtime_fd, int argc, char *const argv[],
                               char *const envp[], sparc64_initial_image_t *out,
                               char *error, size_t error_size);
/* With an expectation, capture the original object once and check its owned
 * bytes before ELF/PT_INTERP parsing. It must be an ELF, never a script to
 * follow. NULL expectation preserves the ordinary initial-script behavior.
 * Descriptor consumption and output ownership match prepare above. */
bool sparc64_initial_image_prepare_expected(const char *target_path, int owned_image_fd,
                               const char *execfn, const char *sysroot,
                               int runtime_fd, int argc, char *const argv[],
                               char *const envp[],
                               const sparc64_image_expectation_t *expected,
                               sparc64_initial_image_t *out,
                               char *error, size_t error_size);
void sparc64_initial_image_destroy(sparc64_initial_image_t *image);

#endif
