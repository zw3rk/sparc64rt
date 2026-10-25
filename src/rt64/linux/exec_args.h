/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SPARC64RT_LINUX_EXEC_ARGS_H
#define SPARC64RT_LINUX_EXEC_ARGS_H

#include "memory/space.h"

#include <stddef.h>
#include <stdint.h>

#define SPARC64_LINUX_EXEC_PATH_MAX ((size_t)4096)
#define SPARC64_LINUX_EXEC_VECTOR_MAX ((size_t)2048)
#define SPARC64_LINUX_EXEC_BYTES_MAX ((size_t)131072)

/* Owned copies of guest execve inputs. Initialize to {0} before first read.
 * Do not read into an object that still owns a snapshot; destroy it first.
 * This object is process-local and is not a serialized Linux stack image. */
typedef struct sparc64_linux_exec_args {
    char *path;
    char **argv;
    char **envp;
    size_t argc;
    size_t envc;
} sparc64_linux_exec_args_t;

/* Copy RV64 little-endian guest pointers and strings while the caller still
 * holds the guest-memory guard. Returns zero or a guest-negative Linux errno.
 * NULL argv or an explicit empty argv vector synthesizes argv[0]=""; NULL
 * envp denotes an empty environment.
 * Successful results own both NULL-terminated vectors, including empty ones.
 * On failure, all temporary allocations are freed and out is empty. */
uint64_t sparc64_linux_exec_args_read(sparc64_space_t *space, uint64_t path,
                                 uint64_t argv, uint64_t envp,
                                 sparc64_linux_exec_args_t *out);
/* Copy trusted host launch vectors with the same bounds/ownership contract.
 * argc=0 synthesizes empty argv[0]; NULL envp is empty. Path is guest execfn,
 * independent of the native image pathname. out must be unused or destroyed. */
uint64_t sparc64_linux_exec_args_copy(const char *path, int argc,
                                 char *const argv[], char *const envp[],
                                 sparc64_linux_exec_args_t *out);
void sparc64_linux_exec_args_destroy(sparc64_linux_exec_args_t *args);
/* Replace argv[0] with interpreter, optional single opaque argument, script
 * and old argv[1..]. Preserve original path/AT_EXECFN and envp. Transactional
 * on failure, enforcing the same vector and copied-string budget as read. */
uint64_t sparc64_linux_exec_args_script(sparc64_linux_exec_args_t *args,
                                   const char *interpreter,
                                   const char *optional_argument,
                                   const char *script);

#endif
