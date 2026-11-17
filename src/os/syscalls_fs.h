/*
 * src/os/syscalls_fs.h — Path/attribute/limit/wait syscall tail
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SPARC64RT_OS_SYSCALLS_FS_H
#define SPARC64RT_OS_SYSCALLS_FS_H

#include <stdint.h>

#include "core/cpu.h"
#include "os/syscalls_min.h"

/* Dispatch tail for the legacy fs/misc family. *claimed is set to 1
 * when nr was handled (the return is a host-style result) and 0 when
 * the caller keeps its -ENOSYS default. */
long sparc64_l2a_fs_extra(sparc64_ctx_t *ctx, const sparc64_syscall_mem_t *mem,
                          long nr, uint64_t o0, uint64_t o1, uint64_t o2,
                          uint64_t o3, uint64_t o4, int *claimed);

/* fcntl F_GETLK/F_SETLK/F_SETLKW (sparc64 cmds 7/8/9). */
long sparc64_fs_fcntl_lock(const sparc64_syscall_mem_t *mem, uint64_t fd,
                           uint64_t cmd, uint64_t arg);

#endif /* SPARC64RT_OS_SYSCALLS_FS_H */
