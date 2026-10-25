/*
 * src/os/guest_run_priv.h — shared guest-runner internals (coordinator)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Private bridge between src/os/guest_run.c (loading, entries),
 * src/os/guest_stack.c (_start stack synthesis), and
 * src/os/guest_engines.c (interp/dbt/difftest run loops). Not a
 * public API; all three TUs include it.
 */

#ifndef SPARC64RT_OS_GUEST_RUN_PRIV_H
#define SPARC64RT_OS_GUEST_RUN_PRIV_H

#include <stdint.h>

#include "core/cpu.h"
#include "dbt/dbt.h"
#include "os/syscalls_min.h"
#include "rt64/memory/space.h"

typedef struct {
    sparc64_space_t space;
    int space_live;
    uint64_t brk_base;
    uint64_t brk_cur;
    uint64_t tid_addr;
    long host_tid;
    /* Non-NULL while a DBT engine runs: mapping changes invalidate it. */
    struct sparc64_dbt *dbt;
} guest_state_t;

/* Guest ABI constants shared by the loader (guest_run.c) and the
 * _start stack synthesis (guest_stack.c). */
#define GUEST_PAGE_SIZE UINT64_C(4096)
#define GUEST_MAX_ARGC 256U

/* Loader outcomes: positive errno-style values without depending on
 * host-specific codes (ELIBBAD exists on Linux only). */
enum {
    LOAD_OK = 0,
    LOAD_BAD = 1,
    LOAD_INTERP = 2,
    LOAD_IO = 3,
    LOAD_NOMEM = 4
};

/* Byte-level guest memory (interp steps, DBT fragments, difftest). */
extern const sparc64_mem_ops_t guest_mem_ops;

/* _start stack synthesis (guest_stack.c, E01): lay out
 * argc/argv/envp/auxv/strings and return the biased %sp. */
uint64_t count_strings(char **vec, uint64_t max);
int build_stack(guest_state_t *g, uint64_t phdr_va, uint64_t entry,
    uint64_t phnum, uint64_t phent, char **argv, uint64_t argc,
    uint64_t *sp_out);

/* Syscall memory/file/map layer over the same space. */
const sparc64_syscall_mem_t *sysmem_ops(guest_state_t *g,
    sparc64_syscall_mem_t *ops);

/* Full image replacement for execve(59) (guest_run.c, Phase 4 lane
 * L4c): destroys the current space, loads path with host argv (the
 * caller swaps the translator's environ to the guest envp across the
 * call; build_stack consumes it), and re-inits ctx at the new entry
 * with a fresh biased %sp and leaf windows. Keeps the host pid;
 * brk/tids reset; signals are the caller's job. Returns 0 or a
 * negative errno-style code (-ENOENT open, -ENOEXEC bad image,
 * -E2BIG/-ENOMEM stack/load limits, -EFAULT bad pointers). */
int sparc64_guest_exec_image(guest_state_t *g, sparc64_ctx_t *ctx,
    const char *path, char **argv);

/* Engine run loops (guest_engines.c). Each returns the guest exit
 * status, or 1 when the runner itself fails. */
int run_interp(guest_state_t *g, sparc64_ctx_t *ctx,
    const sparc64_syscall_mem_t *ops);
int run_dbt(guest_state_t *g, sparc64_ctx_t *ctx,
    const sparc64_syscall_mem_t *ops);
int run_difftest(guest_state_t *g, sparc64_ctx_t *ctx,
    const sparc64_syscall_mem_t *ops);

#endif /* SPARC64RT_OS_GUEST_RUN_PRIV_H */
