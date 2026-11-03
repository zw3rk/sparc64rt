/*
 * src/os/syscalls_min.h — Minimal SPARC64 Linux syscall layer (Phase 1, L1c)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Declares the Phase-1 syscall subset implemented in src/os/syscalls_min.c:
 * exit(1), exit_group(188), read(3), write(4), brk(17), mmap(71),
 * munmap(73), mprotect(74), uname(189), set_tid_address(166).
 *
 * The layer is deliberately decoupled from the address-space substrate so
 * it compiles with -Isrc alone: all guest-memory effects go through the
 * sparc64_syscall_mem_t operations implemented by src/os/guest_run.c over
 * the rt64 memory substrate. do_* handlers return a host-style result
 * (>= 0 value, negative host errno); copy helpers return true on success
 * (false reads as -EFAULT).
 */

#ifndef SPARC64RT_OS_SYSCALLS_MIN_H
#define SPARC64RT_OS_SYSCALLS_MIN_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "core/cpu.h"

/* Guest-memory operations backing the Phase-1 subset. context is the
 * runner-owned state (address space, brk, tid slot); every handler
 * threads it through. prot carries SPARC PROT_* bits (1/2/4). */
typedef struct sparc64_syscall_mem sparc64_syscall_mem_t;
struct sparc64_syscall_mem {
    void *context;
    bool (*read)(void *context, uint64_t va, void *host, uint64_t len);
    bool (*write)(void *context, uint64_t va, const void *host,
                  uint64_t len);
    bool (*prepare_write)(void *context, uint64_t va, uint64_t len);
    long (*do_mmap)(void *context, uint64_t addr, uint64_t len,
                    unsigned prot, unsigned flags, int fd, uint64_t offset);
    long (*do_munmap)(void *context, uint64_t addr, uint64_t len);
    long (*do_mprotect)(void *context, uint64_t addr, uint64_t len,
                       unsigned prot);
    long (*do_brk)(void *context, uint64_t addr);
    long (*set_tid_address)(void *context, uint64_t va);
};

/* Nonzero when nr names a terminal exit (exit/exit_group). */
int sparc64_syscall_is_exit(long nr);
/* Nonzero only for exit_group (whole-process exit). A plain exit from a
 * CLONE_VM thread ends just that thread and must not arm group exit. */
int sparc64_syscall_is_group_exit(long nr);

/* Short name for nr, or NULL when out of range. */
const char *sparc64_syscall_name(long nr);

/* Process-wide guest syscall dispatch count for --stats (Phase 6, L6a):
 * every sparc64_handle_syscall dispatch (all engines, all threads). */
unsigned long long sparc64_syscalls_dispatched(void);

/* Host errno -> SPARC guest errno (asm-generic numbers except where
 * arch/sparc overrides; ENOSYS is 90 on SPARC). Shared by
 * src/os/syscalls_min.c and src/os/syscalls_sig.c. */
uint64_t sparc64_host_errno_to_guest(long host_errno);

/* Commit one handler result to %o0/ccr following the frozen dual-carry
 * convention: negative host errno fails with both carries set, anything
 * else succeeds with both carries clear (N/Z/V preserved). Shared by
 * src/os/syscalls_min.c and src/os/syscalls_sig.c. */
void sparc64_commit_sysret(sparc64_ctx_t *ctx, long ret);

/* Dispatch the syscall in %g1 (args %o0..%o5), commit the SPARC64 carry
 * convention (E02/SPEC section 2.2: success clears both icc.C and xcc.C,
 * error sets both, other CCR bits preserved; %o0 carries the value or
 * the positive SPARC errno), and advance pc = npc; npc += 4. Returns the
 * guest exit status for exit/exit_group (terminal), 0 otherwise. */
long sparc64_handle_syscall(sparc64_ctx_t *ctx,
                            const sparc64_syscall_mem_t *mem);

#endif /* SPARC64RT_OS_SYSCALLS_MIN_H */
