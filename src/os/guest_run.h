/*
 * src/os/guest_run.h — SPARC64 guest runner entry point (Phase 1, L1c)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Loads an ELF64-BE EM_SPARCV9 image through the rt64 memory substrate,
 * synthesizes the _start stack, and runs the reference interpreter until
 * a terminal syscall or a trap. New files only: the coordinator wires this
 * hook into src/main.c after the lanes merge.
 */

#ifndef SPARC64RT_OS_GUEST_RUN_H
#define SPARC64RT_OS_GUEST_RUN_H

/* Run the guest at path with argv (argv[0] names the program, like
 * execv; NULL argv synthesizes one from path). interp_only selects the
 * reference interpreter; a zero value runs the DBT engine. Returns the
 * guest exit status, or 1 on runner error. */
int sparc64_guest_run(const char *path, char **argv, int interp_only);

/* Engine dispatch: 0 = reference interpreter, 1 = AArch64 DBT,
 * 2 = lockstep difftest (prints the divergence report; returns the
 * guest exit status on a divergence-free run). */
int sparc64_guest_run_engine(const char *path, char **argv, int engine);

#endif /* SPARC64RT_OS_GUEST_RUN_H */
