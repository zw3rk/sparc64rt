/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SPARC64RT_RUNTIME_EXEC_LAUNCH_H
#define SPARC64RT_RUNTIME_EXEC_LAUNCH_H

#include "linux/fd_handoff.h"
#include "loader/image.h"
#include "runtime/exec_state.h"
#include "runtime/diagnostic.h"
#include "runtime/file_service_owner.h"

typedef struct {
    int state, image, descriptors, control, directory, runtime;
    int pin_sender, pin_receiver, diagnostic, source_request, source_lifetime;
    int parent_cap;
#ifdef SPARC64_RUNTIME_TEST_ATTRIBUTED_FILE
    int service_pidfd, service_observer, vfork_completion;
#endif
    int entries[SPARC64_FD_TABLE_LIMIT];
    size_t count;
} sparc64_exec_caps_t;

/* The CLI version changes with its capability vector or exec-state schema.
 * Never reinterpret an older handoff's descriptor words or child roles. */
#ifdef SPARC64_RUNTIME_TEST_ATTRIBUTED_FILE
#define SPARC64_EXEC_RESUME_FLAG "--resume-v11"
#define SPARC64_EXEC_FIXED_CAPS 15u
#else
#define SPARC64_EXEC_RESUME_FLAG "--resume-v9"
#define SPARC64_EXEC_FIXED_CAPS 12u
#endif

/* Private native startup argv, never guest argv. Eight required roles precede
 * optional diagnostic and optional source request/lifetime pair. The pair is
 * either entirely present or both -1. Present capabilities are distinct >=3.
 * The descriptor vector is bounded; -1 never denotes a guest descriptor.
 * A rejected command leaves out unchanged and takes no individual FD owner. */
/* Internal numeric vector validation shared by encoder and parser. */
bool sparc64_exec_caps_distinct(const int *values, size_t count);
bool sparc64_exec_caps_parse(int argc, char *const argv[], sparc64_exec_caps_t *out);
void sparc64_exec_caps_close(sparc64_exec_caps_t *caps);
/* Retain a private CLOEXEC descriptor for this static AArch64 PIE. Linux
 * procfs pins the running image; the explicit host bootstrap argv0 is the
 * fallback when that host does not provide procfs. Call before guest stdio
 * import and register the resulting inode before exposing guest paths. */
int sparc64_exec_pin_runtime(const char *bootstrap_argv0);
bool sparc64_exec_runtime_valid(int descriptor);
/* Complete scheduler/I/O/memory/native-registration quiescence is required.
 * Does not return on success. A returning native exec restores every changed
 * FD flag before returning -1/errno. Any uncertain rollback exits125. Owners
 * and all old guest state remain alive for the caller's abort path. */
int sparc64_exec_launch(int runtime_fd, sparc64_diagnostic_t *diagnostic,
                     sparc64_exec_state_export_t *state,
                     sparc64_program_export_t *image, sparc64_fd_handoff_t *files,
                     sparc64_family_exec_t *family,
                     int parent_cap_fd,
                     const sparc64_file_service_owner_t *service_owner,
                     int vfork_completion_fd);

#endif
