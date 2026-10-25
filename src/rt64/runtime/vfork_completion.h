/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SPARC64RT_RUNTIME_VFORK_COMPLETION_H
#define SPARC64RT_RUNTIME_VFORK_COMPLETION_H

#include <stdbool.h>

/* Private native shared-MM process channel. Neither endpoint enters the guest
 * FD table. The parent owns reader; the child owns writer through MM JOIN and,
 * for vfork, across native exec. Creation yields distinct >=3 CLOEXEC FDs. */
int sparc64_vfork_completion_pair(int *out_reader, int *out_writer);
/* Reestablish private CLOEXEC on the exact inherited writer before admitting
 * any new guest execution. Does not consume it on failure. */
int sparc64_vfork_completion_adopt(int writer);

/* Child sends JOIN only after its same-MM member is durably visible. Plain
 * CLONE_VM closes writer afterward; vfork retains it through failed exec. */
int sparc64_vfork_completion_join(int writer);

/* The caller has released its scheduler turn and family guard. Plain clone
 * waits for JOIN (or child-exit EOF); vfork then waits for exec replay E or
 * child-exit EOF. completed means JOIN for plain clone, replay for vfork.
 * This never consumes the child's wait status. Caller closes reader. */
int sparc64_vfork_completion_wait(int reader, bool wait_exec, bool *completed);
/* While a parent is semantically blocked, service must acknowledge native
 * quiescence requests without resuming guest execution. A non-NULL service
 * runs before every bounded readiness wait. A service return of 1 means the
 * caller's scheduler is terminal: stop waiting without claiming child replay.
 * A return of -1 is an infrastructure error. */
typedef int (*sparc64_vfork_wait_service_fn)(void *context);
int sparc64_vfork_completion_wait_service(int reader, bool wait_exec, bool *completed,
                                     sparc64_vfork_wait_service_fn service,
                                     void *context);

/* Only the successful exec receiver calls this after replay and owner-selective
 * old-MM retirement. EPIPE means its native parent died; it is not a child
 * failure. The caller remains responsible for closing writer. */
int sparc64_vfork_completion_signal(int writer);

#endif
