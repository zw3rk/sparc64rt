/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SPARC64RT_LINUX_SIGNAL_EXEC_H
#define SPARC64RT_LINUX_SIGNAL_EXEC_H

#include "linux/signal.h"

/* Process-local snapshot only. This representation contains no borrowed
 * pointers and is not a transport or serialized wire format. Capture and
 * restore require the caller to hold the guest execution/quiescence guard. */
typedef struct {
    uint64_t ignored;
    uint64_t blocked;
    uint64_t process_pending;
    unsigned char process_information[64][128];
    uint64_t thread_pending;
    unsigned char thread_information[64][128];
} sparc64_linux_signal_exec_state_t;

/* Validate a pointer-free snapshot before publication or transport import. */
bool sparc64_linux_signal_exec_state_valid(const sparc64_linux_signal_exec_state_t *state);

/* Capture the process dispositions and shared pending queue plus the calling
 * thread's current effective mask and directed pending queue. This does not
 * consume signals or capture sigsuspend's saved mask. On failure, out is
 * unchanged. */
bool sparc64_linux_signal_exec_capture(const sparc64_linux_signals_t *caller,
                                   sparc64_linux_signal_exec_state_t *out);

/* Restore into a freshly initialized process with its sole attached TGID
 * worker. Identity, address space, trampoline, callbacks, and worker links
 * remain those of the new image. Caught/default actions reset, ignored
 * dispositions and both pending queues survive, and thread altstack and
 * sigsuspend state reset. Validation completes before any destination write. */
bool sparc64_linux_signal_exec_restore(sparc64_signal_process_t *process,
                                   sparc64_linux_signals_t *worker,
                                   const sparc64_linux_signal_exec_state_t *state);

#endif
