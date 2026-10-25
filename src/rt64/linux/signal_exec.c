/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#include "linux/signal_exec.h"

#include <errno.h>
#include <string.h>

#define SIGNAL_COUNT 64U
#define SIGKILL_NUMBER 9U
#define SIGSTOP_NUMBER 19U

static uint64_t signal_bit(unsigned int signal)
{
    return UINT64_C(1) << (signal - 1U);
}

static uint32_t info_signo(const unsigned char information[128])
{
    return (uint32_t)information[0] |
           (uint32_t)information[1] << 8 |
           (uint32_t)information[2] << 16 |
           (uint32_t)information[3] << 24;
}

static bool mask_valid(uint64_t mask)
{
    return (mask & (signal_bit(SIGKILL_NUMBER) |
                    signal_bit(SIGSTOP_NUMBER))) == 0;
}

static bool pending_valid(uint64_t pending, const unsigned char *information)
{
    for (unsigned int signal = 1; signal <= SIGNAL_COUNT; ++signal) {
        if ((pending & signal_bit(signal)) != 0 &&
            info_signo(information + (signal - 1U) * 128U) != signal)
            return false;
    }
    return true;
}

bool sparc64_linux_signal_exec_state_valid(const sparc64_linux_signal_exec_state_t *state)
{
    return state != NULL && mask_valid(state->ignored) &&
           mask_valid(state->blocked) &&
           pending_valid(state->process_pending,
                         &state->process_information[0][0]) &&
           pending_valid(state->thread_pending,
                         &state->thread_information[0][0]);
}

static bool is_attached(const sparc64_linux_signals_t *caller)
{
    if (caller == NULL || caller->process == NULL)
        return false;
    for (const sparc64_linux_signals_t *worker = caller->process->workers;
         worker != NULL; worker = worker->next) {
        if (worker == caller)
            return true;
    }
    return false;
}

bool sparc64_linux_signal_exec_capture(const sparc64_linux_signals_t *caller,
                                   sparc64_linux_signal_exec_state_t *out)
{
    if (out == NULL || !is_attached(caller) ||
        !mask_valid(caller->thread.blocked) ||
        !pending_valid(caller->process->pending,
                       &caller->process->information[0][0]) ||
        !pending_valid(caller->thread.pending,
                       &caller->thread.information[0][0])) {
        errno = EINVAL;
        return false;
    }

    sparc64_linux_signal_exec_state_t captured = {0};
    for (unsigned int signal = 1; signal <= SIGNAL_COUNT; ++signal) {
        if (caller->process->actions[signal - 1U].handler == 1)
            captured.ignored |= signal_bit(signal);
    }
    if (!sparc64_linux_signal_exec_state_valid(&captured)) {
        errno = EINVAL;
        return false;
    }
    captured.blocked = caller->thread.blocked;
    captured.process_pending = caller->process->pending;
    captured.thread_pending = caller->thread.pending;
    for (unsigned int signal = 1; signal <= SIGNAL_COUNT; ++signal) {
        uint64_t bit = signal_bit(signal);
        if ((captured.process_pending & bit) != 0)
            memcpy(captured.process_information[signal - 1U],
                   caller->process->information[signal - 1U], 128);
        if ((captured.thread_pending & bit) != 0)
            memcpy(captured.thread_information[signal - 1U],
                   caller->thread.information[signal - 1U], 128);
    }
    *out = captured;
    return true;
}

bool sparc64_linux_signal_exec_restore(sparc64_signal_process_t *process,
                                   sparc64_linux_signals_t *worker,
                                   const sparc64_linux_signal_exec_state_t *state)
{
    if (process == NULL || worker == NULL || state == NULL ||
        worker->process != process || worker->next != NULL ||
        process->workers != worker || worker->guest_tid != process->pid ||
        !sparc64_linux_signal_exec_state_valid(state)) {
        errno = EINVAL;
        return false;
    }

    sparc64_signal_action_t reset_actions[SIGNAL_COUNT] = {{0}};
    for (unsigned int signal = 1; signal <= SIGNAL_COUNT; ++signal) {
        if ((state->ignored & signal_bit(signal)) != 0)
            reset_actions[signal - 1U].handler = 1;
    }

    memcpy(process->actions, reset_actions, sizeof(reset_actions));
    process->pending = state->process_pending;
    memset(process->information, 0, sizeof(process->information));
    for (unsigned int signal = 1; signal <= SIGNAL_COUNT; ++signal) {
        if ((state->process_pending & signal_bit(signal)) != 0)
            memcpy(process->information[signal - 1U],
                   state->process_information[signal - 1U], 128);
    }
    process->leader_blocked = state->blocked;

    worker->thread.blocked = state->blocked;
    worker->thread.pending = state->thread_pending;
    memset(worker->thread.information, 0, sizeof(worker->thread.information));
    for (unsigned int signal = 1; signal <= SIGNAL_COUNT; ++signal) {
        if ((state->thread_pending & signal_bit(signal)) != 0)
            memcpy(worker->thread.information[signal - 1U],
                   state->thread_information[signal - 1U], 128);
    }
    worker->thread.alternate = (sparc64_signal_stack_t){.flags = 2};
    worker->thread.saved_mask = 0;
    worker->thread.restore_mask = false;
    return true;
}
