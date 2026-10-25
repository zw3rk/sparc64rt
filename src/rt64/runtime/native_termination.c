/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#define _GNU_SOURCE
#include "runtime/native_termination.h"

#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>
#if defined(__linux__)
#include <sys/syscall.h>
#endif

bool sparc64_native_termination_block(void)
{
    sigset_t all;
    if (sigfillset(&all) != 0)
        return false;
    int error = pthread_sigmask(SIG_SETMASK, &all, NULL);
    if (error != 0) {
        errno = error;
        return false;
    }
    return true;
}

_Noreturn void sparc64_native_termination_raise(int native_signal)
{
    /* A corrupt/nonfatal reason must fail rather than stop or wait forever.
     * Guest RT queuing and job control are outside this runtime profile. */
    if (native_signal <= 0 || native_signal >= 32 ||
        native_signal == SIGSTOP || native_signal == SIGTSTP ||
        native_signal == SIGTTIN || native_signal == SIGTTOU ||
        native_signal == SIGCONT || native_signal == SIGCHLD ||
        native_signal == SIGURG || native_signal == SIGWINCH
#ifdef SIGINFO
        || native_signal == SIGINFO
#endif
        )
        _exit(125);
    if (!sparc64_native_termination_block())
        _exit(125);
    if (native_signal != SIGKILL) {
        struct sigaction action;
        memset(&action, 0, sizeof(action));
        action.sa_handler = SIG_DFL;
        if (sigemptyset(&action.sa_mask) != 0 ||
            sigaction(native_signal, &action, NULL) != 0)
            _exit(125);
    }
#if defined(__linux__)
    long tid = syscall(SYS_gettid);
    if (tid <= 0 || syscall(SYS_tgkill, getpid(), tid, native_signal) != 0)
        _exit(125);
#else
    /* Native Darwin units exercise TERM/USR ownership with native constants;
     * production guest-number identity is specific to AArch64 Linux. */
    if (pthread_kill(pthread_self(), native_signal) != 0)
        _exit(125);
#endif
    sigset_t only_selected;
    if (sigfillset(&only_selected) != 0 ||
        sigdelset(&only_selected, native_signal) != 0)
        _exit(125);
    (void)sigsuspend(&only_selected);
    _exit(125); /* A default-fatal signal cannot return from delivery. */
}
