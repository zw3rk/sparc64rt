/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#define _POSIX_C_SOURCE 200809L
#include "runtime/diagnostic.h"

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>

void sparc64_diagnostic_init(sparc64_diagnostic_t *sink)
{
    *sink = (sparc64_diagnostic_t){.direct_fd = STDERR_FILENO};
}

int sparc64_diagnostic_take(sparc64_diagnostic_t *sink, int source)
{
    if (sink == NULL || sink->owns_direct || source < 0) {
        errno = EINVAL; return -1;
    }
    int flags = fcntl(source, F_GETFD);
    if (flags < 0)
        return -1;
    int owned = source;
    if (source < 3) {
        owned = fcntl(source, F_DUPFD_CLOEXEC, 3);
        if (owned < 0)
            return -1;
        if (close(source) != 0)
            _exit(125);
    } else if (fcntl(source, F_SETFD, flags | FD_CLOEXEC) != 0) {
        return -1;
    }
    *sink = (sparc64_diagnostic_t){.direct_fd = owned, .owns_direct = true};
    return 0;
}

void sparc64_diagnostic_initial(sparc64_diagnostic_t *sink, sparc64_fd_initial_t *initial)
{
    if (!sink->owns_direct)
        *sink = (sparc64_diagnostic_t){.direct_fd = -1, .initial = initial};
}

void sparc64_diagnostic_table(sparc64_diagnostic_t *sink, sparc64_fd_table_t *table)
{
    if (!sink->owns_direct)
        *sink = (sparc64_diagnostic_t){.direct_fd = -1, .table = table};
}

void sparc64_diagnostic_detach(sparc64_diagnostic_t *sink)
{
    if (!sink->owns_direct)
        *sink = (sparc64_diagnostic_t){.direct_fd = -1};
}

void sparc64_diagnostic_destroy(sparc64_diagnostic_t *sink)
{
    int saved = errno;
    if (sink->owns_direct)
        (void)close(sink->direct_fd);
    *sink = (sparc64_diagnostic_t){.direct_fd = -1};
    errno = saved;
}

void sparc64_diagnostic_write(void *context, const char *bytes, size_t size)
{
    sparc64_diagnostic_t *sink = context;
    if (sink == NULL || bytes == NULL)
        return;
    int saved = errno;
    sigset_t only_pipe, old_mask, pending;
    sigemptyset(&only_pipe);
    sigaddset(&only_pipe, SIGPIPE);
    if (pthread_sigmask(SIG_BLOCK, &only_pipe, &old_mask) != 0) {
        errno = saved;
        return;
    }
    if (sigpending(&pending) != 0)
        goto restore_mask;
    bool had_pipe = sigismember(&pending, SIGPIPE) == 1;
    bool broken_pipe = false;
    int descriptor = sink->direct_fd;
    sparc64_fd_borrow_t borrow = {0};
    if (sink->table != NULL) {
        if (sparc64_fd_borrow(sink->table, 2, &borrow) != 0)
            goto done;
        descriptor = borrow.host_fd;
    } else if (sink->initial != NULL) {
        descriptor = sink->initial->descriptors[2];
    }
    while (descriptor >= 0 && size != 0) {
        ssize_t written = write(descriptor, bytes, size);
        if (written < 0 && errno == EINTR)
            continue;
        if (written < 0 && errno == EPIPE)
            broken_pipe = true;
        if (written <= 0)
            break;
        bytes += written;
        size -= (size_t)written;
    }
    if (borrow.table != NULL && sparc64_fd_unborrow(&borrow) != 0)
        _exit(125);
done:
    /* A diagnostic must neither kill the runtime nor leave its own SIGPIPE
     * for a surrounding guest write flight to misattribute. A previously
     * pending instance belongs to that caller and is left untouched. */
    if (broken_pipe && !had_pipe) {
#if defined(__linux__)
        const struct timespec zero = {0, 0};
        int result;
        do { result = sigtimedwait(&only_pipe, NULL, &zero); }
        while (result < 0 && errno == EINTR);
        if (result != SIGPIPE && !(result < 0 && errno == EAGAIN))
            _exit(125);
#else
        /* Darwin native units lack sigtimedwait; only this thread dequeues. */
        if (sigpending(&pending) != 0)
            _exit(125);
        if (sigismember(&pending, SIGPIPE) == 1) {
            int result;
            if (sigwait(&only_pipe, &result) != 0 || result != SIGPIPE)
                _exit(125);
        }
#endif
    }
restore_mask:
    if (pthread_sigmask(SIG_SETMASK, &old_mask, NULL) != 0)
        _exit(125);
    errno = saved;
}

void sparc64_diagnostic_printf(sparc64_diagnostic_t *sink, const char *format, ...)
{
    int saved = errno;
    char line[2048];
    va_list arguments;
    va_start(arguments, format);
    int count = vsnprintf(line, sizeof(line), format, arguments);
    va_end(arguments);
    /* Diagnostics are bounded. Never emit an unterminated/truncated record. */
    if (count > 0 && (size_t)count < sizeof(line))
        sparc64_diagnostic_write(sink, line, (size_t)count);
    errno = saved;
}
