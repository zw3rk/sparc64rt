/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SPARC64RT_RUNTIME_DIAGNOSTIC_H
#define SPARC64RT_RUNTIME_DIAGNOSTIC_H

#include "linux/fd_initial.h"

/* A sink owns only an explicitly requested private channel. The default
 * briefly borrows CURRENT guest2; it never holds a duplicate between writes.
 * Bind/unbind only while worker admission is stopped. Not signal-safe. */
typedef struct {
    sparc64_fd_table_t *table;
    sparc64_fd_initial_t *initial;
    int direct_fd;
    bool owns_direct;
} sparc64_diagnostic_t;

void sparc64_diagnostic_init(sparc64_diagnostic_t *sink);
/* Caller validates the original FD and all role conflicts before allocating
 * any resources. Consumes source only on success; native CLOEXEC, >=3. */
int sparc64_diagnostic_take(sparc64_diagnostic_t *sink, int source);
void sparc64_diagnostic_initial(sparc64_diagnostic_t *sink, sparc64_fd_initial_t *initial);
void sparc64_diagnostic_table(sparc64_diagnostic_t *sink, sparc64_fd_table_t *table);
/* Required immediately in a native fork child, before any copied mutex use,
 * and before table destruction. Explicit private channel remains usable. */
void sparc64_diagnostic_detach(sparc64_diagnostic_t *sink);
void sparc64_diagnostic_destroy(sparc64_diagnostic_t *sink);
void sparc64_diagnostic_write(void *context, const char *bytes, size_t size);
void sparc64_diagnostic_printf(sparc64_diagnostic_t *sink, const char *format, ...)

#if defined(__GNUC__) || defined(__clang__)
    __attribute__((format(printf, 2, 3)))
#endif
    ;

#endif
