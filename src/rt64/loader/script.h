/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SPARC64RT_LOADER_SCRIPT_H
#define SPARC64RT_LOADER_SCRIPT_H

#include <stdbool.h>

typedef struct {
    char interpreter[256];
    char argument[256];
    bool has_argument;
} sparc64_script_header_t;

/* Linux v6.18's 256-byte, zero-padded binfmt script header. Returns a Linux
 * errno number, zero on success. Space/tab only; optional argument is opaque.
 * An empty interpreter is retained for the internal open's EACCES (cwd is a
 * directory), as for a bare "#!". A user execve empty path is separate. */
unsigned int sparc64_script_parse(const unsigned char header[256], sparc64_script_header_t *out);

#endif
