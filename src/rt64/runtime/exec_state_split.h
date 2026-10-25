/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SPARC64RT_RUNTIME_EXEC_STATE_SPLIT_H
#define SPARC64RT_RUNTIME_EXEC_STATE_SPLIT_H

/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#define _POSIX_C_SOURCE 200809L
#include "runtime/exec_state.h"
#include "runtime/aot_discover.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define EXEC_RECORD_MAX ((size_t)1024 * 1024)
#define EXEC_RECORD_HEADER 24u
#define EXEC_INVENTORY_MAX ((size_t)4096)
#define EXEC_SYSROOT_MAX ((size_t)8192)
#define EXEC_CACHE_DIRECTORY_MAX SPARC64_EXEC_CACHE_DIRECTORY_MAX
#ifdef SPARC64_RUNTIME_TEST_ATTRIBUTED_FILE
#define EXEC_RECORD_MAGIC "RVEXST13"
#define EXEC_RECORD_VERSION 13u
#else
#define EXEC_RECORD_MAGIC "RVEXST07"
#define EXEC_RECORD_VERSION 7u
#endif

struct sparc64_exec_state_export {
    sparc64_path_registration_t *registration;
    int metadata;
    int old_flags;
    int *child_caps;
    int *child_flags;
    size_t child_count;
    bool active, poisoned;
};

typedef struct {
    unsigned char *bytes;
    size_t pos, limit;
} writer_t;

typedef struct {
    const unsigned char *bytes;
    size_t pos, limit;
} reader_t;

/* Cross-part declarations (generated L0a split). */
uint32_t get32(const unsigned char *p);
uint64_t get64(const unsigned char *p);
bool read_bytes(reader_t *reader, void *bytes, size_t length);
bool read32(reader_t *reader, uint32_t *value);
bool read64(reader_t *reader, uint64_t *value);
bool read_string(reader_t *reader, size_t maximum, char **out);
bool state_valid(const sparc64_exec_state_t *state);
void sparc64_exec_state_destroy(sparc64_exec_state_t *state);
bool encode(const sparc64_exec_state_t *state, unsigned char **out, size_t *length);
int64_t decode_i64(uint64_t word);

#endif /* SPARC64RT_RUNTIME_EXEC_STATE_SPLIT_H */
