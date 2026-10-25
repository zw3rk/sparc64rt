/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SPARC64RT_RUNTIME_FILE_CATALOG_H
#define SPARC64RT_RUNTIME_FILE_CATALOG_H

#include "memory/file_identity.h"
#include "runtime/inode_pins.h"

#include <stddef.h>

#define SPARC64_FILE_CATALOG_CAPACITY SPARC64_INODE_PINS_MAX_ATTEMPTS
#define SPARC64_FILE_CATALOG_RECORD_SIZE 160u

/* Fixed little-endian values: ID8, device8, provider4, format4, length4,
 * reserved4, payload128. Native padding/bools/pointers are never serialized. */
typedef struct {
    unsigned char bytes[SPARC64_FILE_CATALOG_RECORD_SIZE];
} sparc64_file_catalog_record_t;

bool sparc64_file_catalog_encode(sparc64_file_catalog_record_t *record, uint64_t id,
                              const sparc64_file_identity_t *identity);
bool sparc64_file_catalog_decode(const sparc64_file_catalog_record_t *record,
                              uint64_t next_id, uint64_t *id,
                              sparc64_file_identity_t *identity);
/* Validate append order, unique full identities, bounded provider records and
 * canonical zero tail/reserved. Records are an owned snapshot under a guard. */
bool sparc64_file_catalog_validate(const sparc64_file_catalog_record_t *records,
                                size_t count, uint64_t next_id);

#endif
