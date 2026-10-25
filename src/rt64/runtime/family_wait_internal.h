/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SPARC64RT_RUNTIME_FAMILY_WAIT_INTERNAL_H
#define SPARC64RT_RUNTIME_FAMILY_WAIT_INTERNAL_H

#include "runtime/family_wait.h"

int sparc64_family_wait_backend_read(sparc64_family_guard_t *guard,
                                sparc64_family_wait_table_t *table);
int sparc64_family_wait_backend_commit(sparc64_family_guard_t *guard,
                                  sparc64_family_wait_table_t *table,
                                  const sparc64_family_object_update_t *updates,
                                  size_t update_count);
int sparc64_family_wait_backend_id(sparc64_family_guard_t *guard, bool mm_id,
                              uint64_t *out);

#ifdef SPARC64_FAMILY_TESTING
void sparc64_family_wait_test_fail_next_validation_alloc(void);
#endif

#endif
