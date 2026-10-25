/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#include "runtime/family_wait_internal.h"

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifdef SPARC64_FAMILY_TESTING
static bool fail_next_validation_alloc;

void sparc64_family_wait_test_fail_next_validation_alloc(void)
{
    fail_next_validation_alloc = true;
}
#endif

static void *validation_alloc(size_t size)
{
#ifdef SPARC64_FAMILY_TESTING
    if (fail_next_validation_alloc) {
        fail_next_validation_alloc = false;
        errno = ENOMEM;
        return NULL;
    }
#endif
    return malloc(size);
}

static int compare_wait_id(const void *left, const void *right)
{
    uint64_t a = *(const uint64_t *)left;
    uint64_t b = *(const uint64_t *)right;
    return (a > b) - (a < b);
}

static int validate_table(const sparc64_family_wait_table_t *table)
{
    if (table == NULL || table->count > table->capacity ||
        table->capacity > SPARC64_FAMILY_WAIT_MAX_ROWS ||
        (table->count != 0 && table->rows == NULL)) {
        errno = EINVAL;
        return -1;
    }
    if (table->count > SIZE_MAX / sizeof(uint64_t)) {
        errno = EOVERFLOW;
        return -1;
    }
    uint64_t *ids = table->count == 0 ? NULL :
                    validation_alloc(table->count * sizeof(*ids));
    if (table->count != 0 && ids == NULL)
        return -1;
    for (size_t i = 0; i < table->count; ++i) {
        const sparc64_family_wait_row_t *row = &table->rows[i];
        if (row->wait_id == 0 || row->owner_incarnation == 0 || row->mm_id == 0 ||
            row->worker_id == 0 || row->key.kind < SPARC64_FAMILY_WAIT_PRIVATE ||
            row->key.kind > SPARC64_FAMILY_WAIT_FILE || row->key.identity == 0 ||
            row->bitset == 0 || (row->state != SPARC64_FAMILY_WAITING &&
                                 row->state != SPARC64_FAMILY_WOKEN)) {
            free(ids);
            errno = EINVAL;
            return -1;
        }
        ids[i] = row->wait_id;
    }
    if (table->count > 1)
        qsort(ids, table->count, sizeof(*ids), compare_wait_id);
    for (size_t i = 1; i < table->count; ++i) {
        if (ids[i - 1u] == ids[i]) {
            free(ids);
            errno = EINVAL;
            return -1;
        }
    }
    free(ids);
    return 0;
}

int sparc64_family_wait_table_read(sparc64_family_guard_t *guard,
                              sparc64_family_wait_table_t *table)
{
    if (table == NULL) {
        errno = EINVAL;
        return -1;
    }
    sparc64_family_wait_table_t fresh = {0};
    if (sparc64_family_wait_backend_read(guard, &fresh) != 0) {
        sparc64_family_wait_table_destroy(&fresh);
        return -1;
    }
    if (validate_table(&fresh) != 0) {
        int validation_error = errno;
        sparc64_family_wait_table_destroy(&fresh);
        errno = validation_error == ENOMEM ? ENOMEM : EIO;
        return -1;
    }
    sparc64_family_wait_table_destroy(table);
    *table = fresh;
    return 0;
}

int sparc64_family_wait_table_reserve(sparc64_family_wait_table_t *table, size_t capacity)
{
    if (table == NULL || capacity > SPARC64_FAMILY_WAIT_MAX_ROWS) {
        errno = EINVAL;
        return -1;
    }
    if (capacity <= table->capacity)
        return 0;
    if (capacity > SIZE_MAX / sizeof(*table->rows)) {
        errno = EOVERFLOW;
        return -1;
    }
    sparc64_family_wait_row_t *rows = realloc(table->rows, capacity * sizeof(*rows));
    if (rows == NULL)
        return -1;
    table->rows = rows;
    table->capacity = capacity;
    return 0;
}

void sparc64_family_wait_table_destroy(sparc64_family_wait_table_t *table)
{
    if (table == NULL)
        return;
    free(table->rows);
    memset(table, 0, sizeof(*table));
}

int sparc64_family_wait_table_commit(sparc64_family_guard_t *guard,
                                sparc64_family_wait_table_t *table,
                                const sparc64_family_object_update_t *updates,
                                size_t update_count)
{
    if (validate_table(table) != 0 || update_count > 2 ||
        (update_count != 0 && updates == NULL)) {
        if (errno == 0)
            errno = EINVAL;
        return -1;
    }
    return sparc64_family_wait_backend_commit(guard, table, updates, update_count);
}

int sparc64_family_wait_id(sparc64_family_guard_t *guard, uint64_t *out)
{
    return sparc64_family_wait_backend_id(guard, false, out);
}

int sparc64_family_mm_id(sparc64_family_guard_t *guard, uint64_t *out)
{
    return sparc64_family_wait_backend_id(guard, true, out);
}

int sparc64_family_wait_table_sweep(sparc64_family_guard_t *guard,
                               sparc64_family_wait_table_t *table)
{
    if (validate_table(table) != 0 || guard == NULL) {
        if (errno == 0)
            errno = EINVAL;
        return -1;
    }
    sparc64_family_wait_table_t candidate = {0};
    if (sparc64_family_wait_table_reserve(&candidate, table->count) != 0)
        return -1;
    candidate.revision = table->revision;
    size_t kept = 0;
    for (size_t i = 0; i < table->count; ++i) {
        bool alive = false;
        if (sparc64_family_owner_alive(guard, table->rows[i].owner_incarnation,
                                  &alive) != 0) {
            sparc64_family_wait_table_destroy(&candidate);
            return -1;
        }
        if (alive)
            candidate.rows[kept++] = table->rows[i];
    }
    candidate.count = kept;
    if (kept == table->count) {
        sparc64_family_wait_table_destroy(&candidate);
        return 0;
    }
    if (sparc64_family_wait_table_commit(guard, &candidate, NULL, 0) != 0) {
        sparc64_family_wait_table_destroy(&candidate);
        return -1;
    }
    sparc64_family_wait_table_destroy(table);
    *table = candidate;
    return 0;
}
