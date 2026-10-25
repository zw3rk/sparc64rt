/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SPARC64RT_LINUX_FD_INITIAL_H
#define SPARC64RT_LINUX_FD_INITIAL_H

#include "linux/fd.h"

/* Read once before opening any runtime resources. -1 means closed. Native
 * flags are retained, so pre-main CLOEXEC handles never become guest caps. */
typedef struct {
    int flags[SPARC64_FD_TABLE_LIMIT];
} sparc64_fd_census_t;

/* Sole startup-thread owner. Plain records, never a copied live mutex. After
 * capture every present descriptor is owned, >=3 and native CLOEXEC. Distinct
 * records can still share one kernel OFD; do not infer identity from IDs. */
typedef struct sparc64_fd_initial {
    int descriptors[SPARC64_FD_TABLE_LIMIT];
} sparc64_fd_initial_t;

int sparc64_fd_census_read(sparc64_fd_census_t *out);
/* Validate explicit roles before this allocating call. Exclude exact ORIGINAL
 * native numbers, even if their owner has already relocated a low cap. The
 * image/diagnostic owners consume those roles separately. Before commit any
 * failure leaves admitted originals/flags intact. After commit originals0..2
 * are consumed; uncertain close/rollback is fatal125. No rescanning. */
int sparc64_fd_initial_capture(const sparc64_fd_census_t *census, int image_fd,
                           int diagnostic_fd, sparc64_fd_initial_t **out);
void sparc64_fd_initial_destroy(sparc64_fd_initial_t **owner);
/* Fresh table only. Allocate all descriptions before moving capabilities;
 * failure leaves *owner unchanged. Success consumes/frees *owner. */
int sparc64_fd_table_init_initial(sparc64_fd_table_t *table, sparc64_fd_initial_t **owner);

#endif
