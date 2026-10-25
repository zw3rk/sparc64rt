/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SPARC64RT_RUNTIME_FAMILY_AUTHORITY_H
#define SPARC64RT_RUNTIME_FAMILY_AUTHORITY_H

/* Immutable storage authority selected by the launching runtime. This is
 * independent of executable-cache authority and guest file identity. */
typedef enum {
    SPARC64_FAMILY_AUTHORITY_AUTO = 0,
    SPARC64_FAMILY_AUTHORITY_HYPER_LINUX_APFS_ACL_V1 = 1
} sparc64_family_storage_authority_t;

#endif
