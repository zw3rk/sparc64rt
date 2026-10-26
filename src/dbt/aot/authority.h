/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SPARC64RT_AOT_AUTHORITY_H
#define SPARC64RT_AOT_AUTHORITY_H

#include <stdbool.h>

typedef enum sparc64_aot_authority_policy {
    SPARC64_AOT_AUTHORITY_AUTO,
    SPARC64_AOT_AUTHORITY_HYPER_LINUX_APFS_ACL_V1
} sparc64_aot_authority_policy_t;

/* A caller-selected policy, never supplied by a record. Any unknown or
 * unverifiable filesystem/ACL state declines caching. The borrowed exact FD
 * remains open throughout this check; owner/mode/link checks are additionally
 * enforced by the reader/writer. Native same-UID writers are trusted. */
bool sparc64_aot_authorize_fd(int fd, bool directory,
                         sparc64_aot_authority_policy_t policy);

#endif
