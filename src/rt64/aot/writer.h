/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SPARC64RT_AOT_WRITER_H
#define SPARC64RT_AOT_WRITER_H

#include "aot/format.h"
#include "aot/authority.h"

/* The borrowed directory FD must remain open and stable for the call, and the
 * image and all referenced spans must remain valid and unchanged during it.
 * The directory must be effective-UID-owned and exactly mode0700; elevated
 * UID/GID operation declines. Leaves are single names (<=255 bytes), not . or
 * .., and may not contain '/'. This writes a bounded v2 cache record but does
 * not authorize it for use. The caller supplies a unique temporary leaf; it is
 * created exclusively and never reused. Before-rename failures remove only
 * that owned temporary file and preserve final. A directory-fsync error after
 * rename returns ERROR although the complete record may already be published;
 * durability is then uncertain and final is not removed. The checks cover
 * POSIX owner/mode fields, not extended ACL authorization. No RX mapping or
 * runtime activation occurs here.
 */
typedef enum sparc64_aot_write_result {
    SPARC64_AOT_WRITE_ERROR = -1,
    SPARC64_AOT_WRITE_DECLINE = 0,
    SPARC64_AOT_WRITE_STORED = 1
} sparc64_aot_write_result_t;

sparc64_aot_write_result_t sparc64_aot_snapshot_write(
    int directory_fd, const char *final_leaf, const char *temporary_leaf,
    const sparc64_aot_image_t *image);

/* Exact-FD ACL-certified runtime publication. Unknown authority declines;
 * the old structural writer above is only for offline/cache tooling. */
sparc64_aot_write_result_t sparc64_aot_snapshot_write_authorized(
    int directory_fd, const char *final_leaf, const char *temporary_leaf,
    const sparc64_aot_image_t *image, sparc64_aot_authority_policy_t policy);

#endif
