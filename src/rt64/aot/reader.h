/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SPARC64RT_AOT_READER_H
#define SPARC64RT_AOT_READER_H
#include "aot/format.h"
#include "aot/authority.h"
#include <stddef.h>
#include <stdint.h>

typedef struct sparc64_aot_identity {
    uint8_t input_digest[SPARC64_AOT_DIGEST_BYTES];
    uint8_t runtime_digest[SPARC64_AOT_DIGEST_BYTES];
    uint8_t emitter_digest[SPARC64_AOT_DIGEST_BYTES];
    uint8_t profile_digest[SPARC64_AOT_DIGEST_BYTES];
    uint64_t guest_extensions;
    uint64_t a64_host_requirements;
    uint32_t guest_page_size;
    uint32_t a64_host_page_size;
    uint32_t memory_model;
    uint8_t xlen;
    uint8_t abi;
} sparc64_aot_identity_t;

typedef struct sparc64_aot_snapshot {
    uint8_t *bytes;
    size_t size;
    sparc64_aot_view_t view;
} sparc64_aot_snapshot_t;

typedef enum sparc64_aot_read_result {
    SPARC64_AOT_READ_ERROR = -1,
    SPARC64_AOT_READ_MISS = 0,
    SPARC64_AOT_READ_HIT = 1
} sparc64_aot_read_result_t;

/* Digest domain: the 20 ASCII bytes "sparc64rt-cache-record-v2", followed by the
 * COMPLETE encoded v2 record with its 32-byte digest slot replaced by zeros.
 * The terminating C NUL is not hashed. V1 and malformed records are rejected.
 * This detects corruption; it does not authenticate same-UID cache writers.
 * Output is unchanged on failure. This function creates no executable mapping. */
int sparc64_aot_record_digest(const uint8_t *bytes, size_t size,
                          uint8_t out[SPARC64_AOT_DIGEST_BYTES]);

/* Borrowed directory FD must identify an effective-UID-owned mode0700
 * directory; caller must not close/reuse it during this call. Leaf is one nonempty filename of <=255 bytes, excluding . and ..
 * and any slash. Open uses CLOEXEC, NOFOLLOW and NONBLOCK. Only a regular,
 * single-link, effective-UID-owned mode0600 file of <=16MiB is eligible.
 * Elevated UID/GID operation declines caching. Metadata is rechecked after
 * bounded pread into malloc-owned bytes. V2 structure, whole-record digest,
 * and ALL expected identity fields must match before a HIT is returned.
 *
 * Missing/stale/unsafe/corrupt/changing files return MISS; invalid arguments,
 * resource failure and unexpected I/O return ERROR. Output bytes/view.encoded must be NULL and size must be zero; output
 * is unchanged on MISS/ERROR. No guest effects, relocations or RX publish
 * occur. The snapshot owns its borrowed view and remains valid after the
 * original file is renamed, modified or closed. Same-UID native writers are
 * inside the trust domain. Checks cover POSIX owner/mode fields; extended ACL
 * authorization is not established. A HIT alone is not permission to execute
 * code; filesystem authorization and relocation remain activation requirements. */
sparc64_aot_read_result_t sparc64_aot_snapshot_read(int directory_fd, const char *leaf,
                                          const sparc64_aot_identity_t *expected,
                                          sparc64_aot_snapshot_t *out);
/* Runtime activation must use this exact-FD ACL-certified form. A failed
 * authority query is a MISS, never permission to execute cached code. */
sparc64_aot_read_result_t sparc64_aot_snapshot_read_authorized(
    int directory_fd, const char *leaf, const sparc64_aot_identity_t *expected,
    sparc64_aot_authority_policy_t policy, sparc64_aot_snapshot_t *out);
void sparc64_aot_snapshot_destroy(sparc64_aot_snapshot_t *snapshot);
#endif
