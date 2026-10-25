/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SPARC64RT_MEMORY_FILE_IDENTITY_H
#define SPARC64RT_MEMORY_FILE_IDENTITY_H

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#define SPARC64_FILE_IDENTITY_MAX_BYTES 128u
#define SPARC64_FILE_HANDLE_HL_APFS_V1 UINT32_C(0x52560001)

typedef enum {
    SPARC64_FILE_IDENTITY_AUTO,
    SPARC64_FILE_IDENTITY_HYPER_LINUX_APFS_V1
} sparc64_file_identity_policy_t;

enum {
    SPARC64_FILE_ID_UNKNOWN,
    SPARC64_FILE_ID_LINUX_TMPFS,
    SPARC64_FILE_ID_NATIVE_APFS,
    SPARC64_FILE_ID_HYPER_LINUX_APFS
};

/* A process-local cached value, not an on-disk or native ABI struct. Compare
 * fields, never padding. The retained exact FD must outlive every use; family
 * intern publication additionally requires a successful kernel queue pin.
 * Namespace includes the live filesystem device, never a mount ID (bind
 * aliases name the same inode). Eligibility is a provider property distinct
 * from source equality: an exact visible inode may map another backing inode. */
typedef struct {
    uint64_t device;
    uint32_t provider, format, length;
    unsigned char bytes[SPARC64_FILE_IDENTITY_MAX_BYTES];
    bool mapped_key_eligible;
} sparc64_file_identity_t;

static inline bool sparc64_file_identity_policy_valid(sparc64_file_identity_policy_t policy)
{
    return policy == SPARC64_FILE_IDENTITY_AUTO ||
           policy == SPARC64_FILE_IDENTITY_HYPER_LINUX_APFS_V1;
}
/* Parse the complete public policy value; leave *out unchanged on error. */
int sparc64_file_identity_policy_parse(const char *text, sparc64_file_identity_policy_t *out);
/* Pure operations are shared with persistent family records without linking
 * native provider discovery into the family metadata implementation. */
static inline bool sparc64_file_identity_valid(const sparc64_file_identity_t *identity)
{
    if (identity == NULL)
        return false;
    switch (identity->provider) {
    case SPARC64_FILE_ID_LINUX_TMPFS:
        return identity->format == 1 && identity->length == 12 &&
               identity->mapped_key_eligible;
    case SPARC64_FILE_ID_NATIVE_APFS:
        return identity->format == 1 && identity->length == 16 &&
               !identity->mapped_key_eligible;
    case SPARC64_FILE_ID_HYPER_LINUX_APFS:
        return identity->format == SPARC64_FILE_HANDLE_HL_APFS_V1 &&
               identity->length == 16 && identity->mapped_key_eligible;
    default:
        return false;
    }
}

static inline bool sparc64_file_identity_equal(const sparc64_file_identity_t *a,
                                           const sparc64_file_identity_t *b)
{
    return sparc64_file_identity_valid(a) && sparc64_file_identity_valid(b) &&
           a->provider == b->provider && a->device == b->device &&
           a->format == b->format && a->length == b->length &&
           memcmp(a->bytes, b->bytes, a->length) == 0;
}
/* Borrow fd. Return0 for known OR unknown identity, -1 for a real native or
 * resource failure. Unknown is zero-filled, never equal even to itself.
 * Unsupported providers/flags/permissions produce unknown without excluding
 * the file from ordinary execution. The explicit HL policy trusts the host's
 * standard exact-FD handle implementation; AUTO never infers that provider. */
int sparc64_file_identity_query(int fd, sparc64_file_identity_policy_t policy,
                             sparc64_file_identity_t *out);

#endif
