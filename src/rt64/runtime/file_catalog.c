/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#include "runtime/file_catalog.h"

#include <string.h>

_Static_assert(sizeof(sparc64_file_catalog_record_t) == SPARC64_FILE_CATALOG_RECORD_SIZE,
               "file catalog records contain exactly their fixed wire bytes");

static void write_le(unsigned char *bytes, uint64_t value, size_t count)
{
    for (size_t i = 0; i < count; ++i)
        bytes[i] = (unsigned char)(value >> (8u * i));
}

static uint64_t read_le(const unsigned char *bytes, size_t count)
{
    uint64_t value = 0;
    for (size_t i = 0; i < count; ++i)
        value |= (uint64_t)bytes[i] << (8u * i);
    return value;
}

bool sparc64_file_catalog_encode(sparc64_file_catalog_record_t *record, uint64_t id,
                              const sparc64_file_identity_t *identity)
{
    if (record == NULL || id == 0 || !sparc64_file_identity_valid(identity) ||
        !identity->mapped_key_eligible)
        return false;
    *record = (sparc64_file_catalog_record_t){{0}};
    write_le(record->bytes, id, 8);
    write_le(record->bytes + 8, identity->device, 8);
    write_le(record->bytes + 16, identity->provider, 4);
    write_le(record->bytes + 20, identity->format, 4);
    write_le(record->bytes + 24, identity->length, 4);
    memcpy(record->bytes + 32, identity->bytes, identity->length);
    return true;
}

bool sparc64_file_catalog_decode(const sparc64_file_catalog_record_t *record,
                              uint64_t next_id, uint64_t *id,
                              sparc64_file_identity_t *identity)
{
    if (record == NULL || id == NULL || identity == NULL || next_id == 0)
        return false;
    uint64_t decoded_id = read_le(record->bytes, 8);
    sparc64_file_identity_t decoded = {
        .device = read_le(record->bytes + 8, 8),
        .provider = (uint32_t)read_le(record->bytes + 16, 4),
        .format = (uint32_t)read_le(record->bytes + 20, 4),
        .length = (uint32_t)read_le(record->bytes + 24, 4),
        .mapped_key_eligible = true
    };
    if (decoded_id == 0 || decoded_id >= next_id ||
        !sparc64_file_identity_valid(&decoded) || read_le(record->bytes + 28, 4) != 0)
        return false;
    for (size_t i = decoded.length; i < SPARC64_FILE_IDENTITY_MAX_BYTES; ++i)
        if (record->bytes[32 + i] != 0)
            return false;
    memcpy(decoded.bytes, record->bytes + 32, decoded.length);
    *id = decoded_id;
    *identity = decoded;
    return true;
}

bool sparc64_file_catalog_validate(const sparc64_file_catalog_record_t *records,
                                size_t count, uint64_t next_id)
{
    if (count > SPARC64_FILE_CATALOG_CAPACITY || next_id == 0 ||
        (count != 0 && records == NULL))
        return false;
    uint64_t previous = 0;
    for (size_t i = 0; i < count; ++i) {
        uint64_t id;
        sparc64_file_identity_t identity;
        if (!sparc64_file_catalog_decode(&records[i], next_id, &id, &identity) ||
            id <= previous)
            return false;
        previous = id;
        for (size_t j = 0; j < i; ++j) {
            uint64_t ignored;
            sparc64_file_identity_t earlier;
            if (!sparc64_file_catalog_decode(&records[j], next_id, &ignored, &earlier) ||
                sparc64_file_identity_equal(&identity, &earlier))
                return false;
        }
    }
    return true;
}
