/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#include "runtime/family_file_resize_record.h"
#include "runtime/family_file_index.h"
#include "runtime/file_caps.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

enum {
    RESIZE_HEADER_SIZE = 512,
    RESIZE_ROW_SIZE = 16,
    RESIZE_SCHEMA = 2,
    RESIZE_ATTRIBUTED_SCHEMA = 3,
    RESIZE_IDENTITY_OFFSET = 96,
    RESIZE_IDENTITY_BYTES_OFFSET = 120
};
#define RESIZE_MAGIC UINT64_C(0x315a525452564652)

static void put(unsigned char *p, uint64_t value, size_t count)
{
    for (size_t i = 0; i < count; ++i)
        p[i] = (unsigned char)(value >> (i * 8u));
}

static uint64_t get(const unsigned char *p, size_t count)
{
    uint64_t value = 0;
    for (size_t i = 0; i < count; ++i)
        value |= (uint64_t)p[i] << (i * 8u);
    return value;
}

static bool zero(const unsigned char *p, size_t count)
{
    for (size_t i = 0; i < count; ++i)
        if (p[i] != 0)
            return false;
    return true;
}

static bool identity_valid(const sparc64_file_identity_t *identity)
{
    if (identity->provider == SPARC64_FILE_ID_UNKNOWN)
        return identity->device == 0 && identity->format == 0 &&
               identity->length == 0 && !identity->mapped_key_eligible &&
               zero(identity->bytes, sizeof(identity->bytes));
    return sparc64_file_identity_valid(identity) &&
           zero(identity->bytes + identity->length,
                sizeof(identity->bytes) - identity->length);
}

static bool distinct_refs(const sparc64_family_file_resize_record_t *record)
{
    const uint64_t refs[] = {
        record->self_object, record->anchor_object, record->operation_id,
        record->base_snapshot, record->observation_object,
        record->final_snapshot_object
    };
    for (size_t i = 0; i < sizeof(refs) / sizeof(refs[0]); ++i) {
        if (refs[i] == 0)
            return false;
        for (size_t j = 0; j < i; ++j) {
            bool allowed_same =
                (record->kind == SPARC64_FILE_RESIZE_INTENT &&
                 i == 2u && j == 0u) ||
                (record->kind == SPARC64_FILE_RESIZE_OBSERVATION &&
                 i == 4u && j == 0u);
            if (refs[i] == refs[j] && !allowed_same)
                return false;
        }
    }
    return true;
}

static bool record_valid(const sparc64_family_file_resize_record_t *record)
{
    if (record == NULL ||
        (record->kind != SPARC64_FILE_RESIZE_INTENT &&
         record->kind != SPARC64_FILE_RESIZE_OBSERVATION) ||
        record->target_length > INT64_MAX || record->base_revision == 0 ||
        record->source_count > SPARC64_FAMILY_FILE_INDEX_MAX_SOURCES ||
        record->association_count > SPARC64_FAMILY_FILE_INDEX_MAX_ASSOCIATIONS ||
        !sparc64_file_identity_policy_valid(record->identity_policy) ||
        record->native_errno >= 4096 || !identity_valid(&record->target_identity) ||
        !distinct_refs(record))
        return false;

    if (record->attributed) {
        if (!sparc64_file_caps_call_context_valid(&record->caller) ||
            (record->kind == SPARC64_FILE_RESIZE_INTENT && record->generated_sigxfsz))
            return false;
    } else if (record->generated_sigxfsz || record->caller.owner_incarnation != 0 ||
               record->caller.mm_id != 0 || record->caller.worker_id != 0 ||
               record->caller.fsize_soft != 0 || record->caller.fsize_hard != 0) {
        return false;
    }

    if (record->mutation_kind == SPARC64_FILE_MUTATION_TRUNCATE) {
        if (record->write_offset != 0 || record->write_count != 0 ||
            record->result_count != 0)
            return false;
    } else if (record->mutation_kind == SPARC64_FILE_MUTATION_PWRITE ||
               record->mutation_kind == SPARC64_FILE_MUTATION_WRITE ||
               record->mutation_kind == SPARC64_FILE_MUTATION_APPEND_PWRITE) {
        if (record->target_length != 0 || record->write_offset > INT64_MAX ||
            record->write_count > SPARC64_FILE_CAPS_MAX_WRITE_BYTES ||
            record->write_count > (uint64_t)INT64_MAX - record->write_offset ||
            record->result_count > record->write_count ||
            (record->native_errno != 0 && record->result_count != 0))
            return false;
    } else {
        return false;
    }

    if (record->kind == SPARC64_FILE_RESIZE_INTENT) {
        if (record->operation_id != record->self_object ||
            record->native_errno != 0 || record->result_count != 0 ||
            record->sizes != NULL)
            return false;
    } else if (record->self_object != record->observation_object ||
               record->operation_id == record->self_object ||
               (record->source_count == 0 ? record->sizes != NULL :
                                            record->sizes == NULL)) {
        return false;
    }

    if (record->kind == SPARC64_FILE_RESIZE_OBSERVATION) {
        for (uint32_t i = 0; i < record->source_count; ++i) {
            if (record->sizes == NULL || record->sizes[i].source_id == 0 ||
                record->sizes[i].after_size > INT64_MAX ||
                (i != 0 && record->sizes[i - 1u].source_id >=
                           record->sizes[i].source_id))
                return false;
        }
    }
    return true;
}

int sparc64_family_file_resize_record_slots(sparc64_family_file_resize_kind_t kind,
                                        uint32_t source_count,
                                        uint32_t *out_slots)
{
    if (out_slots == NULL || (kind != SPARC64_FILE_RESIZE_INTENT &&
                              kind != SPARC64_FILE_RESIZE_OBSERVATION) ||
        source_count > SPARC64_FAMILY_FILE_INDEX_MAX_SOURCES) {
        errno = EINVAL;
        return -1;
    }
    if (kind == SPARC64_FILE_RESIZE_INTENT) {
        *out_slots = 1;
        return 0;
    }
    size_t bytes = RESIZE_HEADER_SIZE + (size_t)source_count * RESIZE_ROW_SIZE;
    size_t slots = (bytes + SPARC64_FAMILY_PAGE_SIZE - 1u) / SPARC64_FAMILY_PAGE_SIZE;
    if (slots == 0 || slots > SPARC64_FAMILY_OBJECT_MAX_SLOTS) {
        errno = EOVERFLOW;
        return -1;
    }
    *out_slots = (uint32_t)slots;
    return 0;
}

static void encode(const sparc64_family_file_resize_record_t *record,
                   unsigned char *bytes)
{
    put(bytes, RESIZE_MAGIC, 8);
    put(bytes + 8, record->attributed ? RESIZE_ATTRIBUTED_SCHEMA : RESIZE_SCHEMA, 4);
    put(bytes + 12, record->kind, 4);
    put(bytes + 16, record->self_object, 8);
    put(bytes + 24, record->anchor_object, 8);
    put(bytes + 32, record->operation_id, 8);
    put(bytes + 40, record->base_snapshot, 8);
    put(bytes + 48, record->base_revision, 8);
    put(bytes + 56, record->target_length, 8);
    put(bytes + 64, record->observation_object, 8);
    put(bytes + 72, record->final_snapshot_object, 8);
    put(bytes + 80, record->source_count, 4);
    put(bytes + 84, record->association_count, 4);
    put(bytes + 88, record->native_errno, 4);
    put(bytes + 92, record->identity_policy, 4);
    put(bytes + RESIZE_IDENTITY_OFFSET, record->target_identity.provider, 4);
    put(bytes + 100, record->target_identity.format, 4);
    put(bytes + 104, record->target_identity.length, 4);
    put(bytes + 108, record->target_identity.mapped_key_eligible ? 1u : 0u, 4);
    put(bytes + 112, record->target_identity.device, 8);
    memcpy(bytes + RESIZE_IDENTITY_BYTES_OFFSET, record->target_identity.bytes,
           SPARC64_FILE_IDENTITY_MAX_BYTES);
    put(bytes + 248, record->mutation_kind, 4);
    put(bytes + 256, record->write_offset, 8);
    put(bytes + 264, record->write_count, 8);
    put(bytes + 272, record->result_count, 8);
    if (record->attributed) {
        put(bytes + 280, 1u | (record->generated_sigxfsz ? 2u : 0u), 4);
        put(bytes + 288, record->caller.owner_incarnation, 8);
        put(bytes + 296, record->caller.mm_id, 8);
        put(bytes + 304, record->caller.worker_id, 8);
        put(bytes + 312, record->caller.fsize_soft, 8);
        put(bytes + 320, record->caller.fsize_hard, 8);
    }
    if (record->kind == SPARC64_FILE_RESIZE_OBSERVATION) {
        for (uint32_t i = 0; i < record->source_count; ++i) {
            unsigned char *row = bytes + RESIZE_HEADER_SIZE +
                                 (size_t)i * RESIZE_ROW_SIZE;
            put(row, record->sizes[i].source_id, 8);
            put(row + 8, record->sizes[i].after_size, 8);
        }
    }
}

static bool metadata_page(const sparc64_family_page_state_t *page)
{
    return page->private_cow == 0 && page->reserved == 0 &&
           page->notified[0] == 0 && page->notified[1] == 0 &&
           page->notified[2] == 0 && page->notified[3] == 0;
}

static int write_reserved_slot(sparc64_family_guard_t *guard,
                               sparc64_family_object_t *object, uint32_t slot,
                               const unsigned char *bytes)
{
    sparc64_family_page_state_t current, target = {0};
    if (sparc64_family_object_snapshot(guard, object, slot, &current) != 0)
        return -1;
    target.content_generation = 1;
    for (size_t i = 0; i < SPARC64_FAMILY_EPOCHS; ++i)
        target.epochs[i] = 1;
    memcpy(target.bytes, bytes, SPARC64_FAMILY_PAGE_SIZE);

    bool virgin = metadata_page(&current) && current.content_generation == 0 &&
                  zero(current.bytes, sizeof(current.bytes));
    for (size_t i = 0; virgin && i < SPARC64_FAMILY_EPOCHS; ++i)
        virgin = current.epochs[i] == 0;
    if (!virgin) {
        bool staged = metadata_page(&current) && current.content_generation == 1 &&
                      memcmp(current.bytes, bytes, SPARC64_FAMILY_PAGE_SIZE) == 0;
        for (size_t i = 0; staged && i < SPARC64_FAMILY_EPOCHS; ++i)
            staged = current.epochs[i] == 1;
        if (staged)
            return 0;
        errno = EIO;
        return -1;
    }
    return sparc64_family_object_commit(guard, object, slot, &target);
}

int sparc64_family_file_resize_record_stage(sparc64_family_guard_t *guard,
                                        uint64_t reserved_object,
                                        const sparc64_family_file_resize_record_t *record)
{
    uint32_t slots;
    if (guard == NULL || reserved_object == 0 || !record_valid(record) ||
        record->self_object != reserved_object ||
        sparc64_family_file_resize_record_slots(record->kind, record->source_count,
                                            &slots) != 0) {
        errno = EINVAL;
        return -1;
    }
    size_t byte_count = (size_t)slots * SPARC64_FAMILY_PAGE_SIZE;
    unsigned char *bytes = calloc(1, byte_count);
    if (bytes == NULL)
        return -1;
    encode(record, bytes);

    sparc64_family_object_t *object = NULL;
    if (sparc64_family_object_open(guard, reserved_object, &object) != 0) {
        free(bytes);
        return -1;
    }
    int result = -1;
    if (sparc64_family_object_count(object) != slots) {
        errno = EINVAL;
        goto done;
    }
    for (uint32_t i = 0; i < slots; ++i) {
        if (write_reserved_slot(guard, object, i,
                                bytes + (size_t)i * SPARC64_FAMILY_PAGE_SIZE) != 0)
            goto done;
    }
    result = 0;
done: {
        int saved = errno;
        sparc64_family_object_close(object);
        free(bytes);
        errno = saved;
        return result;
    }
}

static bool decode_identity(const unsigned char *bytes,
                            sparc64_file_identity_t *identity)
{
    memset(identity, 0, sizeof(*identity));
    identity->provider = (uint32_t)get(bytes + RESIZE_IDENTITY_OFFSET, 4);
    identity->format = (uint32_t)get(bytes + 100, 4);
    identity->length = (uint32_t)get(bytes + 104, 4);
    uint32_t mapped = (uint32_t)get(bytes + 108, 4);
    identity->device = get(bytes + 112, 8);
    if (mapped > 1)
        return false;
    identity->mapped_key_eligible = mapped != 0;
    memcpy(identity->bytes, bytes + RESIZE_IDENTITY_BYTES_OFFSET,
           SPARC64_FILE_IDENTITY_MAX_BYTES);
    return identity_valid(identity);
}

static bool decode_header(const unsigned char *bytes,
                          sparc64_family_file_resize_record_t *record)
{
    uint64_t sources = get(bytes + 80, 4);
    uint64_t associations = get(bytes + 84, 4);
    uint64_t schema = get(bytes + 8, 4);
    if (get(bytes, 8) != RESIZE_MAGIC ||
        (schema != 1 && schema != RESIZE_SCHEMA && schema != RESIZE_ATTRIBUTED_SCHEMA) ||
        sources > SPARC64_FAMILY_FILE_INDEX_MAX_SOURCES ||
        associations > SPARC64_FAMILY_FILE_INDEX_MAX_ASSOCIATIONS ||
        (schema == 1 ? !zero(bytes + 248, RESIZE_HEADER_SIZE - 248u) :
         !zero(bytes + 252, 4)) ||
        (schema == RESIZE_SCHEMA && !zero(bytes + 280, RESIZE_HEADER_SIZE - 280u)) ||
        (schema == RESIZE_ATTRIBUTED_SCHEMA &&
         ((get(bytes + 280, 4) != 1u && get(bytes + 280, 4) != 3u) ||
          !zero(bytes + 284, 4) || !zero(bytes + 328, RESIZE_HEADER_SIZE - 328u))))
        return false;
    record->kind = (sparc64_family_file_resize_kind_t)get(bytes + 12, 4);
    record->self_object = get(bytes + 16, 8);
    record->anchor_object = get(bytes + 24, 8);
    record->operation_id = get(bytes + 32, 8);
    record->base_snapshot = get(bytes + 40, 8);
    record->base_revision = get(bytes + 48, 8);
    record->target_length = get(bytes + 56, 8);
    record->observation_object = get(bytes + 64, 8);
    record->final_snapshot_object = get(bytes + 72, 8);
    record->source_count = (uint32_t)sources;
    record->association_count = (uint32_t)associations;
    record->native_errno = (uint32_t)get(bytes + 88, 4);
    record->identity_policy = (sparc64_file_identity_policy_t)get(bytes + 92, 4);
    if (schema != 1) {
        record->mutation_kind = (sparc64_family_file_mutation_kind_t)get(bytes + 248, 4);
        record->write_offset = get(bytes + 256, 8);
        record->write_count = get(bytes + 264, 8);
        record->result_count = get(bytes + 272, 8);
    }
    if (schema == RESIZE_ATTRIBUTED_SCHEMA) {
        record->attributed = true;
        record->generated_sigxfsz = (get(bytes + 280, 4) & 2u) != 0;
        record->caller = (sparc64_file_caps_call_context_t){
            .owner_incarnation = get(bytes + 288, 8),
            .mm_id = get(bytes + 296, 8),
            .worker_id = get(bytes + 304, 8),
            .fsize_soft = get(bytes + 312, 8),
            .fsize_hard = get(bytes + 320, 8)
        };
    }
    if (!decode_identity(bytes, &record->target_identity))
        return false;
    uint32_t source_count = record->source_count;
    if (record->kind == SPARC64_FILE_RESIZE_OBSERVATION && source_count != 0)
        record->source_count = 0;
    bool valid = record_valid(record);
    record->source_count = source_count;
    return valid;
}

void sparc64_family_file_resize_record_destroy(sparc64_family_file_resize_record_t *record)
{
    if (record == NULL)
        return;
    free(record->sizes);
    memset(record, 0, sizeof(*record));
}

int sparc64_family_file_resize_record_read(sparc64_family_guard_t *guard,
                                       uint64_t object_id,
                                       sparc64_family_file_resize_record_t *out)
{
    if (guard == NULL || object_id == 0 || out == NULL) {
        errno = EINVAL;
        return -1;
    }
    sparc64_family_file_resize_record_t candidate = {0};
    sparc64_family_object_t *object = NULL;
    if (sparc64_family_object_open(guard, object_id, &object) != 0)
        return -1;
    int result = -1;
    uint32_t slot_count = sparc64_family_object_count(object);
    unsigned char *bytes = NULL;
    if (slot_count == 0) {
        errno = EIO;
        goto done;
    }
    size_t bytes_size = (size_t)slot_count * SPARC64_FAMILY_PAGE_SIZE;
    bytes = calloc(1, bytes_size);
    if (bytes == NULL)
        goto done;
    for (uint32_t i = 0; i < slot_count; ++i) {
        sparc64_family_page_state_t page;
        if (sparc64_family_object_snapshot(guard, object, i, &page) != 0)
            goto done;
        if (!metadata_page(&page) || page.content_generation != 1) {
            errno = EIO;
            goto done;
        }
        for (size_t e = 0; e < SPARC64_FAMILY_EPOCHS; ++e) {
            if (page.epochs[e] != 1) {
                errno = EIO;
                goto done;
            }
        }
        memcpy(bytes + (size_t)i * SPARC64_FAMILY_PAGE_SIZE, page.bytes,
               SPARC64_FAMILY_PAGE_SIZE);
    }
    if (!decode_header(bytes, &candidate) || candidate.self_object != object_id) {
        errno = EIO;
        goto done;
    }
    uint32_t expected_slots;
    if (sparc64_family_file_resize_record_slots(candidate.kind,
                                            candidate.source_count,
                                            &expected_slots) != 0 ||
        expected_slots != slot_count) {
        errno = EIO;
        goto done;
    }
    size_t used = RESIZE_HEADER_SIZE;
    if (candidate.kind == SPARC64_FILE_RESIZE_OBSERVATION) {
        used += (size_t)candidate.source_count * RESIZE_ROW_SIZE;
        if (candidate.source_count != 0) {
            candidate.sizes = calloc(candidate.source_count,
                                      sizeof(*candidate.sizes));
            if (candidate.sizes == NULL)
                goto done;
        }
        for (uint32_t i = 0; i < candidate.source_count; ++i) {
            const unsigned char *row = bytes + RESIZE_HEADER_SIZE +
                                       (size_t)i * RESIZE_ROW_SIZE;
            candidate.sizes[i].source_id = get(row, 8);
            candidate.sizes[i].after_size = get(row + 8, 8);
        }
        if (!record_valid(&candidate)) {
            errno = EIO;
            goto done;
        }
    }
    if (!zero(bytes + used, bytes_size - used)) {
        errno = EIO;
        goto done;
    }
    free(bytes);
    bytes = NULL;
    sparc64_family_object_close(object);
    object = NULL;
    sparc64_family_file_resize_record_destroy(out);
    *out = candidate;
    memset(&candidate, 0, sizeof(candidate));
    result = 0;
done: {
        int saved = errno;
        free(bytes);
        sparc64_family_object_close(object);
        sparc64_family_file_resize_record_destroy(&candidate);
        errno = saved;
        return result;
    }
}
