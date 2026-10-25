/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#include "runtime/family_file_recovery.h"
#include "runtime/family_file_recovery_internal.h"
#include "runtime/family_file_index_internal.h"
#include "runtime/family_file_resize_record.h"

#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

static int begin_write(sparc64_family_guard_t *guard, int borrowed_target,
                         bool positioned, uint64_t offset,
                         const void *bytes, size_t count,
                         sparc64_file_identity_policy_t policy,
                         sparc64_file_caps_write_result_t *out,
                         const sparc64_file_caps_call_context_t *caller,
                         sparc64_family_file_completion_t *out_attributed)
{
    if (guard == NULL || (out == NULL) == (out_attributed == NULL) ||
        (caller == NULL) != (out_attributed == NULL) ||
        (caller != NULL && !sparc64_file_caps_call_context_valid(caller)) ||
        count > SPARC64_FILE_CAPS_MAX_WRITE_BYTES ||
        (positioned && (offset > INT64_MAX ||
                        count > (uint64_t)INT64_MAX - offset)) ||
        (count != 0 && bytes == NULL) || !sparc64_file_identity_policy_valid(policy)) {
        errno = EINVAL;
        return -1;
    }
    if (caller != NULL && caller->owner_incarnation != guard->incarnation) {
        errno = EPERM; return -1;
    }
    if (sparc64_family_file_target_check(guard, borrowed_target) != 0)
        return -1;
    int flags = fcntl(borrowed_target, F_GETFL);
    if (flags < 0)
        return -1;
    bool append = (flags & O_APPEND) != 0;
    if (!positioned || append) {
        if (append) {
            struct stat status;
            if (fstat(borrowed_target, &status) != 0)
                return -1;
            if (status.st_size < 0) { errno = EIO; return -1; }
            offset = (uint64_t)status.st_size;
        } else {
            off_t current = lseek(borrowed_target, 0, SEEK_CUR);
            if (current < 0)
                return -1;
            offset = (uint64_t)current;
        }
    }
    if (offset > INT64_MAX || count > (uint64_t)INT64_MAX - offset) {
        errno = EINVAL;
        return -1;
    }
    sparc64_family_file_cursor_t cursor;
    if (sparc64_family_file_index_cursor_read(guard, &cursor) != 0)
        return -1;
    if (cursor.phase != SPARC64_FILE_IDLE) { errno = EBUSY; return -1; }
    uint64_t anchor = sparc64_family_file_index_object(guard);
    sparc64_family_file_index_state_t index = {0};
    sparc64_family_file_resize_record_t intent = {
        .kind = SPARC64_FILE_RESIZE_INTENT,
        .mutation_kind = !positioned ? SPARC64_FILE_MUTATION_WRITE :
                         append ? SPARC64_FILE_MUTATION_APPEND_PWRITE :
                                  SPARC64_FILE_MUTATION_PWRITE,
        .anchor_object = anchor,
        .base_snapshot = cursor.snapshot_object,
        .base_revision = cursor.revision,
        .write_offset = offset,
        .write_count = count,
        .identity_policy = policy
    };
    if (caller != NULL) {
        intent.attributed = true;
        intent.caller = *caller;
    }
    sparc64_family_object_t *record = NULL, *observation = NULL;
    int result = -1;
    if (sparc64_family_file_index_read(guard, anchor, &index) != 0 ||
        sparc64_file_identity_query(borrowed_target, policy, &intent.target_identity) != 0 ||
        sparc64_family_file_preflight_write(guard, &index, &intent.target_identity,
                                          offset, count) != 0 ||
        sparc64_family_file_index_cursor_reserve(guard, index.association_count + 3u) != 0)
        goto done;
    intent.source_count = (uint32_t)index.source_count;
    intent.association_count = (uint32_t)index.association_count;
    uint32_t slots = 0;
    if (sparc64_family_file_resize_record_slots(SPARC64_FILE_RESIZE_OBSERVATION,
                                             intent.source_count, &slots) != 0 ||
        sparc64_family_object_create(guard, 1, &record) != 0)
        goto done;
    intent.self_object = intent.operation_id = sparc64_family_object_id(record);
    if (sparc64_family_object_create(guard, slots, &observation) != 0)
        goto done;
    intent.observation_object = sparc64_family_object_id(observation);
    if (sparc64_family_file_index_reserve_snapshot(guard, &intent.final_snapshot_object) != 0 ||
        sparc64_family_file_resize_record_stage(guard, intent.self_object, &intent) != 0)
        goto done;
    int staged;
    if (caller != NULL && !positioned)
        staged = sparc64_file_caps_write_stage_attributed(sparc64_family_sources(guard),
            intent.operation_id, borrowed_target, offset, append, bytes, count, caller);
    else if (caller != NULL && append)
        staged = sparc64_file_caps_append_pwrite_stage_attributed(sparc64_family_sources(guard),
            intent.operation_id, borrowed_target, offset, bytes, count, caller);
    else if (caller != NULL)
        staged = sparc64_file_caps_pwrite_stage_attributed(sparc64_family_sources(guard),
            intent.operation_id, borrowed_target, offset, bytes, count, caller);
    else if (!positioned)
        staged = sparc64_file_caps_write_stage(sparc64_family_sources(guard), intent.operation_id,
                                           borrowed_target, offset, append, bytes, count);
    else if (append)
        staged = sparc64_file_caps_append_pwrite_stage(sparc64_family_sources(guard),
                        intent.operation_id, borrowed_target, offset, bytes, count);
    else
        staged = sparc64_file_caps_pwrite_stage(sparc64_family_sources(guard), intent.operation_id,
                                            borrowed_target, offset, bytes, count);
    if (staged != 0)
        goto done;
    sparc64_family_file_cursor_t pending = cursor;
    pending.phase = SPARC64_FILE_STAGED;
    pending.intent_object = intent.self_object;
    if (sparc64_family_file_index_cursor_advance(guard, &cursor, &pending, NULL) != 0)
        goto done;
#ifdef SPARC64_FAMILY_TESTING
    sparc64_family_test_point(guard, SPARC64_FAMILY_TEST_RESIZE_INTENT_PUBLISHED);
#endif
    result = caller != NULL ? sparc64_family_file_drain_attributed(guard, caller, out_attributed) :
                              sparc64_family_file_drain_write(guard, out);
done: {
        int saved = errno;
        sparc64_family_object_close(observation);
        sparc64_family_object_close(record);
        sparc64_family_file_index_state_destroy(&index);
        errno = saved;
        return result;
    }
}

int sparc64_family_file_pwrite(sparc64_family_guard_t *guard, int borrowed_target,
                            uint64_t offset, const void *bytes, size_t count,
                            sparc64_file_identity_policy_t policy,
                            sparc64_file_caps_write_result_t *out)
{
    return begin_write(guard, borrowed_target, true, offset, bytes, count, policy,
                         out, NULL, NULL);
}

int sparc64_family_file_write(sparc64_family_guard_t *guard, int borrowed_target,
                           const void *bytes, size_t count,
                           sparc64_file_identity_policy_t policy,
                           sparc64_file_caps_write_result_t *out)
{
    return begin_write(guard, borrowed_target, false, 0, bytes, count, policy,
                         out, NULL, NULL);
}

int sparc64_family_file_pwrite_attributed(sparc64_family_guard_t *guard, int borrowed_target,
    uint64_t offset, const void *bytes, size_t count, sparc64_file_identity_policy_t policy,
    const sparc64_file_caps_call_context_t *caller, sparc64_family_file_completion_t *out)
{
    return begin_write(guard, borrowed_target, true, offset, bytes, count, policy,
                         NULL, caller, out);
}

int sparc64_family_file_write_attributed(sparc64_family_guard_t *guard, int borrowed_target,
    const void *bytes, size_t count, sparc64_file_identity_policy_t policy,
    const sparc64_file_caps_call_context_t *caller, sparc64_family_file_completion_t *out)
{
    return begin_write(guard, borrowed_target, false, 0, bytes, count, policy,
                         NULL, caller, out);
}
