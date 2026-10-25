/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#define _POSIX_C_SOURCE 200809L
#include "runtime/family_file_recovery.h"
#include "runtime/family_file_recovery_internal.h"
#include "runtime/family_file_index_internal.h"
#include "runtime/family_file_resize_record.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* Different proof providers/formats are incomparable, not proof of distinct
 * files. Unknown and incomparable descriptions participate conservatively. */
static bool candidate(const sparc64_file_identity_t *source, const sparc64_file_identity_t *target)
{
    return !sparc64_file_identity_valid(source) || !sparc64_file_identity_valid(target) ||
        source->provider != target->provider || source->format != target->format ||
        sparc64_file_identity_equal(source, target);
}

static bool write_kind(sparc64_family_file_mutation_kind_t kind)
{
    return kind == SPARC64_FILE_MUTATION_PWRITE || kind == SPARC64_FILE_MUTATION_WRITE ||
           kind == SPARC64_FILE_MUTATION_APPEND_PWRITE;
}

static bool identical_identity(const sparc64_file_identity_t *a, const sparc64_file_identity_t *b)
{
    return a->provider == b->provider && a->device == b->device &&
        a->format == b->format && a->length == b->length &&
        a->mapped_key_eligible == b->mapped_key_eligible &&
        memcmp(a->bytes, b->bytes, sizeof(a->bytes)) == 0;
}

static size_t source_at(const sparc64_family_file_index_state_t *index, uint64_t id)
{
    size_t left = 0, right = index->source_count;
    while (left < right) {
        size_t middle = left + (right - left) / 2u;
        if (index->sources[middle].source_id < id) left = middle + 1u;
        else right = middle;
    }
    return left;
}

static int own_size(sparc64_family_guard_t *guard, uint64_t source_id, uint64_t *out)
{
    int fd = -1;
    if (sparc64_file_caps_fetch(sparc64_family_sources(guard), source_id, &fd) != 0)
        return -1;
    struct stat status;
    int result;
    do { result = fstat(fd, &status); } while (result != 0 && errno == EINTR);
    int saved = errno;
    (void)close(fd);
    if (result != 0) { errno = saved; return -1; }
    if (!S_ISREG(status.st_mode) || status.st_size < 0) { errno = EIO; return -1; }
    *out = (uint64_t)status.st_size;
    return 0;
}

static bool file_payload(const sparc64_family_page_state_t *p)
{
    return p->private_cow <= 1 && p->reserved == 0 && p->notified[0] == 0 &&
        p->notified[1] == 0 && p->notified[2] == 0 && p->notified[3] == 0;
}

/* Same semantics as the reference file_backing resize: a partial last COW
 * page preserves its private tail; complete pages beyond rounded EOF reset. */
static size_t shrink_start(const sparc64_family_page_state_t *page, uint64_t offset,
                             uint64_t size)
{
    if (offset >= size && (offset != (size & ~(UINT64_C(4096) - 1u)) ||
                           size % SPARC64_FAMILY_PAGE_SIZE == 0))
        return 0;
    if (page->private_cow != 0 || offset >= size || size - offset >= SPARC64_FAMILY_PAGE_SIZE)
        return SPARC64_FAMILY_PAGE_SIZE;
    return (size_t)(size - offset);
}

int sparc64_family_file_preflight_payloads(sparc64_family_guard_t *guard,
                                const sparc64_family_file_index_state_t *index,
                                const sparc64_file_identity_t *identity, uint64_t length)
{
    for (size_t i = 0; i < index->source_count; ++i) {
        const sparc64_family_file_index_source_t *source = &index->sources[i];
        if (!candidate(&source->identity, identity))
            continue;
        uint64_t size;
        if (own_size(guard, source->source_id, &size) != 0)
            return -1;
        /* Unmanaged mutation history cannot be inferred from current size.
         * This component admits only its own serialized resize operations. */
        if (size != source->reconciled_size) { errno = EIO; return -1; }
        if (length != size && source->mutation_sequence == UINT64_MAX) {
            errno = EOVERFLOW; return -1;
        }
    }
    for (size_t i = 0; i < index->association_count; ++i) {
        const sparc64_family_file_index_assoc_t *association = &index->associations[i];
        size_t at = source_at(index, association->source_id);
        if (at == index->source_count || index->sources[at].source_id != association->source_id) {
            errno = EIO; return -1;
        }
        const sparc64_family_file_index_source_t *source = &index->sources[at];
        if (!candidate(&source->identity, identity) || length >= source->reconciled_size)
            continue;
        sparc64_family_object_t *object = NULL;
        if (sparc64_family_object_open(guard, association->key.object_id, &object) != 0)
            return -1;
        sparc64_family_page_state_t page;
        int result = sparc64_family_object_snapshot(guard, object,
            (uint32_t)association->key.page_index, &page), saved = errno;
        sparc64_family_object_close(object);
        if (result != 0) { errno = saved; return -1; }
        if (!file_payload(&page)) { errno = EOPNOTSUPP; return -1; }
        size_t first = shrink_start(&page, association->file_offset, length);
        if (first == SPARC64_FAMILY_PAGE_SIZE)
            continue;
        if (page.content_generation == UINT64_MAX) { errno = EOVERFLOW; return -1; }
        for (size_t j = first / 16u; j < SPARC64_FAMILY_EPOCHS; ++j)
            if (page.epochs[j] == UINT64_MAX) { errno = EOVERFLOW; return -1; }
    }
    return 0;
}

typedef struct { size_t first, count; } write_range_t;

/* Index offsets are page-aligned and <=INT64_MAX; request end is checked by
 * the codec/begin API. Cold bytes outside a known write stay lazy. Reading a
 * whole known page here would introduce unpreflighted changes outside range. */
static write_range_t write_range(const sparc64_file_identity_t *source,
                                   const sparc64_file_identity_t *target,
                                   uint64_t page_offset, uint64_t offset,
                                   uint64_t count)
{
    if (count == 0)
        return (write_range_t){0, 0};
    if (!sparc64_file_identity_equal(source, target))
        return (write_range_t){0, SPARC64_FAMILY_PAGE_SIZE};
    uint64_t first = page_offset > offset ? page_offset : offset;
    uint64_t end = page_offset + SPARC64_FAMILY_PAGE_SIZE;
    if (end > offset + count)
        end = offset + count;
    return end > first ?
        (write_range_t){(size_t)(first - page_offset), (size_t)(end - first)} :
        (write_range_t){0, 0};
}

int sparc64_family_file_preflight_write(sparc64_family_guard_t *guard,
                                     const sparc64_family_file_index_state_t *index,
                                     const sparc64_file_identity_t *identity,
                                     uint64_t offset, uint64_t count)
{
    if (offset > INT64_MAX || count > SPARC64_FILE_CAPS_MAX_WRITE_BYTES ||
        count > (uint64_t)INT64_MAX - offset) { errno = EINVAL; return -1; }
    for (size_t i = 0; i < index->source_count; ++i) {
        const sparc64_family_file_index_source_t *source = &index->sources[i];
        if (!candidate(&source->identity, identity))
            continue;
        uint64_t size;
        if (own_size(guard, source->source_id, &size) != 0)
            return -1;
        if (size != source->reconciled_size) { errno = EIO; return -1; }
        if (count != 0 && source->mutation_sequence == UINT64_MAX) {
            errno = EOVERFLOW; return -1;
        }
    }
    for (size_t i = 0; i < index->association_count; ++i) {
        const sparc64_family_file_index_assoc_t *a = &index->associations[i];
        size_t at = source_at(index, a->source_id);
        if (at == index->source_count || index->sources[at].source_id != a->source_id) {
            errno = EIO; return -1;
        }
        const sparc64_file_identity_t *source = &index->sources[at].identity;
        if (!candidate(source, identity))
            continue;
        sparc64_family_object_t *object = NULL;
        if (sparc64_family_object_open(guard, a->key.object_id, &object) != 0)
            return -1;
        sparc64_family_page_state_t page;
        int result = sparc64_family_object_snapshot(guard, object,
                                                 (uint32_t)a->key.page_index, &page);
        int saved = errno;
        sparc64_family_object_close(object);
        if (result != 0) { errno = saved; return -1; }
        /* An older lazy notification must be consumed before staging. Never
         * silently erase one on an untouched or private page. */
        if (!file_payload(&page)) { errno = EOPNOTSUPP; return -1; }
        write_range_t range = write_range(source, identity, a->file_offset, offset, count);
        if (page.private_cow != 0 || range.count == 0)
            continue;
        if (page.content_generation == UINT64_MAX) { errno = EOVERFLOW; return -1; }
        size_t last = (range.first + range.count - 1u) / 16u;
        for (size_t granule = range.first / 16u; granule <= last; ++granule)
            if (page.epochs[granule] == UINT64_MAX) { errno = EOVERFLOW; return -1; }
    }
    return 0;
}

static int intent_matches(const sparc64_family_file_resize_record_t *intent,
                            uint64_t anchor, const sparc64_family_file_cursor_t *cursor,
                            const sparc64_family_file_index_state_t *index)
{
    if (intent->kind != SPARC64_FILE_RESIZE_INTENT ||
        intent->self_object != cursor->intent_object ||
        intent->operation_id != cursor->intent_object || intent->anchor_object != anchor ||
        intent->base_snapshot != cursor->snapshot_object ||
        intent->base_revision != cursor->revision || index->revision != cursor->revision ||
        intent->source_count != index->source_count ||
        intent->association_count != index->association_count ||
        cursor->cursor > index->association_count ||
        intent->operation_id <= cursor->snapshot_object ||
        intent->observation_object <= intent->operation_id ||
        intent->final_snapshot_object <= intent->operation_id ||
        (cursor->phase == SPARC64_FILE_RECONCILE &&
         cursor->observed_object != intent->observation_object)) {
        errno = EIO; return -1;
    }
    /* All referenced payloads predate the frozen snapshot; reserved metadata
     * is freshly allocated after the intent ID. Never reinterpret a data key. */
    for (size_t i = 0; i < index->association_count; ++i)
        if (index->associations[i].key.object_id >= cursor->snapshot_object) {
            errno = EIO; return -1;
        }
    return 0;
}

static bool after_size_valid(const sparc64_family_file_index_source_t *source,
                               const sparc64_family_file_resize_record_t *intent,
                               uint64_t actual, uint64_t after_size)
{
    uint64_t before = source->reconciled_size;
    if (!candidate(&source->identity, &intent->target_identity))
        return after_size == before;
    if (intent->mutation_kind == SPARC64_FILE_MUTATION_TRUNCATE)
        return after_size == before || after_size == intent->target_length;
    if (actual == 0)
        return after_size == before;
    uint64_t grown = intent->write_offset + actual;
    if (grown < before)
        grown = before;
    /* Proven equality identifies this exact target; unknown candidates may
     * instead be unrelated files whose own retained size stays unchanged. */
    return after_size == grown ||
        (!sparc64_file_identity_equal(&source->identity, &intent->target_identity) &&
         after_size == before);
}

static int observation_matches(const sparc64_family_file_resize_record_t *observed,
                                 const sparc64_family_file_resize_record_t *intent,
                                 const sparc64_family_file_index_state_t *index)
{
    if (observed->kind != SPARC64_FILE_RESIZE_OBSERVATION ||
        observed->self_object != intent->observation_object ||
        observed->operation_id != intent->operation_id ||
        observed->anchor_object != intent->anchor_object ||
        observed->base_snapshot != intent->base_snapshot ||
        observed->base_revision != intent->base_revision ||
        observed->mutation_kind != intent->mutation_kind ||
        observed->attributed != intent->attributed ||
        (intent->attributed &&
         !sparc64_file_caps_call_context_equal(&observed->caller, &intent->caller)) ||
        observed->write_offset != intent->write_offset ||
        observed->write_count != intent->write_count ||
        observed->target_length != intent->target_length ||
        observed->observation_object != intent->observation_object ||
        observed->final_snapshot_object != intent->final_snapshot_object ||
        observed->identity_policy != intent->identity_policy ||
        !identical_identity(&observed->target_identity, &intent->target_identity) ||
        observed->source_count != intent->source_count ||
        observed->association_count != intent->association_count) {
        errno = EIO; return -1;
    }
    for (size_t i = 0; i < index->source_count; ++i) {
        const sparc64_family_file_index_source_t *source = &index->sources[i];
        if (observed->sizes[i].source_id != source->source_id ||
            !after_size_valid(source, intent, observed->result_count,
                                 observed->sizes[i].after_size)) {
            errno = EIO; return -1;
        }
    }
    return 0;
}

static int observe(sparc64_family_guard_t *guard,
                     const sparc64_family_file_resize_record_t *intent,
                     const sparc64_family_file_index_state_t *index,
                     sparc64_family_file_cursor_t *cursor)
{
    int native_error = 0;
    uint64_t actual = 0;
    bool generated_sigxfsz = false;
    if (intent->attributed) {
        sparc64_file_caps_mutation_result_t native;
        int executed;
        if (intent->mutation_kind == SPARC64_FILE_MUTATION_TRUNCATE)
            executed = sparc64_file_caps_truncate_execute_attributed(sparc64_family_sources(guard),
                intent->operation_id, &intent->caller, &native);
        else if (intent->mutation_kind == SPARC64_FILE_MUTATION_PWRITE)
            executed = sparc64_file_caps_pwrite_execute_attributed(sparc64_family_sources(guard),
                intent->operation_id, &intent->caller, &native);
        else if (intent->mutation_kind == SPARC64_FILE_MUTATION_APPEND_PWRITE)
            executed = sparc64_file_caps_append_pwrite_execute_attributed(sparc64_family_sources(guard),
                intent->operation_id, &intent->caller, &native);
        else
            executed = sparc64_file_caps_write_execute_attributed(sparc64_family_sources(guard),
                intent->operation_id, &intent->caller, &native);
        if (executed != 0)
            return -1;
        if (native.native_errno < 0 || native.native_errno >= 4096 ||
            (native.native_errno == 0 ? native.transferred < 0 ||
             (uint64_t)native.transferred > intent->write_count :
             native.transferred != -1)) { errno = EIO; return -1; }
        native_error = native.native_errno;
        generated_sigxfsz = native.generated_sigxfsz;
        if (native.transferred >= 0)
            actual = (uint64_t)native.transferred;
    } else if (intent->mutation_kind == SPARC64_FILE_MUTATION_TRUNCATE) {
        if (sparc64_file_caps_truncate_execute(sparc64_family_sources(guard), intent->operation_id,
                                             &native_error) != 0)
            return -1;
    } else {
        sparc64_file_caps_write_result_t native;
        int executed;
        if (intent->mutation_kind == SPARC64_FILE_MUTATION_PWRITE)
            executed = sparc64_file_caps_pwrite_execute(sparc64_family_sources(guard),
                                                    intent->operation_id, &native);
        else if (intent->mutation_kind == SPARC64_FILE_MUTATION_APPEND_PWRITE)
            executed = sparc64_file_caps_append_pwrite_execute(sparc64_family_sources(guard),
                                                           intent->operation_id, &native);
        else
            executed = sparc64_file_caps_write_execute(sparc64_family_sources(guard),
                                                   intent->operation_id, &native);
        if (executed != 0)
            return -1;
        if (native.native_errno < 0 || native.native_errno >= 4096 ||
            (native.native_errno == 0 ? native.transferred < 0 ||
             (uint64_t)native.transferred > intent->write_count :
             native.transferred != -1)) { errno = EIO; return -1; }
        native_error = native.native_errno;
        if (native.transferred >= 0)
            actual = (uint64_t)native.transferred;
    }
#ifdef SPARC64_FAMILY_TESTING
    sparc64_family_test_point(guard, SPARC64_FAMILY_TEST_RESIZE_NATIVE_RESULT);
#endif
    sparc64_family_file_resize_record_t observed = *intent;
    observed.kind = SPARC64_FILE_RESIZE_OBSERVATION;
    observed.self_object = intent->observation_object;
    observed.native_errno = (uint32_t)native_error;
    observed.result_count = actual;
    observed.generated_sigxfsz = generated_sigxfsz;
    observed.sizes = index->source_count == 0 ? NULL : calloc(index->source_count, sizeof(*observed.sizes));
    if (index->source_count != 0 && observed.sizes == NULL)
        return -1;
    int result = -1;
    for (size_t i = 0; i < index->source_count; ++i) {
        const sparc64_family_file_index_source_t *source = &index->sources[i];
        observed.sizes[i].source_id = source->source_id;
        observed.sizes[i].after_size = source->reconciled_size;
        if (candidate(&source->identity, &intent->target_identity) &&
            own_size(guard, source->source_id, &observed.sizes[i].after_size) != 0)
            goto done;
        /* Only this controlled operation can change candidate source sizes.
         * Do not infer equality or apply the target's size to another source. */
        if (!after_size_valid(source, intent, actual, observed.sizes[i].after_size)) {
            errno = EIO;
            goto done;
        }
    }
    if (sparc64_family_file_resize_record_stage(guard, intent->observation_object, &observed) != 0)
        goto done;
    sparc64_family_file_cursor_t next = *cursor;
    next.phase = SPARC64_FILE_RECONCILE;
    next.observed_object = intent->observation_object;
    if (sparc64_family_file_index_cursor_advance(guard, cursor, &next, NULL) != 0)
        goto done;
    *cursor = next;
#ifdef SPARC64_FAMILY_TESTING
    sparc64_family_test_point(guard, SPARC64_FAMILY_TEST_RESIZE_OBSERVATION_PUBLISHED);
#endif
    result = 0;
done: {
        int saved = errno;
        free(observed.sizes);
        errno = saved;
        return result;
    }
}

static int reconcile_page(sparc64_family_guard_t *guard,
                            const sparc64_family_file_index_assoc_t *association,
                            uint64_t after_size, sparc64_family_file_cursor_t *cursor)
{
    sparc64_family_object_t *object = NULL;
    if (sparc64_family_object_open(guard, association->key.object_id, &object) != 0)
        return -1;
    sparc64_family_page_state_t target;
    int result = -1;
    if (sparc64_family_object_snapshot(guard, object, (uint32_t)association->key.page_index, &target) != 0)
        goto done;
    if (!file_payload(&target)) { errno = EIO; goto done; }
    size_t first = shrink_start(&target, association->file_offset, after_size);
    sparc64_family_object_update_t payload = {object, (uint32_t)association->key.page_index, &target};
    if (first != SPARC64_FAMILY_PAGE_SIZE) {
        if (target.content_generation == UINT64_MAX) { errno = EOVERFLOW; goto done; }
        for (size_t i = first / 16u; i < SPARC64_FAMILY_EPOCHS; ++i) {
            if (target.epochs[i] == UINT64_MAX) { errno = EOVERFLOW; goto done; }
            ++target.epochs[i];
        }
        ++target.content_generation;
        memset(target.bytes + first, 0, SPARC64_FAMILY_PAGE_SIZE - first);
        if (first == 0)
            target.private_cow = 0;
    }
    sparc64_family_file_cursor_t next = *cursor;
    ++next.cursor;
    result = sparc64_family_file_index_cursor_advance(guard, cursor, &next,
        first == SPARC64_FAMILY_PAGE_SIZE ? NULL : &payload);
    if (result == 0)
        *cursor = next;
done: {
        int saved = errno;
        sparc64_family_object_close(object);
        errno = saved;
        return result;
    }
}

static int exact_size(int fd, uint64_t expected)
{
    struct stat status;
    int result;
    do { result = fstat(fd, &status); } while (result != 0 && errno == EINTR);
    if (result != 0)
        return -1;
    if (!S_ISREG(status.st_mode) || status.st_size < 0 ||
        (uint64_t)status.st_size != expected) { errno = EIO; return -1; }
    return 0;
}

/* Infrastructure reads, not guest accesses: pages beyond this source's own
 * EOF are zero storage, not BUS faults. Never read a native signed offset
 * unless it lies below the validated nonnegative own size. */
static int read_write_range(sparc64_family_guard_t *guard, uint64_t source_id,
                               uint64_t file_offset, uint64_t own_after_size,
                               write_range_t range, unsigned char *bytes)
{
    int fd = -1;
    if (sparc64_file_caps_fetch(sparc64_family_sources(guard), source_id, &fd) != 0)
        return -1;
    int result = -1;
    if (exact_size(fd, own_after_size) != 0)
        goto done;
    memset(bytes, 0, range.count);
    uint64_t start = file_offset + range.first;
    uint64_t available = start < own_after_size ? own_after_size - start : 0;
    size_t wanted = available < range.count ? (size_t)available : range.count;
    size_t received = 0;
    while (received < wanted) {
        ssize_t amount = pread(fd, bytes + received, wanted - received,
                                 (off_t)(start + received));
        if (amount < 0) {
            if (errno == EINTR)
                continue;
            goto done;
        }
        if (amount == 0) { errno = EIO; goto done; }
        received += (size_t)amount;
    }
    if (exact_size(fd, own_after_size) != 0)
        goto done;
    result = 0;
done: {
        int saved = errno;
        (void)close(fd);
        errno = saved;
        return result;
    }
}

static int reconcile_write_page(sparc64_family_guard_t *guard,
                                  const sparc64_family_file_index_assoc_t *a,
                                  const sparc64_family_file_index_source_t *source,
                                  const sparc64_family_file_resize_record_t *intent,
                                  const sparc64_family_file_resize_record_t *observed,
                                  uint64_t own_after_size,
                                  sparc64_family_file_cursor_t *cursor)
{
    write_range_t range = write_range(&source->identity, &intent->target_identity,
        a->file_offset, intent->write_offset, observed->result_count);
    sparc64_family_object_t *object = NULL;
    sparc64_family_page_state_t target;
    sparc64_family_object_update_t update = {0};
    int result = -1;
    if (range.count != 0) {
        if (sparc64_family_object_open(guard, a->key.object_id, &object) != 0 ||
            sparc64_family_object_snapshot(guard, object, (uint32_t)a->key.page_index,
                                         &target) != 0)
            goto done;
        if (!file_payload(&target)) { errno = EIO; goto done; }
        if (target.private_cow == 0) {
            if (target.content_generation == UINT64_MAX) { errno = EOVERFLOW; goto done; }
            size_t last = (range.first + range.count - 1u) / 16u;
            for (size_t i = range.first / 16u; i <= last; ++i) {
                if (target.epochs[i] == UINT64_MAX) { errno = EOVERFLOW; goto done; }
                ++target.epochs[i];
            }
            unsigned char bytes[SPARC64_FAMILY_PAGE_SIZE];
            if (read_write_range(guard, a->source_id, a->file_offset,
                                    own_after_size, range, bytes) != 0)
                goto done;
            memcpy(target.bytes + range.first, bytes, range.count);
            ++target.content_generation;
            update = (sparc64_family_object_update_t){object, (uint32_t)a->key.page_index, &target};
        }
    }
    sparc64_family_file_cursor_t next = *cursor;
    ++next.cursor;
    result = sparc64_family_file_index_cursor_advance(guard, cursor, &next,
                                                    update.object == NULL ? NULL : &update);
    if (result == 0)
        *cursor = next;
done: {
        int saved = errno;
        sparc64_family_object_close(object);
        errno = saved;
        return result;
    }
}

static int drain(sparc64_family_guard_t *guard, int *out_native_errno,
                   sparc64_file_caps_write_result_t *out_write,
                   const sparc64_file_caps_call_context_t *caller,
                   sparc64_family_file_completion_t *out_attributed)
{
    sparc64_family_file_cursor_t cursor;
    if (sparc64_family_file_index_cursor_read(guard, &cursor) != 0)
        return -1;
    if (cursor.phase == SPARC64_FILE_IDLE) {
        if (out_write != NULL || out_attributed != NULL) { errno = EINVAL; return -1; }
        return 0;
    }
    uint64_t anchor = sparc64_family_file_index_object(guard);
    sparc64_family_file_index_state_t index = {0};
    sparc64_family_file_resize_record_t intent = {0}, observed = {0};
    int result = -1;
    if (sparc64_family_file_index_read(guard, anchor, &index) != 0 ||
        sparc64_family_file_resize_record_read(guard, cursor.intent_object, &intent) != 0 ||
        intent_matches(&intent, anchor, &cursor, &index) != 0)
        goto done;
    if ((out_write != NULL && !write_kind(intent.mutation_kind)) ||
        (out_native_errno != NULL && intent.mutation_kind != SPARC64_FILE_MUTATION_TRUNCATE) ||
        ((out_write != NULL || out_native_errno != NULL) && intent.attributed) ||
        (out_attributed != NULL && (!intent.attributed ||
         !sparc64_file_caps_call_context_equal(caller, &intent.caller)))) {
        errno = EIO;
        goto done;
    }
    if (cursor.phase == SPARC64_FILE_STAGED && observe(guard, &intent, &index, &cursor) != 0)
        goto done;
    if (sparc64_family_file_resize_record_read(guard, cursor.observed_object, &observed) != 0 ||
        observation_matches(&observed, &intent, &index) != 0)
        goto done;
    while (cursor.cursor < index.association_count) {
        const sparc64_family_file_index_assoc_t *association = &index.associations[cursor.cursor];
        size_t at = source_at(&index, association->source_id);
        if (at == index.source_count || index.sources[at].source_id != association->source_id) {
            errno = EIO; goto done;
        }
        if (write_kind(intent.mutation_kind) && observed.result_count != 0 &&
            candidate(&index.sources[at].identity, &intent.target_identity)) {
            if (reconcile_write_page(guard, association, &index.sources[at],
                    &intent, &observed, observed.sizes[at].after_size, &cursor) != 0)
                goto done;
        } else if (intent.mutation_kind == SPARC64_FILE_MUTATION_TRUNCATE &&
            candidate(&index.sources[at].identity, &intent.target_identity) &&
            observed.sizes[at].after_size < index.sources[at].reconciled_size) {
            if (reconcile_page(guard, association, observed.sizes[at].after_size, &cursor) != 0)
                goto done;
        } else {
            sparc64_family_file_cursor_t next = cursor;
            ++next.cursor;
            if (sparc64_family_file_index_cursor_advance(guard, &cursor, &next, NULL) != 0)
                goto done;
            cursor = next;
        }
#ifdef SPARC64_FAMILY_TESTING
        sparc64_family_test_point(guard, SPARC64_FAMILY_TEST_RESIZE_CURSOR_COMMITTED);
#endif
    }
    for (size_t i = 0; i < index.source_count; ++i) {
        bool written = write_kind(intent.mutation_kind) &&
            observed.result_count != 0 &&
            candidate(&index.sources[i].identity, &intent.target_identity);
        if (written || observed.sizes[i].after_size != index.sources[i].reconciled_size) {
            if (index.sources[i].mutation_sequence == UINT64_MAX) { errno = EOVERFLOW; goto done; }
            ++index.sources[i].mutation_sequence;
            index.sources[i].reconciled_size = observed.sizes[i].after_size;
        }
    }
    if (sparc64_family_file_index_finish(guard, &cursor, intent.final_snapshot_object, &index) != 0)
        goto done;
    if (out_native_errno != NULL)
        *out_native_errno = (int)observed.native_errno;
    if (out_write != NULL)
        *out_write = (sparc64_file_caps_write_result_t){
            .transferred = observed.native_errno == 0 ? (int64_t)observed.result_count : -1,
            .native_errno = (int)observed.native_errno
        };
    if (out_attributed != NULL)
        *out_attributed = (sparc64_family_file_completion_t){
            .operation_id = observed.operation_id, .caller = observed.caller,
            .native = {
                .transferred = observed.native_errno == 0 ? (int64_t)observed.result_count : -1,
                .native_errno = (int)observed.native_errno,
                .generated_sigxfsz = observed.generated_sigxfsz
            }
        };
    result = 0;
done: {
        int saved = errno;
        sparc64_family_file_resize_record_destroy(&observed);
        sparc64_family_file_resize_record_destroy(&intent);
        sparc64_family_file_index_state_destroy(&index);
        errno = saved;
        return result;
    }
}

int sparc64_family_file_drain(sparc64_family_guard_t *guard, int *out_native_errno)
{
    return drain(guard, out_native_errno, NULL, NULL, NULL);
}

int sparc64_family_file_drain_write(sparc64_family_guard_t *guard,
                                sparc64_file_caps_write_result_t *out)
{
    if (out == NULL) { errno = EINVAL; return -1; }
    return drain(guard, NULL, out, NULL, NULL);
}

int sparc64_family_file_drain_attributed(sparc64_family_guard_t *guard,
    const sparc64_file_caps_call_context_t *caller, sparc64_family_file_completion_t *out)
{
    if (out == NULL || guard == NULL || !sparc64_file_caps_call_context_valid(caller)) {
        errno = EINVAL; return -1;
    }
    if (caller->owner_incarnation != guard->incarnation) { errno = EPERM; return -1; }
    return drain(guard, NULL, NULL, caller, out);
}

int sparc64_family_file_recover(sparc64_family_guard_t *guard)
{
    return sparc64_family_file_drain(guard, NULL);
}
