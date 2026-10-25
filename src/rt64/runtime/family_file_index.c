/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#include "runtime/family_file_index.h"
#include "runtime/family_file_index_internal.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

enum { HEADER_SIZE = 128, SOURCE_SIZE = 176, ASSOC_SIZE = 32, SCHEMA = 2 };
#define INDEX_MAGIC UINT64_C(0x3158494654525652)

typedef struct {
    uint64_t root, snapshot, length;
    sparc64_family_file_index_state_t state;
    sparc64_family_file_cursor_t cursor;
} index_header_t;

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

static int key_compare(sparc64_family_page_key_t a, sparc64_family_page_key_t b)
{
    if (a.object_id != b.object_id)
        return (a.object_id > b.object_id) - (a.object_id < b.object_id);
    return (a.page_index > b.page_index) - (a.page_index < b.page_index);
}

static bool extent(const sparc64_family_file_index_state_t *s, size_t *length, uint32_t *slots)
{
    if (s->source_count > SPARC64_FAMILY_FILE_INDEX_MAX_SOURCES ||
        s->association_count > SPARC64_FAMILY_FILE_INDEX_MAX_ASSOCIATIONS)
        return false;
    /* The combined bound is <3 MiB, including on 32-bit hosts. */
    size_t bytes = HEADER_SIZE + s->source_count * SOURCE_SIZE + s->association_count * ASSOC_SIZE;
    size_t pages = (bytes + SPARC64_FAMILY_PAGE_SIZE - 1u) / SPARC64_FAMILY_PAGE_SIZE;
    if (pages == 0 || pages > SPARC64_FAMILY_OBJECT_MAX_SLOTS)
        return false;
    *length = bytes;
    *slots = (uint32_t)pages;
    return true;
}

static bool identity_valid(const sparc64_file_identity_t *id)
{
    if (id->provider == SPARC64_FILE_ID_UNKNOWN)
        return id->device == 0 && id->format == 0 && id->length == 0 &&
               !id->mapped_key_eligible && zero(id->bytes, sizeof(id->bytes));
    return sparc64_file_identity_valid(id) &&
           zero(id->bytes + id->length, sizeof(id->bytes) - id->length);
}

/* Canonical wire bytes compare identity metadata without treating unknown
 * identity as proof that two distinct sources designate the same inode. */
static void encode_source(unsigned char *p, const sparc64_family_file_index_source_t *s)
{
    put(p, s->source_id, 8); put(p + 8, s->reconciled_size, 8);
    put(p + 16, s->mutation_sequence, 8); put(p + 24, s->identity.device, 8);
    put(p + 32, s->identity.provider, 4); put(p + 36, s->identity.format, 4);
    put(p + 40, s->identity.length, 4); put(p + 44, s->identity.mapped_key_eligible ? 1u : 0u, 4);
    memcpy(p + 48, s->identity.bytes, SPARC64_FILE_IDENTITY_MAX_BYTES);
}

static const sparc64_family_file_index_source_t *find_source(
    const sparc64_family_file_index_state_t *s, uint64_t id)
{
    size_t left = 0, right = s->source_count;
    while (left < right) {
        size_t middle = left + (right - left) / 2u;
        if (s->sources[middle].source_id < id) left = middle + 1u;
        else right = middle;
    }
    return left < s->source_count && s->sources[left].source_id == id ? &s->sources[left] : NULL;
}

static bool valid_state(const sparc64_family_file_index_state_t *s, uint64_t root)
{
    size_t length;
    uint32_t slots;
    if (!extent(s, &length, &slots) ||
        (s->source_count != 0 && s->sources == NULL) ||
        (s->association_count != 0 && s->associations == NULL))
        return false;
    for (size_t i = 0; i < s->source_count; ++i) {
        const sparc64_family_file_index_source_t *source = &s->sources[i];
        if (source->source_id == 0 || source->reconciled_size > INT64_MAX ||
            !identity_valid(&source->identity) ||
            (i != 0 && s->sources[i - 1u].source_id >= source->source_id))
            return false;
    }
    for (size_t i = 0; i < s->association_count; ++i) {
        const sparc64_family_file_index_assoc_t *a = &s->associations[i];
        if (a->key.object_id == 0 || a->key.object_id == root ||
            a->key.page_index >= SPARC64_FAMILY_OBJECT_MAX_SLOTS ||
            a->file_offset > INT64_MAX || a->file_offset % SPARC64_FAMILY_PAGE_SIZE != 0 ||
            find_source(s, a->source_id) == NULL ||
            (i != 0 && key_compare(s->associations[i - 1u].key, a->key) >= 0))
            return false;
    }
    return true;
}

static void encode_header(unsigned char *p, bool root, const index_header_t *h)
{
    put(p, INDEX_MAGIC, 8); put(p + 8, SCHEMA, 4); put(p + 12, root ? 1u : 2u, 4);
    put(p + 16, h->root, 8); put(p + 24, h->snapshot, 8);
    put(p + 32, h->state.revision, 8); put(p + 40, h->length, 8);
    put(p + 48, h->state.source_count, 8); put(p + 56, h->state.association_count, 8);
    if (root) {
        put(p + 64, h->cursor.intent_object, 8);
        put(p + 72, h->cursor.observed_object, 8);
        put(p + 80, h->cursor.cursor, 8);
        put(p + 88, h->cursor.phase, 4);
    }
}

static bool cursor_valid(const sparc64_family_file_cursor_t *c)
{
    if (c->phase == SPARC64_FILE_IDLE)
        return c->intent_object == 0 && c->observed_object == 0 && c->cursor == 0;
    if (c->phase == SPARC64_FILE_STAGED)
        return c->intent_object != 0 && c->observed_object == 0 && c->cursor == 0;
    return c->phase == SPARC64_FILE_RECONCILE && c->intent_object != 0 &&
        c->observed_object != 0 && c->intent_object != c->observed_object &&
        c->cursor <= SPARC64_FAMILY_FILE_INDEX_MAX_ASSOCIATIONS;
}

static bool decode_header(const unsigned char *p, uint64_t root, index_header_t *h)
{
    uint64_t sources = get(p + 48, 8), associations = get(p + 56, 8);
    if (get(p, 8) != INDEX_MAGIC || get(p + 8, 4) != SCHEMA || get(p + 12, 4) != 1 ||
        get(p + 16, 8) != root || root == 0 || !zero(p + 92, HEADER_SIZE - 92u) ||
        sources > SPARC64_FAMILY_FILE_INDEX_MAX_SOURCES || associations > SPARC64_FAMILY_FILE_INDEX_MAX_ASSOCIATIONS)
        return false;
    *h = (index_header_t){.root = root, .snapshot = get(p + 24, 8), .length = get(p + 40, 8),
        .state = {.revision = get(p + 32, 8), .source_count = (size_t)sources,
                   .association_count = (size_t)associations},
        .cursor = {.snapshot_object = get(p + 24, 8), .revision = get(p + 32, 8),
            .intent_object = get(p + 64, 8), .observed_object = get(p + 72, 8),
            .cursor = get(p + 80, 8), .phase = (uint32_t)get(p + 88, 4)}};
    size_t length;
    uint32_t slots;
    return cursor_valid(&h->cursor) && h->cursor.intent_object != root &&
           h->cursor.observed_object != root &&
           h->cursor.intent_object != h->snapshot && h->cursor.observed_object != h->snapshot &&
           h->snapshot != 0 && h->snapshot != root && h->state.revision != 0 &&
           extent(&h->state, &length, &slots) && h->length == length;
}

static bool metadata_page(const sparc64_family_page_state_t *p)
{
    return p->private_cow == 0 && p->reserved == 0 && p->notified[0] == 0 &&
           p->notified[1] == 0 && p->notified[2] == 0 && p->notified[3] == 0;
}

static int read_root(sparc64_family_guard_t *guard, uint64_t root,
                       sparc64_family_object_t **object, index_header_t *header)
{
    if (root == 0 || sparc64_family_file_index_object(guard) != root) {
        errno = EINVAL; return -1;
    }
    if (sparc64_family_object_open(guard, root, object) != 0)
        return -1;
    sparc64_family_page_state_t page;
    if (sparc64_family_object_count(*object) != 1 ||
        sparc64_family_object_snapshot(guard, *object, 0, &page) != 0 ||
        !metadata_page(&page) || !decode_header(page.bytes, root, header) ||
        !zero(page.bytes + HEADER_SIZE, SPARC64_FAMILY_PAGE_SIZE - HEADER_SIZE)) {
        sparc64_family_object_close(*object); *object = NULL;
        errno = EIO; return -1;
    }
    return 0;
}

static int write_slot(sparc64_family_guard_t *guard, sparc64_family_object_t *object,
                        uint32_t slot, const unsigned char *bytes)
{
    sparc64_family_page_state_t page;
    if (sparc64_family_object_snapshot(guard, object, slot, &page) != 0)
        return -1;
    if (!metadata_page(&page) || page.content_generation == UINT64_MAX) {
        errno = EOVERFLOW; return -1;
    }
    for (size_t i = 0; i < SPARC64_FAMILY_EPOCHS; ++i) {
        if (page.epochs[i] == UINT64_MAX) { errno = EOVERFLOW; return -1; }
        ++page.epochs[i];
    }
    ++page.content_generation;
    memcpy(page.bytes, bytes, SPARC64_FAMILY_PAGE_SIZE);
    return sparc64_family_object_commit(guard, object, slot, &page);
}

static int write_reserved_slot(sparc64_family_guard_t *guard, sparc64_family_object_t *object,
                                uint32_t slot, const unsigned char *bytes)
{
    sparc64_family_page_state_t current, target = {0};
    if (sparc64_family_object_snapshot(guard, object, slot, &current) != 0)
        return -1;
    target.content_generation = 1;
    for (size_t i = 0; i < SPARC64_FAMILY_EPOCHS; ++i)
        target.epochs[i] = 1;
    memcpy(target.bytes, bytes, SPARC64_FAMILY_PAGE_SIZE);
    /* A retry must be either a virgin reserved slot or this exact previously
     * staged target. Never consume another epoch/generation or overwrite a
     * differently occupied object. Ordinary redo replays before this check. */
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
        errno = EIO; return -1;
    }
    return sparc64_family_object_commit(guard, object, slot, &target);
}

static int publish(sparc64_family_guard_t *guard, sparc64_family_object_t *root,
                      sparc64_family_file_index_state_t *state, uint64_t reserved_snapshot)
{
    size_t length;
    uint32_t slots;
    if (!extent(state, &length, &slots) || state->revision == UINT64_MAX) {
        errno = EOVERFLOW; return -1;
    }
    unsigned char *bytes = calloc(slots, SPARC64_FAMILY_PAGE_SIZE);
    if (bytes == NULL)
        return -1;
    sparc64_family_object_t *snapshot = NULL;
    int opened = reserved_snapshot == 0 ? sparc64_family_object_create(guard, slots, &snapshot) :
        sparc64_family_object_open(guard, reserved_snapshot, &snapshot);
    if (opened != 0) { free(bytes); return -1; }
    if (sparc64_family_object_count(snapshot) != slots) {
        sparc64_family_object_close(snapshot); free(bytes); errno = EINVAL; return -1;
    }
    index_header_t h = {.root = sparc64_family_object_id(root), .snapshot = sparc64_family_object_id(snapshot),
                         .length = length, .state = *state};
    ++h.state.revision;
    encode_header(bytes, false, &h);
    size_t offset = HEADER_SIZE;
    for (size_t i = 0; i < state->source_count; ++i, offset += SOURCE_SIZE)
        encode_source(bytes + offset, &state->sources[i]);
    for (size_t i = 0; i < state->association_count; ++i, offset += ASSOC_SIZE) {
        const sparc64_family_file_index_assoc_t *a = &state->associations[i];
        put(bytes + offset, a->key.object_id, 8); put(bytes + offset + 8, a->key.page_index, 8);
        put(bytes + offset + 16, a->source_id, 8); put(bytes + offset + 24, a->file_offset, 8);
    }
    int result = 0;
    for (uint32_t i = 0; result == 0 && i < slots; ++i)
        result = reserved_snapshot == 0 ?
            write_slot(guard, snapshot, i, bytes + (size_t)i * SPARC64_FAMILY_PAGE_SIZE) :
            write_reserved_slot(guard, snapshot, i, bytes + (size_t)i * SPARC64_FAMILY_PAGE_SIZE);
    if (result == 0) {
        unsigned char root_bytes[SPARC64_FAMILY_PAGE_SIZE] = {0};
        encode_header(root_bytes, true, &h);
        result = write_slot(guard, root, 0, root_bytes);
        if (result == 0)
            state->revision = h.state.revision;
    }
    int saved = errno;
    sparc64_family_object_close(snapshot); free(bytes);
    errno = saved;
    return result;
}

void sparc64_family_file_index_state_destroy(sparc64_family_file_index_state_t *state)
{
    if (state != NULL) {
        free(state->sources); free(state->associations);
        *state = (sparc64_family_file_index_state_t){0};
    }
}

int sparc64_family_file_index_create_empty(sparc64_family_guard_t *guard, uint64_t *out_root_object)
{
    if (out_root_object == NULL || *out_root_object != 0 || guard == NULL ||
        !sparc64_family_guard_matches(guard, guard->family) || sparc64_family_sources(guard) != NULL) {
        errno = EINVAL; return -1;
    }
    sparc64_family_object_t *root = NULL;
    if (sparc64_family_object_create(guard, 1, &root) != 0)
        return -1;
    sparc64_family_file_index_state_t empty = {0};
    int result = publish(guard, root, &empty, 0), saved = errno;
    if (result == 0)
        *out_root_object = sparc64_family_object_id(root);
    sparc64_family_object_close(root);
    errno = saved;
    return result;
}

int sparc64_family_file_index_read(sparc64_family_guard_t *guard, uint64_t root_object,
                               sparc64_family_file_index_state_t *out)
{
    if (out == NULL) { errno = EINVAL; return -1; }
    sparc64_family_object_t *root = NULL, *snapshot = NULL;
    index_header_t h;
    if (read_root(guard, root_object, &root, &h) != 0)
        return -1;
    sparc64_family_object_close(root);
    size_t length;
    uint32_t slots;
    if (!extent(&h.state, &length, &slots)) { errno = EIO; return -1; }
    if (sparc64_family_object_open(guard, h.snapshot, &snapshot) != 0)
        return -1;
    if (sparc64_family_object_count(snapshot) != slots) {
        sparc64_family_object_close(snapshot); errno = EIO; return -1;
    }
    size_t allocation = (size_t)slots * SPARC64_FAMILY_PAGE_SIZE;
    unsigned char *bytes = malloc(allocation);
    if (bytes == NULL) { sparc64_family_object_close(snapshot); return -1; }
    sparc64_family_file_index_state_t fresh = h.state;
    int result = -1;
    for (uint32_t i = 0; i < slots; ++i) {
        sparc64_family_page_state_t page;
        if (sparc64_family_object_snapshot(guard, snapshot, i, &page) != 0)
            goto done;
        if (!metadata_page(&page)) { errno = EIO; goto done; }
        memcpy(bytes + (size_t)i * SPARC64_FAMILY_PAGE_SIZE, page.bytes, SPARC64_FAMILY_PAGE_SIZE);
    }
    unsigned char expected[HEADER_SIZE] = {0};
    encode_header(expected, false, &h);
    if (memcmp(bytes, expected, HEADER_SIZE) != 0 || !zero(bytes + length, allocation - length)) {
        errno = EIO; goto done;
    }
    fresh.sources = fresh.source_count == 0 ? NULL : calloc(fresh.source_count, sizeof(*fresh.sources));
    fresh.associations = fresh.association_count == 0 ? NULL : calloc(fresh.association_count, sizeof(*fresh.associations));
    if ((fresh.source_count != 0 && fresh.sources == NULL) ||
        (fresh.association_count != 0 && fresh.associations == NULL))
        goto done;
    size_t offset = HEADER_SIZE;
    for (size_t i = 0; i < fresh.source_count; ++i, offset += SOURCE_SIZE) {
        sparc64_family_file_index_source_t *s = &fresh.sources[i];
        s->source_id = get(bytes + offset, 8); s->reconciled_size = get(bytes + offset + 8, 8);
        s->mutation_sequence = get(bytes + offset + 16, 8); s->identity.device = get(bytes + offset + 24, 8);
        s->identity.provider = (uint32_t)get(bytes + offset + 32, 4);
        s->identity.format = (uint32_t)get(bytes + offset + 36, 4);
        s->identity.length = (uint32_t)get(bytes + offset + 40, 4);
        uint64_t eligible = get(bytes + offset + 44, 4);
        if (eligible > 1) { errno = EIO; goto done; }
        s->identity.mapped_key_eligible = eligible != 0;
        memcpy(s->identity.bytes, bytes + offset + 48, SPARC64_FILE_IDENTITY_MAX_BYTES);
    }
    for (size_t i = 0; i < fresh.association_count; ++i, offset += ASSOC_SIZE)
        fresh.associations[i] = (sparc64_family_file_index_assoc_t){
            .key = {get(bytes + offset, 8), get(bytes + offset + 8, 8)},
            .source_id = get(bytes + offset + 16, 8), .file_offset = get(bytes + offset + 24, 8)};
    if (!valid_state(&fresh, root_object)) { errno = EIO; goto done; }
    sparc64_family_file_index_state_destroy(out);
    *out = fresh;
    fresh = (sparc64_family_file_index_state_t){0};
    result = 0;
done: {
        int saved = errno;
        sparc64_family_file_index_state_destroy(&fresh);
        free(bytes); sparc64_family_object_close(snapshot);
        errno = saved;
        return result;
    }
}

static int validate_transition(sparc64_family_guard_t *guard,
    const sparc64_family_file_index_state_t *old, const sparc64_family_file_index_state_t *next)
{
    size_t at = 0;
    for (size_t i = 0; i < old->association_count; ++i) {
        const sparc64_family_file_index_assoc_t *a = &old->associations[i];
        while (at < next->association_count && key_compare(next->associations[at].key, a->key) < 0)
            ++at;
        if (at == next->association_count || key_compare(next->associations[at].key, a->key) != 0 ||
            next->associations[at].source_id != a->source_id || next->associations[at].file_offset != a->file_offset) {
            errno = EINVAL; return -1;
        }
    }
    for (size_t i = 0; i < old->source_count; ++i) {
        const sparc64_family_file_index_source_t *a = &old->sources[i];
        const sparc64_family_file_index_source_t *b = find_source(next, a->source_id);
        unsigned char x[SOURCE_SIZE], y[SOURCE_SIZE];
        if (b == NULL) { errno = EINVAL; return -1; }
        encode_source(x, a); encode_source(y, b);
        if (memcmp(x + 24, y + 24, SOURCE_SIZE - 24u) != 0 ||
            b->mutation_sequence < a->mutation_sequence ||
            (b->reconciled_size != a->reconciled_size && b->mutation_sequence == a->mutation_sequence)) {
            errno = EINVAL; return -1;
        }
    }
    /* ACK retention is proved by fetch, never by an allocated-ID range. */
    for (size_t i = 0; i < next->source_count; ++i) {
        const sparc64_family_file_index_source_t *s = &next->sources[i];
        if (find_source(old, s->source_id) != NULL)
            continue;
        if (s->mutation_sequence != 0) { errno = EINVAL; return -1; }
        int fd = -1;
        if (sparc64_file_caps_fetch(sparc64_family_sources(guard), s->source_id, &fd) != 0)
            return -1;
        struct stat status;
        int result = fstat(fd, &status), saved = errno;
        (void)close(fd);
        if (result != 0) { errno = saved; return -1; }
        if (!S_ISREG(status.st_mode) || status.st_size < 0 || (uint64_t)status.st_size != s->reconciled_size) {
            errno = EAGAIN; return -1;
        }
    }
    for (size_t i = 0; i < next->association_count; ++i) {
        sparc64_family_object_t *object = NULL;
        const sparc64_family_file_index_assoc_t *a = &next->associations[i];
        if (sparc64_family_object_open(guard, a->key.object_id, &object) != 0)
            return -1;
        bool valid = a->key.page_index < sparc64_family_object_count(object);
        sparc64_family_object_close(object);
        if (!valid) { errno = EINVAL; return -1; }
    }
    return 0;
}

int sparc64_family_file_index_commit(sparc64_family_guard_t *guard, uint64_t root_object,
                                 sparc64_family_file_index_state_t *state)
{
    if (state == NULL) { errno = EINVAL; return -1; }
    sparc64_family_object_t *root = NULL;
    index_header_t h;
    if (read_root(guard, root_object, &root, &h) != 0)
        return -1;
    int result = -1;
    if (state->revision != h.state.revision)
        errno = EAGAIN;
    else if (h.cursor.phase != SPARC64_FILE_IDLE)
        errno = EBUSY;
    else if (!valid_state(state, root_object))
        errno = EINVAL;
    else {
        sparc64_family_file_index_state_t old = {0};
        if (sparc64_family_file_index_read(guard, root_object, &old) == 0 &&
            validate_transition(guard, &old, state) == 0)
            result = publish(guard, root, state, 0);
        sparc64_family_file_index_state_destroy(&old);
    }
    int saved = errno;
    sparc64_family_object_close(root);
    errno = saved;
    return result;
}

static bool same_cursor(const sparc64_family_file_cursor_t *a,
                          const sparc64_family_file_cursor_t *b)
{
    return a->snapshot_object == b->snapshot_object && a->revision == b->revision &&
        a->intent_object == b->intent_object && a->observed_object == b->observed_object &&
        a->cursor == b->cursor && a->phase == b->phase;
}

int sparc64_family_file_index_cursor_read(sparc64_family_guard_t *guard,
                                      sparc64_family_file_cursor_t *out)
{
    if (out == NULL) { errno = EINVAL; return -1; }
    sparc64_family_object_t *root = NULL;
    index_header_t h;
    uint64_t id = sparc64_family_file_index_object(guard);
    if (id == 0 || read_root(guard, id, &root, &h) != 0)
        return -1;
    sparc64_family_object_close(root);
    *out = h.cursor;
    return 0;
}

int sparc64_family_file_index_cursor_reserve(sparc64_family_guard_t *guard, uint64_t updates)
{
    sparc64_family_object_t *root = NULL;
    index_header_t h;
    uint64_t id = sparc64_family_file_index_object(guard);
    if (updates == 0) { errno = EINVAL; return -1; }
    if (id == 0 || read_root(guard, id, &root, &h) != 0)
        return -1;
    int result = -1;
    sparc64_family_page_state_t page;
    if (h.cursor.phase != SPARC64_FILE_IDLE) { errno = EBUSY; goto done; }
    if (sparc64_family_object_snapshot(guard, root, 0, &page) != 0)
        goto done;
    if (h.state.revision == UINT64_MAX || updates > UINT64_MAX - page.content_generation) {
        errno = EOVERFLOW; goto done;
    }
    for (size_t i = 0; i < SPARC64_FAMILY_EPOCHS; ++i)
        if (updates > UINT64_MAX - page.epochs[i]) { errno = EOVERFLOW; goto done; }
    result = 0;
done: {
        int saved = errno;
        sparc64_family_object_close(root);
        errno = saved;
        return result;
    }
}

int sparc64_family_file_index_reserve_snapshot(sparc64_family_guard_t *guard, uint64_t *out_object)
{
    if (out_object == NULL || *out_object != 0) { errno = EINVAL; return -1; }
    uint64_t id = sparc64_family_file_index_object(guard);
    sparc64_family_object_t *root = NULL, *reserved = NULL;
    index_header_t h;
    if (id == 0 || read_root(guard, id, &root, &h) != 0)
        return -1;
    size_t length;
    uint32_t slots;
    int result = -1;
    if (h.cursor.phase != SPARC64_FILE_IDLE) { errno = EBUSY; goto done; }
    if (!extent(&h.state, &length, &slots)) { errno = EIO; goto done; }
    if (sparc64_family_object_create(guard, slots, &reserved) != 0)
        goto done;
    *out_object = sparc64_family_object_id(reserved);
    result = 0;
done: {
        int saved = errno;
        sparc64_family_object_close(reserved); sparc64_family_object_close(root);
        errno = saved;
        return result;
    }
}

int sparc64_family_file_index_cursor_advance(sparc64_family_guard_t *guard,
                                         const sparc64_family_file_cursor_t *expected,
                                         const sparc64_family_file_cursor_t *next,
                                         const sparc64_family_object_update_t *payload)
{
    if (expected == NULL || next == NULL || !cursor_valid(expected) || !cursor_valid(next) ||
        expected->snapshot_object != next->snapshot_object || expected->revision != next->revision) {
        errno = EINVAL; return -1;
    }
    bool stage = expected->phase == SPARC64_FILE_IDLE && next->phase == SPARC64_FILE_STAGED;
    bool observe = expected->phase == SPARC64_FILE_STAGED && next->phase == SPARC64_FILE_RECONCILE &&
        next->intent_object == expected->intent_object && next->cursor == 0;
    bool step = expected->phase == SPARC64_FILE_RECONCILE && next->phase == SPARC64_FILE_RECONCILE &&
        next->intent_object == expected->intent_object &&
        next->observed_object == expected->observed_object &&
        next->cursor == expected->cursor + 1u;
    if ((!stage && !observe && !step) || (payload != NULL && !step)) {
        errno = EINVAL; return -1;
    }
    uint64_t id = sparc64_family_file_index_object(guard);
    sparc64_family_object_t *root = NULL, *record = NULL;
    index_header_t h;
    if (id == 0 || read_root(guard, id, &root, &h) != 0)
        return -1;
    int result = -1;
    if (!same_cursor(&h.cursor, expected)) { errno = EAGAIN; goto done; }
    uint64_t record_id = stage ? next->intent_object : observe ? next->observed_object : 0;
    if (next->intent_object == id || next->observed_object == id ||
        next->intent_object == h.snapshot || next->observed_object == h.snapshot) {
        errno = EINVAL; goto done;
    }
    if (record_id != 0 && sparc64_family_object_open(guard, record_id, &record) != 0)
        goto done;
    if (payload != NULL) {
        uint64_t payload_id = sparc64_family_object_id(payload->object);
        if (payload_id == id || payload_id == h.snapshot ||
            payload_id == next->intent_object || payload_id == next->observed_object) {
            errno = EINVAL; goto done;
        }
    }
    sparc64_family_page_state_t target;
    if (sparc64_family_object_snapshot(guard, root, 0, &target) != 0)
        goto done;
    if (target.content_generation == UINT64_MAX) { errno = EOVERFLOW; goto done; }
    for (size_t i = 0; i < SPARC64_FAMILY_EPOCHS; ++i) {
        if (target.epochs[i] == UINT64_MAX) { errno = EOVERFLOW; goto done; }
        ++target.epochs[i];
    }
    ++target.content_generation;
    h.cursor = *next;
    memset(target.bytes, 0, sizeof(target.bytes));
    encode_header(target.bytes, true, &h);
    sparc64_family_object_update_t updates[2] = {{root, 0, &target}, {0}};
    if (payload != NULL)
        updates[1] = *payload;
    result = sparc64_family_object_commitv(guard, updates, payload == NULL ? 1u : 2u);
done: {
        int saved = errno;
        sparc64_family_object_close(record); sparc64_family_object_close(root);
        errno = saved;
        return result;
    }
}

int sparc64_family_file_index_finish(sparc64_family_guard_t *guard,
                                 const sparc64_family_file_cursor_t *expected,
                                 uint64_t reserved_snapshot,
                                 sparc64_family_file_index_state_t *state)
{
    if (expected == NULL || state == NULL || expected->phase != SPARC64_FILE_RECONCILE ||
        reserved_snapshot == 0 || reserved_snapshot == expected->snapshot_object ||
        reserved_snapshot == expected->intent_object || reserved_snapshot == expected->observed_object) {
        errno = EINVAL; return -1;
    }
    uint64_t id = sparc64_family_file_index_object(guard);
    sparc64_family_object_t *root = NULL;
    index_header_t h;
    if (id == 0 || read_root(guard, id, &root, &h) != 0)
        return -1;
    int result = -1;
    if (reserved_snapshot == id)
        errno = EINVAL;
    else if (!same_cursor(&h.cursor, expected) || state->revision != h.state.revision)
        errno = EAGAIN;
    else if (!valid_state(state, id))
        errno = EINVAL;
    else {
        sparc64_family_file_index_state_t old = {0};
        if (sparc64_family_file_index_read(guard, id, &old) == 0) {
            if (old.source_count != state->source_count ||
                old.association_count != state->association_count)
                errno = EINVAL;
            else if (validate_transition(guard, &old, state) == 0)
                result = publish(guard, root, state, reserved_snapshot);
        }
        sparc64_family_file_index_state_destroy(&old);
    }
    int saved = errno;
    sparc64_family_object_close(root);
    errno = saved;
    return result;
}
