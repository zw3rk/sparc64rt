/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#include "exec_state_split.h"


static void put32(unsigned char *p, uint32_t value)
{
    for (unsigned int i = 0; i < 4; ++i)
        p[i] = (unsigned char)(value >> (8u * i));
}

static void put64(unsigned char *p, uint64_t value)
{
    for (unsigned int i = 0; i < 8; ++i)
        p[i] = (unsigned char)(value >> (8u * i));
}

uint32_t get32(const unsigned char *p)
{
    uint32_t value = 0;
    for (unsigned int i = 0; i < 4; ++i)
        value |= (uint32_t)p[i] << (8u * i);
    return value;
}

uint64_t get64(const unsigned char *p)
{
    uint64_t value = 0;
    for (unsigned int i = 0; i < 8; ++i)
        value |= (uint64_t)p[i] << (8u * i);
    return value;
}

static bool write_bytes(writer_t *writer, const void *bytes, size_t length)
{
    if (length > writer->limit - writer->pos) {
        errno = E2BIG;
        return false;
    }
    memcpy(writer->bytes + writer->pos, bytes, length);
    writer->pos += length;
    return true;
}

static bool write32(writer_t *writer, uint32_t value)
{
    unsigned char bytes[4];
    put32(bytes, value);
    return write_bytes(writer, bytes, sizeof(bytes));
}

static bool write64(writer_t *writer, uint64_t value)
{
    unsigned char bytes[8];
    put64(bytes, value);
    return write_bytes(writer, bytes, sizeof(bytes));
}

bool read_bytes(reader_t *reader, void *bytes, size_t length)
{
    if (length > reader->limit - reader->pos) {
        errno = EINVAL;
        return false;
    }
    memcpy(bytes, reader->bytes + reader->pos, length);
    reader->pos += length;
    return true;
}

bool read32(reader_t *reader, uint32_t *value)
{
    unsigned char bytes[4];
    if (!read_bytes(reader, bytes, sizeof(bytes)))
        return false;
    *value = get32(bytes);
    return true;
}

bool read64(reader_t *reader, uint64_t *value)
{
    unsigned char bytes[8];
    if (!read_bytes(reader, bytes, sizeof(bytes)))
        return false;
    *value = get64(bytes);
    return true;
}

static bool string_length(const char *string, size_t maximum, size_t *length)
{
    if (string == NULL) {
        errno = EINVAL;
        return false;
    }
    size_t size = strnlen(string, maximum);
    if (size == maximum) {
        errno = E2BIG;
        return false;
    }
    *length = size + 1;
    return true;
}

static bool write_string(writer_t *writer, const char *string,
                         size_t maximum)
{
    size_t length;
    return string_length(string, maximum, &length) &&
           write32(writer, (uint32_t)length) &&
           write_bytes(writer, string, length);
}

bool read_string(reader_t *reader, size_t maximum, char **out)
{
    uint32_t length;
    if (!read32(reader, &length))
        return false;
    if (length == 0 || length > maximum || length > reader->limit - reader->pos) {
        errno = EINVAL;
        return false;
    }
    char *copy = malloc(length);
    if (copy == NULL)
        return false;
    if (!read_bytes(reader, copy, length)) {
        free(copy);
        return false;
    }
    if (copy[length - 1] != '\0' || strnlen(copy, length) != length - 1) {
        free(copy);
        errno = EINVAL;
        return false;
    }
    *out = copy;
    return true;
}

static bool family_valid(const sparc64_family_exec_state_t *family)
{
    if (family->owner_pid != (uint64_t)getpid() ||
        family->incarnation == 0 ||
        family->incarnation >= family->next_incarnation ||
        family->identity.control_inode == 0 ||
        family->identity.directory_inode == 0)
        return false;
    size_t directory = strnlen(family->directory, sizeof(family->directory));
    return directory < sizeof(family->directory) &&
           (family->creator ? (directory != 0 && family->directory[0] == '/') :
                              directory == 0);
}

static bool config_valid(const sparc64_exec_config_t *config)
{
    if (config->xlen != 64 || config->quantum == 0 ||
        (config->flags & ~SPARC64_EXEC_FLAG_ALL) != 0 ||
        config->stats_period > UINT32_MAX ||
        config->progress_period > UINT32_MAX ||
        (config->max_steps != 0 && config->steps > config->max_steps) ||
        config->jit_steps > config->steps ||
        config->fallback_steps > config->steps ||
        config->jit_steps > UINT64_MAX - config->fallback_steps ||
        config->jit_steps + config->fallback_steps > config->steps ||
        config->cache_authority > SPARC64_AOT_AUTHORITY_HYPER_LINUX_APFS_ACL_V1 ||
        (config->cache_blocks == 0 ||
         config->cache_blocks > SPARC64_AOT_DISCOVERY_MAX_BLOCKS))
        return false;
#ifdef SPARC64_RUNTIME_TEST_ATTRIBUTED_FILE
    if (config->fsize_soft > config->fsize_hard)
        return false;
#endif
    return true;
}

static bool clear_tid_valid(const sparc64_exec_tid_clear_t *clear)
{
    if (clear->segment_count == 0 || clear->segment_count > 2)
        return false;
    if (clear->role > SPARC64_EXEC_TID_CALLER_IF_LIVE_PEER)
        return false;
#ifndef SPARC64_RUNTIME_TEST_ATTRIBUTED_FILE
    if (clear->mm_shared_wake_address != 0 || clear->role != SPARC64_EXEC_TID_SIBLING)
        return false;
#endif
    if (clear->mm_shared_wake_address != 0 &&
        (clear->segment_count != 1 || clear->lengths[0] != 4 ||
         (clear->mm_shared_wake_address & 3u) != 0 ||
         (clear->mm_shared_wake_address & (SPARC64_FAMILY_PAGE_SIZE - 1u)) !=
             clear->offsets[0]))
        return false;
    uint32_t total = 0;
    for (uint32_t i = 0; i < 2; ++i) {
        bool used = i < clear->segment_count;
        if (!used) {
            if (clear->keys[i].object_id != 0 ||
                clear->keys[i].page_index != 0 ||
                clear->offsets[i] != 0 || clear->lengths[i] != 0)
                return false;
            continue;
        }
        if (clear->keys[i].object_id == 0 ||
            clear->keys[i].page_index > UINT32_MAX ||
            clear->lengths[i] == 0 || clear->lengths[i] > 4 ||
            clear->offsets[i] > SPARC64_FAMILY_PAGE_SIZE - clear->lengths[i])
            return false;
        total += clear->lengths[i];
    }
    if (total > 4)
        return false;
    if (clear->segment_count == 2 &&
        clear->keys[0].object_id == clear->keys[1].object_id &&
        clear->keys[0].page_index == clear->keys[1].page_index) {
        uint32_t a = clear->offsets[0], b = clear->offsets[1];
        if (a < b + clear->lengths[1] && b < a + clear->lengths[0])
            return false;
    }
    return true;
}

bool state_valid(const sparc64_exec_state_t *state)
{
    if (state == NULL || state->args.argc == 0) {
        errno = EINVAL;
        return false;
    }
    if (state->args.argc > SPARC64_LINUX_EXEC_VECTOR_MAX ||
        state->args.envc > SPARC64_LINUX_EXEC_VECTOR_MAX ||
        state->child_count > EXEC_INVENTORY_MAX ||
        state->fifo_count > EXEC_INVENTORY_MAX ||
        state->clear_tid_count > EXEC_INVENTORY_MAX) {
        errno = E2BIG;
        return false;
    }
    if (state->args.argv == NULL || state->args.envp == NULL ||
        state->args.argv[state->args.argc] != NULL ||
        state->args.envp[state->args.envc] != NULL ||
        (state->child_count != 0 && state->children == NULL) ||
        (state->fifo_count != 0 && state->fifos == NULL) ||
        (state->clear_tid_count != 0 && state->clear_tids == NULL) ||
        !sparc64_linux_signal_exec_state_valid(&state->signals) ||
        !family_valid(&state->family) || state->old_mm_id == 0 ||
        state->parent_pid < 0 ||
#ifdef SPARC64_RUNTIME_TEST_ATTRIBUTED_FILE
        (state->old_mm_root_object == 0) != (state->old_mm_task_id == 0) ||
#endif
        !config_valid(&state->config)) {
        errno = EINVAL;
        return false;
    }
    size_t length, total = 0;
    if (!string_length(state->args.path, SPARC64_LINUX_EXEC_PATH_MAX, &length))
        return false;
    total += length;
    for (size_t i = 0; i < state->args.argc + state->args.envc; ++i) {
        const char *string = i < state->args.argc ? state->args.argv[i] :
                             state->args.envp[i - state->args.argc];
        if (!string_length(string, SPARC64_LINUX_EXEC_BYTES_MAX, &length))
            return false;
        if (length > SPARC64_LINUX_EXEC_BYTES_MAX - total) {
            errno = E2BIG;
            return false;
        }
        total += length;
    }
    if (state->sysroot != NULL) {
        if (!string_length(state->sysroot, EXEC_SYSROOT_MAX, &length))
            return false;
        if (state->sysroot[0] != '/') {
            errno = EINVAL;
            return false;
        }
    }
    if (state->cache_directory != NULL) {
        if (!string_length(state->cache_directory,
                           EXEC_CACHE_DIRECTORY_MAX, &length))
            return false;
        if (length == 1 || state->cache_directory[0] != '/') {
            errno = EINVAL;
            return false;
        }
    } else if (state->config.cache_authority != SPARC64_AOT_AUTHORITY_AUTO ||
               state->config.cache_blocks != 1) {
        errno = EINVAL;
        return false;
    }
    for (size_t i = 0; i < state->child_count; ++i) {
        if (state->children[i].pid <= 0 ||
            state->children[i].pid == getpid() ||
            state->children[i].cap_fd < 3 ||
            (state->children[i].role != SPARC64_PROCESS_CHILD_FAMILY &&
             state->children[i].role != SPARC64_PROCESS_CHILD_EXTERNAL)) {
            errno = EINVAL;
            return false;
        }
        for (size_t j = 0; j < i; ++j)
            if (state->children[j].pid == state->children[i].pid ||
                state->children[j].cap_fd == state->children[i].cap_fd) {
                errno = EINVAL;
                return false;
            }
    }
    for (size_t i = 0; i < state->fifo_count; ++i)
        if (state->fifos[i].inode == 0 ||
            state->fifos[i].birth_nanoseconds >= 1000000000u) {
            errno = EINVAL;
            return false;
        }
    bool caller_root_valid = true;
#ifdef SPARC64_RUNTIME_TEST_ATTRIBUTED_FILE
    caller_root_valid = state->old_mm_root_object != 0;
#endif
    size_t conditional_callers = 0;
    for (size_t i = 0; i < state->clear_tid_count; ++i)
        if (!clear_tid_valid(&state->clear_tids[i]) ||
            (state->clear_tids[i].role == SPARC64_EXEC_TID_CALLER_IF_LIVE_PEER &&
             (++conditional_callers > 1 || !caller_root_valid))) {
            errno = EINVAL;
            return false;
        }
    return true;
}

void sparc64_exec_state_destroy(sparc64_exec_state_t *state)
{
    if (state == NULL)
        return;
    int saved = errno;
    sparc64_linux_exec_args_destroy(&state->args);
    free(state->sysroot);
    free(state->cache_directory);
    free(state->children);
    free(state->fifos);
    free(state->clear_tids);
    memset(state, 0, sizeof(*state));
    errno = saved;
}

bool encode(const sparc64_exec_state_t *state, unsigned char **out,
                   size_t *length)
{
    if (!state_valid(state))
        return false;
    unsigned char *bytes = calloc(1, EXEC_RECORD_MAX);
    if (bytes == NULL)
        return false;
    writer_t writer = {.bytes = bytes, .limit = EXEC_RECORD_MAX};
    const sparc64_family_exec_state_t *family = &state->family;
    const sparc64_exec_config_t *config = &state->config;
    bool valid = write_bytes(&writer, EXEC_RECORD_MAGIC, 8) &&
        write32(&writer, EXEC_RECORD_VERSION) && write32(&writer, EXEC_RECORD_HEADER) &&
        write64(&writer, 0) &&
        write32(&writer, (uint32_t)state->args.argc) &&
        write32(&writer, (uint32_t)state->args.envc) &&
        write32(&writer, (uint32_t)state->child_count) &&
        write32(&writer, (uint32_t)state->fifo_count) &&
        write64(&writer, config->max_steps) &&
        write64(&writer, config->steps) &&
        write64(&writer, config->jit_steps) &&
        write64(&writer, config->fallback_steps) &&
        write64(&writer, config->progress_period) &&
        write64(&writer, config->stats_period) &&
        write64(&writer, config->worker_attempts) &&
#ifdef SPARC64_RUNTIME_TEST_ATTRIBUTED_FILE
        write64(&writer, config->fsize_soft) &&
        write64(&writer, config->fsize_hard) &&
#endif
        write32(&writer, config->quantum) &&
        write32(&writer, config->flags) &&
        write32(&writer, config->xlen) &&
        write64(&writer, family->owner_pid) &&
        write64(&writer, family->incarnation) &&
        write64(&writer, family->recovery_epoch) &&
        write64(&writer, family->next_incarnation) &&
        write64(&writer, state->old_mm_id) &&
        write64(&writer, (uint64_t)state->parent_pid) &&
#ifdef SPARC64_RUNTIME_TEST_ATTRIBUTED_FILE
        write64(&writer, state->old_mm_root_object) &&
        write64(&writer, state->old_mm_task_id) &&
#endif
        write64(&writer, (uint64_t)family->identity.control_device) &&
        write64(&writer, (uint64_t)family->identity.control_inode) &&
        write64(&writer, (uint64_t)family->identity.directory_device) &&
        write64(&writer, (uint64_t)family->identity.directory_inode) &&
        write32(&writer, family->creator ? 1u : 0u) &&
        write_string(&writer, family->directory, sizeof(family->directory)) &&
        write64(&writer, state->signals.ignored) &&
        write64(&writer, state->signals.blocked) &&
        write64(&writer, state->signals.process_pending) &&
        write64(&writer, state->signals.thread_pending) &&
        write_bytes(&writer, state->signals.process_information,
                    sizeof(state->signals.process_information)) &&
        write_bytes(&writer, state->signals.thread_information,
                    sizeof(state->signals.thread_information)) &&
        write_string(&writer, state->args.path, SPARC64_LINUX_EXEC_PATH_MAX);
    for (size_t i = 0; valid && i < state->args.argc; ++i)
        valid = write_string(&writer, state->args.argv[i],
                             SPARC64_LINUX_EXEC_BYTES_MAX);
    for (size_t i = 0; valid && i < state->args.envc; ++i)
        valid = write_string(&writer, state->args.envp[i],
                             SPARC64_LINUX_EXEC_BYTES_MAX);
    if (valid)
        valid = state->sysroot == NULL ? write32(&writer, 0) :
                write_string(&writer, state->sysroot, EXEC_SYSROOT_MAX);
    for (size_t i = 0; valid && i < state->child_count; ++i)
        valid = write64(&writer, (uint64_t)state->children[i].pid) &&
                write64(&writer, (uint64_t)state->children[i].cap_fd) &&
                write32(&writer, (uint32_t)state->children[i].role) &&
                write32(&writer, 0u);
    for (size_t i = 0; valid && i < state->fifo_count; ++i) {
        const sparc64_linux_fifo_identity_t *fifo = &state->fifos[i];
        valid = write32(&writer, fifo->device_major) &&
                write32(&writer, fifo->device_minor) &&
                write64(&writer, fifo->inode) &&
                write64(&writer, (uint64_t)fifo->birth_seconds) &&
                write32(&writer, fifo->birth_nanoseconds) &&
                write32(&writer, 0);
    }
    if (valid)
        valid = write32(&writer, (uint32_t)state->clear_tid_count);
    for (size_t i = 0; valid && i < state->clear_tid_count; ++i) {
        const sparc64_exec_tid_clear_t *clear = &state->clear_tids[i];
        valid = write32(&writer, clear->segment_count);
        for (size_t segment = 0; valid && segment < 2; ++segment)
            valid = write64(&writer, clear->keys[segment].object_id) &&
                    write64(&writer, clear->keys[segment].page_index) &&
                    write32(&writer, clear->offsets[segment]) &&
                    write32(&writer, clear->lengths[segment]);
#ifdef SPARC64_RUNTIME_TEST_ATTRIBUTED_FILE
        if (valid)
            valid = write64(&writer, clear->mm_shared_wake_address) &&
                    write64(&writer, clear->role);
#endif
    }
    if (valid)
        valid = write32(&writer, config->cache_authority) &&
                write32(&writer, config->cache_blocks) &&
                (state->cache_directory == NULL ? write32(&writer, 0) :
                 write_string(&writer, state->cache_directory,
                              EXEC_CACHE_DIRECTORY_MAX));
    if (!valid) {
        free(bytes);
        return false;
    }
    put64(bytes + 16, writer.pos);
    *out = bytes;
    *length = writer.pos;
    return true;
}

int64_t decode_i64(uint64_t word)
{
    if (word <= INT64_MAX)
        return (int64_t)word;
    return -(int64_t)(~word) - 1;
}
