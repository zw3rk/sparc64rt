/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#define _GNU_SOURCE 1
#include "runtime/aot_cache.h"
#include "aot/digest.h"
#include "aot/reader.h"
#include "aot/writer.h"
#include "core/profile.h"

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

static void decline(sparc64_runtime_aot_cache_t *cache, const char *reason)
{
    cache->status = SPARC64_RUNTIME_AOT_DECLINED;
    cache->reason = reason;
}

static void little32(uint8_t *out, uint32_t value)
{
    for (unsigned i = 0; i < 4; ++i)
        out[i] = (uint8_t)(value >> (i * 8u));
}

static void little64(uint8_t *out, uint64_t value)
{
    for (unsigned i = 0; i < 8; ++i)
        out[i] = (uint8_t)(value >> (i * 8u));
}

static uint32_t get32(const uint8_t *bytes)
{
    return (uint32_t)bytes[0] | ((uint32_t)bytes[1] << 8) |
           ((uint32_t)bytes[2] << 16) | ((uint32_t)bytes[3] << 24);
}

static bool source_read(void *opaque, uint64_t address, void *bytes,
                        size_t size, sparc64_access_t access, sparc64_mem_fault_t *fault)
{
    sparc64_space_t *space = opaque;
    bool ok = sparc64_space_read(space, address, bytes, size,
                            access == SPARC64_ACCESS_FETCH ? SPARC64_MEM_EXEC : SPARC64_MEM_READ);
    if (!ok && fault != NULL) {
        sparc64_mem_fault_reason_t reason = SPARC64_MEM_FAULT_INTERNAL;
        switch (space->fault_reason) {
        case SPARC64_FAULT_UNMAPPED: reason = SPARC64_MEM_FAULT_UNMAPPED; break;
        case SPARC64_FAULT_PERMISSION: reason = SPARC64_MEM_FAULT_PERMISSION; break;
        case SPARC64_FAULT_RANGE: reason = SPARC64_MEM_FAULT_RANGE; break;
        case SPARC64_FAULT_BUS: reason = SPARC64_MEM_FAULT_BUS; break;
        case SPARC64_FAULT_RESOURCE: reason = SPARC64_MEM_FAULT_RESOURCE; break;
        case SPARC64_FAULT_RETRY: reason = SPARC64_MEM_FAULT_RETRY; break;
        case SPARC64_FAULT_NONE:
        case SPARC64_FAULT_INTERNAL: break;
        }
        *fault = (sparc64_mem_fault_t){space->fault_address, reason};
    }
    return ok;
}

typedef struct {
    sparc64_space_t *space;
    uint64_t start;
    uint64_t end;
} source_span_t;

static bool source_span_read(void *opaque, uint64_t address, void *bytes,
                             size_t size, sparc64_access_t access,
                             sparc64_mem_fault_t *fault)
{
    source_span_t *span = opaque;
    if (span == NULL || span->space == NULL || address < span->start ||
        address > span->end || (uint64_t)size > span->end - address) {
        if (fault != NULL) {
            fault->address = span != NULL && address >= span->start ?
                             span->end : address;
            fault->reason = SPARC64_MEM_FAULT_UNMAPPED;
        }
        return false;
    }
    return source_read(span->space, address, bytes, size, access, fault);
}

static bool runtime_digest(int fd, uint8_t out[SPARC64_AOT_DIGEST_BYTES])
{
    struct stat before, after;
    if (fd < 3 || fstat(fd, &before) != 0 || !S_ISREG(before.st_mode) ||
        before.st_size <= 0 || before.st_size > (off_t)(128u * 1024u * 1024u))
        return false;
    size_t length = (size_t)before.st_size;
    void *bytes = mmap(NULL, length, PROT_READ, MAP_PRIVATE, fd, 0);
    if (bytes == MAP_FAILED)
        return false;
    bool valid = sparc64_aot_sha256(bytes, length, out) == 0 &&
        fstat(fd, &after) == 0 && before.st_dev == after.st_dev &&
        before.st_ino == after.st_ino && before.st_size == after.st_size;
#if defined(__APPLE__)
    valid = valid && before.st_mtimespec.tv_sec == after.st_mtimespec.tv_sec &&
        before.st_mtimespec.tv_nsec == after.st_mtimespec.tv_nsec;
#else
    valid = valid && before.st_mtim.tv_sec == after.st_mtim.tv_sec &&
        before.st_mtim.tv_nsec == after.st_mtim.tv_nsec;
#endif
    (void)munmap(bytes, length);
    return valid;
}

static bool identity_create(const uint8_t *target, size_t target_size,
                            const uint8_t *interpreter, size_t interpreter_size,
                            int runtime_fd, sparc64_aot_identity_t *out)
{
    static const uint8_t emitter[] = "sparc64rt-a64-direct-source-relative-rvc-v3";
    static const uint8_t dynamic_domain[] =
        "sparc64rt-aot-main-and-pt-interp-snapshots-v1";
    static const uint8_t profile_domain[] =
        "sparc64rt-rv64gc-lp64d-sparse-checked-extensions-v1";
    const sparc64_profile_t *profile = sparc64_profile_for_xlen(64);
    uint8_t profile_bytes[256];
    size_t profile_size = sizeof(profile_domain) - 1u;
    uint64_t extension_bits = 0;
    long host_page = sysconf(_SC_PAGESIZE);
    if (target == NULL || target_size == 0 || profile == NULL ||
        profile->elf_float_abi != 4 ||
        profile->extension_count >
            (sizeof(profile_bytes) - profile_size - 4u) / 12u ||
        host_page <= 0 ||
        (uint64_t)host_page > UINT32_MAX ||
        (interpreter != NULL && interpreter_size == 0) ||
        (interpreter == NULL && interpreter_size != 0) ||
        !runtime_digest(runtime_fd, out->runtime_digest))
        return false;
    if (interpreter == NULL) {
        if (sparc64_aot_sha256(target, target_size, out->input_digest) != 0)
            return false;
    } else {
        uint8_t lengths[16];
        little64(lengths, (uint64_t)target_size);
        little64(lengths + 8, (uint64_t)interpreter_size);
        const sparc64_aot_span_t images[] = {
            {dynamic_domain, sizeof(dynamic_domain) - 1u},
            {lengths, 8u}, {target, target_size},
            {lengths + 8, 8u}, {interpreter, interpreter_size}
        };
        if (sparc64_aot_sha256_spans(images, 5, out->input_digest) != 0)
            return false;
    }
    memcpy(profile_bytes, profile_domain, profile_size);
    little32(profile_bytes + profile_size,
             (uint32_t)profile->extension_count);
    profile_size += 4u;
    for (size_t i = 0; i < profile->extension_count; ++i) {
        const sparc64_extension_t *extension = &profile->extensions[i];
        if ((unsigned)extension->id >= 64u ||
            (extension_bits & (UINT64_C(1) << (unsigned)extension->id)) != 0)
            return false;
        extension_bits |= UINT64_C(1) << (unsigned)extension->id;
        little32(profile_bytes + profile_size, (uint32_t)extension->id);
        little32(profile_bytes + profile_size + 4u, extension->major);
        little32(profile_bytes + profile_size + 8u, extension->minor);
        profile_size += 12u;
    }
    const sparc64_aot_span_t emitter_spans[] = {
        {emitter, sizeof(emitter) - 1},
        {out->runtime_digest, sizeof(out->runtime_digest)}
    };
    if (sparc64_aot_sha256_spans(emitter_spans, 2, out->emitter_digest) != 0 ||
        sparc64_aot_sha256(profile_bytes, profile_size,
                      out->profile_digest) != 0)
        return false;
    out->guest_extensions = extension_bits; /* sparc64_extension_id_t bit positions. */
    out->a64_host_requirements = 0; /* Baseline AArch64 only. */
    out->guest_page_size = SPARC64_PAGE_SIZE;
    out->a64_host_page_size = (uint32_t)host_page;
    out->memory_model = SPARC64_AOT_MEMORY_SPARSE_CHECKED;
    out->xlen = 64;
    out->abi = SPARC64_AOT_ABI_LP64D;
    return true;
}

static void image_identity(sparc64_aot_image_t *image,
                           const sparc64_aot_identity_t *identity)
{
    memcpy(image->input_digest, identity->input_digest, SPARC64_AOT_DIGEST_BYTES);
    memcpy(image->runtime_digest, identity->runtime_digest, SPARC64_AOT_DIGEST_BYTES);
    memcpy(image->emitter_digest, identity->emitter_digest, SPARC64_AOT_DIGEST_BYTES);
    memcpy(image->profile_digest, identity->profile_digest, SPARC64_AOT_DIGEST_BYTES);
    image->guest_extensions = identity->guest_extensions;
    image->a64_host_requirements = identity->a64_host_requirements;
    image->guest_page_size = identity->guest_page_size;
    image->a64_host_page_size = identity->a64_host_page_size;
    image->memory_model = identity->memory_model;
    image->xlen = identity->xlen;
    image->abi = identity->abi;
}

static bool leaf_create(char out[96], const uint8_t digest[32], uint64_t offset)
{
    static const char hex[] = "0123456789abcdef";
    memcpy(out, "rv2-", 4);
    for (size_t i = 0; i < 32; ++i) {
        out[4 + i * 2] = hex[digest[i] >> 4];
        out[5 + i * 2] = hex[digest[i] & 15u];
    }
    out[68] = '-';
    for (size_t i = 0; i < 16; ++i)
        out[69 + i] = hex[(offset >> ((15u - i) * 4u)) & 15u];
    memcpy(out + 85, ".aot", 5);
    return true;
}

static bool block_matches(const sparc64_aot_block_view_t *block,
                          const sparc64_jit_relocatable_t *fresh,
                          const uint8_t *source, size_t source_size)
{
    if (block->source_offset != fresh->source_offset ||
        block->source_size != source_size ||
        block->a64_size != fresh->emission.word_count * 4u ||
        block->relocation_count != fresh->relocation_count ||
        memcmp(block->source_bytes, source, source_size) != 0)
        return false;
    for (uint32_t i = 0; i < fresh->emission.word_count; ++i)
        if (get32(block->a64_text + (size_t)i * 4u) !=
            fresh->emission.words[i])
            return false;
    for (uint16_t i = 0; i < fresh->relocation_count; ++i) {
        sparc64_aot_relocation_t saved;
        const sparc64_aot_relocation_t *expected = &fresh->relocations[i];
        if (sparc64_aot_view_relocation(block, i, &saved) != 0 ||
            saved.kind != expected->kind || saved.width != expected->width ||
            saved.patch_offset != expected->patch_offset ||
            saved.target != expected->target || saved.addend != expected->addend)
            return false;
    }
    return true;
}

static void clear_staged(sparc64_runtime_aot_cache_t *cache)
{
    for (size_t i = 0; i < SPARC64_RUNTIME_AOT_MAX_STAGED_BLOCKS; ++i)
        sparc64_aot_relocated_destroy(&cache->blocks[i].relocated);
    memset(cache->blocks, 0, sizeof(cache->blocks));
    cache->block_count = 0;
    cache->staged = false;
}

static void try_stage(sparc64_runtime_aot_cache_t *cache,
                      const sparc64_aot_snapshot_t *snapshot,
                      const sparc64_jit_relocatable_t *fresh,
                      uint8_t source[][SPARC64_JIT_MAX_INSNS * 4u],
                      uint32_t count, uint64_t image_base)
{
    if (snapshot->view.block_count != count)
        return;
    sparc64_measure_observer_t *measure = cache->measure;
    for (uint32_t i = 0; i < count; ++i) {
        sparc64_aot_block_view_t block;
        size_t source_size = fresh[i].emission.source_size;
        if (sparc64_aot_view_block(&snapshot->view, i, &block) != 0)
            goto decline;
        sparc64_measure_stamp_t stamp = sparc64_measure_begin(measure, SPARC64_MEASURE_AOT_VERIFY);
        bool matches = block_matches(&block, &fresh[i], source[i], source_size);
        sparc64_measure_end(measure, SPARC64_MEASURE_AOT_VERIFY, stamp);
        if (!matches)
            goto decline;
        sparc64_runtime_aot_block_t *candidate = &cache->blocks[i];
        stamp = sparc64_measure_begin(measure, SPARC64_MEASURE_AOT_RELOCATE);
        sparc64_aot_relocate_result_t relocated = sparc64_aot_relocate_guest(
            &block, image_base, &candidate->relocated);
        sparc64_measure_end(measure, SPARC64_MEASURE_AOT_RELOCATE, stamp);
        if (relocated != SPARC64_AOT_RELOCATE_OK)
            goto decline;
        candidate->source_offset = fresh[i].source_offset;
        candidate->metadata.guest_pc = fresh[i].emission.guest_pc;
        candidate->metadata.last_pc = fresh[i].emission.last_pc;
        candidate->metadata.last_length = fresh[i].emission.last_length;
        candidate->metadata.instruction_count = fresh[i].emission.instruction_count;
        candidate->metadata.source_size = fresh[i].emission.source_size;
        memcpy(candidate->metadata.source_words, fresh[i].emission.source_words,
               (size_t)fresh[i].emission.instruction_count *
                   sizeof(fresh[i].emission.source_words[0]));
        memcpy(candidate->metadata.source_lengths, fresh[i].emission.source_lengths,
               (size_t)fresh[i].emission.instruction_count *
                   sizeof(fresh[i].emission.source_lengths[0]));
        candidate->staged = true;
    }
    cache->block_count = count;
    cache->staged = true;
    return;
decline:
    clear_staged(cache);
}

typedef struct {
    sparc64_jit_relocatable_t fresh[SPARC64_RUNTIME_AOT_MAX_STAGED_BLOCKS];
    uint8_t source[SPARC64_RUNTIME_AOT_MAX_STAGED_BLOCKS][SPARC64_JIT_MAX_INSNS * 4u];
    uint8_t text[SPARC64_RUNTIME_AOT_MAX_STAGED_BLOCKS][SPARC64_JIT_MAX_EMITTED_WORDS * 4u];
    sparc64_aot_block_t blocks[SPARC64_RUNTIME_AOT_MAX_STAGED_BLOCKS];
} cache_work_t;

static int cache_prepare_impl(sparc64_runtime_aot_cache_t *cache,
                                  const char *directory,
                                  sparc64_aot_authority_policy_t policy,
                                  const sparc64_prepared_program_t *prepared,
                                  int runtime_fd, const sparc64_image_info_t *image,
                                  sparc64_space_t *space, uint32_t quantum,
                                  uint32_t requested_blocks)
{
    if (cache == NULL || directory == NULL || image == NULL || space == NULL ||
        (requested_blocks == 0 || requested_blocks > SPARC64_RUNTIME_AOT_MAX_STAGED_BLOCKS)) {
        errno = EINVAL;
        return -1;
    }
    cache->enabled = true;
    cache->requested_blocks = requested_blocks;
    decline(cache, "unsupported");
    const uint8_t *target, *interpreter_bytes = NULL;
    size_t target_size, interpreter_size = 0;
    bool interpreter;
    if (!sparc64_program_prepared_target(prepared, &target, &target_size,
                                    &interpreter) ||
        (interpreter && !sparc64_program_prepared_interpreter(
            prepared, &interpreter_bytes, &interpreter_size)) ||
        (!interpreter && image->interpreter_base != 0) || quantum == 0)
        return 0;
    /* PT_INTERP starts at its own image base. Main entry and AT_ENTRY retain
     * the distinct main-image bias; this slice caches interpreter roots only. */
    uint64_t source_base = interpreter ? image->interpreter_base : image->load_bias;
    if (image->start_pc < source_base)
        return 0;
    uint64_t entry_offset = image->start_pc - source_base;
    uint64_t exec_start, exec_end;
    if (!sparc64_program_prepared_entry_exec_end(prepared, interpreter,
                                            entry_offset, &exec_end) ||
        !sparc64_program_prepared_exec_span(prepared, interpreter, entry_offset,
                                        &exec_start, &exec_end) ||
        exec_end <= entry_offset || exec_end - entry_offset < 2u ||
        source_base > UINT64_MAX - exec_end)
        return 0;
    sparc64_measure_observer_t *measure = space->measure;
    sparc64_measure_stamp_t measure_stamp = sparc64_measure_begin(
        measure, SPARC64_MEASURE_AOT_AUTHORITY);
    int dirfd = open(directory, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (dirfd < 0) {
        sparc64_measure_end(measure, SPARC64_MEASURE_AOT_AUTHORITY, measure_stamp);
        decline(cache, "authority");
        return 0;
    }
    struct stat directory_status;
    if (fstat(dirfd, &directory_status) != 0 ||
        !S_ISDIR(directory_status.st_mode) ||
        directory_status.st_uid != geteuid() ||
        (directory_status.st_mode & 07777) != 0700 ||
        geteuid() != getuid() || getegid() != getgid() ||
        !sparc64_aot_authorize_fd(dirfd, true, policy)) {
        (void)close(dirfd);
        sparc64_measure_end(measure, SPARC64_MEASURE_AOT_AUTHORITY, measure_stamp);
        decline(cache, "authority");
        return 0;
    }
    sparc64_measure_end(measure, SPARC64_MEASURE_AOT_AUTHORITY, measure_stamp);
    sparc64_aot_identity_t identity = {0};
    measure_stamp = sparc64_measure_begin(measure, SPARC64_MEASURE_AOT_IDENTITY);
    bool identity_ok = identity_create(target, target_size,
                                      interpreter_bytes, interpreter_size,
                                      runtime_fd, &identity);
    sparc64_measure_end(measure, SPARC64_MEASURE_AOT_IDENTITY, measure_stamp);
    if (!identity_ok) {
        (void)close(dirfd);
        decline(cache, "identity");
        return 0;
    }
    sparc64_cpu_t cpu;
    sparc64_cpu_init(&cpu, image->start_pc);
    const sparc64_mem_ops_t memory = {.read = source_read};
    source_span_t source_span = {
        .space = space,
        .start = source_base + exec_start,
        .end = source_base + exec_end
    };
    const sparc64_mem_ops_t bounded_memory = {.read = source_span_read};
    cache_work_t *work = calloc(1, sizeof(*work));
    if (work == NULL) {
        (void)close(dirfd);
        decline(cache, "resource");
        return 0;
    }
    int outcome = 0;
    sparc64_jit_relocatable_t *fresh = work->fresh;
    uint32_t count = 0;
    if (requested_blocks > 2u) {
        sparc64_aot_discovery_t *discovery = NULL;
        measure_stamp = sparc64_measure_begin(measure, SPARC64_MEASURE_AOT_EMIT);
        int discovered = sparc64_aot_discover(&memory, space, source_base,
            source_base + exec_start, source_base + exec_end, image->start_pc,
            quantum, requested_blocks, &discovery, NULL, 0);
        sparc64_measure_end(measure, SPARC64_MEASURE_AOT_EMIT, measure_stamp);
        if (discovered != 0) {
            if (discovered == -2)
                decline(cache, "resource");
            else
                outcome = -1;
            goto finish;
        }
        count = discovery->count;
        memcpy(fresh, discovery->blocks, (size_t)count * sizeof(*fresh));
        free(discovery);
        if (count == 0) {
            decline(cache, "emit");
            goto finish;
        }
    } else {
        char error[128] = {0};
        uint32_t limit = quantum < SPARC64_JIT_MAX_INSNS ? quantum : SPARC64_JIT_MAX_INSNS;
        uint64_t remaining = (exec_end - entry_offset) / 2u;
        if (remaining < limit)
            limit = (uint32_t)remaining;
        measure_stamp = sparc64_measure_begin(measure, SPARC64_MEASURE_AOT_EMIT);
        sparc64_jit_relocatable_result_t emitted = sparc64_jit_emit_relocatable(
            &cpu, &bounded_memory, &source_span, limit, source_base,
            &fresh[0], error, sizeof(error));
        sparc64_measure_end(measure, SPARC64_MEASURE_AOT_EMIT, measure_stamp);
        if (emitted == SPARC64_JIT_RELOCATABLE_ERROR) {
            outcome = -1;
            goto finish;
        }
        if (emitted != SPARC64_JIT_RELOCATABLE_OK ||
            fresh[0].emission.instruction_count == 0 ||
            fresh[0].emission.instruction_count > SPARC64_JIT_MAX_INSNS) {
            decline(cache, "emit");
            goto finish;
        }
        count = 1;
        /* Only an ecall's sequential return PC is an eligible second root in
         * this bounded slice. Looking ahead has no guest effects: any unavailable
         * or unsupported future source simply leaves the ordinary entry record. */
        uint64_t stop = fresh[0].emission.last_pc;
        if (requested_blocks == 2u &&
            stop <= UINT64_MAX - fresh[0].emission.last_length) {
            stop += fresh[0].emission.last_length;
            if (stop > UINT64_MAX - 4u || stop < source_base ||
                stop - source_base >= exec_end ||
                exec_end - (stop - source_base) < 4u)
                goto no_second_block;
            uint8_t terminator[4];
            sparc64_mem_fault_t fault = {stop, SPARC64_MEM_FAULT_INTERNAL};
            bool fetched = source_read(space, stop, terminator,
                                       sizeof(terminator), SPARC64_ACCESS_FETCH, &fault);
            if (!fetched && (space->internal_failure ||
                             fault.reason == SPARC64_MEM_FAULT_INTERNAL ||
                             fault.reason == SPARC64_MEM_FAULT_RESOURCE ||
                             fault.reason == SPARC64_MEM_FAULT_NONE)) {
                outcome = -1;
                goto finish;
            }
            uint64_t next_pc = stop + 4u;
            uint64_t next_offset = next_pc - source_base;
            if (fetched && get32(terminator) == 0x73u &&
                next_offset < exec_end && exec_end - next_offset >= 2u) {
                sparc64_cpu_init(&cpu, stop + 4u);
                uint32_t next_limit = limit;
                remaining = (exec_end - next_offset) / 2u;
                if (remaining < next_limit)
                    next_limit = (uint32_t)remaining;
                measure_stamp = sparc64_measure_begin(measure, SPARC64_MEASURE_AOT_EMIT);
                sparc64_jit_relocatable_result_t next = sparc64_jit_emit_relocatable(
                    &cpu, &bounded_memory, &source_span, next_limit, source_base,
                    &fresh[1], error, sizeof(error));
                sparc64_measure_end(measure, SPARC64_MEASURE_AOT_EMIT, measure_stamp);
                if (next == SPARC64_JIT_RELOCATABLE_ERROR) {
                    outcome = -1;
                    goto finish;
                }
                if (next == SPARC64_JIT_RELOCATABLE_OK &&
                    fresh[1].emission.instruction_count != 0)
                    count = 2;
            }
        }
no_second_block:;
    }
    uint8_t (*source)[SPARC64_JIT_MAX_INSNS * 4u] = work->source;
    uint8_t (*text)[SPARC64_JIT_MAX_EMITTED_WORDS * 4u] = work->text;
    sparc64_aot_block_t *blocks = work->blocks;
    for (uint32_t b = 0; b < count; ++b) {
        size_t source_size = fresh[b].emission.source_size;
        size_t source_at = 0;
        for (uint32_t i = 0; i < fresh[b].emission.instruction_count; ++i) {
            uint32_t word = fresh[b].emission.source_words[i];
            uint8_t length = fresh[b].emission.source_lengths[i];
            for (uint8_t byte = 0; byte < length; ++byte)
                source[b][source_at++] = (uint8_t)(word >> (byte * 8u));
        }
        if (source_at != source_size) {
            outcome = -1;
            goto finish;
        }
        for (uint32_t i = 0; i < fresh[b].emission.word_count; ++i)
            little32(text[b] + (size_t)i * 4u, fresh[b].emission.words[i]);
        blocks[b] = (sparc64_aot_block_t){
            .source_offset = fresh[b].source_offset,
            .source_bytes = source[b],
            .source_size = (uint32_t)source_size,
            .a64_text = text[b],
            .a64_size = fresh[b].emission.word_count * 4u,
            .relocations = fresh[b].relocations,
            .relocation_count = fresh[b].relocation_count
        };
    }
    char leaf[96];
    (void)leaf_create(leaf, identity.input_digest, entry_offset);
    sparc64_aot_snapshot_t snapshot = {0};
    measure_stamp = sparc64_measure_begin(measure, SPARC64_MEASURE_AOT_READ);
    sparc64_aot_read_result_t read = sparc64_aot_snapshot_read_authorized(
        dirfd, leaf, &identity, policy, &snapshot);
    sparc64_measure_end(measure, SPARC64_MEASURE_AOT_READ, measure_stamp);
    if (read == SPARC64_AOT_READ_HIT) {
        try_stage(cache, &snapshot, fresh, source, count, source_base);
        sparc64_aot_snapshot_destroy(&snapshot);
        if (cache->staged) {
            cache->status = SPARC64_RUNTIME_AOT_MISS;
            cache->reason = "unused";
            goto finish;
        }
    } else if (read == SPARC64_AOT_READ_ERROR) {
        cache->status = SPARC64_RUNTIME_AOT_MISS;
        cache->reason = "read";
        goto finish;
    }
    sparc64_aot_image_t record = {.block_count = count, .blocks = blocks};
    image_identity(&record, &identity);
    /* Internal cache writes must not raise native SIGXFSZ before the guest
     * starts. Never change the translator's inherited file-size limit. */
    struct rlimit fsize;
    size_t record_size = 0;
    measure_stamp = sparc64_measure_begin(measure, SPARC64_MEASURE_AOT_WRITE);
    if (sparc64_aot_encoded_size_v2(&record, &record_size) != 0) {
        sparc64_measure_end(measure, SPARC64_MEASURE_AOT_WRITE, measure_stamp);
        outcome = -1;
        goto finish;
    }
    if (getrlimit(RLIMIT_FSIZE, &fsize) != 0 ||
        (fsize.rlim_cur != RLIM_INFINITY &&
         record_size > (uint64_t)fsize.rlim_cur)) {
        sparc64_measure_end(measure, SPARC64_MEASURE_AOT_WRITE, measure_stamp);
        cache->status = SPARC64_RUNTIME_AOT_MISS;
        cache->reason = "fsize";
        goto finish;
    }
    struct timespec stamp;
    char temporary[160];
    int size = clock_gettime(CLOCK_MONOTONIC, &stamp) == 0 ?
        snprintf(temporary, sizeof(temporary), "%s.%ld.%ld.%ld.tmp", leaf,
                 (long)getpid(), (long)stamp.tv_sec, (long)stamp.tv_nsec) : -1;
    sparc64_aot_write_result_t wrote = SPARC64_AOT_WRITE_ERROR;
    if (size > 0 && (size_t)size < sizeof(temporary))
        wrote = sparc64_aot_snapshot_write_authorized(dirfd, leaf, temporary,
                                                  &record, policy);
    sparc64_measure_end(measure, SPARC64_MEASURE_AOT_WRITE, measure_stamp);
    cache->status = wrote == SPARC64_AOT_WRITE_STORED ?
        SPARC64_RUNTIME_AOT_STORED : SPARC64_RUNTIME_AOT_MISS;
    cache->reason = wrote == SPARC64_AOT_WRITE_STORED ? "cold" : "store";
    if (wrote == SPARC64_AOT_WRITE_STORED) {
        cache->block_count = count;
        for (uint32_t i = 0; i < count; ++i)
            cache->blocks[i].source_offset = fresh[i].source_offset;
    }
finish:
    (void)close(dirfd);
    free(work);
    return outcome;
}

int sparc64_runtime_aot_cache_prepare(sparc64_runtime_aot_cache_t *cache,
                                  const char *directory,
                                  sparc64_aot_authority_policy_t policy,
                                  const sparc64_prepared_program_t *prepared,
                                  int runtime_fd, const sparc64_image_info_t *image,
                                  sparc64_space_t *space, uint32_t quantum,
                                  uint32_t requested_blocks)
{
    sparc64_measure_observer_t *measure = space != NULL ? space->measure : NULL;
    if (cache != NULL)
        cache->measure = measure;
    sparc64_measure_stamp_t stamp = sparc64_measure_begin(measure,
                                                 SPARC64_MEASURE_AOT_PREPARE);
    int result = cache_prepare_impl(cache, directory, policy, prepared,
                                    runtime_fd, image, space, quantum,
                                    requested_blocks);
    sparc64_measure_end(measure, SPARC64_MEASURE_AOT_PREPARE, stamp);
    return result;
}

void sparc64_runtime_aot_cache_pin_generation(sparc64_runtime_aot_cache_t *cache,
                                          uint64_t generation)
{
    if (cache != NULL && cache->staged)
        cache->startup_generation = generation;
}

sparc64_jit_source_result_t sparc64_runtime_aot_cache_publish(
    sparc64_runtime_aot_cache_t *cache, const sparc64_mem_ops_t *memory,
    sparc64_space_t *space, uint64_t pc, uint32_t budget, sparc64_jit_block_t *out)
{
    if (cache == NULL || !cache->staged)
        return SPARC64_JIT_SOURCE_FALLBACK;
    sparc64_runtime_aot_block_t *candidate = NULL;
    for (uint32_t i = 0; i < cache->block_count; ++i)
        if (cache->blocks[i].staged && cache->blocks[i].metadata.guest_pc == pc) {
            candidate = &cache->blocks[i];
            break;
        }
    if (candidate == NULL)
        return SPARC64_JIT_SOURCE_FALLBACK;
    candidate->staged = false;
    cache->staged = false;
    for (uint32_t i = 0; i < cache->block_count; ++i)
        cache->staged = cache->staged || cache->blocks[i].staged;
    if (space == NULL || out == NULL ||
        cache->startup_generation == 0 ||
        space->generation < cache->startup_generation ||
        candidate->metadata.instruction_count > budget) {
        cache->reason = "generation";
        sparc64_aot_relocated_destroy(&candidate->relocated);
        return SPARC64_JIT_SOURCE_FALLBACK;
    }
    /* Unrelated mappings and clone TID writes may advance the global
     * generation. Rebind only after a complete live FETCH/word proof below;
     * no generation, backing identity, or old preparation alone authorizes RX.
     * The caller retains uninterrupted family exclusion through publication. */
    candidate->metadata.memory_generation = space->generation;
    sparc64_jit_source_result_t source = sparc64_jit_source_validate(
        &candidate->metadata, memory, space);
    if (source == SPARC64_JIT_SOURCE_RETRY) {
        /* A detached refresh needs another guarded source check. Keep the
         * immutable candidate and relocation alive until that attempt. */
        candidate->staged = true;
        cache->staged = true;
        return source;
    }
    if (source != SPARC64_JIT_SOURCE_MATCH ||
        space->generation != candidate->metadata.memory_generation) {
        cache->reason = source == SPARC64_JIT_SOURCE_INTERNAL ? "internal" : "source";
        sparc64_aot_relocated_destroy(&candidate->relocated);
        return source == SPARC64_JIT_SOURCE_INTERNAL ? source : SPARC64_JIT_SOURCE_FALLBACK;
    }
    sparc64_measure_stamp_t stamp = sparc64_measure_begin(space->measure,
                                                 SPARC64_MEASURE_PUBLISH);
    bool published = sparc64_jit_publish_relocated(candidate->relocated.bytes,
                                               candidate->relocated.size,
                                               &candidate->metadata, out);
    sparc64_measure_end(space->measure, SPARC64_MEASURE_PUBLISH, stamp);
    if (!published) {
        cache->reason = "publish";
        sparc64_aot_relocated_destroy(&candidate->relocated);
        return SPARC64_JIT_SOURCE_FALLBACK;
    }
    candidate->published_code = out->rx_code;
    out->aot_cache_slot = (uint8_t)(candidate - cache->blocks + 1u);
    sparc64_aot_relocated_destroy(&candidate->relocated);
    return SPARC64_JIT_SOURCE_MATCH;
}

void sparc64_runtime_aot_cache_executed(sparc64_runtime_aot_cache_t *cache,
                                    const sparc64_jit_block_t *block)
{
    if (cache == NULL || block == NULL)
        return;
    for (uint32_t i = 0; i < cache->block_count; ++i) {
        sparc64_runtime_aot_block_t *candidate = &cache->blocks[i];
        if (block->aot_cache_slot == i + 1u &&
            candidate->published_code != NULL &&
            block->rx_code == candidate->published_code) {
            cache->status = SPARC64_RUNTIME_AOT_HIT;
            cache->reason = "executed";
            candidate->published_code = NULL;
            candidate->executed = true;
            return;
        }
    }
}

void sparc64_runtime_aot_cache_disable_child(sparc64_runtime_aot_cache_t *cache)
{
    if (cache != NULL) {
        clear_staged(cache);
        memset(cache, 0, sizeof(*cache));
    }
}

void sparc64_runtime_aot_cache_destroy(sparc64_runtime_aot_cache_t *cache)
{
    sparc64_runtime_aot_cache_disable_child(cache);
}

const char *sparc64_runtime_aot_cache_status(const sparc64_runtime_aot_cache_t *cache)
{
    if (cache == NULL)
        return "declined";
    switch (cache->status) {
    case SPARC64_RUNTIME_AOT_HIT: return "hit";
    case SPARC64_RUNTIME_AOT_STORED: return "stored";
    case SPARC64_RUNTIME_AOT_MISS: return "miss";
    case SPARC64_RUNTIME_AOT_DECLINED:
    case SPARC64_RUNTIME_AOT_DISABLED: return "declined";
    }
    return "declined";
}
