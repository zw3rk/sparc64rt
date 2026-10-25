/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SPARC64RT_RUNTIME_AOT_CACHE_H
#define SPARC64RT_RUNTIME_AOT_CACHE_H

#include "aot/authority.h"
#include "aot/relocate.h"
#include "jit/a64.h"
#include "loader/image.h"
#include "runtime/measure.h"
#include "runtime/aot_discover.h"

typedef enum sparc64_runtime_aot_status {
    SPARC64_RUNTIME_AOT_DISABLED,
    SPARC64_RUNTIME_AOT_DECLINED,
    SPARC64_RUNTIME_AOT_MISS,
    SPARC64_RUNTIME_AOT_STORED,
    SPARC64_RUNTIME_AOT_HIT
} sparc64_runtime_aot_status_t;

#define SPARC64_RUNTIME_AOT_MAX_STAGED_BLOCKS SPARC64_AOT_DISCOVERY_MAX_BLOCKS

typedef struct sparc64_runtime_aot_block {
    sparc64_jit_block_t metadata;
    sparc64_aot_relocated_t relocated;
    uint64_t source_offset;
    void *published_code; /* Local process only; never serialized. */
    bool staged, executed;
} sparc64_runtime_aot_block_t;

typedef struct sparc64_runtime_aot_cache {
    sparc64_measure_observer_t *measure;
    sparc64_runtime_aot_status_t status;
    const char *reason;
    bool enabled, staged;
    uint32_t requested_blocks, block_count;
    uint64_t startup_generation;
    sparc64_runtime_aot_block_t blocks[SPARC64_RUNTIME_AOT_MAX_STAGED_BLOCKS];
} sparc64_runtime_aot_cache_t;

/* The initial RV64 entry block is eligible, using the PT_INTERP image base
 * for dynamic startup and the main image base otherwise. An explicit
 * two-block request may also discover the direct prefix at the checked
 * fallthrough after an entry-block ecall. Limits3..16 opt into bounded
 * CFG discovery within the selected initial image entry's executable segment. This runs
 * before the family guard exists, so cache I/O cannot hold guest exclusion.
 * Only an actual emitter/internal fetch invariant returns -1; every cache
 * authority/I/O/record/resource decline leaves ordinary JIT available. */
int sparc64_runtime_aot_cache_prepare(sparc64_runtime_aot_cache_t *cache,
                                  const char *directory,
                                  sparc64_aot_authority_policy_t policy,
                                  const sparc64_prepared_program_t *prepared,
                                  int runtime_fd, const sparc64_image_info_t *image,
                                  sparc64_space_t *space, uint32_t quantum,
                                  uint32_t requested_blocks);
/* Bind a staged record to the live space before execution. Later generations
 * require full current executable-source validation; zero/backward bindings
 * decline. A changed generation never bypasses the live byte/permission proof. */
void sparc64_runtime_aot_cache_pin_generation(sparc64_runtime_aot_cache_t *cache,
                                          uint64_t generation);
/* Called under the uninterrupted guest family guard. Returns SOURCE_INTERNAL
 * only for current guest-memory internal failure. All cache declines request
 * ordinary JIT/interpreter behavior and leave `out` empty. */
sparc64_jit_source_result_t sparc64_runtime_aot_cache_publish(
    sparc64_runtime_aot_cache_t *cache, const sparc64_mem_ops_t *memory,
    sparc64_space_t *space, uint64_t pc, uint32_t budget, sparc64_jit_block_t *out);
void sparc64_runtime_aot_cache_executed(sparc64_runtime_aot_cache_t *cache,
                                    const sparc64_jit_block_t *block);
void sparc64_runtime_aot_cache_disable_child(sparc64_runtime_aot_cache_t *cache);
void sparc64_runtime_aot_cache_destroy(sparc64_runtime_aot_cache_t *cache);
const char *sparc64_runtime_aot_cache_status(const sparc64_runtime_aot_cache_t *cache);

#endif
