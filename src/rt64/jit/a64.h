/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SPARC64RT_JIT_A64_H
#define SPARC64RT_JIT_A64_H

#include "core/cpu.h"
#include "runtime/measure.h"
#include "aot/format.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define SPARC64_JIT_MAX_INSNS 64u
#define SPARC64_JIT_MAX_EMITTED_WORDS 512u

/* Generated blocks have the AAPCS64 signature void block(context *). CPU
 * state is materialized after each instruction; no host register is part of
 * a guest architectural snapshot. x18 is never used by generated code. */
typedef struct {
    sparc64_cpu_t *cpu;
    const sparc64_mem_ops_t *memory;
    void *memory_context;
    uint64_t memory_generation;
    uint32_t budget;
    sparc64_step_result_t result;
    uint32_t executed;
} sparc64_jit_context_t;

typedef struct {
    uint64_t guest_pc;
    uint64_t memory_generation;
    uint64_t last_pc;
    uint32_t instruction_count;
    uint32_t source_size;
    /* Original source encodings and their 2/4-byte boundaries. File refresh
     * may change bytes without advancing a local generation. */
    uint32_t source_words[SPARC64_JIT_MAX_INSNS];
    uint8_t source_lengths[SPARC64_JIT_MAX_INSNS];
    uint8_t last_length;
    uint8_t aot_cache_slot; /* Zero for ordinary JIT; one-based cache identity. */
    void *rx_code;
    size_t code_size;
    size_t mapping_size;
} sparc64_jit_block_t;

/* Owned, non-executable translation output. This is an in-process emission
 * result, not a relocatable or cacheable artifact: emitted words may contain
 * absolute guest-PC materializations and context-layout assumptions. */
typedef struct {
    uint32_t words[SPARC64_JIT_MAX_EMITTED_WORDS];
    uint32_t word_count;
    uint64_t guest_pc;
    uint32_t source_words[SPARC64_JIT_MAX_INSNS];
    uint8_t source_lengths[SPARC64_JIT_MAX_INSNS];
    uint32_t source_size;
    uint64_t last_pc;
    uint8_t last_length;
    uint32_t instruction_count;
} sparc64_jit_emission_t;

#define SPARC64_JIT_MAX_RELOCATABLE_RELOCS (2u * SPARC64_JIT_MAX_INSNS)

/* Metadata-only source-relative export candidate. The A64 words remain
 * non-executable until a separate applicator validates templates and live
 * bindings. No process pointers or memory-generation claims are retained. */
typedef struct {
    sparc64_jit_emission_t emission;
    uint64_t source_offset;
    sparc64_aot_relocation_t relocations[SPARC64_JIT_MAX_RELOCATABLE_RELOCS];
    uint16_t relocation_count;
} sparc64_jit_relocatable_t;

typedef enum {
    SPARC64_JIT_RELOCATABLE_ERROR = -1,
    SPARC64_JIT_RELOCATABLE_DECLINE = 0,
    SPARC64_JIT_RELOCATABLE_OK = 1
} sparc64_jit_relocatable_result_t;

typedef enum {
    SPARC64_JIT_EXECUTED, /* context.result and executed describe committed state */
    SPARC64_JIT_FALLBACK, /* no supported direct instruction at this PC: sparc64_step */
    SPARC64_JIT_STALE,    /* guest PC or memory generation changed: recompile */
    SPARC64_JIT_BUDGET,   /* run fewer instructions through sparc64_step */
    SPARC64_JIT_ERROR     /* malformed block/context or unavailable host ISA */
} sparc64_jit_run_result_t;

typedef enum {
    SPARC64_JIT_SOURCE_MATCH,
    SPARC64_JIT_SOURCE_FALLBACK,
    SPARC64_JIT_SOURCE_INTERNAL
} sparc64_jit_source_result_t;

/* Pre-execution validation, not an architectural fetch. Compare only the
 * retained direct instructions through checked executable reads. A guest
 * fault anywhere in this lookahead requests interpreter fallback: preceding
 * instructions must still execute before a later instruction can fault.
 * Internal/resource failures remain runtime failures. This never changes CPU
 * state. The caller must hold its memory exclusion continuously through run,
 * and recheck the live generation after refresh before using the block. */
sparc64_jit_source_result_t sparc64_jit_source_validate(const sparc64_jit_block_t *block,
                                             const sparc64_mem_ops_t *memory,
                                             void *memory_context);

/* Fetch and encode direct SPARC V9 integer instructions without allocating,
 * publishing or executing memory. Guest fetch faults and unsupported
 * instructions end the successful prefix; internal fetch failures return
 * false. On failure `out` is unchanged. */
bool sparc64_jit_emit(const sparc64_cpu_t *cpu, const sparc64_mem_ops_t *memory,
                 void *memory_context, uint32_t max_instructions,
                 sparc64_jit_emission_t *out, char *error, size_t error_size);

/* Emit source-relative guest-PC fixups with zero MOV64 immediates for
 * SETHI/call PC-relative results and every materialized next PC. Ordinary
 * immediates remain literal.
 * Exported text is independent of the current guest load bias; the nested
 * recovery metadata describes this emission's current PC. This constructs metadata;
 * it does not validate/apply relocations or authorize executable publication.
 * Guest addresses outside image_base, odd image bases, or address arithmetic
 * wrap decline cleanly. Exporters should use source_offset and source words,
 * not the absolute-PC metadata nested in emission. Output is assigned only on
 * SPARC64_JIT_RELOCATABLE_OK. */
sparc64_jit_relocatable_result_t sparc64_jit_emit_relocatable(
    const sparc64_cpu_t *cpu, const sparc64_mem_ops_t *memory, void *memory_context,
    uint32_t max_instructions, uint64_t image_base,
    sparc64_jit_relocatable_t *out, char *error, size_t error_size);

/* Compile at most max_instructions straight-line direct integer operations.
 * A later fetch fault or unsupported operation ends the block and is handled
 * at its own dispatcher entry. A valid block may contain zero operations,
 * explicitly signaling interpreter fallback. Returns false only for an
 * internal fetch, allocation/publication or invalid-argument error. The caller
 * owns block. */
bool sparc64_jit_compile(const sparc64_cpu_t *cpu, const sparc64_mem_ops_t *memory,
                    void *memory_context, uint64_t memory_generation,
                    uint32_t max_instructions, sparc64_jit_block_t *block,
                    char *error, size_t error_size);

/* Same semantics, with optional inclusive translation/publication timers. */
bool sparc64_jit_compile_measured(const sparc64_cpu_t *cpu, const sparc64_mem_ops_t *memory,
                             void *memory_context, uint64_t memory_generation,
                             uint32_t max_instructions, sparc64_jit_block_t *block,
                             char *error, size_t error_size,
                             sparc64_measure_observer_t *measure);

/* Publish already-relocated A64 bytes only after the caller has validated
 * record identity, source/recovery metadata and current checked EXEC bytes
 * under uninterrupted guest-memory exclusion. `metadata` contains no mapping
 * or host pointer. This makes a private RW mapping, then seals it RX; no RWX
 * state exists. On failure `out` remains empty for ordinary JIT fallback. */
bool sparc64_jit_publish_relocated(const uint8_t *bytes, size_t size,
                               const sparc64_jit_block_t *metadata,
                               sparc64_jit_block_t *out);

sparc64_jit_run_result_t sparc64_jit_run(const sparc64_jit_block_t *block,
                                sparc64_jit_context_t *context);
void sparc64_jit_block_destroy(sparc64_jit_block_t *block);

#endif
