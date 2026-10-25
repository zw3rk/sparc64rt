/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#include "runtime/aot_discover.h"
#include "core/internal.h"

#include <errno.h>
#include <stdlib.h>

typedef struct {
    uint64_t roots[SPARC64_AOT_DISCOVERY_MAX_ROOTS];
    uint32_t count;
    uint64_t start, end;
} roots_t;

typedef struct {
    const sparc64_mem_ops_t *memory;
    void *context;
    uint64_t start;
    uint64_t end;
} bounded_fetch_t;

static bool bounded_fetch(void *opaque, uint64_t address, void *bytes,
                          size_t size, sparc64_access_t access,
                          sparc64_mem_fault_t *fault)
{
    bounded_fetch_t *bounded = opaque;
    if (bounded == NULL || bounded->memory == NULL ||
        bounded->memory->read == NULL || address < bounded->start ||
        address > bounded->end || (uint64_t)size > bounded->end - address) {
        if (fault != NULL) {
            fault->address = address < (bounded == NULL ? 0 : bounded->start) ?
                             address : (bounded == NULL ? address : bounded->end);
            fault->reason = SPARC64_MEM_FAULT_UNMAPPED;
        }
        return false;
    }
    return bounded->memory->read(bounded->context, address, bytes, size,
                                 access, fault);
}

static void enqueue(roots_t *work, uint64_t address)
{
    if ((address & 1u) != 0 || address < work->start || address >= work->end ||
        work->end - address < 2u ||
        work->count == SPARC64_AOT_DISCOVERY_MAX_ROOTS)
        return;
    for (uint32_t i = 0; i < work->count; ++i)
        if (work->roots[i] == address)
            return;
    work->roots[work->count++] = address;
}

/* sparc64_imm_b/j encode a signed displacement in an unsigned container. Check
 * its magnitude before adding; wrapping targets are deliberately undiscovered. */
static void enqueue_relative(roots_t *work, uint64_t pc, uint64_t displacement)
{
    if ((displacement >> 63) != 0) {
        uint64_t magnitude = ~displacement + 1u;
        if (pc >= magnitude)
            enqueue(work, pc - magnitude);
    } else if (pc <= UINT64_MAX - displacement) {
        enqueue(work, pc + displacement);
    }
}

static int compare_blocks(const void *left, const void *right)
{
    const sparc64_jit_relocatable_t *a = left, *b = right;
    return a->source_offset < b->source_offset ? -1 :
           a->source_offset > b->source_offset ? 1 : 0;
}

/* Prepare successors of adjacent AUIPC; JALR and AUIPC; ADDI; JALR calls
 * without translating the JALR or treating prediction as execution authority.
 * The producer must be in the emitted prefix. An ADDI may be emitted with it,
 * or decoded immediately after it when the quantum ends at AUIPC. */
static int enqueue_pcrel_call(roots_t *work, const sparc64_mem_ops_t *memory,
                              void *context, const sparc64_jit_relocatable_t *prefix,
                              uint64_t next_pc)
{
    uint32_t count = prefix->emission.instruction_count;
    if (count == 0)
        return 0;
    uint32_t last = prefix->emission.source_words[count - 1u];
    uint32_t producer = last;
    uint64_t producer_pc = prefix->emission.last_pc;
    uint64_t addi_imm = 0;
    bool addi_emitted = false;
    if (prefix->emission.last_length != 4 || next_pc >= work->end ||
        work->end - next_pc < 2u)
        return 0;
    if ((last & 0x7fu) == 0x13u && ((last >> 12) & 7u) == 0 &&
        count >= 2 && prefix->emission.source_lengths[count - 2u] == 4 &&
        producer_pc >= 4u) {
        producer = prefix->emission.source_words[count - 2u];
        producer_pc -= 4u;
        uint32_t rd = (producer >> 7) & 31u;
        if ((producer & 0x7fu) != 0x17u || rd == 0 ||
            ((last >> 7) & 31u) != rd || ((last >> 15) & 31u) != rd)
            return 0;
        addi_imm = sparc64_imm_i(last);
        addi_emitted = true;
    } else if ((last & 0x7fu) != 0x17u || ((last >> 7) & 31u) == 0) {
        return 0;
    }
    uint32_t rd = (producer >> 7) & 31u;
    uint64_t consumer_pc = next_pc;
    sparc64_cpu_t probe;
    sparc64_cpu_init(&probe, consumer_pc);
    sparc64_insn_t consumer = {0};
    sparc64_step_result_t decoded = sparc64_decode(&probe, memory, context, &consumer);
    if (decoded.kind == SPARC64_STEP_INTERNAL)
        return -1;
    if (decoded.kind != SPARC64_STEP_CONTINUE ||
        (consumer.length != 2 && consumer.length != 4))
        return 0;
    uint32_t canonical = consumer.raw;
    if (consumer.length == 2 &&
        !sparc64_expand_rv64c((uint16_t)consumer.raw, &canonical))
        return 0;
    if (!addi_emitted && consumer.length == 4 &&
        (canonical & 0x707fu) == 0x13u &&
        ((canonical >> 7) & 31u) == rd &&
        ((canonical >> 15) & 31u) == rd) {
        /* Only a complete following transfer may extend the chain. */
        if (work->end - next_pc < 6u)
            return 0;
        addi_imm = sparc64_imm_i(canonical);
        consumer_pc = next_pc + 4u;
        sparc64_cpu_init(&probe, consumer_pc);
        decoded = sparc64_decode(&probe, memory, context, &consumer);
        if (decoded.kind == SPARC64_STEP_INTERNAL)
            return -1;
        if (decoded.kind != SPARC64_STEP_CONTINUE ||
            (consumer.length != 2 && consumer.length != 4))
            return 0;
        canonical = consumer.raw;
        if (consumer.length == 2 &&
            !sparc64_expand_rv64c((uint16_t)consumer.raw, &canonical))
            return 0;
    }
    if ((canonical & 0x707fu) != 0x67u ||
        ((canonical >> 15) & 31u) != rd)
        return 0;
    /* Unsigned addition deliberately implements RV64 register wraparound.
     * enqueue() still requires the final low-bit-cleared target in the
     * immutable selected image span. No native pointer is derived here. */
    uint64_t target = producer_pc +
        sparc64_sext(producer & UINT32_C(0xfffff000), 32) +
        addi_imm +
        sparc64_imm_i(canonical);
    enqueue(work, target & ~UINT64_C(1));
    if (((canonical >> 7) & 31u) != 0 &&
        consumer_pc <= UINT64_MAX - consumer.length)
        enqueue(work, consumer_pc + consumer.length);
    return 0;
}

int sparc64_aot_discover(const sparc64_mem_ops_t *memory, void *context,
                    uint64_t image_base, uint64_t start, uint64_t end,
                    uint64_t entry, uint32_t quantum, uint32_t max_blocks,
                    sparc64_aot_discovery_t **out, char *error, size_t error_size)
{
    if (memory == NULL || memory->read == NULL || out == NULL ||
        (image_base & 1u) != 0 || start < image_base || start >= end ||
        entry < start || entry >= end || (entry & 1u) != 0 || quantum == 0 ||
        max_blocks == 0 || max_blocks > SPARC64_AOT_DISCOVERY_MAX_BLOCKS) {
        errno = EINVAL;
        return -1;
    }
    bounded_fetch_t bounded = {
        .memory = memory, .context = context, .start = start, .end = end
    };
    sparc64_mem_ops_t bounded_memory = {.read = bounded_fetch};
    sparc64_aot_discovery_t *result = calloc(1, sizeof(*result));
    if (result == NULL)
        return -2;
    roots_t work = {.start = start, .end = end};
    enqueue(&work, entry);
    for (uint32_t cursor = 0; cursor < work.count && result->count < max_blocks;
         ++cursor) {
        sparc64_cpu_t cpu;
        sparc64_cpu_init(&cpu, work.roots[cursor]);
        uint64_t remaining = (end - cpu.pc) / 2u;
        uint32_t limit = quantum < SPARC64_JIT_MAX_INSNS ? quantum : SPARC64_JIT_MAX_INSNS;
        if (remaining < limit)
            limit = (uint32_t)remaining;
        sparc64_jit_relocatable_t fresh = {0};
        sparc64_jit_relocatable_result_t emitted = sparc64_jit_emit_relocatable(
            &cpu, &bounded_memory, &bounded, limit, image_base, &fresh,
            error, error_size);
        if (emitted == SPARC64_JIT_RELOCATABLE_ERROR)
            goto failure;
        if (emitted == SPARC64_JIT_RELOCATABLE_OK) {
            result->blocks[result->count++] = fresh;
            uint64_t bytes = fresh.emission.source_size;
            /* Emission cannot leave this span: its instruction budget was
             * clamped above. Check before deriving a speculative next root. */
            if (bytes == 0 || bytes > end - cpu.pc)
                goto invariant_failure;
            cpu.pc += bytes;
            if (enqueue_pcrel_call(&work, &bounded_memory, &bounded,
                                   &fresh, cpu.pc) != 0)
                goto failure;
            if (fresh.emission.instruction_count == limit) {
                enqueue(&work, cpu.pc);
                continue;
            }
        }
        if (cpu.pc >= end || end - cpu.pc < 2u)
            continue;
        sparc64_insn_t stop = {0};
        sparc64_step_result_t fetched = sparc64_decode(&cpu, &bounded_memory, &bounded,
                                              &stop);
        if (fetched.kind == SPARC64_STEP_INTERNAL)
            goto failure;
        if (fetched.kind != SPARC64_STEP_CONTINUE ||
            (stop.length != 2 && stop.length != 4))
            continue;
        uint32_t canonical = stop.raw;
        if (stop.length == 2 &&
            !sparc64_expand_rv64c((uint16_t)stop.raw, &canonical))
            continue;
        uint32_t opcode = canonical & 0x7fu;
        uint32_t funct3 = (canonical >> 12) & 7u;
        if (opcode == 0x63u && funct3 != 2u && funct3 != 3u) {
            enqueue_relative(&work, cpu.pc, sparc64_imm_b(canonical));
            if (cpu.pc <= UINT64_MAX - stop.length)
                enqueue(&work, cpu.pc + stop.length);
        } else if (opcode == 0x6fu) {
            enqueue_relative(&work, cpu.pc, sparc64_imm_j(canonical));
            /* A linked call can return through an indirect JALR that this
             * analysis cannot resolve. Its sequential continuation is safe
             * to prepare speculatively, but never executed speculatively. */
            if (((canonical >> 7) & 31u) != 0 &&
                cpu.pc <= UINT64_MAX - stop.length)
                enqueue(&work, cpu.pc + stop.length);
        } else if (canonical == UINT32_C(0x00000073)) {
            if (cpu.pc <= UINT64_MAX - stop.length)
                enqueue(&work, cpu.pc + stop.length);
        }
    }
    qsort(result->blocks, result->count, sizeof(result->blocks[0]), compare_blocks);
    *out = result;
    return 0;
invariant_failure:
    errno = EINVAL;
failure:
    free(result);
    return -1;
}
