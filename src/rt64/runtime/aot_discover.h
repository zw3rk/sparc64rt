/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SPARC64RT_RUNTIME_AOT_DISCOVER_H
#define SPARC64RT_RUNTIME_AOT_DISCOVER_H

#include "jit/a64.h"

#define SPARC64_AOT_DISCOVERY_MAX_BLOCKS 16u
#define SPARC64_AOT_DISCOVERY_MAX_ROOTS 128u

typedef struct {
    uint32_t count;
    sparc64_jit_relocatable_t blocks[SPARC64_AOT_DISCOVERY_MAX_BLOCKS];
} sparc64_aot_discovery_t;

/* Speculative, non-executing discovery in one immutable executable image
 * span [start,end). The caller exclusively owns the scratch address space.
 * Only supported direct integer prefixes are emitted, retaining their
 * original 4-byte lengths (SPARC has no compressed forms); control flow is
 * left to the interpreter.
 * Adjacent emitted SETHI/nonzero-rd plus matching legal CALL/JMPL prepares
 * bounded PC-relative callee/link-continuation roots, including quantum
 * splits. An adjacent SRA/SRL/OR of the same source/destination may
 * intervene: either both producers are emitted or the quantum ends at
 * SETHI and checked fetch supplies the shift/or. No other register history
 * is inferred. (Phase 6 fills in the real root walk.)
 * Roots are bounded independently of emitted blocks, deduplicated, and output
 * is sorted by source offset. Guest fetch faults/unsupported instructions end
 * only that path; internal/guest-resource failures return -1.
 * Metadata allocation failure returns -2 so the cache owner can decline. No architectural CPU
 * state changes or executable mappings are made. On success *out is owned
 * heap storage (possibly count=0), freed with free(); on failure unchanged. */
int sparc64_aot_discover(const sparc64_mem_ops_t *memory, void *context,
                    uint64_t image_base, uint64_t start, uint64_t end,
                    uint64_t entry, uint32_t quantum, uint32_t max_blocks,
                    sparc64_aot_discovery_t **out, char *error, size_t error_size);

#endif
