/*
 * src/os/guest_run_mem.c — guest memory/syscall-memory bridges (Phase 6, L6a)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Moved verbatim from src/os/guest_run.c (Phase 1, L1c) so the loader
 * entry stays under the 900-line limit: the byte-level
 * sparc64_mem_ops_t bridge and the sparc64_syscall_mem_t read/write
 * helpers over the rt64 memory substrate. No behaviour change.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "core/cpu.h"
#include "os/guest_run_priv.h"
#include "os/mem_space.h"

/* File-range COW promotion (guest_run_sysmem_file.c): mirrors the
 * substrate's private_cow promotion in the per-chunk registry states. */
extern void sysmem_file_note_write(void *context, uint64_t base,
    uint64_t len);

/* ---- sparc64_mem_ops_t bridge over the rt64 substrate ------------------- */
static void record_fault(const guest_state_t *g, sparc64_mem_fault_t *fault)
{
    sparc64_mem_fault_reason_t reason = SPARC64_MEM_FAULT_INTERNAL;
    if (fault == NULL) {
        return;
    }
    switch (g->space.fault_reason) {
    case SPARC64_FAULT_UNMAPPED: reason = SPARC64_MEM_FAULT_UNMAPPED; break;
    case SPARC64_FAULT_PERMISSION: reason = SPARC64_MEM_FAULT_PERMISSION; break;
    case SPARC64_FAULT_RANGE: reason = SPARC64_MEM_FAULT_RANGE; break;
    case SPARC64_FAULT_BUS: reason = SPARC64_MEM_FAULT_BUS; break;
    case SPARC64_FAULT_RESOURCE: reason = SPARC64_MEM_FAULT_RESOURCE; break;
    case SPARC64_FAULT_RETRY: reason = SPARC64_MEM_FAULT_RETRY; break;
    default: break;
    }
    fault->address = g->space.fault_address;
    fault->reason = reason;
}

static bool guest_mem_read(void *context, uint64_t address, void *bytes,
                           size_t size, sparc64_access_t access,
                           sparc64_mem_fault_t *fault)
{
    guest_state_t *g = (guest_state_t *)context;
    unsigned perm = (access == SPARC64_ACCESS_FETCH) ? SPARC64_MEM_EXEC :
                                                       SPARC64_MEM_READ;
    if (g == NULL ||
        !sparc64_space_read(&g->space, address, bytes, size, perm)) {
        if (g != NULL) {
            record_fault(g, fault);
        }
        return false;
    }
    return true;
}

static bool guest_mem_write(void *context, uint64_t address,
                            const void *bytes, size_t size,
                            sparc64_mem_fault_t *fault)
{
    guest_state_t *g = (guest_state_t *)context;
    if (g == NULL || !sparc64_space_write(&g->space, address, bytes, size)) {
        if (g != NULL) {
            record_fault(g, fault);
        }
        return false;
    }
    /* RC-U4 #5: a successful guest write promotes overlapping tracked
     * COW_CLEAN chunks (covers interp, DBT slow-path, and difftest;
     * the DBT fast path never reaches file pages). */
    sysmem_file_note_write(g, address, (uint64_t)size);
    return true;
}

static bool guest_mem_atomic(void *context,
                             const sparc64_atomic_request_t *request,
                             sparc64_atomic_result_t *result,
                             sparc64_mem_fault_t *fault)
{
    guest_state_t *g = (guest_state_t *)context;
    if (g == NULL || request == NULL || result == NULL ||
        !sparc64_space_atomic(&g->space, request, result)) {
        if (g != NULL && request != NULL && result != NULL) {
            record_fault(g, fault);
        }
        return false;
    }
    /* RC-U4 #5: mutating atomics promote like writes (LR only reads;
     * a failed SC writes nothing, mirroring the substrate). */
    if (request->op != SPARC64_ATOMIC_LR &&
        (request->op != SPARC64_ATOMIC_SC || result->sc_success)) {
        sysmem_file_note_write(g, request->address,
            (uint64_t)request->width);
    }
    return true;
}

const sparc64_mem_ops_t guest_mem_ops = {
    guest_mem_read, guest_mem_write, guest_mem_atomic,
};

/* The sparc64_syscall_mem_t read/write/prepare_write helpers stay in
 * src/os/guest_run.c next to sysmem_ops (they share that TU's statics). */