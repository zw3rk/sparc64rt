/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#include "linux/thread.h"

#include <stddef.h>

#define CLONE_VM_VALUE UINT64_C(0x00000100)
#define CLONE_FS_VALUE UINT64_C(0x00000200)
#define CLONE_FILES_VALUE UINT64_C(0x00000400)
#define CLONE_SIGHAND_VALUE UINT64_C(0x00000800)
#define CLONE_THREAD_VALUE UINT64_C(0x00010000)
#define CLONE_SYSVSEM_VALUE UINT64_C(0x00040000)
#define CLONE_SETTLS_VALUE UINT64_C(0x00080000)
#define CLONE_DETACHED_VALUE UINT64_C(0x00400000)
#define CLONE_PARENT_SETTID_VALUE UINT64_C(0x00100000)
#define CLONE_CHILD_CLEARTID_VALUE UINT64_C(0x00200000)
#define CLONE_CHILD_SETTID_VALUE UINT64_C(0x01000000)

uint64_t sparc64_linux_clone_decode(const uint64_t args[6],
                               sparc64_linux_clone_request_t *request)
{
    if (args == NULL || request == NULL)
        return UINT64_C(0) - 22;
    const uint64_t mandatory = CLONE_VM_VALUE | CLONE_FS_VALUE |
        CLONE_FILES_VALUE | CLONE_SIGHAND_VALUE | CLONE_THREAD_VALUE |
        CLONE_SYSVSEM_VALUE;
    /* Linux v6.18 kernel/fork.c rejects CLONE_DETACHED only with PIDFD;
     * otherwise the legacy flag is ignored. PIDFD and clone3 are out of scope. */
    const uint64_t optional = CLONE_SETTLS_VALUE | CLONE_DETACHED_VALUE |
        CLONE_PARENT_SETTID_VALUE |
        CLONE_CHILD_CLEARTID_VALUE | CLONE_CHILD_SETTID_VALUE;
    /* Legacy clone consumes lower_32_bits(flags) in kernel/fork.c. */
    uint64_t flags = (uint32_t)args[0];
    if ((flags & mandatory) != mandatory || (flags & ~(mandatory | optional)) != 0)
        return UINT64_C(0) - 22;
    *request = (sparc64_linux_clone_request_t){
        /* RISC-V selects CONFIG_CLONE_BACKWARDS: a3=tls, a4=ctid. */
        .stack = args[1], .parent_tid = args[2], .child_tid = args[4],
        .tls = args[3], .set_tls = (flags & CLONE_SETTLS_VALUE) != 0,
        .parent_set_tid = (flags & CLONE_PARENT_SETTID_VALUE) != 0,
        .child_set_tid = (flags & CLONE_CHILD_SETTID_VALUE) != 0,
        .child_clear_tid = (flags & CLONE_CHILD_CLEARTID_VALUE) != 0
    };
    return 0;
}

static bool c_direction_allowed(uint16_t raw, unsigned quadrant,
                                unsigned funct3, uint64_t pc,
                                uint64_t after_pc)
{
    /* The sign of each compressed PC-relative displacement is its top
     * immediate bit. For branches, it matters only on a taken branch. */
    if (quadrant != 1)
        return true;
    if (funct3 == 5)
        return (raw & UINT16_C(0x1000)) == 0;
    if (funct3 == 6 || funct3 == 7)
        return after_pc == pc + 2 || (raw & UINT16_C(0x1000)) == 0;
    return true;
}

sparc64_sched_sequence_t sparc64_lrsc_classify(sparc64_insn_t executed, uint64_t after_pc,
                                     sparc64_step_kind_t outcome, unsigned xlen)
{
    if (outcome != SPARC64_STEP_CONTINUE ||
        (executed.length != 2 && executed.length != 4))
        return SPARC64_SCHED_SEQ_BREAK;
    uint32_t raw = executed.raw;
    if (executed.length == 2) {
        unsigned quadrant = raw & 3u;
        unsigned funct3 = (raw >> 13) & 7u;
        bool allowed = false;
        if (quadrant == 0)
            allowed = funct3 == 0; /* C.ADDI4SPN. */
        else if (quadrant == 1) {
            if (funct3 == 0 || funct3 == 2 || funct3 == 3 || funct3 == 4 ||
                funct3 == 5 || funct3 == 6 || funct3 == 7)
                allowed = true;
            if (funct3 == 1 && xlen == 64)
                allowed = true; /* C.ADDIW, never RV32 C.JAL. */
        } else if (quadrant == 2) {
            if (funct3 == 0)
                allowed = true; /* C.SLLI. */
            else if (funct3 == 4) {
                /* Only C.MV/C.ADD. C.JR/JALR/EBREAK have rs2=0. */
                allowed = ((raw >> 2) & 31u) != 0;
            }
        }
        if (!allowed || !c_direction_allowed((uint16_t)raw, quadrant,
                                             funct3, executed.pc, after_pc))
            return SPARC64_SCHED_SEQ_BREAK;
        return SPARC64_SCHED_SEQ_CONSTRAINED;
    }
    unsigned opcode = raw & 0x7fu;
    unsigned funct7 = (raw >> 25) & 0x7fu;
    if (opcode == 0x2f) {
        unsigned funct5 = (raw >> 27) & 0x1fu;
        unsigned funct3 = (raw >> 12) & 7u;
        if ((funct3 != 2 && !(funct3 == 3 && xlen == 64)))
            return SPARC64_SCHED_SEQ_BREAK;
        if (funct5 == 2 && ((raw >> 20) & 31u) == 0)
            return SPARC64_SCHED_SEQ_LR_START;
        if (funct5 == 3)
            return SPARC64_SCHED_SEQ_SC_END;
        return SPARC64_SCHED_SEQ_BREAK;
    }
    if (opcode == 0x6f) /* Sign bit of J displacement. */
        return (raw & UINT32_C(0x80000000)) == 0 ?
            SPARC64_SCHED_SEQ_CONSTRAINED : SPARC64_SCHED_SEQ_BREAK;
    if (opcode == 0x63) {
        bool taken = after_pc != executed.pc + 4;
        return !taken || (raw & UINT32_C(0x80000000)) == 0 ?
            SPARC64_SCHED_SEQ_CONSTRAINED : SPARC64_SCHED_SEQ_BREAK;
    }
    if (opcode == 0x37 || opcode == 0x17 || opcode == 0x13 ||
        (xlen == 64 && opcode == 0x1b))
        return SPARC64_SCHED_SEQ_CONSTRAINED;
    if (opcode == 0x33 || (xlen == 64 && opcode == 0x3b))
        return funct7 == 1 ? SPARC64_SCHED_SEQ_BREAK : SPARC64_SCHED_SEQ_CONSTRAINED;
    return SPARC64_SCHED_SEQ_BREAK;
}
