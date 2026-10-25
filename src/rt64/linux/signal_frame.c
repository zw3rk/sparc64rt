/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Phase-0 SPARC64 register spill into the translator signal-frame scratch
 * area. Layout (all guest fields big-endian, matching the SPARC V9 guest):
 *   INFO 128 B | STACK 24 B | MASK 8 B | CONTEXT (pc, npc, ccr, fsr, fprs,
 *   r[32], f[32]) | zero reservation tail.
 * The frozen Linux rt_signal_frame64 wire layout (SPEC 2.1, 528-byte
 * prefix) lands with lane L0b / Phase 4; this scratch frame is internal
 * only and never observed by the guest.
 */
#include "linux/signal_frame.h"

#include <stddef.h>
#include <string.h>

enum {
    FRAME_INFO = 0,
    FRAME_INFO_SIZE = 128,
    FRAME_STACK = 128,
    FRAME_STACK_SIZE = 24,
    FRAME_MASK = 152,
    FRAME_MASK_SIZE = 8,
    FRAME_CONTEXT = 160,
    FRAME_PC = 160,
    FRAME_NPC = 168,
    FRAME_CCR = 176,
    FRAME_FSR = 184,
    FRAME_FPRS = 192,
    FRAME_GPRS = 200,
    FRAME_GPRS_SIZE = 256,
    FRAME_FP = 456,
    FRAME_FP_SIZE = 128,
    FRAME_END = 584
};

static bool frame_in_range(const sparc64_space_t *space, uint64_t address)
{
    return space != NULL && address <= space->limit &&
           SPARC64_SIGNAL_FRAME_SIZE <= space->limit - address;
}

static void put_be32(unsigned char *p, uint32_t value)
{
    p[0] = (unsigned char)(value >> 24);
    p[1] = (unsigned char)(value >> 16);
    p[2] = (unsigned char)(value >> 8);
    p[3] = (unsigned char)value;
}

static uint32_t get_be32(const unsigned char *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static void put_be64(unsigned char *p, uint64_t value)
{
    put_be32(p, (uint32_t)(value >> 32));
    put_be32(p + 4, (uint32_t)value);
}

static uint64_t get_be64(const unsigned char *p)
{
    return ((uint64_t)get_be32(p) << 32) | (uint64_t)get_be32(p + 4);
}

bool sparc64_signal_frame_write(sparc64_space_t *space, uint64_t frame_address,
                           const sparc64_cpu_t *cpu, uint64_t saved_mask,
                           const sparc64_signal_stack_t *stack,
                           const unsigned char info[128])
{
    unsigned char frame[SPARC64_SIGNAL_FRAME_SIZE];

    if (!frame_in_range(space, frame_address) || cpu == NULL ||
        stack == NULL || info == NULL)
        return false;

    memset(frame, 0, sizeof(frame));
    memcpy(frame + FRAME_INFO, info, FRAME_INFO_SIZE);
    put_be64(frame + FRAME_STACK, stack->sp);
    put_be32(frame + FRAME_STACK + 8, stack->flags);
    put_be64(frame + FRAME_STACK + 16, stack->size);
    put_be64(frame + FRAME_MASK, saved_mask);

    put_be64(frame + FRAME_PC, cpu->pc);
    put_be64(frame + FRAME_NPC, cpu->npc);
    put_be64(frame + FRAME_CCR, cpu->ccr);
    put_be64(frame + FRAME_FSR, cpu->fsr);
    put_be64(frame + FRAME_FPRS, cpu->fprs);
    for (unsigned int i = 0; i < 32; ++i)
        put_be64(frame + FRAME_GPRS + 8U * i, cpu->r[i]);
    for (unsigned int i = 0; i < 32; ++i)
        put_be32(frame + FRAME_FP + 4U * i, cpu->fp.f[i]);

    return sparc64_space_write(space, frame_address, frame, sizeof(frame));
}

bool sparc64_signal_frame_read_mask(sparc64_space_t *space, uint64_t frame_address,
                               uint64_t *saved_mask)
{
    unsigned char bytes[8];

    if (saved_mask == NULL || !frame_in_range(space, frame_address))
        return false;
    if (!sparc64_space_read(space, frame_address + FRAME_MASK, bytes,
                       sizeof(bytes), SPARC64_MEM_READ))
        return false;
    *saved_mask = get_be64(bytes);
    return true;
}

bool sparc64_signal_frame_read_context(sparc64_space_t *space, uint64_t frame_address,
                                  sparc64_cpu_t *cpu)
{
    unsigned char gprs[FRAME_GPRS_SIZE];
    unsigned char fp[FRAME_FP_SIZE];
    unsigned char head[40];
    unsigned char tail[SPARC64_SIGNAL_FRAME_SIZE - FRAME_END];

    if (cpu == NULL || !frame_in_range(space, frame_address))
        return false;
    if (!sparc64_space_read(space, frame_address + FRAME_PC, head,
                       sizeof(head), SPARC64_MEM_READ) ||
        !sparc64_space_read(space, frame_address + FRAME_GPRS, gprs,
                       sizeof(gprs), SPARC64_MEM_READ) ||
        !sparc64_space_read(space, frame_address + FRAME_FP, fp, sizeof(fp),
                       SPARC64_MEM_READ) ||
        !sparc64_space_read(space, frame_address + FRAME_END, tail,
                       sizeof(tail), SPARC64_MEM_READ))
        return false;
    for (size_t i = 0; i < sizeof(tail); ++i) {
        if (tail[i] != 0)
            return false;
    }

    sparc64_cpu_t decoded = *cpu;
    decoded.pc = get_be64(head);
    decoded.npc = get_be64(head + 8);
    decoded.ccr = get_be64(head + 16);
    decoded.fsr = get_be64(head + 24);
    decoded.fprs = get_be64(head + 32);
    for (unsigned int i = 0; i < 32; ++i)
        decoded.r[i] = get_be64(gprs + 8U * i);
    decoded.r[0] = 0;
    for (unsigned int i = 0; i < 32; ++i)
        decoded.fp.f[i] = get_be32(fp + 4U * i);
    *cpu = decoded;
    return true;
}

bool sparc64_signal_frame_read_stack(sparc64_space_t *space, uint64_t frame_address,
                                sparc64_signal_stack_t *stack)
{
    unsigned char bytes[FRAME_STACK_SIZE];

    if (stack == NULL || !frame_in_range(space, frame_address))
        return false;
    if (!sparc64_space_read(space, frame_address + FRAME_STACK, bytes,
                       sizeof(bytes), SPARC64_MEM_READ))
        return false;
    sparc64_signal_stack_t decoded = {
        .sp = get_be64(bytes),
        .flags = get_be32(bytes + 8),
        .size = get_be64(bytes + 16)
    };
    *stack = decoded;
    return true;
}
