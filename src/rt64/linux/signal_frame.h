/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SPARC64RT_LINUX_SIGNAL_FRAME_H
#define SPARC64RT_LINUX_SIGNAL_FRAME_H

#include "core/cpu.h"
#include "memory/space.h"

#include <stdbool.h>
#include <stdint.h>

#define SPARC64_SIGNAL_FRAME_SIZE UINT64_C(1088)

typedef struct {
    uint64_t sp;
    uint64_t size;
    uint32_t flags;
} sparc64_signal_stack_t;

/* These routines encode/decode the translator-internal SPARC64 register
 * spill frame (big-endian guest fields). They do not modify signal masks
 * or deliver signals. A failed read leaves every caller output unchanged.
 * The frozen Linux rt_signal_frame64 wire layout lands with lane L0b. */
bool sparc64_signal_frame_write(sparc64_space_t *space, uint64_t frame_address,
                           const sparc64_cpu_t *cpu, uint64_t saved_mask,
                           const sparc64_signal_stack_t *stack,
                           const unsigned char info[128]);
bool sparc64_signal_frame_read_mask(sparc64_space_t *space, uint64_t frame_address,
                               uint64_t *saved_mask);
bool sparc64_signal_frame_read_context(sparc64_space_t *space, uint64_t frame_address,
                                  sparc64_cpu_t *cpu);
bool sparc64_signal_frame_read_stack(sparc64_space_t *space, uint64_t frame_address,
                                sparc64_signal_stack_t *stack);

#endif
