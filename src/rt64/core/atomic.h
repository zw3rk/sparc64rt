/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SPARC64RT_CORE_ATOMIC_H
#define SPARC64RT_CORE_ATOMIC_H
#include <stdbool.h>
#include <stdint.h>

typedef enum {
    SPARC64_ATOMIC_LR, SPARC64_ATOMIC_SC, SPARC64_ATOMIC_SWAP, SPARC64_ATOMIC_ADD,
    SPARC64_ATOMIC_XOR, SPARC64_ATOMIC_AND, SPARC64_ATOMIC_OR, SPARC64_ATOMIC_MIN,
    SPARC64_ATOMIC_MAX, SPARC64_ATOMIC_MINU, SPARC64_ATOMIC_MAXU
} sparc64_atomic_op_t;

/* Neither member is a host pointer. The binding identifies a canonical
 * mapping-instance + 16-byte slot; aliases share the backing write epoch. */
typedef struct {
    uint64_t binding_id, write_epoch;
} sparc64_reservation_token_t;

typedef struct {
    sparc64_atomic_op_t op;
    unsigned int width;
    uint64_t address, value;
    bool aq, rl, reservation_valid;
    sparc64_reservation_token_t reservation;
} sparc64_atomic_request_t;

typedef struct {
    uint64_t old_value; /* Raw low width; core applies architectural extension. */
    bool sc_success;
    sparc64_reservation_token_t reservation;
} sparc64_atomic_result_t;

/* An atomic memory callback returns false for access failure. SC failure is
 * a successful callback with sc_success=false, after write-permission checks.
 * Core consumes reservations on SC, regardless of the callback outcome. */
#endif
