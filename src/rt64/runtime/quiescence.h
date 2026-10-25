/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SPARC64RT_RUNTIME_QUIESCENCE_H
#define SPARC64RT_RUNTIME_QUIESCENCE_H

#include "runtime/guest_memory.h"
#include "runtime/native_signal.h"
#include "runtime/scheduler.h"

/* Begin under the caller's family guard at a dispatcher boundary. Native
 * wake is nonterminal: a pending read/write may have consumed bytes and must
 * still reenter, finish its staging/copyout, and publish its guest result.
 * Wake fanout failure is infrastructure-fatal because partial fanout may
 * already have interrupted native operations. Ordinary validation failure
 * occurs before any wake and leaves the guest state resumable. */
int sparc64_quiescence_begin(sparc64_sched_ticket_t *owner,
                        sparc64_native_signal_process_t *native_process);

/* While active flights remain, release the family guard and wait for owner
 * admission. Returns 1 with guard held when every flight has either committed
 * its guest result or suspended inside its still-owned callback frame. Such
 * frames retain leases/staging until abort; a fork child must abandon its
 * copied flight capabilities separately. Returns 0 on group terminal, -1 on
 * infrastructure failure. No scheduler mutex spans family acquisition. */
int sparc64_quiescence_wait(sparc64_sched_ticket_t *owner,
                       sparc64_guest_memory_worker_t *memory_worker);

/* Called by every nonowner at the top of its dispatch loop, before the next
 * guest instruction. Returns 1 with guard held, 0 on group terminal, -1 on
 * infrastructure failure. Suspended tickets retain CPU/restart state. */
int sparc64_quiescence_checkpoint(sparc64_sched_ticket_t *ticket,
                             sparc64_guest_memory_worker_t *memory_worker);

/* Reversible failed-prepare or successful fork-parent resume. The caller
 * still owns the family guard and has not destroyed sibling workers. */
int sparc64_quiescence_abort(sparc64_sched_ticket_t *owner);

/* Run a native-thread-only phase on every quiesced sibling. The caller keeps
 * transition ownership and its family guard on success. Waiting temporarily
 * releases that guard; each sibling acknowledges only after its hook finishes.
 * A partial wake failure is infrastructure-fatal, as for begin. */
int sparc64_quiescence_native_phase(sparc64_sched_ticket_t *owner,
                               sparc64_guest_memory_worker_t *memory_worker,
                               sparc64_native_signal_process_t *native_process,
                               unsigned int phase);

#endif
