/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SPARC64RT_RUNTIME_EXEC_TID_H
#define SPARC64RT_RUNTIME_EXEC_TID_H

#include "linux/memory.h"
#include "memory/family_backing.h"
#include "runtime/exec_state.h"
#include "runtime/family_mm.h"

/* Under the old image's held family guard and complete worker/native seals,
 * preflight each entire four-byte clear-tid store. A bad guest destination is
 * best effort and produces no intent. Only segments visible through shared
 * anonymous family slots survive native exec. The caller owns *out. */
int sparc64_exec_tid_capture(sparc64_family_guard_t *guard, sparc64_space_t *space,
                        const sparc64_linux_memory_t *memory,
                        sparc64_family_backing_t *backing,
                        const uint64_t *addresses, size_t address_count,
                        sparc64_exec_tid_clear_t **out, size_t *out_count);

/* A separate CLONE_VM process can observe every mapped family page in the
 * same old MM, including anonymous-private/BRK/initial pages. Under the exact
 * frozen MM guard, capture those writable keys too. File-private preflight
 * refreshes clean bytes without establishing COW; replay makes the first-COW
 * transition only after a successful native exec. Inaccessible/BUS words
 * retain the best-effort rule. */
int sparc64_exec_tid_capture_same_mm(sparc64_family_guard_t *guard, sparc64_space_t *space,
                        const sparc64_linux_memory_t *memory,
                        sparc64_family_backing_t *backing,
                        const uint64_t *addresses, size_t address_count,
                        sparc64_exec_tid_clear_t **out, size_t *out_count);

/* Attributed canonical exec supplies explicit per-store roles. A caller
 * store is captured only while another owner was live at freeze; replay
 * rechecks that exact old MM before deciding whether to apply it. */
int sparc64_exec_tid_capture_tagged(sparc64_family_guard_t *guard, sparc64_space_t *space,
                        const sparc64_linux_memory_t *memory,
                        sparc64_family_backing_t *backing,
                        const sparc64_exec_tid_request_t *requests, size_t count,
                        bool same_mm,
                        sparc64_exec_tid_clear_t **out, size_t *out_count);

/* Point-of-no-return startup only: under the fresh held guard, patch CURRENT
 * family slot states so unrelated peer writes since native exec survive.
 * A failed commit is fatal to startup; no old image can resume. */
int sparc64_exec_tid_replay(sparc64_family_guard_t *guard, uint64_t old_mm_id,
                       const sparc64_exec_tid_clear_t *intents, size_t count);
int sparc64_exec_tid_replay_old_mm(sparc64_family_guard_t *guard, sparc64_family_mm_t old_mm,
                       const sparc64_exec_tid_clear_t *intents, size_t count);

#endif
