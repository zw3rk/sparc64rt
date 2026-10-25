/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Deterministic turn-scheduler worker loop skeleton. Phase 0 owns the
 * entry shape; interp/dbt stepping plugs in during Phase 1/2.
 */
#ifndef SPARC64RT_RUNTIME_WORKER_LOOP_H
#define SPARC64RT_RUNTIME_WORKER_LOOP_H

#include "core/cpu.h"

#define SPARC64_WORKER_EXIT_UNIMPL 125

int sparc64_worker_run(sparc64_ctx_t *ctx);

#endif
