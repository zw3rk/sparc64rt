/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#include "runtime/worker_loop.h"

#include <stddef.h>

int sparc64_worker_run(sparc64_ctx_t *ctx)
{
    if (ctx == NULL)
        return SPARC64_WORKER_EXIT_UNIMPL;
    /* Guest stepping (interp_run / dbt dispatch) plugs in here in
     * Phase 1/2. Until then report the unimplemented marker. */
    return SPARC64_WORKER_EXIT_UNIMPL;
}
