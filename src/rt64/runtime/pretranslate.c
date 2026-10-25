/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#include "runtime/pretranslate.h"
#include "runtime/aot_cache.h"
#include "runtime/initial_image.h"

#include <string.h>

int sparc64_runtime_pretranslate(const sparc64_pretranslate_options_t *options,
                            sparc64_pretranslate_result_t *out)
{
    if (out == NULL)
        return 125;
    memset(out, 0, sizeof(*out));
    out->status = "declined";
    out->reason = "internal";
    if (options == NULL)
        return 125;
    sparc64_space_t space;
    sparc64_space_init(&space, 64);
    space.measure = options->measure;
    sparc64_initial_image_t image = {0};
    sparc64_image_info_t info = {0};
    sparc64_runtime_aot_cache_t cache = {0};
    int status = 1;
    sparc64_measure_stamp_t stamp = sparc64_measure_begin(options->measure, SPARC64_MEASURE_LOAD);
    /* The initial-image owner consumes the supplied descriptor once. Mapping
     * then uses its checked immutable snapshot, without a pathname reopen. */
    bool prepared = sparc64_initial_image_prepare_expected(options->target, options->image_fd,
        options->execfn, options->sysroot, options->runtime_fd, options->argc,
        options->argv, options->envp, options->expected_image,
        &image, out->error, sizeof(out->error));
    bool mapped = prepared && sparc64_program_map_prepared(image.program, &space,
        &info, out->error, sizeof(out->error));
    sparc64_measure_end(options->measure, SPARC64_MEASURE_LOAD, stamp);
    if (!mapped) {
        out->reason = "image";
    } else if (sparc64_runtime_aot_cache_prepare(&cache, options->directory,
            options->authority, image.program, options->runtime_fd,
            &info, &space, options->quantum, options->cache_blocks) != 0) {
        status = 125;
    } else if (cache.status == SPARC64_RUNTIME_AOT_STORED) {
        out->status = "stored";
        out->reason = "cold";
        status = 0;
    } else if (cache.staged) {
        /* Staging validates owned RW bytes. It is deliberately not a HIT:
         * only the ordinary dispatcher can publish and execute the block. */
        out->status = "validated";
        out->reason = "cache";
        status = 0;
    } else {
        out->reason = cache.reason != NULL ? cache.reason : "unsupported";
    }
    stamp = sparc64_measure_begin(options->measure, SPARC64_MEASURE_CLEANUP);
    sparc64_runtime_aot_cache_destroy(&cache);
    sparc64_initial_image_destroy(&image);
    sparc64_space_destroy(&space);
    sparc64_measure_end(options->measure, SPARC64_MEASURE_CLEANUP, stamp);
    return status;
}
