/*
 * src/main.c — sparc64rt CLI (Phase 6, L6a host-contract compliance)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * SPARC V9 (sparc64) user-mode translator entry: host-contract CLI/env
 * parsing lives in src/os/host_contract.c; this TU wires the
 * resolved options to the runner, reports --stats, and owns exit codes.
 * Unknown --options fail hard (exit 2).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "os/guest_run.h"
#include "os/host_contract.h"

int main(int argc, char **argv)
{
    sparc64_host_options_t opts;
    sparc64_host_cache_t cache;
    const char *error = NULL;
    const char *engine_name = "interp";
    const char *exec_path;
    const char *loader_path;
    char *synthetic[2];
    int help_only = 0;
    int engine_id = 0;
    int eff_fd = -1;
    int rc;
    int code;

    memset(&opts, 0, sizeof(opts));
    memset(&cache, 0, sizeof(cache));
    code = sparc64_host_parse(argc, argv, &opts, &error, &help_only);
    if (help_only == 1) {
        sparc64_host_usage((argc > 0) ? argv[0] : "sparc64rt", 1);
        return 0;
    }
    if (help_only != 0) {
        return 0;
    }
    if (code != 0) {
        (void)fprintf(stderr, "sparc64rt: %s\n",
            (error != NULL) ? error : "invalid options");
        sparc64_host_usage((argc > 0) ? argv[0] : "sparc64rt", 0);
        return 2;
    }
    if (opts.selftest) {
        return sparc64_host_selftest();
    }
    code = sparc64_host_check_authorities(&opts);
    if (code != 0) {
        if (opts.stats) {
            sparc64_host_report_stats(&opts, &cache, "none", code);
        }
        return code;
    }
    if (sparc64_host_apply_sysroot(&opts) != 0) {
        (void)fprintf(stderr,
            "sparc64rt: cannot normalize SPARC64RT_SYSROOT\n");
        if (opts.stats) {
            sparc64_host_report_stats(&opts, &cache, "none", 1);
        }
        return 1;
    }
    code = sparc64_host_resolve_image(&opts, &eff_fd, &error);
    if (code != 0) {
        (void)fprintf(stderr, "sparc64rt: %s\n",
            (error != NULL) ? error : "invalid executable descriptor");
        if (opts.stats) {
            sparc64_host_report_stats(&opts, &cache, "none", code);
        }
        return code;
    }
    /* Image source: borrowed fd wins; otherwise execfn, otherwise the
     * positional path token (also argv[0] when --execfn is absent). */
    exec_path = (opts.execfn != NULL) ? opts.execfn : opts.image_path;
    loader_path = (eff_fd >= 0) ? opts.image_path : exec_path;
    if (loader_path == NULL && eff_fd < 0) {
        (void)fprintf(stderr, "sparc64rt: no guest image\n");
        if (opts.stats) {
            sparc64_host_report_stats(&opts, &cache, "none", 2);
        }
        return 2;
    }
    if (opts.cache_dir != NULL) {
        (void)sparc64_host_cache_admit(&opts, eff_fd,
            (eff_fd >= 0) ? NULL : exec_path, &cache);
    }
    if (opts.difftest) {
        engine_id = 2;
        engine_name = "difftest";
    } else if (opts.engine == SPARC64_HOST_ENGINE_DBT) {
        engine_id = 1;
        engine_name = "dbt";
    }
    if (opts.trace) {
        (void)fprintf(stderr, "sparc64rt: --trace is accepted "
            "(per-instruction tracing not wired)\n");
    }
    if (opts.guest_argv == NULL) {
        synthetic[0] = (char *)((exec_path != NULL) ? exec_path :
            loader_path);
        synthetic[1] = NULL;
        rc = sparc64_guest_run_full(loader_path, eff_fd, opts.execfn,
            synthetic, engine_id);
    } else {
        rc = sparc64_guest_run_full(loader_path, eff_fd, opts.execfn,
            opts.guest_argv, engine_id);
    }
    if (opts.stats) {
        sparc64_host_report_stats(&opts, &cache, engine_name,
            rc < 0 ? 1 : rc);
    }
    return rc < 0 ? 1 : rc;
}
