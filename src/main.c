/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * sparc64rt CLI entry: SPARC V9 (sparc64, Oracle M8 / SPARC64 XII)
 * user-mode translator. Phase 0 parses flags and selects the engine;
 * guest loading and execution land in later phases (interp in Phase 1,
 * dbt in Phase 2).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "os/guest_run.h"

#define SPARC64RT_VERSION "0.0.0-phase0"

typedef enum {
    SPARC64_ENGINE_DEFAULT,
    SPARC64_ENGINE_INTERP,
    SPARC64_ENGINE_DBT
} sparc64_engine_t;

static int usage(const char *argv0, FILE *out)
{
    return fprintf(out,
                   "Usage: %s [options] <guest> [guest-args...]\n"
                   "SPARC V9 (sparc64) user-mode translator.\n"
                   "\n"
                   "Options:\n"
                   "  --interp       run the reference interpreter\n"
                   "  --dbt          run the AArch64 dynamic binary translator\n"
                   "  --difftest     compare dbt against interp step by step\n"
                   "  --trace        trace executed guest instructions\n"
                   "  --version      print version and exit\n"
                   "  --help         print this help and exit\n"
                   "\n"
                   "Environment:\n"
                   "  SPARC64RT_ENGINE=interp|dbt  default engine selection\n",
                   argv0);
}

int main(int argc, char **argv)
{
    sparc64_engine_t engine = SPARC64_ENGINE_DEFAULT;
    int difftest = 0;
    int trace = 0;
    const char *guest = NULL;
    int guest_index = 0;

    const char *env = getenv("SPARC64RT_ENGINE");
    if (env != NULL) {
        if (strcmp(env, "interp") == 0)
            engine = SPARC64_ENGINE_INTERP;
        else if (strcmp(env, "dbt") == 0)
            engine = SPARC64_ENGINE_DBT;
        else {
            (void)fprintf(stderr, "sparc64rt: unknown SPARC64RT_ENGINE=%s\n",
                          env);
            return 2;
        }
    }

    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--version") == 0) {
            (void)printf("sparc64rt %s\n", SPARC64RT_VERSION);
            return 0;
        }
        if (strcmp(argv[i], "--help") == 0) {
            usage(argv[0], stdout);
            return 0;
        }
        if (strcmp(argv[i], "--interp") == 0) {
            engine = SPARC64_ENGINE_INTERP;
            continue;
        }
        if (strcmp(argv[i], "--dbt") == 0) {
            engine = SPARC64_ENGINE_DBT;
            continue;
        }
        if (strcmp(argv[i], "--difftest") == 0) {
            difftest = 1;
            continue;
        }
        if (strcmp(argv[i], "--trace") == 0) {
            trace = 1;
            continue;
        }
        if (argv[i][0] == '-' && argv[i][1] == '-' && argv[i][2] != '\0') {
            (void)fprintf(stderr, "sparc64rt: unknown option %s\n", argv[i]);
            usage(argv[0], stderr);
            return 2;
        }
        guest = argv[i];
        guest_index = i;
        break;
    }

    if (guest == NULL) {
        (void)fprintf(stderr, "sparc64rt: no guest image\n");
        usage(argv[0], stderr);
        return 2;
    }

    /* Phase 1: run the guest through the reference interpreter.
     * The DBT engine lands in Phase 2; --dbt/--difftest without it is
     * an error, not a silent fallback. */
    if (engine == SPARC64_ENGINE_DBT || difftest) {
        (void)fprintf(stderr,
                      "sparc64rt: dbt engine not yet available (Phase 2)\n");
        return 2;
    }
    (void)trace;
    return sparc64_guest_run(guest, &argv[guest_index], 1);
}
