/*
 * src/rt64/runtime/host_contract.c — Phase 6 (L6a) host-contract parsing
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * CLI/env table per HOST-CONTRACT.md section 3.2, sysroot
 * normalization, fail-closed authority gate, and AT_EXECFD / --image-fd
 * descriptor hygiene per section 3.1. Identity, family, selftest, and
 * stats live in src/rt64/runtime/host_contract_identity.c.
 */

#define _POSIX_C_SOURCE 200809L
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "runtime/host_contract.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#if defined(__linux__)
#include <sys/auxv.h>
#endif

extern char **environ;

static char parse_error[256];

static void set_error(const char *text)
{
    size_t n = strlen(text);
    if (n >= sizeof(parse_error)) {
        n = sizeof(parse_error) - 1U;
    }
    memcpy(parse_error, text, n);
    parse_error[n] = '\0';
}

void sparc64_host_usage(const char *argv0, int to_stdout)
{
    FILE *out = to_stdout ? stdout : stderr;
    (void)fprintf(out,
        "Usage: %s [options] [--] <guest> [guest-args...]\n"
        "       %s [options] --execfn <path> [--] [guest-args...]\n"
        "SPARC V9 (sparc64) user-mode translator.\n"
        "\n"
        "Options:\n"
        "  --interp       run the reference interpreter\n"
        "  --dbt          run the AArch64 dynamic binary translator\n"
        "  --engine <interp|dbt> (or --engine=<interp|dbt>) select engine\n"
        "  --difftest     compare dbt against interp step by step\n"
        "  --trace        trace executed guest instructions\n"
        "  --sysroot <dir> (or --rootfs <dir>) guest sysroot prefix\n"
        "  --cache <dir> (or --cache-dir <dir>) persistent AOT cache\n"
        "  --execfn <path> explicit guest executable path (AT_EXECFN)\n"
        "  --image-fd <fd> open descriptor for the guest main ELF image\n"
        "  --cache-authority=<auto|hyper-linux-apfs-acl-v1>\n"
        "  --file-identity=<auto|hyper-linux-apfs-v1>\n"
        "  --family-authority=<auto|hyper-linux-apfs-acl-v1>\n"
        "  --stats        execution/dispatch counters to stderr on exit\n"
        "  --selftest-host run host-facility checks and exit\n"
        "  --version      print version and exit\n"
        "  --help         print this help and exit\n"
        "\n"
        "Environment:\n"
        "  SPARC64RT_ENGINE=interp|dbt  default engine selection\n"
        "  SPARC64RT_SYSROOT / SPARC64RT_ROOTFS  guest sysroot prefix\n"
        "  SPARC64RT_CACHE / SPARC64RT_CACHE_DIR  persistent AOT cache\n"
        "  SPARC64RT_EXECFN  explicit guest executable path\n"
        "  SPARC64RT_STATS=1  execution/dispatch counters to stderr\n"
        "Explicit CLI flags override the environment. Unknown --options\n"
        "fail hard. hyper-linux-* authorities fail closed until qualified.\n",
        argv0, argv0);
}

/* Non-empty env value, or NULL when unset/empty. */
static const char *nonempty_env(const char *name)
{
    const char *value = getenv(name);
    if (value == NULL || value[0] == '\0') {
        return NULL;
    }
    return value;
}

/* Strict non-negative int: all digits, fits in int. */
static int parse_fd_value(const char *text, int *out)
{
    size_t i = 0;
    unsigned long value = 0;
    if (text == NULL || text[0] == '\0') {
        return -1;
    }
    while (text[i] != '\0') {
        if (text[i] < '0' || text[i] > '9') {
            return -1;
        }
        value = value * 10UL + (unsigned long)(text[i] - '0');
        if (value > (unsigned long)INT_MAX) {
            return -1;
        }
        i++;
    }
    *out = (int)value;
    return 0;
}

/* Match "--opt rest" (consumes the next argv) or "--opt=rest".
 * Returns 1 with *value set, 0 for no match, -1 for a missing value. */
static int take_value(int argc, char **argv, int *index,
    const char *opt, const char **value)
{
    size_t len = strlen(opt);
    const char *arg = argv[*index];
    if (strncmp(arg, opt, len) != 0) {
        return 0;
    }
    if (arg[len] == '=') {
        if (arg[len + 1] == '\0') {
            return -1;
        }
        *value = arg + len + 1;
        (*index)++;
        return 1;
    }
    if (arg[len] != '\0') {
        return 0;
    }
    if (*index + 1 >= argc || argv[*index + 1][0] == '\0' ||
        strcmp(argv[*index + 1], "--") == 0) {
        return -1;
    }
    *value = argv[*index + 1];
    (*index) += 2;
    return 1;
}

static int parse_engine_value(const char *text, sparc64_host_engine_t *out)
{
    if (strcmp(text, "interp") == 0) {
        *out = SPARC64_HOST_ENGINE_INTERP;
        return 0;
    }
    if (strcmp(text, "dbt") == 0) {
        *out = SPARC64_HOST_ENGINE_DBT;
        return 0;
    }
    return -1;
}

int sparc64_host_parse(int argc, char **argv, sparc64_host_options_t *out,
    const char **error, int *help_only)
{
    const char *value;
    int index = 1;
    int seen_engine = 0, seen_sysroot = 0, seen_cache = 0;
    int seen_execfn = 0, seen_image_fd = 0;
    int seen_cache_auth = 0, seen_file_ident = 0, seen_family_auth = 0;
    int seen_stats = 0, seen_difftest = 0, seen_trace = 0, seen_selftest = 0;
    int tokens_at = -1;
    sparc64_host_engine_t engine = SPARC64_HOST_ENGINE_DEFAULT;
    const char *sysroot = NULL;
    const char *cache_dir = NULL;
    const char *execfn = NULL;
    int image_fd = -1;
    int cache_hl = 0, file_hl = 0, family_hl = 0;
    int stats = 0, difftest = 0, trace = 0, selftest = 0;
    *error = NULL;
    *help_only = 0;
    memset(out, 0, sizeof(*out));
    out->image_fd = -1;
    out->argv0 = (argc > 0) ? argv[0] : NULL;

    {
        const char *env = nonempty_env("SPARC64RT_ENGINE");
        if (env != NULL) {
            if (parse_engine_value(env, &engine) != 0) {
                (void)snprintf(parse_error, sizeof(parse_error),
                    "unknown SPARC64RT_ENGINE=%s", env);
                *error = parse_error;
                return 2;
            }
        }
        if (nonempty_env("SPARC64RT_STATS") != NULL &&
            strcmp(getenv("SPARC64RT_STATS"), "1") == 0) {
            stats = 1;
        }
        sysroot = nonempty_env("SPARC64RT_SYSROOT");
        if (sysroot == NULL) {
            sysroot = nonempty_env("SPARC64RT_ROOTFS");
        }
        cache_dir = nonempty_env("SPARC64RT_CACHE");
        if (cache_dir == NULL) {
            cache_dir = nonempty_env("SPARC64RT_CACHE_DIR");
        }
        execfn = nonempty_env("SPARC64RT_EXECFN");
    }

    while (index < argc && strcmp(argv[index], "--") != 0) {
        const char *arg = argv[index];
        int matched;
        if (strcmp(arg, "--help") == 0) {
            *help_only = 1;
            return 0;
        }
        if (strcmp(arg, "--version") == 0) {
            (void)printf("sparc64rt 0.0.0-phase6\n");
            *help_only = 2;
            return 0;
        }
        if (strcmp(arg, "--interp") == 0 || strcmp(arg, "--dbt") == 0) {
            if (seen_engine) {
                set_error("conflicting engine selection");
                *error = parse_error;
                return 2;
            }
            seen_engine = 1;
            engine = (strcmp(arg, "--dbt") == 0) ?
                SPARC64_HOST_ENGINE_DBT : SPARC64_HOST_ENGINE_INTERP;
            index++;
            continue;
        }
        matched = take_value(argc, argv, &index, "--engine", &value);
        if (matched != 0) {
            if (matched < 0 || parse_engine_value(value, &engine) != 0 ||
                seen_engine) {
                set_error("invalid or duplicate --engine (interp|dbt)");
                *error = parse_error;
                return 2;
            }
            seen_engine = 1;
            continue;
        }
        if (strcmp(arg, "--difftest") == 0) {
            if (seen_difftest) {
                set_error("duplicate --difftest");
                *error = parse_error;
                return 2;
            }
            seen_difftest = 1;
            difftest = 1;
            index++;
            continue;
        }
        if (strcmp(arg, "--trace") == 0) {
            if (seen_trace) {
                set_error("duplicate --trace");
                *error = parse_error;
                return 2;
            }
            seen_trace = 1;
            trace = 1;
            index++;
            continue;
        }
        matched = take_value(argc, argv, &index, "--sysroot", &value);
        if (matched == 0) {
            matched = take_value(argc, argv, &index, "--rootfs", &value);
        }
        if (matched != 0) {
            if (matched < 0 || seen_sysroot) {
                set_error("invalid or duplicate sysroot");
                *error = parse_error;
                return 2;
            }
            seen_sysroot = 1;
            sysroot = value;
            continue;
        }
        matched = take_value(argc, argv, &index, "--cache-dir", &value);
        if (matched == 0) {
            matched = take_value(argc, argv, &index, "--cache", &value);
        }
        if (matched != 0) {
            if (matched < 0 || seen_cache) {
                set_error("invalid or duplicate cache directory");
                *error = parse_error;
                return 2;
            }
            seen_cache = 1;
            cache_dir = value;
            continue;
        }
        matched = take_value(argc, argv, &index, "--execfn", &value);
        if (matched != 0) {
            if (matched < 0 || seen_execfn) {
                set_error("invalid or duplicate execfn");
                *error = parse_error;
                return 2;
            }
            seen_execfn = 1;
            execfn = value;
            continue;
        }
        matched = take_value(argc, argv, &index, "--image-fd", &value);
        if (matched != 0) {
            if (matched < 0 || seen_image_fd ||
                parse_fd_value(value, &image_fd) != 0) {
                set_error("invalid or duplicate --image-fd");
                *error = parse_error;
                return 2;
            }
            seen_image_fd = 1;
            continue;
        }
        matched = take_value(argc, argv, &index, "--cache-authority",
            &value);
        if (matched != 0) {
            if (matched < 0 || seen_cache_auth) {
                set_error("invalid or duplicate cache authority");
                *error = parse_error;
                return 2;
            }
            seen_cache_auth = 1;
            if (strcmp(value, "auto") == 0) {
                cache_hl = 0;
            } else if (strcmp(value, "hyper-linux-apfs-acl-v1") == 0) {
                cache_hl = 1;
            } else {
                set_error("invalid cache authority "
                    "(auto|hyper-linux-apfs-acl-v1)");
                *error = parse_error;
                return 2;
            }
            continue;
        }
        matched = take_value(argc, argv, &index, "--file-identity", &value);
        if (matched != 0) {
            if (matched < 0 || seen_file_ident) {
                set_error("invalid or duplicate file identity "
                    "(auto|hyper-linux-apfs-v1)");
                *error = parse_error;
                return 2;
            }
            seen_file_ident = 1;
            if (strcmp(value, "auto") == 0) {
                file_hl = 0;
            } else if (strcmp(value, "hyper-linux-apfs-v1") == 0) {
                file_hl = 1;
            } else {
                set_error("invalid file identity "
                    "(auto|hyper-linux-apfs-v1)");
                *error = parse_error;
                return 2;
            }
            continue;
        }
        matched = take_value(argc, argv, &index, "--family-authority",
            &value);
        if (matched != 0) {
            if (matched < 0 || seen_family_auth) {
                set_error("invalid or duplicate family authority "
                    "(auto|hyper-linux-apfs-acl-v1)");
                *error = parse_error;
                return 2;
            }
            seen_family_auth = 1;
            if (strcmp(value, "auto") == 0) {
                family_hl = 0;
            } else if (strcmp(value, "hyper-linux-apfs-acl-v1") == 0) {
                family_hl = 1;
            } else {
                set_error("invalid family authority "
                    "(auto|hyper-linux-apfs-acl-v1)");
                *error = parse_error;
                return 2;
            }
            continue;
        }
        if (strcmp(arg, "--stats") == 0) {
            if (seen_stats) {
                set_error("duplicate --stats");
                *error = parse_error;
                return 2;
            }
            seen_stats = 1;
            stats = 1;
            index++;
            continue;
        }
        if (strcmp(arg, "--selftest-host") == 0) {
            if (seen_selftest) {
                set_error("duplicate --selftest-host");
                *error = parse_error;
                return 2;
            }
            seen_selftest = 1;
            selftest = 1;
            index++;
            continue;
        }
        if (arg[0] == '-' && arg[1] == '-' && arg[2] != '\0') {
            static char unknown_error[192];
            (void)snprintf(unknown_error, sizeof(unknown_error),
                "unknown option %s", arg);
            set_error(unknown_error);
            *error = parse_error;
            return 2;
        }
        break;
    }

    tokens_at = index;
    if (tokens_at < argc && strcmp(argv[tokens_at], "--") == 0) {
        tokens_at++;
    }
    if (selftest) {
        out->engine = engine;
        out->difftest = difftest;
        out->trace = trace;
        out->stats = stats;
        out->selftest = 1;
        out->sysroot = sysroot;
        out->sysroot_from_cli = seen_sysroot;
        out->cache_dir = cache_dir;
        out->execfn = execfn;
        out->image_fd = image_fd;
        out->cache_authority_hl = cache_hl;
        out->file_identity_hl = file_hl;
        out->family_authority_hl = family_hl;
        return 0;
    }
    if (execfn == NULL && tokens_at >= argc) {
        set_error("no guest image");
        *error = parse_error;
        return 2;
    }
    out->engine = engine;
    out->difftest = difftest;
    out->trace = trace;
    out->stats = stats;
    out->selftest = 0;
    out->sysroot = sysroot;
    out->sysroot_from_cli = seen_sysroot;
    out->cache_dir = cache_dir;
    out->execfn = execfn;
    out->image_fd = image_fd;
    out->cache_authority_hl = cache_hl;
    out->file_identity_hl = file_hl;
    out->family_authority_hl = family_hl;
    if (execfn != NULL) {
        out->image_path = (tokens_at < argc) ? argv[tokens_at] : execfn;
        out->guest_argv = (tokens_at < argc) ? &argv[tokens_at] : NULL;
        out->guest_argc = argc - tokens_at;
    } else {
        out->image_path = argv[tokens_at];
        out->guest_argv = &argv[tokens_at];
        out->guest_argc = argc - tokens_at;
    }
    return 0;
}

/* ---- sysroot normalization (Phase 5 consumers read the env) ------------- */

int sparc64_host_apply_sysroot(const sparc64_host_options_t *opts)
{
    const char *sysroot;
    const char *rootfs;
    if (opts == NULL) {
        errno = EINVAL;
        return -1;
    }
    if (opts->sysroot_from_cli) {
        if (setenv("SPARC64RT_SYSROOT", opts->sysroot, 1) != 0) {
            return -1;
        }
        return 0;
    }
    sysroot = getenv("SPARC64RT_SYSROOT");
    if (sysroot != NULL && sysroot[0] != '\0') {
        return 0;
    }
    rootfs = getenv("SPARC64RT_ROOTFS");
    if (rootfs != NULL && rootfs[0] != '\0') {
        if (setenv("SPARC64RT_SYSROOT", rootfs, 1) != 0) {
            return -1;
        }
    }
    return 0;
}

/* ---- fail-closed authority gate ----------------------------------------- */

int sparc64_host_check_authorities(const sparc64_host_options_t *opts)
{
    if (opts == NULL) {
        return 2;
    }
    if (opts->cache_authority_hl) {
        (void)fprintf(stderr, "sparc64rt: cache authority "
            "'hyper-linux-apfs-acl-v1' is not qualified on this host "
            "(translator-side fail-closed)\n");
        return 2;
    }
    if (opts->file_identity_hl) {
        (void)fprintf(stderr, "sparc64rt: file identity "
            "'hyper-linux-apfs-v1' is not qualified on this host "
            "(translator-side fail-closed)\n");
        return 2;
    }
    if (opts->family_authority_hl) {
        (void)fprintf(stderr, "sparc64rt: family authority "
            "'hyper-linux-apfs-acl-v1' is not qualified on this host "
            "(translator-side fail-closed)\n");
        return 2;
    }
    return 0;
}

/* ---- AT_EXECFD / --image-fd descriptor hygiene -------------------------- */

void sparc64_host_execfd_probe(int *present, int *fd)
{
#if defined(__linux__)
    int saved;
    unsigned long value;
    if (present != NULL) {
        *present = 0;
    }
    if (fd != NULL) {
        *fd = -1;
    }
    if (present == NULL || fd == NULL) {
        return;
    }
    errno = 0;
    value = getauxval(AT_EXECFD);
    saved = errno;
    if (saved != 0) {
        return;
    }
    if (value > (unsigned long)INT_MAX) {
        return;
    }
    *present = 1;
    *fd = (int)value;
#else
    if (present != NULL) {
        *present = 0;
    }
    if (fd != NULL) {
        *fd = -1;
    }
#endif
}

int sparc64_host_resolve_image(const sparc64_host_options_t *opts,
    int *eff_fd, const char **error)
{
    int aux_present = 0;
    int aux_fd = -1;
    int fd;
    struct stat status;
    static char resolve_error[128];
    *error = NULL;
    *eff_fd = -1;
    sparc64_host_execfd_probe(&aux_present, &aux_fd);
    if (opts->image_fd >= 0 && aux_present && opts->image_fd != aux_fd) {
        set_error("conflicting executable descriptors "
            "(--image-fd disagrees with AT_EXECFD)");
        *error = parse_error;
        return 2;
    }
    fd = (opts->image_fd >= 0) ? opts->image_fd :
        (aux_present ? aux_fd : -1);
    if (fd < 0) {
        return 0;
    }
    if (fd == 2) {
        (void)snprintf(resolve_error, sizeof(resolve_error),
            "invalid executable descriptor (fd 2 carries diagnostics)");
        *error = resolve_error;
        return 1;
    }
    if (fcntl(fd, F_GETFD) < 0) {
        (void)snprintf(resolve_error, sizeof(resolve_error),
            "invalid executable descriptor (not open)");
        *error = resolve_error;
        return 1;
    }
    if (fstat(fd, &status) != 0 || !S_ISREG(status.st_mode)) {
        (void)snprintf(resolve_error, sizeof(resolve_error),
            "invalid executable descriptor (not a regular file)");
        *error = resolve_error;
        return 1;
    }
    *eff_fd = fd;
    return 0;
}
