/*
 * src/rt64/runtime/host_contract.h — Phase 6 (L6a) host-contract wiring
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * CLI/env table per rt-series HOST-CONTRACT.md section 3.2 (SPARC64RT_
 * prefix), --image-fd / AT_EXECFD descriptor hygiene per section 3.1,
 * the three authority policies with auto semantics (hyper-linux-*
 * values fail closed), AOT cache identity (SHA-256 translator digest
 * binds cache keys; dynamic PT_INTERP binds both file digests per
 * section 5.2), family broker name/sequence verification, and --stats
 * execution counters. The AOT cache backend itself stays excluded from
 * the build (frozen Makefile); admission resolves up to the backend
 * boundary and declines with a precise reason.
 */

#ifndef SPARC64RT_RUNTIME_HOST_CONTRACT_H
#define SPARC64RT_RUNTIME_HOST_CONTRACT_H

#include <stdbool.h>

typedef enum sparc64_host_engine {
    SPARC64_HOST_ENGINE_DEFAULT = 0,
    SPARC64_HOST_ENGINE_INTERP = 1,
    SPARC64_HOST_ENGINE_DBT = 2
} sparc64_host_engine_t;

typedef struct sparc64_host_options {
    sparc64_host_engine_t engine;
    int difftest;
    int trace;
    int stats;
    int selftest;
    const char *sysroot; /* Effective; NULL selects the container root. */
    int sysroot_from_cli;
    const char *cache_dir; /* NULL disables the cache. */
    const char *execfn;  /* NULL derives the path from argv. */
    const char *argv0;   /* Translator argv[0] (digest fallback). */
    int image_fd;        /* -1 selects open-by-path. */
    int cache_authority_hl; /* Nonzero requests hyper-linux-apfs-acl-v1. */
    int file_identity_hl;   /* Nonzero requests hyper-linux-apfs-v1. */
    int family_authority_hl; /* Nonzero requests hyper-linux-apfs-acl-v1. */
    const char *image_path; /* Loader display/open path (may be NULL). */
    char **guest_argv;
    int guest_argc;
} sparc64_host_options_t;

/* Parse argv over SPARC64RT_* env defaults. Returns 0 on success
 * (*help_only is 1 for --help, 2 for --version which already printed),
 * 2 on CLI/env errors with *error set to a static diagnostic. Explicit
 * CLI flags override the environment. */
int sparc64_host_parse(int argc, char **argv, sparc64_host_options_t *out,
    const char **error, int *help_only);

/* Print usage to out (stdout for --help, stderr for errors). */
void sparc64_host_usage(const char *argv0, int to_stdout);

/* Normalize SPARC64RT_SYSROOT for the Phase 5 consumers (they read the
 * env): a CLI --sysroot/--rootfs wins via setenv, otherwise mirror a
 * lone SPARC64RT_ROOTFS. Returns 0 or -1 with errno set. */
int sparc64_host_apply_sysroot(const sparc64_host_options_t *opts);

/* Fail-closed authority gate: prints the diagnostic and returns 2 when
 * a hyper-linux-* policy was selected, else 0. */
int sparc64_host_check_authorities(const sparc64_host_options_t *opts);

/* AT_EXECFD probe per section 3.1: errno-checked getauxval, so a valid
 * descriptor 0 (stdin closed before exec) is detected. *present is 1
 * with *fd set when the key exists, else 0. */
void sparc64_host_execfd_probe(int *present, int *fd);

/* Resolve --image-fd against AT_EXECFD. Returns 0 with *eff_fd set to
 * the borrowed descriptor (-1 selects open-by-path), 1 for an invalid
 * descriptor, 2 for a conflicting pair; *error names the failure. */
int sparc64_host_resolve_image(const sparc64_host_options_t *opts,
    int *eff_fd, const char **error);

typedef struct sparc64_host_cache {
    int active; /* A --cache/--cache-dir directory was given. */
    int authorized;
    int has_interp;
    char runtime_hex[65]; /* SHA-256 of the translator image. */
    char input_hex[65];   /* SHA-256 of main (+PT_INTERP) bytes. */
    char key_hex[65];     /* Cache key binding the two above. */
    char status[16];      /* "unused", "ready", or "declined". */
    char reason[128];
} sparc64_host_cache_t;

/* Cache admission up to the backend boundary: authorize the directory
 * (auto), hash the translator, the main image, and a resolved
 * PT_INTERP (both pinned via pread), and derive the cache key. Never
 * fatal: failures decline with a reason and leave status "declined". */
int sparc64_host_cache_admit(const sparc64_host_options_t *opts,
    int image_fd, const char *image_path, sparc64_host_cache_t *out);

/* Family broker end-to-end check: create two families, verify the
 * .sparc64rt-family-<pid>-<seq> naming and sequence step, then clean up
 * and confirm both directories are gone. Prints one line per check. */
int sparc64_host_family_verify(void);

/* --selftest-host: auxv/AT_EXECFD consistency, translator digest,
 * authority matrix, file identity, and the family check. Prints a
 * report; returns 0 when every check passes. */
int sparc64_host_selftest(void);

/* --stats execution/dispatch counters to stderr on process exit. */
void sparc64_host_report_stats(const sparc64_host_options_t *opts,
    const sparc64_host_cache_t *cache, const char *engine_name,
    int exit_code);

#endif /* SPARC64RT_RUNTIME_HOST_CONTRACT_H */
