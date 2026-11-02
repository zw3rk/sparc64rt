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
 *
 * NOTE: _GNU_SOURCE must precede every #include: glibc latches the
 * feature set on first <features.h> inclusion, and a late define
 * leaves ucontext_t members underscore-prefixed (__pc) instead of
 * the musl/glibc-GNU spelling (pc) used below.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(__linux__)
/* glibc declares ucontext_t only here, never via <signal.h>. */
#include <sys/ucontext.h>
#endif

#include "os/guest_run.h"
#include "os/host_contract.h"
#include "os/backend.h"

#if (defined(__linux__) && defined(__aarch64__)) || \
    (defined(__APPLE__) && defined(__aarch64__))
/* Lane A2 runtime init: install the host preemption/fault handlers once
 * at process startup so a preemption signal (SIGRTMIN+1 on Linux,
 * SIGUSR2 on Darwin) is live instead of killing the translator, with
 * in-flight Soft-TLB sequences rewound via vm64_seq_rewind. Declared
 * locally: the txn/seq helpers stay private to src/vm/vm64.c. */
extern uint64_t vm64_seq_rewind(uint64_t pc, uint64_t seq_start,
    uint64_t host_insn);
/* Live-window rewind (src/vm/vm64.c): scans back at most 6 insns for
 * the fast-path opener and rewinds only inside a live sequence;
 * identity anywhere else, so a stray preempt can never misdirect. */
extern uint64_t vm64_seq_rewind_live(uint64_t pc);
extern int vm64_stxn_register_self(void);

static uint64_t a2_host_pc(void *host_ucontext)
{
#if defined(__linux__) && defined(__aarch64__)
    ucontext_t *c = (ucontext_t *)host_ucontext;
    return (c != NULL) ? (uint64_t)c->uc_mcontext.pc : UINT64_C(0);
#elif defined(__APPLE__) && defined(__aarch64__)
    ucontext_t *c = (ucontext_t *)host_ucontext;
    return (c != NULL) ? (uint64_t)c->uc_mcontext->__ss.__pc :
        UINT64_C(0);
#else
    (void)host_ucontext;
    return UINT64_C(0);
#endif
}

static void a2_on_sync_fault(const rt_host_sync_fault_t *fault)
{
    /* No host-fault recovery on this engine: restore the default
     * disposition and re-raise so a genuine host SIGSEGV/SIGBUS
     * crashes exactly as it did before the handlers were installed. */
    int sig = (fault != NULL) ? fault->linux_si_signo : SIGSEGV;
    (void)signal(sig, SIG_DFL);
    (void)raise(sig);
}

static void a2_on_async_sig(const rt_host_async_siginfo_t *sig)
{
    /* No async guest delivery yet (SIGCHLD/SIGALRM stay swallowed, as
     * with a NULL callback); the hook exists so the install is
     * explicit and a delivery path can land here later. */
    (void)sig;
}

static void a2_on_preempt(void *host_ucontext)
{
    uint64_t pc = a2_host_pc(host_ucontext);
    uint64_t rewound = vm64_seq_rewind_live(pc);
    if (rewound != pc && host_ucontext != NULL) {
#if defined(__linux__) && defined(__aarch64__)
        ((ucontext_t *)host_ucontext)->uc_mcontext.pc = rewound;
#elif defined(__APPLE__) && defined(__aarch64__)
        ((ucontext_t *)host_ucontext)->uc_mcontext->__ss.__pc = rewound;
#endif
    }
}
#endif

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
#if (defined(__linux__) && defined(__aarch64__)) || \
    (defined(__APPLE__) && defined(__aarch64__))
    /* Lane A2: preemption must be live before any guest code runs. */
    if (rt_host_install_signal_handlers(a2_on_sync_fault, a2_on_async_sig,
            a2_on_preempt) != 0) {
        (void)fprintf(stderr,
            "sparc64rt: cannot install signal handlers\n");
        return 1;
    }
    /* RC-U12: register this thread in the vm64 worker table so Step-2
     * preemption has a live addressee (numeric tid on Linux,
     * worker-table key on Darwin). S64-R3-5: exhaustion here is
     * fatal (running the main thread unregistered would miss
     * preemption). */
    if (vm64_stxn_register_self() != 0) {
        (void)fprintf(stderr, "sparc64rt: worker table exhausted\n");
        return 1;
    }
#endif
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
