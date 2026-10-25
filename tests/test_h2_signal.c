/*
 * tests/test_h2_signal.c -- Phase 7 libc-test signal battery (lane H2).
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Static-glibc SPARC64 guest exercising the libc signal layer through
 * sigaction/sigprocmask/sigpending/kill/sigaltstack plus fault probes
 * that resume with siglongjmp. SA_SIGINFO handlers throughout (the
 * translator requires them: plain sa_handler is EINVAL, grounded in
 * docs/rc6-parity.md). Single-threaded: verified by oracle vs
 * --interp vs --dbt output parity plus --difftest with 0 divergences.
 * Stdout is fully deterministic (fixed strings and numbers only; no
 * addresses, pids, or timings). Exit status is 0 iff all checks pass.
 *
 * Build (debian:stable-slim container, from the worktree root):
 *   docker exec sparc64rt-h2 sh -c 'cd /w && mkdir -p _build \
 *     && sparc64-linux-gnu-gcc -static -O2 \
 *       -o _build/guest_h2_signal tests/test_h2_signal.c'
 * Oracle: qemu-sparc64 ./_build/guest_h2_signal
 *
 * Expected stdout:
 *   SIGSEGV-OK code=1
 *   SIGILL-OK code=1
 *   SIGFPE-OK code=0
 *   SIGUSR1-OK
 *   MASK-PENDING-OK
 *   MASK-UNBLOCK-OK
 *   ALTSTACK-OK
 *   QUERY-OK
 *   KILL0-OK
 *   H2-SIGNAL-PASS
 */

#define _GNU_SOURCE

#include <errno.h>
#include <setjmp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

static int failures = 0;

static void check(const char *label, int ok)
{
    if (ok) {
        (void)printf("%s-OK\n", label);
    } else {
        (void)printf("%s-FAIL\n", label);
        failures++;
    }
}

static sigjmp_buf fault_jb;
static volatile int fault_sig = 0;
static volatile int fault_code = 0;
static volatile int usr1_seen = 0;
static volatile int usr2_onstack = 0;

static int install_sa(int sig, void (*h)(int, siginfo_t *, void *),
    int extra_flags)
{
    struct sigaction a;
    memset(&a, 0, sizeof(a));
    a.sa_sigaction = h;
    (void)sigemptyset(&a.sa_mask);
    a.sa_flags = SA_SIGINFO | extra_flags;
    return sigaction(sig, &a, NULL);
}

static void fault_handler(int sig, siginfo_t *si, void *u)
{
    (void)u;
    fault_sig = sig;
    fault_code = si->si_code;
    siglongjmp(fault_jb, 1);
}

static void usr1_handler(int sig, siginfo_t *si, void *u)
{
    (void)sig;
    (void)si;
    (void)u;
    usr1_seen = 1;
}

static void usr2_handler(int sig, siginfo_t *si, void *u)
{
    stack_t oss;
    (void)sig;
    (void)si;
    (void)u;
    memset(&oss, 0, sizeof(oss));
    if (sigaltstack(NULL, &oss) == 0) {
        usr2_onstack = ((oss.ss_flags & SS_ONSTACK) != 0) ? 1 : 0;
    }
}

int main(void)
{
    sigset_t block;
    sigset_t pend;
    stack_t ss;
    struct sigaction query;
    int ok;

    /* SIGSEGV fault probe (SEGV_MAPERR, code 1). */
    if (install_sa(SIGSEGV, fault_handler, 0) != 0) {
        check("SIGSEGV", 0);
    } else if (sigsetjmp(fault_jb, 1) == 0) {
        *(volatile int *)0 = 1;
        (void)printf("SIGSEGV-FAIL\n");
        failures++;
    } else if (fault_sig == SIGSEGV && fault_code == 1) {
        (void)printf("SIGSEGV-OK code=%d\n", fault_code);
    } else {
        (void)printf("SIGSEGV-FAIL\n");
        failures++;
    }

    /* SIGILL fault probe: all-zero V9 word (reserved op). */
    if (install_sa(SIGILL, fault_handler, 0) != 0) {
        check("SIGILL", 0);
    } else if (sigsetjmp(fault_jb, 1) == 0) {
        __asm__ volatile (".word 0x00000000");
        (void)printf("SIGILL-FAIL\n");
        failures++;
    } else if (fault_sig == SIGILL && fault_code == 1) {
        (void)printf("SIGILL-OK code=%d\n", fault_code);
    } else {
        (void)printf("SIGILL-FAIL\n");
        failures++;
    }

    /* SIGFPE via kill: SI_USER, code 0. */
    if (install_sa(SIGFPE, fault_handler, 0) != 0) {
        check("SIGFPE", 0);
    } else if (sigsetjmp(fault_jb, 1) == 0) {
        (void)kill(getpid(), SIGFPE);
        (void)printf("SIGFPE-FAIL\n");
        failures++;
    } else if (fault_sig == SIGFPE && fault_code == 0) {
        (void)printf("SIGFPE-OK code=%d\n", fault_code);
    } else {
        (void)printf("SIGFPE-FAIL\n");
        failures++;
    }

    /* SIGUSR1 delivery + flag. */
    usr1_seen = 0;
    if (install_sa(SIGUSR1, usr1_handler, 0) != 0) {
        check("SIGUSR1", 0);
    } else if (kill(getpid(), SIGUSR1) != 0) {
        check("SIGUSR1", 0);
    } else {
        check("SIGUSR1", usr1_seen == 1);
    }

    /* Block, observe pending, unblock, observe delivery. */
    (void)sigemptyset(&block);
    (void)sigaddset(&block, SIGUSR1);
    usr1_seen = 0;
    if (sigprocmask(SIG_BLOCK, &block, NULL) != 0) {
        check("MASK-PENDING", 0);
        check("MASK-UNBLOCK", 0);
    } else if (kill(getpid(), SIGUSR1) != 0) {
        check("MASK-PENDING", 0);
        check("MASK-UNBLOCK", 0);
        (void)sigprocmask(SIG_UNBLOCK, &block, NULL);
    } else {
        (void)sigemptyset(&pend);
        if (sigpending(&pend) != 0 || !sigismember(&pend, SIGUSR1)) {
            check("MASK-PENDING", 0);
        } else {
            check("MASK-PENDING", 1);
        }
        if (usr1_seen != 0) {
            check("MASK-UNBLOCK", 0);
        } else if (sigprocmask(SIG_UNBLOCK, &block, NULL) != 0) {
            check("MASK-UNBLOCK", 0);
        } else {
            check("MASK-UNBLOCK", usr1_seen == 1);
        }
    }

    /* Alternate-stack delivery. */
    memset(&ss, 0, sizeof(ss));
    ss.ss_sp = malloc((size_t)SIGSTKSZ);
    if (ss.ss_sp == NULL) {
        check("ALTSTACK", 0);
    } else {
        ss.ss_size = (size_t)SIGSTKSZ;
        ss.ss_flags = 0;
        usr2_onstack = 0;
        if (sigaltstack(&ss, NULL) != 0) {
            check("ALTSTACK", 0);
        } else if (install_sa(SIGUSR2, usr2_handler, SA_ONSTACK) != 0) {
            check("ALTSTACK", 0);
        } else if (kill(getpid(), SIGUSR2) != 0) {
            check("ALTSTACK", 0);
        } else {
            check("ALTSTACK", usr2_onstack == 1);
        }
        ss.ss_flags = SS_DISABLE;
        (void)sigaltstack(&ss, NULL);
        free(ss.ss_sp);
    }

    /* sigaction query round-trip: installed handler reads back. */
    memset(&query, 0, sizeof(query));
    ok = (sigaction(SIGUSR1, NULL, &query) == 0) &&
        (query.sa_sigaction == usr1_handler);
    check("QUERY", ok);

    /* kill(pid, 0): existence probe, no delivery (flag unchanged). */
    usr1_seen = 0;
    check("KILL0", kill(getpid(), 0) == 0 && usr1_seen == 0);

    if (failures == 0) {
        (void)printf("H2-SIGNAL-PASS\n");
    } else {
        (void)printf("H2-SIGNAL-FAIL n=%d\n", failures);
    }
    return (failures != 0) ? 1 : 0;
}
