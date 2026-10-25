/*
 * tests/test_h2_process.c -- Phase 7 LTP-subset process battery (lane H2):
 * fork, vfork, wait, waitid, execve, pipe throughput.
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Static-glibc SPARC64 guest covering the translator-claimed process
 * syscalls, scoped from src/os/syscall_nr.h and the dispatch in
 * src/os/proc.c (via src/os/syscalls_min.c): fork, vfork, execve,
 * wait4, waitid, exit, exit_group, pipe. The guest re-executes itself
 * with a marker argv (argv[0] must resolve, so run from the worktree
 * root with a relative or absolute path). Stdout is fully
 * deterministic (fixed strings and numbers only; no addresses, pids,
 * or timings). Exit status is 0 iff every check passed.
 *
 * Forking by design: verified by oracle vs --interp vs --dbt output
 * parity. No --difftest leg (the lockstep harness is single-threaded
 * by design: clone returns ENOSYS under engine 2, grounded in
 * tests/test_p5_dyn.c and tests/parity_suite.sh).
 *
 * Known oracle gap (grounded in tests/test_p4_threads_signals.c and
 * docs/rc6-parity.md): qemu-sparc64 rejects every guest execve with
 * ENOEXEC, so the oracle shows EXEC-FAIL/WAIT-FAIL and H2-PROCESS-FAIL
 * n=1 while the engines implement execve. The runner records this as
 * GAP G2, not as a failure.
 *
 * Build (debian:stable-slim container, from the worktree root):
 *   docker exec sparc64rt-h2 sh -c 'cd /w && mkdir -p _build \
 *     && sparc64-linux-gnu-gcc -static -O2 \
 *       -o _build/guest_h2_process tests/test_h2_process.c'
 * Oracle: qemu-sparc64 ./_build/guest_h2_process
 *
 * Expected stdout (engines):
 *   PIPE-THROUGHPUT-OK bytes=262144 sum=33423360
 *   FORK-OK status=11
 *   VFORK-OK status=12
 *   WAITID-OK status=13 code=1
 *   WNOHANG-OK status=14
 *   EXEC-OK
 *   WAIT-OK status=21
 *   H2-PROCESS-PASS
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;

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

/* 256 KiB checksummed round-trip through a pipe (child writes). */
static void test_pipe_throughput(void)
{
    int fds[2] = { -1, -1 };
    unsigned long expect = 0UL;
    unsigned long sum = 0UL;
    unsigned long i;
    unsigned char chunk[4096];
    long left;
    ssize_t n;
    pid_t p;
    int st = 0;

    for (i = 0UL; i < sizeof(chunk); i++) {
        chunk[i] = (unsigned char)(i & 0xffUL);
    }
    for (i = 0UL; i < 262144UL; i++) {
        expect += (unsigned char)(i & 0xffUL);
    }
    if (pipe(fds) != 0) {
        check("PIPE-THROUGHPUT", 0);
        return;
    }
    (void)fflush(NULL);
    p = fork();
    if (p < 0) {
        check("PIPE-THROUGHPUT", 0);
        (void)close(fds[0]);
        (void)close(fds[1]);
        return;
    }
    if (p == 0) {
        (void)close(fds[0]);
        left = 262144L;
        while (left > 0L) {
            long want = (left > 4096L) ? 4096L : left;
            n = write(fds[1], chunk, (size_t)want);
            if (n <= 0) {
                _exit(99);
            }
            left -= (long)n;
        }
        (void)close(fds[1]);
        _exit(0);
    }
    (void)close(fds[1]);
    left = 262144L;
    while (left > 0L) {
        n = read(fds[0], chunk, sizeof(chunk));
        if (n <= 0) {
            break;
        }
        for (i = 0UL; i < (unsigned long)n; i++) {
            sum += chunk[i];
        }
        left -= (long)n;
    }
    (void)close(fds[0]);
    if (waitpid(p, &st, 0) != p || !WIFEXITED(st) ||
        WEXITSTATUS(st) != 0 || left != 0L || sum != expect) {
        check("PIPE-THROUGHPUT", 0);
        return;
    }
    (void)printf("PIPE-THROUGHPUT-OK bytes=262144 sum=%lu\n", sum);
}

static void test_fork_wait(const char *tag, int want, int use_vfork)
{
    pid_t p;
    int st = 0;
    pid_t w = (pid_t)-1;
    (void)fflush(NULL);
    p = use_vfork ? vfork() : fork();
    if (p < 0) {
        check(tag, 0);
        return;
    }
    if (p == 0) {
        _exit(want);
    }
    w = waitpid(p, &st, 0);
    if (w == p && WIFEXITED(st) && WEXITSTATUS(st) == want) {
        (void)printf("%s-OK status=%d\n", tag, WEXITSTATUS(st));
    } else {
        (void)printf("%s-FAIL\n", tag);
        failures++;
    }
}

static void test_waitid(void)
{
    pid_t p;
    siginfo_t si;
    int r;
    (void)fflush(NULL);
    p = fork();
    if (p < 0) {
        check("WAITID", 0);
        return;
    }
    if (p == 0) {
        _exit(13);
    }
    memset(&si, 0, sizeof(si));
    r = waitid(P_PID, p, &si, WEXITED);
    if (r == 0 && si.si_pid == p && si.si_status == 13 &&
        si.si_code == CLD_EXITED) {
        (void)printf("WAITID-OK status=%d code=%d\n", si.si_status,
            si.si_code);
    } else {
        (void)printf("WAITID-FAIL\n");
        failures++;
    }
}

/* WNOHANG reap: child exits at once, parent spins (bounded, no sleep)
 * until the reap succeeds; the outcome is deterministic. */
static void test_wnohang(void)
{
    pid_t p;
    int st = 0;
    pid_t w = (pid_t)-1;
    long spins = 0L;
    (void)fflush(NULL);
    p = fork();
    if (p < 0) {
        check("WNOHANG", 0);
        return;
    }
    if (p == 0) {
        _exit(14);
    }
    while (spins < 1000000L) {
        w = waitpid(p, &st, WNOHANG);
        if (w == p) {
            break;
        }
        if (w != 0) {
            break;
        }
        spins++;
    }
    if (w == p && WIFEXITED(st) && WEXITSTATUS(st) == 14) {
        (void)printf("WNOHANG-OK status=%d\n", WEXITSTATUS(st));
    } else {
        (void)printf("WNOHANG-FAIL\n");
        failures++;
    }
}

static void test_exec_wait(const char *prog)
{
    pid_t p;
    int st = 0;
    pid_t w = (pid_t)-1;
    char *args[3];
    (void)fflush(NULL);
    p = fork();
    if (p < 0) {
        check("WAIT", 0);
        return;
    }
    if (p == 0) {
        args[0] = (char *)prog;
        args[1] = "--h2-childexec";
        args[2] = NULL;
        (void)execve(prog, args, environ);
        _exit(127);
    }
    w = waitpid(p, &st, 0);
    if (w == p && WIFEXITED(st) && WEXITSTATUS(st) == 21) {
        (void)printf("WAIT-OK status=%d\n", WEXITSTATUS(st));
    } else {
        (void)printf("WAIT-FAIL\n");
        failures++;
    }
}

int main(int argc, char **argv)
{
    if (argc > 1 && strcmp(argv[1], "--h2-childexec") == 0) {
        (void)printf("EXEC-OK\n");
        return 21;
    }
    test_pipe_throughput();
    test_fork_wait("FORK", 11, 0);
    test_fork_wait("VFORK", 12, 1);
    test_waitid();
    test_wnohang();
    test_exec_wait(argv[0]);
    if (failures == 0) {
        (void)printf("H2-PROCESS-PASS\n");
    } else {
        (void)printf("H2-PROCESS-FAIL n=%d\n", failures);
    }
    return (failures != 0) ? 1 : 0;
}
