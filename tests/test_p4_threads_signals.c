/*
 * tests/test_p4_threads_signals.c -- Phase 4 static-glibc guest (lane L4c).
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Static glibc + -pthread SPARC64 guest exercising signals, threads,
 * thread-local storage, and process lifecycle. Deterministic stdout
 * (fixed strings and numbers only; no addresses, pids, fds, or
 * timings). Exit status is 0 iff every check passed.
 *
 * Each section prints OK on success or FAIL on failure and continues,
 * so a partial translator still shows which sections pass. Sections:
 * pipe/dup, fork + execve (self re-exec with a marker argv) + wait4,
 * vfork + wait4, waitid, signals (SIGSEGV/SIGILL fault probes with
 * siglongjmp resume; SIGFPE/SIGUSR1 via kill; sigprocmask ordering;
 * sigaltstack delivery; ucontext is inspected, never printed), main
 * thread __thread + mutex, pthreads + mutex + per-thread TLS.
 *
 * Fault probes resume with siglongjmp (never by rewriting ucontext
 * pc): the oracle leaves the first fault's ucontext pc at 0, so raw
 * pc values are not observable output.
 *
 * Build (oracle image sparc32rt-oracle:latest via docker --context
 * default, from the worktree root):
 *   mkdir -p _build && docker --context default run --rm \
 *     -v "$PWD:/w" -w /w sparc32rt-oracle:latest sh -c \
 *     'sparc64-linux-gnu-gcc -static -pthread -o _build/guest_p4 \
 *     tests/test_p4_threads_signals.c'
 * Golden: qemu-sparc64 _build/guest_p4. Run from the worktree root:
 * the fork test re-executes argv[0], so the invocation path must
 * resolve to the guest (relative or absolute).
 *
 * Oracle limitation (grounded): qemu-sparc64 7.2 rejects every guest
 * execve with ENOEXEC (even a direct self-exec), so the oracle golden
 * shows WAIT-FAIL + P4-FAIL n=1 (exit 1). The EXEC/WAIT leg is
 * verified on the translator instead, where execve is implemented.
 *
 * Difftest limitation (grounded): the lockstep harness is single-
 * threaded by design (clone returns ENOSYS under engine 2), so the
 * THREADS leg shows THREADS-FAIL under --difftest with 0 divergences.
 * Thread behavior is verified by --interp vs --dbt output parity.
 *
 * Expected stdout (working kernel / translator with lanes L4a+L4b):
 *   PIPE-OK
 *   DUP-OK
 *   PIPE2-OK
 *   EXEC-OK
 *   WAIT-OK status=7
 *   VFORK-OK status=4
 *   WAITID-OK status=5 code=1
 *   SIGSEGV-OK code=1
 *   SIGILL-OK code=1
 *   SIGFPE-OK code=0
 *   KILL-OK
 *   MASK-PENDING-OK
 *   MASK-UNBLOCK-OK
 *   ALTSTACK-OK
 *   TLS-OK value=1234
 *   MUTEX-OK
 *   THREADS-OK count=2000
 *   P4-PASS
 */

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <setjmp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/ucontext.h>
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

/* ---- pipe/dup -------------------------------------------------------- */

static void test_pipe_dup(void)
{
    int fds[2] = { -1, -1 };
    int w2 = -1;
    int a[2] = { -1, -1 };
    char buf[8];
    ssize_t n;
    int ok;
    if (pipe(fds) != 0) {
        check("PIPE", 0);
        return;
    }
    if (write(fds[1], "PING", 4U) != 4) {
        check("PIPE", 0);
        return;
    }
    memset(buf, 0, sizeof(buf));
    n = read(fds[0], buf, 4U);
    ok = (n == 4 && memcmp(buf, "PING", 4U) == 0);
    check("PIPE", ok);
    /* dup the write end, drop the original, round-trip through it. */
    w2 = dup(fds[1]);
    (void)close(fds[1]);
    fds[1] = -1;
    if (w2 < 0) {
        check("DUP", 0);
        (void)close(fds[0]);
        return;
    }
    if (write(w2, "PONG", 4U) != 4) {
        check("DUP", 0);
        (void)close(fds[0]);
        (void)close(w2);
        return;
    }
    memset(buf, 0, sizeof(buf));
    n = read(fds[0], buf, 4U);
    ok = (n == 4 && memcmp(buf, "PONG", 4U) == 0);
    (void)close(fds[0]);
    (void)close(w2);
    check("DUP", ok);
    /* dup2 onto a fixed descriptor, then pipe2 with CLOEXEC. */
    if (pipe(a) != 0) {
        check("PIPE2", 0);
        return;
    }
    if (dup2(a[0], 10) != 10) {
        check("PIPE2", 0);
        (void)close(a[0]);
        (void)close(a[1]);
        return;
    }
    (void)close(a[0]);
    (void)close(a[1]);
    (void)close(10);
    if (pipe2(a, O_CLOEXEC) != 0) {
        check("PIPE2", 0);
        return;
    }
    ok = ((fcntl(a[0], F_GETFD) & FD_CLOEXEC) != 0) &&
        ((fcntl(a[1], F_GETFD) & FD_CLOEXEC) != 0);
    (void)close(a[0]);
    (void)close(a[1]);
    check("PIPE2", ok);
}

/* ---- fork + execve + wait4, vfork, waitid ------------------------------ */

static void test_fork_exec_wait(const char *prog)
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
        args[1] = "--p4-childexec";
        args[2] = NULL;
        (void)execve(prog, args, environ);
        _exit(127);
    }
    w = waitpid(p, &st, 0);
    if (w == p && WIFEXITED(st) && WEXITSTATUS(st) == 7) {
        (void)printf("WAIT-OK status=%d\n", WEXITSTATUS(st));
    } else {
        (void)printf("WAIT-FAIL\n");
        failures++;
    }
}

static void test_vfork_wait(void)
{
    pid_t p;
    int st = 0;
    pid_t w = (pid_t)-1;
    (void)fflush(NULL);
    p = vfork();
    if (p < 0) {
        check("VFORK", 0);
        return;
    }
    if (p == 0) {
        _exit(4);
    }
    w = waitpid(p, &st, 0);
    if (w == p && WIFEXITED(st) && WEXITSTATUS(st) == 4) {
        (void)printf("VFORK-OK status=%d\n", WEXITSTATUS(st));
    } else {
        (void)printf("VFORK-FAIL\n");
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
        _exit(5);
    }
    memset(&si, 0, sizeof(si));
    r = waitid(P_PID, p, &si, WEXITED);
    if (r == 0 && si.si_pid == p && si.si_status == 5 &&
        si.si_code == CLD_EXITED) {
        (void)printf("WAITID-OK status=%d code=%d\n", si.si_status,
            si.si_code);
    } else {
        (void)printf("WAITID-FAIL\n");
        failures++;
    }
}

/* ---- signals ---------------------------------------------------------- */

static sigjmp_buf fault_jb;
static volatile int fault_sig = 0;
static volatile int fault_code = 0;
static volatile unsigned long fault_o0 = 0UL;
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

/* Fault handler: record signo/code, glance at the ucontext %o0 slot
 * (inspected, never printed: register values vary), resume via
 * siglongjmp. */
static void fault_handler(int sig, siginfo_t *si, void *u)
{
    ucontext_t *uc = (ucontext_t *)u;
    fault_sig = sig;
    fault_code = si->si_code;
    if (uc != NULL) {
        fault_o0 = (unsigned long)uc->uc_mcontext.mc_gregs[MC_O0];
    }
    (void)fault_o0;
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

static void test_fault_probes(void)
{
    if (install_sa(SIGSEGV, fault_handler, 0) != 0) {
        (void)printf("SIGSEGV-FAIL\n");
        failures++;
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
    if (install_sa(SIGILL, fault_handler, 0) != 0) {
        (void)printf("SIGILL-FAIL\n");
        failures++;
    } else if (sigsetjmp(fault_jb, 1) == 0) {
        /* All-zero word: op 00/op2 000 is reserved on V9. */
        __asm__ volatile (".word 0x00000000");
        (void)printf("SIGILL-FAIL\n");
        failures++;
    } else if (fault_sig == SIGILL && fault_code == 1) {
        (void)printf("SIGILL-OK code=%d\n", fault_code);
    } else {
        (void)printf("SIGILL-FAIL\n");
        failures++;
    }
    /* Integer divide by zero does not trap on SPARC, so SIGFPE and
     * SIGUSR1 arrive via kill (SI_USER, code 0). */
    if (install_sa(SIGFPE, fault_handler, 0) != 0) {
        (void)printf("SIGFPE-FAIL\n");
        failures++;
    } else if (sigsetjmp(fault_jb, 1) == 0) {
        /* kill either fails or delivers synchronously; reaching here
         * means the signal was lost. */
        (void)kill(getpid(), SIGFPE);
        (void)printf("SIGFPE-FAIL\n");
        failures++;
    } else if (fault_sig == SIGFPE && fault_code == 0) {
        (void)printf("SIGFPE-OK code=%d\n", fault_code);
    } else {
        (void)printf("SIGFPE-FAIL\n");
        failures++;
    }
}

static void test_kill_mask_altstack(void)
{
    sigset_t block;
    sigset_t pend;
    stack_t ss;
    stack_t old;
    usr1_seen = 0;
    if (install_sa(SIGUSR1, usr1_handler, 0) != 0) {
        check("KILL", 0);
    } else if (kill(getpid(), SIGUSR1) != 0) {
        check("KILL", 0);
    } else {
        check("KILL", usr1_seen == 1);
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
        if (sigpending(&pend) != 0 ||
            !sigismember(&pend, SIGUSR1)) {
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
    /* Alternate stack delivery. */
    memset(&ss, 0, sizeof(ss));
    ss.ss_sp = malloc((size_t)SIGSTKSZ);
    if (ss.ss_sp == NULL) {
        check("ALTSTACK", 0);
        return;
    }
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
    memset(&old, 0, sizeof(old));
    ss.ss_flags = SS_DISABLE;
    (void)sigaltstack(&ss, NULL);
    free(ss.ss_sp);
}

/* ---- threads ----------------------------------------------------------- */

static __thread int tls_main_value = 0;
static pthread_mutex_t main_mutex = PTHREAD_MUTEX_INITIALIZER;

static void test_tls_mutex(void)
{
    tls_main_value = 1234;
    if (tls_main_value != 1234) {
        (void)printf("TLS-FAIL\n");
        failures++;
    } else {
        (void)printf("TLS-OK value=%d\n", tls_main_value);
    }
    if (pthread_mutex_lock(&main_mutex) != 0) {
        check("MUTEX", 0);
        return;
    }
    if (pthread_mutex_unlock(&main_mutex) != 0) {
        check("MUTEX", 0);
        return;
    }
    check("MUTEX", 1);
}

#define P4_NTHREADS 2
#define P4_NLOOPS 1000

static pthread_mutex_t th_mutex = PTHREAD_MUTEX_INITIALIZER;
static long th_counter = 0L;
static __thread int th_id = 0;
static int th_seen[P4_NTHREADS] = { 0, 0 };

static void *th_worker(void *arg)
{
    long id = (long)arg;
    int i;
    th_id = (int)id + 1;
    for (i = 0; i < P4_NLOOPS; i++) {
        (void)pthread_mutex_lock(&th_mutex);
        th_counter++;
        (void)pthread_mutex_unlock(&th_mutex);
    }
    th_seen[id] = th_id;
    return NULL;
}

static void test_threads(void)
{
    pthread_t th[P4_NTHREADS];
    int created[P4_NTHREADS] = { 0, 0 };
    int i;
    int ok;
    for (i = 0; i < P4_NTHREADS; i++) {
        if (pthread_create(&th[i], NULL, th_worker,
                (void *)(long)i) == 0) {
            created[i] = 1;
        }
    }
    for (i = 0; i < P4_NTHREADS; i++) {
        if (created[i] && pthread_join(th[i], NULL) != 0) {
            created[i] = 0;
        }
    }
    ok = created[0] && created[1] &&
        th_counter == (long)(P4_NTHREADS * P4_NLOOPS) &&
        th_seen[0] == 1 && th_seen[1] == 2;
    if (!ok) {
        (void)printf("THREADS-FAIL\n");
        failures++;
        return;
    }
    (void)printf("THREADS-OK count=%ld\n", th_counter);
}

/* ---- main --------------------------------------------------------------- */

int main(int argc, char **argv)
{
    if (argc > 1 && strcmp(argv[1], "--p4-childexec") == 0) {
        (void)printf("EXEC-OK\n");
        return 7;
    }
    test_pipe_dup();
    test_fork_exec_wait(argv[0]);
    test_vfork_wait();
    test_waitid();
    test_fault_probes();
    test_kill_mask_altstack();
    test_tls_mutex();
    test_threads();
    if (failures == 0) {
        (void)printf("P4-PASS\n");
    } else {
        (void)printf("P4-FAIL n=%d\n", failures);
    }
    return (failures != 0) ? 1 : 0;
}
