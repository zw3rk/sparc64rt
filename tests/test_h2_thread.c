/*
 * tests/test_h2_thread.c -- Phase 7 libc-test pthread/semaphore battery
 * (lane H2).
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Static-glibc + -pthread SPARC64 guest exercising threads, TLS,
 * mutexes, condition variables, and unnamed semaphores. Stdout is
 * fully deterministic (fixed strings and numbers only; no addresses,
 * pids, or timings). Exit status is 0 iff every check passed.
 *
 * Multi-threaded by design: verified by oracle vs --interp vs --dbt
 * output parity. No --difftest leg (the lockstep harness is
 * single-threaded by design: clone returns ENOSYS under engine 2,
 * grounded in tests/test_p5_dyn.c and tests/parity_suite.sh).
 *
 * Build (debian:stable-slim container, from the worktree root):
 *   docker exec sparc64rt-h2 sh -c 'cd /w && mkdir -p _build \
 *     && sparc64-linux-gnu-gcc -static -pthread -O2 \
 *       -o _build/guest_h2_thread tests/test_h2_thread.c'
 * Oracle: qemu-sparc64 ./_build/guest_h2_thread
 *
 * Expected stdout:
 *   TRYLOCK-OK
 *   MUTEX-OK count=2000
 *   TLS-OK
 *   COND-OK
 *   SEM-OK
 *   BARRIER-OK
 *   H2-THREAD-PASS
 */

#define _GNU_SOURCE

#include <pthread.h>
#include <semaphore.h>
#include <stdio.h>

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

#define H2_NTHREADS 4
#define H2_NLOOPS 500

static pthread_mutex_t count_mutex = PTHREAD_MUTEX_INITIALIZER;
static long count_total = 0L;
static __thread int tls_mark = 0;
static int tls_seen[H2_NTHREADS] = { 0, 0, 0, 0 };

static void *count_worker(void *arg)
{
    long id = (long)arg;
    int i;
    tls_mark = (int)id + 1;
    for (i = 0; i < H2_NLOOPS; i++) {
        (void)pthread_mutex_lock(&count_mutex);
        count_total++;
        (void)pthread_mutex_unlock(&count_mutex);
    }
    tls_seen[id] = tls_mark;
    return NULL;
}

/* Condition handoff: one worker sets flag + signals, main waits. */
static pthread_mutex_t cond_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cond_var = PTHREAD_COND_INITIALIZER;
static int cond_flag = 0;

static void *cond_worker(void *arg)
{
    (void)arg;
    (void)pthread_mutex_lock(&cond_mutex);
    cond_flag = 1;
    (void)pthread_cond_signal(&cond_var);
    (void)pthread_mutex_unlock(&cond_mutex);
    return NULL;
}

/* Semaphore handoff: worker posts 3, main waits 3. */
static sem_t sem_handle;

static void *sem_worker(void *arg)
{
    (void)arg;
    (void)sem_post(&sem_handle);
    (void)sem_post(&sem_handle);
    (void)sem_post(&sem_handle);
    return NULL;
}

/* Barrier rendezvous between two workers. */
static pthread_barrier_t rendezvous;
static int barrier_after[H2_NTHREADS] = { 0, 0, 0, 0 };

static void *barrier_worker(void *arg)
{
    long id = (long)arg;
    int rc = pthread_barrier_wait(&rendezvous);
    barrier_after[id] = (rc == 0 || rc == PTHREAD_BARRIER_SERIAL_THREAD) ?
        1 : 0;
    return NULL;
}

int main(void)
{
    pthread_t th[H2_NTHREADS];
    pthread_t single;
    pthread_t sem_th;
    pthread_t bar_th[2];
    int created[H2_NTHREADS] = { 0, 0, 0, 0 };
    int i;
    int sem_val = -1;
    int ok;

    /* trylock on a free mutex. */
    ok = (pthread_mutex_trylock(&count_mutex) == 0);
    if (ok) {
        ok = (pthread_mutex_unlock(&count_mutex) == 0);
    }
    check("TRYLOCK", ok);

    /* Mutex counter + per-thread TLS. */
    for (i = 0; i < H2_NTHREADS; i++) {
        if (pthread_create(&th[i], NULL, count_worker,
                (void *)(long)i) == 0) {
            created[i] = 1;
        }
    }
    for (i = 0; i < H2_NTHREADS; i++) {
        if (created[i] && pthread_join(th[i], NULL) != 0) {
            created[i] = 0;
        }
    }
    ok = created[0] && created[1] && created[2] && created[3] &&
        count_total == (long)(H2_NTHREADS * H2_NLOOPS) &&
        tls_seen[0] == 1 && tls_seen[1] == 2 && tls_seen[2] == 3 &&
        tls_seen[3] == 4;
    if (ok) {
        (void)printf("MUTEX-OK count=%ld\n", count_total);
    } else {
        (void)printf("MUTEX-FAIL\n");
        failures++;
    }
    check("TLS", tls_seen[0] == 1 && tls_seen[1] == 2 &&
        tls_seen[2] == 3 && tls_seen[3] == 4);

    /* Condition variable handoff. */
    if (pthread_create(&single, NULL, cond_worker, NULL) != 0) {
        check("COND", 0);
    } else {
        (void)pthread_mutex_lock(&cond_mutex);
        while (cond_flag == 0) {
            (void)pthread_cond_wait(&cond_var, &cond_mutex);
        }
        (void)pthread_mutex_unlock(&cond_mutex);
        check("COND", cond_flag == 1 &&
            pthread_join(single, NULL) == 0);
    }

    /* Unnamed semaphore handoff. */
    if (sem_init(&sem_handle, 0, 0U) != 0) {
        check("SEM", 0);
    } else if (pthread_create(&sem_th, NULL, sem_worker, NULL) != 0) {
        check("SEM", 0);
        (void)sem_destroy(&sem_handle);
    } else {
        ok = (sem_wait(&sem_handle) == 0) &&
            (sem_wait(&sem_handle) == 0) &&
            (sem_wait(&sem_handle) == 0) &&
            (pthread_join(sem_th, NULL) == 0) &&
            (sem_getvalue(&sem_handle, &sem_val) == 0) &&
            (sem_val == 0);
        check("SEM", ok);
        (void)sem_destroy(&sem_handle);
    }

    /* Two-worker barrier rendezvous. */
    if (pthread_barrier_init(&rendezvous, NULL, 2U) != 0) {
        check("BARRIER", 0);
    } else if (pthread_create(&bar_th[0], NULL, barrier_worker,
            (void *)0L) != 0 ||
        pthread_create(&bar_th[1], NULL, barrier_worker,
            (void *)1L) != 0) {
        check("BARRIER", 0);
    } else {
        ok = (pthread_join(bar_th[0], NULL) == 0) &&
            (pthread_join(bar_th[1], NULL) == 0) &&
            barrier_after[0] == 1 && barrier_after[1] == 1;
        check("BARRIER", ok);
        (void)pthread_barrier_destroy(&rendezvous);
    }

    if (failures == 0) {
        (void)printf("H2-THREAD-PASS\n");
    } else {
        (void)printf("H2-THREAD-FAIL n=%d\n", failures);
    }
    return (failures != 0) ? 1 : 0;
}
