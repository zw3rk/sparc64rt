/*
 * tests/test_p5_dyn.c -- Phase 5 dynamic-glibc guest (lane L5b).
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Dynamic glibc + -pthread SPARC64 guest. Links one purpose-built
 * shared object (tests/libp5.c -> _build/libp5.so) and exercises
 * cross-DSO calls, dlopen+dlsym by symbol name, __thread TLS on both
 * sides of the DSO boundary, malloc/printf via the real libc.so.6, a
 * small deterministic auxv sample via getauxval, and a pthread
 * mutex counter. Stdout is fully deterministic (fixed strings and
 * numbers only; no addresses, pids, fds, or timings). Exit status is
 * 0 iff every check passed.
 *
 * Each section prints OK on success or FAIL on failure and continues,
 * so a partial translator still shows which sections pass.
 *
 * Build (debian:stable-slim container, from the worktree root):
 *   docker run --rm --platform linux/arm64 -v "$PWD:/w" -w /w \
 *     debian:stable-slim sh -c 'apt-get update \
 *     && apt-get install -y gcc-sparc64-linux-gnu qemu-user \
 *     && sparc64-linux-gnu-gcc -shared -fPIC -O2 \
 *          -o _build/libp5.so tests/libp5.c \
 *     && sparc64-linux-gnu-gcc -O2 -pthread "-Wl,-rpath,$ORIGIN" \
 *          -o _build/guest_p5_dyn tests/test_p5_dyn.c _build/libp5.so -ldl'
 * Golden (same container):
 *   qemu-sparc64 -L /usr/sparc64-linux-gnu ./_build/guest_p5_dyn
 * (run with the worktree root as cwd so the $ORIGIN rpath and the
 * dlopen("libp5.so") lookup resolve to _build/libp5.so).
 *
 * Engine runs need SPARC64RT_SYSROOT=/usr/sparc64-linux-gnu in the
 * same container (ld.so + libc come from the cross sysroot).
 * Difftest limitation (grounded): the lockstep harness is single-
 * threaded by design (clone returns ENOSYS under engine 2), so the
 * TLS and PTHREAD legs show FAIL under --difftest with 0 divergences;
 * thread behavior is verified by --interp vs --dbt output parity.
 *
 * Expected oracle stdout (golden committed as tests/test_p5_dyn.golden):
 *   DSO-CALL-OK sum=42 prod=42 name=libp5
 *   DLOPEN-OK sym=42
 *   TLS-OK main=7 thread=13
 *   MALLOC-OK sum=36
 *   PRINTF-OK dec=42 hex=2a
 *   AUXV-OK pagesz=8192 clktck=100 secure=0   (SPARC64 uses 8 KiB pages)
 *   PTHREAD-OK count=2000
 *   P5-PASS
 */

#define _GNU_SOURCE

#include <dlfcn.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>
#include <unistd.h>

#include "libp5.h"

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

/* ---- cross-DSO calls (linked at build time) -------------------------- */

static void test_dso_call(void)
{
    int sum = p5_add(40, 2);
    int prod = p5_mul(6, 7);
    const char *name = p5_name();
    int ok = (sum == 42) && (prod == 42) && (name != NULL) &&
        (strcmp(name, "libp5") == 0);
    if (ok) {
        (void)printf("DSO-CALL-OK sum=%d prod=%d name=%s\n", sum, prod,
            name);
    } else {
        (void)printf("DSO-CALL-FAIL\n");
        failures++;
    }
}

/* ---- dlopen + dlsym by name ------------------------------------------ */

static void test_dlopen(void)
{
    void *h;
    int (*sym)(int, int);
    int ok = 0;

    h = dlopen("libp5.so", RTLD_NOW);
    if (h != NULL) {
        *(void **)(&sym) = dlsym(h, "p5_add");
        if (sym != NULL && sym(40, 2) == 42) {
            ok = 1;
        }
        (void)dlclose(h);
    }
    if (ok) {
        (void)printf("DLOPEN-OK sym=42\n");
    } else {
        (void)printf("DLOPEN-FAIL\n");
        failures++;
    }
}

/* ---- __thread TLS across the DSO boundary ---------------------------- */

static __thread int exe_tls_cell = 0;
static int thread_seen = -1;

static void *tls_thread(void *arg)
{
    (void)arg;
    p5_set_tls(13);
    exe_tls_cell = 13;
    if (p5_get_tls() != 13 || exe_tls_cell != 13) {
        return (void *)1;
    }
    thread_seen = p5_get_tls();
    return (void *)0;
}

static void test_tls(void)
{
    pthread_t th;
    void *ret = NULL;
    int ok;

    p5_set_tls(7);
    exe_tls_cell = 7;
    if (p5_get_tls() != 7 || exe_tls_cell != 7) {
        check("TLS", 0);
        return;
    }
    if (pthread_create(&th, NULL, tls_thread, NULL) != 0) {
        check("TLS", 0);
        return;
    }
    (void)pthread_join(th, &ret);
    /* The main thread's cells must be untouched by the child. */
    ok = (ret == NULL) && (thread_seen == 13) && (p5_get_tls() == 7) &&
        (exe_tls_cell == 7);
    if (ok) {
        (void)printf("TLS-OK main=%d thread=%d\n", p5_get_tls(),
            thread_seen);
    } else {
        (void)printf("TLS-FAIL\n");
        failures++;
    }
}

/* ---- malloc/free via libc.so.6 --------------------------------------- */

static void test_malloc(void)
{
    int *vec;
    int sum = 0;
    int i;

    vec = (int *)malloc(8U * sizeof(*vec));
    if (vec == NULL) {
        check("MALLOC", 0);
        return;
    }
    for (i = 0; i < 8; i++) {
        vec[i] = i + 1;
    }
    for (i = 0; i < 8; i++) {
        sum += vec[i];
    }
    free(vec);
    if (sum == 36) {
        (void)printf("MALLOC-OK sum=%d\n", sum);
    } else {
        (void)printf("MALLOC-FAIL\n");
        failures++;
    }
}

/* ---- printf formatting via libc.so.6 (self-checked) ------------------ */

static void test_printf(void)
{
    char buf[64];
    int n;

    n = snprintf(buf, sizeof(buf), "dec=%d hex=%x", 42, 42);
    if (n == 13 && strcmp(buf, "dec=42 hex=2a") == 0) {
        (void)printf("PRINTF-OK %s\n", buf);
    } else {
        (void)printf("PRINTF-FAIL\n");
        failures++;
    }
}

/* ---- deterministic auxv sample --------------------------------------- */

static void test_auxv(void)
{
    unsigned long pagesz = getauxval(AT_PAGESZ);
    unsigned long clktck = getauxval(AT_CLKTCK);
    unsigned long secure = getauxval(AT_SECURE);
    unsigned long uid = getauxval(AT_UID);
    unsigned long euid = getauxval(AT_EUID);
    int ok;

    ok = (pagesz != 0UL) && ((pagesz & (pagesz - 1UL)) == 0UL) &&
        (clktck != 0UL) && (uid == euid);
    if (ok) {
        (void)printf("AUXV-OK pagesz=%lu clktck=%lu secure=%lu\n", pagesz,
            clktck, secure);
    } else {
        (void)printf("AUXV-FAIL\n");
        failures++;
    }
}

/* ---- pthread mutex counter ------------------------------------------- */

static pthread_mutex_t p5_lock = PTHREAD_MUTEX_INITIALIZER;
static int p5_count = 0;

static void *count_thread(void *arg)
{
    int i;
    (void)arg;
    for (i = 0; i < 1000; i++) {
        (void)pthread_mutex_lock(&p5_lock);
        p5_count++;
        (void)pthread_mutex_unlock(&p5_lock);
    }
    return NULL;
}

static void test_pthread(void)
{
    pthread_t t1;
    pthread_t t2;

    if (pthread_create(&t1, NULL, count_thread, NULL) != 0 ||
        pthread_create(&t2, NULL, count_thread, NULL) != 0) {
        check("PTHREAD", 0);
        return;
    }
    (void)pthread_join(t1, NULL);
    (void)pthread_join(t2, NULL);
    if (p5_count == 2000) {
        (void)printf("PTHREAD-OK count=%d\n", p5_count);
    } else {
        (void)printf("PTHREAD-FAIL\n");
        failures++;
    }
}

int main(void)
{
    test_dso_call();
    test_dlopen();
    test_tls();
    test_malloc();
    test_printf();
    test_auxv();
    test_pthread();
    if (failures == 0) {
        (void)printf("P5-PASS\n");
        return 0;
    }
    (void)printf("P5-FAIL n=%d\n", failures);
    return 1;
}
