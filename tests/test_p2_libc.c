/*
 * tests/test_p2_libc.c -- Phase 2 static-glibc guest (lane L2d).
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Static-glibc SPARC64 guest exercising the Phase 2 extended syscall
 * layer under both engines (--interp oracle first, then --difftest):
 * hello, printf formatting, malloc/free, qsort, and file
 * fopen/fread/fwrite. Stdout is fully deterministic (fixed strings and
 * numbers only; no addresses, pids, or timings). Exit status is 0 iff
 * every check passed.
 *
 * Build (oracle image sparc32rt-oracle:latest via docker --context
 * default, from the worktree root):
 *   docker --context default run --rm --platform linux/amd64 \
 *     -v "$PWD:/w" -w /w sparc32rt-oracle:latest sh -c \
 *     'sparc64-linux-gnu-gcc -static -O2 -o /tmp/test_p2_libc tests/test_p2_libc.c \
 *     && qemu-sparc64 /tmp/test_p2_libc'
 * NOTE (host quirk, see tests/test_p1_isa.c): where `--platform` forces
 * a failed registry pull, omit it (and `--context default`).
 *
 * Golden stdout (qemu-sparc64 oracle):
 *   hello sparc64
 *   dec=42 hex=2a str=rt char=Z
 *   malloc-sum=36
 *   sorted=1,2,3,4,5,6,7,8
 *   file=sparc64-libc-file
 *   p2-libc: PASS
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int cmp_int(const void *a, const void *b)
{
    int x = *(const int *)a;
    int y = *(const int *)b;
    return (x > y) - (x < y);
}

int main(void)
{
    int *vec;
    int keys[8] = { 5, 1, 7, 3, 8, 2, 6, 4 };
    int sum = 0;
    int i;
    FILE *f;
    char buf[64];
    size_t got;
    static const char msg[] = "sparc64-libc-file\n";

    (void)printf("hello sparc64\n");
    (void)printf("dec=%d hex=%x str=%s char=%c\n", 42, 42, "rt", 'Z');

    /* malloc/free: fixed contents, checksum only (no addresses). */
    vec = (int *)malloc(8U * sizeof(*vec));
    if (vec == NULL) {
        (void)printf("malloc: FAIL\n");
        return 1;
    }
    for (i = 0; i < 8; i++) {
        vec[i] = 8 - i;
    }
    for (i = 0; i < 8; i++) {
        sum += vec[i];
    }
    if (sum != 36) {
        (void)printf("malloc-sum=%d: FAIL\n", sum);
        free(vec);
        return 1;
    }
    (void)printf("malloc-sum=%d\n", sum);
    free(vec);

    /* qsort: fixed input, deterministic ascending output. */
    qsort(keys, 8U, sizeof(keys[0]), cmp_int);
    for (i = 0; i < 8; i++) {
        if (keys[i] != i + 1) {
            (void)printf("sorted: FAIL\n");
            return 1;
        }
    }
    (void)printf("sorted=");
    for (i = 0; i < 8; i++) {
        (void)printf("%s%d", (i != 0) ? "," : "", keys[i]);
    }
    (void)printf("\n");

    /* fopen/fread/fwrite round-trip through a temp file. */
    f = fopen("/tmp/p2_libc_t.txt", "w");
    if (f == NULL) {
        (void)printf("fopen-write: FAIL\n");
        return 1;
    }
    if (fwrite(msg, 1U, sizeof(msg) - 1U, f) != sizeof(msg) - 1U) {
        (void)printf("fwrite: FAIL\n");
        (void)fclose(f);
        return 1;
    }
    if (fclose(f) != 0) {
        (void)printf("fclose-write: FAIL\n");
        return 1;
    }
    f = fopen("/tmp/p2_libc_t.txt", "r");
    if (f == NULL) {
        (void)printf("fopen-read: FAIL\n");
        return 1;
    }
    memset(buf, 0, sizeof(buf));
    got = fread(buf, 1U, sizeof(buf) - 1U, f);
    if (fclose(f) != 0) {
        (void)printf("fclose-read: FAIL\n");
        return 1;
    }
    if (got != sizeof(msg) - 1U || memcmp(buf, msg, got) != 0) {
        (void)printf("file: FAIL\n");
        (void)remove("/tmp/p2_libc_t.txt");
        return 1;
    }
    (void)printf("file=%s", buf);
    (void)remove("/tmp/p2_libc_t.txt");

    (void)printf("p2-libc: PASS\n");
    return 0;
}
