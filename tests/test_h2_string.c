/*
 * tests/test_h2_string.c -- Phase 7 libc-test string battery (lane H2).
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Static-glibc SPARC64 guest exercising the libc string layer (pure
 * userspace: memcpy, memmove, memset, memcmp, memchr, strlen, strcpy,
 * strncpy, strcat, strncat, strcmp, strncmp, strchr, strrchr, strstr,
 * strtok, strerror). Stdout is fully deterministic (fixed strings and
 * numbers only; no addresses, pids, or timings). Exit status is 0 iff
 * every check passed.
 *
 * Build (debian:stable-slim container, from the worktree root):
 *   docker exec sparc64rt-h2 sh -c 'cd /w && mkdir -p _build \
 *     && sparc64-linux-gnu-gcc -static -O2 -o _build/guest_h2_string \
 *       tests/test_h2_string.c'
 * Oracle: qemu-sparc64 ./_build/guest_h2_string
 *
 * Expected stdout:
 *   MEMCPY-OK
 *   MEMMOVE-OK
 *   MEMSET-OK
 *   MEMCMP-OK
 *   MEMCHR-OK
 *   STRLEN-OK
 *   STRCPY-OK
 *   STRNCPY-OK
 *   STRCAT-OK
 *   STRNCMP-OK
 *   STRCHR-OK
 *   STRRCHR-OK
 *   STRSTR-OK
 *   STRTOK-OK
 *   STRERROR-OK
 *   H2-STRING-PASS
 */

#include <errno.h>
#include <stdio.h>
#include <string.h>

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

int main(void)
{
    char buf[64];
    char buf2[64];
    char tok[64];
    const char *msg;
    char *tokp;
    char *save = NULL;
    int ok_move = 0;
    int ok_tok = 0;

    /* memcpy: exact copy including the NUL. */
    memset(buf, 0x5a, sizeof(buf));
    (void)memcpy(buf, "sparc64rt", 10U);
    check("MEMCPY", memcmp(buf, "sparc64rt", 10U) == 0 &&
        buf[9] == '\0' && buf[10] == 0x5a);

    /* memmove: overlapping forward and backward. */
    (void)memcpy(buf, "abcdefgh", 9U);
    (void)memmove(buf + 2, buf, 4U);
    ok_move = (memcmp(buf, "ababcdgh", 9U) == 0);
    (void)memcpy(buf, "abcdefgh", 9U);
    (void)memmove(buf, buf + 2, 4U);
    check("MEMMOVE", ok_move && memcmp(buf, "cdefefgh", 9U) == 0);

    /* memset/memcmp ordering. */
    memset(buf, 0x41, 16U);
    buf[16] = '\0';
    check("MEMSET", buf[0] == 'A' && buf[15] == 'A' && buf[16] == '\0');
    check("MEMCMP", memcmp("abc", "abd", 3U) < 0 &&
        memcmp("abd", "abc", 3U) > 0 &&
        memcmp("abc", "abc", 3U) == 0);

    /* memchr found / not found. */
    (void)memcpy(buf, "hello world", 12U);
    check("MEMCHR", memchr(buf, 'w', 11U) == buf + 6 &&
        memchr(buf, 'z', 11U) == NULL);

    /* strlen incl. empty. */
    check("STRLEN", strlen("sparc64") == 7U && strlen("") == 0U);

    /* strcpy/strncpy incl. NUL padding. */
    (void)strcpy(buf, "rt");
    check("STRCPY", strcmp(buf, "rt") == 0);
    memset(buf2, 0x5a, sizeof(buf2));
    (void)strncpy(buf2, "hi", sizeof(buf2) - 1U);
    check("STRNCPY", buf2[0] == 'h' && buf2[1] == 'i' &&
        buf2[2] == '\0' && buf2[3] == '\0');

    /* strcat/strncat. */
    (void)strcpy(buf, "foo");
    (void)strcat(buf, "bar");
    ok_move = (strcmp(buf, "foobar") == 0);
    (void)strcpy(buf, "foo");
    (void)strncat(buf, "barbaz", 3U);
    check("STRCAT", ok_move && strcmp(buf, "foobar") == 0);

    /* strcmp/strncmp ordering and length limits. */
    check("STRNCMP", strcmp("abc", "abc") == 0 &&
        strcmp("", "") == 0 &&
        strncmp("abcdef", "abcxyz", 3U) == 0 &&
        strncmp("abcdef", "abcxyz", 4U) != 0);

    /* strchr/strrchr. */
    (void)strcpy(buf, "a:b:c");
    check("STRCHR", strchr(buf, ':') == buf + 1 &&
        strchr(buf, 'q') == NULL);
    check("STRRCHR", strrchr(buf, ':') == buf + 3 &&
        strrchr(buf, 'q') == NULL);

    /* strstr. */
    check("STRSTR", strstr("hello world", "world") != NULL &&
        strstr("hello world", "world")[0] == 'w' &&
        strstr("hello", "z") == NULL &&
        strstr("hello", "")[0] == 'h');

    /* strtok_r two tokens plus tail. */
    (void)strcpy(tok, "one:two:three");
    tokp = strtok_r(tok, ":", &save);
    ok_tok = (tokp != NULL && strcmp(tokp, "one") == 0);
    tokp = strtok_r(NULL, ":", &save);
    ok_tok = ok_tok && tokp != NULL && strcmp(tokp, "two") == 0;
    tokp = strtok_r(NULL, ":", &save);
    ok_tok = ok_tok && tokp != NULL && strcmp(tokp, "three") == 0;
    check("STRTOK", ok_tok && strtok_r(NULL, ":", &save) == NULL);

    /* strerror: C-locale message for ENOENT. */
    msg = strerror(ENOENT);
    check("STRERROR", msg != NULL && strstr(msg, "such file") != NULL);

    if (failures == 0) {
        (void)printf("H2-STRING-PASS\n");
    } else {
        (void)printf("H2-STRING-FAIL n=%d\n", failures);
    }
    return (failures != 0) ? 1 : 0;
}
