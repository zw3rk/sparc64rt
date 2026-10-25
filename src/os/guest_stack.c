/*
 * src/os/guest_stack.c — _start stack synthesis (Phase 1, L1c; split RC2)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Synthesizes the initial SPARC64 Linux stack with the 2047 bias (E01):
 * unbiased frame F is 16-byte aligned, %sp = F - 2047, [F,F+128) is
 * the zeroed rwindow_64 area, argc sits at [F+128]; every multi-byte
 * field is big-endian. Split from guest_run.c to hold the line limit.
 */

#define _POSIX_C_SOURCE 200809L
/* Needs _GNU_SOURCE: musl hides syscall(2) under -std=c11. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#include "core/cpu.h"
#include "os/guest_run_priv.h"
#include "rt64/memory/space.h"

/* ---- Stack ABI constants (SPARC Linux, arch/sparc) ---------------------- */
#define GUEST_STACK_TOP UINT64_C(0x7ffffffff000)
#define GUEST_STACK_MAX UINT64_C(0x800000)
#define GUEST_MAX_ENVC 512U
#define GUEST_MAX_STRING_BYTES ((uint64_t)131072)

/* AT_* keys carried in the initial stack (subset the static guest needs). */
#define GUEST_AT_NULL 0U
#define GUEST_AT_PHDR 3U
#define GUEST_AT_PHENT 4U
#define GUEST_AT_PHNUM 5U
#define GUEST_AT_PAGESZ 6U
#define GUEST_AT_ENTRY 9U
#define GUEST_AT_UID 11U
#define GUEST_AT_EUID 12U
#define GUEST_AT_GID 13U
#define GUEST_AT_EGID 14U
#define GUEST_AT_RANDOM 25U
#define GUEST_AT_RANDOM_BYTES 16U
#define GUEST_AT_EXECFN 31U

/* AT_* keys carried in the initial stack, in auxv order. */
static const unsigned aux_keys[11] = {
    GUEST_AT_PHDR, GUEST_AT_PHENT, GUEST_AT_PHNUM, GUEST_AT_PAGESZ,
    GUEST_AT_ENTRY, GUEST_AT_UID, GUEST_AT_EUID, GUEST_AT_GID,
    GUEST_AT_EGID, GUEST_AT_EXECFN, GUEST_AT_RANDOM,
};

extern char **environ;

static uint64_t align_down(uint64_t v, uint64_t a)
{
    return v & ~(a - UINT64_C(1));
}

static void wr64be(uint8_t *p, uint64_t v)
{
    p[0] = (uint8_t)(v >> 56);
    p[1] = (uint8_t)(v >> 48);
    p[2] = (uint8_t)(v >> 40);
    p[3] = (uint8_t)(v >> 32);
    p[4] = (uint8_t)(v >> 24);
    p[5] = (uint8_t)(v >> 16);
    p[6] = (uint8_t)(v >> 8);
    p[7] = (uint8_t)v;
}

/* ---- _start stack synthesis (E01) ---------------------------------------- */
uint64_t count_strings(char **vec, uint64_t max)
{
    uint64_t n = 0;
    if (vec == NULL) {
        return 0;
    }
    while (n < max && vec[n] != NULL) {
        n++;
    }
    return n;
}

static int string_bytes(char **vec, uint64_t n, uint64_t *total)
{
    uint64_t sum = 0;
    uint64_t i;
    for (i = 0; i < n; i++) {
        size_t len = strlen(vec[i]);
        if (len > (size_t)65536 ||
            sum > GUEST_MAX_STRING_BYTES - (uint64_t)len - UINT64_C(1)) {
            return -E2BIG;
        }
        sum += (uint64_t)len + UINT64_C(1);
    }
    *total = sum;
    return 0;
}

/* Push one NUL-terminated string below cursor; returns its guest VA. */
static int push_string(guest_state_t *g, uint64_t *cursor, const char *s,
                       uint64_t *addr)
{
    size_t len = strlen(s) + 1;
    if (*cursor < (uint64_t)len) {
        return -E2BIG;
    }
    *cursor -= (uint64_t)len;
    *addr = *cursor;
    return sparc64_space_write_initial(&g->space, *addr, s, len) ? 0 :
                                                                   -ENOMEM;
}

static int put64(guest_state_t *g, uint64_t *cursor, uint64_t v)
{
    uint8_t buf[8];
    wr64be(buf, v);
    if (!sparc64_space_write_initial(&g->space, *cursor, buf, sizeof(buf))) {
        return -ENOMEM;
    }
    *cursor += 8U;
    return 0;
}

/* Push every string in vec below cursor, recording guest VAs. */
static int push_vec(guest_state_t *g, uint64_t *cursor, char **vec,
                    uint64_t n, uint64_t *addrs)
{
    uint64_t i;
    for (i = 0; i < n; i++) {
        if (push_string(g, cursor, vec[i], &addrs[i]) != 0) {
            return -LOAD_NOMEM;
        }
    }
    return LOAD_OK;
}

/* Write a vector of big-endian words at the ascending cursor. */
static int put_vec(guest_state_t *g, uint64_t *cursor, const uint64_t *v,
                   uint64_t n)
{
    uint64_t i;
    for (i = 0; i < n; i++) {
        if (put64(g, cursor, v[i]) != 0) {
            return -LOAD_NOMEM;
        }
    }
    return LOAD_OK;
}

/* Lay out argc/argv/envp/auxv/strings; returns the biased %sp. Stack
 * pages are mapped READ|WRITE; every multi-byte field is big-endian. */
int build_stack(guest_state_t *g, uint64_t phdr_va, uint64_t entry,
                uint64_t phnum, uint64_t phent, char **argv, uint64_t argc,
                uint64_t *sp_out)
{
    uint64_t envc = count_strings(environ, GUEST_MAX_ENVC);
    uint64_t argv_bytes = 0, env_bytes = 0, str_size, str_base;
    uint64_t cursor, frame, stack_base, stack_size, execfn = 0, words, at, i;
    uint64_t argv_addr[GUEST_MAX_ARGC], env_addr[GUEST_MAX_ENVC];
    uint64_t auxv[24], vals[11];
    uint64_t rnd_addr = UINT64_C(0);
    uint8_t zeros[128];
    uint8_t rnd[GUEST_AT_RANDOM_BYTES];
    if (argc > (uint64_t)GUEST_MAX_ARGC ||
        envc > (uint64_t)GUEST_MAX_ENVC) {
        return -E2BIG;
    }
    if (string_bytes(argv, argc, &argv_bytes) != 0 ||
        string_bytes(environ, envc, &env_bytes) != 0) {
        return -E2BIG;
    }
    str_size = argv_bytes + env_bytes + (uint64_t)GUEST_AT_RANDOM_BYTES;
    /* Reserve: argc + argv+NULL + envp+NULL + 12 auxv pairs. */
    words = UINT64_C(1) + (argc + UINT64_C(1)) + (envc + UINT64_C(1)) +
        UINT64_C(24);
    str_base = GUEST_STACK_TOP - str_size;
    if (str_size > GUEST_MAX_STRING_BYTES || str_size >= GUEST_STACK_TOP ||
        str_base < words * UINT64_C(8) + UINT64_C(128)) {
        return -E2BIG;
    }
    frame = align_down(str_base - words * UINT64_C(8) - UINT64_C(128), 16U);
    stack_base = align_down(frame, GUEST_PAGE_SIZE);
    stack_size = GUEST_STACK_TOP - stack_base;
    if (stack_size == 0U || stack_size > GUEST_STACK_MAX) {
        return -ENOMEM;
    }
    if (!sparc64_space_map(&g->space, stack_base, stack_size,
                           SPARC64_MEM_READ | SPARC64_MEM_WRITE, false)) {
        return -ENOMEM;
    }
    /* AT_RANDOM: 16 unpredictable bytes at the top of the stack; static
     * glibc dereferences them unconditionally during early startup. */
#if defined(__linux__) && defined(SYS_getrandom)
    {
        size_t done = 0;
        while (done < sizeof(rnd)) {
            long rc = syscall(SYS_getrandom, rnd + done,
                sizeof(rnd) - done, 0U);
            if (rc <= 0L) {
                break;
            }
            done += (size_t)rc;
        }
        if (done != sizeof(rnd)) {
            memset(rnd, 0, sizeof(rnd));
        }
    }
#else
    memset(rnd, 0, sizeof(rnd));
#endif
    rnd_addr = GUEST_STACK_TOP - (uint64_t)GUEST_AT_RANDOM_BYTES;
    if (!sparc64_space_write_initial(&g->space, rnd_addr, rnd,
        sizeof(rnd))) {
        return -ENOMEM;
    }
    cursor = rnd_addr;
    if (push_vec(g, &cursor, argv, argc, argv_addr) != 0 ||
        push_vec(g, &cursor, environ, envc, env_addr) != 0) {
        return -ENOMEM;
    }
    execfn = (argc != 0U) ? argv_addr[0] : 0U;
    memset(zeros, 0, sizeof(zeros)); /* Zero the rwindow_64 [F, F+128). */
    if (!sparc64_space_write_initial(&g->space, frame, zeros,
                                     sizeof(zeros))) {
        return -ENOMEM;
    }
    vals[0] = phdr_va; vals[1] = phent; vals[2] = phnum;
    vals[3] = GUEST_PAGE_SIZE; vals[4] = entry;
    vals[5] = (uint64_t)getuid(); vals[6] = (uint64_t)geteuid();
    vals[7] = (uint64_t)getgid(); vals[8] = (uint64_t)getegid();
    vals[9] = execfn; vals[10] = rnd_addr;
    for (i = 0; i < 11U; i++) {
        auxv[2U * i] = aux_keys[i];
        auxv[2U * i + 1U] = vals[i];
    }
    at = frame + UINT64_C(128);
    if (put64(g, &at, argc) != 0 ||
        put_vec(g, &at, argv_addr, argc) != 0 ||
        put64(g, &at, 0U) != 0 ||
        put_vec(g, &at, env_addr, envc) != 0 ||
        put64(g, &at, 0U) != 0 ||
        put_vec(g, &at, auxv, 22U) != 0 ||
        put64(g, &at, GUEST_AT_NULL) != 0 ||
        put64(g, &at, 0U) != 0) {
        return -ENOMEM;
    }
    *sp_out = frame - SPARC64_STACK_BIAS;
    return 0;
}
