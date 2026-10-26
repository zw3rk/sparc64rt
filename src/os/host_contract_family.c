/*
 * src/os/host_contract_family.c — Wave U1 lightweight Provider-A family
 * control check
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Replaces the heavy rv_family_create-based broker dependency formerly
 * used by sparc64_host_family_verify (src/rt64/runtime/family*.c, ~30k
 * LOC of user-space family MM/file/truncation machinery). The check
 * keeps the exact selftest diagnostics (naming, sequence step, and
 * cleanup verification) while exercising only a minimal Provider-A
 * style control: a per-family directory
 * (/tmp/.sparc64rt-family-<pid>-<seq>-<suffix>) keyed by its live
 * (st_dev, st_ino) identity in a small sparc64_family_control_t record.
 */

#define _POSIX_C_SOURCE 200809L
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "os/host_contract.h"

#include <dirent.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* Minimal Provider-A family-shared inode control record: the canonical
 * identity of one family control directory. Compare fields, never
 * padding. */
typedef struct {
    uint64_t device; /* st_dev of the control directory */
    uint64_t inode; /* st_ino of the control directory */
    unsigned long seq; /* family sequence number embedded in the name */
    char dir[128]; /* NUL-terminated control directory path */
} sparc64_family_control_t;

/* Parse "/tmp/.sparc64rt-family-<pid>-<seq>-<suffix>": pid and seq out,
 * 0 on success. */
static int parse_family_name(const char *dir, long *pid, unsigned long *seq)
{
    static const char prefix[] = "/tmp/.sparc64rt-family-";
    const char *p = dir;
    char *end = NULL;
    long parsed_pid;
    unsigned long parsed_seq;
    size_t i;
    if (strncmp(p, prefix, sizeof(prefix) - 1U) != 0) {
        return -1;
    }
    p += sizeof(prefix) - 1U;
    errno = 0;
    parsed_pid = strtol(p, &end, 10);
    if (errno != 0 || end == p || *end != '-') {
        return -1;
    }
    p = end + 1;
    errno = 0;
    parsed_seq = strtoul(p, &end, 10);
    if (errno != 0 || end == p || *end != '-') {
        return -1;
    }
    p = end + 1;
    for (i = 0; i < 6U; i++) {
        if (p[i] == '\0' || p[i] == '/') {
            return -1;
        }
    }
    if (p[6] != '\0') {
        return -1;
    }
    *pid = parsed_pid;
    *seq = parsed_seq;
    return 0;
}

/* Seed the next family sequence from existing control directories of
 * this pid so repeated selftests keep a monotonic naming stream. */
static unsigned long next_family_seq(void)
{
    static const char prefix[] = ".sparc64rt-family-";
    char wanted[64];
    unsigned long best = 0;
    int have = 0;
    DIR *dir = NULL;
    struct dirent *entry = NULL;
    (void)snprintf(wanted, sizeof(wanted), "%s%ld-",
        prefix, (long)getpid());
    dir = opendir("/tmp");
    if (dir == NULL) {
        return 0;
    }
    while ((entry = readdir(dir)) != NULL) {
        size_t wlen = strlen(wanted);
        char *end = NULL;
        unsigned long seq;
        if (strncmp(entry->d_name, wanted, wlen) != 0) {
            continue;
        }
        errno = 0;
        seq = strtoul(entry->d_name + wlen, &end, 10);
        if (errno != 0 || end == entry->d_name + wlen ||
            *end != '-') {
            continue;
        }
        if (!have || seq + 1U > best) {
            best = seq + 1U;
            have = 1;
        }
    }
    (void)closedir(dir);
    return have ? best : 0;
}

static int family_control_create(sparc64_family_control_t *out, unsigned long seq)
{
    char tmpl[128];
    struct stat status;
    if (out == NULL) {
        errno = EINVAL;
        return -1;
    }
    memset(out, 0, sizeof(*out));
    (void)snprintf(tmpl, sizeof(tmpl), "/tmp/.sparc64rt-family-%ld-%lu-XXXXXX",
        (long)getpid(), seq);
    if (mkdtemp(tmpl) == NULL) {
        return -1;
    }
    if (stat(tmpl, &status) != 0 || !S_ISDIR(status.st_mode)) {
        (void)rmdir(tmpl);
        return -1;
    }
    out->device = (uint64_t)status.st_dev;
    out->inode = (uint64_t)status.st_ino;
    out->seq = seq;
    (void)snprintf(out->dir, sizeof(out->dir), "%s", tmpl);
    return 0;
}

static int family_control_retire(sparc64_family_control_t *control)
{
    char dir[128];
    int gone;
    if (control == NULL || control->dir[0] == '\0') {
        return -1;
    }
    (void)snprintf(dir, sizeof(dir), "%s", control->dir);
    control->dir[0] = '\0';
    control->device = 0;
    control->inode = 0;
    if (rmdir(dir) != 0) {
        return -1;
    }
    gone = access(dir, F_OK) != 0;
    return gone ? 0 : -1;
}

int sparc64_host_family_verify(void)
{
    sparc64_family_control_t first;
    sparc64_family_control_t second;
    int first_live = 0;
    int second_live = 0;
    unsigned long base;
    long pid1 = 0, pid2 = 0;
    unsigned long seq1 = 0, seq2 = 0;
    int rc = -1;
    memset(&first, 0, sizeof(first));
    memset(&second, 0, sizeof(second));
    base = next_family_seq();
    if (family_control_create(&first, base) != 0 ||
        family_control_create(&second, base + 1U) != 0) {
        (void)printf("sparc64rt: family=FAIL reason=create\n");
        goto done;
    }
    first_live = 1;
    second_live = 1;
    if (first.dir[0] == '\0' || second.dir[0] == '\0') {
        (void)printf("sparc64rt: family=FAIL reason=no-directory\n");
        goto done;
    }
    if (parse_family_name(first.dir, &pid1, &seq1) != 0 ||
        parse_family_name(second.dir, &pid2, &seq2) != 0) {
        (void)printf("sparc64rt: family=FAIL reason=bad-name "
            "dir1=%s dir2=%s\n", first.dir, second.dir);
        goto done;
    }
    (void)printf("sparc64rt: family[0] dir=%s pid=%ld seq=%lu\n",
        first.dir, pid1, seq1);
    (void)printf("sparc64rt: family[1] dir=%s pid=%ld seq=%lu\n",
        second.dir, pid2, seq2);
    if (pid1 != (long)getpid() || pid2 != (long)getpid() ||
        seq2 != seq1 + 1U) {
        (void)printf("sparc64rt: family=FAIL reason=sequence\n");
        goto done;
    }
    if (first.device == 0 || first.inode == 0 ||
        second.device == 0 || second.inode == 0) {
        (void)printf("sparc64rt: family=FAIL reason=retire\n");
        goto done;
    }
    if (family_control_retire(&first) != 0 ||
        family_control_retire(&second) != 0) {
        (void)printf("sparc64rt: family=FAIL reason=retire\n");
        goto done;
    }
    first_live = 0;
    second_live = 0;
    (void)printf("sparc64rt: family=ok sequence-step=1 cleaned-up=yes\n");
    rc = 0;
done:
    if (first_live) {
        (void)family_control_retire(&first);
    }
    if (second_live) {
        (void)family_control_retire(&second);
    }
    return rc;
}
