/*
 * src/os/host_contract_interp.c — Wave U1 PT_INTERP path helpers
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Migrated from src/rt64/loader/interp_map.c (read cursor plus
 * sparc64_interp_read_path/sparc64_interp_resolve only): validates a
 * BE EM_SPARCV9 ELF via position-independent pread and extracts or
 * resolves its PT_INTERP path for the AOT cache identity. Never touches
 * x18 (pure C, no asm).
 */

#define _POSIX_C_SOURCE 200809L
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "os/host_contract_interp.h"

#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#define INTERP_EHDR_SIZE 64U
#define INTERP_PHDR_SIZE 56U
#define INTERP_MAX_PHDR 64U
#define INTERP_PT_INTERP 3U
#define INTERP_ET_DYN 3U
#define INTERP_EM_SPARCV9 43U

static uint16_t rd16(const uint8_t *p)
{
    return (uint16_t)(((uint16_t)p[0] << 8) | (uint16_t)p[1]);
}

static uint32_t rd32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
        ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static uint64_t rd64(const uint8_t *p)
{
    return ((uint64_t)rd32(p) << 32) | (uint64_t)rd32(p + 4);
}

/* Robust pread: 0 with *moved bytes, -1 with errno on failure. */
static int read_at(int fd, uint64_t offset, uint8_t *dst, uint64_t len,
    uint64_t *moved)
{
    uint64_t done = 0;
    *moved = 0;
    while (done < len) {
        ssize_t got = pread(fd, dst + done, (size_t)(len - done),
            (off_t)(offset + done));
        if (got < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        if (got == 0) {
            break;
        }
        done += (uint64_t)got;
    }
    *moved = done;
    return 0;
}

static int read_exact(int fd, uint64_t offset, uint8_t *dst, uint64_t len)
{
    uint64_t moved = 0;
    if (read_at(fd, offset, dst, len, &moved) != 0 || moved != len) {
        return (errno == 0) ? -EIO : -errno;
    }
    return 0;
}

/* Shared EHDR/PHDR cursor: validates BE SPARC64, returns phoff/phnum
 * (phent must be 56) and whether the image is ET_DYN. */
static int read_headers(int fd, uint64_t *phoff_out, uint32_t *phnum_out,
    int *dyn_out)
{
    uint8_t ehdr[INTERP_EHDR_SIZE];
    uint16_t type;
    int rc = read_exact(fd, 0, ehdr, sizeof(ehdr));
    if (rc != 0) {
        return rc;
    }
    if (ehdr[0] != 0x7fU || ehdr[1] != 0x45U || ehdr[2] != 0x4cU ||
        ehdr[3] != 0x46U || ehdr[4] != 2U || ehdr[5] != 2U ||
        ehdr[6] != 1U) {
        return -ENOEXEC;
    }
    type = rd16(ehdr + 16);
    if ((type != 2U && type != INTERP_ET_DYN) ||
        rd16(ehdr + 18) != (uint16_t)INTERP_EM_SPARCV9 ||
        rd32(ehdr + 20) != 1U || rd16(ehdr + 54) != INTERP_PHDR_SIZE) {
        return -ENOEXEC;
    }
    *phnum_out = rd16(ehdr + 56);
    if (*phnum_out == 0U || *phnum_out > INTERP_MAX_PHDR) {
        return -ENOEXEC;
    }
    *phoff_out = rd64(ehdr + 32);
    *dyn_out = (type == INTERP_ET_DYN) ? 1 : 0;
    return 0;
}

int sparc64_interp_read_path(int fd, char *out, size_t cap)
{
    uint64_t phoff = 0;
    uint32_t phnum = 0;
    int dyn = 0;
    uint32_t i;
    if (out == NULL || cap == 0U) {
        return -EINVAL;
    }
    out[0] = '\0';
    if (read_headers(fd, &phoff, &phnum, &dyn) != 0) {
        return -ENOEXEC;
    }
    for (i = 0; i < phnum; i++) {
        uint8_t phdr[INTERP_PHDR_SIZE];
        uint64_t offset, length;
        uint64_t moved = 0;
        if (read_at(fd, phoff + (uint64_t)i * INTERP_PHDR_SIZE, phdr,
                sizeof(phdr), &moved) != 0 ||
            moved != (uint64_t)sizeof(phdr)) {
            return -ENOEXEC;
        }
        if (rd32(phdr) != INTERP_PT_INTERP) {
            continue;
        }
        offset = rd64(phdr + 8);
        length = rd64(phdr + 32);
        if (length < 2U || length > (uint64_t)SPARC64RT_INTERP_PATH_MAX ||
            length > cap) {
            return -ENOEXEC;
        }
        if (read_exact(fd, offset, (uint8_t *)out, length) != 0) {
            return -ENOEXEC;
        }
        if (out[length - 1U] != '\0' ||
            memchr(out, '\0', (size_t)length - 1U) != NULL) {
            out[0] = '\0';
            return -ENOEXEC;
        }
        return 0;
    }
    return -ENOENT;
}

int sparc64_interp_resolve(const char *interp, const char *sysroot,
    char *out, size_t cap)
{
    size_t root_len = 0;
    size_t interp_len;
    if (interp == NULL || out == NULL || cap == 0U) {
        return -EINVAL;
    }
    interp_len = strlen(interp);
    if (interp_len == 0U || interp_len >= cap) {
        return -ENAMETOOLONG;
    }
    /* Container root (unset, empty, or all slashes): verbatim. */
    if (sysroot != NULL) {
        while (sysroot[root_len] == '/') {
            root_len++;
        }
        root_len = strlen(sysroot);
        while (root_len != 0U && sysroot[root_len - 1U] == '/') {
            root_len--;
        }
    }
    if (sysroot == NULL || root_len == 0U || interp[0] != '/') {
        memcpy(out, interp, interp_len + 1U);
        return 0;
    }
    if (root_len + interp_len + 1U > cap) {
        return -ENAMETOOLONG;
    }
    memcpy(out, sysroot, root_len);
    memcpy(out + root_len, interp, interp_len + 1U);
    return 0;
}
