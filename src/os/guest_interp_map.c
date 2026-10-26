/* src/os/guest_interp_map.c -- ported from src/rt64/loader/interp_map.c
 * (Wave U1 coordinator). PT_INTERP mapping + sysroot open; path
 * read/resolve live in os/host_contract_interp.c (Wave U1 lane M1).
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Maps a BE EM_SPARCV9 ET_DYN interpreter (ld.so) at a free base with
 * its own PT_LOAD segments, honouring the largest p_align; the
 * dynamic guest entry point becomes the interpreter entry. Mirrors the
 * segment validation in src/os/guest_run.c (perms union on shared
 * boundary pages, file bytes win over earlier BSS) so both loaders
 * admit the same objects. Never touches x18 (pure C, no asm).
 */

#define _POSIX_C_SOURCE 200809L
/* Needs _GNU_SOURCE: glibc hides pread/openat under -std=c11. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "os/guest_interp_map.h"

#define INTERP_EHDR_SIZE 64U
#define INTERP_PHDR_SIZE 56U
#define INTERP_MAX_PHDR 64U
#define INTERP_MAX_LOADS 128U
#define INTERP_PT_LOAD 1U
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

static uint64_t align_up(uint64_t v, uint64_t a)
{
    return (v + (a - UINT64_C(1))) & ~(a - UINT64_C(1));
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

bool sparc64_sysroot_try_open(int dirfd, const char *path, int flags,
    unsigned mode, int *fd_out)
{
    const char *sysroot = getenv("SPARC64RT_SYSROOT");
    char joined[SPARC64RT_INTERP_PATH_MAX];
    int fd;
    if (path == NULL || path[0] != '/' || fd_out == NULL ||
            sysroot == NULL || sysroot[0] == '\0') {
        return false;
    }
    /* An absolute guest path ignores dirfd per POSIX either way. */
    if (sparc64_interp_resolve(path, sysroot, joined,
            sizeof(joined)) != 0) {
        return false;
    }
    fd = openat(dirfd, joined, flags, (mode_t)mode);
    if (fd < 0 && (errno == ENOENT || errno == ENOTDIR)) {
        return false;
    }
    *fd_out = fd;
    return true;
}

/* One validated PT_LOAD (file offsets + mapped span + host perms). */
typedef struct {
    uint64_t offset, address, filesz, memsz;
    unsigned int permissions;
} interp_load_t;

static int zero_tail(sparc64_space_t *space, uint64_t at, uint64_t end)
{
    uint8_t zeros[512];
    memset(zeros, 0, sizeof(zeros));
    while (at < end) {
        uint64_t want = end - at;
        if (want > (uint64_t)sizeof(zeros)) {
            want = (uint64_t)sizeof(zeros);
        }
        if (!sparc64_space_write_initial(space, at, zeros,
                (size_t)want)) {
            return -ENOMEM;
        }
        at += want;
    }
    return 0;
}

static int copy_from_fd(sparc64_space_t *space, int fd, uint64_t offset,
    uint64_t base, uint64_t len)
{
    uint64_t done = 0;
    uint8_t chunk[4096];
    while (done < len) {
        uint64_t want = len - done;
        uint64_t moved = 0;
        if (want > (uint64_t)sizeof(chunk)) {
            want = (uint64_t)sizeof(chunk);
        }
        if (read_at(fd, offset + done, chunk, want, &moved) != 0 ||
            moved == 0U) {
            return -EIO;
        }
        if (!sparc64_space_write_initial(space, base + done, chunk,
                (size_t)moved)) {
            return -ENOMEM;
        }
        done += moved;
        if (moved < want) {
            return -EIO;
        }
    }
    return 0;
}

int sparc64_interp_map(sparc64_space_t *space, int fd,
    uint64_t *entry_out, uint64_t *base_out, uint64_t *hi_out)
{
    uint8_t ehdr[INTERP_EHDR_SIZE];
    uint64_t phoff = 0, minimum = UINT64_MAX, maximum = 0, align = 0;
    uint64_t entry = 0, bias = 0, span_min = 0, span_size = 0;
    uint32_t phnum = 0, i;
    int has_exec_entry = 0;
    interp_load_t loads[INTERP_MAX_LOADS];
    size_t count = 0;
    if (space == NULL || entry_out == NULL || base_out == NULL ||
        hi_out == NULL) {
        return -EINVAL;
    }
    if (read_exact(fd, 0, ehdr, sizeof(ehdr)) != 0) {
        return -ENOEXEC;
    }
    if (ehdr[0] != 0x7fU || ehdr[1] != 0x45U || ehdr[2] != 0x4cU ||
        ehdr[3] != 0x46U || ehdr[4] != 2U || ehdr[5] != 2U ||
        ehdr[6] != 1U || rd16(ehdr + 16) != INTERP_ET_DYN ||
        rd16(ehdr + 18) != (uint16_t)INTERP_EM_SPARCV9 ||
        rd32(ehdr + 20) != 1U || rd16(ehdr + 54) != INTERP_PHDR_SIZE) {
        return -ENOEXEC;
    }
    entry = rd64(ehdr + 24);
    phoff = rd64(ehdr + 32);
    phnum = rd16(ehdr + 56);
    if (phnum == 0U || phnum > INTERP_MAX_PHDR) {
        return -ENOEXEC;
    }
    for (i = 0; i < phnum; i++) {
        uint8_t phdr[INTERP_PHDR_SIZE];
        uint32_t p_type, p_flags;
        uint64_t p_offset, p_vaddr, p_filesz, p_memsz, p_align;
        uint64_t start, end;
        unsigned int perms;
        if (read_exact(fd, phoff + (uint64_t)i * INTERP_PHDR_SIZE, phdr,
                sizeof(phdr)) != 0) {
            return -ENOEXEC;
        }
        p_type = rd32(phdr);
        if (p_type == INTERP_PT_INTERP) {
            return -ENOEXEC; /* Nested interpreters stay rejected. */
        }
        if (p_type != INTERP_PT_LOAD) {
            continue;
        }
        p_flags = rd32(phdr + 4);
        p_offset = rd64(phdr + 8);
        p_vaddr = rd64(phdr + 16);
        p_filesz = rd64(phdr + 32);
        p_memsz = rd64(phdr + 40);
        p_align = rd64(phdr + 48);
        if (p_memsz == 0U || p_memsz < p_filesz ||
            (p_flags & ~7U) != 0U) {
            return -ENOEXEC;
        }
        if (p_align > 1U &&
            ((p_align & (p_align - 1U)) != 0U ||
             p_vaddr % p_align != p_offset % p_align)) {
            return -ENOEXEC;
        }
        if (p_vaddr >= space->limit || p_memsz > space->limit - p_vaddr ||
            count == INTERP_MAX_LOADS) {
            return -ENOEXEC;
        }
        end = p_vaddr + p_memsz;
        for (size_t j = 0; j < count; j++) {
            if (p_vaddr < loads[j].address + loads[j].memsz &&
                loads[j].address < end) {
                return -ENOEXEC;
            }
        }
        perms = ((p_flags & 4U) != 0U ? SPARC64_MEM_READ : 0U) |
            ((p_flags & 2U) != 0U ? SPARC64_MEM_WRITE : 0U) |
            ((p_flags & 1U) != 0U ? SPARC64_MEM_EXEC : 0U);
        loads[count++] = (interp_load_t){ p_offset, p_vaddr, p_filesz,
            p_memsz, perms };
        if ((perms & SPARC64_MEM_EXEC) != 0U && entry >= p_vaddr &&
            entry < end) {
            has_exec_entry = 1;
        }
        if (end > maximum) {
            maximum = end;
        }
        start = p_vaddr & ~(SPARC64_PAGE_SIZE - UINT64_C(1));
        if (start < minimum) {
            minimum = start;
        }
        if (p_align > align) {
            align = p_align;
        }
    }
    if (count == 0U || !has_exec_entry || (entry & 1U) != 0U) {
        return -ENOEXEC;
    }
    /* Mapping granule: the reported guest page size (8K) or the
     * largest p_align, whichever is coarser (both powers of two, so
     * the coarser divides the finer). The bias stays a multiple of
     * the granule, preserving p_align congruence and keeping
     * 8K-rounded RELRO mprotects inside the mapping. */
    if (align < UINT64_C(8192)) {
        align = UINT64_C(8192);
    }
    /* Bias the whole span into a free hole: the aligned span start
     * must land exactly on a hole start. */
    span_min = minimum & ~(align - UINT64_C(1));
    span_size = align_up(maximum - span_min, align);
    {
        uint64_t cursor = SPARC64RT_INTERP_HINT;
        unsigned int attempt = 0;
        int placed = 0;
        for (attempt = 0; attempt < 64U && !placed; attempt++) {
            uint64_t found = 0;
            if (!sparc64_space_find_hole(space, cursor, span_size,
                    &found)) {
                return -ENOMEM;
            }
            bias = align_up(found - span_min, align);
            if (bias + span_min != found) {
                cursor = found + SPARC64_PAGE_SIZE;
                continue;
            }
            if (bias + span_min + span_size < bias + span_min ||
                bias + span_min + span_size > space->limit) {
                return -ENOMEM;
            }
            {
                uint64_t check = 0;
                if (!sparc64_space_find_hole(space, bias + span_min,
                        span_size, &check) ||
                    check != bias + span_min) {
                    cursor = bias + span_min + SPARC64_PAGE_SIZE;
                    continue;
                }
            }
            placed = 1;
        }
        if (!placed) {
            return -ENOMEM;
        }
    }
    /* Map every segment (union perms on shared boundary pages),
     * copy file bytes, zero the BSS tail. */
    for (size_t k = 0; k < count; k++) {
        uint64_t base = (loads[k].address + bias) & ~(align - UINT64_C(1));
        uint64_t end = align_up(loads[k].address + bias + loads[k].memsz,
            align);
        if (!sparc64_space_map(space, base, end - base,
                loads[k].permissions, true)) {
            return -ENOMEM;
        }
    }
    for (size_t k = 0; k < count; k++) {
        int rc;
        if (loads[k].filesz != 0U) {
            rc = copy_from_fd(space, fd, loads[k].offset,
                loads[k].address + bias, loads[k].filesz);
            if (rc != 0) {
                return rc;
            }
        }
        rc = zero_tail(space, loads[k].address + bias + loads[k].filesz,
            loads[k].address + bias + loads[k].memsz);
        if (rc != 0) {
            return rc;
        }
    }
    *entry_out = entry + bias;
    *base_out = bias;
    *hi_out = align_up(maximum + bias, SPARC64_PAGE_SIZE);
    return 0;
}
