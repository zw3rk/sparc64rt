/*
 * include/a32host.h — Versioned host capability handshake ABI (A32H_ABI 1.0 / 1.1)
 * plus W^X code-arena and I-cache helpers for the Phase 2 AArch64 DBT.
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Adapted from ../sparc32rt/include/a32host.h (Phase 2 lane L2b card).
 * The A32H handshake block below is kept identical so host providers such
 * as hyper-linux (/dev/a32host) keep working; the trailing section adds
 * the cache-maintenance + W^X helpers the DBT dispatcher (src/dbt/dbt.c)
 * uses to publish translated code. Guest data pages are never mapped
 * PROT_EXEC; emitted A64 code lives in anonymous staging flipped to
 * PROT_READ | PROT_EXEC with an I-cache clear before execution.
 *
 * This header compiles for both the host cc and the aarch64 cross gcc
 * under curated C11 (-std=c11 -Werror=vla -pedantic -Wall -Wextra).
 */

#ifndef SPARC64RT_A32HOST_H
#define SPARC64RT_A32HOST_H

#include <stddef.h>
#include <stdint.h>
#include <sys/mman.h>
#include <unistd.h>

#define A32H_ABI_MAJOR     1U
#define A32H_ABI_MINOR     0U
#define A32H_ABI_MINOR_TSO 1U

#define A32H_DEV_PATH "/dev/a32host"

/*
 * Capability flags advertised in `a32h_info_t.caps`.
 */
#define A32H_CAP_PAGE4K            (1ULL << 0) /* mmap/mprotect granularity is 4 KiB */
#define A32H_CAP_WX_ENFORCED       (1ULL << 1) /* W^X enforced; host toggles on fault (hl) or denies */
#define A32H_CAP_ICACHE_TRAP_IALLU (1ULL << 2) /* one trapped IC op suffices to invalidate all */
#define A32H_CAP_LOW4G_FREE        (1ULL << 3) /* [mmap_min_addr, 4G) guaranteed free -> G = 0 */
#define A32H_CAP_DIROFF32          (1ULL << 4) /* getdents64/lseek dir cookies fit in 31 bits */
#define A32H_CAP_AOT_SOCKET        (1ULL << 5) /* aot_socket valid */
#define A32H_CAP_COMPAT_IOCTL      (1ULL << 6) /* A32H_COMPAT_IOCTL supported */
#define A32H_CAP_ROBUST32          (1ULL << 7) /* A32H_SET_ROBUST32 supported */
#define A32H_CAP_SET_PROC          (1ULL << 8) /* A32H_SET_PROC supported */
#define A32H_CAP_HW_TSO            (1ULL << 9) /* ACTLR_EL1.EnTSO hardware TSO active on all vCPUs (ABI 1.1) */

/*
 * Linux-compatible `_IOR('a', 0x01, struct a32h_info)` encoding:
 *   dir  = 2 (read, _IOC_READ) << 30
 *   size = 256 (sizeof(a32h_info_t)) << 16
 *   type = 'a' (0x61) << 8
 *   nr   = 0x01
 */
#define A32H_GET_INFO 0x81006101UL

typedef struct a32h_info {
    uint16_t abi_major;        /* A32H_ABI_MAJOR (1) */
    uint16_t abi_minor;        /* A32H_ABI_MINOR (0 or 1) */
    uint32_t flags;            /* reserved, 0 */
    uint64_t caps;             /* A32H_CAP_* bitmask */
    uint64_t window_hint;      /* preferred G (e.g. 0x100000000ULL), 0 = none */
    uint32_t page_size;        /* guaranteed mmap granularity (4096) */
    uint32_t _pad;             /* reserved, 0 */
    char     aot_socket[108];  /* AF_UNIX path, "" = none */
    uint8_t  _reserved[116];   /* pad total size to 256 bytes */
} a32h_info_t;

_Static_assert(sizeof(a32h_info_t) == 256, "a32h_info_t must be exactly 256 bytes");

/* ---- W^X code-arena + I-cache helpers (Phase 2 DBT, lane L2b) -------------
 * The caller passes page-rounded spans (see a32h_page_span); the helpers
 * never truncate guest addresses and never touch guest mappings. All are
 * static inline so TUs that only need the handshake ABI pay nothing and
 * -Wall -Wextra report no unused-function warnings. */

#ifndef MAP_ANONYMOUS
#ifdef MAP_ANON
#define MAP_ANONYMOUS MAP_ANON
#else
#define MAP_ANONYMOUS 0x20
#endif
#endif

/* Round `used` bytes up to a whole host-page span for mprotect. */
static inline size_t a32h_page_span(size_t used)
{
    long page = sysconf(_SC_PAGESIZE);
    size_t p;
    size_t mask;
    if (page <= 0L) {
        page = 4096L;
    }
    p = (size_t)page;
    mask = p - (size_t)1;
    return (used + mask) & ~mask;
}

/* Map anonymous RW staging for emitted code (outside any guest window). */
static inline void *a32h_arena_map(size_t size)
{
    void *p;
    if (size == (size_t)0) {
        return NULL;
    }
    p = mmap(NULL, size, PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) {
        return NULL;
    }
    return p;
}

static inline void a32h_arena_unmap(void *addr, size_t size)
{
    if (addr != NULL && size != (size_t)0) {
        (void)munmap(addr, size);
    }
}

/* Flip staging RW -> PROT_READ | PROT_EXEC before first execution. */
static inline int a32h_wx_publish(void *addr, size_t span)
{
    if (addr == NULL || span == (size_t)0) {
        return 0;
    }
    if (mprotect(addr, span, PROT_READ | PROT_EXEC) != 0) {
        return -1;
    }
    return 0;
}

/* Reopen RX staging as RW so translation can continue (W^X stays
 * sequential: a span is never writable and executable at once). */
static inline int a32h_wx_reopen(void *addr, size_t span)
{
    if (addr == NULL || span == (size_t)0) {
        return 0;
    }
    if (mprotect(addr, span, PROT_READ | PROT_WRITE) != 0) {
        return -1;
    }
    return 0;
}

/* Invalidate the instruction cache over staged code (both host cc and
 * the aarch64 cross gcc lower this to the right IC maintenance). */
static inline void a32h_icache_clear(void *begin, void *end)
{
    if (begin != NULL && end != NULL && begin != end) {
        __builtin___clear_cache((char *)begin, (char *)end);
    }
}

#endif /* SPARC64RT_A32HOST_H */
