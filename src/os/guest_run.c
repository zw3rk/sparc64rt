/*
 * src/os/guest_run.c — SPARC64 guest runner (Phase 1, L1c)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Loads an ELFCLASS64/ELFDATA2MSB/EM_SPARCV9 image through the rt64
 * memory substrate, synthesizes the _start stack with the 2047 bias
 * (E01), and runs the reference interpreter over sparc64_step until a
 * terminal syscall or a trap. Engine contract (sparc32rt donor):
 * sparc64_step stops with SPARC64_STEP_SYSCALL without advancing pc;
 * sparc64_handle_syscall owns the single pc = npc; npc += 4 commit.
 * Stack: unbiased frame F is 16-byte aligned, %sp = F - 2047, [F,F+128)
 * is the zeroed rwindow_64 area, argc sits at [F+128]; all fields BE.
 */

#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include "core/cpu.h"
#include "os/guest_run.h"
#include "os/sync_sig.h"
#include "os/syscall_nr.h"
#include "os/syscalls_min.h"
#include "rt64/memory/space.h"

/* ---- Guest ABI constants (SPARC Linux, arch/sparc) --------------------- */
#define GUEST_PAGE_SIZE UINT64_C(4096)
#define GUEST_PAGE_MASK (GUEST_PAGE_SIZE - UINT64_C(1))
#define GUEST_ET_EXEC 2U
#define GUEST_ET_DYN 3U
#define GUEST_PT_LOAD 1U
#define GUEST_PT_INTERP 3U
#define GUEST_PF_X 1U
#define GUEST_PF_W 2U
#define GUEST_PF_R 4U
#define GUEST_EHDR_SIZE 64U
#define GUEST_PHDR_SIZE 56U
#define GUEST_MAX_PHDR 64U
#define GUEST_STACK_TOP UINT64_C(0x7ffffffff000)
#define GUEST_STACK_MAX UINT64_C(0x800000)
#define GUEST_MMAP_BASE UINT64_C(0x6000000000)
#define GUEST_DYN_BIAS UINT64_C(0x4000000000)
#define GUEST_MAX_ARGC 256U
#define GUEST_MAX_ENVC 512U
#define GUEST_MAX_STRING_BYTES ((uint64_t)131072)

/* SPARC mmap(71) flags (asm/mman.h). */
#define GUEST_MAP_SHARED 0x01U
#define GUEST_MAP_PRIVATE 0x02U
#define GUEST_MAP_FIXED 0x10U
#define GUEST_MAP_ANONYMOUS 0x20U

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
#define GUEST_AT_EXECFN 31U

/* AT_* keys carried in the initial stack, in auxv order. */
static const unsigned aux_keys[10] = {
    GUEST_AT_PHDR, GUEST_AT_PHENT, GUEST_AT_PHNUM, GUEST_AT_PAGESZ,
    GUEST_AT_ENTRY, GUEST_AT_UID, GUEST_AT_EUID, GUEST_AT_GID,
    GUEST_AT_EGID, GUEST_AT_EXECFN,
};

extern char **environ;

/* Loader outcomes: positive errno-style values without depending on
 * host-specific codes (ELIBBAD exists on Linux only). */
enum {
    LOAD_OK = 0,
    LOAD_BAD = 1,
    LOAD_INTERP = 2,
    LOAD_IO = 3,
    LOAD_NOMEM = 4
};

typedef struct {
    sparc64_space_t space;
    int space_live;
    uint64_t brk_base;
    uint64_t brk_cur;
    uint64_t tid_addr;
    long host_tid;
} guest_state_t;

static uint64_t align_up(uint64_t v, uint64_t a)
{
    return (v + (a - UINT64_C(1))) & ~(a - UINT64_C(1));
}

static uint64_t align_down(uint64_t v, uint64_t a)
{
    return v & ~(a - UINT64_C(1));
}

/* ---- Big-endian readers/writers (guest is BE, host may be LE) ---------- */
static uint16_t rd16be(const uint8_t *p)
{
    return (uint16_t)(((uint16_t)p[0] << 8) | (uint16_t)p[1]);
}

static uint32_t rd32be(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
        ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static uint64_t rd64be(const uint8_t *p)
{
    return ((uint64_t)rd32be(p) << 32) | (uint64_t)rd32be(p + 4);
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

/* Robust pread loop: 0 on success with *out_len bytes moved, -1 with
 * errno set on failure (short reads at EOF report what was moved). */
static int read_at(int fd, uint64_t offset, uint8_t *dst, uint64_t len,
                   uint64_t *out_len)
{
    uint64_t done = 0;
    *out_len = 0;
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
    *out_len = done;
    return 0;
}

/* Copy len bytes from fd@offset into guest space at base. Short reads
 * (EOF) leave the tail as mapped (fresh pages are zero-filled). */
static int copy_from_fd(guest_state_t *g, int fd, uint64_t offset,
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
            return -LOAD_IO;
        }
        if (!sparc64_space_write_initial(&g->space, base + done, chunk,
                                         (size_t)moved)) {
            return -LOAD_NOMEM;
        }
        done += moved;
        if (moved < want) {
            return -LOAD_IO;
        }
    }
    return LOAD_OK;
}

/* ---- sparc64_mem_ops_t bridge over the rt64 substrate ------------------- */
static void record_fault(const guest_state_t *g, sparc64_mem_fault_t *fault)
{
    sparc64_mem_fault_reason_t reason = SPARC64_MEM_FAULT_INTERNAL;
    if (fault == NULL) {
        return;
    }
    switch (g->space.fault_reason) {
    case SPARC64_FAULT_UNMAPPED: reason = SPARC64_MEM_FAULT_UNMAPPED; break;
    case SPARC64_FAULT_PERMISSION: reason = SPARC64_MEM_FAULT_PERMISSION; break;
    case SPARC64_FAULT_RANGE: reason = SPARC64_MEM_FAULT_RANGE; break;
    case SPARC64_FAULT_BUS: reason = SPARC64_MEM_FAULT_BUS; break;
    case SPARC64_FAULT_RESOURCE: reason = SPARC64_MEM_FAULT_RESOURCE; break;
    case SPARC64_FAULT_RETRY: reason = SPARC64_MEM_FAULT_RETRY; break;
    default: break;
    }
    fault->address = g->space.fault_address;
    fault->reason = reason;
}

static bool guest_mem_read(void *context, uint64_t address, void *bytes,
                           size_t size, sparc64_access_t access,
                           sparc64_mem_fault_t *fault)
{
    guest_state_t *g = (guest_state_t *)context;
    unsigned perm = (access == SPARC64_ACCESS_FETCH) ? SPARC64_MEM_EXEC :
                                                       SPARC64_MEM_READ;
    if (g == NULL ||
        !sparc64_space_read(&g->space, address, bytes, size, perm)) {
        if (g != NULL) {
            record_fault(g, fault);
        }
        return false;
    }
    return true;
}

static bool guest_mem_write(void *context, uint64_t address,
                            const void *bytes, size_t size,
                            sparc64_mem_fault_t *fault)
{
    guest_state_t *g = (guest_state_t *)context;
    if (g == NULL || !sparc64_space_write(&g->space, address, bytes, size)) {
        if (g != NULL) {
            record_fault(g, fault);
        }
        return false;
    }
    return true;
}

static bool guest_mem_atomic(void *context,
                             const sparc64_atomic_request_t *request,
                             sparc64_atomic_result_t *result,
                             sparc64_mem_fault_t *fault)
{
    guest_state_t *g = (guest_state_t *)context;
    if (g == NULL || request == NULL || result == NULL ||
        !sparc64_space_atomic(&g->space, request, result)) {
        if (g != NULL && request != NULL && result != NULL) {
            record_fault(g, fault);
        }
        return false;
    }
    return true;
}

static const sparc64_mem_ops_t guest_mem_ops = {
    guest_mem_read, guest_mem_write, guest_mem_atomic,
};

/* ---- sparc64_syscall_mem_t implementation over the same space ----------- */
static bool sysmem_read(void *context, uint64_t va, void *host,
                        uint64_t len)
{
    guest_state_t *g = (guest_state_t *)context;
    if (g == NULL || (len != 0U && host == NULL) || len == 0U) {
        return g != NULL;
    }
    return sparc64_space_read(&g->space, va, host, (size_t)len,
                             SPARC64_MEM_READ);
}

static bool sysmem_write(void *context, uint64_t va, const void *host,
                         uint64_t len)
{
    guest_state_t *g = (guest_state_t *)context;
    if (g == NULL || (len != 0U && host == NULL) || len == 0U) {
        return g != NULL;
    }
    return sparc64_space_write(&g->space, va, host, (size_t)len);
}

static bool sysmem_prepare_write(void *context, uint64_t va, uint64_t len)
{
    guest_state_t *g = (guest_state_t *)context;
    if (g == NULL || len == 0U) {
        return g != NULL;
    }
    return sparc64_space_prepare_write(&g->space, va, (size_t)len);
}

/* Resolve the mapping base: MAP_FIXED uses addr verbatim, otherwise the
 * first hole at/above addr (falling back to MMAP_BASE below the stack). */
static long resolve_base(guest_state_t *g, uint64_t addr, uint64_t size,
                         unsigned flags, uint64_t *base)
{
    if ((flags & GUEST_MAP_FIXED) != 0U) {
        if ((addr & GUEST_PAGE_MASK) != 0U || addr == 0U ||
            addr >= SPARC64_TASK_SIZE ||
            size > SPARC64_TASK_SIZE - addr) {
            return -EINVAL;
        }
        *base = addr;
        return 0;
    }
    *base = (addr == 0U) ? GUEST_MMAP_BASE : align_up(addr, GUEST_PAGE_SIZE);
    if (*base == 0U || *base >= SPARC64_TASK_SIZE ||
        size > SPARC64_TASK_SIZE - *base) {
        *base = GUEST_MMAP_BASE;
    }
    if (!sparc64_space_find_hole(&g->space, *base, size, base) &&
        (*base == GUEST_MMAP_BASE ||
         !sparc64_space_find_hole(&g->space, GUEST_MMAP_BASE, size, base))) {
        return -ENOMEM;
    }
    return 0;
}

static long sysmem_mmap(void *context, uint64_t addr, uint64_t len,
                        unsigned prot, unsigned flags, int fd,
                        uint64_t offset)
{
    guest_state_t *g = (guest_state_t *)context;
    uint64_t size;
    uint64_t base;
    if (g == NULL) {
        return -EFAULT;
    }
    if (len == 0U || len > SPARC64_TASK_SIZE) {
        return -EINVAL;
    }
    size = align_up(len, GUEST_PAGE_SIZE);
    if (size == 0U || size > SPARC64_TASK_SIZE) {
        return -ENOMEM;
    }
    if ((prot & ~7U) != 0U) {
        return -EINVAL;
    }
    if (((flags & (GUEST_MAP_PRIVATE | GUEST_MAP_SHARED)) == 0U) ||
        ((flags & (GUEST_MAP_PRIVATE | GUEST_MAP_SHARED)) ==
         (GUEST_MAP_PRIVATE | GUEST_MAP_SHARED))) {
        return -EINVAL;
    }
    if ((flags & GUEST_MAP_ANONYMOUS) == 0U) {
        /* File-backed: pread probe validates fd readability. */
        uint8_t probe;
        if ((offset & GUEST_PAGE_MASK) != 0U) {
            return -EINVAL;
        }
        if (len != 0U &&
            pread(fd, &probe, sizeof(probe), (off_t)offset) < 0) {
            return -(long)errno;
        }
    }
    {
        long rc = resolve_base(g, addr, size, flags, &base);
        bool fixed = (flags & GUEST_MAP_FIXED) != 0U;
        bool mapped;
        if (rc != 0) {
            return rc;
        }
        mapped = fixed ? sparc64_space_replace(&g->space, base, size,
                                               prot & 7U) :
                         sparc64_space_map(&g->space, base, size, prot & 7U,
                                           false);
        if (!mapped) {
            return -ENOMEM;
        }
        if ((flags & GUEST_MAP_ANONYMOUS) != 0U) {
            return (long)base;
        }
    }
    /* Short files leave a zero tail (fresh pages are zero-filled). */
    if (len != 0U &&
        copy_from_fd(g, fd, offset, base, len) == -LOAD_NOMEM) {
        (void)sparc64_space_unmap(&g->space, base, size);
        return -ENOMEM;
    }
    return (long)base;
}

static long sysmem_munmap(void *context, uint64_t addr, uint64_t len)
{
    guest_state_t *g = (guest_state_t *)context;
    uint64_t base;
    uint64_t size;
    if (g == NULL) {
        return -EFAULT;
    }
    if (len == 0U) {
        return -EINVAL;
    }
    base = align_down(addr, GUEST_PAGE_SIZE);
    size = align_up(addr + len, GUEST_PAGE_SIZE) - base;
    if (base < GUEST_PAGE_SIZE || size > SPARC64_TASK_SIZE - base) {
        return -EINVAL;
    }
    /* Tolerates holes like Linux; shrink the break when its tail goes. */
    (void)sparc64_space_unmap(&g->space, base, size);
    if (base >= g->brk_base && base < g->brk_cur &&
        base + size >= g->brk_cur) {
        g->brk_cur = base;
    }
    return 0;
}

static long sysmem_mprotect(void *context, uint64_t addr, uint64_t len,
                            unsigned prot)
{
    guest_state_t *g = (guest_state_t *)context;
    uint64_t size;
    if (g == NULL) {
        return -EFAULT;
    }
    if (len == 0U || (prot & ~7U) != 0U) {
        return -EINVAL;
    }
    if ((addr & GUEST_PAGE_MASK) != 0U) {
        return -EINVAL;
    }
    size = align_up(len, GUEST_PAGE_SIZE);
    if (addr < GUEST_PAGE_SIZE || size > SPARC64_TASK_SIZE - addr) {
        return -ENOMEM;
    }
    /* Every page must be mapped (Linux reports ENOMEM otherwise). */
    if (!sparc64_space_protect(&g->space, addr, size, prot & 7U)) {
        return -ENOMEM;
    }
    return 0;
}

static long sysmem_brk(void *context, uint64_t addr)
{
    guest_state_t *g = (guest_state_t *)context;
    uint64_t target;
    uint64_t cur;
    if (g == NULL) {
        return -EFAULT;
    }
    if (addr == 0U) {
        return (long)g->brk_cur;
    }
    if (addr < g->brk_base || addr > SPARC64_TASK_SIZE) {
        return (long)g->brk_cur;
    }
    target = align_up(addr, GUEST_PAGE_SIZE);
    cur = align_up(g->brk_cur, GUEST_PAGE_SIZE);
    if (target > cur) {
        if (!sparc64_space_map(&g->space, cur, target - cur,
                               SPARC64_MEM_READ | SPARC64_MEM_WRITE,
                               false)) {
            return (long)g->brk_cur;
        }
    } else if (target < cur) {
        (void)sparc64_space_unmap(&g->space, target, cur - target);
    }
    g->brk_cur = addr;
    return (long)addr;
}

static long sysmem_set_tid(void *context, uint64_t va)
{
    guest_state_t *g = (guest_state_t *)context;
    if (g == NULL) {
        return -EFAULT;
    }
    g->tid_addr = va;
    return g->host_tid;
}

static const sparc64_syscall_mem_t *sysmem_ops(guest_state_t *g,
                                               sparc64_syscall_mem_t *ops)
{
    ops->context = g;
    ops->read = sysmem_read;
    ops->write = sysmem_write;
    ops->prepare_write = sysmem_prepare_write;
    ops->do_mmap = sysmem_mmap;
    ops->do_munmap = sysmem_munmap;
    ops->do_mprotect = sysmem_mprotect;
    ops->do_brk = sysmem_brk;
    ops->set_tid_address = sysmem_set_tid;
    return ops;
}

/* ---- ELF loading -------------------------------------------------------- */
typedef struct {
    uint64_t entry;
    uint64_t phoff;
    uint32_t phnum;
    uint16_t phent;
} guest_image_t;

/* Admit the ELF header: ELFCLASS64/ELFDATA2MSB/EM_SPARCV9, ET_EXEC/DYN. */
static int load_ehdr(int fd, guest_image_t *img, uint64_t *bias)
{
    uint8_t ehdr[GUEST_EHDR_SIZE];
    uint64_t moved = 0;
    uint16_t type;
    if (read_at(fd, 0, ehdr, sizeof(ehdr), &moved) != 0 ||
        moved != (uint64_t)sizeof(ehdr) || ehdr[0] != 0x7fU ||
        ehdr[1] != 0x45U || ehdr[2] != 0x4cU || ehdr[3] != 0x46U ||
        ehdr[4] != 2U || ehdr[5] != 2U || ehdr[6] != 1U) {
        return -LOAD_BAD;
    }
    type = rd16be(ehdr + 16);
    img->phent = rd16be(ehdr + 54);
    img->phnum = rd16be(ehdr + 56);
    if ((type != (uint16_t)GUEST_ET_EXEC &&
         type != (uint16_t)GUEST_ET_DYN) ||
        rd16be(ehdr + 18) != (uint16_t)SPARC64_EM_SPARCV9 ||
        rd32be(ehdr + 20) != 1U ||
        img->phent != (uint16_t)GUEST_PHDR_SIZE || img->phnum == 0U ||
        img->phnum > (uint32_t)GUEST_MAX_PHDR) {
        return -LOAD_BAD;
    }
    *bias = (type == (uint16_t)GUEST_ET_DYN) ? GUEST_DYN_BIAS : 0U;
    img->entry = rd64be(ehdr + 24) + *bias;
    img->phoff = rd64be(ehdr + 32);
    return 0;
}

/* Zero [at, end) through the loader-only initializer. */
static int zero_tail(guest_state_t *g, uint64_t at, uint64_t end)
{
    uint8_t zeros[512];
    memset(zeros, 0, sizeof(zeros));
    while (at < end) {
        uint64_t want = end - at;
        if (want > (uint64_t)sizeof(zeros)) {
            want = (uint64_t)sizeof(zeros);
        }
        if (!sparc64_space_write_initial(&g->space, at, zeros,
                                         (size_t)want)) {
            return -LOAD_NOMEM;
        }
        at += want;
    }
    return LOAD_OK;
}

/* Map every PT_LOAD in file order (merge unions perms and preserves
 * bytes), copy file bytes, and zero the BSS tail inline so a later
 * segment's file bytes always win over an earlier BSS. Rejects
 * PT_INTERP: Phase 1 runs static guests only. hi_out receives the
 * post-image break, phdr_va_out the VA of the program-header table. */
static int load_segments(int fd, guest_state_t *g, uint64_t bias,
                         uint64_t phoff, uint32_t phnum, uint64_t file_phoff,
                         uint64_t *hi_out, uint64_t *phdr_va_out)
{
    uint64_t hi = 0;
    uint64_t phdr_va = 0;
    uint32_t i;
    uint32_t n = 0;
    for (i = 0; i < phnum; i++) {
        uint8_t phdr[GUEST_PHDR_SIZE];
        uint64_t moved = 0;
        uint32_t p_flags;
        uint64_t p_vaddr;
        uint64_t p_filesz;
        uint64_t p_memsz;
        uint64_t start;
        uint64_t end;
        unsigned perms = 0U;
        uint32_t p_type;
        if (read_at(fd, phoff + (uint64_t)i * GUEST_PHDR_SIZE, phdr,
                    sizeof(phdr), &moved) != 0 ||
            moved != (uint64_t)sizeof(phdr)) {
            return -LOAD_IO;
        }
        p_type = rd32be(phdr);
        if (p_type == (uint32_t)GUEST_PT_INTERP) {
            return -LOAD_INTERP;
        }
        if (p_type != (uint32_t)GUEST_PT_LOAD) {
            continue;
        }
        p_flags = rd32be(phdr + 4);
        p_vaddr = rd64be(phdr + 16) + bias;
        p_filesz = rd64be(phdr + 32);
        p_memsz = rd64be(phdr + 40);
        if (rd64be(phdr + 8) <= file_phoff &&
            file_phoff < rd64be(phdr + 8) + p_filesz) {
            phdr_va = p_vaddr + (file_phoff - rd64be(phdr + 8));
        }
        if (p_memsz == 0U || p_memsz < p_filesz) {
            return -LOAD_BAD;
        }
        perms = ((p_flags & GUEST_PF_R) != 0U ? SPARC64_MEM_READ : 0U) |
                ((p_flags & GUEST_PF_W) != 0U ? SPARC64_MEM_WRITE : 0U) |
                ((p_flags & GUEST_PF_X) != 0U ? SPARC64_MEM_EXEC : 0U);
        start = align_down(p_vaddr, GUEST_PAGE_SIZE);
        end = align_up(p_vaddr + p_memsz, GUEST_PAGE_SIZE);
        if (end <= start || end - start > SPARC64_TASK_SIZE ||
            start >= SPARC64_TASK_SIZE || end > SPARC64_TASK_SIZE) {
            return -LOAD_BAD;
        }
        if (!sparc64_space_map(&g->space, start, end - start, perms, true)) {
            return -LOAD_NOMEM;
        }
        if (p_filesz != 0U) {
            int seg_rc = copy_from_fd(g, fd, rd64be(phdr + 8), p_vaddr,
                                      p_filesz);
            if (seg_rc != LOAD_OK) {
                return seg_rc;
            }
        }
        {
            int seg_rc = zero_tail(g, p_vaddr + p_filesz, p_vaddr + p_memsz);
            if (seg_rc != LOAD_OK) {
                return seg_rc;
            }
        }
        n++;
        if (end > hi) {
            hi = end;
        }
    }
    if (n == 0U || phdr_va == 0U) {
        return -LOAD_BAD;
    }
    *phdr_va_out = phdr_va;
    *hi_out = hi;
    return 0;
}

/* ---- _start stack synthesis (E01) ---------------------------------------- */
static uint64_t count_strings(char **vec, uint64_t max)
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
static int build_stack(guest_state_t *g, uint64_t phdr_va, uint64_t entry,
                       uint64_t phnum, uint64_t phent, char **argv,
                       uint64_t argc, uint64_t *sp_out)
{
    uint64_t envc = count_strings(environ, GUEST_MAX_ENVC);
    uint64_t argv_bytes = 0, env_bytes = 0, str_size, str_base;
    uint64_t cursor, frame, stack_base, stack_size, execfn = 0, words, at, i;
    uint64_t argv_addr[GUEST_MAX_ARGC], env_addr[GUEST_MAX_ENVC];
    uint64_t auxv[20], vals[10];
    uint8_t zeros[128];
    if (argc > (uint64_t)GUEST_MAX_ARGC ||
        envc > (uint64_t)GUEST_MAX_ENVC) {
        return -E2BIG;
    }
    if (string_bytes(argv, argc, &argv_bytes) != 0 ||
        string_bytes(environ, envc, &env_bytes) != 0) {
        return -E2BIG;
    }
    str_size = argv_bytes + env_bytes;
    /* Reserve: argc + argv+NULL + envp+NULL + 11 auxv pairs. */
    words = UINT64_C(1) + (argc + UINT64_C(1)) + (envc + UINT64_C(1)) +
        UINT64_C(22);
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
    cursor = GUEST_STACK_TOP;
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
    vals[9] = execfn;
    for (i = 0; i < 10U; i++) {
        auxv[2U * i] = aux_keys[i];
        auxv[2U * i + 1U] = vals[i];
    }
    at = frame + UINT64_C(128);
    if (put64(g, &at, argc) != 0 ||
        put_vec(g, &at, argv_addr, argc) != 0 ||
        put64(g, &at, 0U) != 0 ||
        put_vec(g, &at, env_addr, envc) != 0 ||
        put64(g, &at, 0U) != 0 ||
        put_vec(g, &at, auxv, 20U) != 0 ||
        put64(g, &at, GUEST_AT_NULL) != 0 ||
        put64(g, &at, 0U) != 0) {
        return -ENOMEM;
    }
    *sp_out = frame - SPARC64_STACK_BIAS;
    return 0;
}

/* ---- Entry point --------------------------------------------------------- */
int sparc64_guest_run(const char *path, char **argv, int interp_only)
{
    guest_state_t g;
    guest_image_t img;
    sparc64_ctx_t ctx;
    sparc64_syscall_mem_t ops_storage;
    const sparc64_syscall_mem_t *ops;
    uint64_t bias = 0, guest_phdr = 0, heap_hi = 0, sp = 0, argc = 0;
    char *synthetic[2];
    int fd = -1;
    int rc;
    memset(&g, 0, sizeof(g));
    memset(&img, 0, sizeof(img));
    if (path == NULL) {
        (void)fprintf(stderr, "sparc64rt: no guest image\n");
        return 1;
    }
    if (!interp_only) {
        (void)fprintf(stderr, "sparc64rt: dbt lands in Phase 2\n");
        return 1;
    }
    if (argv == NULL || argv[0] == NULL) {
        synthetic[0] = (char *)path;
        synthetic[1] = NULL;
        argv = synthetic;
        argc = 1;
    } else {
        argc = count_strings(argv, GUEST_MAX_ARGC + 1U);
    }
    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        (void)fprintf(stderr, "sparc64rt: cannot open '%s': %s\n", path,
                      strerror(errno));
        return 1;
    }
    sparc64_space_init(&g.space, 64);
    g.space_live = 1;
    g.host_tid = (long)getpid();
    rc = load_ehdr(fd, &img, &bias);
    if (rc != 0) {
        (void)fprintf(stderr, "sparc64rt: '%s' is not a static SPARC64 ELF\n",
                      path);
        goto fail;
    }
    rc = load_segments(fd, &g, bias, img.phoff, img.phnum, img.phoff,
                       &heap_hi, &guest_phdr);
    if (rc != 0) {
        (void)fprintf(stderr, rc == -LOAD_INTERP ?
                      "sparc64rt: '%s' needs an interpreter (static only)\n" :
                      "sparc64rt: cannot load '%s'\n", path);
        goto fail;
    }
    g.brk_base = align_up(heap_hi, GUEST_PAGE_SIZE);
    g.brk_cur = g.brk_base;
    rc = build_stack(&g, guest_phdr, img.entry, img.phnum, img.phent,
                     argv, argc, &sp);
    if (rc != 0) {
        (void)fprintf(stderr, "sparc64rt: cannot build the guest stack\n");
        goto fail;
    }
    (void)close(fd);
    fd = -1;
    sparc64_ctx_init(&ctx, img.entry);
    ctx.r[SPARC64_SP] = sp;
    /* Fresh windows (E01): CWP 0, no invalid windows, so the first
     * SAVE/RESTORE pair rotates in-register without spill/fill. */
    ctx.cwp = 0U;
    ctx.cansave = (uint32_t)(SPARC64_NWINDOWS - 1U);
    ops = sysmem_ops(&g, &ops_storage);
    for (;;) {
        sparc64_step_result_t step = sparc64_step(&ctx, &guest_mem_ops, &g);
        if (step.kind == SPARC64_STEP_SYSCALL) {
            long nr = (long)ctx.r[SPARC64_G1];
            long status = sparc64_handle_syscall(&ctx, ops);
            if (sparc64_syscall_is_exit(nr)) {
                sparc64_space_destroy(&g.space);
                return (int)(status & 0xffL);
            }
        } else if (step.kind == SPARC64_STEP_TRAP) {
            /* Synchronous signal delivery (Phase 1): faults with an
             * installed handler resume in the handler; anything else
             * (and internal/retry states) is fatal. */
            int code = 0;
            int signo = sparc64_sync_sig_for_trap(step.cause, &code);
            if (signo > 0 &&
                sparc64_sync_sig_deliver(&ctx, ops, signo, code,
                    step.tval) == 0) {
                continue;
            }
            (void)fprintf(stderr,
                          "sparc64rt: unhandled guest trap: cause=%d pc=0x%llx tval=0x%llx\n",
                          (int)step.cause,
                          (unsigned long long)step.pc,
                          (unsigned long long)step.tval);
            goto fail;
        } else if (step.kind != SPARC64_STEP_CONTINUE) {
            (void)fprintf(stderr,
                          "sparc64rt: guest stopped: kind=%d cause=%d pc=0x%llx\n",
                          (int)step.kind, (int)step.cause,
                          (unsigned long long)step.pc);
            goto fail;
        }
    }
fail:
    if (fd >= 0) {
        (void)close(fd);
    }
    if (g.space_live) {
        sparc64_space_destroy(&g.space);
    }
    return 1;
}
