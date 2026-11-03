/*
 * src/os/guest_run_sysmem.c — SPARC64 guest memory syscalls (Lane A2 split)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Split from src/os/guest_run.c (Lane A2) so neither TU exceeds the
 * 900-line limit: this file owns the sparc64_syscall_mem_t cluster
 * (read/write/prepare_write, mmap/munmap/mprotect/mremap, brk helpers
 * stay in guest_run.c) over the rt64 memory substrate. Every mapping
 * mutation runs the 6-step quiescence legs from src/vm/vm64.c
 * (vm64_stxn_prepare / host_op / commit, host-op-first abort, commit
 * publishes); paired Soft-TLB + DBT invalidation stays here with the
 * live sparc64_dbt_tlb owner. Guest VA is 8 KiB-granular
 * (GUEST_ABI_PAGE_SIZE); the file never maps guest data PROT_EXEC on
 * the host and never touches host register x18.
 */

#define _POSIX_C_SOURCE 200809L
/* Needs _GNU_SOURCE: musl hides pread(2) under -std=c11. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

#include "core/cpu.h"
#include "os/guest_run_priv.h"
#include "os/guest_proc.h"
#include "os/guest_interp_map.h"
#include "dbt/dbt.h"
#include "dbt/mem_sites.h"
#include "os/syscalls_min.h"
#include "os/mem_space.h"
#include "vm/vm64.h"

/* ---- Guest ABI constants (SPARC Linux, arch/sparc) --------------------- */
/* Canonical source is src/os/guest_run_priv.h (GUEST_ABI_PAGE_SIZE); the
 * map-flag values mirror arch/sparc asm/mman.h. Repeated here so this TU
 * compiles standalone until the coordinator rewires the headers. */
#define SYSMEM_PAGE_MASK (GUEST_PAGE_SIZE - UINT64_C(1))
#define SYSMEM_MMAP_BASE UINT64_C(0x6000000000)
#define SYSMEM_MAP_SHARED 0x01U
#define SYSMEM_MAP_PRIVATE 0x02U
#define SYSMEM_MAP_FIXED 0x10U
#define SYSMEM_MAP_ANONYMOUS 0x20U
/* SPARC Linux mmap flag values (arch/sparc asm/mman.h) accepted
 * alongside the four above; anything else is -EINVAL (S64-R9-5). */
#define SYSMEM_MAP_NORESERVE 0x40U
#define SYSMEM_MAP_DENYWRITE 0x0800U
#define SYSMEM_MAP_EXECUTABLE 0x1000U
#define SYSMEM_MAP_POPULATE 0x8000U
#define SYSMEM_MAP_STACK 0x20000U
#define SYSMEM_MAP_FIXED_NOREPLACE 0x100000U
#define SYSMEM_MAP_KNOWN \
    (SYSMEM_MAP_SHARED | SYSMEM_MAP_PRIVATE | SYSMEM_MAP_FIXED | \
     SYSMEM_MAP_ANONYMOUS | SYSMEM_MAP_FIXED_NOREPLACE | \
     SYSMEM_MAP_NORESERVE | SYSMEM_MAP_DENYWRITE | \
     SYSMEM_MAP_EXECUTABLE | SYSMEM_MAP_POPULATE | SYSMEM_MAP_STACK)
/* Linux mremap(2) flags (asm-generic, same on SPARC). */
#define SYSMEM_MREMAP_MAYMOVE 1u
#define SYSMEM_MREMAP_FIXED 2u
/* Soft-TLB indexing granule for the permission-span scan. */
#define SYSMEM_SUB_PAGE UINT64_C(4096)

static uint64_t sysmem_align_up(uint64_t v, uint64_t a)
{
    return (v + (a - UINT64_C(1))) & ~(a - UINT64_C(1));
}

/* ---- sparc64_syscall_mem_t read/write helpers over the same space ------ */
/* File-range COW promotion (guest_run_sysmem_file.c). */
extern void sysmem_file_note_write(void *context, uint64_t base,
    uint64_t len);

bool sparc64_sysmem_read(void *context, uint64_t va, void *host,
    uint64_t len)
{
    guest_state_t *g = (guest_state_t *)context;
    if (g == NULL || (len != 0U && host == NULL) || len == 0U) {
        return g != NULL;
    }
    return sparc64_space_read(&g->space, va, host, (size_t)len,
        SPARC64_MEM_READ);
}

bool sparc64_sysmem_write(void *context, uint64_t va, const void *host,
    uint64_t len)
{
    guest_state_t *g = (guest_state_t *)context;
    if (g == NULL || (len != 0U && host == NULL) || len == 0U) {
        return g != NULL;
    }
    if (!sparc64_space_write(&g->space, va, host, (size_t)len)) {
        return false;
    }
    /* RC-U4 #5: syscall copyout (read/recv into guest buffers) dirties
     * file pages exactly like guest stores do. */
    sysmem_file_note_write(g, va, len);
    /* S64-R9-3: copyout onto a code-bearing page is SMC like any
     * store: evict writable Soft-TLB tags, invalidate DBT blocks,
     * and bump the code generation. */
    sparc64_tlb_evict_writes(va, len);
    if (g->dbt != NULL) {
        sparc64_dbt_invalidate(g->dbt, va, len);
    }
    vm64_code_epoch_bump();
    return true;
}

bool sparc64_sysmem_prepare_write(void *context, uint64_t va, uint64_t len)
{
    guest_state_t *g = (guest_state_t *)context;
    if (g == NULL || len == 0U) {
        return g != NULL;
    }
    return sparc64_space_prepare_write(&g->space, va, (size_t)len);
}

/* ---- Shared transactional space-op dispatcher (Step 3 host ops) --------- */
#define SYSOP_MAP 1U
#define SYSOP_REPLACE 2U
#define SYSOP_UNMAP 3U
#define SYSOP_PROTECT 4U
#define SYSOP_REMAP 5U

typedef struct {
    guest_state_t *g;
    uint64_t base;
    uint64_t size;
    unsigned prot;
    unsigned kind;
    uint64_t dest;
    uint64_t new_size;
} sysmem_span_op_t;

static long sysmem_space_op(void *ctx)
{
    sysmem_span_op_t *p = (sysmem_span_op_t *)ctx;
    switch (p->kind) {
    case SYSOP_MAP:
        return sparc64_space_map(&p->g->space, p->base, p->size,
            p->prot, false) ? 0 : -ENOMEM;
    case SYSOP_REPLACE:
        return sparc64_space_replace(&p->g->space, p->base, p->size,
            p->prot) ? 0 : -ENOMEM;
    case SYSOP_UNMAP:
        (void)sparc64_space_unmap(&p->g->space, p->base, p->size);
        return 0;
    case SYSOP_PROTECT:
        return sparc64_space_protect(&p->g->space, p->base, p->size,
            p->prot) ? 0 : -ENOMEM;
    case SYSOP_REMAP:
        return sparc64_space_remap(&p->g->space, p->base, p->size,
            p->dest, p->new_size, p->prot) ? 0 : -ENOMEM;
    default:
        return -EINVAL;
    }
}

/* Free-span probe (defined next to mremap below): true when no page in
 * [base, base + len) is mapped. Needed by the mmap NOREPLACE arm. */
static bool sysmem_span_free(guest_state_t *g, uint64_t base, uint64_t len);

/* Resolve the mapping base: MAP_FIXED uses addr verbatim, otherwise the
 * first hole at/above addr (falling back to MMAP_BASE below the stack). */
static long sysmem_resolve_base(guest_state_t *g, uint64_t addr,
    uint64_t size, unsigned flags, uint64_t *base)
{
    if ((flags & SYSMEM_MAP_FIXED) != 0U) {
        if ((addr & SYSMEM_PAGE_MASK) != 0U || addr == 0U ||
            addr >= SPARC64_TASK_SIZE ||
            size > SPARC64_TASK_SIZE - addr) {
            return -EINVAL;
        }
        *base = addr;
        return 0;
    }
    *base = (addr == 0U || addr >= SPARC64_TASK_SIZE) ? SYSMEM_MMAP_BASE :
        sysmem_align_up(addr, GUEST_PAGE_SIZE);
    if (*base == 0U || *base >= SPARC64_TASK_SIZE ||
        size > SPARC64_TASK_SIZE - *base) {
        *base = SYSMEM_MMAP_BASE;
    }
    if (!sparc64_space_find_hole(&g->space, *base, size, base) &&
        (*base == SYSMEM_MMAP_BASE ||
         !sparc64_space_find_hole(&g->space, SYSMEM_MMAP_BASE, size,
             base))) {
        return -ENOMEM;
    }
    return 0;
}

/* Robust pread loop for the file-backed fill below. */
static ssize_t sysmem_pread_all(int fd, uint64_t offset, uint8_t *dst,
    uint64_t want)
{
    uint64_t done = 0;
    while (done < want) {
        ssize_t got = pread(fd, dst + done, (size_t)(want - done),
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
    return (ssize_t)done;
}

/* File-backed range registry, truncate/resize handling, mremap
 * coverage updates, and the Provider-A populate fill live in
 * src/os/guest_run_sysmem_file.c + src/os/sysmem_file_fill.c (RC-U4
 * split, S64-R3 growth); the shells below call in through the shared
 * header so the compiler checks signatures. */
#include "os/sysmem_file.h"

long sparc64_sysmem_mmap(void *context, uint64_t addr, uint64_t len,
    unsigned prot, unsigned flags, int fd, uint64_t offset)
{
    guest_state_t *g = (guest_state_t *)context;
    uint64_t size;
    uint64_t base;
    sysmem_span_op_t pub;
    long hop;
    if (g == NULL) {
        return -EFAULT;
    }
    if (vm64_check_mmap_args(addr, len,
            ((flags & SYSMEM_MAP_ANONYMOUS) != 0U) ? UINT64_C(0) : offset,
            flags & SYSMEM_MAP_FIXED) != 0) {
        return -EINVAL;
    }
    size = sysmem_align_up(len, GUEST_PAGE_SIZE);
    if (size == 0U || size > SPARC64_TASK_SIZE) {
        return -ENOMEM;
    }
    if ((prot & ~7U) != 0U) {
        return -EINVAL;
    }
    /* W^X (H1, coordinator ruling): WX is deliberately NOT refused.
     * The platform toolchain emits RWE DSO LOADs (even libc.so.6 has
     * one, with BSS zero-fill), so refusing WX breaks all dynamic
     * loading; Linux and qemu-user both allow it. Host W^X still
     * holds: guest pages are heap-backed data the host never
     * executes. The H1 guest records WX as SKIP on allow. */
    if (((flags & (SYSMEM_MAP_PRIVATE | SYSMEM_MAP_SHARED)) == 0U) ||
        ((flags & (SYSMEM_MAP_PRIVATE | SYSMEM_MAP_SHARED)) ==
         (SYSMEM_MAP_PRIVATE | SYSMEM_MAP_SHARED))) {
        return -EINVAL;
    }
    /* S64-R9-5: unknown MAP_* bits are -EINVAL, not silent hints. */
    if ((flags & ~SYSMEM_MAP_KNOWN) != 0U) {
        return -EINVAL;
    }
    if ((flags & SYSMEM_MAP_ANONYMOUS) == 0U) {
        /* File-backed: pread probe validates fd readability. */
        uint8_t probe;
        ssize_t got = sysmem_pread_all(fd, offset, &probe, sizeof(probe));
        if (len != 0U && got < 0) {
            return -(long)errno;
        }
    }
    if ((flags & SYSMEM_MAP_FIXED_NOREPLACE) != 0U) {
        /* S64-R9-5: FIXED_NOREPLACE pins addr like FIXED but reports
         * -EEXIST when the span is occupied, never hinting elsewhere. */
        if ((addr & SYSMEM_PAGE_MASK) != 0U || addr == 0U ||
            addr >= SPARC64_TASK_SIZE ||
            size > SPARC64_TASK_SIZE - addr) {
            return -EINVAL;
        }
        if (!sysmem_span_free(g, addr, size)) {
            return -EEXIST;
        }
        base = addr;
        flags |= SYSMEM_MAP_FIXED;
    } else {
        long rc = sysmem_resolve_base(g, addr, size, flags, &base);
        if (rc != 0) {
            return rc;
        }
    }
    /* S64-R3-3: reserve the registry slots BEFORE the 6-step legs so
     * a full table reports -ENOMEM with zero mutation instead of
     * evicting a live mapping's truncate metadata. MAP_FIXED replaces
     * the destination span, so its drop-split tail is reserved too
     * (S64-R3-3 REGRESSION: claim_free can realloc mid-drop). */
    {
        size_t need = 0u;
        int is_fixed = ((flags & SYSMEM_MAP_FIXED) != 0U) ? 1 : 0;
        int is_anon = ((flags & SYSMEM_MAP_ANONYMOUS) != 0U) ? 1 : 0;
        if (is_fixed != 0) {
            need += sysmem_file_drop_extra(base, size);
        }
        if (is_anon == 0) {
            need += 1u;
        }
        if (need != 0u && sysmem_file_reserve(need) != 0) {
            return -ENOMEM;
        }
    }
    /* 6-step legs: the space publish is the host op (transactional:
     * failure leaves zero mutation); the file fill follows under the
     * same announcement with rollback on LOAD_NOMEM. */
    if (vm64_stxn_prepare() != 0) {
        return -EFAULT;
    }
    pub.g = g;
    pub.base = base;
    pub.size = size;
    pub.prot = prot & 7U;
    pub.kind = ((flags & SYSMEM_MAP_FIXED) != 0U) ? SYSOP_REPLACE :
        SYSOP_MAP;
    pub.dest = UINT64_C(0);
    pub.new_size = UINT64_C(0);
    hop = vm64_stxn_host_op(sysmem_space_op, &pub);
    if (hop != 0) {
        return hop;
    }
    /* MAP_FIXED replaces the destination span: excise tracked file
     * ranges first (reserved above, so no realloc mid-drop). */
    if ((flags & SYSMEM_MAP_FIXED) != 0U) {
        sysmem_file_drop_map(g, base, size);
    }
    if ((flags & SYSMEM_MAP_ANONYMOUS) != 0U) {
        /* Commit edge: publish done above; drop paired 4 KiB
         * Soft-TLB entries (vpn, vpn^1) and the block range. */
        sparc64_tlb_invalidate_gva(base, size);
        if (g->dbt != NULL) {
            sparc64_dbt_invalidate(g->dbt, base, size);
        }
        (void)vm64_stxn_commit(base, size);
        return (long)base;
    }
    /* RC-U4 #5: populate through vm_file_populate_segment (fresh-size
     * aware) into a bounded 8 KiB staging buffer, then into the guest
     * pages. Short files leave a zero tail and report LOAD_IO (the
     * caller keeps the mapping); LOAD_NOMEM rolls the span back. */
    {
        struct stat st;
        uint64_t fsize = UINT64_C(0xffffffffffffffff);
        uint64_t fdev = UINT64_C(0);
        uint64_t fino = UINT64_C(0);
        bool have_reg = false;
        uint64_t bus;
        uint64_t bus_len;
        /* Bounded per-8KiB-chunk state for the range entry; matches
         * SYSMEM_FILERANGE_CHUNKS in the registry TU. */
        uint8_t cstate[64];
        size_t nchunk = 0u;
        int is_private;
        int frc;
        if (fstat(fd, &st) == 0 && S_ISREG(st.st_mode) &&
            st.st_size >= 0 &&
            (uint64_t)st.st_size <= (uint64_t)INT64_MAX) {
            fsize = (uint64_t)st.st_size;
            fdev = (uint64_t)st.st_dev;
            fino = (uint64_t)st.st_ino;
            have_reg = true;
        }
        is_private = ((flags & SYSMEM_MAP_PRIVATE) != 0U) ? 1 : 0;
        frc = sysmem_file_fill(g, fd, offset, base, len, fsize,
            is_private, cstate, sizeof(cstate), &nchunk);
        if (frc == -LOAD_NOMEM) {
            /* Host-op-first abort: roll the span back (zero net
             * mutation) and drop any paired Soft-TLB coverage. */
            (void)sparc64_space_unmap(&g->space, base, size);
            sparc64_tlb_invalidate_gva(base, size);
            vm64_stxn_abort();
            return -ENOMEM;
        }
        /* Label the span for /proc/self/maps (L5a, best-effort):
         * guest fds are host fds, so readlink the translator's own
         * fd. */
        {
            char link[32];
            char target[SPARC64RT_INTERP_PATH_MAX];
            ssize_t got;
            int wn = snprintf(link, sizeof(link), "/proc/self/fd/%d",
                fd);
            if (wn > 0 && (size_t)wn < sizeof(link)) {
                got = readlink(link, target, sizeof(target) - 1U);
                if (got > 0) {
                    target[got] = '\0';
                    sparc64_guest_proc_note_map(g, base, base + size,
                        target);
                }
            }
        }
        sparc64_tlb_invalidate_gva(base, size);
        if (g->dbt != NULL) {
            sparc64_dbt_invalidate(g->dbt, base, size);
        }
        /* RC-U4: beyond-EOF full 8 KiB pages fault (SIGBUS) instead of
         * serving stale zeros: map them BUS and drop paired TLB
         * coverage. Partial tail pages stay mapped (zero-filled by the
         * fill above). */
        if (have_reg) {
            if (sysmem_file_bus_span(offset, size, fsize, &bus,
                    &bus_len)) {
                uint64_t gbus = base + (bus - offset);
                (void)sparc64_space_map_bus(&g->space, gbus, bus_len,
                    prot & 7u, true);
                sparc64_tlb_invalidate_gva(gbus, bus_len);
            }
            /* S64-R3-2/R3-3: retain the fd for later growth fills;
             * a failed note rolls the span back (zero net mutation),
             * never evicting another mapping's metadata. */
            if (sysmem_file_note_map(g, fd, fdev, fino, offset, base,
                    size, prot & 7u, is_private, cstate,
                    nchunk) != 0) {
                (void)sparc64_space_unmap(&g->space, base, size);
                sparc64_tlb_invalidate_gva(base, size);
                vm64_stxn_abort();
                return -ENOMEM;
            }
        }
    }
    (void)vm64_stxn_commit(base, size);
    return (long)base;
}

long sparc64_sysmem_munmap(void *context, uint64_t addr, uint64_t len)
{
    guest_state_t *g = (guest_state_t *)context;
    uint64_t base;
    uint64_t size;
    sysmem_span_op_t op;
    long hop;
    if (g == NULL) {
        return -EFAULT;
    }
    if (vm64_check_munmap_args(addr, len, &base, &size) != 0) {
        return -EINVAL;
    }
    /* 6-step legs: unmap tolerates holes (no failure leg); commit then
     * drops paired Soft-TLB entries and the block-cache range.
     * S64-R3-3 REGRESSION: reserve the drop-split tail BEFORE the legs
     * so claim_free cannot realloc mid-drop. S64-R4-5: a reserve miss
     * reports -ENOMEM with zero mutation instead of silently dropping
     * the surviving tail's truncate metadata. */
    if (sysmem_file_reserve(sysmem_file_drop_extra(base, size)) != 0) {
        return -ENOMEM;
    }
    if (vm64_stxn_prepare() != 0) {
        return -EFAULT;
    }
    op.g = g;
    op.base = base;
    op.size = size;
    op.prot = 0U;
    op.kind = SYSOP_UNMAP;
    op.dest = UINT64_C(0);
    op.new_size = UINT64_C(0);
    hop = vm64_stxn_host_op(sysmem_space_op, &op);
    if (hop != 0) {
        return hop;
    }
    sparc64_tlb_invalidate_gva(base, size);
    if (g->dbt != NULL) {
        sparc64_dbt_invalidate(g->dbt, base, size);
    }
    if (base >= g->brk_base && base < g->brk_cur &&
        base + size >= g->brk_cur) {
        g->brk_cur = base;
    }
    /* RC-U4: an unmapped file range must not linger in the registry,
     * or a later truncate would BUS or restore the wrong addresses. */
    sysmem_file_drop_map(g, base, size);
    (void)vm64_stxn_commit(base, size);
    return 0;
}

long sparc64_sysmem_mprotect(void *context, uint64_t addr, uint64_t len,
    unsigned prot)
{
    guest_state_t *g = (guest_state_t *)context;
    uint64_t size;
    sysmem_span_op_t op;
    long hop;
    if (g == NULL) {
        return -EFAULT;
    }
    if ((prot & ~7U) != 0U) {
        return -EINVAL;
    }
    {
        int chk = vm64_check_mprotect_args(addr, len, &size);
        if (chk != 0) {
            return (long)chk;
        }
    }
    /* 6-step legs: protect mutates nothing unless every page is mapped
     * (zero-mutation abort otherwise); commit invalidates the span.
     * S64-R4-6: reserve the protect-split slots BEFORE the legs so the
     * registry update below cannot fail mid-mutation; a reserve miss
     * reports -ENOMEM with zero mutation. */
    if (sysmem_file_reserve(sysmem_file_protect_extra(addr, size)) != 0) {
        return -ENOMEM;
    }
    if (vm64_stxn_prepare() != 0) {
        return -EFAULT;
    }
    op.g = g;
    op.base = addr;
    op.size = size;
    op.prot = prot & 7U;
    op.kind = SYSOP_PROTECT;
    op.dest = UINT64_C(0);
    op.new_size = UINT64_C(0);
    /* Every page must be mapped (Linux reports ENOMEM otherwise). */
    hop = vm64_stxn_host_op(sysmem_space_op, &op);
    if (hop != 0) {
        return hop;
    }
    /* Commit edge: permission change drops paired Soft-TLB entries
     * (write-tag gating) and the block-cache range. */
    sparc64_tlb_invalidate_gva(addr, size);
    if (g->dbt != NULL) {
        sparc64_dbt_invalidate(g->dbt, addr, size);
    }
    /* S64-R4-6: the registry tracks the new permissions (split-aware),
     * so a later truncate resize restores the current prot instead of
     * the stale one (reserved above: no split can fail mid-update). */
    sysmem_file_protect_update(g, addr, size, prot & 7U);
    (void)vm64_stxn_commit(addr, size);
    return 0;
}

/* Permission probe over an 8 KiB-rounded span: every 4 KiB sub-page must
 * exist (full coverage), and the result is the intersection of the
 * sub-page permissions. All engine mutations are 8 KiB-granular with
 * uniform permissions per span, so mixed spans do not arise in practice;
 * the intersection is the fail-closed choice if one ever does. */
static bool sysmem_span_perms(guest_state_t *g, uint64_t base, uint64_t len,
    unsigned *perms_out)
{
    uint64_t off;
    unsigned perms = 7U;
    for (off = 0U; off < len; off += SYSMEM_SUB_PAGE) {
        bool found = false;
        size_t i;
        for (i = 0; i < g->space.count; i++) {
            if (g->space.pages[i].address == base + off) {
                perms &= g->space.pages[i].permissions;
                found = true;
                break;
            }
        }
        if (!found) {
            return false;
        }
    }
    if (perms_out != NULL) {
        *perms_out = perms;
    }
    return true;
}

/* Range overlap test for the FIXED destination check. */
static bool sysmem_overlap(uint64_t a_base, uint64_t a_len, uint64_t b_base,
    uint64_t b_len)
{
    return a_base < b_base + b_len && b_base < a_base + a_len;
}

/* Free-span probe for in-place mremap growth: true when no page in
 * [base, base + len) is mapped. A partially occupied tail is not free
 * (the substrate would replace those pages). */
static bool sysmem_span_free(guest_state_t *g, uint64_t base, uint64_t len)
{
    uint64_t off;
    size_t i;
    for (off = 0U; off < len; off += SYSMEM_SUB_PAGE) {
        for (i = 0; i < g->space.count; i++) {
            if (g->space.pages[i].address == base + off) {
                return false;
            }
        }
    }
    return true;
}

/* Guest mremap(250) on the 8 KiB ABI granule. The old address must be
 * 8 KiB-aligned (-EINVAL otherwise, like Linux); both sizes round up to
 * 8 KiB. Shrink (or same-size without FIXED) completes in place;
 * growth extends in place past a free tail, else relocates via
 * MREMAP_MAYMOVE (map/copy/unmap through the transactional substrate,
 * which preserves bytes and permissions); without MAYMOVE and no free
 * tail the answer is -ENOMEM. MREMAP_FIXED needs MAYMOVE, an
 * 8 KiB-aligned non-overlapping target, and replaces the destination
 * (matching Linux). Unmapped sources read as -EFAULT (verified against
 * Linux aarch64); resource exhaustion reads as -ENOMEM. */
long sparc64_sysmem_mremap(void *context, uint64_t old_addr,
    uint64_t old_size, uint64_t new_size, unsigned flags, uint64_t new_addr)
{
    guest_state_t *g = (guest_state_t *)context;
    uint64_t old_len;
    uint64_t new_len;
    uint64_t dest;
    unsigned perms = 7U;
    sysmem_span_op_t op;
    long hop;
    sysmem_file_range_t *snap = NULL;
    size_t snap_cap = 0u;
    if (g == NULL) {
        return -EFAULT;
    }
    if (vm64_check_mremap_args(old_addr, old_size, new_size, flags,
            new_addr) != 0) {
        return -EINVAL;
    }
    old_len = sysmem_align_up(old_size, GUEST_PAGE_SIZE);
    new_len = sysmem_align_up(new_size, GUEST_PAGE_SIZE);
    if (new_len == old_len && (flags & SYSMEM_MREMAP_FIXED) == 0U) {
        /* S64-R9-4: the shortcut still needs a mapped source. */
        if (!sysmem_span_perms(g, old_addr, old_len, &perms)) {
            return -EFAULT;
        }
        return (long)old_addr;
    }
    if ((flags & SYSMEM_MREMAP_FIXED) != 0U) {
        /* FIXED relocates; same-address same-size FIXED is -EINVAL on
         * Linux, and overlapping ranges are -EINVAL too. */
        if (new_addr == old_addr && new_len == old_len) {
            return -EINVAL;
        }
        if (sysmem_overlap(new_addr, new_len, old_addr, old_len)) {
            return -EINVAL;
        }
        dest = new_addr;
        if (!sysmem_span_perms(g, old_addr, old_len, &perms)) {
            return -EFAULT;
        }
    } else if (new_len < old_len) {
        /* Shrink in place: drop the tail (holes tolerated, like the
         * munmap path above). S64-R3-3: reserve before the legs so
         * the coverage trim cannot realloc mid-update. */
        if (sysmem_file_reserve(sysmem_file_span_extra(old_addr,
                old_len, old_addr, new_len)) != 0) {
            return -ENOMEM;
        }
        if (vm64_stxn_prepare() != 0) {
            return -EFAULT;
        }
        op.g = g;
        op.base = old_addr + new_len;
        op.size = old_len - new_len;
        op.prot = 0U;
        op.kind = SYSOP_UNMAP;
        op.dest = UINT64_C(0);
        op.new_size = UINT64_C(0);
        hop = vm64_stxn_host_op(sysmem_space_op, &op);
        if (hop != 0) {
            return hop;
        }
        sparc64_tlb_invalidate_gva(old_addr, old_len);
        if (g->dbt != NULL) {
            sparc64_dbt_invalidate(g->dbt, old_addr, old_len);
        }
        if (old_addr + new_len >= g->brk_base &&
            old_addr + new_len < g->brk_cur &&
            old_addr + old_len >= g->brk_cur) {
            g->brk_cur = old_addr + new_len;
        }
        /* RC-U4 #4: trim the tracked coverage to the shrunken length
         * (the dropped tail must not receive truncate updates). */
        sysmem_file_remap_update(g, old_addr, old_len, old_addr,
            new_len);
        (void)vm64_stxn_commit(old_addr, old_len);
        return (long)old_addr;
    } else if (new_len > SPARC64_TASK_SIZE - (old_addr + old_len) ||
        !sysmem_span_free(g, old_addr + old_len, new_len - old_len)) {
        /* No free tail past the span: relocate when MAYMOVE allows,
         * else -ENOMEM like Linux. A source with holes reads as
         * -EFAULT (the remap below enforces full coverage). */
        long rc;
        if ((flags & SYSMEM_MREMAP_MAYMOVE) == 0U) {
            return -ENOMEM;
        }
        rc = sysmem_resolve_base(g, 0U, new_len, 0U, &dest);
        if (rc != 0) {
            return rc;
        }
        if (!sysmem_span_perms(g, old_addr, old_len, &perms)) {
            return -EFAULT;
        }
    } else {
        /* Free tail: extend in place (needs no MAYMOVE, like Linux). */
        if (!sysmem_span_perms(g, old_addr, old_len, &perms)) {
            return -EFAULT;
        }
        dest = old_addr;
    }
    /* S64-R3-3: reserve the worst-case registry slots BEFORE the
     * 6-step legs (straddler splits + destination excision), so the
     * coverage update below cannot fail mid-mutation. S64-R4-3:
     * snapshot the registry too, so a failed growth fill can restore
     * the pre-relocation coverage exactly; either failure below
     * reports -ENOMEM with zero mutation. */
    if (sysmem_file_reserve(sysmem_file_span_extra(old_addr, old_len,
            dest, new_len)) != 0) {
        return -ENOMEM;
    }
    if (sysmem_file_snapshot(&snap, &snap_cap) != 0) {
        return -ENOMEM;
    }
    if (vm64_stxn_prepare() != 0) {
        sysmem_file_snapshot_discard(snap, snap_cap);
        return -EFAULT;
    }
    op.g = g;
    op.base = old_addr;
    op.size = old_len;
    op.prot = perms;
    op.kind = SYSOP_REMAP;
    op.dest = dest;
    op.new_size = new_len;
    hop = vm64_stxn_host_op(sysmem_space_op, &op);
    if (hop != 0) {
        /* The substrate stamps fault_reason: unmapped source reads as
         * -EFAULT (Linux class), range faults as -EINVAL, everything
         * else (resource/internal) as -ENOMEM. */
        sysmem_file_snapshot_discard(snap, snap_cap);
        if (g->space.fault_reason == SPARC64_FAULT_UNMAPPED) {
            return -EFAULT;
        }
        if (g->space.fault_reason == SPARC64_FAULT_RANGE) {
            return -EINVAL;
        }
        return -ENOMEM;
    }
    /* Commit edge: both spans drop paired Soft-TLB entries and the
     * block-cache ranges. */
    sparc64_tlb_invalidate_gva(old_addr, old_len);
    sparc64_tlb_invalidate_gva(dest, new_len);
    if (g->dbt != NULL) {
        sparc64_dbt_invalidate(g->dbt, old_addr, old_len);
        sparc64_dbt_invalidate(g->dbt, dest, new_len);
    }
    /* RC-U4 #4: a moved file mapping keeps its (possibly BUS) pages;
     * rebase the tracked coverage to the destination (trimming past a
     * shrunken length, covering an extension tail) so a later truncate
     * still BUSes or restores the right addresses. Straddlers split
     * (unmoved head/tail stay, the middle moves); replaced destination
     * spans excise the same split-aware way. */
    sysmem_file_remap_update(g, old_addr, old_len, dest, new_len);
    /* S64-R3-2: grow the tail through the file-population/EOF path
     * (MAP_SHARED and MAP_PRIVATE alike, with beyond-EOF BUS
     * classification) before committing, so an 8 KiB mapping of a
     * larger file grown past its end serves file bytes, not zeros. */
    if (new_len > old_len) {
        long frc = (long)sysmem_file_fill_growth(g, dest, old_len,
            new_len);
        if (frc == -12L) {
            /* S64-R4-3: the relocation published but the growth tail
             * rejected the fill. Roll everything back: drop the fresh
             * tail, move the relocated head back to the source (the
             * substrate reuses the same backings, so the source bytes
             * are intact), restore the registry snapshot, invalidate
             * both spans, and bump the code generation (mappings
             * changed under the announcement, which aborts without
             * bumping). A failed move-back keeps the relocated state
             * (with its matching mutated registry) instead of
             * restoring half. */
            int space_ok = 1;
            sysmem_span_op_t tail;
            tail.g = g;
            tail.base = dest + old_len;
            tail.size = new_len - old_len;
            tail.prot = 0U;
            tail.kind = SYSOP_UNMAP;
            tail.dest = UINT64_C(0);
            tail.new_size = UINT64_C(0);
            (void)sysmem_space_op(&tail);
            if (dest != old_addr) {
                sysmem_span_op_t back;
                back.g = g;
                back.base = dest;
                back.size = old_len;
                back.prot = perms;
                back.kind = SYSOP_REMAP;
                back.dest = old_addr;
                back.new_size = old_len;
                space_ok = (sysmem_space_op(&back) == 0);
            }
            if (space_ok) {
                sysmem_file_restore(snap, snap_cap);
                /* S64-R4-3 residual: the restored snapshot still
                 * covers the excised destination, which is now
                 * unmapped (head moved back, tail dropped). */
                if (dest != old_addr) {
                    sysmem_file_drop_map(g, dest, new_len);
                }
            } else {
                sysmem_file_snapshot_discard(snap, snap_cap);
            }
            snap = NULL;
            sparc64_tlb_invalidate_gva(old_addr, old_len);
            sparc64_tlb_invalidate_gva(dest, new_len);
            if (g->dbt != NULL) {
                sparc64_dbt_invalidate(g->dbt, old_addr, old_len);
                sparc64_dbt_invalidate(g->dbt, dest, new_len);
            }
            vm64_code_epoch_bump();
            vm64_stxn_abort();
            return -ENOMEM;
        }
    }
    if (old_addr != dest && old_addr >= g->brk_base &&
        old_addr < g->brk_cur && old_addr + old_len >= g->brk_cur) {
        g->brk_cur = dest + (g->brk_cur - old_addr);
    }
    sysmem_file_snapshot_discard(snap, snap_cap);
    (void)vm64_stxn_commit(dest, new_len);
    return (long)dest;
}

/* Guest madvise(75) on the 8 KiB ABI granule (S64-R9-6): 8 KiB-aligned
 * addr (-EINVAL), zero length succeeds, benign advices validate and
 * return 0, DONTNEED zeroes (with COW promotion) and runs the SMC
 * sequence, unknown advices are -EINVAL, holes are -ENOMEM. */
#define SYSMEM_MADV_NORMAL 0U
#define SYSMEM_MADV_RANDOM 1U
#define SYSMEM_MADV_SEQUENTIAL 2U
#define SYSMEM_MADV_WILLNEED 3U
#define SYSMEM_MADV_DONTNEED 4U
#define SYSMEM_MADV_DONTFORK 10U
long sparc64_sysmem_madvise(void *context, uint64_t addr, uint64_t len,
    uint64_t advice)
{
    guest_state_t *g = (guest_state_t *)context;
    uint64_t size;
    uint64_t off;
    unsigned perms = 7U;
    if (g == NULL) {
        return -EFAULT;
    }
    if ((addr & (GUEST_PAGE_SIZE - UINT64_C(1))) != UINT64_C(0)) {
        return -EINVAL;
    }
    if (len == 0U) {
        return 0;
    }
    switch (advice) {
    case (uint64_t)SYSMEM_MADV_NORMAL:
    case (uint64_t)SYSMEM_MADV_RANDOM:
    case (uint64_t)SYSMEM_MADV_SEQUENTIAL:
    case (uint64_t)SYSMEM_MADV_WILLNEED:
    case (uint64_t)SYSMEM_MADV_DONTNEED:
    case (uint64_t)SYSMEM_MADV_DONTFORK:
        break;
    default:
        return -EINVAL;
    }
    if (addr >= SPARC64_TASK_SIZE || len > SPARC64_TASK_SIZE - addr) {
        return -ENOMEM;
    }
    size = sysmem_align_up(len, GUEST_PAGE_SIZE);
    if (size == 0U || size > SPARC64_TASK_SIZE - addr) {
        return -ENOMEM;
    }
    if (!sysmem_span_perms(g, addr, size, &perms)) {
        return -ENOMEM;
    }
    if (advice != (uint64_t)SYSMEM_MADV_DONTNEED) {
        return 0;
    }
    if ((perms & (unsigned)SPARC64_MEM_WRITE) != 0U) {
        uint8_t zeros[512] = { 0 };
        for (off = 0U; off < size; off += (uint64_t)sizeof(zeros)) {
            uint64_t chunk = size - off;
            if (chunk > (uint64_t)sizeof(zeros)) {
                chunk = (uint64_t)sizeof(zeros);
            }
            if (!sparc64_space_write(&g->space, addr + off, zeros,
                    (size_t)chunk)) {
                return -ENOMEM;
            }
        }
        sysmem_file_note_write(g, addr, size);
    }
    sparc64_tlb_evict_writes(addr, size);
    if (g->dbt != NULL) {
        sparc64_dbt_invalidate(g->dbt, addr, size);
    }
    vm64_code_epoch_bump();
    return 0;
}

