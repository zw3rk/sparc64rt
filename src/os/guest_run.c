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
/* Needs _GNU_SOURCE: musl hides syscall(2) under -std=c11. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#include "core/cpu.h"
#include "os/guest_proc.h"
#include "os/guest_run.h"
#include "os/guest_run_priv.h"
#include "dbt/dbt.h"
#include "dbt/difftest.h"
#include "dbt/mem_sites.h"
#include "os/sync_sig.h"
#include "os/syscall_nr.h"
#include "os/syscalls_min.h"
#include "os/guest_interp_map.h"
#include "os/mem_space.h"

/* ---- Guest ABI constants (SPARC Linux, arch/sparc) --------------------- */
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
#define GUEST_MMAP_BASE UINT64_C(0x6000000000)
#define GUEST_DYN_BIAS UINT64_C(0x4000000000)

/* SPARC mmap(71) flags (asm/mman.h). */
#define GUEST_MAP_SHARED 0x01U
#define GUEST_MAP_PRIVATE 0x02U
#define GUEST_MAP_FIXED 0x10U
#define GUEST_MAP_ANONYMOUS 0x20U

/* Loader mapping granule (Phase 5, L5a): PT_LOAD spans round to the
 * reported guest page size (8K), not the 4K syscall granule, so the
 * 8K-rounded RELRO mprotect ld.so issues stays inside the mapping. */
#define GUEST_MAP_GRANULE GUEST_AT_PAGESZ_VALUE
#define GUEST_MAP_GRANULE_MASK (GUEST_AT_PAGESZ_VALUE - UINT64_C(1))

/* Stack synthesis lives in guest_stack.c; loader outcomes in
 * guest_run_priv.h. */

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

/* Memory bridges (guest_mem_ops and the byte-level read/write/atomic
 * helpers) live in src/os/guest_run_mem.c (Phase 6, L6a split for the
 * line limit); the syscall read/write/prepare_write helpers and the
 * mmap/munmap/mprotect/mremap bodies live in src/os/guest_run_sysmem.c
 * (Lane A2 split for the same limit), declared locally below so this TU
 * keeps no shared header beyond guest_run_priv.h. */

/* Lane A2 sysmem cluster (defined in src/os/guest_run_sysmem.c). */
extern bool sparc64_sysmem_read(void *context, uint64_t va, void *host,
    uint64_t len);
extern bool sparc64_sysmem_write(void *context, uint64_t va,
    const void *host, uint64_t len);
extern bool sparc64_sysmem_prepare_write(void *context, uint64_t va,
    uint64_t len);
extern long sparc64_sysmem_mmap(void *context, uint64_t addr, uint64_t len,
    unsigned prot, unsigned flags, int fd, uint64_t offset);
extern long sparc64_sysmem_munmap(void *context, uint64_t addr,
    uint64_t len);
extern long sparc64_sysmem_mprotect(void *context, uint64_t addr,
    uint64_t len, unsigned prot);

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
    if (g->dbt != NULL && target != cur) {
        sparc64_dbt_invalidate(g->dbt, 0U, SPARC64_TASK_SIZE);
    }
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

const sparc64_syscall_mem_t *sysmem_ops(guest_state_t *g,
                                               sparc64_syscall_mem_t *ops)
{
    ops->context = g;
    ops->read = sparc64_sysmem_read;
    ops->write = sparc64_sysmem_write;
    ops->prepare_write = sparc64_sysmem_prepare_write;
    ops->do_mmap = sparc64_sysmem_mmap;
    ops->do_munmap = sparc64_sysmem_munmap;
    ops->do_mprotect = sparc64_sysmem_mprotect;
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
 * segment's file bytes always win over an earlier BSS. PT_INTERP is
 * collected into interp_out (empty when static) for the Phase-5
 * dynamic path. hi_out receives the post-image break, phdr_va_out
 * the VA of the program-header table. */
static int load_segments(int fd, guest_state_t *g, uint64_t bias,
                         uint64_t phoff, uint32_t phnum, uint64_t file_phoff,
                         uint64_t *hi_out, uint64_t *phdr_va_out,
                         char *interp_out, const char *map_label)
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
            /* Dynamic guest: stash the path for interp_map (a second
             * PT_INTERP or an overlong path is rejected). */
            uint64_t ilen = rd64be(phdr + 32);
            uint64_t ioff = rd64be(phdr + 8);
            uint64_t imoved = 0;
            if (interp_out == NULL || interp_out[0] != '\0' ||
                ilen < 2U ||
                ilen > (uint64_t)SPARC64RT_INTERP_PATH_MAX) {
                return -LOAD_BAD;
            }
            if (read_at(fd, ioff, (uint8_t *)interp_out, ilen,
                    &imoved) != 0 ||
                imoved != ilen ||
                interp_out[ilen - 1U] != '\0' ||
                memchr(interp_out, '\0', (size_t)ilen - 1U) != NULL) {
                interp_out[0] = '\0';
                return -LOAD_BAD;
            }
            continue;
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
        /* Round to the 8K loader granule (see GUEST_MAP_GRANULE);
         * overlapping rounded spans union perms harmlessly. */
        start = align_down(p_vaddr, GUEST_MAP_GRANULE);
        end = align_up(p_vaddr + p_memsz, GUEST_MAP_GRANULE);
        if (end <= start || end - start > SPARC64_TASK_SIZE ||
            start < GUEST_PAGE_SIZE || end > SPARC64_TASK_SIZE) {
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
        if (map_label != NULL) {
            sparc64_guest_proc_note_map(g, start, end, map_label);
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

/* Dynamic tail (L5a): resolve PT_INTERP via SPARC64RT_SYSROOT
 * (else /), map ld.so, return its entry/base (app keeps AT_ENTRY). */
static int load_interp(guest_state_t *g, const char *interp,
                       uint64_t *entry_out, uint64_t *base_out,
                       char *resolved_out)
{
    const char *sysroot = getenv("SPARC64RT_SYSROOT");
    int ifd = -1, mrc;
    uint64_t hi = 0;
    if (sparc64_interp_resolve(interp, sysroot, resolved_out,
            SPARC64RT_INTERP_PATH_MAX) != 0) {
        return -LOAD_BAD;
    }
    ifd = open(resolved_out, O_RDONLY | O_CLOEXEC);
    if (ifd < 0) {
        return -LOAD_IO;
    }
    mrc = sparc64_interp_map(&g->space, ifd, entry_out, base_out, &hi);
    (void)close(ifd);
    if (mrc != 0) {
        return (mrc == -ENOEXEC) ? -LOAD_BAD : -LOAD_NOMEM;
    }
    sparc64_guest_proc_note_map(g, *base_out, hi, resolved_out);
    return LOAD_OK;
}

/* ---- Entry point (stack synthesis lives in guest_stack.c) ------------------ */
int sparc64_guest_run(const char *path, char **argv, int interp_only)
{
    return sparc64_guest_run_engine(path, argv, interp_only != 0 ? 0 : 1);
}

int sparc64_guest_run_engine(const char *path, char **argv, int engine)
{
    return sparc64_guest_run_full(path, -1, NULL, argv, engine);
}

/* Phase 6 (L6a) host-contract entry: image_fd >= 0 loads the ELF via
 * position-independent reads from the borrowed descriptor (never closed,
 * so guest fds 0,1,2 and inherited >= 3 are untouched); otherwise path is
 * opened and the loader-private fd is closed after mapping. execfn NULL
 * keeps argv[0] as AT_EXECFN and path as /proc/self/exe; otherwise both
 * name the execfn path while argv stays verbatim. */
int sparc64_guest_run_full(const char *path, int image_fd,
    const char *execfn, char **argv, int engine)
{
    guest_state_t g;
    guest_image_t img;
    sparc64_ctx_t ctx;
    sparc64_syscall_mem_t ops_storage;
    const sparc64_syscall_mem_t *ops;
    uint64_t bias = 0, guest_phdr = 0, heap_hi = 0, sp = 0, argc = 0;
    uint64_t start_entry = 0, interp_base = 0;
    char interp[SPARC64RT_INTERP_PATH_MAX];
    char resolved[SPARC64RT_INTERP_PATH_MAX];
    char *synthetic[2];
    const char *display;
    int owned;
    int fd = -1;
    int rc;
    memset(&g, 0, sizeof(g));
    memset(&img, 0, sizeof(img));
    memset(interp, 0, sizeof(interp));
    memset(resolved, 0, sizeof(resolved));
    if (path == NULL && image_fd < 0 && execfn == NULL) {
        (void)fprintf(stderr, "sparc64rt: no guest image\n");
        return 1;
    }
    if (engine < 0 || engine > 2) {
        (void)fprintf(stderr, "sparc64rt: unknown engine %d\n", engine);
        return 1;
    }
    display = (execfn != NULL) ? execfn :
        ((path != NULL) ? path : "guest image");
    if (argv == NULL || argv[0] == NULL) {
        synthetic[0] = (char *)((path != NULL) ? path : display);
        synthetic[1] = NULL;
        argv = synthetic;
        argc = 1;
    } else {
        argc = count_strings(argv, GUEST_MAX_ARGC + 1U);
    }
    owned = (image_fd < 0);
    if (owned) {
        if (path == NULL) {
            (void)fprintf(stderr, "sparc64rt: no guest image\n");
            return 1;
        }
        fd = open(path, O_RDONLY | O_CLOEXEC);
        if (fd < 0) {
            (void)fprintf(stderr, "sparc64rt: cannot open '%s': %s\n", path,
                          strerror(errno));
            return 1;
        }
    } else {
        fd = image_fd;
    }
    sparc64_space_init(&g.space, 64);
    g.space_live = 1;
    g.host_tid = (long)getpid();
    rc = load_ehdr(fd, &img, &bias);
    if (rc != 0) {
        (void)fprintf(stderr, "sparc64rt: '%s' is not a SPARC64 ELF\n",
                      display);
        goto fail;
    }
    rc = load_segments(fd, &g, bias, img.phoff, img.phnum, img.phoff,
                       &heap_hi, &guest_phdr, interp, display);
    if (rc != 0) {
        (void)fprintf(stderr, "sparc64rt: cannot load '%s'\n", display);
        goto fail;
    }
    start_entry = img.entry;
    if (interp[0] != '\0') {
        uint64_t ld_entry = 0, ld_base = 0;
        rc = load_interp(&g, interp, &ld_entry, &ld_base, resolved);
        if (rc != 0) {
            (void)fprintf(stderr,
                          "sparc64rt: cannot map interpreter '%s'\n",
                          display);
            goto fail;
        }
        start_entry = ld_entry;
        interp_base = ld_base;
    }
    g.brk_base = align_up(heap_hi, GUEST_PAGE_SIZE);
    g.brk_cur = g.brk_base;
    if (interp_base != UINT64_C(0)) {
        rc = build_stack_dyn(&g, guest_phdr, img.entry, img.phnum,
                             img.phent, interp_base, argv, argc, execfn,
                             &sp);
    } else {
        rc = build_stack(&g, guest_phdr, img.entry, img.phnum, img.phent,
                         argv, argc, execfn, &sp);
    }
    if (rc != 0) {
        (void)fprintf(stderr, "sparc64rt: cannot build the guest stack\n");
        goto fail;
    }
    sparc64_guest_proc_note_exec(&g, display);
    if (owned) {
        (void)close(fd);
        fd = -1;
    }
    sparc64_ctx_init(&ctx, start_entry);
    ctx.r[SPARC64_SP] = sp;
    /* Fresh windows (E01): CWP 0, no invalid windows, so the first
     * SAVE/RESTORE pair rotates in-register without spill/fill. */
    ctx.cwp = 0U;
    ctx.cansave = (uint32_t)(SPARC64_NWINDOWS - 1U);
    ops = sysmem_ops(&g, &ops_storage);
    if (engine == 2) {
        rc = run_difftest(&g, &ctx, ops);
    } else if (engine == 1) {
        rc = run_dbt(&g, &ctx, ops);
    } else {
        rc = run_interp(&g, &ctx, ops);
    }
    if (rc == 0) {
        sparc64_space_destroy(&g.space);
        g.space_live = 0;
    }
fail:
    if (owned && fd >= 0) {
        (void)close(fd);
    }
    if (g.space_live) {
        sparc64_space_destroy(&g.space);
        g.space_live = 0;
    }
    sparc64_guest_proc_forget(&g);
    /* Loader/runner failures collapse to 1; guest and difftest codes
     * (including difftest's 2 = agreement without exit) pass through. */
    return rc < 0 ? 1 : rc;
}

/* ---- Phase 4 (L4c): full image replacement for execve(59) -------------- */
/* Loads path with host argv into a scratch state, then commits it over
 * the current space and re-inits ctx at the new entry. A bad image
 * leaves the old space intact (Linux execve atomicity); only a fully
 * stacked image commits. The caller swaps the translator's environ to
 * the guest envp across this call (build_stack consumes it) and resets
 * signal state afterwards. */
int sparc64_guest_exec_image(guest_state_t *g, sparc64_ctx_t *ctx,
    const char *path, char **argv)
{
    guest_state_t ng;
    guest_image_t img;
    uint64_t bias = 0, guest_phdr = 0, heap_hi = 0, sp = 0, argc = 0;
    char img_path[SPARC64RT_INTERP_PATH_MAX];
    int fd = -1;
    int rc;
    if (g == NULL || ctx == NULL || path == NULL || argv == NULL) {
        return -EFAULT;
    }
    argc = count_strings(argv, GUEST_MAX_ARGC + 1U);
    if (argc == 0U || argc > (uint64_t)GUEST_MAX_ARGC) {
        return -E2BIG;
    }
    fd = sparc64_proc_open_exec(g, path, img_path, &path);
    if (fd < 0) {
        return fd;
    }
    memset(&img, 0, sizeof(img));
    rc = load_ehdr(fd, &img, &bias);
    if (rc != 0) {
        (void)close(fd);
        return -ENOEXEC;
    }
    uint64_t start_entry = img.entry, interp_base = 0;
    char interp[SPARC64RT_INTERP_PATH_MAX];
    char resolved[SPARC64RT_INTERP_PATH_MAX];
    memset(&ng, 0, sizeof(ng));
    memset(interp, 0, sizeof(interp));
    memset(resolved, 0, sizeof(resolved));
    sparc64_space_init(&ng.space, 64);
    ng.space_live = 1;
    ng.dbt = g->dbt;
    ng.host_tid = (long)getpid();
    ng.tid_addr = 0U;
    rc = load_segments(fd, &ng, bias, img.phoff, img.phnum, img.phoff,
        &heap_hi, &guest_phdr, interp, path);
    (void)close(fd);
    fd = -1;
    if (rc != 0) {
        sparc64_space_destroy(&ng.space);
        sparc64_guest_proc_forget(&ng);
        return (rc == -LOAD_NOMEM) ? -ENOMEM : -ENOEXEC;
    }
    if (interp[0] != '\0') {
        uint64_t ld_entry = 0, ld_base = 0;
        rc = load_interp(&ng, interp, &ld_entry, &ld_base, resolved);
        if (rc != 0) {
            sparc64_space_destroy(&ng.space);
            sparc64_guest_proc_forget(&ng);
            return (rc == -LOAD_NOMEM) ? -ENOMEM : -ENOEXEC;
        }
        start_entry = ld_entry;
        interp_base = ld_base;
    }
    ng.brk_base = align_up(heap_hi, GUEST_PAGE_SIZE);
    ng.brk_cur = ng.brk_base;
    if (interp_base != UINT64_C(0)) {
        rc = build_stack_dyn(&ng, guest_phdr, img.entry, img.phnum,
            img.phent, interp_base, argv, argc, NULL, &sp);
    } else {
        rc = build_stack(&ng, guest_phdr, img.entry, img.phnum, img.phent,
            argv, argc, NULL, &sp);
    }
    if (rc != 0) {
        sparc64_space_destroy(&ng.space);
        sparc64_guest_proc_forget(&ng);
        return rc;
    }
    sparc64_guest_proc_note_exec(&ng, path);
    /* Commit: move the fresh registry over the old space. Both spaces
     * use the default heap factory (no external managed context), so
     * the struct move transfers ownership cleanly. The fresh proc
     * snapshot replaces the old one (execve atomicity). */
    if (g->space_live) {
        sparc64_space_destroy(&g->space);
        g->space_live = 0;
    }
    sparc64_guest_proc_forget(g);
    g->space = ng.space;
    g->space_live = 1;
    ng.space_live = 0;
    g->proc = ng.proc;
    ng.proc = NULL;
    g->brk_base = ng.brk_base;
    g->brk_cur = ng.brk_cur;
    g->tid_addr = 0U;
    g->host_tid = (long)getpid();
    sparc64_ctx_init(ctx, start_entry);
    ctx->r[SPARC64_SP] = sp;
    /* Fresh windows (E01): CWP 0, no invalid windows, so the first
     * SAVE/RESTORE pair rotates in-register without spill/fill. */
    ctx->cwp = 0U;
    ctx->cansave = (uint32_t)(SPARC64_NWINDOWS - 1U);
    return 0;
}
