/*
 * tests/test_h1_smc.c -- Phase 7 lane H1: SMC + W^X probe.
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Static glibc SPARC64 guest exercising self-modifying code (SMC) in
 * three memory kinds plus the SPARC FLUSH instruction, and the W^X
 * leg. Each SMC leg stages a 3-instruction leaf stub (or %g0,VAL,%o0;
 * jmpl %o7+8,%g0; nop), flushes it, flips the page(s) to
 * PROT_READ|PROT_EXEC, executes the stub, flips back to RW, rewrites
 * the stub with a new return value, flushes again, re-flips, and
 * re-executes: the second execution must observe the NEW bytes. The
 * mprotect flip is also what invalidates the translator's DBT block
 * cache (sparc64_dbt_invalidate). Regions: a stack buffer, heap
 * (malloc), and one anonymous mmap. The W^X leg asserts mmap/mprotect
 * with PROT_WRITE|PROT_EXEC fail while an RX-flipped page executes.
 * Deterministic stdout (fixed strings only); exit 0 with H1-SMC-PASS
 * iff every check passed, else H1-SMC-FAIL n=<fails> with exit 1.
 *
 * Build (from the worktree root, in the lane container):
 *   sparc64-linux-gnu-gcc -static -O2 -o _build/guest_h1smc \
 *     tests/test_h1_smc.c
 * Oracle:
 *   qemu-sparc64 _build/guest_h1smc
 * Acceptance (oracle vs --interp vs --dbt bit-for-bit, --difftest clean):
 *   qemu-sparc64 _build/guest_h1smc >o.txt; \
 *   ./_build/sparc64rt --interp _build/guest_h1smc >i.txt; \
 *   ./_build/sparc64rt --dbt _build/guest_h1smc >d.txt; \
 *   cmp o.txt i.txt && cmp o.txt d.txt && \
 *   ./_build/sparc64rt --difftest _build/guest_h1smc | grep '0 divergences'
 */
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

static volatile int fails = 0;

/* SPARC V9 leaf stub words: or %g0,VAL,%o0 (i=1: 0x90102000|VAL);
 * jmpl %o7+8,%g0; nop. */
#define SMC_OP_OR 0x90102000U
#define SMC_OP_JMPL 0x81c3e008U
#define SMC_OP_NOP 0x01000000U

static void *h1_fn;
static int h1_ret;

/* Indirect call with no C-level call frame traffic: the SMC target is
 * invoked with a raw jmpl and its %o0 result stored to a global, so
 * the stack page can stay PROT_EXEC across the call window. */
static int call_nostack(void)
{
    /* Linked jmpl into the SMC stub: %o7 is parked in %g1 first so
     * the stub's `jmpl %o7+8` lands on the restore below, and the
     * real return address is live again for the function epilogue. */
    __asm__ volatile (
        "mov %%o7, %%g1\n\t"
        "ldx [%1], %%o1\n\t"
        "jmpl %%o1 + %%g0, %%o7\n\t"
        " nop\n\t"
        "mov %%g1, %%o7\n\t"
        "st %%o0, [%0]"
        :
        : "r" (&h1_ret), "r" (&h1_fn)
        : "o0", "o1", "o7", "g1", "memory");
    return h1_ret;
}

static void sparc_flush(void *p)
{
    /* Flush both cache lines the 12-byte stub can touch. */
    __asm__ volatile ("flush %0" :: "r" (p) : "memory");
    __asm__ volatile ("flush %0" :: "r" ((char *)p + 8) : "memory");
}

static void check(const char *ok, const char *bad, int passed)
{
    if (passed) {
        (void)printf("%s\n", ok);
    } else {
        (void)printf("%s\n", bad);
        fails++;
    }
}

/* Raw SPARC Linux mprotect trap (no C call): a libc call while the
 * stack page itself is PROT_EXEC would spill register windows onto
 * it and fault, so the stack leg restores writability this way.
 * Error convention: carry set in %xcc (test_p1_isa documents it). */
#define SPARC_NR_MPROTECT 74
#define TRAP_MPROTECT(addr, len, prot, rc) \
    __asm__ volatile ( \
        "mov %1, %%o0\n\t" \
        "mov %2, %%o1\n\t" \
        "mov %3, %%o2\n\t" \
        "mov %4, %%g1\n\t" \
        "ta 0x6d\n\t" \
        "bcs %%xcc, 1f\n\t" \
        " nop\n\t" \
        "mov %%o0, %0\n\t" \
        "ba %%xcc, 2f\n\t" \
        " nop\n\t" \
        "1:\n\t" \
        "mov -1, %0\n\t" \
        "2:" \
        : "=r" (rc) \
        : "r" ((unsigned long)(addr)), "r" ((unsigned long)(len)), \
          "r" ((unsigned long)(prot)), "i" (SPARC_NR_MPROTECT) \
        : "o0", "o1", "o2", "g1", "cc", "memory")

/* Raw trap exit(1): last resort if the stack page cannot be made
 * writable again (no C call is safe on an RX stack). */
#define TRAP_EXIT_ONE() \
    __asm__ volatile ( \
        "mov 1, %%o0\n\t" \
        "mov 1, %%g1\n\t" \
        "ta 0x6d" \
        : : : "o0", "g1", "memory")

/* One SMC leg over [area, area+12): write v1, RX-flip, exec, RW-flip,
 * rewrite v2, flush, RX-flip, re-exec (must see v2), RW restore. No C
 * call happens while the page is PROT_EXEC (is_stack restores via the
 * raw trap); every check/printf runs with the stack writable. */
static void smc_leg(const char *tag, unsigned char *area, int v1, int v2,
                    int is_stack)
{
    char okv1[64], badv1[64], okv2[64], badv2[64];
    /* Guest AT_PAGESZ is 8192: round to 8K so mprotect stays valid
     * on 8K-page kernels (oracle) and inside the 4K software granule. */
    unsigned long lo = (unsigned long)area & ~(unsigned long)8191UL;
    unsigned long hi = ((unsigned long)area + 12UL + 8191UL) &
        ~(unsigned long)8191UL;
    unsigned char *page = (unsigned char *)lo;
    uint32_t w1[3], w2[3];
    size_t span = (size_t)(hi - lo);
    long rc;
    int v;

    w1[0] = SMC_OP_OR | (uint32_t)v1;
    w1[1] = SMC_OP_JMPL;
    w1[2] = SMC_OP_NOP;
    w2[0] = SMC_OP_OR | (uint32_t)v2;
    w2[1] = SMC_OP_JMPL;
    w2[2] = SMC_OP_NOP;

    (void)snprintf(okv1, sizeof okv1, "SMC-%s-V1-OK", tag);
    (void)snprintf(badv1, sizeof badv1, "SMC-%s-V1-FAIL", tag);
    (void)snprintf(okv2, sizeof okv2, "SMC-%s-V2-OK", tag);
    (void)snprintf(badv2, sizeof badv2, "SMC-%s-V2-FAIL", tag);

    (void)memcpy(area, w1, sizeof w1);
    sparc_flush(area);
    __builtin___clear_cache((char *)area, (char *)area + 12);
    if (mprotect(page, span, PROT_READ | PROT_EXEC) != 0) {
        check(okv1, badv1, 0);
        return;
    }
    h1_fn = area;
    v = call_nostack();
    if (is_stack != 0) {
        TRAP_MPROTECT(page, span, PROT_READ | PROT_WRITE, rc);
    } else {
        rc = (long)mprotect(page, span, PROT_READ | PROT_WRITE);
    }
    if (rc != 0) {
        if (is_stack != 0) {
            TRAP_EXIT_ONE();
            __builtin_unreachable();
        }
        check(okv1, badv1, 0);
        check(okv2, badv2, 0);
        return;
    }
    check(okv1, badv1, v == v1);

    (void)memcpy(area, w2, sizeof w2);
    sparc_flush(area);
    __builtin___clear_cache((char *)area, (char *)area + 12);
    if (mprotect(page, span, PROT_READ | PROT_EXEC) != 0) {
        check(okv2, badv2, 0);
        return;
    }
    h1_fn = area;
    v = call_nostack();
    if (is_stack != 0) {
        TRAP_MPROTECT(page, span, PROT_READ | PROT_WRITE, rc);
    } else {
        rc = (long)mprotect(page, span, PROT_READ | PROT_WRITE);
    }
    if (rc != 0) {
        if (is_stack != 0) {
            TRAP_EXIT_ONE();
            __builtin_unreachable();
        }
        check(okv2, badv2, 0);
        return;
    }
    check(okv2, badv2, v == v2);
}

int main(void)
{
    long p = sysconf(_SC_PAGESIZE);
    /* 16 KiB scratch frame: carve an 8K-aligned slice and touch every
     * byte first. The translator materializes stack pages on write,
     * so the memset guarantees both 4K pages of the mprotect window
     * exist; on the oracle (full 8 MB VMA) it is a harmless no-op.
     * Fixed-size array, not a VLA. */
    unsigned char stackwin[16384];
    unsigned char *slice;
    unsigned long aligned;
    unsigned char *heap;
    unsigned char *map;
    void *wx;
    uint32_t rxw[3];
    int v;

    (void)setvbuf(stdout, NULL, _IONBF, 0);
    if (p != 8192) {
        (void)printf("PAGESZ-FAIL\nH1-SMC-FAIL n=99\n");
        return 1;
    }
    (void)printf("PAGESZ-OK value=8192\n");

    /* Stack leg: 12-byte slot inside a fully touched 8K slice. */
    slice = (unsigned char *)(((unsigned long)stackwin + 8191UL) &
        ~(unsigned long)8191UL);
    (void)memset(slice, 0, 8192);
    aligned = ((unsigned long)slice + 15UL) & ~(unsigned long)15UL;
    smc_leg("STACK", (unsigned char *)aligned, 0x51, 0x52, 1);

    /* Heap leg. */
    heap = (unsigned char *)malloc(8192);
    if (heap == NULL) {
        (void)printf("SMC-HEAP-V1-FAIL\nSMC-HEAP-V2-FAIL\n");
        fails += 2;
    } else {
        aligned = ((unsigned long)heap + 15UL) & ~(unsigned long)15UL;
        smc_leg("HEAP", (unsigned char *)aligned, 0x61, 0x62, 0);
        free(heap);
    }

    /* Anonymous-mmap leg. */
    map = (unsigned char *)mmap(NULL, 8192, PROT_READ | PROT_WRITE,
                                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (map == MAP_FAILED) {
        (void)printf("SMC-MMAP-V1-FAIL\nSMC-MMAP-V2-FAIL\n");
        fails += 2;
    } else {
        smc_leg("MMAP", map, 0x71, 0x72, 0);
        (void)munmap(map, 8192);
    }

    /* W^X leg: WX mmap must fail. */
    wx = mmap(NULL, 8192, PROT_READ | PROT_WRITE | PROT_EXEC,
              MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    check("WXMMAP-OK", "WXMMAP-FAIL", wx == MAP_FAILED);
    if (wx != MAP_FAILED) {
        (void)munmap(wx, 8192);
    }

    /* W^X leg: mprotect adding EXEC to data must fail; an RX-flipped
     * page executes. */
    map = (unsigned char *)mmap(NULL, 8192, PROT_READ | PROT_WRITE,
                                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (map == MAP_FAILED) {
        check("WXMPROT-OK", "WXMPROT-FAIL", 0);
        check("RXEXEC-OK", "RXEXEC-FAIL", 0);
    } else {
        v = mprotect(map, 8192, PROT_READ | PROT_WRITE | PROT_EXEC);
        check("WXMPROT-OK", "WXMPROT-FAIL", v != 0);
        rxw[0] = SMC_OP_OR | 0x42U;
        rxw[1] = SMC_OP_JMPL;
        rxw[2] = SMC_OP_NOP;
        (void)memcpy(map, rxw, sizeof rxw);
        sparc_flush(map);
        __builtin___clear_cache((char *)map, (char *)map + 12);
        if (mprotect(map, 8192, PROT_READ | PROT_EXEC) != 0) {
            check("RXEXEC-OK", "RXEXEC-FAIL", 0);
        } else {
            h1_fn = map;
            v = call_nostack();
            check("RXEXEC-OK", "RXEXEC-FAIL", v == 0x42);
            (void)mprotect(map, 8192, PROT_READ | PROT_WRITE);
        }
        (void)munmap(map, 8192);
    }

    if (fails == 0) {
        (void)printf("H1-SMC-PASS\n");
        return 0;
    }
    (void)printf("H1-SMC-FAIL n=%d\n", fails);
    return 1;
}
