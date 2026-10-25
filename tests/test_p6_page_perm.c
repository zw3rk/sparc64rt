/*
 * tests/test_p6_page_perm.c -- Phase 6 adjacent page-permission probe.
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Static glibc SPARC64 guest exercising adjacent guest mappings with
 * distinct permissions (HOST-CONTRACT v1.1 section 2.1.3): a
 * PROT_READ|PROT_EXEC page directly next to a PROT_READ|PROT_WRITE
 * page, plus a PROT_NONE page, inside one anonymous mapping.
 * Regions are 8 KiB (the guest AT_PAGESZ) so the qemu oracle and both
 * translator engines observe identical mprotect geometry; the
 * translator enforces these through its 4 KiB software page table
 * either way. Enforcement is checked functionally: execute the X page
 * (must return), store to the X page (must SIGSEGV), store to the RW
 * page (must succeed), execute the RW page (must SIGSEGV), and touch
 * the NONE page (must SIGSEGV). Faults resume with siglongjmp (never
 * by rewriting ucontext pc). The handler is installed SA_SIGINFO,
 * which the translator requires (plain sa_handler is EINVAL there).
 * Deterministic stdout (fixed strings only; no addresses); exit 0
 * with P6P-PASS iff every check passed, else P6P-FAIL n=<fails> with
 * exit 1.
 *
 * The RELRO-next-to-.bss shape is qualified implicitly by every
 * dynamic leg (ld.so maps RELRO adjacent to writable .bss; a
 * permission-merge bug would crash relocation): test_p5_dyn and the
 * BusyBox probe passing IS that qualification. This probe covers the
 * explicit adjacent-permission enforcement leg.
 *
 * Build (from the worktree root, in the lane container):
 *   sparc64-linux-gnu-gcc -static -O2 -o _build/guest_p6pperm \
 *     tests/test_p6_page_perm.c
 * Oracle:
 *   qemu-sparc64 _build/guest_p6pperm
 */
#include <setjmp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

static sigjmp_buf jb;
static volatile int fails = 0;

/* SPARC V9 leaf returning 42: or %g0,42,%o0; jmpl %o7+8,%g0; nop. */
static const unsigned int stub_words[3] = {
    0x9010202aU, 0x81c3e008U, 0x01000000U
};

static void on_segv(int sig, siginfo_t *info, void *uctx)
{
    (void)sig;
    (void)info;
    (void)uctx;
    siglongjmp(jb, 1);
}

static int install_handler(void)
{
    struct sigaction a;
    (void)memset(&a, 0, sizeof a);
    a.sa_sigaction = on_segv;
    (void)sigemptyset(&a.sa_mask);
    a.sa_flags = SA_SIGINFO;
    return sigaction(SIGSEGV, &a, NULL);
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

int main(void)
{
    long p = sysconf(_SC_PAGESIZE);
    unsigned char *base;
    unsigned char *xpage, *rwpage, *nonepage, *tailpage;
    typedef int (*fn_t)(void);
    fn_t fn;
    int v;

    (void)setvbuf(stdout, NULL, _IONBF, 0);
    if (p != 8192) {
        (void)printf("PAGESZ-FAIL\nP6P-FAIL n=99\n");
        return 1;
    }
    (void)printf("PAGESZ-OK value=8192\n");

    base = (unsigned char *)mmap(NULL, (size_t)3 * 8192UL,
                                 PROT_READ | PROT_WRITE,
                                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (base == MAP_FAILED) {
        (void)printf("MMAP-FAIL\nP6P-FAIL n=99\n");
        return 1;
    }
    (void)printf("MMAP-OK\n");

    xpage = base;                /* first 8K page: X only */
    rwpage = base + 8192;        /* second 8K page: stays RW */
    nonepage = base + 16384;     /* third 8K page: NONE */
    tailpage = base + 12288;     /* last 4K of RW, adjacent to NONE */

    /* Stage the executable stub while the mapping is still writable;
     * the X page loses write permission below. */
    (void)memcpy(xpage, stub_words, sizeof stub_words);
    (void)memcpy(rwpage, stub_words, sizeof stub_words);
    __builtin___clear_cache((char *)xpage, (char *)xpage + 12);
    __builtin___clear_cache((char *)rwpage, (char *)rwpage + 12);

    if (mprotect(xpage, 8192, PROT_READ | PROT_EXEC) != 0) {
        (void)printf("MPX-FAIL\nP6P-FAIL n=99\n");
        return 1;
    }
    if (mprotect(nonepage, 8192, PROT_NONE) != 0) {
        (void)printf("MPN-FAIL\nP6P-FAIL n=99\n");
        return 1;
    }
    (void)printf("MPROTECT-OK\n");

    if (install_handler() != 0) {
        (void)printf("SIGHAND-FAIL\nP6P-FAIL n=99\n");
        return 1;
    }

    /* EXEC leg: run the stub from the X page. */
    fn = (fn_t)(void *)xpage;
    if (sigsetjmp(jb, 1) == 0) {
        v = fn();
        check("EXEC-OK", "EXEC-FAIL", v == 42);
    } else {
        check("EXEC-OK", "EXEC-FAIL", 0);
    }

    /* W^X leg: storing to the X page must fault. */
    if (sigsetjmp(jb, 1) == 0) {
        xpage[0] = (unsigned char)0;
        check("WPROT-OK", "WPROT-FAIL", 0);
    } else {
        check("WPROT-OK", "WPROT-FAIL", 1);
    }

    /* RW leg: the adjacent RW page stays writable and readable. */
    if (sigsetjmp(jb, 1) == 0) {
        rwpage[100] = (unsigned char)0x5a;
        v = (rwpage[100] == (unsigned char)0x5a) ? 1 : 0;
        check("RW-OK", "RW-FAIL", v);
    } else {
        check("RW-OK", "RW-FAIL", 0);
    }

    /* Non-exec leg: executing the RW page must fault. */
    fn = (fn_t)(void *)rwpage;
    if (sigsetjmp(jb, 1) == 0) {
        v = fn();
        (void)v;
        check("XPROT-OK", "XPROT-FAIL", 0);
    } else {
        check("XPROT-OK", "XPROT-FAIL", 1);
    }

    /* NONE leg: touching the PROT_NONE page must fault. The volatile
     * forces the load to execute (a dead non-volatile load would be
     * eliminated and the missing fault would be a false failure). */
    if (sigsetjmp(jb, 1) == 0) {
        v = *(volatile unsigned char *)nonepage;
        (void)v;
        check("NONE-OK", "NONE-FAIL", 0);
    } else {
        check("NONE-OK", "NONE-FAIL", 1);
    }

    /* Tail leg: the RW page next to NONE is unaffected. */
    if (sigsetjmp(jb, 1) == 0) {
        tailpage[0] = (unsigned char)0x7e;
        v = (tailpage[0] == (unsigned char)0x7e) ? 1 : 0;
        check("TAIL-OK", "TAIL-FAIL", v);
    } else {
        check("TAIL-OK", "TAIL-FAIL", 0);
    }

    if (fails == 0) {
        (void)printf("P6P-PASS\n");
        return 0;
    }
    (void)printf("P6P-FAIL n=%d\n", fails);
    return 1;
}
