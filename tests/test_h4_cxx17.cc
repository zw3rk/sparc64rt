/* tests/test_h4_cxx17.cc -- Phase 7 lane H4 C++17 guest (dynamic).
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Dynamic C++17 SPARC64 guest (g++-sparc64-linux-gnu) exercising:
 *   EXC leg    try/catch, nested rethrow, catch-all ordering.
 *   SIGNAL leg throw from a SA_SIGINFO SIGUSR1 handler, caught in
 *              main (unwinds through the translator's rt signal
 *              frame and the glibc sa_restorer). The handler is
 *              triggered via the opaque DSO helper h4_raise_sig so
 *              the interrupted call site carries a call-site record
 *              (raise() itself is noexcept and would emit none).
 *   RTTI leg   dynamic_cast across the libh4.so DSO boundary
 *              (typeinfo lives only in the DSO) plus catching an
 *              H4Err thrown by the DSO in main.
 *   THREAD leg std::thread workers with thread_local guards: each
 *              worker records a body event then a dtor event at
 *              thread exit; destruction must follow the body per
 *              thread and every guard must be destroyed on join.
 *
 * Stdout is fully deterministic (fixed strings and numbers only; no
 * addresses, pids, or timings). Exit status is 0 iff every check
 * passed. Each leg prints OK on success or FAIL on failure and the
 * guest continues, so a partial translator shows which legs pass.
 *
 * Build (debian:stable-slim container, from the worktree root):
 *   docker exec sparc64rt-h4 sh -c 'cd /w && mkdir -p _build \
 *     && sparc64-linux-gnu-g++ -std=c++17 -O2 -fPIC -shared \
 *          -Wl,-soname,libh4.so -o _build/libh4.so tests/libh4.cc \
 *     && sparc64-linux-gnu-g++ -std=c++17 -O2 -pthread \
 *          "-Wl,-rpath,$ORIGIN" -o _build/guest_h4_cxx \
 *          tests/test_h4_cxx17.cc -L_build -l:libh4.so'
 * Oracle (run from the worktree root so $ORIGIN resolves):
 *   qemu-sparc64 -L /usr/sparc64-linux-gnu ./_build/guest_h4_cxx
 * Engines (same container):
 *   SPARC64RT_SYSROOT=/usr/sparc64-linux-gnu \
 *     /w/_build/sparc64rt --interp ./_build/guest_h4_cxx
 *   SPARC64RT_SYSROOT=/usr/sparc64-linux-gnu \
 *     /w/_build/sparc64rt --dbt ./_build/guest_h4_cxx
 *
 * Expected oracle stdout (tests/test_h4_cxx17.golden):
 *   EXC-OK depth=3 sum=42
 *   SIGNAL-OK code=42
 *   RTTI-OK derived=42 null=1 kind=1
 *   DSO-EXC-OK code=7
 *   THREAD-OK workers=2 dtors=2 order=ok
 *   H4-PASS
 */

#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <atomic>
#include <mutex>
#include <thread>
#include <vector>

#include "libh4.h"

static int failures = 0;

/* ---- EXC leg: nested throw/rethrow ----------------------------------- */

struct H4Inner {
    int code;
};

static int exc_depth(void)
{
    try {
        throw H4Inner{40};
    } catch (const H4Inner &e) {
        try {
            throw H4Inner{e.code + 2};
        } catch (const H4Inner &f) {
            return f.code;
        } catch (...) {
            return -1;
        }
    } catch (...) {
        return -1;
    }
}

static void test_exc(void)
{
    int depth = exc_depth();
    int sum = 0;
    try {
        try {
            throw 21;
        } catch (int v) {
            sum = v * 2;
            throw;
        }
    } catch (int v) {
        sum += 0;
        if (v != 21) {
            sum = -1000;
        }
    } catch (...) {
        sum = -1000;
    }
    if (depth == 42 && sum == 42) {
        (void)printf("EXC-OK depth=%d sum=%d\n", depth, sum);
    } else {
        (void)printf("EXC-FAIL depth=%d sum=%d\n", depth, sum);
        failures++;
    }
}

/* ---- SIGNAL leg: throw from a SIGUSR1 handler ----------------------- */

struct SigEscape {
    int code;
};

static void h4_sigusr1(int sig, siginfo_t *info, void *ctx)
{
    (void)ctx;
    /* Accept any si_code: the oracle reports SI_TKILL for raise() while
     * the translator's kill family always carries SI_USER (RC4-locked).
     * The guest must not depend on that difference. */
    if (sig == SIGUSR1 && info != nullptr) {
        throw SigEscape{42};
    }
}

static void test_signal(void)
{
    struct sigaction act;
    struct sigaction old;
    int rc;
    (void)memset(&act, 0, sizeof(act));
    (void)memset(&old, 0, sizeof(old));
    act.sa_sigaction = h4_sigusr1;
    act.sa_flags = SA_SIGINFO;
    (void)sigemptyset(&act.sa_mask);
    rc = sigaction(SIGUSR1, &act, &old);
    if (rc != 0) {
        (void)printf("SIGNAL-FAIL setup\n");
        failures++;
        return;
    }
    /* The raise goes through the opaque DSO helper so the call site
     * in the try carries a call-site record (see libh4.h); a direct
     * noexcept raise() call would have no record and terminate. */
    try {
        if (h4_raise_sig(SIGUSR1) != 0) {
            (void)printf("SIGNAL-FAIL raise\n");
            failures++;
        } else {
            (void)printf("SIGNAL-FAIL uncaught\n");
            failures++;
        }
    } catch (const SigEscape &e) {
        if (e.code == 42) {
            (void)printf("SIGNAL-OK code=%d\n", e.code);
        } else {
            (void)printf("SIGNAL-FAIL code=%d\n", e.code);
            failures++;
        }
    } catch (...) {
        (void)printf("SIGNAL-FAIL wrong-type\n");
        failures++;
    }
    (void)sigaction(SIGUSR1, &old, nullptr);
}

/* ---- RTTI leg: dynamic_cast + exceptions across the DSO -------------- */

static void test_rtti(void)
{
    H4Base *b = h4_make_derived(42);
    H4Derived *d = nullptr;
    H4Other *o = nullptr;
    int kind = 0;
    if (b != nullptr) {
        d = dynamic_cast<H4Derived *>(b);
        o = dynamic_cast<H4Other *>(b);
        kind = b->kind();
    }
    if (d != nullptr && d->value == 42 && o == nullptr && kind == 1) {
        (void)printf("RTTI-OK derived=%d null=%d kind=%d\n", d->value,
            o == nullptr ? 1 : 0, kind);
    } else {
        (void)printf("RTTI-FAIL\n");
        failures++;
    }
    try {
        h4_throw_err(7);
        (void)printf("DSO-EXC-FAIL uncaught\n");
        failures++;
    } catch (const H4Err &e) {
        if (e.code == 7) {
            (void)printf("DSO-EXC-OK code=%d\n", e.code);
        } else {
            (void)printf("DSO-EXC-FAIL code=%d\n", e.code);
            failures++;
        }
    } catch (...) {
        (void)printf("DSO-EXC-FAIL wrong-type\n");
        failures++;
    }
    delete b;
}

/* ---- THREAD leg: std::thread + thread_local destructors -------------- */

static std::atomic<int> g_ctors{0};
static std::atomic<int> g_dtors{0};
static std::mutex g_mu;
static std::vector<int> g_events;

struct H4TlsGuard {
    int id;
    explicit H4TlsGuard(int v) : id(v)
    {
        g_ctors.fetch_add(1, std::memory_order_relaxed);
    }
    ~H4TlsGuard()
    {
        g_dtors.fetch_add(1, std::memory_order_relaxed);
        std::lock_guard<std::mutex> lk(g_mu);
        g_events.push_back(id * 10 + 1);
    }
};

static void h4_worker(int id)
{
    thread_local H4TlsGuard guard{id};
    (void)guard.id;
    {
        std::lock_guard<std::mutex> lk(g_mu);
        g_events.push_back(id * 10 + 0);
    }
}

static void test_threads(void)
{
    int order_ok = 0;
    {
        std::thread t0(h4_worker, 0);
        std::thread t1(h4_worker, 1);
        t0.join();
        t1.join();
    }
    {
        std::lock_guard<std::mutex> lk(g_mu);
        size_t i0 = g_events.size(), d0 = g_events.size();
        size_t i1 = g_events.size(), d1 = g_events.size();
        for (size_t i = 0; i < g_events.size(); i++) {
            if (g_events[i] == 0) {
                i0 = i;
            } else if (g_events[i] == 1) {
                d0 = i;
            } else if (g_events[i] == 10) {
                i1 = i;
            } else if (g_events[i] == 11) {
                d1 = i;
            }
        }
        order_ok = (i0 < d0) && (i1 < d1);
    }
    if (g_ctors.load() == 2 && g_dtors.load() == 2 && order_ok != 0) {
        (void)printf("THREAD-OK workers=2 dtors=2 order=ok\n");
    } else {
        (void)printf("THREAD-FAIL ctors=%d dtors=%d order=%d events=%d\n",
            (int)g_ctors.load(), (int)g_dtors.load(), order_ok,
            (int)g_events.size());
        failures++;
    }
}

int main(void)
{
    test_exc();
    test_signal();
    test_rtti();
    test_threads();
    if (failures == 0) {
        (void)printf("H4-PASS\n");
        return 0;
    }
    (void)printf("H4-FAIL count=%d\n", failures);
    return 1;
}
