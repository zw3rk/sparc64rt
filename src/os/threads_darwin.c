/*
 * src/os/threads_darwin.c — Darwin guest-futex dispatch (S64-R3-4)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Routes the CLONE_VM futex WAIT/WAKE syscalls through the backend
 * contract (src/os/backend.h section 7) instead of reporting -ENOSYS:
 * the caller-validated guest address is re-resolved to a host word,
 * its backing is retained across the sleep (munmap during the wait
 * cannot free the bytes out from under the waiter), the waiter sleeps
 * under a validated private key with the thread's worker signal state
 * (a preemption signal interrupts the wait with -EINTR), and the value
 * is re-verified after every wakeup exactly like the Linux path.
 *
 * Locking: the big guest lock is held on entry. It is dropped across
 * the backend sleep only (the pin keeps the mapping bytes alive) and
 * re-held before returning, so mapping mutations stay serialized.
 *
 * No guest data page is mapped PROT_EXEC here and host register x18
 * is never touched.
 */
#if defined(__APPLE__) && defined(__aarch64__)

#define _POSIX_C_SOURCE 200809L

#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "core/cpu.h"
#include "interp/interp_win.h"
#include "os/backend.h"
#include "os/guest_run_priv.h"
#include "os/syscalls_ext.h"
#include "os/threads.h"
#include "os/threads_darwin.h"
#include "os/mem_space_split.h"

#define THR_DARWIN_CMD_MASK UINT64_C(127)
#define THR_DARWIN_WAIT_BITSET 9U
#define THR_DARWIN_CLOCK_REALTIME UINT64_C(256)

/* Guest-visible results use fixed Linux numbers, NOT host <errno.h>:
 * EAGAIN 11, ENOSYS 38 and ETIMEDOUT 110 differ on Darwin (35/78/60);
 * EFAULT 14, EINVAL 22, EINTR 4 and ENOMEM 12 coincide. The backend
 * contract already speaks Linux (-11/-110/-4/-12), so waiter outcomes
 * compare and pass through unchanged. */
#define THR_LINUX_EAGAIN 11L
#define THR_LINUX_ENOSYS 38L
#define THR_LINUX_ETIMEDOUT 110L
#define THR_LINUX_EINTR 4L
#define THR_LINUX_EFAULT 14L
#define THR_LINUX_EINVAL 22L

/* ---- per-thread worker signal state ---------------------------------- */

static _Thread_local rt_worker_sync_t *thr_darwin_ws = NULL;

static rt_worker_sync_t *thr_darwin_get_ws(void)
{
    rt_worker_sync_t *ws;
    if (thr_darwin_ws != NULL) {
        return thr_darwin_ws;
    }
    ws = (rt_worker_sync_t *)calloc(1U, sizeof(*ws));
    if (ws == NULL) {
        return NULL;
    }
    if (rt_host_worker_sync_init(ws) != 0) {
        free(ws);
        return NULL;
    }
    thr_darwin_ws = ws;
    return ws;
}

void thr_darwin_ws_teardown(void)
{
    if (thr_darwin_ws != NULL) {
        rt_host_worker_sync_destroy(thr_darwin_ws);
        free(thr_darwin_ws);
        thr_darwin_ws = NULL;
    }
    rt_host_unregister_self();
}

/* ---- validated keys ----------------------------------------------------
 * Private key over (owning pid, guest VA), mirroring the Linux private
 * futex identity (mm, address): two waiters match exactly when they
 * name the same word in this process. Shared cross-process futexes
 * are outside the single-process runtime. */

static rt_futex_key_t thr_darwin_key(uint64_t uaddr)
{
    rt_futex_key_t key;
    (void)memset(&key, 0, sizeof(key));
    key.kind = (uint32_t)RT_FUTEX_KEY_PRIVATE;
    key.owner_id = (uint64_t)getpid();
    key.mount_id = UINT64_C(0);
    key.offset = uaddr;
    return key;
}

/* ---- pinning ------------------------------------------------------------
 * Resolve [va, va+4) at the 4 KiB translation granule and retain the
 * backing view for the sleep. validate_access runs the file refresh
 * and permission checks first, exactly like the shared-mapping
 * resolver in threads.c; the retained reference is the waiter's pin. */

typedef struct {
    sparc64_backing_t *backing;
    _Atomic uint32_t *word;
} thr_darwin_pin_t;

static int thr_darwin_pin(void *mc, uint64_t va, thr_darwin_pin_t *pin)
{
    guest_state_t *g = (guest_state_t *)mc;
    uint64_t base;
    size_t pos;
    size_t off;
    sparc64_backing_t *backing;
    pin->backing = NULL;
    pin->word = NULL;
    if (g == NULL) {
        return -THR_LINUX_EFAULT;
    }
    if (va > SPARC64_TASK_SIZE - UINT64_C(4)) {
        return -THR_LINUX_EFAULT;
    }
    base = va & ~(SPARC64_PAGE_SIZE - UINT64_C(1));
    off = (size_t)(va - base);
    if (off + (size_t)4 > (size_t)SPARC64_PAGE_SIZE) {
        return -THR_LINUX_EFAULT;
    }
    if (!validate_access(&g->space, va, (size_t)4,
            (unsigned)SPARC64_MEM_READ)) {
        return -THR_LINUX_EFAULT;
    }
    pos = page_position(&g->space, base);
    if (pos >= g->space.count ||
        g->space.pages[pos].address != base) {
        return -THR_LINUX_EFAULT;
    }
    backing = g->space.pages[pos].backing;
    if (backing == NULL || backing->bus_fault || backing->bytes == NULL) {
        return -THR_LINUX_EFAULT;
    }
    if (!sparc64_backing_retain(backing)) {
        return -THR_LINUX_EAGAIN;
    }
    pin->backing = backing;
    pin->word = (_Atomic uint32_t *)(void *)(backing->bytes + off);
    return 0;
}

static void thr_darwin_unpin(thr_darwin_pin_t *pin)
{
    if (pin->backing != NULL) {
        sparc64_backing_release(pin->backing);
        pin->backing = NULL;
        pin->word = NULL;
    }
}

/* Big-endian guest word load through the syscall copy layer. */
static int thr_darwin_read_u32(const sparc64_syscall_mem_t *mem,
    uint64_t va, uint32_t *out)
{
    uint8_t raw[4];
    if (l2a_range_ok(va, (uint64_t)sizeof(raw)) != 0) {
        return -THR_LINUX_EFAULT;
    }
    if (!mem->read(mem->context, va, raw, (uint64_t)sizeof(raw))) {
        return -THR_LINUX_EFAULT;
    }
    *out = l2a_get_be32(raw);
    return 0;
}

long thr_darwin_futex_wait(sparc64_ctx_t *ctx,
    const sparc64_syscall_mem_t *mem, uint64_t uaddr, uint64_t op,
    uint64_t val, uint32_t bitset, const struct timespec *ts)
{
    uint64_t cmd = op & THR_DARWIN_CMD_MASK;
    int is_abs = (cmd == (uint64_t)THR_DARWIN_WAIT_BITSET) ? 1 : 0;
    int realtime =
        (op & THR_DARWIN_CLOCK_REALTIME) != UINT64_C(0) ? 1 : 0;
    uint32_t host_val = __builtin_bswap32((uint32_t)val);
    rt_worker_sync_t *ws;
    uint32_t expected_seq = 0U;
    int prc;
    uint32_t cur = 0U;
    (void)ctx;
    if (cmd != UINT64_C(0) && cmd != (uint64_t)THR_DARWIN_WAIT_BITSET) {
        return -THR_LINUX_ENOSYS;
    }
    if ((uaddr & UINT64_C(3)) != UINT64_C(0)) {
        return -THR_LINUX_EINVAL;
    }
    if (is_abs != 0 && bitset == 0U) {
        return -THR_LINUX_EINVAL;
    }
    /* Worker signal state for the sleeping thread (lazy; a NULL ws
     * still sleeps with deadline slices, only without signal
     * interruption, so OOM degrades instead of failing the wait). */
    ws = thr_darwin_get_ws();
    if (ws != NULL) {
        expected_seq = atomic_load_explicit(&ws->sig_seq,
            memory_order_acquire);
    }
    for (;;) {
        thr_darwin_pin_t pin;
        rt_futex_key_t key;
        int64_t wrc;
        if (sparc64_threads_group_exiting(NULL)) {
            return -THR_LINUX_EINTR;
        }
        prc = thr_darwin_read_u32(mem, uaddr, &cur);
        if (prc != 0) {
            return (long)prc;
        }
        if (cur != (uint32_t)val) {
            return -THR_LINUX_EAGAIN;
        }
        /* Pin under the held big lock; the drop below cannot free
         * the bytes while the pin is retained. */
        prc = thr_darwin_pin(mem->context, uaddr, &pin);
        if (prc != 0) {
            return (prc == -THR_LINUX_EAGAIN) ? -THR_LINUX_EAGAIN :
                -THR_LINUX_EFAULT;
        }
        key = thr_darwin_key(uaddr);
        sparc64_thread_big_unlock();
        wrc = rt_host_futex_wait_bitset(pin.word, &key, host_val, ts,
            is_abs, realtime, (is_abs != 0) ? bitset : UINT32_C(0xffffffff),
            ws, expected_seq);
        sparc64_thread_big_lock();
        thr_darwin_unpin(&pin);
        /* Re-acquired after a drop: cached window images belong to
         * whichever thread cached them; refill from our own homes. */
        sparc64_win_invalidate_all();
        if (wrc == 0L) {
            /* Woken: re-verify through the copy layer (an unmap
             * during the sleep reads as -EFAULT, like Linux). */
            prc = thr_darwin_read_u32(mem, uaddr, &cur);
            if (prc != 0) {
                return (long)prc;
            }
            return 0L;
        }
        if (wrc == -4L) {
            if (sparc64_threads_group_exiting(NULL)) {
                return -THR_LINUX_EINTR;
            }
            prc = thr_darwin_read_u32(mem, uaddr, &cur);
            if (prc != 0) {
                return (long)prc;
            }
            if (cur != (uint32_t)val) {
                return -THR_LINUX_EAGAIN;
            }
            continue;
        }
        if (wrc == -11L) {
            /* Value changed between the entry check and backend
             * admission: re-verify once instead of sleeping. */
            prc = thr_darwin_read_u32(mem, uaddr, &cur);
            if (prc != 0) {
                return (long)prc;
            }
            if (cur != (uint32_t)val) {
                return -THR_LINUX_EAGAIN;
            }
            continue;
        }
        if (wrc == -110L) {
            return -THR_LINUX_ETIMEDOUT;
        }
        return (long)wrc;
    }
}

long thr_darwin_futex_wake(const sparc64_syscall_mem_t *mem,
    uint64_t uaddr, uint64_t val)
{
    guest_state_t *g = (guest_state_t *)mem->context;
    uint64_t base;
    size_t pos;
    size_t off;
    sparc64_backing_t *backing;
    rt_futex_key_t key;
    int count;
    if (mem == NULL) {
        return -THR_LINUX_EFAULT;
    }
    if ((uaddr & UINT64_C(3)) != UINT64_C(0)) {
        return -THR_LINUX_EINVAL;
    }
    if (uaddr > SPARC64_TASK_SIZE - UINT64_C(4)) {
        return -THR_LINUX_EFAULT;
    }
    /* Resolve only (no sleep, no pin needed); the big lock is held by
     * the caller, so the lookup cannot race a remap. */
    base = uaddr & ~(SPARC64_PAGE_SIZE - UINT64_C(1));
    off = (size_t)(uaddr - base);
    if (off + (size_t)4 > (size_t)SPARC64_PAGE_SIZE) {
        return -THR_LINUX_EFAULT;
    }
    if (g == NULL ||
        !validate_access(&g->space, uaddr, (size_t)4,
            (unsigned)SPARC64_MEM_READ)) {
        return -THR_LINUX_EFAULT;
    }
    pos = page_position(&g->space, base);
    if (pos >= g->space.count ||
        g->space.pages[pos].address != base) {
        return -THR_LINUX_EFAULT;
    }
    backing = g->space.pages[pos].backing;
    if (backing == NULL || backing->bus_fault || backing->bytes == NULL) {
        return -THR_LINUX_EFAULT;
    }
    key = thr_darwin_key(uaddr);
    count = (val > (uint64_t)INT32_MAX) ? INT32_MAX : (int)val;
    if (count <= 0) {
        return 0L;
    }
    return (long)rt_host_futex_wake_bitset(
        (_Atomic uint32_t *)(void *)(backing->bytes + off), &key,
        count, UINT32_C(0xffffffff));
}
#else /* not macOS-arm64: no symbols, keeps -pedantic quiet */
typedef int rt_host_threads_darwin_unused_t;
#endif /* defined(__APPLE__) && defined(__aarch64__) */
