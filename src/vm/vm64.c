/*
 * src/vm/vm64.c — Class-B 64-bit guest address space on the 8 KiB
 * SPARC V9 ABI granule (Wave U2, lane M2).
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Unifies GUEST_ABI_PAGE_SIZE = 8192 (UNIFICATION-PLAN Rev 4, section
 * 4.2) across AT_PAGESZ, mmap / mprotect / munmap / mremap alignment
 * (-EINVAL on 4KiB-only offsets/addresses), ELF segment rounding,
 * whole-8KiB PAGE_COW_CLEAN -> PAGE_COW_DIRTY in-place promotion, and
 * 8 KiB EOF tail zeroing. Every 8 KiB guest page operation updates the
 * PAIRED 4 KiB Soft-TLB entries (vpn and vpn ^ 1) together; the TLB
 * helper below is deliberately local to this TU (other lanes own the
 * shared headers, so the coordinator rewires this module to
 * src/os/backend.h and the DBT at merge time).
 *
 * Backend independence: this TU performs no host syscalls. Host
 * operations (map/protect/unmap/ftruncate, worker preemption) arrive
 * as caller-supplied callbacks or via src/vm/vm_file.c; the 6-step
 * Prepare -> Quiesce -> Host-Op -> Commit protocol (section 4.5) is
 * implemented over an injected preempt hook. No guest data page is
 * ever mapped PROT_EXEC on the host (strict W^X); this TU emits no
 * machine code and never touches host register x18.
 */

#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "os/backend.h"

/* ---- Linux errno values returned as negative codes ----------------------
 * Fixed Linux numbers (not host <errno.h>: identical on Linux and
 * Darwin for these codes, but the translator targets Linux ABI). */
#define VM64_EINVAL 22
#define VM64_ENOMEM 12
#define VM64_EFAULT 14

/* ---- Page granules -------------------------------------------------------
 * Canonical source is src/os/guest_run_priv.h (GUEST_ABI_PAGE_SIZE /
 * RT_TRANSLATION_GRANULE); repeated here so this TU compiles standalone
 * until the coordinator wires the headers. */
#define VM64_ABI_PAGE UINT64_C(8192)
#define VM64_ABI_MASK (VM64_ABI_PAGE - UINT64_C(1))
#define VM64_SUB_PAGE UINT64_C(4096)
#define VM64_SUB_MASK (VM64_SUB_PAGE - UINT64_C(1))

/* Soft-TLB geometry (UNIFICATION-PLAN section 4.3): 4096 entries of
 * 32 bytes, indexed by 4 KiB virtual page number. */
#define VM64_TLB_BITS 12u
#define VM64_TLB_SIZE (1u << VM64_TLB_BITS)

/* Guest user address space (SPARC64_TASK_SIZE, 1 << 47). */
#define VM64_TASK_SIZE (UINT64_C(1) << 47)

/* Linux mremap(2) flags accepted by vm64_mremap_check. */
#define VM64_MREMAP_MAYMOVE 1u
#define VM64_MREMAP_FIXED 2u

/* Per-8KiB-page states live in src/vm/vm64.h (shared with
 * src/vm/vm_file.c and the RC-U2 gate test so the compiler checks
 * the vm64_page_state_t* signatures instead of int* punning). */
#include "vm/vm64.h"

/* Soft-TLB entry (section 4.3.1): 32 bytes, read_tag at +0, addend at
 * +8, write_tag at +16, reserved at +24. */
typedef struct {
    uint64_t read_tag;
    uintptr_t addend;
    uint64_t write_tag;
    uint64_t flags_reserved;
} vm64_tlb_entry_t;

_Static_assert(sizeof(vm64_tlb_entry_t) == 32,
    "Soft-TLB entry must be 32 bytes");

#define VM64_TLB_INVALID_TAG (~UINT64_C(0))

/* Worker states for the quiescence protocol (section 4.5.1). */
typedef enum {
    VM64_WORKER_RUNNING_DBT = 0,
    VM64_WORKER_SYSCALL_LEASE = 1,
    VM64_WORKER_PARKED = 2,
    VM64_WORKER_MUTATING = 3
} vm64_worker_state_t;

typedef struct {
    _Atomic unsigned state;
    _Atomic uint64_t dbt_epoch;
    /* Platform worker id (tgkill target on Linux, worker-table key on
     * Darwin); zero marks a free slot the prepare loop skips. Atomic
     * so register/unregister (table lock) and the lock-free prepare
     * scan never race on plain storage. */
    _Atomic uint64_t host_tid;
} vm64_worker_t;

/* Host-operation callback executed in Step 3 (Quiesce held). Returns
 * >= 0 on success, a negative -errno on failure (state untouched). */
typedef long (*vm64_host_op_fn)(void *op_ctx);

/* Worker-preemption callback (tgkill(SIGRTMIN+1) on Linux,
 * pthread_kill(SIGUSR2) on Darwin). Returns 0 on success. */
typedef int (*vm64_preempt_fn)(uint64_t host_tid, void *ctx);

/* Lane S2 wire-up: default Step-2 preempt hook over the existing
 * rt_host_* backend. The coordinator installs this as
 * vm64_txn_t.preempt where a live peer table exists; single-threaded
 * engines take the epoch-bump leg instead. No guest mapping, no x18. */
int vm64_preempt_via_rt_host(uint64_t host_tid, void *ctx)
{
    (void)ctx;
    return rt_host_preempt_worker(host_tid);
}

/* ---- 8 KiB alignment primitives ------------------------------------------ */

static inline bool vm64_is_8k_aligned(uint64_t v)
{
    return (v & VM64_ABI_MASK) == UINT64_C(0);
}

static inline uint64_t vm64_align_up_8k(uint64_t v)
{
    return (v + VM64_ABI_MASK) & ~VM64_ABI_MASK;
}

static inline uint64_t vm64_align_down_8k(uint64_t v)
{
    return v & ~VM64_ABI_MASK;
}

/* ---- Guest-visible argument validation (-EINVAL on 4KiB-only) ------------ */

/* mmap(71): addr/offset must be 8 KiB-aligned (MAP_FIXED addr included),
 * len is rounded up to 8 KiB by the caller. Rejects zero length,
 * oversized spans, and 4KiB-only offsets (section 4.2.1). */
int vm64_check_mmap_args(uint64_t addr, uint64_t len, uint64_t offset,
    unsigned flags_fixed)
{
    if (len == UINT64_C(0) || len > VM64_TASK_SIZE) {
        return -VM64_EINVAL;
    }
    if ((offset & VM64_ABI_MASK) != UINT64_C(0)) {
        return -VM64_EINVAL;
    }
    if (flags_fixed != 0u) {
        if (!vm64_is_8k_aligned(addr) || addr == UINT64_C(0) ||
            addr >= VM64_TASK_SIZE ||
            vm64_align_up_8k(len) > VM64_TASK_SIZE - addr) {
            return -VM64_EINVAL;
        }
    }
    return 0;
}

/* mprotect(74): addr must be 8 KiB-aligned, len nonzero; size rounds up
 * to 8 KiB. 4KiB-only addresses fail with -EINVAL. */
int vm64_check_mprotect_args(uint64_t addr, uint64_t len, uint64_t *size_out)
{
    uint64_t size;
    if (len == UINT64_C(0)) {
        return -VM64_EINVAL;
    }
    if (!vm64_is_8k_aligned(addr)) {
        return -VM64_EINVAL;
    }
    size = vm64_align_up_8k(len);
    if (addr < VM64_ABI_PAGE || size > VM64_TASK_SIZE - addr) {
        return -VM64_ENOMEM;
    }
    if (size_out != NULL) {
        *size_out = size;
    }
    return 0;
}

/* munmap(73): rounds [addr, addr+len) out to the 8 KiB granule (Linux
 * tolerates holes). Unaligned addr is -EINVAL, matching the kernel. */
int vm64_check_munmap_args(uint64_t addr, uint64_t len, uint64_t *base_out,
    uint64_t *size_out)
{
    uint64_t base;
    uint64_t size;
    if (len == UINT64_C(0)) {
        return -VM64_EINVAL;
    }
    if (!vm64_is_8k_aligned(addr)) {
        return -VM64_EINVAL;
    }
    base = vm64_align_down_8k(addr);
    size = vm64_align_up_8k(addr + len) - base;
    if (base < VM64_ABI_PAGE || size > VM64_TASK_SIZE - base) {
        return -VM64_EINVAL;
    }
    if (base_out != NULL) {
        *base_out = base;
    }
    if (size_out != NULL) {
        *size_out = size;
    }
    return 0;
}

/* mremap(25x/250): old address and both sizes must sit on the 8 KiB
 * granule; MREMAP_FIXED additionally needs an 8 KiB-aligned new
 * address. Mirrors the kernel's -EINVAL classes on SPARC64. */
int vm64_check_mremap_args(uint64_t old_addr, uint64_t old_size,
    uint64_t new_size, unsigned flags, uint64_t new_addr)
{
    uint64_t base;
    uint64_t size;
    if (old_size == UINT64_C(0) || new_size == UINT64_C(0) ||
        new_size > VM64_TASK_SIZE) {
        return -VM64_EINVAL;
    }
    if (!vm64_is_8k_aligned(old_addr)) {
        return -VM64_EINVAL;
    }
    base = vm64_align_down_8k(old_addr);
    size = vm64_align_up_8k(old_addr + old_size) - base;
    if (base < VM64_ABI_PAGE || size > VM64_TASK_SIZE - base) {
        return -VM64_EINVAL;
    }
    if ((flags & ~(VM64_MREMAP_MAYMOVE | VM64_MREMAP_FIXED)) != 0u) {
        return -VM64_EINVAL;
    }
    if ((flags & VM64_MREMAP_FIXED) != 0u) {
        if ((flags & VM64_MREMAP_MAYMOVE) == 0u) {
            return -VM64_EINVAL;
        }
        if (!vm64_is_8k_aligned(new_addr) ||
            new_addr == UINT64_C(0) ||
            new_addr >= VM64_TASK_SIZE ||
            vm64_align_up_8k(new_size) > VM64_TASK_SIZE - new_addr) {
            return -VM64_EINVAL;
        }
    }
    return 0;
}

/* ---- ELF segment rounding (8 KiB loader granule) --------------------------
 * PT_LOAD spans round to [align_down_8k(p_vaddr),
 * align_up_8k(p_vaddr + p_memsz)) so the 8K-rounded RELRO mprotect
 * ld.so issues stays inside the mapping. Returns 0 with *start_out /
 * *end_out set, or -VM64_EFAULT when the span is empty, inverted, or
 * outside the user address space. */
int vm64_round_elf_span(uint64_t p_vaddr, uint64_t p_memsz,
    uint64_t p_filesz, uint64_t *start_out, uint64_t *end_out)
{
    uint64_t start;
    uint64_t end;
    if (p_memsz == UINT64_C(0) || p_memsz < p_filesz) {
        return -VM64_EFAULT;
    }
    start = vm64_align_down_8k(p_vaddr);
    end = vm64_align_up_8k(p_vaddr + p_memsz);
    if (end <= start || start < VM64_ABI_PAGE || end > VM64_TASK_SIZE) {
        return -VM64_EFAULT;
    }
    if (start_out != NULL) {
        *start_out = start;
    }
    if (end_out != NULL) {
        *end_out = end;
    }
    return 0;
}

/* ---- Whole-8KiB COW promotion (in place, section 5.1.1) -------------------
 * A MAP_PRIVATE file page promotes as one indivisible 8 KiB unit: both
 * 4 KiB halves move PAGE_COW_CLEAN -> PAGE_COW_DIRTY together so one
 * half is never left COW_DIRTY while the other stays COW_CLEAN. The
 * canonical HVA (arena_base + gva) and the TLB addend never change.
 * Returns true when a promotion happened (caller then enables
 * write_tag on both halves); false when already promoted or when the
 * page is not private-file state. */
bool vm64_cow_promote_8k(vm64_page_state_t *lower_half,
    vm64_page_state_t *upper_half)
{
    bool promoted = false;
    if (lower_half == NULL || upper_half == NULL) {
        return false;
    }
    if (*lower_half == VM64_PAGE_COW_CLEAN) {
        *lower_half = VM64_PAGE_COW_DIRTY;
        promoted = true;
    }
    if (*upper_half == VM64_PAGE_COW_CLEAN) {
        *upper_half = VM64_PAGE_COW_DIRTY;
        promoted = true;
    }
    return promoted;
}

/* A write may hit the inline Soft-TLB fast path only when the whole
 * 8 KiB page is already promoted (both halves != COW_CLEAN). */
bool vm64_cow_writable(vm64_page_state_t lower_half,
    vm64_page_state_t upper_half)
{
    return lower_half != VM64_PAGE_COW_CLEAN &&
        upper_half != VM64_PAGE_COW_CLEAN &&
        lower_half != VM64_PAGE_UNMAPPED &&
        upper_half != VM64_PAGE_UNMAPPED;
}

/* ---- 8 KiB EOF tail zeroing (section 4.2.1) -------------------------------
 * When a file ends in the LOWER 4 KiB half of an 8 KiB guest page on a
 * 4 KiB host, the UPPER 4 KiB half must materialize as an anonymous
 * zeroed page so valid accesses there never raise a kernel SIGBUS.
 * vm64_eof_upper_half reports the upper-half span to zero: returns true
 * with *zero_start_out / *zero_len_out set (zero_len is always 4096),
 * or false when no upper-half materialization is needed. */
bool vm64_eof_upper_half(uint64_t file_size, uint64_t map_end,
    uint64_t *zero_start_out, uint64_t *zero_len_out)
{
    uint64_t page_base;
    uint64_t in_page;
    uint64_t upper;
    if (map_end <= file_size) {
        return false;
    }
    page_base = vm64_align_down_8k(file_size);
    in_page = file_size - page_base;
    if (in_page == UINT64_C(0) || in_page > VM64_SUB_PAGE) {
        return false;
    }
    upper = page_base + VM64_SUB_PAGE;
    if (upper >= map_end) {
        return false;
    }
    if (zero_start_out != NULL) {
        *zero_start_out = upper;
    }
    if (zero_len_out != NULL) {
        *zero_len_out = VM64_SUB_PAGE;
    }
    return true;
}

/* Zero-fill helper for tails/BSS (byte loop would do; memset is the
 * curated equivalent and is NOT in the banned set). */
void vm64_zero_span(void *host_addr, size_t len)
{
    if (host_addr != NULL && len != 0u) {
        (void)memset(host_addr, 0, len);
    }
}

/* ---- Paired 4 KiB Soft-TLB updates (section 4.2.2, LOCAL helper) -----------
 * Every 8 KiB guest page transition updates BOTH consecutive 4 KiB
 * Soft-TLB entries (vpn and vpn ^ 1) together. gva8k must be 8 KiB
 * aligned; read/write tags use the 4 KiB-aligned sub-page VA form
 * (gva & ~0xFFF). addend is constant across the arena
 * (arena_base): in-place COW promotion never changes it. */

/* Index of the LOWER 4 KiB half of the enclosing 8 KiB page. */
static uint32_t vm64_tlb_lower_index(uint64_t gva8k)
{
    uint64_t vpn = (gva8k >> 12) & (uint64_t)(VM64_TLB_SIZE - 1u);
    return (uint32_t)(vpn & ~(uint64_t)1u);
}

/* Publish one 8 KiB guest page into both paired TLB entries. */
void vm64_tlb_publish_pair(vm64_tlb_entry_t *tlb, uint64_t gva8k,
    bool readable, bool writable, uintptr_t addend)
{
    uint32_t lo;
    uint32_t hi;
    uint64_t lo_va;
    uint64_t hi_va;
    if (tlb == NULL || !vm64_is_8k_aligned(gva8k)) {
        return;
    }
    lo = vm64_tlb_lower_index(gva8k);
    hi = lo ^ 1u;
    lo_va = gva8k & ~(uint64_t)VM64_SUB_MASK;
    hi_va = (gva8k + VM64_SUB_PAGE) & ~(uint64_t)VM64_SUB_MASK;
    tlb[lo].read_tag = readable ? lo_va : VM64_TLB_INVALID_TAG;
    tlb[lo].addend = addend;
    tlb[lo].write_tag = writable ? lo_va : VM64_TLB_INVALID_TAG;
    tlb[lo].flags_reserved = UINT64_C(0);
    tlb[hi].read_tag = readable ? hi_va : VM64_TLB_INVALID_TAG;
    tlb[hi].addend = addend;
    tlb[hi].write_tag = writable ? hi_va : VM64_TLB_INVALID_TAG;
    tlb[hi].flags_reserved = UINT64_C(0);
}

/* Invalidate both paired entries of the enclosing 8 KiB page. */
void vm64_tlb_invalidate_pair(vm64_tlb_entry_t *tlb, uint64_t gva)
{
    uint32_t lo;
    uint32_t hi;
    if (tlb == NULL) {
        return;
    }
    lo = vm64_tlb_lower_index(vm64_align_down_8k(gva));
    hi = lo ^ 1u;
    tlb[lo].read_tag = VM64_TLB_INVALID_TAG;
    tlb[lo].write_tag = VM64_TLB_INVALID_TAG;
    tlb[lo].flags_reserved = UINT64_C(0);
    tlb[hi].read_tag = VM64_TLB_INVALID_TAG;
    tlb[hi].write_tag = VM64_TLB_INVALID_TAG;
    tlb[hi].flags_reserved = UINT64_C(0);
}

/* Range-selective invalidation (section 4.5, Step 5): ranges under 512
 * 4 KiB pages invalidate only the covered paired indices; larger
 * ranges clear the full 128 KiB array. tlb_bytes must be
 * VM64_TLB_SIZE * 32. */
void vm64_tlb_invalidate_range(vm64_tlb_entry_t *tlb, uint64_t base,
    uint64_t len)
{
    uint64_t first;
    uint64_t count;
    uint64_t i;
    if (tlb == NULL || len == UINT64_C(0)) {
        return;
    }
    first = vm64_align_down_8k(base) >> 12;
    count = (vm64_align_up_8k(base + len) - vm64_align_down_8k(base)) >>
        12;
    if (count >= UINT64_C(512)) {
        for (i = 0; i < (uint64_t)VM64_TLB_SIZE; ++i) {
            tlb[i].read_tag = VM64_TLB_INVALID_TAG;
            tlb[i].write_tag = VM64_TLB_INVALID_TAG;
            tlb[i].flags_reserved = UINT64_C(0);
        }
        return;
    }
    for (i = 0; i < count; i += UINT64_C(2)) {
        uint32_t idx =
            (uint32_t)((first + i) & (uint64_t)(VM64_TLB_SIZE - 1u));
        idx &= ~(uint32_t)1u;
        tlb[idx].read_tag = VM64_TLB_INVALID_TAG;
        tlb[idx].write_tag = VM64_TLB_INVALID_TAG;
        tlb[idx].flags_reserved = UINT64_C(0);
        tlb[idx ^ 1u].read_tag = VM64_TLB_INVALID_TAG;
        tlb[idx ^ 1u].write_tag = VM64_TLB_INVALID_TAG;
        tlb[idx ^ 1u].flags_reserved = UINT64_C(0);
    }
}

/* Signal-handler sequence rewind (section 4.5, Step 2): when the
 * preemption signal interrupts a worker inside Soft-TLB instructions
 * 1-6 ([seq_start, host_insn), zero architectural side effects but a
 * possibly stale addend in x3), rewind pc to seq_start. Pure helper so
 * the handler itself stays in src/os. */
uint64_t vm64_seq_rewind(uint64_t pc, uint64_t seq_start,
    uint64_t host_insn)
{
    if (pc >= seq_start && pc < host_insn) {
        return seq_start;
    }
    return pc;
}

/* ---- Live-sequence rewind (RC-U12 follow-up) -----------------------------
 * Every emitted Soft-TLB fast path opens with `ubfm x2, x1, #12, #23`
 * (see mem_emit_check in src/dbt/emit_mem.c; the word is written out
 * from the encoder inputs below so drift is greppable, not magic).
 * The 6-word check prefix has zero architectural side effects, so a
 * worker preempted inside a live sequence may safely resume at its
 * start and re-resolve against current TLB state. The arena window
 * (published by the DBT when it maps the code arena) bounds the only
 * reads this probe performs: outside JIT code, or when no sequence
 * start is found within 6 words back, it returns pc unchanged (safe
 * identity — never jumps somewhere unrecognized). Pre-commit
 * idempotence is what makes re-execution safe: a preempt is always
 * delivered before the mutation it quiesces for, while the old
 * mapping is still live. */
#define VM64_SEQ_START_WORD \
    (UINT32_C(0xd3400000) | ((uint32_t)12 << 16) | \
     ((uint32_t)23 << 10) | ((uint32_t)1 << 5) | (uint32_t)2)
#define VM64_SEQ_SCAN_WORDS 6u
#define VM64_SEQ_WINDOW_BYTES (7u * 4u)

static uint64_t seq_arena_base;
static uint64_t seq_arena_end;

void vm64_seq_publish(uint64_t arena_base, uint64_t arena_size)
{
    seq_arena_base = arena_base;
    seq_arena_end = arena_base + arena_size;
}

uint64_t vm64_seq_rewind_live(uint64_t pc)
{
    uint64_t cand;
    unsigned i;
    uint32_t w;
    if (pc < 4u || seq_arena_base == 0u || seq_arena_end <= seq_arena_base) {
        return pc;
    }
    if (pc < seq_arena_base + (uint64_t)VM64_SEQ_SCAN_WORDS * 4u ||
        pc >= seq_arena_end) {
        return pc;
    }
    cand = (pc - 4u) & ~UINT64_C(3);
    for (i = 0u; i <= VM64_SEQ_SCAN_WORDS; i++) {
        if (cand < seq_arena_base) {
            break;
        }
        w = *(volatile const uint32_t *)(uintptr_t)cand;
        if (w == VM64_SEQ_START_WORD &&
            pc - cand < (uint64_t)VM64_SEQ_WINDOW_BYTES) {
            return cand;
        }
        if (cand < 4u) {
            break;
        }
        cand -= 4u;
    }
    return pc;
}


/* ---- 6-step Prepare -> Quiesce -> Host-Op -> Commit (section 4.5) ---------
 * Operates on a caller-supplied worker table; the coordinator wires
 * the real thread list and the rt_host_preempt_worker hook at merge.
 * Step 1 parks self BEFORE taking the mutation lock (no A/B deadlock).
 * Step 2 announces g_vm_mutating, bumps peer epochs, and preempts
 * RUNNING_DBT peers via the injected hook. Step 3 runs the host op;
 * on failure it releases everything with ZERO state mutation and
 * returns the negative errno. Steps 4-6 publish state (via the
 * commit callback), invalidate the paired TLB range, and resume. */

typedef struct {
    _Atomic unsigned mutating;
    vm64_worker_t *workers;
    size_t nworkers;
    size_t self_index;
    vm64_preempt_fn preempt;
    void *preempt_ctx;
} vm64_txn_t;

int vm64_txn_prepare(vm64_txn_t *txn)
{
    size_t i;
    if (txn == NULL || txn->workers == NULL || txn->nworkers == 0u ||
        txn->self_index >= txn->nworkers) {
        return -VM64_EFAULT;
    }
    /* Step 1: park self first (drop any syscall lease implicitly:
     * the parked state refuses new leases until resume). */
    atomic_store_explicit(&txn->workers[txn->self_index].state,
        (unsigned)VM64_WORKER_PARKED, memory_order_seq_cst);
    /* Step 2: announce quiescence. (The global mutation lock itself is
     * owned by the coordinator around this call.) */
    atomic_store_explicit(&txn->mutating, 1u, memory_order_seq_cst);
    for (i = 0; i < txn->nworkers; ++i) {
        unsigned st;
        uint64_t peer;
        if (i == txn->self_index) {
            continue;
        }
        /* Free table slots carry host_tid 0 (never a live thread:
         * the platform ids are nonzero); they hold no DBT state to
         * preempt, so the scan skips them. Fully populated external
         * tables behave exactly as before. */
        peer = atomic_load_explicit(&txn->workers[i].host_tid,
            memory_order_seq_cst);
        if (peer == UINT64_C(0)) {
            continue;
        }
        (void)atomic_fetch_add_explicit(&txn->workers[i].dbt_epoch,
            (uint64_t)1, memory_order_seq_cst);
        st = atomic_load_explicit(&txn->workers[i].state,
            memory_order_seq_cst);
        if (st == (unsigned)VM64_WORKER_RUNNING_DBT &&
            txn->preempt != NULL) {
            (void)txn->preempt(peer, txn->preempt_ctx);
        }
    }
    return 0;
}

/* Step 3: run the host op while all peers are parked. Failure returns
 * the op's negative errno with zero VMA/inode/COW mutation. */
long vm64_txn_host_op(vm64_txn_t *txn, vm64_host_op_fn op, void *op_ctx)
{
    long rc;
    if (txn == NULL || op == NULL) {
        return -VM64_EFAULT;
    }
    rc = op(op_ctx);
    if (rc < 0L) {
        atomic_store_explicit(&txn->mutating, 0u,
            memory_order_release);
    }
    return rc;
}

/* ---- Lane A2: active-worker txn legs for sysmem_* (RC-U4 #3) -------------
 * The big-lock engine serializes guest execution, but quiescence must
 * address every live thread: the main thread registers at startup and
 * each CLONE_VM worker registers on thread entry (unregistering on
 * exit). The legs below run the section 4.5 core over that table;
 * with zero or one live worker the loop parks self and finds no peers,
 * which is exactly the old nworkers=1/self-0 fast path. Paired-TLB
 * invalidation stays at the sysmem_* call sites (they own the live
 * sparc64_dbt_tlb via src/dbt/mem_sites.h); the commit leg below
 * therefore takes a NULL table, which is a no-op by contract.
 * Fork children inherit the table: stale parent tids never park (the
 * child registers itself on first prepare) and failed preemptions are
 * ignored by contract, so no fork hook is needed. */

/* Main slot plus one per host-thread-backed guest thread. */
#define VM64_MAX_WORKERS 65u

static vm64_worker_t vm64_workers[VM64_MAX_WORKERS];
static vm64_txn_t a2_txn;
static int a2_bound;
static atomic_flag vm64_table_lock = ATOMIC_FLAG_INIT;

/* Forward declarations of the section 4.5 core (defined below). */
int vm64_txn_prepare(vm64_txn_t *txn);
long vm64_txn_host_op(vm64_txn_t *txn, vm64_host_op_fn op, void *op_ctx);
int vm64_txn_commit(vm64_txn_t *txn, vm64_tlb_entry_t *tlb,
    uint64_t changed_base, uint64_t changed_len);

static void a2_bind(void)
{
    if (a2_bound == 0) {
        a2_txn.workers = vm64_workers;
        a2_txn.nworkers = (size_t)VM64_MAX_WORKERS;
        a2_txn.self_index = 0u;
        a2_txn.preempt = vm64_preempt_via_rt_host;
        a2_txn.preempt_ctx = NULL;
        a2_bound = 1;
    }
}

static void vm64_table_lock_acq(void)
{
    while (atomic_flag_test_and_set_explicit(&vm64_table_lock,
            memory_order_acquire)) {
    }
}

static void vm64_table_lock_rel(void)
{
    atomic_flag_clear_explicit(&vm64_table_lock, memory_order_release);
}

/* Find the calling thread's slot, claiming a free one when absent.
 * Returns VM64_MAX_WORKERS when the table is full (unreachable in
 * practice: main plus one slot per guest thread). */
static size_t vm64_find_or_claim_self(uint64_t tid)
{
    size_t i;
    size_t free_slot = (size_t)VM64_MAX_WORKERS;
    for (i = 0; i < (size_t)VM64_MAX_WORKERS; i++) {
        uint64_t have = atomic_load_explicit(&vm64_workers[i].host_tid,
            memory_order_seq_cst);
        if (have == tid) {
            atomic_store_explicit(&vm64_workers[i].state,
                (unsigned)VM64_WORKER_RUNNING_DBT,
                memory_order_seq_cst);
            return i;
        }
        if (free_slot == (size_t)VM64_MAX_WORKERS &&
            have == UINT64_C(0)) {
            free_slot = i;
        }
    }
    if (free_slot < (size_t)VM64_MAX_WORKERS) {
        atomic_store_explicit(&vm64_workers[free_slot].host_tid, tid,
            memory_order_seq_cst);
        atomic_store_explicit(&vm64_workers[free_slot].state,
            (unsigned)VM64_WORKER_RUNNING_DBT, memory_order_seq_cst);
    }
    return free_slot;
}

/* Register the calling thread in the quiescence worker table with its
 * platform worker id (tgkill target on Linux, worker-table key on
 * Darwin). Idempotent: re-registering a live thread only marks it
 * running. Called once at engine startup for the thread that runs
 * guest code, and on every CLONE_VM worker-thread entry; without it
 * Step-2 preemption has no live addressee. */
void vm64_worker_register(void)
{
    uint64_t tid = rt_host_register_self();
    if (tid == UINT64_C(0)) {
        return;
    }
    vm64_table_lock_acq();
    (void)vm64_find_or_claim_self(tid);
    vm64_table_lock_rel();
}

/* Drop the calling thread's quiescence slot (worker-thread exit). The
 * cleared slot resumes as free: commit's PARKED->RUNNING CAS no-ops on
 * it and prepare skips it by its zero tid. Idempotent. */
void vm64_worker_unregister(void)
{
    uint64_t tid = rt_host_register_self();
    size_t i;
    if (tid == UINT64_C(0)) {
        return;
    }
    vm64_table_lock_acq();
    for (i = 0; i < (size_t)VM64_MAX_WORKERS; i++) {
        uint64_t have = atomic_load_explicit(&vm64_workers[i].host_tid,
            memory_order_seq_cst);
        if (have == tid) {
            atomic_store_explicit(&vm64_workers[i].host_tid,
                UINT64_C(0), memory_order_seq_cst);
            atomic_store_explicit(&vm64_workers[i].state,
                (unsigned)VM64_WORKER_RUNNING_DBT,
                memory_order_seq_cst);
            break;
        }
    }
    vm64_table_lock_rel();
}

/* Live-slot count for tests and diagnostics. */
unsigned vm64_worker_live_count(void)
{
    size_t i;
    unsigned n = 0u;
    vm64_table_lock_acq();
    for (i = 0; i < (size_t)VM64_MAX_WORKERS; i++) {
        if (atomic_load_explicit(&vm64_workers[i].host_tid,
                memory_order_relaxed) != UINT64_C(0)) {
            n++;
        }
    }
    vm64_table_lock_rel();
    return n;
}

/* Historical startup entry: registers the calling (main) thread. */
void vm64_stxn_register_self(void)
{
    vm64_worker_register();
}

/* Steps 1-2: park self, announce the mutation, preempt live peers.
 * The caller registers on demand, so zero or one live worker takes
 * the same fast path as the old single-participant slot. Returns 0,
 * or -VM64_EFAULT when the table is unusable. */
int vm64_stxn_prepare(void)
{
    uint64_t tid;
    size_t idx;
    a2_bind();
    tid = rt_host_register_self();
    if (tid == UINT64_C(0)) {
        return -VM64_EFAULT;
    }
    vm64_table_lock_acq();
    idx = vm64_find_or_claim_self(tid);
    vm64_table_lock_rel();
    if (idx >= (size_t)VM64_MAX_WORKERS) {
        return -VM64_EFAULT;
    }
    a2_txn.self_index = idx;
    return vm64_txn_prepare(&a2_txn);
}

/* Step 3: run the fallible op; on failure the abort below already
 * released the announcement AND resumed self, so the caller returns the
 * negative errno with zero net mutation. */
long vm64_stxn_host_op(long (*op)(void *), void *op_ctx)
{
    long rc;
    unsigned expect;
    a2_bind();
    if (op == NULL) {
        return -VM64_EFAULT;
    }
    rc = vm64_txn_host_op(&a2_txn, op, op_ctx);
    if (rc < 0L) {
        expect = (unsigned)VM64_WORKER_PARKED;
        (void)atomic_compare_exchange_strong_explicit(
            &a2_txn.workers[a2_txn.self_index].state, &expect,
            (unsigned)VM64_WORKER_RUNNING_DBT,
            memory_order_seq_cst, memory_order_seq_cst);
    }
    return rc;
}

/* Steps 4-6: the caller published state after Step 3 succeeded; clear
 * the announcement and resume. */
int vm64_stxn_commit(uint64_t changed_base, uint64_t changed_len)
{
    a2_bind();
    return vm64_txn_commit(&a2_txn, NULL, changed_base, changed_len);
}

/* Abort leg for failures AFTER a successful host op (e.g. a file fill
 * faulting past the mapping publish): drop the announcement and resume
 * self so the engine keeps running with zero net mutation. */
void vm64_stxn_abort(void)
{
    unsigned expect = (unsigned)VM64_WORKER_PARKED;
    a2_bind();
    atomic_store_explicit(&a2_txn.mutating, 0u, memory_order_release);
    (void)atomic_compare_exchange_strong_explicit(
        &a2_txn.workers[a2_txn.self_index].state, &expect,
        (unsigned)VM64_WORKER_RUNNING_DBT,
        memory_order_seq_cst, memory_order_seq_cst);
}

/* Steps 4-6: commit callback publishes VMA/inode state (only reached
 * after Step 3 succeeded), the paired TLB range is invalidated, and
 * all parked workers resume. */
int vm64_txn_commit(vm64_txn_t *txn, vm64_tlb_entry_t *tlb,
    uint64_t changed_base, uint64_t changed_len)
{
    size_t i;
    if (txn == NULL || txn->workers == NULL ||
        txn->self_index >= txn->nworkers) {
        return -VM64_EFAULT;
    }
    /* Steps 4-5: state already published by the caller; invalidate the
     * dependent paired TLB entries across worker contexts (here: the
     * shared table; per-thread tables repeat this loop). */
    vm64_tlb_invalidate_range(tlb, changed_base, changed_len);
    /* Step 6: resume. */
    atomic_store_explicit(&txn->mutating, 0u, memory_order_release);
    for (i = 0; i < txn->nworkers; ++i) {
        unsigned expect = (unsigned)VM64_WORKER_PARKED;
        (void)atomic_compare_exchange_strong_explicit(
            &txn->workers[i].state, &expect,
            (unsigned)VM64_WORKER_RUNNING_DBT, memory_order_seq_cst,
            memory_order_seq_cst);
    }
    return 0;
}
