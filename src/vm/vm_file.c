/*
 * src/vm/vm_file.c — Provider A: in-place arena file backing,
 * non-relocating COW and family-shared inode table (Wave U2, lane M2).
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Keeps every guest page in place at its fixed canonical host address
 * HVA = arena_base + gva (UNIFICATION-PLAN Rev 4, section 5.1), so the
 * Soft-TLB addend is constant across the arena: MAP_PRIVATE COW
 * promotion (PAGE_COW_CLEAN -> PAGE_COW_DIRTY) never relocates the
 * page, sibling CLONE_VM threads observe writes immediately, futex
 * wait/wake always address the same HVA, and host fork() COW-clones
 * the MAP_PRIVATE arena natively.
 *
 * Backend independence: host operations are declared as local externs
 * using the section 6 backend names (the coordinator rewires them to
 * src/os/backend.h at merge); no other TU is included. Host page size
 * H is a caller-supplied parameter, never hardcoded. No guest data
 * page is mapped PROT_EXEC (strict W^X); this TU emits no machine
 * code and never touches host register x18.
 */

#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "os/backend.h"

/* ---- Linux errno values as negative codes -------------------------------- */
#define VMF_EINVAL 22
#define VMF_ENOMEM 12
#define VMF_EFAULT 14
#define VMF_ENOENT 2
#define VMF_EIO 5

#define VMF_ABI_PAGE UINT64_C(8192)
#define VMF_ABI_MASK (VMF_ABI_PAGE - UINT64_C(1))
#define VMF_SUB_PAGE UINT64_C(4096)
#define VMF_TASK_SIZE (UINT64_C(1) << 47)

/* Linux msync flags consumed through rt_host_msync. */
#define VMF_MS_SYNC 4

/* Inode table capacity: fixed, no allocator, fork-inherited MAP_SHARED
 * control segment (`.<rt>-family-<pid>-<seq>`) created by the
 * coordinator via rt_host_create_shared_mem. */
#define VMF_INODE_MAX 256u

/* Lightweight family-shared inode control (section 5.1.3), keyed by
 * (st_dev, st_ino, st_ctime_nsec) with a retained open descriptor so
 * unlink + reopen never aliases a live unlinked inode. */
typedef struct {
    _Atomic unsigned valid;
    uint64_t st_dev;
    uint64_t st_ino;
    uint64_t st_ctime_nsec;
    int host_fd;
    _Atomic uint64_t file_size;
    _Atomic uint64_t resize_seq;
    _Atomic uint64_t min_shrunk_since_epoch;
    _Atomic uint64_t code_generation;
    _Atomic uint64_t futex_pin_count;
} vm_inode_shared_t;

typedef struct {
    atomic_flag lock;
    vm_inode_shared_t entries[VMF_INODE_MAX];
    _Atomic uint64_t anon_pin_count;
    _Atomic uint64_t epoch;
} vm_file_table_t;

static inline uint64_t vmf_align_up_8k(uint64_t v)
{
    return (v + VMF_ABI_MASK) & ~VMF_ABI_MASK;
}

static inline uint64_t vmf_align_down_8k(uint64_t v)
{
    return v & ~VMF_ABI_MASK;
}

/* Fixed canonical HVA (section 5.1): addend is constant arena-wide.
 * Returns 0 when gva is outside the user address space. */
uintptr_t vm_file_hva(uintptr_t arena_base, uint64_t gva)
{
    if (gva < VMF_ABI_PAGE || gva >= VMF_TASK_SIZE) {
        return (uintptr_t)0;
    }
    return arena_base + (uintptr_t)gva;
}

/* ---- Family inode table --------------------------------------------------- */

void vm_file_table_init(vm_file_table_t *t)
{
    unsigned i;
    if (t == NULL) {
        return;
    }
    atomic_flag_clear(&t->lock);
    for (i = 0; i < VMF_INODE_MAX; ++i) {
        atomic_store_explicit(&t->entries[i].valid, 0u,
            memory_order_relaxed);
        t->entries[i].host_fd = -1;
        atomic_store_explicit(&t->entries[i].file_size, UINT64_C(0),
            memory_order_relaxed);
        atomic_store_explicit(&t->entries[i].resize_seq, UINT64_C(0),
            memory_order_relaxed);
        atomic_store_explicit(&t->entries[i].min_shrunk_since_epoch,
            ~UINT64_C(0), memory_order_relaxed);
        atomic_store_explicit(&t->entries[i].code_generation,
            UINT64_C(0), memory_order_relaxed);
        atomic_store_explicit(&t->entries[i].futex_pin_count,
            UINT64_C(0), memory_order_relaxed);
    }
    atomic_store_explicit(&t->anon_pin_count, UINT64_C(0),
        memory_order_relaxed);
    atomic_store_explicit(&t->epoch, UINT64_C(0), memory_order_relaxed);
}

/* Intern (dev, ino, ctime) with a retained fd and current size. Returns
 * the table index, or -1 when full. Existing entries refresh the fd
 * only when the old one is gone (fd < 0), preserving descriptor
 * identity across sibling mappers and post-fork re-mappers. */
int vm_file_intern(vm_file_table_t *t, uint64_t st_dev, uint64_t st_ino,
    uint64_t st_ctime_nsec, int host_fd, uint64_t file_size)
{
    unsigned i;
    unsigned free_slot = VMF_INODE_MAX;
    if (t == NULL || host_fd < 0) {
        return -1;
    }
    while (atomic_flag_test_and_set_explicit(&t->lock,
        memory_order_acquire)) {
    }
    for (i = 0; i < VMF_INODE_MAX; ++i) {
        unsigned v = atomic_load_explicit(&t->entries[i].valid,
            memory_order_relaxed);
        if (v == 0u) {
            if (free_slot == VMF_INODE_MAX) {
                free_slot = i;
            }
            continue;
        }
        if (t->entries[i].st_dev == st_dev &&
            t->entries[i].st_ino == st_ino &&
            t->entries[i].st_ctime_nsec == st_ctime_nsec) {
            if (t->entries[i].host_fd < 0) {
                t->entries[i].host_fd = host_fd;
            }
            atomic_flag_clear_explicit(&t->lock, memory_order_release);
            return (int)i;
        }
    }
    if (free_slot < VMF_INODE_MAX) {
        vm_inode_shared_t *e = &t->entries[free_slot];
        e->st_dev = st_dev;
        e->st_ino = st_ino;
        e->st_ctime_nsec = st_ctime_nsec;
        e->host_fd = host_fd;
        atomic_store_explicit(&e->file_size, file_size,
            memory_order_relaxed);
        atomic_store_explicit(&e->resize_seq, UINT64_C(0),
            memory_order_relaxed);
        atomic_store_explicit(&e->min_shrunk_since_epoch, ~UINT64_C(0),
            memory_order_relaxed);
        atomic_store_explicit(&e->code_generation, UINT64_C(0),
            memory_order_relaxed);
        atomic_store_explicit(&e->futex_pin_count, UINT64_C(0),
            memory_order_relaxed);
        atomic_store_explicit(&e->valid, 1u, memory_order_relaxed);
        atomic_flag_clear_explicit(&t->lock, memory_order_release);
        return (int)free_slot;
    }
    atomic_flag_clear_explicit(&t->lock, memory_order_release);
    return -1;
}

int vm_file_lookup(const vm_file_table_t *t, uint64_t st_dev,
    uint64_t st_ino, uint64_t st_ctime_nsec)
{
    unsigned i;
    if (t == NULL) {
        return -1;
    }
    for (i = 0; i < VMF_INODE_MAX; ++i) {
        if (atomic_load_explicit(&t->entries[i].valid,
                memory_order_relaxed) == 0u) {
            continue;
        }
        if (t->entries[i].st_dev == st_dev &&
            t->entries[i].st_ino == st_ino &&
            t->entries[i].st_ctime_nsec == st_ctime_nsec) {
            return (int)i;
        }
    }
    return -1;
}

/* ---- Mutation hooks (section 5.1.3, complete coverage) ---------------------
 * op_kind covers ftruncate, truncate, openat(O_TRUNC), write,
 * pwrite64, writev, fallocate, sendfile, and copy_file_range. The host
 * syscall runs FIRST (Step 3 of section 4.5); only when host_rc >= 0
 * does this commit file_size + code_generation (Step 4). On host
 * failure it returns host_rc with zero state mutation. */
typedef enum {
    VMF_OP_FTRUNCATE = 0,
    VMF_OP_TRUNCATE = 1,
    VMF_OP_OPEN_TRUNC = 2,
    VMF_OP_WRITE = 3,
    VMF_OP_PWRITE64 = 4,
    VMF_OP_WRITEV = 5,
    VMF_OP_FALLOCATE = 6,
    VMF_OP_SENDFILE = 7,
    VMF_OP_COPY_RANGE = 8
} vm_file_op_t;

/* Discard-range callback: the coordinator flips every MAP_PRIVATE
 * 8 KiB page in [discard_base, discard_base + discard_len) from
 * PAGE_COW_DIRTY back to PAGE_COW_CLEAN (zeroing/refilling from the
 * file), preserving partial final COW_DIRTY pages holding bytes below
 * the shrink point. */
typedef void (*vm_file_discard_fn)(uint64_t discard_base,
    uint64_t discard_len, void *ctx);

long vm_file_commit_resize(vm_file_table_t *t, int index,
    uint64_t new_size, long host_rc, vm_file_op_t op,
    vm_file_discard_fn discard, void *discard_ctx,
    uint64_t *discard_base_out, uint64_t *discard_len_out)
{
    uint64_t old_size;
    (void)op;
    if (t == NULL || index < 0 || (unsigned)index >= VMF_INODE_MAX) {
        return -VMF_EFAULT;
    }
    if (host_rc < 0L) {
        return host_rc;
    }
    old_size = atomic_load_explicit(&t->entries[index].file_size,
        memory_order_relaxed);
    if (new_size < old_size) {
        /* Ordered shrink-then-regrow (section 5.1.3): record the
         * shrink floor, then discard every wholly-removed MAP_PRIVATE
         * page at/above align_up(new_size, 8K). Partial final pages
         * with bytes below new_size stay COW_DIRTY (the discard
         * callback skips them). */
        uint64_t floor = vmf_align_up_8k(new_size);
        uint64_t cur_min = atomic_load_explicit(
            &t->entries[index].min_shrunk_since_epoch,
            memory_order_relaxed);
        if (new_size < cur_min) {
            atomic_store_explicit(
                &t->entries[index].min_shrunk_since_epoch, new_size,
                memory_order_relaxed);
        }
        if (discard_base_out != NULL) {
            *discard_base_out = floor;
        }
        if (discard_len_out != NULL) {
            *discard_len_out = (old_size > floor) ? old_size - floor :
                UINT64_C(0);
        }
        if (discard != NULL && old_size > floor) {
            discard(floor, old_size - floor, discard_ctx);
        }
    } else {
        if (discard_base_out != NULL) {
            *discard_base_out = UINT64_C(0);
        }
        if (discard_len_out != NULL) {
            *discard_len_out = UINT64_C(0);
        }
    }
    atomic_store_explicit(&t->entries[index].file_size, new_size,
        memory_order_relaxed);
    (void)atomic_fetch_add_explicit(&t->entries[index].resize_seq,
        (uint64_t)1, memory_order_relaxed);
    (void)atomic_fetch_add_explicit(&t->entries[index].code_generation,
        (uint64_t)1, memory_order_relaxed);
    return host_rc;
}

/* External non-family truncation check (fable m4): on a Soft-TLB miss
 * to a file-backed page near/past EOF, the caller passes a fresh
 * fstat size; when it differs from the cached size the entry refreshes
 * (bumping code_generation so stale DBT blocks invalidate) and this
 * returns true. */
bool vm_file_refresh_on_miss(vm_file_table_t *t, int index,
    uint64_t fstat_size)
{
    uint64_t cached;
    if (t == NULL || index < 0 || (unsigned)index >= VMF_INODE_MAX) {
        return false;
    }
    cached = atomic_load_explicit(&t->entries[index].file_size,
        memory_order_relaxed);
    if (cached == fstat_size) {
        return false;
    }
    atomic_store_explicit(&t->entries[index].file_size, fstat_size,
        memory_order_relaxed);
    (void)atomic_fetch_add_explicit(&t->entries[index].code_generation,
        (uint64_t)1, memory_order_relaxed);
    return true;
}

/* ---- MAP_SHARED placement vs host page size (section 5.1.2) ---------------
 * Direct MAP_SHARED mapping at HVA needs (gva ^ file_offset) aligned
 * to H - 1. Otherwise the coordinator allocates a family-shared
 * backing page (rt_host_create_shared_mem), populates it with
 * rt_host_pread64, and syncs it back on msync / write / ftruncate /
 * munmap. Returns true when the direct path is legal. */
bool vm_file_shared_direct_ok(uint64_t gva, uint64_t file_offset,
    size_t host_page)
{
    uint64_t mask;
    if (host_page == 0u) {
        return false;
    }
    mask = (uint64_t)host_page - UINT64_C(1);
    return ((gva ^ file_offset) & mask) == UINT64_C(0);
}

/* Cross-TU 8 KiB legs owned by src/vm/vm64.c (same binary, lane A3).
 * vm64_eof_upper_half / vm64_zero_span take plain integer and pointer
 * types. vm64_cow_promote_8k takes vm64.c-local vm64_page_state_t
 * (UNMAPPED = 0, ANON = 1, SHARED = 2, COW_CLEAN = 3, COW_DIRTY = 4,
 * declared in that order); both TUs compile the states as int-sized
 * enums, so the int-punned prototype below is representation-identical
 * and the RC-U2 gate test pins the 3 -> 4 transition at runtime. */
extern bool vm64_cow_promote_8k(int *lower_half, int *upper_half);
extern bool vm64_eof_upper_half(uint64_t file_size, uint64_t map_end,
    uint64_t *zero_start_out, uint64_t *zero_len_out);
extern void vm64_zero_span(void *host_addr, size_t len);

/* Populate a mapping from the file at mmap time (H > 4096 hosts keep
 * MAP_PRIVATE | MAP_ANONYMOUS arena backing at HVA and pread the
 * bytes; H == 4096 hosts map the file directly and never call this).
 * Short reads at EOF leave the tail zero-filled by the caller. */
long vm_file_populate(int host_fd, uint64_t file_offset, void *host_addr,
    size_t len, size_t *moved_out)
{
    size_t done = 0;
    if (host_fd < 0 || host_addr == NULL || len == 0u) {
        return -VMF_EINVAL;
    }
    while (done < len) {
        int64_t got = rt_host_pread64(host_fd,
            (char *)host_addr + done, len - done,
            (int64_t)(file_offset + (uint64_t)done));
        if (got < 0L) {
            return got;
        }
        if (got == 0L) {
            break;
        }
        done += (size_t)got;
    }
    if (moved_out != NULL) {
        *moved_out = done;
    }
    return (long)done;
}

/* ---- Provider-A segment data path (lane A3, RC-U2) ----------------------
 * Populate one 8 KiB-quantized file-backed segment in place at its fixed
 * canonical host address (UNIFICATION-PLAN Rev 4, section 5.1): pread the
 * file bytes, zero the [st_size, 8 KiB) EOF tail (including the upper-half
 * materialization span reported by vm64_eof_upper_half), promote the
 * enclosing 8 KiB page COW_CLEAN -> COW_DIRTY as one unit through
 * vm64_cow_promote_8k, and report full 4 KiB pages completely beyond EOF
 * as a SIGBUS span for the caller to convert (Linux file-mmap fault
 * behavior; the loader uses sparc64_space_map_bus for this).
 *
 * file_size is a fresh fstat st_size taken by the caller. The segment
 * covers file bytes [file_offset, file_offset + seg_len). Returns the
 * number of file bytes populated, or a negative -errno: -VMF_EINVAL on
 * bad arguments, a negative host errno from rt_host_pread64, or -VMF_EIO
 * when the file shrank under the caller (pread hit EOF before file_size
 * bytes were served).
 *
 * lower_state / upper_state track the enclosing 8 KiB page halves as
 * ints (3 = COW_CLEAN, 4 = COW_DIRTY, see above); both may be NULL to
 * skip promotion (fresh anonymous pages, e.g. the ELF loader path).
 * bus_base_out / bus_len_out receive the beyond-EOF span in FILE
 * coordinates (both 0 when no full page lies beyond EOF); either may be
 * NULL. The tail zeroing runs even when the upper-half leg reports
 * nothing, so [file_size, file_offset + seg_len) always reads zero. */
long vm_file_populate_segment(int host_fd, uint64_t file_offset,
    uint64_t file_size, void *host_addr, size_t seg_len,
    int *lower_state, int *upper_state,
    uint64_t *bus_base_out, uint64_t *bus_len_out)
{
    uint64_t avail;
    uint64_t want;
    uint64_t eof_off;
    uint64_t bus;
    uint64_t seg_end;
    size_t done = 0;
    if (bus_base_out != NULL) {
        *bus_base_out = UINT64_C(0);
    }
    if (bus_len_out != NULL) {
        *bus_len_out = UINT64_C(0);
    }
    if (host_fd < 0 || host_addr == NULL || seg_len == 0u) {
        return -VMF_EINVAL;
    }
    if (file_offset > UINT64_MAX - (uint64_t)seg_len) {
        return -VMF_EINVAL;
    }
    seg_end = file_offset + (uint64_t)seg_len;
    avail = file_offset < file_size ? file_size - file_offset : UINT64_C(0);
    want = avail < (uint64_t)seg_len ? avail : (uint64_t)seg_len;
    while (done < (size_t)want) {
        int64_t got = rt_host_pread64(host_fd,
            (char *)host_addr + done, (size_t)want - done,
            (int64_t)(file_offset + (uint64_t)done));
        if (got < 0L) {
            return got;
        }
        if (got == 0L) {
            return -VMF_EIO;
        }
        done += (size_t)got;
    }
    /* [st_size, 8 KiB) EOF zeroing: everything past the last file byte
     * in this segment reads zero (partial-page tail and BSS alike). */
    if (done < seg_len) {
        vm64_zero_span((char *)host_addr + done, seg_len - done);
    }
    /* Upper-half materialization: when the file ends in the lower 4 KiB
     * half of an 8 KiB page and the mapping runs into the upper half,
     * guarantee that span reads zero (idempotent on this substrate,
     * load-bearing where the upper 4 KiB host page maps separately). */
    {
        uint64_t zs = UINT64_C(0);
        uint64_t zl = UINT64_C(0);
        if (vm64_eof_upper_half(file_size, seg_end, &zs, &zl) &&
            zl != UINT64_C(0) && zs >= file_offset &&
            zl <= seg_end - zs) {
            vm64_zero_span((char *)host_addr + (zs - file_offset),
                (size_t)zl);
        }
    }
    /* Whole-8KiB COW promotion: populating file bytes materializes the
     * private copy, so the enclosing page promotes as one indivisible
     * unit (HVA and TLB addend never change). */
    if (lower_state != NULL && upper_state != NULL && done != 0u) {
        (void)vm64_cow_promote_8k(lower_state, upper_state);
    }
    /* Beyond-EOF SIGBUS span: full 4 KiB pages past the last populated
     * byte, in file coordinates for the caller to convert to BUS. */
    eof_off = file_offset + (uint64_t)done;
    bus = eof_off + (VMF_SUB_PAGE - UINT64_C(1));
    if (bus < eof_off) {
        bus = UINT64_MAX;
    }
    bus &= ~(VMF_SUB_PAGE - UINT64_C(1));
    if (bus < seg_end) {
        if (bus_base_out != NULL) {
            *bus_base_out = bus;
        }
        if (bus_len_out != NULL) {
            *bus_len_out = seg_end - bus;
        }
    }
    return (long)done;
}

/* Flush a family-shared backing span to the underlying fd (called on
 * msync, write, ftruncate, munmap for the bounce-span path). */
long vm_file_sync_backing(void *host_addr, size_t len)
{
    int64_t rc;
    if (host_addr == NULL || len == 0u) {
        return -VMF_EINVAL;
    }
    rc = rt_host_msync(host_addr, len, VMF_MS_SYNC);
    return (long)rc;
}

/* ---- Pinned futex admission (section 6.7, local key mirror) ---------------
 * Runs BEFORE the futex bucket lock (Rank 7, inner to Rank 1
 * mmap_lock): promotes PAGE_COW_CLEAN -> PAGE_COW_DIRTY when the
 * waiter will write, pins the backing object while waiters sleep, and
 * converts the value to host endianness (sparc64 guests are BE, so a
 * 32-bit swap applies). The VM lease is held by the caller across
 * this call and released BEFORE entering rt_host_futex_wait_bitset. */

typedef enum {
    VMF_FUTEX_PRIVATE = 1,
    VMF_FUTEX_SHARED_ANON = 2,
    VMF_FUTEX_SHARED_FILE = 3
} vm_futex_key_kind_t;

typedef struct {
    uint32_t kind;
    uint32_t reserved;
    uint64_t owner_id;
    uint64_t mount_id;
    uint64_t offset;
} vm_futex_key_t;

/* Resolve callback (implemented by the coordinator over its page
 * tables): HVA of gva, whether it is a shared-file page, the family
 * table index (or -1), and the backing byte offset. */
typedef bool (*vm_file_resolve_fn)(uint64_t gva, uintptr_t *hva_out,
    bool *shared_file_out, int *table_index_out,
    uint64_t *backing_off_out, void *ctx);

/* In-place promotion callback: flips the enclosing 8 KiB page
 * CLEAN -> DIRTY without changing HVA; returns false when the page
 * cannot be promoted (unmapped, shared). */
typedef bool (*vm_file_promote_fn)(uint64_t gva8k, void *ctx);

static inline uint32_t vmf_bswap32(uint32_t v)
{
    return ((v & UINT32_C(0x000000ff)) << 24) |
        ((v & UINT32_C(0x0000ff00)) << 8) |
        ((v & UINT32_C(0x00ff0000)) >> 8) |
        ((v & UINT32_C(0xff000000)) >> 24);
}

int vm_futex_prepare_and_pin(vm_file_table_t *t,
    vm_file_resolve_fn resolve, vm_file_promote_fn promote, void *ctx,
    uint64_t gva, bool is_write, uint64_t mm_id, uint32_t guest_val,
    uintptr_t *pinned_hva_out, vm_futex_key_t *key_out,
    uint32_t *host_val_out)
{
    uintptr_t hva = (uintptr_t)0;
    bool shared_file = false;
    int index = -1;
    uint64_t backing_off = UINT64_C(0);
    if (t == NULL || resolve == NULL || pinned_hva_out == NULL ||
        key_out == NULL || host_val_out == NULL) {
        return -VMF_EFAULT;
    }
    if (!resolve(gva, &hva, &shared_file, &index, &backing_off, ctx) ||
        hva == (uintptr_t)0) {
        return -VMF_EFAULT;
    }
    if (is_write) {
        if (promote == NULL ||
            !promote(vmf_align_down_8k(gva), ctx)) {
            return -VMF_EFAULT;
        }
    }
    if (shared_file) {
        if (index < 0 || (unsigned)index >= VMF_INODE_MAX) {
            return -VMF_EFAULT;
        }
        (void)atomic_fetch_add_explicit(
            &t->entries[index].futex_pin_count, (uint64_t)1,
            memory_order_relaxed);
        key_out->kind = (uint32_t)VMF_FUTEX_SHARED_FILE;
        key_out->reserved = 0u;
        key_out->owner_id = t->entries[index].st_ino;
        key_out->mount_id = t->entries[index].st_dev;
        key_out->offset = backing_off;
    } else {
        (void)atomic_fetch_add_explicit(&t->anon_pin_count,
            (uint64_t)1, memory_order_relaxed);
        key_out->kind = (uint32_t)VMF_FUTEX_PRIVATE;
        key_out->reserved = 0u;
        key_out->owner_id = mm_id;
        key_out->mount_id = UINT64_C(0);
        key_out->offset = gva;
    }
    *pinned_hva_out = hva;
    *host_val_out = vmf_bswap32(guest_val);
    return 0;
}

/* Release a pin taken by vm_futex_prepare_and_pin (wake path). */
void vm_futex_unpin(vm_file_table_t *t, const vm_futex_key_t *key)
{
    unsigned i;
    if (t == NULL || key == NULL) {
        return;
    }
    if (key->kind == (uint32_t)VMF_FUTEX_SHARED_FILE) {
        for (i = 0; i < VMF_INODE_MAX; ++i) {
            if (atomic_load_explicit(&t->entries[i].valid,
                    memory_order_relaxed) != 0u &&
                t->entries[i].st_ino == key->owner_id &&
                t->entries[i].st_dev == key->mount_id) {
                (void)atomic_fetch_sub_explicit(
                    &t->entries[i].futex_pin_count, (uint64_t)1,
                    memory_order_relaxed);
                return;
            }
        }
        return;
    }
    (void)atomic_fetch_sub_explicit(&t->anon_pin_count, (uint64_t)1,
        memory_order_relaxed);
}
