/* src/os/mem_space.h -- ported from src/rt64/memory/space.h (Wave U1 coordinator).
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SPARC64RT_MEMORY_SPACE_H
#define SPARC64RT_MEMORY_SPACE_H

#include "core/atomic.h"
#include "os/mem_measure.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define SPARC64_PAGE_SIZE UINT64_C(4096)
#define SPARC64_R1_MAX_PAGES ((size_t)65536)
#define SPARC64_RESERVATION_GRANULE ((size_t)16)
#define SPARC64_PAGE_GRANULES ((size_t)256)

/* Guest user address space: 1ULL << 47 (128 TiB, va_bits = 47,
 * AT_PAGESZ = 4096). Guest VAs are full 64-bit values and are never
 * truncated into a 4 GiB window. */
#define SPARC64_VA_BITS 47
#define SPARC64_TASK_SIZE (UINT64_C(1) << SPARC64_VA_BITS)
#define SPARC64_AT_PAGESZ UINT64_C(4096)

enum { SPARC64_MEM_READ = 1, SPARC64_MEM_WRITE = 2, SPARC64_MEM_EXEC = 4 };
typedef enum {
    SPARC64_FAULT_NONE, SPARC64_FAULT_RANGE, SPARC64_FAULT_UNMAPPED, SPARC64_FAULT_PERMISSION,
    SPARC64_FAULT_BUS, SPARC64_FAULT_RESOURCE, SPARC64_FAULT_RETRY, SPARC64_FAULT_INTERNAL
} sparc64_fault_reason_t;

/* RESOURCE is a pre-publication allocation/size limit. INTERNAL denotes a
 * broken guard, redo/refresh, or exhausted monotonic correctness counter. */
static inline bool sparc64_fault_is_runtime(sparc64_fault_reason_t reason)
{
    return reason == SPARC64_FAULT_RESOURCE || reason == SPARC64_FAULT_INTERNAL;
}

typedef struct sparc64_space sparc64_space_t;
typedef struct sparc64_backing sparc64_backing_t;
typedef struct sparc64_page_payload sparc64_page_payload_t;
typedef struct sparc64_file_source sparc64_file_source_t;
typedef struct sparc64_file_refresh_ticket sparc64_file_refresh_ticket_t;

typedef enum {
    SPARC64_REFRESH_READY,
    SPARC64_REFRESH_SAMPLE,
    SPARC64_REFRESH_STALE,
    SPARC64_REFRESH_FAULT
} sparc64_refresh_result_t;
typedef struct sparc64_copyout sparc64_copyout_t;
typedef struct sparc64_io_copyout sparc64_io_copyout_t;

typedef enum {
    SPARC64_PAYLOAD_HEAP,
    SPARC64_PAYLOAD_MANAGED
} sparc64_payload_backend_t;

/* The factory creates one owned payload with references=1, zero-filled 4 KiB
 * bytes, zeroed 256 16-byte write epochs, and a disposer. Bytes/epochs stay aligned for
 * unsigned char/uint64_t access until the last reference is released. A
 * family-backed factory may place many payloads in one retained host view. */
struct sparc64_page_payload {
    unsigned char *bytes;
    uint64_t *epochs;
    size_t references;
    void (*dispose)(sparc64_page_payload_t *payload);
    /* Set when the payload is created. Every alias retains this identity.
     * Legacy private file pages are heap owned; canonical imports are managed. */
    sparc64_payload_backend_t backend;
    /* Managed file state is read from the freshly guarded canonical mirror,
     * rather than any one alias's projected private_cow flag. Heap/custom
     * anonymous payloads leave this NULL. */
    const uint32_t *canonical_private_cow;
};

typedef struct {
    sparc64_page_payload_t *(*create)(void *context);
    void *context; /* Must outlive every payload produced by this factory. */
} sparc64_page_factory_t;

typedef struct {
    sparc64_page_payload_t *payload;
    unsigned char bytes[SPARC64_PAGE_SIZE];
    uint64_t epochs[SPARC64_PAGE_GRANULES];
    bool make_private_cow;
} sparc64_managed_page_update_t;

typedef struct {
    bool (*check_guard)(void *context);
    /* A changed snapshot must not publish when code-generation capacity is
     * exhausted; a later access must still see that pending change. */
    bool (*refresh)(void *context, sparc64_page_payload_t *payload,
                    bool can_publish, bool *changed,
                    sparc64_measure_observer_t *measure);
    /* Origin resolution may allocate during full-span preflight only. A
     * retained-I/O completion passes allow_resolve=false after native input. */
    bool (*check_write)(void *context, sparc64_page_payload_t *payload,
                         bool expected_file, bool allow_resolve);
    bool (*commitv)(void *context, const sparc64_managed_page_update_t *updates,
                    size_t count);
    void *context;
} sparc64_managed_page_ops_t;

/* File-backed pages keep a retained source. Its implementation owns native
 * file identity and checked reads; the sparse core stays independent of native
 * filesystem APIs. refresh may publish clean bytes but must not recurse into
 * guest writes, allocate pages, or mark a page COW. Sources are space-owned. */
struct sparc64_file_source {
    sparc64_space_t *space;
    void (*retain)(sparc64_file_source_t *source);
    void (*release)(sparc64_file_source_t *source);
    bool (*refresh)(sparc64_file_source_t *source, sparc64_backing_t *backing, uint64_t address);
};

struct sparc64_backing {
    /* Process-local view. Shared bytes/epochs live in the retained payload;
     * file refresh/COW state belongs to this view. */
    unsigned char *bytes;
    uint64_t *epochs;
    sparc64_page_payload_t *payload;
    size_t references;
    sparc64_file_source_t *file;
    uint64_t file_offset;
    /* Granules already invalidated by successful native file writes. Refresh
     * publishes their bytes without consuming a second epoch/generation. */
    uint64_t file_notified[4];
    bool private_cow;
    /* Immutable mapped BUS view: bytes/epochs/payload/file are all NULL.
     * Permission checks still apply; there is no fabricated data identity. */
    bool bus_fault;
};

typedef struct {
    uint64_t address;
    unsigned int permissions;
    sparc64_backing_t *backing;
    uint64_t binding_base;
} sparc64_page_t;

/* The default factory creates heap-backed private pages. Factory/view
 * reference counts are process-local and require external serialization.
 * A managed space uses the caller's uninterrupted family guard for the whole
 * operation, including any heap-backed private file pages. */
struct sparc64_space {
    /* Optional process-local observation, never part of guest/shared state. */
    sparc64_measure_observer_t *measure;
    sparc64_page_t *pages;
    sparc64_page_factory_t page_factory;
    sparc64_managed_page_ops_t managed;
    /* Reusable process-local preflight scratch. A successful prepare_write
     * reserves enough space for the matching commit without another malloc. */
    void *epoch_scratch;
    size_t epoch_scratch_capacity;
    size_t count, capacity;
    uint64_t limit;
    /* Conservative code-visibility generation. Advance before any mutation;
     * current R2 blocks never survive a guest write or mapping operation. */
    uint64_t generation;
    uint64_t next_binding;
    uint64_t fault_address;
    sparc64_fault_reason_t fault_reason;
    bool internal_failure; /* Sticky: a later successful access cannot hide it. */
    /* Sticky conservative fallback until JIT file-source guards are present. */
    bool has_file_pages;
    /* Armed only around one ordinary engine attempt. Syscall copyout and
     * loader access keep the established synchronous refresh behavior. */
    void *refresh_context;
    bool (*refresh_check)(void *context, sparc64_space_t *space,
                          const sparc64_page_t *page, uint64_t address,
                          unsigned int permissions);
};

void sparc64_space_init(sparc64_space_t *space, unsigned int xlen);
void sparc64_space_destroy(sparc64_space_t *space);
/* Select a factory only while no pages are mapped. A failed switch leaves the
 * old factory in place. The default heap factory needs no external context. */
bool sparc64_space_set_page_factory(sparc64_space_t *space, sparc64_page_factory_t factory);
/* Select a managed anonymous factory on an empty space. File-private pages
 * retain heap ownership. Every access still requires the current family guard.
 * Architectural stores touching at most two distinct managed payloads use one
 * redo commit; larger copies progress through bounded redo batches. */
bool sparc64_space_set_managed_factory(sparc64_space_t *space, sparc64_page_factory_t factory,
                                  sparc64_managed_page_ops_t managed);
/* Retain/release a process-local view; DATA retains one payload and optional
 * file source, while a BUS view owns no payload or file-source reference. */
bool sparc64_backing_retain(sparc64_backing_t *backing);
void sparc64_backing_release(sparc64_backing_t *backing);
/* Page-aligned ranges. Mapping changes are transactional: failure preserves
 * existing pages, permissions, bindings and generation (fault fields change).
 * merge unions loader permissions; replace discards old bytes in the range.
 * Anonymous aliases now share payload bytes/epochs. Concurrent family use
 * still requires the R5 execution token and packed shared storage. */
bool sparc64_space_map(sparc64_space_t *space, uint64_t address, uint64_t size,
                  unsigned int permissions, bool merge);
/* Mapped address/permissions with no data payload. Every nonempty checked
 * access faults BUS after range/permissions and managed guard validation,
 * including SC with no valid reservation. Transactional like ordinary mapping;
 * aliases/moved pages preserve the fault. Does not enable shared-growth ABI by itself. */
bool sparc64_space_map_bus(sparc64_space_t *space, uint64_t address, uint64_t size,
                      unsigned int permissions, bool replace);
bool sparc64_space_replace(sparc64_space_t *space, uint64_t address, uint64_t size,
                      unsigned int permissions);
/* Retains source once per new backing. File offsets are page-aligned. Beyond
 * EOF is mapped successfully and checked on access. Caller retains its source
 * reference independently; failed mapping preserves all existing ownership. */
bool sparc64_space_map_file(sparc64_space_t *space, uint64_t address, uint64_t size,
                       unsigned int permissions, bool replace,
                       sparc64_file_source_t *source, uint64_t file_offset);
/* Alias a complete anonymous source range at an unused destination. Views are
 * distinct; bytes/epochs are shared. Failure changes no mapping or references.
 * Fresh binding IDs make an old LR reservation invalid after mapping changes. */
bool sparc64_space_alias(sparc64_space_t *space, uint64_t source, uint64_t destination,
                    uint64_t size, unsigned int permissions);
/* Install a retained managed payload at one vacant guest page with a fresh
 * view and binding. The caller must establish that the payload belongs to
 * this space's managed context; the family adapter checks canonical ownership.
 * The caller retains its own payload reference. Failure
 * leaves the registry, generation, bindings and references unchanged. */
bool sparc64_space_map_shared_payload(sparc64_space_t *space, uint64_t address,
                                 unsigned int permissions,
                                 sparc64_page_payload_t *payload);
/* Same atomic vacant-page import, with a retained managed file source. This is
 * an adapter primitive: the caller proves key/source/offset association and
 * implements canonical refresh. It must not pass a legacy heap-file source. */
bool sparc64_space_map_managed_file_payload(sparc64_space_t *space, uint64_t address,
                                        unsigned int permissions,
                                        sparc64_page_payload_t *payload,
                                        sparc64_file_source_t *source, uint64_t offset);
/* Unpublished candidate only: source stays bound to its stable final owner.
 * Both spaces must have the same managed context/limit. The adapter checks the
 * exact guard. Never access candidate bytes/atomics before its page registry
 * is moved into that stable owner; discard may release views without access. */
bool sparc64_space_stage_managed_file_payload(sparc64_space_t *space, uint64_t address,
                                          unsigned int permissions,
                                          sparc64_page_payload_t *payload,
                                          sparc64_file_source_t *source, uint64_t offset);
/* unmap tolerates holes. protect requires every page to be mapped. */
bool sparc64_space_unmap(sparc64_space_t *space, uint64_t address, uint64_t size);
bool sparc64_space_protect(sparc64_space_t *space, uint64_t address, uint64_t size,
                      unsigned int permissions);
/* Transactional private-backing move/resize. Ranges must be identical-start
 * or disjoint, and every source page must exist. Replaces destination pages;
 * preserves source bytes without consulting guest permissions. New pages are
 * zero, and moved bindings invalidate reservations. */
bool sparc64_space_remap(sparc64_space_t *space, uint64_t source, uint64_t old_size,
                    uint64_t destination, uint64_t new_size,
                    unsigned int permissions);
/* Find a page-aligned gap at or above start; never allocate host VA at the
 * guest address. Does not mutate the address space, including fault fields. */
bool sparc64_space_find_hole(const sparc64_space_t *space, uint64_t start, uint64_t size,
                        uint64_t *address);
bool sparc64_space_read(sparc64_space_t *space, uint64_t address, void *bytes,
                   size_t size, unsigned int permissions);
/* Capture one ordinary file page under the current family guard. A SAMPLE
 * ticket retains its backing/source, but carries no borrowed page pointer
 * across the native I/O boundary. READY needs no native sample. */
sparc64_refresh_result_t sparc64_space_refresh_capture(sparc64_space_t *space,
    uint64_t address, unsigned int permissions, sparc64_file_refresh_ticket_t **out);
/* Re-find the exact page/binding under the guard before accepting a detached
 * sample. STALE has made no sample publication and requires fresh capture. */
sparc64_refresh_result_t sparc64_space_refresh_apply(sparc64_space_t *space,
    sparc64_file_refresh_ticket_t *ticket);
bool sparc64_space_write(sparc64_space_t *space, uint64_t address, const void *bytes,
                    size_t size);
/* A guard-held four-byte write with one external transaction boundary.
 * After complete access/counter preflight, commit is called exactly once with
 * 0..2 distinct managed payload updates (zero for heap-only writes). It must
 * publish those updates and their mirrors on success, without other guest
 * writes, mapping changes or releasing the guard. On failure no write is
 * published locally.
 * Set errno=ENOMEM only for a recoverable precommit resource failure; every
 * other failure is internal, including any failure after shared publication.
 * The callback and context are never retained or installed in the space. */
typedef bool (*sparc64_space_word_commit_fn)(void *context,
                                        const sparc64_managed_page_update_t *updates,
                                        size_t count);
bool sparc64_space_write_word_commit(sparc64_space_t *space, uint64_t address,
                                const unsigned char bytes[4],
                                sparc64_space_word_commit_fn commit, void *context);
/* Check destination access and all write-counter capacity before irreversible
 * native I/O. Does not COW or consume write epochs. Caller preserves ownership
 * of mappings/state through the subsequent write. File refresh still applies. */
bool sparc64_space_prepare_write(sparc64_space_t *space, uint64_t address, size_t size);
/* Establish private ownership of the writable file page containing address,
 * without a guest store. Refresh precedes COW. Bytes and mapping bindings stay
 * unchanged; whole-page reservation epochs and code generation advance once.
 * Existing COW/anonymous pages are no-ops after checked write access. This is
 * the ownership side effect of a Linux writable page pin, not a lifetime pin. */
bool sparc64_space_cow_file_page(sparc64_space_t *space, uint64_t address);
/* A native read may consume input before its guest copyout. Prepare the entire
 * possible destination while the caller still owns that input: refresh files,
 * check permissions and all alias/write counters, allocate metadata, and pin
 * local backing views. The caller must hold one uninterrupted worker/family
 * guard and leave guest mappings, contents, and file sources unchanged until
 * commit/discard. This does not make concurrent external file writers safe.
 *
 * Commit is one-shot, copies only actual bytes (<= maximum), and never
 * allocates, refreshes a file, or performs native I/O. Stale state or a failed
 * managed commit is sticky INTERNAL; callers must not replay consumed input.
 * Managed payloads are each patched once in VA order and committed in batches
 * of at most two. Failure after an earlier batch is terminal: its effects are
 * committed batches, not a contiguous guest-VA prefix.
 * A zero-byte commit succeeds without mutation. Discard every token before
 * destroying its space, including after a failed commit. Input bytes must be
 * separate staging storage, not an overlapping guest backing. */
sparc64_copyout_t *sparc64_space_copyout_prepare(sparc64_space_t *space, uint64_t address,
                                       size_t maximum);
bool sparc64_space_copyout_commit(sparc64_copyout_t *copyout, const void *bytes,
                              size_t actual);
void sparc64_space_copyout_discard(sparc64_copyout_t *copyout);
/* Owned I/O completion plan, distinct from the uninterrupted copyout above.
 * Prepare under the family guard before native input is consumed. The space
 * and all file-source owners must outlive this plan; discard under the guard.
 * The plan pins original views and reserves all copyout metadata. The caller
 * may release the guard, but must reacquire it before commit or discard.
 *
 * Commit refreshes CURRENT backing state and checks original mapping bindings
 * and current WRITE permission for the completed prefix only. Unrelated writes
 * are preserved. A changed mapping, protection or file BUS fault stops copying
 * at that page; false with *committed>0 reports a valid guest-VA prefix, false
 * with zero reports EFAULT. The native read may already have consumed more
 * input than that prefix: never replay it. Refresh can perform file I/O, but
 * commit allocates no metadata. Failed counters/guards/managed publication are
 * sticky INTERNAL, not an ordinary partial result; the caller must terminate.
 * Every commit attempt is one-shot, including failed/zero-byte attempts. */
sparc64_io_copyout_t *sparc64_space_io_copyout_prepare(sparc64_space_t *space, uint64_t address,
                                            size_t maximum);
bool sparc64_space_io_copyout_commit(sparc64_io_copyout_t *copyout, const void *bytes,
                                 size_t actual, size_t *committed);
void sparc64_space_io_copyout_discard(sparc64_io_copyout_t *copyout);
/* Loader-only: requires mapped pages but permits initialization of RX data. */
bool sparc64_space_write_initial(sparc64_space_t *space, uint64_t address,
                            const void *bytes, size_t size);
/* R3 is single-threaded. R5 must hold the managed-family token around this
 * entire operation and every other guest memory write. */
bool sparc64_space_atomic(sparc64_space_t *space, const sparc64_atomic_request_t *request,
                      sparc64_atomic_result_t *result);

#endif
