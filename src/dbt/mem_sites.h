/*
 * src/dbt/mem_sites.h — Soft-TLB storage, memory-site records (Lane M3)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * UNIFICATION-PLAN Rev 4 section 4.3 contract for sparc64rt: the 32-byte
 * Soft-TLB entry, the 2-instruction per-site miss stub index space, and
 * the purely relative 24-byte dbt_mem_site_t recovery record serialized
 * into AOT block payloads. The translator binds host x20 to
 * &sparc64_dbt_tlb[0] (see trampoline_a64.S); cpu.h stays frozen, so the
 * table lives here as process-global storage with a per-worker follow-up
 * recorded for the coordinator (a frozen-header cpu.h field is required
 * before per-thread tables can hang off sparc64_ctx_t).
 *
 * Register discipline for emitted code: x19 = ctx, x20 = TLB base,
 * x27 = chain entry, x28 = &dbt->epoch, x15 = exit PC, w16 = exit
 * reason. x18 is never used. Instructions 1-6 of the fast path never
 * touch PSTATE.NZCV (which caches guest CCR, see emit_priv.h) and never
 * clobber x0 (value/dst) or x1 (guest effective address).
 */

#ifndef SPARC64RT_DBT_MEM_SITES_H
#define SPARC64RT_DBT_MEM_SITES_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "core/cpu.h"

/* Soft-TLB: 4096 entries of 32 bytes = 128 KiB, indexed by 4 KiB guest
 * virtual page number ((gva >> 12) & 0xFFF). Translation granule stays
 * 4 KiB; every 8 KiB sparc64 guest page transition updates the
 * consecutive pair (vpn and vpn ^ 1) together. */
#define SPARC64_TLB_BITS 12u
#define SPARC64_TLB_SIZE (1u << SPARC64_TLB_BITS)
#define SPARC64_TLB_INVALID_TAG (~UINT64_C(0))

typedef struct {
    uint64_t read_tag;  /* Offset  0: (gva & ~0xFFF) if readable, else ~0 */
    uintptr_t addend;   /* Offset  8: host_page_base - (gva & ~0xFFF)      */
    uint64_t write_tag; /* Offset 16: (gva & ~0xFFF) iff writable and not
                         * COW-clean, code-bearing, or LL-reserved        */
    uint64_t reserved;  /* Offset 24: zero, keeps 32-byte alignment        */
} sparc64_tlb_entry_t;

_Static_assert(sizeof(sparc64_tlb_entry_t) == 32,
    "Soft-TLB entry must be 32 bytes");

/* Process-global Soft-TLB base bound into host x20 by the trampoline.
 * 128 KiB of BSS; zero-initialized tags (~0ULL only after
 * sparc64_tlb_init, since BSS zeroes would read as tag 0). */
extern sparc64_tlb_entry_t sparc64_dbt_tlb[SPARC64_TLB_SIZE];

/* RC-U4 A1: original JMPL/RETURN continuation snapshot. Generated code
 * (e_emit_jmpl_ret) stores the pre-effect branch target here before the
 * delay slot runs, and the dispatcher (dbt_delay_continuation) reads it
 * back instead of recomputing the target from post-CTI registers (the
 * rd write and, for RETURN, the window restore have already committed
 * when a delay-slot miss exits). Written and read by the same worker
 * thread under the big guest lock, so no slot array is needed; the
 * value is only meaningful on a delay-slot miss exit whose exit_dest
 * decodes as JMPL/RETURN (every such exit executes the storing
 * fragment first). Baked as an absolute mov64 like the helper
 * addresses (see emit_mem.h): the AOT writer lane must relocate it. */
extern uint64_t sparc64_dbt_cti_target;

/* Mark every entry invalid. Must run once before translated code runs. */
void sparc64_tlb_init(void);

/* Publish one 4 KiB entry: tag is (gva & ~0xFFF), addend is
 * host_page_base - (gva & ~0xFFF). Readable/writable select which tags
 * go live (the other stays ~0ULL); addend is stored whenever either
 * is set. A no-permission call (both false) leaves the entry invalid.
 * The miss helper calls this after a successful interpreter replay so
 * later accesses to the page hit the inline fast path. */
void sparc64_tlb_fill(uint64_t gva, uintptr_t addend, bool readable,
    bool writable);

/* Drop coverage of [gva, gva + len): under 512 pages invalidate exactly
 * those indices, otherwise clear the whole table (Rev 4 section 4.5). */
void sparc64_tlb_invalidate_gva(uint64_t gva, uint64_t len);

/* How guest npc is recovered for a faulting site. SEQUENTIAL covers
 * plain loads/stores; STATIC_TARGET covers CTI delay slots with a fixed
 * target; DYNAMIC_CTX covers JMPL/RETURN delay slots whose target the
 * dispatcher reads from the sparc64_dbt_cti_target snapshot above. */
typedef enum {
    SPARC64_NPC_SEQUENTIAL = 0,
    SPARC64_NPC_STATIC_TARGET = 1,
    SPARC64_NPC_DYNAMIC_CTX = 2
} sparc64_npc_mode_t;

/* Purely relative 24-byte site record. Offsets are byte offsets from the
 * block RX base, so records serialize into AOT payloads unchanged. */
typedef struct {
    uint16_t seq_start_offset; /* .L_tlb_seq_start_k (ubfx) for rewind   */
    uint16_t host_insn_offset; /* .L_tlb_mem_insn_k (ldr/str)             */
    uint16_t cont_insn_offset; /* .L_tlb_cont_k (resume address)          */
    uint16_t guest_pc_delta;   /* faulting guest PC minus block base      */
    int32_t npc_delta;         /* static-target delta (STATIC_TARGET)    */
    uint32_t insn_word;        /* raw guest instruction word              */
    int16_t sp_rollback_delta; /* signed undo added to r[addr_base_reg]  */
    uint8_t npc_mode;          /* sparc64_npc_mode_t                      */
    uint8_t width;             /* 1, 2, 4, 8, or 16                       */
    uint8_t flags;             /* SPARC64_MEM_F_* below                   */
    uint8_t val_or_dst_reg;    /* arch reg index for load dst / store val */
    uint8_t addr_base_reg;     /* arch base reg index for rollback        */
    uint8_t reserved;
} sparc64_mem_site_t;

_Static_assert(sizeof(sparc64_mem_site_t) == 24,
    "dbt_mem_site_t must be 24 bytes");

/* Site flag bits. */
#define SPARC64_MEM_F_STORE (1u << 0)
#define SPARC64_MEM_F_SIGNED (1u << 1)
#define SPARC64_MEM_F_BE (1u << 2)
#define SPARC64_MEM_F_IN_DELAY_SLOT (1u << 3)
#define SPARC64_MEM_F_ATOMIC (1u << 4)

/* Per-block C-side record baked (by address) into the emitted per-block
 * miss trampoline. Keeps absolute pointers out of the site table so the
 * sites array itself stays position-independent for AOT. */
typedef struct {
    const sparc64_mem_ops_t *mem;
    void *mc;
    uint64_t guest_pc_base;
    uint64_t rx_base;
    uint32_t n_sites;
    sparc64_mem_site_t sites[];
} sparc64_mem_block_t;

sparc64_mem_block_t *sparc64_mem_block_alloc(
    const sparc64_mem_ops_t *mem, void *mc, uint64_t guest_pc_base,
    uint64_t rx_base, uint32_t n_sites);
void sparc64_mem_block_free(sparc64_mem_block_t *blk);

/* Run one guest instruction at exec_pc through the reference
 * interpreter with pc/npc restored afterwards. Returns
 * SPARC64_EXIT_NONE when the instruction completed (caller resumes at
 * the cont address); any other SPARC64_EXIT_* reason is committed into
 * ctx->exit_reason/exit_dest for the dispatcher, with exit_dest at
 * fault_pc (the architectural fault PC: for a delay-slot site the CTI,
 * while exec_pc is the delay-slot instruction itself). */
uint32_t sparc64_mem_slow_step(sparc64_ctx_t *ctx,
    const sparc64_mem_ops_t *mem, void *mc, uint64_t exec_pc,
    uint64_t fault_pc);

/* Miss-trampoline slow path: (ctx, x1 = gva, x0 = val, blk, site_idx).
 * Applies the SP rollback, runs the interpreter step, and returns the
 * resume host address (blk->rx_base + cont offset), or NULL when the
 * step trapped: ctx then carries exit_reason/exit_dest. NZCV handling
 * stays in emitted code (mrs before the call, msr after). */
void *sparc64_mem_miss(sparc64_ctx_t *ctx, uint64_t gva, uint64_t val,
    const sparc64_mem_block_t *blk, uint32_t site_idx);

/* Lane P5: drop only writable Soft-TLB tags over [gva, gva+len) when
 * fresh code lands on the page. Reads keep their fills. */
void sparc64_tlb_evict_writes(uint64_t gva, uint64_t len);

#endif /* SPARC64RT_DBT_MEM_SITES_H */
