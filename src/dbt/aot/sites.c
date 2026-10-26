/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#include "dbt/aot/sites.h"
#include "dbt/emit_mem.h"

#include <errno.h>
#include <string.h>

_Static_assert(sizeof(sparc64_mem_site_t) == SPARC64_AOT_SITE_BYTES,
    "dbt_mem_site_t must be 24 bytes");
_Static_assert(SPARC64_AOT_SITES_MAX == 64u &&
    SPARC64_AOT_SITES_MAX <= SPARC64_DBT_MAX_SITES_PER_BLOCK,
    "site section must fit one block");

static uint16_t get16(const uint8_t *p)
{
    return (uint16_t)p[0] | (uint16_t)((uint16_t)p[1] << 8);
}

static uint32_t get32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
        ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void put16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
}

static void put32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

static bool width_valid(unsigned width)
{
    return width == 1u || width == 2u || width == 4u || width == 8u ||
        width == 16u;
}

static bool site_valid(const sparc64_mem_site_t *site)
{
    uint8_t known_flags = (uint8_t)(SPARC64_MEM_F_STORE |
        SPARC64_MEM_F_SIGNED | SPARC64_MEM_F_BE |
        SPARC64_MEM_F_IN_DELAY_SLOT | SPARC64_MEM_F_ATOMIC);
    if (!width_valid(site->width) ||
        site->npc_mode > (uint8_t)SPARC64_NPC_DYNAMIC_CTX ||
        (site->flags & (uint8_t)~known_flags) != 0u ||
        site->reserved != 0u) {
        return false;
    }
    return true;
}

int sparc64_aot_sites_encoded_size(uint32_t n_sites, size_t *size)
{
    if (size == NULL || n_sites == 0u ||
        n_sites > SPARC64_AOT_SITES_MAX) {
        errno = EINVAL;
        return -1;
    }
    *size = (size_t)n_sites * SPARC64_AOT_SITE_BYTES;
    return 0;
}

int sparc64_aot_sites_encode(const sparc64_mem_site_t *sites,
    uint32_t n_sites, uint8_t *dst, size_t cap, size_t *written)
{
    size_t total = 0;
    uint32_t i;
    if (sites == NULL || dst == NULL || written == NULL ||
        sparc64_aot_sites_encoded_size(n_sites, &total) != 0) {
        errno = EINVAL;
        return -1;
    }
    if (cap < total) {
        errno = ENOSPC;
        return -1;
    }
    for (i = 0; i < n_sites; ++i) {
        const sparc64_mem_site_t *site = &sites[i];
        uint8_t *p = dst + (size_t)i * SPARC64_AOT_SITE_BYTES;
        if (!site_valid(site)) {
            errno = EINVAL;
            return -1;
        }
        put16(p, site->seq_start_offset);
        put16(p + 2, site->host_insn_offset);
        put16(p + 4, site->cont_insn_offset);
        put16(p + 6, site->guest_pc_delta);
        put32(p + 8, (uint32_t)site->npc_delta);
        put32(p + 12, site->insn_word);
        put16(p + 16, (uint16_t)site->sp_rollback_delta);
        p[18] = site->npc_mode;
        p[19] = site->width;
        p[20] = site->flags;
        p[21] = site->val_or_dst_reg;
        p[22] = site->addr_base_reg;
        p[23] = site->reserved;
    }
    *written = total;
    return 0;
}

int sparc64_aot_sites_decode(const uint8_t *src, size_t len,
    sparc64_mem_site_t *out, uint32_t n_sites)
{
    size_t total = 0;
    uint32_t i;
    if (src == NULL || out == NULL ||
        sparc64_aot_sites_encoded_size(n_sites, &total) != 0 ||
        len != total) {
        errno = EINVAL;
        return -1;
    }
    for (i = 0; i < n_sites; ++i) {
        const uint8_t *p = src + (size_t)i * SPARC64_AOT_SITE_BYTES;
        sparc64_mem_site_t site;
        if (p[23] != 0u) {
            errno = EINVAL;
            return -1;
        }
        site.seq_start_offset = get16(p);
        site.host_insn_offset = get16(p + 2);
        site.cont_insn_offset = get16(p + 4);
        site.guest_pc_delta = get16(p + 6);
        site.npc_delta = (int32_t)get32(p + 8);
        site.insn_word = get32(p + 12);
        site.sp_rollback_delta = (int16_t)get16(p + 16);
        site.npc_mode = p[18];
        site.width = p[19];
        site.flags = p[20];
        site.val_or_dst_reg = p[21];
        site.addr_base_reg = p[22];
        site.reserved = p[23];
        if (!site_valid(&site)) {
            errno = EINVAL;
            return -1;
        }
        out[i] = site;
    }
    return 0;
}
