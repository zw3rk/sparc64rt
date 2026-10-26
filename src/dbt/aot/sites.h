/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SPARC64RT_AOT_SITES_H
#define SPARC64RT_AOT_SITES_H

#include <stddef.h>
#include <stdint.h>

#include "dbt/mem_sites.h"

/* AOT serialization of dbt_mem_site_t[] recovery records (lane A3).
 *
 * The site table is position-independent (all offsets are byte offsets
 * from the block RX base), so it serializes unchanged: 24 bytes per
 * record in struct field order, all integer wire fields little-endian.
 * This mirrors the relocation codec style in src/dbt/aot/relocate.c.
 * Decoded records carry no authority and must not be executed or
 * published RX; a later owner verifies cache ownership, live guest
 * bytes, and relocation semantics before use.
 */
#define SPARC64_AOT_SITE_BYTES 24u
/* Upper bound per block (at most one site per guest insn; matches
 * SPARC64_DBT_MAX_SITES_PER_BLOCK in src/dbt/emit_mem.h). */
#define SPARC64_AOT_SITES_MAX 64u

/* Exact wire size of n_sites records. Fails with errno EINVAL when
 * n_sites is 0 or above SPARC64_AOT_SITES_MAX. */
int sparc64_aot_sites_encoded_size(uint32_t n_sites, size_t *size);
/* Encode n_sites records into dst[0, cap). Fails with errno EINVAL on
 * bad arguments or unserializable field values (bad width, npc mode,
 * flag bits, or nonzero reserved byte); ENOSPC when cap is short. */
int sparc64_aot_sites_encode(const sparc64_mem_site_t *sites,
    uint32_t n_sites, uint8_t *dst, size_t cap, size_t *written);
/* Decode exactly n_sites records from src[0, len); len must equal
 * n_sites * SPARC64_AOT_SITE_BYTES. Fails with errno EINVAL on bad
 * arguments, short/long input, or unserializable wire values. */
int sparc64_aot_sites_decode(const uint8_t *src, size_t len,
    sparc64_mem_site_t *out, uint32_t n_sites);

#endif
