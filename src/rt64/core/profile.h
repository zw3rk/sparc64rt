/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SPARC64RT_CORE_PROFILE_H
#define SPARC64RT_CORE_PROFILE_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef enum {
    SPARC64_EXT_I, SPARC64_EXT_M, SPARC64_EXT_A, SPARC64_EXT_F, SPARC64_EXT_D, SPARC64_EXT_C,
    SPARC64_EXT_ZICSR, SPARC64_EXT_ZIFENCEI
} sparc64_extension_id_t;
typedef struct {
    sparc64_extension_id_t id;
    const char *name;
    unsigned int major, minor;
    int hwcap_bit; /* Linux legacy HWCAP; -1 means no corresponding bit. */
} sparc64_extension_t;
typedef struct {
    const char *name;
    unsigned int xlen, elf_class;
    uint32_t elf_float_abi;
    const sparc64_extension_t *extensions;
    size_t extension_count;
} sparc64_profile_t;

/* Immutable implemented-feature data, shared by decoding, ELF admission and
 * Linux capability construction. Addresses of header-local constants are not
 * profile identities; use XLEN/ABI and the extension versions for cache keys.
 * RV32 is deliberately absent until its execution and ABI phase lands. */
static inline const sparc64_profile_t *sparc64_profile_for_xlen(unsigned int xlen)
{
    static const sparc64_extension_t extensions[] = {
        {SPARC64_EXT_I, "I", 2, 1, 8}, {SPARC64_EXT_M, "M", 2, 0, 12},
        {SPARC64_EXT_A, "A", 2, 1, 0}, {SPARC64_EXT_F, "F", 2, 2, 5},
        {SPARC64_EXT_D, "D", 2, 2, 3}, {SPARC64_EXT_C, "C", 2, 0, 2},
        {SPARC64_EXT_ZICSR, "Zicsr", 2, 0, -1},
        {SPARC64_EXT_ZIFENCEI, "Zifencei", 2, 0, -1}
    };
    static const sparc64_profile_t profile = {
        "RV64GC/LP64D", 64, 2, 4, extensions,
        sizeof(extensions) / sizeof(extensions[0])
    };
    return xlen == profile.xlen ? &profile : NULL;
}
static inline bool sparc64_profile_has(unsigned int xlen, sparc64_extension_id_t extension)
{
    const sparc64_profile_t *profile = sparc64_profile_for_xlen(xlen);
    if (profile == NULL)
        return false;
    for (size_t i = 0; i < profile->extension_count; ++i)
        if (profile->extensions[i].id == extension)
            return true;
    return false;
}
static inline uint64_t sparc64_profile_hwcap(const sparc64_profile_t *profile)
{
    uint64_t mask = 0;
    if (profile == NULL)
        return 0;
    for (size_t i = 0; i < profile->extension_count; ++i) {
        int bit = profile->extensions[i].hwcap_bit;
        if (bit >= 0 && bit < 64)
            mask |= UINT64_C(1) << (unsigned int)bit;
    }
    return mask;
}
static inline bool sparc64_profile_accepts_elf(const sparc64_profile_t *profile,
                                          unsigned int elf_class, uint32_t flags)
{
    /* EF_RISCV_RVC is optional. E, TSO, alternate floating ABIs and unknown
     * flags do not silently select another execution profile. */
    return profile != NULL && elf_class == profile->elf_class &&
           (flags & UINT32_C(6)) == profile->elf_float_abi &&
           (flags & ~UINT32_C(7)) == 0 &&
           ((flags & 1u) == 0 || sparc64_profile_has(profile->xlen, SPARC64_EXT_C));
}
#endif
