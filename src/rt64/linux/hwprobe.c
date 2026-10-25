/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#include "linux/hwprobe.h"
#include "core/profile.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Public Linux RISC-V ABI constants, pinned to v6.18 asm/hwprobe.h. */
#define SPARC64_HWPROBE_WHICH_CPUS UINT32_C(1)
#define SPARC64_HWPROBE_CPUSET_SIZE ((size_t)8)
#define SPARC64_HWPROBE_UNKNOWN UINT64_MAX

static uint64_t negative(unsigned int error)
{
    return UINT64_C(0) - error;
}

static uint64_t get64(const unsigned char *bytes)
{
    uint64_t value = 0;
    for (unsigned int i = 0; i < 8; ++i)
        value |= (uint64_t)bytes[i] << (i * 8u);
    return value;
}

static void put64(unsigned char *bytes, uint64_t value)
{
    for (unsigned int i = 0; i < 8; ++i)
        bytes[i] = (unsigned char)(value >> (i * 8u));
}

static uint64_t access_failure(const sparc64_space_t *space)
{
    /* INTERNAL remains sticky and fatal at the runtime dispatch boundary. */
    return negative(sparc64_fault_is_runtime(space->fault_reason) ? 12u : 14u);
}

static bool known_key(uint64_t key)
{
    return key <= 14;
}

static bool mask_key(uint64_t key)
{
    return key == 3 || key == 4 || key == 5 || key == 11 || key == 13 || key == 14;
}

static uint64_t value_for(const sparc64_space_t *space, unsigned int xlen, uint64_t key)
{
    switch (key) {
    case 0: case 1: case 2:
        return 0; /* No assigned hardware vendor/architecture/implementation ID. */
    case 3:
        return sparc64_profile_has(xlen, SPARC64_EXT_I) && sparc64_profile_has(xlen, SPARC64_EXT_M) &&
               sparc64_profile_has(xlen, SPARC64_EXT_A) ? UINT64_C(1) : 0;
    case 4: {
        uint64_t value = 0;
        if (sparc64_profile_has(xlen, SPARC64_EXT_F) && sparc64_profile_has(xlen, SPARC64_EXT_D))
            value |= UINT64_C(1);
        if (sparc64_profile_has(xlen, SPARC64_EXT_C))
            value |= UINT64_C(2);
        return value; /* V, bit manipulation, crypto and added extensions absent. */
    }
    case 5: case 9:
        return 1; /* Ordinary scalar misalignment is emulated; AMOs stay aligned. */
    case 7:
        return space->limit; /* Linux reports the exclusive user-VA ceiling. */
    case 8:
        /* Virtual-profile policy: no usable time CSR and no frequency. This
         * is not a Linux-defined unsupported-frequency sentinel or host clock. */
        return 0;
    case 10:
        return 4; /* Vector misalignment unsupported because V is absent. */
    case 6: case 11: case 12: case 13: case 14:
    default:
        return 0; /* No CBO blocks or vendor extensions. */
    }
}

/* copy_to_user publishes a page prefix before a later mapped-page fault, but
 * rejects a numerically out-of-domain range before publishing any prefix. */
static uint64_t copy_bytes(sparc64_space_t *space, uint64_t address,
                            const unsigned char *bytes, size_t size)
{
    if (address > space->limit || size > space->limit - address)
        return negative(14);
    for (size_t offset = 0; offset < size;) {
        size_t amount = (size_t)(SPARC64_PAGE_SIZE - (address + offset) % SPARC64_PAGE_SIZE);
        if (amount > size - offset)
            amount = size - offset;
        if (!sparc64_space_write(space, address + offset, bytes + offset, amount))
            return access_failure(space);
        offset += amount;
    }
    return 0;
}

/* get_user/put_user on a pair key/value are separate scalar accesses. Do not
 * preflight the whole array: earlier output must survive a later pair fault. */
static uint64_t put_scalar(sparc64_space_t *space, uint64_t address, uint64_t value)
{
    unsigned char bytes[8];
    put64(bytes, value);
    return sparc64_space_write(space, address, bytes, sizeof(bytes)) ? 0 : access_failure(space);
}

uint64_t sparc64_linux_hwprobe(sparc64_space_t *space, unsigned int xlen,
                           const uint64_t arguments[6])
{
    if (space == NULL || arguments == NULL || sparc64_profile_for_xlen(xlen) == NULL)
        return negative(38);
    /* Linux declares flags unsigned int, not uintptr_t. */
    uint32_t flags = (uint32_t)arguments[4];
    if (flags != 0 && flags != SPARC64_HWPROBE_WHICH_CPUS)
        return negative(22);
    bool selecting = flags == SPARC64_HWPROBE_WHICH_CPUS;
    uint64_t cpus_address = arguments[3], cpus_size = arguments[2];
    if (selecting && (cpus_size == 0 || cpus_address == 0))
        return negative(22);
    size_t amount = cpus_size < SPARC64_HWPROBE_CPUSET_SIZE ?
                    (size_t)cpus_size : SPARC64_HWPROBE_CPUSET_SIZE;
    unsigned char cpus[SPARC64_HWPROBE_CPUSET_SIZE] = {0};
    if ((cpus_size != 0 || cpus_address != 0) && amount != 0 &&
        !sparc64_space_read(space, cpus_address, cpus, amount, SPARC64_MEM_READ))
        return access_failure(space);
    uint64_t requested = get64(cpus);
    bool cpu_selected = (requested & UINT64_C(1)) != 0;
    if (selecting) {
        if (requested == 0)
            cpu_selected = true;
    } else if (cpus_size == 0 && cpus_address == 0) {
        cpu_selected = true;
    } else if (!cpu_selected) {
        return negative(22);
    }
    uint64_t pair_address = arguments[0];
    for (uint64_t index = 0; index < arguments[1]; ++index) {
        unsigned char bytes[16];
        size_t read_size = selecting ? sizeof(bytes) : (size_t)8;
        if (!sparc64_space_read(space, pair_address, bytes, read_size, SPARC64_MEM_READ))
            return access_failure(space);
        uint64_t key = get64(bytes);
        if (selecting) {
            if (!known_key(key)) {
                put64(bytes, SPARC64_HWPROBE_UNKNOWN);
                put64(bytes + 8, 0);
                uint64_t result = copy_bytes(space, pair_address, bytes, sizeof(bytes));
                if (result != 0)
                    return result;
                cpu_selected = false;
            } else if (cpu_selected) {
                uint64_t actual = value_for(space, xlen, key), wanted = get64(bytes + 8);
                cpu_selected = mask_key(key) ? (actual & wanted) == wanted : actual == wanted;
            }
        } else {
            uint64_t value = known_key(key) ? value_for(space, xlen, key) : 0;
            if (!known_key(key))
                key = SPARC64_HWPROBE_UNKNOWN;
            uint64_t result = put_scalar(space, pair_address, key);
            if (result != 0)
                return result;
            if (pair_address > UINT64_MAX - 8u)
                return negative(14);
            result = put_scalar(space, pair_address + 8u, value);
            if (result != 0)
                return result;
        }
        if (pair_address > UINT64_MAX - sizeof(bytes))
            return index + 1u < arguments[1] ? negative(14) : 0;
        pair_address += sizeof(bytes);
    }
    if (selecting) {
        for (size_t i = 0; i < sizeof(cpus); ++i)
            cpus[i] = 0;
        cpus[0] = cpu_selected ? 1 : 0;
        return copy_bytes(space, cpus_address, cpus, amount);
    }
    return 0;
}
