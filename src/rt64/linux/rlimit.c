/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#include "linux/rlimit.h"

#include <errno.h>
#include <sys/resource.h>

static uint64_t negative(unsigned int error)
{
    return UINT64_C(0) - error;
}

static uint64_t read_word(const unsigned char *bytes)
{
    uint64_t value = 0;
    for (unsigned int i = 0; i < 8; ++i)
        value |= (uint64_t)bytes[i] << (i * 8);
    return value;
}

static void write_word(unsigned char *bytes, uint64_t value)
{
    for (unsigned int i = 0; i < 8; ++i)
        bytes[i] = (unsigned char)(value >> (i * 8));
}

static uint64_t memory_error(const sparc64_space_t *space)
{
    return negative(sparc64_fault_is_runtime(space->fault_reason) ? 12u : 14u);
}

/* Native RV32 Linux uses a 32-bit unsigned long internally even though this
 * syscall's fields are 64-bit. Values at/above ULONG_MAX denote infinity.
 * Keep that ABI conversion outside the XLEN-independent process owner. */
static uint64_t limit_value(unsigned int xlen, uint64_t value)
{
    return xlen == 32 && value >= UINT32_MAX ?
           UINT64_MAX : value;
}

bool sparc64_linux_fsize_prlimit_dispatch(sparc64_space_t *space,
    sparc64_runtime_file_limits_t *limits, unsigned int xlen,
    uint32_t guest_pid, uint32_t guest_tid, uint64_t number,
    const uint64_t arguments[6], uint64_t *result)
{
    if (number != 261 || space == NULL || limits == NULL || arguments == NULL ||
        result == NULL || guest_pid == 0 || guest_tid == 0 ||
        (xlen != 32 && xlen != 64))
        return false;
    sparc64_runtime_file_limit_values_t replacement = {0}, old = {0};
    unsigned char bytes[16];
    if (arguments[2] != 0) {
        if (!sparc64_space_read(space, arguments[2], bytes, sizeof(bytes), SPARC64_MEM_READ)) {
            *result = memory_error(space);
            return true;
        }
        replacement.soft = limit_value(xlen, read_word(bytes));
        replacement.hard = limit_value(xlen, read_word(bytes + 8));
    }
    /* Linux pid_t and resource arguments discard their upper register bits. */
    uint32_t pid = (uint32_t)arguments[0];
    uint32_t resource = (uint32_t)arguments[1];
    if ((pid & UINT32_C(0x80000000)) != 0) {
        *result = negative(3); /* A negative PID has no task. */
        return true;
    }
    if (pid != 0 && pid != guest_pid && pid != guest_tid) {
        *result = negative(95); /* Cross-process permission/lifetime deferred. */
        return true;
    }
    if (resource >= 16) {
        *result = negative(22);
        return true;
    }
    if (resource != 1) {
        *result = negative(95);
        return true;
    }
    if (sparc64_runtime_file_limits_prlimit(limits,
            arguments[2] != 0 ? &replacement : NULL, &old) != 0) {
        int saved = errno;
        if (saved != EINVAL && saved != EPERM) {
            space->internal_failure = true;
            space->fault_reason = SPARC64_FAULT_INTERNAL;
            *result = negative(5);
        } else
            *result = negative(saved == EINVAL ? 22u : 1u);
        return true;
    }
    if (arguments[3] != 0) {
        write_word(bytes, limit_value(xlen, old.soft));
        write_word(bytes + 8, limit_value(xlen, old.hard));
        if (!sparc64_space_prepare_write(space, arguments[3], sizeof(bytes)) ||
            !sparc64_space_write(space, arguments[3], bytes, sizeof(bytes))) {
            *result = memory_error(space);
            return true;
        }
    }
    *result = 0;
    return true;
}

bool sparc64_linux_fsize_prlimit_native_query(sparc64_space_t *space, unsigned int xlen,
    uint32_t guest_pid, uint32_t guest_tid, uint64_t number,
    const uint64_t arguments[6], uint64_t *result)
{
    if (number != 261 || space == NULL || arguments == NULL || result == NULL ||
        guest_pid == 0 || guest_tid == 0 || (xlen != 32 && xlen != 64))
        return false;
    /* Only the read is supported while ordinary guest file operations use
     * native RLIMIT_FSIZE. A requested update must not mutate an isolated
     * logical owner that those operations would never consult. */
    if (arguments[2] != 0) {
        *result = negative(95);
        return true;
    }
    uint32_t pid = (uint32_t)arguments[0];
    uint32_t resource = (uint32_t)arguments[1];
    if ((pid & UINT32_C(0x80000000)) != 0) {
        *result = negative(3);
        return true;
    }
    if (pid != 0 && pid != guest_pid && pid != guest_tid) {
        *result = negative(95);
        return true;
    }
    if (resource >= 16) {
        *result = negative(22);
        return true;
    }
    if (resource != 1) {
        *result = negative(95);
        return true;
    }
    struct rlimit native;
    if (getrlimit(RLIMIT_FSIZE, &native) != 0) {
        space->internal_failure = true;
        space->fault_reason = SPARC64_FAULT_INTERNAL;
        *result = negative(5);
        return true;
    }
    if (arguments[3] != 0) {
        unsigned char bytes[16];
        uint64_t soft = native.rlim_cur == RLIM_INFINITY ? UINT64_MAX :
                                                        (uint64_t)native.rlim_cur;
        uint64_t hard = native.rlim_max == RLIM_INFINITY ? UINT64_MAX :
                                                        (uint64_t)native.rlim_max;
        write_word(bytes, limit_value(xlen, soft));
        write_word(bytes + 8, limit_value(xlen, hard));
        if (!sparc64_space_prepare_write(space, arguments[3], sizeof(bytes)) ||
            !sparc64_space_write(space, arguments[3], bytes, sizeof(bytes))) {
            *result = memory_error(space);
            return true;
        }
    }
    *result = 0;
    return true;
}
