/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#include "linux/wait.h"

#include <limits.h>
#include <stddef.h>

#define WAIT_NOHANG UINT32_C(1)
#define WAIT_EXITED UINT32_C(4)
#define WAIT_NOWAIT UINT32_C(0x01000000)
#define WAIT_KNOWN UINT32_C(0xe100000f)

uint64_t sparc64_linux_waitid_decode(const uint64_t args[6],
                                sparc64_linux_waitid_request_t *out)
{
    if (args == NULL || out == NULL)
        return UINT64_C(0) - 22;
    const uint32_t options = (uint32_t)args[3];
    if ((options & ~WAIT_KNOWN) != 0 || (options & UINT32_C(14)) == 0)
        return UINT64_C(0) - 22;

    const uint32_t which = (uint32_t)args[0];
    const uint32_t id = (uint32_t)args[1];
    int32_t pid;
    if (which == 0) {
        pid = -1;
    } else if (which == 1) {
        if (id == 0 || id > INT32_MAX)
            return UINT64_C(0) - 22;
        pid = (int32_t)id;
    } else if (which == 2 || which == 3) {
        if (id > INT32_MAX)
            return UINT64_C(0) - 22;
        return UINT64_C(0) - 95;
    } else {
        return UINT64_C(0) - 22;
    }
    if ((options & ~(WAIT_NOHANG | WAIT_EXITED | WAIT_NOWAIT)) != 0 ||
        args[4] != 0)
        return UINT64_C(0) - 95;
    *out = (sparc64_linux_waitid_request_t){
        .pid = pid,
        .info_address = args[2],
        .nohang = (options & WAIT_NOHANG) != 0,
        .nowait = (options & WAIT_NOWAIT) != 0
    };
    return 0;
}

uint64_t sparc64_linux_waitid_copyout64(sparc64_space_t *space, uint64_t address,
                                   const sparc64_linux_waitid_info_t *info)
{
    if (space == NULL || info == NULL || info->pid < 0 ||
        (info->pid == 0 &&
         (info->uid != 0 || info->cause != 0 || info->status != 0)) ||
        (info->pid != 0 && (info->cause < 1 || info->cause > 6)))
        return UINT64_C(0) - 22;
    if (address == 0)
        return 0;
    if (address >= space->limit || space->limit - address < 128)
        return UINT64_C(0) - 14;

    /* RISC-V LP64 siginfo's union starts at16. Linux waitid writes neither
     * the alignment word at12 nor si_utime/si_stime at32/40. */
    static const unsigned int offsets[6] = {0, 4, 8, 16, 20, 24};
    const uint32_t words[6] = {
        info->pid == 0 ? 0u : 17u, 0, info->cause,
        (uint32_t)info->pid, info->uid, (uint32_t)info->status
    };
    for (size_t field = 0; field < 6; ++field) {
        unsigned char bytes[4];
        for (unsigned int byte = 0; byte < 4; ++byte)
            bytes[byte] = (unsigned char)(words[field] >> (byte * 8));
        if (!sparc64_space_write(space, address + offsets[field], bytes,
                             sizeof(bytes)))
            return UINT64_C(0) -
                (sparc64_fault_is_runtime(space->fault_reason) ? 12u : 14u);
    }
    return 0;
}
