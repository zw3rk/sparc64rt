/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#include "linux/process.h"

#include <stddef.h>

#define CLONE_PARENT_SETTID_VALUE UINT32_C(0x00100000)
#define CLONE_CHILD_CLEARTID_VALUE UINT32_C(0x00200000)
#define CLONE_CHILD_SETTID_VALUE UINT32_C(0x01000000)
#define CLONE_VM_VALUE UINT32_C(0x00000100)
#define CLONE_VFORK_VALUE UINT32_C(0x00004000)

uint64_t sparc64_linux_fork_decode(const uint64_t args[6],
                              sparc64_linux_fork_request_t *out)
{
    if (args == NULL || out == NULL)
        return UINT64_C(0) - 22;
    const uint32_t flags = (uint32_t)args[0];
    const uint32_t allowed = UINT32_C(17) | CLONE_VM_VALUE |
                             CLONE_VFORK_VALUE | CLONE_PARENT_SETTID_VALUE |
                             CLONE_CHILD_CLEARTID_VALUE |
                             CLONE_CHILD_SETTID_VALUE;
    if ((flags & ~allowed) != 0 || (flags & UINT32_C(255)) != 17u ||
        ((flags & CLONE_VFORK_VALUE) != 0 &&
         (flags & CLONE_VM_VALUE) == 0) ||
        ((flags & CLONE_VM_VALUE) == 0 && args[1] != 0))
        return UINT64_C(0) - 95;
    *out = (sparc64_linux_fork_request_t){
        .mode = (flags & CLONE_VFORK_VALUE) != 0 ?
                    SPARC64_LINUX_FORK_VFORK_MM :
                    (flags & CLONE_VM_VALUE) != 0 ?
                        SPARC64_LINUX_FORK_SHARE_MM : SPARC64_LINUX_FORK_COPY_MM,
        .child_stack = args[1],
        .parent_tid = args[2],
        .child_tid = args[4],
        .parent_set_tid = (flags & CLONE_PARENT_SETTID_VALUE) != 0,
        .child_set_tid = (flags & CLONE_CHILD_SETTID_VALUE) != 0,
        .child_clear_tid = (flags & CLONE_CHILD_CLEARTID_VALUE) != 0
    };
    return 0;
}

uint64_t sparc64_linux_wait4_decode(const uint64_t args[6],
                               sparc64_linux_wait4_request_t *out)
{
    if (args == NULL || out == NULL)
        return UINT64_C(0) - 22;
    int32_t pid = (int32_t)(uint32_t)args[0];
    uint32_t options = (uint32_t)args[2];
    if ((pid <= 0 && pid != -1) || (options & ~UINT32_C(1)) != 0 ||
        args[3] != 0)
        return UINT64_C(0) - 95;
    *out = (sparc64_linux_wait4_request_t){
        .pid = pid, .status_address = args[1], .options = options
    };
    return 0;
}
