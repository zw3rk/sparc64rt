/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SPARC64RT_LINUX_FUTEX_KEY_H
#define SPARC64RT_LINUX_FUTEX_KEY_H

#include "linux/memory.h"
#include "memory/family_backing.h"
#include "runtime/family_wait.h"

/* Resolve under the uninterrupted current family guard. PRIVATE is numeric
 * mm/VA even on a hole; nonprivate anonymous-private pages use a distinct mm
 * namespace. Shared anonymous views use packed object/offset identity across
 * aliases, remap and fork. Writable private file pages first acquire COW
 * ownership and use the nonprivate mm namespace. Clean read-only inode keys
 * remain an explicit unsupported ABI until inode incarnation is implemented.
 * A true result carries either a key and error=0, or a deliberate guest errno.
 * False denotes a broken runtime ownership/resource contract. */
bool sparc64_linux_futex_key(sparc64_linux_memory_t *memory,
                         sparc64_family_backing_t *backing, uint64_t mm_id,
                         uint64_t address, bool private_key, bool write,
                         sparc64_family_wait_key_t *key, uint64_t *error);

#endif
