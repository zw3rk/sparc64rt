/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SPARC64RT_RUNTIME_MM_RUNTIME_BINDING_H
#define SPARC64RT_RUNTIME_MM_RUNTIME_BINDING_H

#include "linux/file.h"
#include "runtime/mm_view.h"

/* Exact active family guard; view, files and memory must name one image.
 * 0: no canonical view or an unrelated syscall, result untouched.
 * 1: definite guest result. -1: infrastructure failure, result untouched;
 * never fall back to the local Linux memory registry on that path.
 * A preparation ENOMEM is a guest ENOMEM (brk returns the current break).
 * All other canonical transaction failures require runtime termination.
 * File mmap pins the exact guest description until source registration and
 * mapping preparation finish. Internal family descriptors cannot be mapped. */
int sparc64_runtime_mm_dispatch(sparc64_mm_view_t *view, sparc64_family_guard_t *guard,
    sparc64_linux_file_t *files, sparc64_linux_memory_t *memory, uint64_t number,
    const uint64_t arguments[6], uint64_t *guest_result);

#endif
