/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SPARC64RT_RUNTIME_PROC_INVENTORY_H
#define SPARC64RT_RUNTIME_PROC_INVENTORY_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

typedef struct {
    uint64_t mount_id;
    uint32_t dev_major;
    uint32_t dev_minor;
} sparc64_proc_instance_t;

/* Pure bounded parsers for already-read proc text. Return 0 on acceptance or
 * a positive errno value on rejection; they leave errno and output arguments
 * unchanged on failure and perform no proc I/O. The caller must supply an
 * EOF-verified complete capture: a valid truncated prefix is not proof of
 * namespace or mount-view completeness. */
int sparc64_proc_inventory_namespace(const char *text, size_t length,
                                pid_t expected);
int sparc64_proc_inventory_parent(const char *text, size_t length, pid_t expected,
                             pid_t *parent);
int sparc64_proc_inventory_mount(const char *text, size_t length,
                            const sparc64_proc_instance_t *expected);

#endif
