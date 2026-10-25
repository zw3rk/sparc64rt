/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#define _POSIX_C_SOURCE 200809L
#include "runtime/exec_launch.h"
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

bool sparc64_exec_caps_distinct(const int *values, size_t count)
{
    if (values == NULL || count < SPARC64_EXEC_FIXED_CAPS ||
        count > SPARC64_FD_TABLE_LIMIT + SPARC64_EXEC_FIXED_CAPS ||
        ((values[9] == -1) != (values[10] == -1)))
        return false;
#ifdef SPARC64_RUNTIME_TEST_ATTRIBUTED_FILE
    if (((values[12] == -1) != (values[13] == -1)) ||
        ((values[9] == -1) != (values[12] == -1)) ||
        (values[14] != -1 && values[12] == -1))
        return false;
#endif
    for (size_t i = 0; i < count; ++i) {
        if (i >= 8 && i < SPARC64_EXEC_FIXED_CAPS && values[i] == -1)
            continue;
        if (values[i] < 3)
            return false;
        for (size_t j = 0; j < i; ++j)
            if (values[i] == values[j])
                return false;
    }
    return true;
}

static bool decimal(const char *text, unsigned long maximum, unsigned long *value)
{
    if (text == NULL || text[0] < '0' || text[0] > '9')
        return false;
    char *end = NULL;
    errno = 0;
    unsigned long parsed = strtoul(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0' || parsed > maximum)
        return false;
    *value = parsed;
    return true;
}

bool sparc64_exec_caps_parse(int argc, char *const argv[], sparc64_exec_caps_t *out)
{
    if (out == NULL || argv == NULL || argc < (int)SPARC64_EXEC_FIXED_CAPS + 3 || argv[1] == NULL ||
        strcmp(argv[1], SPARC64_EXEC_RESUME_FLAG) != 0)
        return false;
    unsigned long count;
    if (!decimal(argv[SPARC64_EXEC_FIXED_CAPS + 2], SPARC64_FD_TABLE_LIMIT, &count) ||
        (unsigned long)(argc - (int)SPARC64_EXEC_FIXED_CAPS - 3) != count)
        return false;
    int all[SPARC64_FD_TABLE_LIMIT + SPARC64_EXEC_FIXED_CAPS];
    for (size_t i = 0; i < SPARC64_EXEC_FIXED_CAPS + count; ++i) {
        unsigned long value;
        size_t index = i < SPARC64_EXEC_FIXED_CAPS ? 2 + i : 3 + i;
        if (argv[index] == NULL)
            return false;
        if (i >= 8 && i < SPARC64_EXEC_FIXED_CAPS && strcmp(argv[index], "-1") == 0) {
            all[i] = -1;
            continue;
        }
        if (!decimal(argv[index], INT_MAX, &value))
            return false;
        all[i] = (int)value;
    }
    if (!sparc64_exec_caps_distinct(all, SPARC64_EXEC_FIXED_CAPS + count))
        return false;
    sparc64_exec_caps_t caps = {.state = all[0], .image = all[1], .descriptors = all[2],
                           .control = all[3], .directory = all[4], .runtime = all[5],
                           .pin_sender = all[6], .pin_receiver = all[7],
                           .diagnostic = all[8], .source_request = all[9],
                           .source_lifetime = all[10], .parent_cap = all[11],
#ifdef SPARC64_RUNTIME_TEST_ATTRIBUTED_FILE
                           .service_pidfd = all[12], .service_observer = all[13],
                           .vfork_completion = all[14],
#endif
                           .count = count};
    for (size_t i = 0; i < SPARC64_FD_TABLE_LIMIT; ++i)
        caps.entries[i] = i < count ? all[SPARC64_EXEC_FIXED_CAPS + i] : -1;
    *out = caps;
    return true;
}

void sparc64_exec_caps_close(sparc64_exec_caps_t *caps)
{
    if (caps == NULL)
        return;
    int *fixed[] = {&caps->state, &caps->image, &caps->descriptors,
                    &caps->control, &caps->directory, &caps->runtime,
                    &caps->pin_sender, &caps->pin_receiver, &caps->diagnostic,
                    &caps->source_request, &caps->source_lifetime,
                    &caps->parent_cap,
#ifdef SPARC64_RUNTIME_TEST_ATTRIBUTED_FILE
                    &caps->service_pidfd, &caps->service_observer,
                    &caps->vfork_completion
#endif
                    };
    for (size_t i = 0; i < sizeof(fixed) / sizeof(fixed[0]); ++i) {
        if (*fixed[i] >= 3)
            (void)close(*fixed[i]);
        *fixed[i] = -1;
    }
    for (size_t i = 0; i < caps->count; ++i) {
        if (caps->entries[i] >= 3)
            (void)close(caps->entries[i]);
        caps->entries[i] = -1;
    }
    caps->count = 0;
}

