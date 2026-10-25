/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#include "runtime/file_runtime_limits.h"

#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdlib.h>
#include <sys/resource.h>

struct sparc64_runtime_file_limits {
    pthread_mutex_t lock;
    sparc64_runtime_file_limit_values_t values;
};

int sparc64_runtime_file_limits_create_values(sparc64_runtime_file_limits_t **out,
                                        sparc64_runtime_file_limit_values_t values)
{
    if (out == NULL || *out != NULL || values.soft > values.hard) {
        errno = EINVAL;
        return -1;
    }
    sparc64_runtime_file_limits_t *owner = calloc(1, sizeof(*owner));
    if (owner == NULL)
        return -1;
    int error = pthread_mutex_init(&owner->lock, NULL);
    if (error != 0) {
        free(owner);
        errno = error;
        return -1;
    }
    owner->values = values;
    *out = owner;
    return 0;
}

int sparc64_runtime_file_limits_create_native(sparc64_runtime_file_limits_t **out)
{
    if (out == NULL || *out != NULL) {
        errno = EINVAL;
        return -1;
    }
    struct rlimit limit;
    if (getrlimit(RLIMIT_FSIZE, &limit) != 0)
        return -1;
    sparc64_runtime_file_limit_values_t values = {
        .soft = limit.rlim_cur == RLIM_INFINITY ? UINT64_MAX :
                                                (uint64_t)limit.rlim_cur,
        .hard = limit.rlim_max == RLIM_INFINITY ? UINT64_MAX :
                                                (uint64_t)limit.rlim_max
    };
    return sparc64_runtime_file_limits_create_values(out, values);
}

int sparc64_runtime_file_limits_prlimit(sparc64_runtime_file_limits_t *owner,
    const sparc64_runtime_file_limit_values_t *replacement,
    sparc64_runtime_file_limit_values_t *old_values)
{
    if (owner == NULL || (replacement != NULL &&
                         replacement->soft > replacement->hard)) {
        errno = EINVAL;
        return -1;
    }
    int error = pthread_mutex_lock(&owner->lock);
    if (error != 0) {
        errno = error;
        return -1;
    }
    sparc64_runtime_file_limit_values_t values = owner->values;
    int rejected = 0;
    if (replacement != NULL) {
        if (replacement->hard > values.hard)
            rejected = EPERM;
        else
            owner->values = *replacement;
    }
    error = pthread_mutex_unlock(&owner->lock);
    if (error != 0) {
        errno = error;
        return -1;
    }
    if (rejected != 0) {
        errno = rejected;
        return -1;
    }
    if (old_values != NULL)
        *old_values = values;
    return 0;
}

int sparc64_runtime_file_limits_snapshot(sparc64_runtime_file_limits_t *owner,
                                    sparc64_runtime_file_limit_values_t *out)
{
    if (out == NULL) { errno = EINVAL; return -1; }
    return sparc64_runtime_file_limits_prlimit(owner, NULL, out);
}

void sparc64_runtime_file_limits_destroy(sparc64_runtime_file_limits_t **owner)
{
    if (owner == NULL || *owner == NULL)
        return;
    sparc64_runtime_file_limits_t *current = *owner;
    *owner = NULL;
    if (pthread_mutex_destroy(&current->lock) != 0)
        _Exit(125); /* All guest workers must have retired first. */
    free(current);
}
