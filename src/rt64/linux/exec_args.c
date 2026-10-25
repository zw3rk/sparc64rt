/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#include "linux/exec_args.h"

#include "linux/error.h"

#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    char **items;
    size_t count;
    size_t capacity;
} string_vector_t;

static uint64_t guest_error(unsigned int error)
{
    return UINT64_C(0) - (uint64_t)error;
}

static uint64_t host_error(int error)
{
    return guest_error(sparc64_linux_errno(error));
}

void sparc64_linux_exec_args_destroy(sparc64_linux_exec_args_t *args)
{
    if (args == NULL)
        return;
    free(args->path);
    for (size_t i = 0; args->argv != NULL && i < args->argc; ++i)
        free(args->argv[i]);
    for (size_t i = 0; args->envp != NULL && i < args->envc; ++i)
        free(args->envp[i]);
    free(args->argv);
    free(args->envp);
    memset(args, 0, sizeof(*args));
}

static bool budget_string(size_t *total, const char *string)
{
    if (string == NULL)
        return false;
    size_t remaining = SPARC64_LINUX_EXEC_BYTES_MAX - *total;
    for (size_t i = 0; i < remaining; ++i) {
        if (string[i] == '\0') {
            *total += i + 1;
            return true;
        }
    }
    return false;
}

uint64_t sparc64_linux_exec_args_script(sparc64_linux_exec_args_t *args,
                                   const char *interpreter,
                                   const char *optional_argument,
                                   const char *script)
{
    if (args == NULL || args->path == NULL || args->argv == NULL ||
        args->argc == 0 || interpreter == NULL || script == NULL)
        return host_error(EINVAL);
    size_t prefix = optional_argument != NULL ? 3 : 2;
    if (args->argc > SPARC64_LINUX_EXEC_VECTOR_MAX - (prefix - 1) ||
        args->envc > SPARC64_LINUX_EXEC_VECTOR_MAX)
        return host_error(E2BIG);
    size_t total = 0;
    const char *added[3] = {interpreter,
        optional_argument != NULL ? optional_argument : script, script};
    if (!budget_string(&total, args->path))
        return host_error(E2BIG);
    for (size_t i = 0; i < prefix; ++i)
        if (!budget_string(&total, added[i]))
            return host_error(E2BIG);
    for (size_t i = 1; i < args->argc; ++i)
        if (!budget_string(&total, args->argv[i]))
            return host_error(E2BIG);
    for (size_t i = 0; i < args->envc; ++i)
        if (args->envp == NULL || !budget_string(&total, args->envp[i]))
            return host_error(E2BIG);
    size_t count = args->argc + prefix - 1;
    char **items = calloc(count + 1, sizeof(*items));
    if (items == NULL)
        return host_error(ENOMEM);
    for (size_t i = 0; i < prefix; ++i) {
        size_t size = strlen(added[i]) + 1;
        items[i] = malloc(size);
        if (items[i] == NULL) {
            for (size_t j = 0; j < i; ++j)
                free(items[j]);
            free(items);
            return host_error(ENOMEM);
        }
        memcpy(items[i], added[i], size);
    }
    memcpy(items + prefix, args->argv + 1,
           (args->argc - 1) * sizeof(*items));
    free(args->argv[0]);
    free(args->argv);
    args->argv = items;
    args->argc = count;
    return 0;
}

static bool address_add(uint64_t base, size_t offset, uint64_t *result)
{
    if ((uint64_t)offset > UINT64_MAX - base)
        return false;
    *result = base + (uint64_t)offset;
    return true;
}

static bool read_pointer(sparc64_space_t *space, uint64_t address,
                         uint64_t *value)
{
    unsigned char bytes[8];
    if (!sparc64_space_read(space, address, bytes, sizeof(bytes), SPARC64_MEM_READ))
        return false;
    uint64_t decoded = 0;
    for (unsigned int i = 0; i < 8; ++i)
        decoded |= (uint64_t)bytes[i] << (8 * i);
    *value = decoded;
    return true;
}

static uint64_t read_string(sparc64_space_t *space, uint64_t address,
                            size_t maximum, bool path, size_t *total,
                            char **result)
{
    size_t limit = maximum;
    if (limit == 0)
        return host_error(E2BIG);

    size_t capacity = limit < 64 ? limit : 64;
    char *copy = malloc(capacity);
    if (copy == NULL)
        return host_error(ENOMEM);

    for (size_t used = 0; used < limit; ++used) {
        uint64_t at;
        unsigned char byte;
        if (!address_add(address, used, &at) ||
            !sparc64_space_read(space, at, &byte, 1, SPARC64_MEM_READ)) {
            free(copy);
            return host_error(EFAULT);
        }
        if (used == capacity) {
            size_t grown = capacity > limit / 2 ? limit : capacity * 2;
            if (grown <= capacity) {
                free(copy);
                return host_error(ENOMEM);
            }
            char *replacement = realloc(copy, grown);
            if (replacement == NULL) {
                free(copy);
                return host_error(ENOMEM);
            }
            copy = replacement;
            capacity = grown;
        }
        copy[used] = (char)byte;
        if (byte == 0) {
            *total += used + 1;
            *result = copy;
            return 0;
        }
    }
    free(copy);
    return host_error(path ? ENAMETOOLONG : E2BIG);
}

static uint64_t vector_append(string_vector_t *vector, char *string)
{
    if (vector->count == SPARC64_LINUX_EXEC_VECTOR_MAX) {
        free(string);
        return host_error(E2BIG);
    }
    if (vector->count + 1 >= vector->capacity) {
        size_t grown = vector->capacity == 0 ? 8 : vector->capacity * 2;
        if (grown < vector->capacity ||
            grown > SPARC64_LINUX_EXEC_VECTOR_MAX + 1)
            grown = SPARC64_LINUX_EXEC_VECTOR_MAX + 1;
        if (grown <= vector->capacity || grown > SIZE_MAX / sizeof(char *)) {
            free(string);
            return host_error(ENOMEM);
        }
        char **replacement = realloc(vector->items, grown * sizeof(char *));
        if (replacement == NULL) {
            free(string);
            return host_error(ENOMEM);
        }
        vector->items = replacement;
        vector->capacity = grown;
    }
    vector->items[vector->count++] = string;
    vector->items[vector->count] = NULL;
    return 0;
}

static uint64_t read_vector(sparc64_space_t *space, uint64_t guest_vector,
                            size_t *total, string_vector_t *vector)
{
    if (guest_vector == 0)
        return 0;
    for (size_t index = 0; index <= SPARC64_LINUX_EXEC_VECTOR_MAX; ++index) {
        if (index > UINT64_MAX / 8)
            return host_error(EFAULT);
        uint64_t offset = (uint64_t)index * 8;
        if (offset > UINT64_MAX - guest_vector)
            return host_error(EFAULT);
        uint64_t pointer;
        if (!read_pointer(space, guest_vector + offset, &pointer))
            return host_error(EFAULT);
        if (pointer == 0)
            return 0;
        if (index == SPARC64_LINUX_EXEC_VECTOR_MAX)
            return host_error(E2BIG);
        if (*total >= SPARC64_LINUX_EXEC_BYTES_MAX)
            return host_error(E2BIG);
        char *string = NULL;
        uint64_t error = read_string(space, pointer,
            SPARC64_LINUX_EXEC_BYTES_MAX - *total, false, total, &string);
        if (error != 0)
            return error;
        error = vector_append(vector, string);
        if (error != 0)
            return error;
    }
    return host_error(E2BIG);
}

static uint64_t copy_host_string(const char *text, size_t maximum, bool path,
                                  size_t *total, char **out)
{
    if (text == NULL)
        return host_error(EINVAL);
    size_t remaining = SPARC64_LINUX_EXEC_BYTES_MAX - *total;
    size_t limit = maximum < remaining ? maximum : remaining;
    size_t length = 0;
    while (length < limit && text[length] != '\0')
        ++length;
    if (length == limit)
        return host_error(path && limit == maximum ? ENAMETOOLONG : E2BIG);
    char *copy = malloc(length + 1);
    if (copy == NULL)
        return host_error(ENOMEM);
    memcpy(copy, text, length + 1);
    *total += length + 1;
    *out = copy;
    return 0;
}

uint64_t sparc64_linux_exec_args_copy(const char *path, int argc,
                                 char *const argv[], char *const envp[],
                                 sparc64_linux_exec_args_t *out)
{
    if (out == NULL)
        return host_error(EINVAL);
    memset(out, 0, sizeof(*out));
    if (argc < 0 || (argc != 0 && argv == NULL))
        return host_error(EINVAL);
    if ((size_t)argc > SPARC64_LINUX_EXEC_VECTOR_MAX)
        return host_error(E2BIG);
    sparc64_linux_exec_args_t staged = {0};
    string_vector_t arguments = {0}, environment = {0};
    size_t total = 0;
    uint64_t error = copy_host_string(path, SPARC64_LINUX_EXEC_PATH_MAX, true,
                                     &total, &staged.path);
    if (error != 0)
        goto done;
    int count = argc == 0 ? 1 : argc;
    for (int i = 0; i < count; ++i) {
        char *copy = NULL;
        error = copy_host_string(argc == 0 ? "" : argv[i], SPARC64_LINUX_EXEC_BYTES_MAX,
                                  false, &total, &copy);
        if (error != 0)
            goto done;
        error = vector_append(&arguments, copy);
        if (error != 0)
            goto done;
    }
    for (size_t i = 0; envp != NULL && envp[i] != NULL; ++i) {
        if (i == SPARC64_LINUX_EXEC_VECTOR_MAX) {
            error = host_error(E2BIG);
            goto done;
        }
        char *copy = NULL;
        error = copy_host_string(envp[i], SPARC64_LINUX_EXEC_BYTES_MAX, false, &total, &copy);
        if (error != 0)
            goto done;
        error = vector_append(&environment, copy);
        if (error != 0)
            goto done;
    }
    if (environment.items == NULL) {
        environment.items = calloc(1, sizeof(*environment.items));
        if (environment.items == NULL)
            error = host_error(ENOMEM);
    }
done:
    staged.argv = arguments.items;
    staged.argc = arguments.count;
    staged.envp = environment.items;
    staged.envc = environment.count;
    if (error != 0)
        sparc64_linux_exec_args_destroy(&staged);
    else
        *out = staged;
    return error;
}

uint64_t sparc64_linux_exec_args_read(sparc64_space_t *space, uint64_t path,
                                 uint64_t argv, uint64_t envp,
                                 sparc64_linux_exec_args_t *out)
{
    if (out == NULL)
        return host_error(EINVAL);
    memset(out, 0, sizeof(*out));
    if (space == NULL)
        return host_error(EINVAL);

    sparc64_linux_exec_args_t staged = {0};
    string_vector_t arguments = {0}, environment = {0};
    size_t total = 0;
    uint64_t error = read_string(space, path, SPARC64_LINUX_EXEC_PATH_MAX, true,
                                 &total, &staged.path);
    if (error != 0)
        goto fail;

    if (argv != 0) {
        error = read_vector(space, argv, &total, &arguments);
        if (error != 0)
            goto fail;
    }
    if (arguments.count == 0) {
        if (total >= SPARC64_LINUX_EXEC_BYTES_MAX) {
            error = host_error(E2BIG);
            goto fail;
        }
        char *empty = calloc(1, 1);
        if (empty == NULL) {
            error = host_error(ENOMEM);
            goto fail;
        }
        total += 1;
        error = vector_append(&arguments, empty);
        if (error != 0)
            goto fail;
    }
    error = read_vector(space, envp, &total, &environment);
    if (error != 0)
        goto fail;

    if (arguments.items == NULL) {
        arguments.items = calloc(1, sizeof(*arguments.items));
        if (arguments.items == NULL) {
            error = host_error(ENOMEM);
            goto fail;
        }
        arguments.capacity = 1;
    }
    if (environment.items == NULL) {
        environment.items = calloc(1, sizeof(*environment.items));
        if (environment.items == NULL) {
            error = host_error(ENOMEM);
            goto fail;
        }
        environment.capacity = 1;
    }

    staged.argv = arguments.items;
    staged.argc = arguments.count;
    staged.envp = environment.items;
    staged.envc = environment.count;
    *out = staged;
    return 0;

fail:
    free(staged.path);
    for (size_t i = 0; i < arguments.count; ++i)
        free(arguments.items[i]);
    for (size_t i = 0; i < environment.count; ++i)
        free(environment.items[i]);
    free(arguments.items);
    free(environment.items);
    memset(out, 0, sizeof(*out));
    return error;
}
