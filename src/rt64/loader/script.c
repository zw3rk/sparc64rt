/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#define _POSIX_C_SOURCE 200809L
#include "loader/script.h"
#include "loader/image_internal.h"
#include "linux/error.h"
#include "linux/exec_args.h"
#include "linux/path.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static bool space_tab(unsigned char c)
{
    return c == ' ' || c == '\t';
}

unsigned int sparc64_script_parse(const unsigned char header[256], sparc64_script_header_t *out)
{
    if (header == NULL || out == NULL)
        return 22;
    memset(out, 0, sizeof(*out));
    if (header[0] != '#' || header[1] != '!')
        return 8;
    unsigned char bytes[257] = {0};
    memcpy(bytes, header, 256);
    size_t end = 0;
    while (end < 256 && bytes[end] != 0 && bytes[end] != '\n')
        ++end;
    if (end == 256 || bytes[end] != '\n') {
        size_t name = 2;
        while (name < 256 && space_tab(bytes[name]))
            ++name;
        if (name == 256)
            return 8;
        size_t terminator = name;
        while (terminator < 256 && bytes[terminator] != 0 &&
               !space_tab(bytes[terminator]))
            ++terminator;
        if (terminator == 256)
            return 8;
        end = 255;
    }
    while (end > 0 && space_tab(bytes[end - 1]))
        --end;
    size_t name = 2;
    while (name <= end && space_tab(bytes[name]))
        ++name;
    if (name >= end)
        return 8;
    size_t separator = name;
    while (separator <= end && bytes[separator] != 0 &&
           !space_tab(bytes[separator]))
        ++separator;
    size_t argument = end + 1;
    if (separator <= end && bytes[separator] != 0) {
        argument = separator;
        while (argument <= end && space_tab(bytes[argument]))
            ++argument;
    }
    bytes[end] = 0;
    if (argument <= end) {
        bytes[separator] = 0;
        out->has_argument = true;
        memcpy(out->argument, bytes + argument, strlen((char *)bytes + argument) + 1);
    }
    memcpy(out->interpreter, bytes + name, strlen((char *)bytes + name) + 1);
    return 0;
}

bool sparc64_program_prepare_guest_exec(const char *host_path, int owned_target_fd,
                                    const char *sysroot,
                                    sparc64_path_resolver_t *resolver,
                                    sparc64_linux_exec_args_t *args,
                                    sparc64_prepared_program_t **out,
                                    char *error, size_t error_size,
                                    unsigned int *linux_error)
{
    int fd = owned_target_fd;
    unsigned int failure = 0;
    sparc64_object_snapshot_t snapshot = {0};
    if (out != NULL)
        *out = NULL;
    if (linux_error != NULL)
        *linux_error = 0;
    if (fd < 0 || host_path == NULL || resolver == NULL ||
        !resolver->initialized || args == NULL || args->path == NULL || out == NULL) {
        errno = EINVAL;
        goto failed;
    }
    char current_script[SPARC64_LINUX_EXEC_PATH_MAX];
    size_t length = strnlen(args->path, sizeof(current_script));
    if (length == sizeof(current_script)) {
        errno = ENAMETOOLONG;
        goto failed;
    }
    memcpy(current_script, args->path, length + 1);
    for (unsigned int depth = 0;; ++depth) {
        /* Linux checks depth before the next handler, after the preceding
         * script has parsed, rewritten argv and opened its interpreter. */
        if (depth > 5) {
            errno = ELOOP;
            goto failed;
        }
        unsigned char header[256];
        struct stat version;
        if (!sparc64_object_header_read(fd, header, &version))
            goto failed;
        if (header[0] != '#' || header[1] != '!') {
            int consumed = fd;
            fd = -1;
            if (!sparc64_object_snapshot_read(host_path, consumed, &snapshot, &version,
                    NULL, NULL, true, false, &failure, error, error_size))
                goto failed;
            bool valid = sparc64_program_prepare_snapshot(&snapshot, sysroot, true,
                sparc64_image_open_guest_path, resolver, true, out, &failure, error, error_size);
            free(snapshot.bytes);
            snapshot.bytes = NULL;
            if (!valid)
                goto failed;
            return true;
        }
        sparc64_script_header_t script;
        failure = sparc64_script_parse(header, &script);
        if (failure != 0) {
            errno = ENOEXEC;
            goto failed;
        }
        uint64_t rewritten = sparc64_linux_exec_args_script(args, script.interpreter,
            script.has_argument ? script.argument : NULL, current_script);
        if (rewritten != 0) {
            failure = (unsigned int)(UINT64_C(0) - rewritten);
            errno = failure == 12 ? ENOMEM : E2BIG;
            goto failed;
        }
        int closed = close(fd);
        fd = -1;
        if (closed != 0)
            goto failed;
        memcpy(current_script, script.interpreter, strlen(script.interpreter) + 1);
        /* Kernel open_exec uses getname_kernel, which permits an empty name
         * and resolves cwd; its regular-file check returns EACCES. Guest
         * pathname syscalls instead reject empty user paths with ENOENT. */
        if (current_script[0] == '\0') {
            errno = EACCES;
            goto failed;
        }
        char resolved[SPARC64_LINUX_HOST_PATH_MAX];
        if (sparc64_linux_path_join(sysroot, current_script, resolved) != 0)
            goto failed;
        fd = sparc64_image_open_guest_path(resolver, resolved);
        if (fd < 0)
            goto failed;
    }
failed:
    {
        int saved = errno;
        if (fd >= 0)
            (void)close(fd);
        free(snapshot.bytes);
        if (failure == 0 || failure == SPARC64_IMAGE_LINUX_ERRNO_FROM_HOST)
            failure = sparc64_linux_errno(saved);
        if (linux_error != NULL)
            *linux_error = failure;
        if (error != NULL && error_size != 0) {
            int written = snprintf(error, error_size, "cannot prepare guest executable (Linux errno %u)", failure);
            if (written < 0 || (size_t)written >= error_size)
                error[0] = '\0';
        }
        errno = saved;
        return false;
    }
}
