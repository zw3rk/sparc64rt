/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#define _POSIX_C_SOURCE 200809L
#include "runtime/initial_image.h"
#include "loader/image_internal.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

void sparc64_initial_image_destroy(sparc64_initial_image_t *image)
{
    if (image == NULL)
        return;
    sparc64_program_prepared_destroy(image->program);
    sparc64_linux_exec_args_destroy(&image->args);
    memset(image, 0, sizeof(*image));
}

bool sparc64_initial_image_prepare(const char *target_path, int owned_image_fd,
                               const char *execfn, const char *sysroot,
                               int runtime_fd, int argc, char *const argv[],
                               char *const envp[], sparc64_initial_image_t *out,
                               char *error, size_t error_size)
{
    return sparc64_initial_image_prepare_expected(target_path, owned_image_fd,
        execfn, sysroot, runtime_fd, argc, argv, envp, NULL, out, error, error_size);
}

bool sparc64_initial_image_prepare_expected(const char *target_path, int owned_image_fd,
                               const char *execfn, const char *sysroot,
                               int runtime_fd, int argc, char *const argv[],
                               char *const envp[],
                               const sparc64_image_expectation_t *expected,
                               sparc64_initial_image_t *out,
                               char *error, size_t error_size)
{
    int fd = owned_image_fd;
    sparc64_initial_image_t staged = {0};
    sparc64_path_resolver_t paths = {0};
    struct stat status;
    const char *failure = "cannot prepare initial image";
    if (out != NULL)
        memset(out, 0, sizeof(*out));
    if (target_path == NULL || runtime_fd < 3 || out == NULL || fd == runtime_fd) {
        /* Never close the borrowed private runtime capability. */
        if (fd == runtime_fd)
            fd = -1;
        errno = EINVAL;
        goto failed;
    }
    /* Validate a supplied cap before creating any temporary descriptors that
     * could otherwise reuse an invalid numeric input. main validates it even
     * earlier, before pinning its own executable or creating capture pipes. */
    if (fd >= 0 && fstat(fd, &status) != 0)
        goto failed;
    uint64_t copied = sparc64_linux_exec_args_copy(execfn != NULL ? execfn : target_path,
                                              argc, argv, envp, &staged.args);
    if (copied != 0) {
        failure = "initial arguments exceed bounds or cannot be copied";
        errno = copied == UINT64_C(0) - 12 ? ENOMEM :
                copied == UINT64_C(0) - 36 ? ENAMETOOLONG :
                copied == UINT64_C(0) - 22 ? EINVAL : E2BIG;
        goto failed;
    }
    if (sparc64_path_resolver_init(&paths) != 0 ||
        sparc64_path_protect_fd(&paths, runtime_fd) != 0)
        goto failed;
    if (fd < 0)
        fd = sparc64_path_open(&paths, AT_FDCWD, target_path,
                           O_RDONLY | O_NONBLOCK | O_CLOEXEC, 0);
    if (fd < 0 || fstat(fd, &status) != 0)
        goto failed;
    if (!S_ISREG(status.st_mode)) {
        errno = EACCES;
        goto failed;
    }
    if ((status.st_mode & (S_ISUID | S_ISGID)) != 0) {
        errno = EOPNOTSUPP;
        goto failed;
    }
    int consumed = fd;
    fd = -1;
    unsigned int linux_error = 0;
    bool prepared;
    if (expected == NULL) {
        prepared = sparc64_program_prepare_guest_exec(target_path, consumed, sysroot,
            &paths, &staged.args, &staged.program, error, error_size, &linux_error);
    } else {
        sparc64_object_snapshot_t snapshot = {0};
        prepared = sparc64_object_snapshot_read(target_path, consumed, &snapshot,
            &status, NULL, NULL, true, false, &linux_error, error, error_size);
        if (prepared && !sparc64_image_expectation_match(expected, snapshot.bytes,
                                                     snapshot.size)) {
            free(snapshot.bytes);
            failure = "initial image does not match expected size and SHA-256";
            goto failed;
        }
        if (prepared)
            prepared = sparc64_program_prepare_snapshot(&snapshot, sysroot, true,
                sparc64_image_open_guest_path, &paths, true, &staged.program,
                &linux_error, error, error_size);
        free(snapshot.bytes);
    }
    int saved = errno;
    sparc64_path_resolver_destroy(&paths);
    if (!prepared) {
        sparc64_initial_image_destroy(&staged);
        errno = saved;
        return false;
    }
    *out = staged;
    return true;
failed:
    {
        int saved = errno;
        if (fd >= 0)
            (void)close(fd);
        sparc64_path_resolver_destroy(&paths);
        sparc64_initial_image_destroy(&staged);
        if (error != NULL && error_size != 0) {
            int n = snprintf(error, error_size, "%s: %s", failure, strerror(saved));
            if (n < 0 || (size_t)n >= error_size)
                error[0] = '\0';
        }
        errno = saved;
        return false;
    }
}
