/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#define _GNU_SOURCE
#include "loader/image.h"
#include "loader/image_internal.h"
#include "linux/error.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

#ifdef SPARC64RT_TEST_IMAGE_GUEST
int sparc64_image_guest_test_exec_access(int fd);
#endif

static int check_guest_exec_access(int fd)
{
#ifdef SPARC64RT_TEST_IMAGE_GUEST
    return sparc64_image_guest_test_exec_access(fd);
#elif defined(__linux__)
    return faccessat(fd, "", X_OK, AT_EMPTY_PATH | AT_EACCESS);
#else
    (void)fd;
    errno = ENOTSUP;
    return -1;
#endif
}

int sparc64_image_open_guest_path(void *context, const char *path)
{
    sparc64_path_resolver_t *resolver = context;
    int fd = sparc64_path_open(resolver, AT_FDCWD, path,
                          O_RDONLY | O_CLOEXEC | O_NONBLOCK, 0);
    if (fd < 0)
        return -1;
    struct stat status;
    int result = fstat(fd, &status);
    if (result == 0 && !S_ISREG(status.st_mode)) {
        errno = EACCES;
        result = -1;
    }
    if (result == 0 && (status.st_mode & (S_ISUID | S_ISGID)) != 0) {
        errno = EOPNOTSUPP;
        result = -1;
    }
    if (result == 0 && check_guest_exec_access(fd) == 0)
        return fd;
    int saved_errno = errno;
    (void)close(fd);
    errno = saved_errno;
    return -1;
}

static void set_error(char *error, size_t size, const char *message)
{
    if (error == NULL || size == 0)
        return;
    int written = snprintf(error, size, "%s", message);
    if (written < 0 || (size_t)written >= size)
        error[0] = '\0';
}

bool sparc64_program_prepare_guest(const char *path, int owned_target_fd,
                              const char *sysroot,
                              sparc64_path_resolver_t *borrowed_resolver,
                              sparc64_prepared_program_t **out, char *error,
                              size_t error_size, unsigned int *linux_error)
{
    unsigned int captured_linux_error = 0;
    if (out != NULL)
        *out = NULL;
    if (linux_error != NULL)
        *linux_error = 0;
    if (owned_target_fd < 0 || path == NULL || borrowed_resolver == NULL ||
        !borrowed_resolver->initialized || out == NULL) {
        int saved = EINVAL;
        if (owned_target_fd >= 0)
            (void)close(owned_target_fd);
        errno = saved;
        if (linux_error != NULL)
            *linux_error = 22;
        set_error(error, error_size, "invalid guest executable arguments");
        return false;
    }
    bool prepared = sparc64_program_prepare_with_opener(
        path, owned_target_fd, sysroot, sparc64_image_open_guest_path, borrowed_resolver,
        out, &captured_linux_error, error, error_size);
    if (!prepared && captured_linux_error == SPARC64_IMAGE_LINUX_ERRNO_FROM_HOST)
        captured_linux_error = sparc64_linux_errno(errno);
    if (linux_error != NULL)
        *linux_error = captured_linux_error;
    return prepared;
}
