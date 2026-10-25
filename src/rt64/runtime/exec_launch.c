/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#define _GNU_SOURCE 1
#include "runtime/exec_launch.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static uint16_t get16(const unsigned char *bytes)
{
    return (uint16_t)((uint16_t)bytes[0] | (uint16_t)((uint16_t)bytes[1] << 8));
}

static uint64_t get64(const unsigned char *bytes)
{
    uint64_t value = 0;
    for (unsigned int i = 0; i < 8; ++i)
        value |= (uint64_t)bytes[i] << (8u * i);
    return value;
}

static bool read_at(int descriptor, void *buffer, size_t length, off_t offset)
{
    ssize_t result;
    do { result = pread(descriptor, buffer, length, offset); }
    while (result < 0 && errno == EINTR);
    return result == (ssize_t)length;
}

bool sparc64_exec_runtime_valid(int descriptor)
{
    struct stat status;
    unsigned char header[64], program_header[56];
    if (descriptor < 3 || fstat(descriptor, &status) != 0 ||
        !S_ISREG(status.st_mode) || status.st_size < 64 ||
        (uint64_t)status.st_size > UINT64_C(67108864) ||
        !read_at(descriptor, header, sizeof(header), 0) ||
        memcmp(header, "\177ELF\002\001\001", 7) != 0 ||
        get16(header + 16) != 3 || get16(header + 18) != 183 ||
        header[20] != 1 || header[21] != 0 || header[22] != 0 || header[23] != 0 ||
        get16(header + 52) != 64 || get16(header + 54) != 56)
        return false;
    uint64_t offset = get64(header + 32);
    uint16_t count = get16(header + 56);
    if (count == 0 || count > 128 || offset > (uint64_t)status.st_size ||
        (uint64_t)count * 56 > (uint64_t)status.st_size - offset)
        return false;
    for (uint16_t i = 0; i < count; ++i) {
        if (!read_at(descriptor, program_header, sizeof(program_header),
                       (off_t)(offset + (uint64_t)i * 56)))
            return false;
        if (program_header[0] == 3 && program_header[1] == 0 &&
            program_header[2] == 0 && program_header[3] == 0)
            return false;
    }
    return true;
}

int sparc64_exec_pin_runtime(const char *bootstrap_argv0)
{
    const char *paths[2] = {"/proc/self/exe", bootstrap_argv0};
    for (size_t i = 0; i < 2; ++i) {
        if (paths[i] == NULL || paths[i][0] == '\0')
            continue;
        int opened = open(paths[i], O_RDONLY | O_CLOEXEC);
        if (opened < 0)
            continue;
        int descriptor = fcntl(opened, F_DUPFD_CLOEXEC, 3);
        (void)close(opened);
        if (descriptor < 0)
            continue;
        if (sparc64_exec_runtime_valid(descriptor))
            return descriptor;
        (void)close(descriptor);
    }
    errno = ENOEXEC;
    return -1;
}

int sparc64_exec_launch(int runtime_fd, sparc64_diagnostic_t *diagnostic,
                     sparc64_exec_state_export_t *state,
                     sparc64_program_export_t *image, sparc64_fd_handoff_t *files,
                     sparc64_family_exec_t *family,
                     int parent_cap_fd,
                     const sparc64_file_service_owner_t *service_owner,
                     int vfork_completion_fd)
{
    int capabilities[SPARC64_FD_TABLE_LIMIT + SPARC64_EXEC_FIXED_CAPS], family_caps[6];
    capabilities[0] = sparc64_exec_state_export_fd(state);
    capabilities[1] = sparc64_program_export_fd(image);
    capabilities[2] = sparc64_fd_handoff_metadata(files);
    bool with_sources = sparc64_family_exec_source_capabilities(family, family_caps) == 0;
    if (!with_sources) {
        if (errno != EOPNOTSUPP || sparc64_family_exec_capabilities(family, family_caps) != 0)
            return -1;
        family_caps[4] = family_caps[5] = -1;
    }
    capabilities[3] = family_caps[0];
    capabilities[4] = family_caps[1];
    capabilities[5] = runtime_fd;
    capabilities[6] = family_caps[2];
    capabilities[7] = family_caps[3];
    capabilities[8] = diagnostic != NULL && diagnostic->owns_direct ?
                        diagnostic->direct_fd : -1;
    capabilities[9] = family_caps[4];
    capabilities[10] = family_caps[5];
    capabilities[11] = parent_cap_fd;
#ifdef SPARC64_RUNTIME_TEST_ATTRIBUTED_FILE
    capabilities[12] = service_owner == NULL ? -1 : service_owner->pidfd;
    capabilities[13] = service_owner == NULL ? -1 : service_owner->observer_fd;
    capabilities[14] = vfork_completion_fd;
#else
    if (service_owner != NULL || vfork_completion_fd >= 0) {
        errno = EINVAL;
        return -1;
    }
#endif
    size_t count = sparc64_fd_handoff_descriptors(files, capabilities + SPARC64_EXEC_FIXED_CAPS);
    if (count > SPARC64_FD_TABLE_LIMIT || !sparc64_exec_caps_distinct(capabilities, count + SPARC64_EXEC_FIXED_CAPS) ||
        !sparc64_exec_runtime_valid(runtime_fd)) {
        errno = EINVAL;
        return -1;
    }
    char numbers[SPARC64_FD_TABLE_LIMIT + SPARC64_EXEC_FIXED_CAPS + 1u][24];
    char *arguments[SPARC64_FD_TABLE_LIMIT + SPARC64_EXEC_FIXED_CAPS + 4u] = {
        "sparc64rt-linux-aarch64", SPARC64_EXEC_RESUME_FLAG};
    for (size_t i = 0; i < count + SPARC64_EXEC_FIXED_CAPS; ++i) {
        int n = snprintf(numbers[i], sizeof(numbers[i]), "%d", capabilities[i]);
        if (n < 0 || (size_t)n >= sizeof(numbers[i])) {
            errno = EOVERFLOW;
            return -1;
        }
        arguments[i < SPARC64_EXEC_FIXED_CAPS ? i + 2 : i + 3] = numbers[i];
    }
    int n = snprintf(numbers[count + SPARC64_EXEC_FIXED_CAPS],
                       sizeof(numbers[count + SPARC64_EXEC_FIXED_CAPS]), "%zu", count);
    if (n < 0 || (size_t)n >= sizeof(numbers[count + SPARC64_EXEC_FIXED_CAPS])) {
        errno = EOVERFLOW;
        return -1;
    }
    arguments[SPARC64_EXEC_FIXED_CAPS + 2u] = numbers[count + SPARC64_EXEC_FIXED_CAPS];
    arguments[count + SPARC64_EXEC_FIXED_CAPS + 3u] = NULL;
    int runtime_flags = fcntl(runtime_fd, F_GETFD);
    int diagnostic_flags = capabilities[8] < 0 ? 0 : fcntl(capabilities[8], F_GETFD);
    int parent_flags = parent_cap_fd < 0 ? 0 : fcntl(parent_cap_fd, F_GETFD);
    if (parent_flags < 0 || (parent_cap_fd >= 0 &&
        (parent_flags & FD_CLOEXEC) == 0)) { errno = EINVAL; return -1; }
#ifdef SPARC64_RUNTIME_TEST_ATTRIBUTED_FILE
    int service_flags[2] = {0, 0};
    for (size_t i = 0; i < 2; ++i)
        if (capabilities[12 + i] >= 0) {
            service_flags[i] = fcntl(capabilities[12 + i], F_GETFD);
            if (service_flags[i] < 0 ||
                (service_flags[i] & FD_CLOEXEC) == 0) {
                errno = EINVAL;
                return -1;
            }
        }
    int vfork_flags = 0;
    if (vfork_completion_fd >= 0) {
        vfork_flags = fcntl(vfork_completion_fd, F_GETFD);
        if (vfork_flags < 0 || (vfork_flags & FD_CLOEXEC) == 0) {
            errno = EINVAL;
            return -1;
        }
    }
#endif
    if (diagnostic_flags < 0 || (capabilities[8] >= 0 &&
            (diagnostic_flags & FD_CLOEXEC) == 0)) {
        errno = EINVAL; return -1;
    }
    bool family_active = false, runtime_attempted = false;
    bool diagnostic_attempted = false;
    bool parent_attempted = false;
#ifdef SPARC64_RUNTIME_TEST_ATTRIBUTED_FILE
    bool service_attempted[2] = {false, false};
    bool vfork_attempted = false;
#endif
    if (runtime_flags < 0 || (runtime_flags & FD_CLOEXEC) == 0) {
        errno = EINVAL;
        return -1;
    }
    if (sparc64_exec_state_export_activate(state) == 0 &&
        sparc64_program_export_activate(image) == 0 &&
        sparc64_fd_handoff_activate(files) == 0 &&
        sparc64_family_exec_activate(family) == 0) {
        family_active = true;
        runtime_attempted = true;
        bool activated = fcntl(runtime_fd, F_SETFD, runtime_flags & ~FD_CLOEXEC) == 0;
        if (activated && capabilities[8] >= 0) {
            diagnostic_attempted = true;
            activated = fcntl(capabilities[8], F_SETFD, diagnostic_flags & ~FD_CLOEXEC) == 0;
        }
        if (activated && parent_cap_fd >= 0) {
            parent_attempted = true;
            activated = fcntl(parent_cap_fd, F_SETFD,
                              parent_flags & ~FD_CLOEXEC) == 0;
        }
#ifdef SPARC64_RUNTIME_TEST_ATTRIBUTED_FILE
        for (size_t i = 0; activated && i < 2; ++i)
            if (capabilities[12 + i] >= 0) {
                service_attempted[i] = true;
                activated = fcntl(capabilities[12 + i], F_SETFD,
                                  service_flags[i] & ~FD_CLOEXEC) == 0;
            }
        if (activated && vfork_completion_fd >= 0) {
            vfork_attempted = true;
            activated = fcntl(vfork_completion_fd, F_SETFD,
                              vfork_flags & ~FD_CLOEXEC) == 0;
        }
#endif
        if (activated) {
#if defined(SPARC64_RUNTIME_TEST_EXEC_NATIVE_FAILURE)
            /* Compile-only fault injection after EVERY capability activation.
             * No production CLI or shipped-runtime behavior selects this. */
            (void)arguments;
            static const char marker[] = "SPARC64RT_TEST_EXEC_NATIVE_FAILURE\n";
            sparc64_diagnostic_write(diagnostic, marker, sizeof(marker) - 1u);
            errno = EIO;
#elif defined(__linux__)
            char *environment[] = {NULL};
            fexecve(runtime_fd, arguments, environment);
#else
            (void)arguments;
            errno = ENOSYS;
#endif
        }
    }
    int saved = errno;
    bool failed = false;
    if (parent_attempted &&
        fcntl(parent_cap_fd, F_SETFD, parent_flags) != 0)
        failed = true;
#ifdef SPARC64_RUNTIME_TEST_ATTRIBUTED_FILE
    if (vfork_attempted &&
        fcntl(vfork_completion_fd, F_SETFD, vfork_flags) != 0)
        failed = true;
    for (size_t i = 0; i < 2; ++i)
        if (service_attempted[i] &&
            fcntl(capabilities[12 + i], F_SETFD, service_flags[i]) != 0)
            failed = true;
#endif
    if (diagnostic_attempted &&
        fcntl(capabilities[8], F_SETFD, diagnostic_flags) != 0)
        failed = true;
    if (runtime_attempted && fcntl(runtime_fd, F_SETFD, runtime_flags) != 0)
        failed = true;
    if (family_active ? sparc64_family_exec_deactivate(family) != 0 :
                        sparc64_family_exec_state(family) == NULL)
        failed = true;
    if (sparc64_fd_handoff_deactivate(files) != 0)
        failed = true;
    if (sparc64_program_export_deactivate(image) != 0)
        failed = true;
    if (sparc64_exec_state_export_deactivate(state) != 0)
        failed = true;
    if (failed)
        _exit(125);
    errno = saved;
    return -1;
}
