/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#define _POSIX_C_SOURCE 200809L
#include "loader/image_internal.h"
#include "core/profile.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define SPARC64_MAX_LOADS 128
#define SPARC64_INTERP_MAX ((size_t)4096)

static uint16_t u16(const unsigned char *p)
{
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}
static uint32_t u32(const unsigned char *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static uint64_t u64(const unsigned char *p)
{
    return (uint64_t)u32(p) | ((uint64_t)u32(p + 4) << 32);
}
static bool inside(uint64_t offset, uint64_t length, uint64_t size)
{
    return offset <= size && length <= size - offset;
}
static bool image_error(char *error, size_t size, const char *message)
{
    if (error != NULL && size != 0) {
        int written = snprintf(error, size, "%s", message);
        if (written < 0 || (size_t)written >= size)
            error[0] = '\0';
    }
    return false;
}

static bool same_snapshot_stat(const struct stat *before, const struct stat *after)
{
#ifdef __APPLE__
    /* POSIX/XSI feature selection exposes scalar nanosecond fields on Darwin. */
    struct timespec before_mtime = {before->st_mtime, before->st_mtimensec};
    struct timespec after_mtime = {after->st_mtime, after->st_mtimensec};
    struct timespec before_ctime = {before->st_ctime, before->st_ctimensec};
    struct timespec after_ctime = {after->st_ctime, after->st_ctimensec};
#else
    struct timespec before_mtime = before->st_mtim, after_mtime = after->st_mtim;
    struct timespec before_ctime = before->st_ctim, after_ctime = after->st_ctim;
#endif
    return before->st_dev == after->st_dev && before->st_ino == after->st_ino &&
           before->st_size == after->st_size &&
           before_mtime.tv_sec == after_mtime.tv_sec && before_mtime.tv_nsec == after_mtime.tv_nsec &&
           before_ctime.tv_sec == after_ctime.tv_sec && before_ctime.tv_nsec == after_ctime.tv_nsec;
}

static bool choose_bias(const sparc64_space_t *space, uint64_t minimum, uint64_t maximum,
                         uint64_t alignment, uint64_t hint, uint64_t *bias)
{
    uint64_t size = maximum - minimum;
    for (unsigned int attempt = 0; attempt < 2; ++attempt) {
        uint64_t cursor = attempt == 0 ? hint : (minimum == 0 ? alignment : 0);
        for (size_t i = 0; i <= space->count; ++i) {
            if (cursor > space->limit || alignment - 1 > space->limit - cursor)
                break;
            uint64_t candidate_bias = (cursor + alignment - 1) & ~(alignment - 1);
            if (maximum > space->limit - candidate_bias)
                break;
            uint64_t base = candidate_bias + minimum;
            if (base < SPARC64_PAGE_SIZE) {
                cursor = alignment;
                continue;
            }
            uint64_t found;
            if (!sparc64_space_find_hole(space, base, size, &found))
                break;
            if (found == base) {
                *bias = candidate_bias;
                return true;
            }
            cursor = found - minimum;
        }
    }
    return false;
}

bool sparc64_object_header_read(int fd, unsigned char header[256], struct stat *version)
{
    struct stat after;
    if (fstat(fd, version) != 0)
        return false;
    if (!S_ISREG(version->st_mode) || version->st_size < 0) {
        errno = EACCES;
        return false;
    }
    memset(header, 0, 256);
    size_t size = version->st_size < 256 ? (size_t)version->st_size : 256;
    for (size_t offset = 0; offset < size;) {
        ssize_t got = pread(fd, header + offset, size - offset, (off_t)offset);
        if (got < 0 && errno == EINTR)
            continue;
        if (got < 0)
            return false;
        if (got == 0) {
            errno = ETXTBSY;
            return false;
        }
        offset += (size_t)got;
    }
    if (fstat(fd, &after) != 0)
        return false;
    if (!same_snapshot_stat(version, &after)) {
        errno = ETXTBSY;
        return false;
    }
    return true;
}

bool sparc64_object_snapshot_read(const char *path, int image_fd,
                            sparc64_object_snapshot_t *snapshot,
                            const struct stat *expected_version,
                            sparc64_image_path_open_fn open_path, void *open_context,
                            bool precise_errno, bool interpreter_object,
                            unsigned int *linux_error, char *error, size_t error_size)
{
    struct stat before, after;
    unsigned char *data = NULL;
    int fd = image_fd;
    bool success = false;
    int failure_errno = ENOEXEC;
    unsigned int failure_linux_errno = interpreter_object ? 80u : 8u;
    const char *failure = "cannot open executable";
    if (path == NULL || snapshot == NULL) {
        if (fd >= 0)
            (void)close(fd);
        if (precise_errno)
            errno = EINVAL;
        if (linux_error != NULL)
            *linux_error = 22;
        return image_error(error, error_size, "invalid image arguments");
    }
    snapshot->bytes = NULL;
    snapshot->size = 0;
    if (fd < 0) {
        fd = open_path != NULL ? open_path(open_context, path) :
             open(path, O_RDONLY | O_CLOEXEC);
    }
    if (fd < 0) {
        failure_errno = precise_errno ? errno : ENOEXEC;
        failure_linux_errno = precise_errno ? SPARC64_IMAGE_LINUX_ERRNO_FROM_HOST : 8u;
        if (precise_errno)
            errno = failure_errno;
        if (linux_error != NULL)
            *linux_error = failure_linux_errno;
        return image_error(error, error_size, failure);
    }
    failure = "executable must be a bounded regular file";
    if (fstat(fd, &before) != 0) {
        failure_errno = errno;
        failure_linux_errno = SPARC64_IMAGE_LINUX_ERRNO_FROM_HOST;
        goto done;
    }
    if (expected_version != NULL && !same_snapshot_stat(expected_version, &before)) {
        failure = "executable changed after header snapshot";
        failure_errno = ETXTBSY;
        failure_linux_errno = 26;
        goto done;
    }
    if (!S_ISREG(before.st_mode)) {
        failure_errno = EACCES;
        failure_linux_errno = 13;
        goto done;
    }
    if (before.st_size < 0 || (uint64_t)before.st_size > SPARC64_IMAGE_MAX_SIZE) {
        failure_errno = ENOEXEC;
        failure_linux_errno = interpreter_object ? 80u : 8u;
        goto done;
    }
    size_t size = (size_t)before.st_size;
    data = malloc(size == 0 ? 1 : size);
    failure = "cannot allocate executable snapshot";
    if (data == NULL) {
        failure_errno = ENOMEM;
        failure_linux_errno = 12;
        goto done;
    }
    for (size_t offset = 0; offset < size;) {
        ssize_t got = pread(fd, data + offset, size - offset, (off_t)offset);
        if (got < 0 && errno == EINTR)
            continue;
        failure = "cannot read complete executable snapshot";
        if (got < 0) {
            failure_errno = errno;
            failure_linux_errno = SPARC64_IMAGE_LINUX_ERRNO_FROM_HOST;
            goto done;
        }
        if (got == 0) {
            failure_errno = ETXTBSY;
            failure_linux_errno = 26;
            goto done;
        }
        offset += (size_t)got;
    }
    failure = "executable changed while snapshotting";
    if (fstat(fd, &after) != 0) {
        failure_errno = errno;
        failure_linux_errno = SPARC64_IMAGE_LINUX_ERRNO_FROM_HOST;
        goto done;
    }
    if (!same_snapshot_stat(&before, &after)) {
        failure_errno = ETXTBSY;
        failure_linux_errno = 26;
        goto done;
    }
    success = true;
done:
    if (close(fd) != 0 && success) {
        failure = "cannot close executable descriptor";
        failure_errno = errno;
        failure_linux_errno = SPARC64_IMAGE_LINUX_ERRNO_FROM_HOST;
        success = false;
    }
    if (!success) {
        free(data);
        if (precise_errno)
            errno = failure_errno;
        if (linux_error != NULL)
            *linux_error = failure_linux_errno;
        return image_error(error, error_size, failure);
    }
    snapshot->bytes = data;
    snapshot->size = size;
    return true;
}

static bool map_snapshot(const sparc64_object_snapshot_t *snapshot, sparc64_space_t *space,
                         sparc64_image_info_t *info, uint64_t hint, bool allow_interp,
                         char interpreter[4096], char *error, size_t error_size)
{
    if (snapshot == NULL || snapshot->bytes == NULL || space == NULL ||
        info == NULL || interpreter == NULL)
        return image_error(error, error_size, "invalid image arguments");
    const unsigned char *data = snapshot->bytes;
    size_t size = snapshot->size;
    bool success = false;
    const char *failure;
    memset(info, 0, sizeof(*info));
    interpreter[0] = '\0';
    failure = "expected little-endian ELF64 RISC-V ET_EXEC or ET_DYN version 1";
    if (size < 64 || memcmp(data, "\177ELF\002\001\001", 7) != 0 ||
        (u16(data + 16) != 2 && u16(data + 16) != 3) ||
        u16(data + 18) != 243 || u32(data + 20) != 1 || u16(data + 52) != 64)
        goto done;
    bool dynamic = u16(data + 16) == 3;
    uint64_t phoff = u64(data + 32), entry = u64(data + 24);
    uint16_t phnum = u16(data + 56);
    uint32_t flags = u32(data + 48);
    failure = "supported LP64D flags only (optional RVC); unsupported ELF ABI flags";
    if (!sparc64_profile_accepts_elf(sparc64_profile_for_xlen(64), data[4], flags))
        goto done;
    failure = "invalid or unsupported program-header table";
    if (u16(data + 54) != 56 || phnum == 0 || phnum == UINT16_MAX ||
        !inside(phoff, (uint64_t)phnum * 56, size))
        goto done;
    struct load {
        uint64_t offset, address, filesz, memsz;
        unsigned int permissions;
    } loads[SPARC64_MAX_LOADS];
    size_t count = 0;
    bool executable_entry = false, have_phdr = false;
    uint64_t phdr = 0, maximum = 0, minimum = UINT64_MAX, alignment = SPARC64_PAGE_SIZE;
    for (uint32_t i = 0; i < phnum; ++i) {
        const unsigned char *ph = data + phoff + (size_t)i * 56;
        uint32_t type = u32(ph), permissions = u32(ph + 4);
        if (type == 0)
            continue;
        if (type == 3) {
            uint64_t offset = u64(ph + 8), length = u64(ph + 32);
            failure = "invalid, duplicate or nested PT_INTERP";
            if (!allow_interp || interpreter[0] != '\0' || length < 2 ||
                length > SPARC64_INTERP_MAX || !inside(offset, length, size) ||
                data[offset + length - 1] != 0 || memchr(data + offset, 0, (size_t)length - 1) != NULL)
                goto done;
            memcpy(interpreter, data + offset, (size_t)length);
            continue;
        }
        if (type != 1)
            continue;
        uint64_t offset = u64(ph + 8), address = u64(ph + 16);
        uint64_t filesz = u64(ph + 32), memsz = u64(ph + 40), align = u64(ph + 48);
        failure = "invalid PT_LOAD size, permissions, file bounds or alignment";
        if (filesz > memsz || !inside(offset, filesz, size) ||
            (permissions & ~UINT32_C(7)) != 0 ||
            (align > 1 && ((align & (align - 1)) != 0 ||
                           address % align != offset % align)))
            goto done;
        if (memsz == 0)
            continue;
        if ((!dynamic && address < SPARC64_PAGE_SIZE) || address >= space->limit ||
            memsz > space->limit - address || count == SPARC64_MAX_LOADS)
            goto done;
        uint64_t end = address + memsz;
        failure = "overlapping PT_LOAD byte ranges";
        for (size_t j = 0; j < count; ++j)
            if (address < loads[j].address + loads[j].memsz && loads[j].address < end)
                goto done;
        /* Linux RISC-V writable pages are also readable. */
        unsigned int access = ((permissions & 6u) ? SPARC64_MEM_READ : 0u) |
                              ((permissions & 2u) ? SPARC64_MEM_WRITE : 0u) |
                              ((permissions & 1u) ? SPARC64_MEM_EXEC : 0u);
        loads[count++] = (struct load){offset, address, filesz, memsz, access};
        if ((access & SPARC64_MEM_EXEC) != 0 && entry >= address && entry < end)
            executable_entry = true;
        if (end > maximum)
            maximum = end;
        uint64_t page = address & ~(SPARC64_PAGE_SIZE - 1);
        if (page < minimum)
            minimum = page;
        if (align > alignment)
            alignment = align;
        if (phoff >= offset && (uint64_t)phnum * 56 <= filesz &&
            phoff - offset <= filesz - (uint64_t)phnum * 56 && (access & SPARC64_MEM_READ))
        {
            phdr = address + (phoff - offset);
            have_phdr = true;
        }
    }
    failure = "executable entry or mapped readable program headers missing";
    if (count == 0 || !executable_entry || (entry & 1u) != 0 || !have_phdr)
        goto done;
    uint64_t maximum_page = (maximum + SPARC64_PAGE_SIZE - 1) & ~(SPARC64_PAGE_SIZE - 1);
    uint64_t bias = 0;
    failure = "cannot place ELF within guest address space";
    if (dynamic && !choose_bias(space, minimum, maximum_page, alignment, hint, &bias))
        goto done;
    for (size_t i = 0; i < count; ++i) {
        if (loads[i].address > space->limit - bias ||
            loads[i].memsz > space->limit - bias - loads[i].address)
            goto done;
        loads[i].address += bias;
        uint64_t base = loads[i].address & ~(SPARC64_PAGE_SIZE - 1);
        uint64_t end = (loads[i].address + loads[i].memsz + SPARC64_PAGE_SIZE - 1) &
                       ~(SPARC64_PAGE_SIZE - 1);
        uint64_t found;
        if (base < SPARC64_PAGE_SIZE ||
            !sparc64_space_find_hole(space, base, end - base, &found) || found != base)
            goto done;
    }
    /* Allocate every segment before copying file bytes: zero backing then
     * union permissions on shared boundary pages without erasing file data. */
    for (size_t i = 0; i < count; ++i) {
        uint64_t base = loads[i].address & ~(SPARC64_PAGE_SIZE - 1);
        uint64_t end = (loads[i].address + loads[i].memsz + SPARC64_PAGE_SIZE - 1) &
                       ~(SPARC64_PAGE_SIZE - 1);
        failure = "cannot map executable within guest memory limits";
        if (!sparc64_space_map(space, base, end - base, loads[i].permissions, true))
            goto done;
    }
    for (size_t i = 0; i < count; ++i) {
        failure = "cannot initialize executable segment";
        if (!sparc64_space_write_initial(space, loads[i].address, data + loads[i].offset,
                                     (size_t)loads[i].filesz))
            goto done;
    }
    *info = (sparc64_image_info_t){.entry = entry + bias, .phdr = phdr + bias,
                             .program_break = maximum_page + bias,
                             .phnum = phnum, .flags = flags,
                             .start_pc = entry + bias, .load_bias = bias};
    success = true;
done:
    return success ? true : image_error(error, error_size, failure);
}

bool sparc64_prepared_validate(const sparc64_prepared_program_t *prepared,
                           char *error, size_t error_size)
{
    if (prepared == NULL || prepared->target.bytes == NULL ||
        (prepared->has_interpreter && prepared->interpreter.bytes == NULL))
        return image_error(error, error_size, "invalid prepared image");
    sparc64_space_t trial;
    sparc64_space_init(&trial, 64);
    sparc64_image_info_t target, loader;
    char interpreter[4096], nested[4096];
    bool valid = map_snapshot(&prepared->target, &trial, &target,
                              UINT64_C(0x100000000), true, interpreter,
                              error, error_size);
    if (valid && (interpreter[0] != '\0') != prepared->has_interpreter)
        valid = image_error(error, error_size, "interpreter record mismatch");
    if (valid && prepared->has_interpreter)
        valid = map_snapshot(&prepared->interpreter, &trial, &loader,
                             UINT64_C(0x2000000000), false, nested,
                             error, error_size);
    sparc64_space_destroy(&trial);
    return valid;
}

void sparc64_program_prepared_destroy(sparc64_prepared_program_t *prepared)
{
    if (prepared == NULL)
        return;
    free(prepared->target.bytes);
    free(prepared->interpreter.bytes);
    free(prepared);
}

bool sparc64_program_prepared_target(const sparc64_prepared_program_t *prepared,
                                const uint8_t **bytes, size_t *size,
                                bool *has_interpreter)
{
    if (prepared == NULL || prepared->target.bytes == NULL ||
        bytes == NULL || size == NULL || has_interpreter == NULL)
        return false;
    *bytes = prepared->target.bytes;
    *size = prepared->target.size;
    *has_interpreter = prepared->has_interpreter;
    return true;
}

bool sparc64_program_prepared_interpreter(const sparc64_prepared_program_t *prepared,
                                     const uint8_t **bytes, size_t *size)
{
    if (prepared == NULL || !prepared->has_interpreter ||
        prepared->interpreter.bytes == NULL ||
        prepared->interpreter.size == 0 || bytes == NULL || size == NULL)
        return false;
    *bytes = prepared->interpreter.bytes;
    *size = prepared->interpreter.size;
    return true;
}

bool sparc64_program_prepared_entry_exec_end(const sparc64_prepared_program_t *prepared,
                                        bool interpreter, uint64_t entry_offset,
                                        uint64_t *end_offset)
{
    if (prepared == NULL || end_offset == NULL ||
        (interpreter && !prepared->has_interpreter))
        return false;
    const sparc64_object_snapshot_t *snapshot = interpreter ?
        &prepared->interpreter : &prepared->target;
    if (snapshot->bytes == NULL || snapshot->size < 64 ||
        u64(snapshot->bytes + 24) != entry_offset)
        return false;
    uint64_t start;
    return sparc64_program_prepared_exec_span(prepared, interpreter, entry_offset,
                                          &start, end_offset);
}

bool sparc64_program_prepared_exec_span(const sparc64_prepared_program_t *prepared,
                                    bool interpreter, uint64_t relative_pc,
                                    uint64_t *start_offset, uint64_t *end_offset)
{
    if (prepared == NULL || start_offset == NULL || end_offset == NULL ||
        (interpreter && !prepared->has_interpreter))
        return false;
    const sparc64_object_snapshot_t *snapshot = interpreter ?
        &prepared->interpreter : &prepared->target;
    if (snapshot->bytes == NULL || snapshot->size < 64)
        return false;
    const unsigned char *data = snapshot->bytes;
    uint64_t phoff = u64(data + 32);
    uint16_t count = u16(data + 56);
    if (count == 0 ||
        !inside(phoff, (uint64_t)count * 56u, snapshot->size))
        return false;
    for (uint16_t i = 0; i < count; ++i) {
        const unsigned char *ph = data + phoff + (size_t)i * 56u;
        uint64_t start = u64(ph + 16), length = u64(ph + 40);
        if (u32(ph) == 1 && (u32(ph + 4) & 1u) != 0 &&
            start <= relative_pc && length != 0 &&
            length <= UINT64_MAX - start && relative_pc < start + length) {
            *start_offset = start;
            *end_offset = start + length;
            return true;
        }
    }
    return false;
}

bool sparc64_program_prepare_snapshot(sparc64_object_snapshot_t *snapshot, const char *sysroot,
                            bool validate_combined_placement,
                            sparc64_image_path_open_fn open_path, void *open_context,
                            bool precise_errno, sparc64_prepared_program_t **out,
                            unsigned int *linux_error,
                            char *error, size_t error_size)
{
    if (linux_error != NULL)
        *linux_error = 0;
    if (out == NULL || snapshot == NULL || snapshot->bytes == NULL) {
        if (precise_errno)
            errno = EINVAL;
        if (linux_error != NULL)
            *linux_error = 22;
        return image_error(error, error_size, "invalid image arguments");
    }
    *out = NULL;
    sparc64_prepared_program_t *prepared = calloc(1, sizeof(*prepared));
    if (prepared == NULL) {
        if (precise_errno)
            errno = ENOMEM;
        if (linux_error != NULL)
            *linux_error = 12;
        return image_error(error, error_size, "cannot allocate executable snapshot");
    }
    prepared->target = *snapshot;
    memset(snapshot, 0, sizeof(*snapshot));
    /* Validate both complete ELF objects in a disposable fresh address space.
     * The destination may still reject mapping due to its own mappings or
     * resource limits; no file path is revisited after this point. */
    sparc64_space_t trial;
    sparc64_space_init(&trial, 64);
    sparc64_image_info_t target, loader;
    char interpreter[4096], nested[4096], resolved[8192];
    bool valid = map_snapshot(&prepared->target, &trial, &target,
                              UINT64_C(0x100000000), true, interpreter,
                              error, error_size);
    if (!valid) {
        if (precise_errno)
            errno = trial.fault_reason == SPARC64_FAULT_RESOURCE ? ENOMEM :
                    trial.fault_reason == SPARC64_FAULT_INTERNAL ? EIO : ENOEXEC;
        if (linux_error != NULL)
            *linux_error = trial.fault_reason == SPARC64_FAULT_RESOURCE ? 12u :
                           trial.fault_reason == SPARC64_FAULT_INTERNAL ? 5u : 8u;
        goto done;
    }
    if (interpreter[0] == '\0')
        goto done;
    const char *interpreter_path = interpreter;
    if (sysroot != NULL && interpreter[0] == '/') {
        size_t length = strnlen(sysroot, SPARC64_INTERP_MAX);
        if (length == 0 || length == SPARC64_INTERP_MAX) {
            valid = image_error(error, error_size, "invalid interpreter sysroot");
            if (precise_errno)
                errno = EINVAL;
            if (linux_error != NULL)
                *linux_error = 22;
            goto done;
        }
        int written = snprintf(resolved, sizeof(resolved), "%s%s", sysroot, interpreter);
        if (written < 0 || (size_t)written >= sizeof(resolved)) {
            valid = image_error(error, error_size, "interpreter path is too long");
            if (precise_errno)
                errno = ENAMETOOLONG;
            if (linux_error != NULL)
                *linux_error = 36;
            goto done;
        }
        interpreter_path = resolved;
    }
    valid = sparc64_object_snapshot_read(interpreter_path, -1, &prepared->interpreter, NULL,
                            open_path, open_context, precise_errno, true,
                            linux_error, error, error_size);
    if (valid) {
        prepared->has_interpreter = true;
        if (!validate_combined_placement) {
            /* The original one-call loader maps the target before detecting
             * interpreter collisions. Preserve its partial-failure result. */
            sparc64_space_destroy(&trial);
            sparc64_space_init(&trial, 64);
        }
        valid = map_snapshot(&prepared->interpreter, &trial, &loader,
                             UINT64_C(0x2000000000), false, nested,
                             error, error_size);
        if (!valid && precise_errno)
            errno = trial.fault_reason == SPARC64_FAULT_RESOURCE ? ENOMEM :
                    trial.fault_reason == SPARC64_FAULT_INTERNAL ? EIO : ENOEXEC;
        if (!valid && linux_error != NULL)
            *linux_error = trial.fault_reason == SPARC64_FAULT_RESOURCE ? 12u :
                           trial.fault_reason == SPARC64_FAULT_INTERNAL ? 5u : 80u;
    }
done:
    sparc64_space_destroy(&trial);
    if (!valid) {
        sparc64_program_prepared_destroy(prepared);
        return false;
    }
    *out = prepared;
    return true;
}

static bool prepare_program(const char *path, int image_fd, const char *sysroot,
                            bool validate_combined_placement,
                            sparc64_image_path_open_fn open_path, void *open_context,
                            bool precise_errno, sparc64_prepared_program_t **out,
                            unsigned int *linux_error,
                            char *error, size_t error_size)
{
    if (out != NULL)
        *out = NULL;
    if (out == NULL || path == NULL) {
        if (image_fd >= 0)
            (void)close(image_fd);
        if (precise_errno)
            errno = EINVAL;
        if (linux_error != NULL)
            *linux_error = 22;
        return image_error(error, error_size, "invalid image arguments");
    }
    sparc64_object_snapshot_t snapshot = {0};
    if (!sparc64_object_snapshot_read(path, image_fd, &snapshot, NULL, NULL, NULL,
                                 precise_errno, false, linux_error, error, error_size))
        return false;
    bool valid = sparc64_program_prepare_snapshot(&snapshot, sysroot,
        validate_combined_placement, open_path, open_context, precise_errno,
        out, linux_error, error, error_size);
    free(snapshot.bytes);
    return valid;
}

bool sparc64_program_prepare(const char *path, int image_fd, const char *sysroot,
                        sparc64_prepared_program_t **out, char *error,
                        size_t error_size)
{
    return prepare_program(path, image_fd, sysroot, true, NULL, NULL, false,
                           out, NULL, error, error_size);
}

bool sparc64_program_prepare_with_opener(const char *path, int owned_image_fd,
                                    const char *sysroot,
                                    sparc64_image_path_open_fn open_path,
                                    void *open_context,
                                    sparc64_prepared_program_t **out,
                                    unsigned int *linux_error,
                                    char *error, size_t error_size)
{
    if (open_path == NULL) {
        if (owned_image_fd >= 0)
            (void)close(owned_image_fd);
        if (out != NULL)
            *out = NULL;
        if (linux_error != NULL)
            *linux_error = 22;
        errno = EINVAL;
        return image_error(error, error_size, "invalid image opener");
    }
    return prepare_program(path, owned_image_fd, sysroot, true, open_path,
                           open_context, true, out, linux_error, error,
                           error_size);
}

bool sparc64_program_map_prepared(const sparc64_prepared_program_t *prepared,
                             sparc64_space_t *space, sparc64_image_info_t *info,
                             char *error, size_t error_size)
{
    if (prepared == NULL || space == NULL || info == NULL)
        return image_error(error, error_size, "invalid image arguments");
    char interpreter[4096], nested[4096];
    if (!map_snapshot(&prepared->target, space, info, UINT64_C(0x100000000),
                      true, interpreter, error, error_size))
        return false;
    if (!prepared->has_interpreter)
        return true;
    sparc64_image_info_t loader;
    if (!map_snapshot(&prepared->interpreter, space, &loader,
                      UINT64_C(0x2000000000), false, nested,
                      error, error_size))
        return false;
    info->start_pc = loader.entry;
    info->interpreter_base = loader.load_bias;
    return true;
}

bool sparc64_program_load(const char *path, int image_fd, const char *sysroot,
                      sparc64_space_t *space, sparc64_image_info_t *info,
                      char *error, size_t error_size)
{
    if (space == NULL || info == NULL) {
        if (image_fd >= 0)
            (void)close(image_fd);
        return image_error(error, error_size, "invalid image arguments");
    }
    sparc64_prepared_program_t *prepared = NULL;
    if (!prepare_program(path, image_fd, sysroot, false, NULL, NULL, false,
                         &prepared, NULL, error, error_size))
        return false;
    bool loaded = sparc64_program_map_prepared(prepared, space, info, error, error_size);
    sparc64_program_prepared_destroy(prepared);
    return loaded;
}

bool sparc64_image_load(const char *path, int image_fd, sparc64_space_t *space,
                    sparc64_image_info_t *info, char *error, size_t error_size)
{
    return sparc64_program_load(path, image_fd, NULL, space, info, error, error_size);
}
