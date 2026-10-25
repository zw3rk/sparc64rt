/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#define _POSIX_C_SOURCE 200809L
#include "loader/image.h"
#include "linux/signal_frame.h"
#include "core/profile.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define SPARC64_STACK_TOP UINT64_C(0x4000000000)
#define SPARC64_STACK_SIZE UINT64_C(0x100000)
#define SPARC64_MAX_STRINGS 2048
#define SPARC64_MAX_STRING_BYTES ((size_t)131072)

static bool stack_error(char *error, size_t size)
{
    if (error != NULL && size != 0) {
        int n = snprintf(error, size, "%s", "cannot build bounded guest stack");
        if (n < 0 || (size_t)n >= size)
            error[0] = '\0';
    }
    return false;
}
static bool push_string(sparc64_space_t *space, uint64_t *cursor, const char *text,
                         uint64_t *address, size_t *total)
{
    if (text == NULL)
        return false;
    size_t size = 0;
    while (size < SPARC64_MAX_STRING_BYTES && text[size] != '\0')
        ++size;
    if (size == SPARC64_MAX_STRING_BYTES || *total > SPARC64_MAX_STRING_BYTES - (size + 1))
        return false;
    ++size;
    *cursor -= size;
    *total += size;
    *address = *cursor;
    return sparc64_space_write(space, *cursor, text, size);
}
static bool put_word(sparc64_space_t *space, uint64_t *cursor, uint64_t word)
{
    unsigned char data[8];
    for (unsigned int i = 0; i < 8; ++i)
        data[i] = (unsigned char)(word >> (i * 8));
    bool ok = sparc64_space_write(space, *cursor, data, sizeof(data));
    *cursor += 8;
    return ok;
}

bool sparc64_stack_build(sparc64_space_t *space, const sparc64_image_info_t *image,
                     const char *path, int argc, char *const argv[],
                     char *const envp[], uint64_t *stack_pointer,
                     char *error, size_t error_size)
{
    uint64_t arguments[SPARC64_MAX_STRINGS], environment[SPARC64_MAX_STRINGS];
    size_t envc = 0, string_bytes = 0;
    if (space == NULL || image == NULL || path == NULL || argc < 1 ||
        argc > SPARC64_MAX_STRINGS || argv == NULL || envp == NULL || stack_pointer == NULL)
        return stack_error(error, error_size);
    while (envp[envc] != NULL) {
        if (envc == SPARC64_MAX_STRINGS)
            return stack_error(error, error_size);
        ++envc;
    }
    if (!sparc64_space_map(space, SPARC64_STACK_TOP - SPARC64_STACK_SIZE, SPARC64_STACK_SIZE,
                       SPARC64_MEM_READ | SPARC64_MEM_WRITE, false))
        return stack_error(error, error_size);
    uint64_t cursor = SPARC64_STACK_TOP;
    for (int i = 0; i < argc; ++i)
        if (!push_string(space, &cursor, argv[i], &arguments[i], &string_bytes))
            return stack_error(error, error_size);
    for (size_t i = 0; i < envc; ++i)
        if (!push_string(space, &cursor, envp[i], &environment[i], &string_bytes))
            return stack_error(error, error_size);
    uint64_t execfn;
    if (!push_string(space, &cursor, path, &execfn, &string_bytes))
        return stack_error(error, error_size);
    unsigned char random[16];
    int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return stack_error(error, error_size);
    size_t done = 0;
    while (done < sizeof(random)) {
        ssize_t got = read(fd, random + done, sizeof(random) - done);
        if (got < 0 && errno == EINTR)
            continue;
        if (got <= 0)
            break;
        done += (size_t)got;
    }
    int closed = close(fd);
    if (done != sizeof(random) || closed != 0)
        return stack_error(error, error_size);
    cursor -= sizeof(random);
    uint64_t random_address = cursor;
    if (!sparc64_space_write(space, cursor, random, sizeof(random)))
        return stack_error(error, error_size);
    struct aux { uint64_t key, value; } aux[] = {
        {3, image->phdr}, {4, 56}, {5, image->phnum}, {6, SPARC64_PAGE_SIZE},
        {7, image->interpreter_base}, {8, 0}, {9, image->entry}, {11, (uint64_t)getuid()},
        {12, (uint64_t)geteuid()}, {13, (uint64_t)getgid()}, {14, (uint64_t)getegid()},
        {16, sparc64_profile_hwcap(sparc64_profile_for_xlen(64))},
        {23, 0}, {25, random_address}, {31, execfn}, {51, SPARC64_SIGNAL_FRAME_SIZE}, {0, 0}
    };
    size_t words = 1 + (size_t)argc + 1 + envc + 1 + 2 * (sizeof(aux) / sizeof(aux[0]));
    uint64_t start = (cursor - (uint64_t)words * 8) & ~UINT64_C(15);
    cursor = start;
    if (!put_word(space, &cursor, (uint64_t)argc))
        return stack_error(error, error_size);
    for (int i = 0; i < argc; ++i)
        if (!put_word(space, &cursor, arguments[i]))
            return stack_error(error, error_size);
    if (!put_word(space, &cursor, 0))
        return stack_error(error, error_size);
    for (size_t i = 0; i < envc; ++i)
        if (!put_word(space, &cursor, environment[i]))
            return stack_error(error, error_size);
    if (!put_word(space, &cursor, 0))
        return stack_error(error, error_size);
    for (size_t i = 0; i < sizeof(aux) / sizeof(aux[0]); ++i)
        if (!put_word(space, &cursor, aux[i].key) || !put_word(space, &cursor, aux[i].value))
            return stack_error(error, error_size);
    *stack_pointer = start;
    return true;
}
