/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SPARC64RT_RUNTIME_FILE_CAPS_INTERNAL_H
#define SPARC64RT_RUNTIME_FILE_CAPS_INTERNAL_H

#include "runtime/file_caps.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/types.h>

enum { SPARC64_FILE_CAPS_V2_REQUEST_SIZE = 32, SPARC64_FILE_CAPS_V2_REPLY_SIZE = 40,
       SPARC64_FILE_CAPS_V2_CHUNK_MAX = 224 };

typedef enum {
    SPARC64_FILE_CAPS_MUTATION_NONE,
    SPARC64_FILE_CAPS_MUTATION_TRUNCATE,
    SPARC64_FILE_CAPS_MUTATION_WRITE,
    SPARC64_FILE_CAPS_MUTATION_SEQUENTIAL_WRITE,
    SPARC64_FILE_CAPS_MUTATION_APPEND_PWRITE
} sparc64_file_caps_mutation_kind_t;

typedef struct {
    uint64_t id, length, offset, received;
    uint32_t count;
    int fd, native_errno;
    int64_t transferred;
    sparc64_file_caps_mutation_kind_t kind;
    bool sealed, executed, append, generated_sigxfsz;
    unsigned int protocol_version;
    sparc64_file_caps_call_context_t context;
    unsigned char bytes[SPARC64_FILE_CAPS_MAX_WRITE_BYTES];
} sparc64_file_caps_mutation_t;

void sparc64_file_caps_internal_close_rights(int rights[4], size_t count);
void sparc64_file_caps_internal_close_two(int first, int second);
int sparc64_file_caps_internal_private_fd(int *fd);
bool sparc64_file_caps_internal_connected_socket(int fd, int expected_type);
bool sparc64_file_caps_internal_unix_socket_kind(int fd, int expected_type);
void sparc64_file_caps_internal_put_u32(unsigned char *at, uint32_t value);
uint32_t sparc64_file_caps_internal_get_u32(const unsigned char *at);
void sparc64_file_caps_internal_put_u64(unsigned char *at, uint64_t value);
uint64_t sparc64_file_caps_internal_get_u64(const unsigned char *at);
int sparc64_file_caps_internal_collect_rights(struct msghdr *message, int rights[4],
                                         size_t *count);
int sparc64_file_caps_internal_await_reply(int reply_fd, int life_fd,
                                      unsigned char *frame, size_t frame_size,
                                      int rights[4], size_t *right_count);
int sparc64_file_caps_internal_writable_regular(int fd);
int sparc64_file_caps_internal_no_sigpipe(int fd);
void sparc64_file_caps_internal_test_point(int point);

int sparc64_file_caps_internal_process_v2(const unsigned char *packet,
                                     ssize_t received, bool frame_truncated,
                                     int rights[4], size_t right_count,
                                     bool rights_valid,
                                     sparc64_file_caps_mutation_t *mutation);
int sparc64_file_caps_internal_process_v3(const unsigned char *packet,
                                     ssize_t received, bool frame_truncated,
                                     int rights[4], size_t right_count,
                                     bool rights_valid,
                                     sparc64_file_caps_mutation_t *mutation);
int sparc64_file_caps_internal_pwrite_target(int fd, bool append,
                                       uint64_t expected_eof);
int sparc64_file_caps_internal_sequential_target(int fd, uint64_t expected_offset,
                                            bool expected_append);

#ifdef SPARC64_FILE_CAPS_TESTING
#define SPARC64_FILE_CAPS_INTERNAL_TEST_POINT(point) \
    sparc64_file_caps_internal_test_point((int)(point))
#else
#define SPARC64_FILE_CAPS_INTERNAL_TEST_POINT(point) ((void)0)
#endif

#endif
