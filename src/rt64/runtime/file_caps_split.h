/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SPARC64RT_RUNTIME_FILE_CAPS_SPLIT_H
#define SPARC64RT_RUNTIME_FILE_CAPS_SPLIT_H

/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#define _GNU_SOURCE 1
#define _DARWIN_C_SOURCE 1
#define _POSIX_C_SOURCE 200809L
#include "runtime/file_caps.h"
#include "runtime/native_cmsg.h"
#include "runtime/file_caps_internal.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

enum { FRAME_SIZE = 24, MAX_RIGHTS = 4, REPLY_WAIT_MS = 5000,
       OP_REGISTER = 1, OP_FETCH = 2, OP_TRUNCATE_STAGE = 3,
       OP_TRUNCATE_EXECUTE = 4, CLEANUP_FRAME_SIZE = 96,
       CLEANUP_VERSION = 4, OP_CLEANUP_CONTROL = 1,
       OP_CLEANUP_DIRECTORY = 2, DEPARTURE_VERSION = 5,
       OP_DEPARTURE_PREPARE = 1, MAX_DEPARTURES = 4096 };

typedef struct {
    uint64_t id;
    int fd;
} source_t;

typedef struct {
    int control_fd, directory_fd;
    char directory[64];
    void *retained;
    bool ready;
} cleanup_registration_t;

typedef struct {
    int reply_fd, lifetime_fd, sender_fd;
    bool release_seen, released;
} departure_slot_t;

_Static_assert(sizeof(off_t) == 8, "file service requires 64-bit truncate offsets");
#ifdef SPARC64_FILE_CAPS_TESTING
extern sparc64_file_caps_test_hook_t test_hook;
extern void *test_context;
#define TEST_POINT(point) do { if (test_hook != NULL) \
    test_hook((point), test_context); } while (0)
void sparc64_file_caps_test_set_hook(sparc64_file_caps_test_hook_t hook,
                                     void *context);
#else
#define TEST_POINT(point) ((void)0)
#endif

/* Cross-part declarations (generated L0a split). */
void close_two(int first, int second);
void close_rights(int rights[MAX_RIGHTS], size_t count);
int private_fd(int *fd);
bool connected_socket(int fd, int expected_type);
bool unix_socket_kind(int fd, int expected_type);
bool sparc64_file_caps_client_live(const sparc64_file_caps_client_t *client);
int no_sigpipe(int fd);
int native_lifetime_socket_type(void);
int sparc64_file_caps_client_adopt(sparc64_file_caps_client_t *out, int request_fd, int lifetime_fd);
int sparc64_file_caps_client_adopt_terminal(sparc64_file_caps_client_t *out, int request_fd, int lifetime_fd);
int sparc64_file_caps_pair_create(sparc64_file_caps_client_t *client, sparc64_file_caps_server_t *server);
int sparc64_file_caps_client_duplicate(const sparc64_file_caps_client_t *source, sparc64_file_caps_client_t *out);
void sparc64_file_caps_client_close(sparc64_file_caps_client_t *client);
void sparc64_file_caps_server_close(sparc64_file_caps_server_t *server);
void put_u32(unsigned char *at, uint32_t value);
uint32_t get_u32(const unsigned char *at);
void put_u64(unsigned char *at, uint64_t value);
uint64_t get_u64(const unsigned char *at);
void frame_base(unsigned char frame[FRAME_SIZE], unsigned char op);
bool frame_valid(const unsigned char frame[FRAME_SIZE], unsigned char op);
int collect_rights(struct msghdr *message, int rights[MAX_RIGHTS], size_t *count);
ssize_t send_packet(int socket_fd, const unsigned char *frame, size_t frame_size, const int *rights, size_t count);
ssize_t send_frame(int socket_fd, const unsigned char frame[FRAME_SIZE], const int *rights, size_t count);
int await_reply(int reply_fd, int life_fd, unsigned char *frame, size_t frame_size, int rights[MAX_RIGHTS], size_t *right_count);
int request(const sparc64_file_caps_client_t *client, unsigned char op, uint64_t id, uint64_t attempt, int source_fd, int *out_fd, int *out_native_errno);
int sparc64_file_caps_register(const sparc64_file_caps_client_t *client, int source_fd, uint64_t source_id, uint64_t *attempts);
int sparc64_file_caps_register_terminal_cleanup(const sparc64_file_caps_client_t *client, int borrowed_control_fd, int borrowed_directory_fd, const char *directory, bool *may_have_delegated);
int departure_reply_byte(int reply_fd, int lifetime_fd, char *answer);
int sparc64_file_caps_departure_begin(const sparc64_file_caps_client_t *client, sparc64_file_caps_departure_t *out);
int sparc64_file_caps_departure_finish(sparc64_file_caps_departure_t *handle, bool *last);
int sparc64_file_caps_departure_end(sparc64_file_caps_departure_t *handle);
int sparc64_file_caps_fetch(const sparc64_file_caps_client_t *client, uint64_t source_id, int *out_fd);
int writable_regular(int fd);
int sparc64_file_caps_truncate_stage(const sparc64_file_caps_client_t *client, uint64_t operation_id, int borrowed_fd, uint64_t length);
int sparc64_file_caps_truncate_execute(const sparc64_file_caps_client_t *client, uint64_t operation_id, int *out_native_errno);
void departure_slot_close(departure_slot_t *slot);
int process_request(int control_fd, source_t *sources, size_t *count, uint64_t *last_id, uint64_t *last_attempt, sparc64_file_caps_mutation_t *mutation, cleanup_registration_t *cleanup, departure_slot_t *departures, bool allow_cleanup, const sparc64_file_caps_retained_cleanup_t *retained_ops);
int departure_receive_release(departure_slot_t *slot);
int departure_answer(departure_slot_t *slot, char answer);
int lifetime_probe(int fd);
int sparc64_file_caps_serve_with_cleanup(sparc64_file_caps_server_t *server, sparc64_file_caps_terminal_cleanup_fn terminal);
int sparc64_file_caps_serve_with_retained_cleanup( sparc64_file_caps_server_t *server, const sparc64_file_caps_retained_cleanup_t *cleanup);
int sparc64_file_caps_serve(sparc64_file_caps_server_t *server);
void sparc64_file_caps_internal_close_two(int first, int second);
void sparc64_file_caps_internal_close_rights(int rights[4], size_t count);
int sparc64_file_caps_internal_private_fd(int *fd);
bool sparc64_file_caps_internal_connected_socket(int fd, int type);
bool sparc64_file_caps_internal_unix_socket_kind(int fd, int type);
void sparc64_file_caps_internal_put_u32(unsigned char *at, uint32_t v);
uint32_t sparc64_file_caps_internal_get_u32(const unsigned char *at);
void sparc64_file_caps_internal_put_u64(unsigned char *at, uint64_t v);
uint64_t sparc64_file_caps_internal_get_u64(const unsigned char *at);
int sparc64_file_caps_internal_collect_rights(struct msghdr *m, int r[4], size_t *n);
int sparc64_file_caps_internal_await_reply(int fd, int life, unsigned char *frame, size_t size, int rights[4], size_t *count);
int sparc64_file_caps_internal_writable_regular(int fd);
int sparc64_file_caps_internal_no_sigpipe(int fd);
void sparc64_file_caps_internal_test_point(int point);

#endif /* SPARC64RT_RUNTIME_FILE_CAPS_SPLIT_H */
