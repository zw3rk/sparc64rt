/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#define _GNU_SOURCE 1
#define _DARWIN_C_SOURCE 1
#define _POSIX_C_SOURCE 200809L
#include "runtime/file_caps_internal.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

enum { V2_REQUEST_SIZE = 32, V2_REPLY_SIZE = 40, V2_CHUNK_MAX = 224,
       MAX_RIGHTS = 4, OP_WRITE_BEGIN = 5, OP_WRITE_CHUNK = 6,
       OP_WRITE_SEAL = 7, OP_WRITE_EXECUTE = 8,
       OP_SEQ_WRITE_BEGIN = 9, OP_SEQ_WRITE_EXECUTE = 10,
       OP_APPEND_PWRITE_BEGIN = 11, OP_APPEND_PWRITE_EXECUTE = 12 };

#define put_u32 sparc64_file_caps_internal_put_u32
#define get_u32 sparc64_file_caps_internal_get_u32
#define put_u64 sparc64_file_caps_internal_put_u64
#define get_u64 sparc64_file_caps_internal_get_u64
#define close_rights sparc64_file_caps_internal_close_rights
#define private_fd sparc64_file_caps_internal_private_fd
#define connected_socket sparc64_file_caps_internal_connected_socket
#define unix_socket_kind sparc64_file_caps_internal_unix_socket_kind
#define collect_rights sparc64_file_caps_internal_collect_rights
#define await_reply sparc64_file_caps_internal_await_reply
#define writable_regular sparc64_file_caps_internal_writable_regular
#define no_sigpipe sparc64_file_caps_internal_no_sigpipe
#define TEST_POINT SPARC64_FILE_CAPS_INTERNAL_TEST_POINT
#define close_two sparc64_file_caps_internal_close_two
#define MUTATION_WRITE SPARC64_FILE_CAPS_MUTATION_WRITE
#define MUTATION_SEQUENTIAL_WRITE SPARC64_FILE_CAPS_MUTATION_SEQUENTIAL_WRITE
#define mutation_t sparc64_file_caps_mutation_t


static void v2_frame_base(unsigned char frame[V2_REQUEST_SIZE], unsigned char op)
{
    memset(frame, 0, V2_REQUEST_SIZE);
    memcpy(frame, "RVFC", 4);
    frame[4] = 2;
    frame[5] = op;
}


static bool v2_frame_valid(const unsigned char *frame, unsigned char op)
{
    return memcmp(frame, "RVFC", 4) == 0 && frame[4] == 2 &&
           frame[5] == op && frame[6] == 0 && frame[7] == 0 &&
           (op == OP_SEQ_WRITE_BEGIN ? get_u32(frame + 28) <= 1u :
                                       get_u32(frame + 28) == 0);
}


static ssize_t send_v2_frame(int socket_fd,
                             const unsigned char frame[V2_REQUEST_SIZE],
                             const void *payload, size_t payload_size,
                             const int *rights, size_t count)
{
    if (count > 4 || payload_size > V2_CHUNK_MAX ||
        (payload_size != 0 && payload == NULL)) {
        errno = EINVAL;
        return -1;
    }
    struct iovec vectors[2] = {
        {.iov_base = (void *)frame, .iov_len = V2_REQUEST_SIZE},
        {.iov_base = (void *)payload, .iov_len = payload_size}
    };
    union {
        struct cmsghdr alignment;
        unsigned char bytes[CMSG_SPACE(4 * sizeof(int))];
    } ancillary;
    memset(&ancillary, 0, sizeof(ancillary));
    struct msghdr message = {.msg_iov = vectors,
        .msg_iovlen = payload_size == 0 ? 1u : 2u};
    if (count != 0) {
        message.msg_control = ancillary.bytes;
        message.msg_controllen = CMSG_SPACE(count * sizeof(int));
        struct cmsghdr *header = CMSG_FIRSTHDR(&message);
        if (header == NULL) {
            errno = EIO;
            return -1;
        }
        header->cmsg_level = SOL_SOCKET;
        header->cmsg_type = SCM_RIGHTS;
        header->cmsg_len = CMSG_LEN(count * sizeof(int));
        memcpy(CMSG_DATA(header), rights, count * sizeof(int));
    }
    return sendmsg(socket_fd, &message, MSG_DONTWAIT | MSG_NOSIGNAL);
}


static int request_v2(const sparc64_file_caps_client_t *client, unsigned char op,
                      uint64_t id, uint64_t offset, uint32_t count,
                      uint32_t flags,
                      const void *payload, size_t payload_size, int source_fd,
                      sparc64_file_caps_write_result_t *out_result)
{
    if (client == NULL || client->request_fd < 3 || client->lifetime_fd < 3 ||
        id == 0 || op < OP_WRITE_BEGIN || op > OP_APPEND_PWRITE_EXECUTE ||
        payload_size > V2_CHUNK_MAX ||
        (payload_size != 0 && payload == NULL)) {
        errno = EINVAL;
        return -1;
    }
    int reply[2] = {-1, -1};
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, reply) != 0)
        return -1;
    if (private_fd(&reply[0]) != 0 || private_fd(&reply[1]) != 0 ||
        no_sigpipe(reply[1]) != 0) {
        int saved = errno;
        close_two(reply[0], reply[1]);
        errno = saved;
        return -1;
    }
    unsigned char frame[V2_REQUEST_SIZE];
    v2_frame_base(frame, op);
    put_u64(frame + 8, id);
    put_u64(frame + 16, offset);
    put_u32(frame + 24, count);
    put_u32(frame + 28, flags);
    int rights[4] = {reply[1], client->lifetime_fd, client->request_fd, source_fd};
    size_t right_count = op == OP_WRITE_BEGIN || op == OP_SEQ_WRITE_BEGIN ||
                         op == OP_APPEND_PWRITE_BEGIN ? 4u : 3u;
    ssize_t sent = send_v2_frame(client->request_fd, frame, payload, payload_size,
                                 rights, right_count);
    int send_error = errno;
    (void)close(reply[1]);
    reply[1] = -1;
    if (sent != (ssize_t)(V2_REQUEST_SIZE + payload_size)) {
        (void)close(reply[0]);
        errno = sent >= 0 ? EIO : send_error;
        return -1;
    }
    TEST_POINT(op == OP_WRITE_BEGIN ? SPARC64_FILE_CAPS_TEST_PWRITE_BEGIN_SENT :
               op == OP_WRITE_CHUNK ? SPARC64_FILE_CAPS_TEST_PWRITE_CHUNK_SENT :
               op == OP_WRITE_SEAL ? SPARC64_FILE_CAPS_TEST_PWRITE_SEAL_SENT :
               op == OP_WRITE_EXECUTE ? SPARC64_FILE_CAPS_TEST_PWRITE_EXECUTE_SENT :
               op == OP_SEQ_WRITE_BEGIN ? SPARC64_FILE_CAPS_TEST_WRITE_BEGIN_SENT :
               op == OP_SEQ_WRITE_EXECUTE ? SPARC64_FILE_CAPS_TEST_WRITE_EXECUTE_SENT :
               op == OP_APPEND_PWRITE_BEGIN ?
                   SPARC64_FILE_CAPS_TEST_APPEND_PWRITE_BEGIN_SENT :
                   SPARC64_FILE_CAPS_TEST_APPEND_PWRITE_EXECUTE_SENT);
    int received_rights[MAX_RIGHTS] = {-1, -1, -1, -1};
    size_t received_count = 0;
    unsigned char reply_frame[V2_REPLY_SIZE];
    int result = await_reply(reply[0], client->lifetime_fd, reply_frame,
                             V2_REPLY_SIZE, received_rights, &received_count);
    (void)close(reply[0]);
    if (result != 0) {
        close_rights(received_rights, received_count);
        errno = EIO;
        return -1;
    }
    uint32_t status = get_u32(reply_frame + 16);
    uint32_t native_error = get_u32(reply_frame + 20);
    uint64_t transferred = get_u64(reply_frame + 24);
    bool execute = op == OP_WRITE_EXECUTE || op == OP_SEQ_WRITE_EXECUTE ||
                   op == OP_APPEND_PWRITE_EXECUTE;
    bool valid_transfer = execute ?
        (native_error == 0 ? transferred <= SPARC64_FILE_CAPS_MAX_WRITE_BYTES :
                             transferred == UINT64_MAX) :
        (native_error == 0 && transferred == 0);
    bool valid = memcmp(reply_frame, "RVFC", 4) == 0 &&
        reply_frame[4] == 2 && reply_frame[5] == op &&
        reply_frame[6] == 0 && reply_frame[7] == 0 &&
        get_u64(reply_frame + 8) == id && status < 4096 && native_error < 4096 &&
        memcmp(reply_frame + 32, "\0\0\0\0\0\0\0\0", 8) == 0 &&
        received_count == 0 && valid_transfer &&
        (status == 0 || (native_error == 0 && transferred == 0));
    if (!valid) {
        close_rights(received_rights, received_count);
        errno = EIO;
        return -1;
    }
    if (status != 0) {
        errno = (int)status;
        return -1;
    }
    if (execute) {
        sparc64_file_caps_write_result_t completed = {
            .transferred = transferred == UINT64_MAX ? -1 : (int64_t)transferred,
            .native_errno = (int)native_error
        };
        *out_result = completed;
    }
    return 0;
}


static int writable_regular_no_append(int fd)
{
    if (writable_regular(fd) != 0)
        return -1;
    int flags = fcntl(fd, F_GETFL);
    if (flags < 0)
        return -1;
    if ((flags & O_APPEND) != 0) {
        errno = EINVAL;
        return -1;
    }
    return 0;
}


static int sequential_origin(int fd, uint64_t *offset, bool *append)
{
    if (writable_regular(fd) != 0)
        return -1;
    int flags = fcntl(fd, F_GETFL);
    if (flags < 0)
        return -1;
    struct stat status;
    if (fstat(fd, &status) != 0)
        return -1;
    bool is_append = (flags & O_APPEND) != 0;
    uint64_t current;
    if (is_append) {
        if (status.st_size < 0) {
            errno = EOVERFLOW;
            return -1;
        }
        current = (uint64_t)status.st_size;
    } else {
        off_t cursor = lseek(fd, 0, SEEK_CUR);
        if (cursor < 0)
            return -1;
        current = (uint64_t)cursor;
    }
    if (current > INT64_MAX) {
        errno = EOVERFLOW;
        return -1;
    }
    *offset = current;
    *append = is_append;
    return 0;
}


static bool sequential_origin_matches(int fd, uint64_t expected_offset,
                                      bool expected_append)
{
    uint64_t actual_offset = 0;
    bool actual_append = false;
    return sequential_origin(fd, &actual_offset, &actual_append) == 0 &&
           actual_offset == expected_offset && actual_append == expected_append;
}


static int append_pwrite_origin(int fd, uint64_t expected_eof)
{
    uint64_t actual_eof = 0;
    bool append = false;
    if (sequential_origin(fd, &actual_eof, &append) != 0)
        return -1;
    if (!append || actual_eof != expected_eof) {
        errno = EINVAL;
        return -1;
    }
    return 0;
}

int sparc64_file_caps_internal_pwrite_target(int fd, bool append,
                                       uint64_t expected_eof)
{
    return append ? append_pwrite_origin(fd, expected_eof) :
                    writable_regular_no_append(fd);
}

int sparc64_file_caps_internal_sequential_target(int fd, uint64_t expected_offset,
                                            bool expected_append)
{
    if (!sequential_origin_matches(fd, expected_offset, expected_append)) {
        errno = EIO;
        return -1;
    }
    return 0;
}


static int native_pwrite_once(int fd, const unsigned char *bytes, size_t count,
                              uint64_t offset, int64_t *transferred,
                              int *native_error)
{
    sigset_t blocked, previous, pending;
    if (sigemptyset(&blocked) != 0 || sigaddset(&blocked, SIGXFSZ) != 0 ||
        sigprocmask(SIG_BLOCK, &blocked, &previous) != 0)
        return -1;
    int result = -1, saved = 0;
    if (sigpending(&pending) != 0) { saved = errno; goto restore; }
    bool already_pending = sigismember(&pending, SIGXFSZ) == 1;
    ssize_t applied = pwrite(fd, bytes, count, (off_t)offset);
    int call_error = errno;
    if (applied < 0) {
        *transferred = -1;
        *native_error = call_error;
    } else {
        *transferred = (int64_t)applied;
        *native_error = 0;
    }
    if (!already_pending && *native_error == EFBIG) {
        if (sigpending(&pending) != 0) { saved = errno; goto restore; }
        if (sigismember(&pending, SIGXFSZ) == 1) {
            int signal_number = 0;
            int waited = sigwait(&blocked, &signal_number);
            if (waited != 0 || signal_number != SIGXFSZ) {
                saved = waited != 0 ? waited : EIO; goto restore;
            }
        }
    }
    result = 0;
restore:
    if (sigprocmask(SIG_SETMASK, &previous, NULL) != 0)
        return -1;
    if (result != 0)
        errno = saved;
    return result;
}


static int native_write_once(int fd, const unsigned char *bytes, size_t count,
                             int64_t *transferred, int *native_error)
{
    sigset_t blocked, previous, pending;
    if (sigemptyset(&blocked) != 0 || sigaddset(&blocked, SIGXFSZ) != 0 ||
        sigprocmask(SIG_BLOCK, &blocked, &previous) != 0)
        return -1;
    int result = -1, saved = 0;
    if (sigpending(&pending) != 0) { saved = errno; goto restore; }
    bool already_pending = sigismember(&pending, SIGXFSZ) == 1;
    ssize_t applied = write(fd, bytes, count);
    int call_error = errno;
    if (applied < 0) {
        *transferred = -1;
        *native_error = call_error;
    } else {
        *transferred = (int64_t)applied;
        *native_error = 0;
    }
    if (!already_pending) {
        if (sigpending(&pending) != 0) { saved = errno; goto restore; }
        if (sigismember(&pending, SIGXFSZ) == 1) {
            int signal_number = 0;
            int waited = sigwait(&blocked, &signal_number);
            if (waited != 0 || signal_number != SIGXFSZ) {
                saved = waited != 0 ? waited : EIO; goto restore;
            }
        }
    }
    result = 0;
restore:
    if (sigprocmask(SIG_SETMASK, &previous, NULL) != 0)
        return -1;
    if (result != 0)
        errno = saved;
    return result;
}


int sparc64_file_caps_pwrite_stage(const sparc64_file_caps_client_t *client,
                              uint64_t operation_id, int borrowed_fd,
                              uint64_t offset, const void *bytes, size_t count)
{
    if (operation_id == 0 || borrowed_fd < 0 || count > SPARC64_FILE_CAPS_MAX_WRITE_BYTES ||
        (count != 0 && bytes == NULL) || offset > INT64_MAX ||
        (uint64_t)count > (uint64_t)INT64_MAX - offset) {
        errno = EINVAL;
        return -1;
    }
    if (writable_regular_no_append(borrowed_fd) != 0)
        return -1;
    if (request_v2(client, OP_WRITE_BEGIN, operation_id, offset, (uint32_t)count,
                   0, NULL, 0, borrowed_fd, NULL) != 0)
        return -1;
    const unsigned char *source = bytes;
    size_t sent = 0;
    while (sent < count) {
        size_t amount = count - sent;
        if (amount > V2_CHUNK_MAX)
            amount = V2_CHUNK_MAX;
        if (request_v2(client, OP_WRITE_CHUNK, operation_id, sent,
                       (uint32_t)amount, 0, source + sent, amount, -1, NULL) != 0)
            return -1;
        sent += amount;
    }
    return request_v2(client, OP_WRITE_SEAL, operation_id, 0, 0, 0,
                      NULL, 0, -1, NULL);
}


int sparc64_file_caps_pwrite_execute(const sparc64_file_caps_client_t *client,
                                uint64_t operation_id,
                                sparc64_file_caps_write_result_t *result)
{
    if (operation_id == 0 || result == NULL) {
        errno = EINVAL;
        return -1;
    }
    return request_v2(client, OP_WRITE_EXECUTE, operation_id, 0, 0, 0,
                      NULL, 0, -1, result);
}


int sparc64_file_caps_append_pwrite_stage(const sparc64_file_caps_client_t *client,
                                      uint64_t operation_id, int borrowed_fd,
                                      uint64_t expected_eof,
                                      const void *bytes, size_t count)
{
    if (operation_id == 0 || borrowed_fd < 0 ||
        count > SPARC64_FILE_CAPS_MAX_WRITE_BYTES ||
        (count != 0 && bytes == NULL) || expected_eof > INT64_MAX ||
        (uint64_t)count > (uint64_t)INT64_MAX - expected_eof) {
        errno = EINVAL;
        return -1;
    }
    if (append_pwrite_origin(borrowed_fd, expected_eof) != 0)
        return -1;
    if (request_v2(client, OP_APPEND_PWRITE_BEGIN, operation_id, expected_eof,
                   (uint32_t)count, 0, NULL, 0, borrowed_fd, NULL) != 0)
        return -1;
    const unsigned char *source = bytes;
    size_t sent = 0;
    while (sent < count) {
        size_t amount = count - sent;
        if (amount > V2_CHUNK_MAX)
            amount = V2_CHUNK_MAX;
        if (request_v2(client, OP_WRITE_CHUNK, operation_id, sent,
                       (uint32_t)amount, 0, source + sent, amount, -1, NULL) != 0)
            return -1;
        sent += amount;
    }
    return request_v2(client, OP_WRITE_SEAL, operation_id, 0, 0, 0,
                      NULL, 0, -1, NULL);
}


int sparc64_file_caps_append_pwrite_execute(const sparc64_file_caps_client_t *client,
                                        uint64_t operation_id,
                                        sparc64_file_caps_write_result_t *result)
{
    if (operation_id == 0 || result == NULL) {
        errno = EINVAL;
        return -1;
    }
    return request_v2(client, OP_APPEND_PWRITE_EXECUTE, operation_id,
                      0, 0, 0, NULL, 0, -1, result);
}


int sparc64_file_caps_write_stage(const sparc64_file_caps_client_t *client,
                             uint64_t operation_id, int borrowed_fd,
                             uint64_t expected_offset, bool expected_append,
                             const void *bytes, size_t count)
{
    if (operation_id == 0 || borrowed_fd < 0 ||
        count > SPARC64_FILE_CAPS_MAX_WRITE_BYTES || (count != 0 && bytes == NULL) ||
        expected_offset > INT64_MAX ||
        (uint64_t)count > (uint64_t)INT64_MAX - expected_offset) {
        errno = EINVAL;
        return -1;
    }
    uint64_t observed_offset = 0;
    bool append = false;
    if (sequential_origin(borrowed_fd, &observed_offset, &append) != 0)
        return -1;
    if (observed_offset != expected_offset || append != expected_append) {
        errno = EINVAL;
        return -1;
    }
    if (request_v2(client, OP_SEQ_WRITE_BEGIN, operation_id, expected_offset,
                   (uint32_t)count, expected_append ? 1u : 0u,
                   NULL, 0, borrowed_fd, NULL) != 0)
        return -1;
    const unsigned char *source = bytes;
    size_t sent = 0;
    while (sent < count) {
        size_t amount = count - sent;
        if (amount > V2_CHUNK_MAX)
            amount = V2_CHUNK_MAX;
        if (request_v2(client, OP_WRITE_CHUNK, operation_id, sent,
                       (uint32_t)amount, 0, source + sent, amount, -1, NULL) != 0)
            return -1;
        sent += amount;
    }
    return request_v2(client, OP_WRITE_SEAL, operation_id, 0, 0, 0,
                      NULL, 0, -1, NULL);
}


int sparc64_file_caps_write_execute(const sparc64_file_caps_client_t *client,
                               uint64_t operation_id,
                               sparc64_file_caps_write_result_t *result)
{
    if (operation_id == 0 || result == NULL) {
        errno = EINVAL;
        return -1;
    }
    return request_v2(client, OP_SEQ_WRITE_EXECUTE, operation_id, 0, 0, 0,
                      NULL, 0, -1, result);
}


static int send_v2_response(int reply_fd, unsigned char op, uint64_t id,
                            int status, int native_error, int64_t transferred)
{
    unsigned char frame[V2_REPLY_SIZE] = {0};
    memcpy(frame, "RVFC", 4);
    frame[4] = 2;
    frame[5] = op;
    put_u64(frame + 8, id);
    put_u32(frame + 16, (uint32_t)status);
    put_u32(frame + 20, (uint32_t)native_error);
    put_u64(frame + 24, transferred < 0 ? UINT64_MAX : (uint64_t)transferred);
    /* The v1 helper carries a fixed 24-byte frame. */
    struct iovec vector = {.iov_base = frame, .iov_len = sizeof(frame)};
    struct msghdr message = {.msg_iov = &vector, .msg_iovlen = 1};
    ssize_t sent = sendmsg(reply_fd, &message, MSG_DONTWAIT | MSG_NOSIGNAL);
    if (sent != (ssize_t)sizeof(frame)) {
        if (sent >= 0)
            errno = EIO;
        return -1;
    }
    TEST_POINT(SPARC64_FILE_CAPS_TEST_REPLY_QUEUED);
    return 0;
}


int sparc64_file_caps_internal_process_v2(const unsigned char *packet, ssize_t received,
                              bool frame_truncated, int rights[MAX_RIGHTS],
                              size_t right_count, bool rights_valid,
                                     sparc64_file_caps_mutation_t *mutation)
{
    unsigned char op = received >= 6 ? packet[5] : 0;
    uint64_t id = received >= V2_REQUEST_SIZE ? get_u64(packet + 8) : 0;
    int status = EPROTO;
    int native_error = 0;
    int64_t transferred = 0;
    bool known_op = op >= OP_WRITE_BEGIN && op <= OP_APPEND_PWRITE_EXECUTE;
    uint32_t count = received >= V2_REQUEST_SIZE ? get_u32(packet + 24) : 0;
    uint64_t offset = received >= V2_REQUEST_SIZE ? get_u64(packet + 16) : 0;
    size_t expected_rights = op == OP_WRITE_BEGIN || op == OP_SEQ_WRITE_BEGIN ||
                             op == OP_APPEND_PWRITE_BEGIN ?
        4u : 3u;
    bool valid_packet = !frame_truncated && received >= V2_REQUEST_SIZE &&
        known_op && v2_frame_valid(packet, op) && id != 0 && rights_valid &&
        right_count == expected_rights;
    if (valid_packet) {
        if (op == OP_WRITE_BEGIN || op == OP_SEQ_WRITE_BEGIN ||
            op == OP_APPEND_PWRITE_BEGIN) {
            valid_packet = received == V2_REQUEST_SIZE &&
                offset <= INT64_MAX && count <= SPARC64_FILE_CAPS_MAX_WRITE_BYTES &&
                (uint64_t)count <= (uint64_t)INT64_MAX - offset;
        } else if (op == OP_WRITE_CHUNK) {
            valid_packet = count != 0 && count <= V2_CHUNK_MAX &&
                received == (ssize_t)(V2_REQUEST_SIZE + count);
        } else {
            valid_packet = received == V2_REQUEST_SIZE && offset == 0 && count == 0;
        }
    }
    bool reply_capable = right_count >= 3 && rights[0] >= 0 && rights[1] >= 0 &&
        rights[2] >= 0 && private_fd(&rights[0]) == 0 &&
        private_fd(&rights[1]) == 0 && private_fd(&rights[2]) == 0 &&
        unix_socket_kind(rights[0], SOCK_DGRAM) &&
        connected_socket(rights[1], SOCK_STREAM) &&
        connected_socket(rights[2], SOCK_DGRAM);
    if (!reply_capable)
        valid_packet = false;

    if (!valid_packet) {
        if (reply_capable && known_op && id != 0)
            (void)send_v2_response(rights[0], op, id, EPROTO, 0, 0);
        close_rights(rights, right_count);
        return 0;
    }

    if (op == OP_WRITE_BEGIN || op == OP_SEQ_WRITE_BEGIN ||
        op == OP_APPEND_PWRITE_BEGIN) {
        if (id <= mutation->id)
            status = id == mutation->id ? EEXIST : ERANGE;
        else if (private_fd(&rights[3]) != 0)
            status = errno;
        else if (op == OP_WRITE_BEGIN &&
                 writable_regular_no_append(rights[3]) != 0)
            status = errno;
        else if (op == OP_SEQ_WRITE_BEGIN &&
                 !sequential_origin_matches(rights[3], offset,
                                             get_u32(packet + 28) != 0))
            status = EIO;
        else if (op == OP_APPEND_PWRITE_BEGIN &&
                 append_pwrite_origin(rights[3], offset) != 0)
            status = EIO;
        else {
            if (mutation->fd >= 0)
                (void)close(mutation->fd);
            memset(mutation, 0, sizeof(*mutation));
            mutation->id = id;
            mutation->offset = offset;
            mutation->count = count;
            mutation->fd = rights[3];
            mutation->kind = op == OP_WRITE_BEGIN ? MUTATION_WRITE :
                op == OP_SEQ_WRITE_BEGIN ? MUTATION_SEQUENTIAL_WRITE :
                SPARC64_FILE_CAPS_MUTATION_APPEND_PWRITE;
            mutation->protocol_version = 2u;
            mutation->append = op == OP_SEQ_WRITE_BEGIN &&
                               get_u32(packet + 28) != 0;
            rights[3] = -1;
            TEST_POINT(op == OP_WRITE_BEGIN ? SPARC64_FILE_CAPS_TEST_PWRITE_RETAINED :
                       op == OP_SEQ_WRITE_BEGIN ? SPARC64_FILE_CAPS_TEST_WRITE_RETAINED :
                       SPARC64_FILE_CAPS_TEST_APPEND_PWRITE_RETAINED);
            status = 0;
        }
    } else if (op == OP_WRITE_CHUNK) {
        if (id != mutation->id)
            status = id < mutation->id ? ERANGE : ENOENT;
        else if (mutation->protocol_version != 2u ||
                 (mutation->kind != MUTATION_WRITE &&
                  mutation->kind != MUTATION_SEQUENTIAL_WRITE &&
                  mutation->kind != SPARC64_FILE_CAPS_MUTATION_APPEND_PWRITE) ||
                 mutation->sealed ||
                 offset != mutation->received || mutation->received > mutation->count ||
                 count > mutation->count - mutation->received)
            status = EINVAL;
        else {
            memcpy(mutation->bytes + mutation->received,
                   packet + V2_REQUEST_SIZE, count);
            mutation->received += count;
            status = 0;
        }
    } else if (op == OP_WRITE_SEAL) {
        if (id != mutation->id)
            status = id < mutation->id ? ERANGE : ENOENT;
        else if (mutation->protocol_version != 2u ||
                 (mutation->kind != MUTATION_WRITE &&
                  mutation->kind != MUTATION_SEQUENTIAL_WRITE &&
                  mutation->kind != SPARC64_FILE_CAPS_MUTATION_APPEND_PWRITE) ||
                 mutation->sealed ||
                 mutation->received != mutation->count)
            status = EINVAL;
        else {
            mutation->sealed = true;
            TEST_POINT(mutation->kind == MUTATION_WRITE ?
                       SPARC64_FILE_CAPS_TEST_PWRITE_SEALED :
                       mutation->kind == MUTATION_SEQUENTIAL_WRITE ?
                       SPARC64_FILE_CAPS_TEST_WRITE_SEALED :
                       SPARC64_FILE_CAPS_TEST_APPEND_PWRITE_SEALED);
            status = 0;
        }
    } else {
        if (id != mutation->id)
            status = id < mutation->id ? ERANGE : ENOENT;
        else if (mutation->protocol_version != 2u ||
                 (op == OP_WRITE_EXECUTE &&
                  mutation->kind != MUTATION_WRITE) ||
                 (op == OP_SEQ_WRITE_EXECUTE &&
                  mutation->kind != MUTATION_SEQUENTIAL_WRITE) ||
                 (op == OP_APPEND_PWRITE_EXECUTE &&
                  mutation->kind != SPARC64_FILE_CAPS_MUTATION_APPEND_PWRITE) ||
                 !mutation->sealed)
            status = EINVAL;
        else {
            status = 0;
            if (!mutation->executed) {
                if (mutation->kind == MUTATION_SEQUENTIAL_WRITE) {
                    if (!sequential_origin_matches(mutation->fd,
                                                   mutation->offset,
                                                   mutation->append)) {
                        status = EIO;
                    } else if (native_write_once(mutation->fd, mutation->bytes,
                            mutation->count, &mutation->transferred,
                            &mutation->native_errno) != 0) {
                        close_rights(rights, right_count);
                        return -1;
                    }
                } else if (mutation->kind == SPARC64_FILE_CAPS_MUTATION_APPEND_PWRITE) {
                    if (append_pwrite_origin(mutation->fd, mutation->offset) != 0) {
                        status = EIO;
                    } else if (native_pwrite_once(mutation->fd, mutation->bytes,
                            mutation->count, mutation->offset,
                            &mutation->transferred, &mutation->native_errno) != 0) {
                        close_rights(rights, right_count);
                        return -1;
                    }
                } else if (writable_regular_no_append(mutation->fd) != 0) {
                    mutation->native_errno = errno;
                    mutation->transferred = -1;
                } else if (native_pwrite_once(mutation->fd, mutation->bytes,
                            mutation->count, mutation->offset,
                            &mutation->transferred, &mutation->native_errno) != 0) {
                        close_rights(rights, right_count);
                        return -1;
                }
                if (status == 0) {
                    mutation->executed = true;
                    TEST_POINT(mutation->kind == MUTATION_WRITE ?
                               SPARC64_FILE_CAPS_TEST_PWRITE_EXECUTED :
                               mutation->kind == MUTATION_SEQUENTIAL_WRITE ?
                               SPARC64_FILE_CAPS_TEST_WRITE_EXECUTED :
                               SPARC64_FILE_CAPS_TEST_APPEND_PWRITE_EXECUTED);
                }
            }
            if (status == 0) {
                native_error = mutation->native_errno;
                transferred = mutation->transferred;
                status = 0;
            }
        }
    }
    (void)send_v2_response(rights[0], op, id, status, native_error,
                           status == 0 ? transferred : 0);
    close_rights(rights, right_count);
    return 0;
}
