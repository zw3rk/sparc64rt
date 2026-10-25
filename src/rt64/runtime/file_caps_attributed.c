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
#include <sys/resource.h>
#include <sys/socket.h>
#include <unistd.h>

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

enum { REQUEST_SIZE = 80, REPLY_SIZE = 64, CHUNK_MAX = 176,
       OP_TRUNCATE_STAGE = 3, OP_TRUNCATE_EXECUTE = 4,
       OP_WRITE_BEGIN = 5, OP_WRITE_CHUNK = 6, OP_WRITE_SEAL = 7,
       OP_WRITE_EXECUTE = 8, OP_SEQ_WRITE_BEGIN = 9,
       OP_SEQ_WRITE_EXECUTE = 10, OP_APPEND_PWRITE_BEGIN = 11,
       OP_APPEND_PWRITE_EXECUTE = 12 };

#define put_u32 sparc64_file_caps_internal_put_u32
#define get_u32 sparc64_file_caps_internal_get_u32
#define put_u64 sparc64_file_caps_internal_put_u64
#define get_u64 sparc64_file_caps_internal_get_u64
#define close_rights sparc64_file_caps_internal_close_rights
#define private_fd sparc64_file_caps_internal_private_fd
#define connected_socket sparc64_file_caps_internal_connected_socket
#define unix_socket_kind sparc64_file_caps_internal_unix_socket_kind
#define await_reply sparc64_file_caps_internal_await_reply
#define writable_regular sparc64_file_caps_internal_writable_regular
#define no_sigpipe sparc64_file_caps_internal_no_sigpipe
#define close_two sparc64_file_caps_internal_close_two
#define TEST_POINT SPARC64_FILE_CAPS_INTERNAL_TEST_POINT

bool sparc64_file_caps_call_context_valid(const sparc64_file_caps_call_context_t *context)
{
    return context != NULL && context->owner_incarnation != 0 &&
           context->mm_id != 0 && context->worker_id != 0 &&
           context->worker_id <= INT32_MAX &&
           context->fsize_soft <= context->fsize_hard;
}

bool sparc64_file_caps_call_context_equal(const sparc64_file_caps_call_context_t *a,
                                     const sparc64_file_caps_call_context_t *b)
{
    if (a == NULL || b == NULL)
        return false;
    return a->owner_incarnation == b->owner_incarnation &&
           a->mm_id == b->mm_id && a->worker_id == b->worker_id &&
           a->fsize_soft == b->fsize_soft && a->fsize_hard == b->fsize_hard;
}

static void context_encode(unsigned char *frame,
                           const sparc64_file_caps_call_context_t *context)
{
    put_u64(frame + 32, context->owner_incarnation);
    put_u64(frame + 40, context->mm_id);
    put_u64(frame + 48, context->worker_id);
    put_u64(frame + 56, context->fsize_soft);
    put_u64(frame + 64, context->fsize_hard);
}

static sparc64_file_caps_call_context_t context_decode(const unsigned char *frame)
{
    sparc64_file_caps_call_context_t context = {
        .owner_incarnation = get_u64(frame + 32),
        .mm_id = get_u64(frame + 40),
        .worker_id = get_u64(frame + 48),
        .fsize_soft = get_u64(frame + 56),
        .fsize_hard = get_u64(frame + 64)
    };
    return context;
}

static bool is_begin(unsigned char op)
{
    return op == OP_TRUNCATE_STAGE || op == OP_WRITE_BEGIN ||
           op == OP_SEQ_WRITE_BEGIN || op == OP_APPEND_PWRITE_BEGIN;
}

static bool is_execute(unsigned char op)
{
    return op == OP_TRUNCATE_EXECUTE || op == OP_WRITE_EXECUTE ||
           op == OP_SEQ_WRITE_EXECUTE || op == OP_APPEND_PWRITE_EXECUTE;
}

static bool known_op(unsigned char op)
{ return op >= OP_TRUNCATE_STAGE && op <= OP_APPEND_PWRITE_EXECUTE; }

static ssize_t send_frame(int request_fd, const unsigned char frame[REQUEST_SIZE],
                          const void *payload, size_t payload_size,
                          const int *rights, size_t right_count)
{
    if (payload_size > CHUNK_MAX || right_count > 4u ||
        (payload_size != 0 && payload == NULL)) {
        errno = EINVAL;
        return -1;
    }
    struct iovec vectors[2] = {
        {.iov_base = (void *)frame, .iov_len = REQUEST_SIZE},
        {.iov_base = (void *)payload, .iov_len = payload_size}
    };
    union {
        struct cmsghdr alignment;
        unsigned char bytes[CMSG_SPACE(4 * sizeof(int))];
    } ancillary;
    memset(&ancillary, 0, sizeof(ancillary));
    struct msghdr message = {.msg_iov = vectors,
        .msg_iovlen = payload_size == 0 ? 1u : 2u};
    if (right_count != 0) {
        message.msg_control = ancillary.bytes;
        message.msg_controllen = CMSG_SPACE(right_count * sizeof(int));
        struct cmsghdr *header = CMSG_FIRSTHDR(&message);
        if (header == NULL) { errno = EIO; return -1; }
        header->cmsg_level = SOL_SOCKET;
        header->cmsg_type = SCM_RIGHTS;
        header->cmsg_len = CMSG_LEN(right_count * sizeof(int));
        memcpy(CMSG_DATA(header), rights, right_count * sizeof(int));
    }
    return sendmsg(request_fd, &message, MSG_DONTWAIT | MSG_NOSIGNAL);
}

static int request(const sparc64_file_caps_client_t *client, unsigned char op,
                   uint64_t id, uint64_t operand, uint32_t count,
                   uint32_t flags, const void *payload, size_t payload_size,
                   int borrowed_fd, const sparc64_file_caps_call_context_t *context,
                   sparc64_file_caps_mutation_result_t *out_result)
{
    if (client == NULL || client->request_fd < 3 || client->lifetime_fd < 3 ||
        !sparc64_file_caps_call_context_valid(context) || !known_op(op) || id == 0 ||
        payload_size > CHUNK_MAX || (payload_size != 0 && payload == NULL) ||
        (is_execute(op) && out_result == NULL)) {
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
    unsigned char frame[REQUEST_SIZE] = {0};
    memcpy(frame, "RVFC", 4);
    frame[4] = 3;
    frame[5] = op;
    put_u64(frame + 8, id);
    put_u64(frame + 16, operand);
    put_u32(frame + 24, count);
    put_u32(frame + 28, flags);
    context_encode(frame, context);
    int rights[4] = {reply[1], client->lifetime_fd,
                     client->request_fd, borrowed_fd};
    size_t right_count = is_begin(op) ? 4u : 3u;
    ssize_t sent = send_frame(client->request_fd, frame, payload, payload_size,
                              rights, right_count);
    int send_error = errno;
    (void)close(reply[1]);
    if (sent != (ssize_t)(REQUEST_SIZE + payload_size)) {
        (void)close(reply[0]);
        errno = sent < 0 ? send_error : EIO;
        return -1;
    }
    int received_rights[4] = {-1, -1, -1, -1};
    size_t received_count = 0;
    unsigned char answer[REPLY_SIZE];
    int observed = await_reply(reply[0], client->lifetime_fd, answer,
                               sizeof(answer), received_rights, &received_count);
    (void)close(reply[0]);
    if (observed != 0) {
        close_rights(received_rights, received_count);
        errno = EIO;
        return -1;
    }
    uint32_t status = get_u32(answer + 16);
    uint32_t native_error = get_u32(answer + 20);
    uint64_t raw_transfer = get_u64(answer + 24);
    uint32_t events = get_u32(answer + 32);
    bool valid_result = is_execute(op) ?
        (native_error == 0 ? raw_transfer <= SPARC64_FILE_CAPS_MAX_WRITE_BYTES :
                             raw_transfer == UINT64_MAX) :
        (native_error == 0 && raw_transfer == 0 && events == 0);
    if (op == OP_TRUNCATE_EXECUTE && status == 0 && native_error == 0)
        valid_result = valid_result && raw_transfer == 0;
    bool valid = received_count == 0 &&
        memcmp(answer, "RVFC", 4) == 0 && answer[4] == 3 &&
        answer[5] == op && answer[6] == 0 && answer[7] == 0 &&
        get_u64(answer + 8) == id && status < 4096u &&
        native_error < 4096u && events <= 1u && get_u32(answer + 36) == 0 &&
        get_u64(answer + 40) == context->owner_incarnation &&
        get_u64(answer + 48) == context->mm_id &&
        get_u64(answer + 56) == context->worker_id && valid_result &&
        (status == 0 || (native_error == 0 && raw_transfer == 0 && events == 0));
    if (!valid) {
        close_rights(received_rights, received_count);
        errno = EIO;
        return -1;
    }
    if (status != 0) { errno = (int)status; return -1; }
    if (is_execute(op)) {
        sparc64_file_caps_mutation_result_t completed = {
            .transferred = raw_transfer == UINT64_MAX ? -1 :
                           (int64_t)raw_transfer,
            .native_errno = (int)native_error,
            .generated_sigxfsz = events != 0
        };
        *out_result = completed;
    }
    return 0;
}

static int write_stage(const sparc64_file_caps_client_t *client, unsigned char op,
                       uint64_t id, int fd, uint64_t offset, bool append,
                       const void *bytes, size_t count,
                       const sparc64_file_caps_call_context_t *context)
{
    if (id == 0 || fd < 0 || count > SPARC64_FILE_CAPS_MAX_WRITE_BYTES ||
        (count != 0 && bytes == NULL) || offset > INT64_MAX ||
        (uint64_t)count > (uint64_t)INT64_MAX - offset) {
        errno = EINVAL;
        return -1;
    }
    if (op == OP_SEQ_WRITE_BEGIN) {
        if (sparc64_file_caps_internal_sequential_target(fd, offset, append) != 0)
            return -1;
    } else if (sparc64_file_caps_internal_pwrite_target(
                   fd, op == OP_APPEND_PWRITE_BEGIN, offset) != 0)
        return -1;
    uint32_t flags = op == OP_SEQ_WRITE_BEGIN && append ? 1u : 0u;
    if (request(client, op, id, offset, (uint32_t)count, flags,
                NULL, 0, fd, context, NULL) != 0)
        return -1;
    const unsigned char *source = bytes;
    size_t sent = 0;
    while (sent < count) {
        size_t amount = count - sent;
        if (amount > CHUNK_MAX)
            amount = CHUNK_MAX;
        if (request(client, OP_WRITE_CHUNK, id, sent, (uint32_t)amount, 0,
                    source + sent, amount, -1, context, NULL) != 0)
            return -1;
        sent += amount;
    }
    return request(client, OP_WRITE_SEAL, id, 0, 0, 0,
                   NULL, 0, -1, context, NULL);
}

int sparc64_file_caps_truncate_stage_attributed(const sparc64_file_caps_client_t *client,
    uint64_t id, int fd, uint64_t length,
    const sparc64_file_caps_call_context_t *context)
{
    if (id == 0 || fd < 0 || length > INT64_MAX) { errno = EINVAL; return -1; }
    if (writable_regular(fd) != 0)
        return -1;
    return request(client, OP_TRUNCATE_STAGE, id, length, 0, 0,
                   NULL, 0, fd, context, NULL);
}

int sparc64_file_caps_truncate_execute_attributed(const sparc64_file_caps_client_t *client,
    uint64_t id, const sparc64_file_caps_call_context_t *context,
    sparc64_file_caps_mutation_result_t *result)
{ return request(client, OP_TRUNCATE_EXECUTE, id, 0, 0, 0,
                 NULL, 0, -1, context, result); }

int sparc64_file_caps_pwrite_stage_attributed(const sparc64_file_caps_client_t *client,
    uint64_t id, int fd, uint64_t offset, const void *bytes, size_t count,
    const sparc64_file_caps_call_context_t *context)
{ return write_stage(client, OP_WRITE_BEGIN, id, fd, offset, false,
                     bytes, count, context); }

int sparc64_file_caps_pwrite_execute_attributed(const sparc64_file_caps_client_t *client,
    uint64_t id, const sparc64_file_caps_call_context_t *context,
    sparc64_file_caps_mutation_result_t *result)
{ return request(client, OP_WRITE_EXECUTE, id, 0, 0, 0,
                 NULL, 0, -1, context, result); }

int sparc64_file_caps_append_pwrite_stage_attributed(
    const sparc64_file_caps_client_t *client, uint64_t id, int fd,
    uint64_t expected_eof, const void *bytes, size_t count,
    const sparc64_file_caps_call_context_t *context)
{ return write_stage(client, OP_APPEND_PWRITE_BEGIN, id, fd, expected_eof,
                     false, bytes, count, context); }

int sparc64_file_caps_append_pwrite_execute_attributed(
    const sparc64_file_caps_client_t *client, uint64_t id,
    const sparc64_file_caps_call_context_t *context,
    sparc64_file_caps_mutation_result_t *result)
{ return request(client, OP_APPEND_PWRITE_EXECUTE, id, 0, 0, 0,
                 NULL, 0, -1, context, result); }

int sparc64_file_caps_write_stage_attributed(const sparc64_file_caps_client_t *client,
    uint64_t id, int fd, uint64_t offset, bool append,
    const void *bytes, size_t count,
    const sparc64_file_caps_call_context_t *context)
{ return write_stage(client, OP_SEQ_WRITE_BEGIN, id, fd, offset, append,
                     bytes, count, context); }

int sparc64_file_caps_write_execute_attributed(const sparc64_file_caps_client_t *client,
    uint64_t id, const sparc64_file_caps_call_context_t *context,
    sparc64_file_caps_mutation_result_t *result)
{ return request(client, OP_SEQ_WRITE_EXECUTE, id, 0, 0, 0,
                 NULL, 0, -1, context, result); }

static int send_response(int reply_fd, unsigned char op, uint64_t id,
                         int status, int native_error, int64_t transferred,
                         bool event, const sparc64_file_caps_call_context_t *context)
{
    unsigned char frame[REPLY_SIZE] = {0};
    memcpy(frame, "RVFC", 4);
    frame[4] = 3;
    frame[5] = op;
    put_u64(frame + 8, id);
    put_u32(frame + 16, (uint32_t)status);
    put_u32(frame + 20, (uint32_t)native_error);
    put_u64(frame + 24, transferred < 0 ? UINT64_MAX : (uint64_t)transferred);
    put_u32(frame + 32, event ? 1u : 0u);
    put_u64(frame + 40, context->owner_incarnation);
    put_u64(frame + 48, context->mm_id);
    put_u64(frame + 56, context->worker_id);
    struct iovec vector = {.iov_base = frame, .iov_len = sizeof(frame)};
    struct msghdr message = {.msg_iov = &vector, .msg_iovlen = 1};
    ssize_t sent = sendmsg(reply_fd, &message, MSG_DONTWAIT | MSG_NOSIGNAL);
    if (sent != (ssize_t)sizeof(frame)) {
        if (sent >= 0) errno = EIO;
        return -1;
    }
    TEST_POINT(SPARC64_FILE_CAPS_TEST_REPLY_QUEUED);
    return 0;
}

/* Only the single-threaded independent service changes its native soft
 * ceiling. It never raises native hard; an inherited finite hard ceiling can
 * still reject Linux-valid operations. A preexisting native SIGXFSZ is an
 * attribution violation, not a signal to attach to this operation. */
static int native_once(sparc64_file_caps_mutation_t *mutation)
{
    sigset_t blocked, previous, pending;
    if (sigemptyset(&blocked) != 0 || sigaddset(&blocked, SIGXFSZ) != 0 ||
        sigprocmask(SIG_BLOCK, &blocked, &previous) != 0)
        return -1;
    int result = -1;
    int saved_error = 0;
    struct rlimit original;
    bool changed_limit = false;
    struct sigaction original_action;
    bool changed_action = false;
    if (sigpending(&pending) != 0) { saved_error = errno; goto finish; }
    if (sigismember(&pending, SIGXFSZ) == 1) {
        saved_error = EIO;
        goto finish;
    }
    if (sigaction(SIGXFSZ, NULL, &original_action) != 0) {
        saved_error = errno;
        goto finish;
    }
    struct sigaction capture_action;
    memset(&capture_action, 0, sizeof(capture_action));
    capture_action.sa_handler = SIG_DFL;
    if (sigemptyset(&capture_action.sa_mask) != 0 ||
        sigaction(SIGXFSZ, &capture_action, NULL) != 0) {
        saved_error = errno;
        goto finish;
    }
    changed_action = true;
    if (getrlimit(RLIMIT_FSIZE, &original) != 0) {
        saved_error = errno;
        goto finish;
    }
    struct rlimit applied_limit = original;
    if (mutation->context.fsize_soft == UINT64_MAX)
        applied_limit.rlim_cur = RLIM_INFINITY;
    else if (mutation->context.fsize_soft > (uint64_t)RLIM_INFINITY) {
        saved_error = EOVERFLOW;
        goto finish;
    } else
        applied_limit.rlim_cur = (rlim_t)mutation->context.fsize_soft;
    if (setrlimit(RLIMIT_FSIZE, &applied_limit) != 0) {
        saved_error = errno;
        goto finish;
    }
    changed_limit = true;
    if (mutation->kind == SPARC64_FILE_CAPS_MUTATION_TRUNCATE) {
        int applied = ftruncate(mutation->fd, (off_t)mutation->length);
        int call_error = errno;
        mutation->transferred = applied == 0 ? 0 : -1;
        mutation->native_errno = applied == 0 ? 0 : call_error;
    } else {
        ssize_t applied = mutation->kind == SPARC64_FILE_CAPS_MUTATION_SEQUENTIAL_WRITE ?
            write(mutation->fd, mutation->bytes, mutation->count) :
            pwrite(mutation->fd, mutation->bytes, mutation->count,
                   (off_t)mutation->offset);
        int call_error = errno;
        mutation->transferred = applied < 0 ? -1 : (int64_t)applied;
        mutation->native_errno = applied < 0 ? call_error : 0;
    }
    if (sigpending(&pending) != 0) { saved_error = errno; goto finish; }
    if (sigismember(&pending, SIGXFSZ) == 1) {
        int signal_number = 0;
        int waited = sigwait(&blocked, &signal_number);
        if (waited != 0 || signal_number != SIGXFSZ) {
            saved_error = waited != 0 ? waited : EIO;
            goto finish;
        }
        mutation->generated_sigxfsz = true;
    }
    result = 0;
finish:
    if (changed_limit && setrlimit(RLIMIT_FSIZE, &original) != 0) {
        saved_error = errno;
        result = -1;
    }
    if (changed_action && sigaction(SIGXFSZ, &original_action, NULL) != 0) {
        saved_error = errno;
        result = -1;
    }
    if (sigprocmask(SIG_SETMASK, &previous, NULL) != 0)
        return -1;
    if (result != 0)
        errno = saved_error;
    return result;
}

int sparc64_file_caps_internal_process_v3(const unsigned char *packet,
                                     ssize_t received, bool truncated,
                                     int rights[4], size_t right_count,
                                     bool rights_valid,
                                     sparc64_file_caps_mutation_t *mutation)
{
    unsigned char op = received >= 6 ? packet[5] : 0;
    uint64_t id = received >= REQUEST_SIZE ? get_u64(packet + 8) : 0;
    sparc64_file_caps_call_context_t context = {0};
    if (received >= REQUEST_SIZE)
        context = context_decode(packet);
    uint64_t operand = received >= REQUEST_SIZE ? get_u64(packet + 16) : 0;
    uint32_t count = received >= REQUEST_SIZE ? get_u32(packet + 24) : 0;
    uint32_t flags = received >= REQUEST_SIZE ? get_u32(packet + 28) : 0;
    size_t expected_rights = is_begin(op) ? 4u : 3u;
    bool reply_capable = right_count >= 3 && rights[0] >= 0 &&
        rights[1] >= 0 && rights[2] >= 0 &&
        private_fd(&rights[0]) == 0 && private_fd(&rights[1]) == 0 &&
        private_fd(&rights[2]) == 0 &&
        unix_socket_kind(rights[0], SOCK_DGRAM) &&
        connected_socket(rights[1], SOCK_STREAM) &&
        connected_socket(rights[2], SOCK_DGRAM);
    bool valid = !truncated && received >= REQUEST_SIZE && known_op(op) &&
        memcmp(packet, "RVFC", 4) == 0 && packet[4] == 3 &&
        packet[5] == op && packet[6] == 0 && packet[7] == 0 &&
        get_u64(packet + 72) == 0 && sparc64_file_caps_call_context_valid(&context) &&
        id != 0 && rights_valid && right_count == expected_rights &&
        reply_capable && flags <= (op == OP_SEQ_WRITE_BEGIN ? 1u : 0u);
    if (valid && is_begin(op)) {
        valid = received == REQUEST_SIZE && operand <= INT64_MAX &&
            (op == OP_TRUNCATE_STAGE ? count == 0 :
             count <= SPARC64_FILE_CAPS_MAX_WRITE_BYTES &&
             (uint64_t)count <= (uint64_t)INT64_MAX - operand);
    } else if (valid && op == OP_WRITE_CHUNK) {
        valid = count != 0 && count <= CHUNK_MAX &&
                received == (ssize_t)(REQUEST_SIZE + count);
    } else if (valid) {
        valid = received == REQUEST_SIZE && operand == 0 && count == 0;
    }
    if (!valid) {
        if (reply_capable && known_op(op) && id != 0 &&
            sparc64_file_caps_call_context_valid(&context))
            (void)send_response(rights[0], op, id, EPROTO, 0, 0,
                                false, &context);
        close_rights(rights, right_count);
        return 0;
    }
    int status = 0;
    int native_error = 0;
    int64_t transferred = 0;
    bool event = false;
    if (is_begin(op)) {
        if (id <= mutation->id)
            status = id == mutation->id ? EEXIST : ERANGE;
        else if (private_fd(&rights[3]) != 0)
            status = errno;
        else if (op == OP_TRUNCATE_STAGE && writable_regular(rights[3]) != 0)
            status = errno;
        else if (op == OP_WRITE_BEGIN &&
                 sparc64_file_caps_internal_pwrite_target(rights[3], false,
                                                      operand) != 0)
            status = errno;
        else if (op == OP_SEQ_WRITE_BEGIN &&
                 sparc64_file_caps_internal_sequential_target(rights[3], operand,
                                                         flags != 0) != 0)
            status = EIO;
        else if (op == OP_APPEND_PWRITE_BEGIN &&
                 sparc64_file_caps_internal_pwrite_target(rights[3], true,
                                                      operand) != 0)
            status = EIO;
        else {
            if (mutation->fd >= 0)
                (void)close(mutation->fd);
            memset(mutation, 0, sizeof(*mutation));
            mutation->id = id;
            mutation->length = operand;
            mutation->offset = operand;
            mutation->count = count;
            mutation->fd = rights[3];
            mutation->kind = op == OP_TRUNCATE_STAGE ?
                SPARC64_FILE_CAPS_MUTATION_TRUNCATE :
                op == OP_WRITE_BEGIN ? SPARC64_FILE_CAPS_MUTATION_WRITE :
                op == OP_SEQ_WRITE_BEGIN ?
                    SPARC64_FILE_CAPS_MUTATION_SEQUENTIAL_WRITE :
                    SPARC64_FILE_CAPS_MUTATION_APPEND_PWRITE;
            mutation->append = op == OP_SEQ_WRITE_BEGIN && flags != 0;
            mutation->protocol_version = 3u;
            mutation->context = context;
            rights[3] = -1;
        }
    } else if (id != mutation->id)
        status = id < mutation->id ? ERANGE : ENOENT;
    else if (mutation->protocol_version != 3u ||
             !sparc64_file_caps_call_context_equal(&context, &mutation->context))
        status = EINVAL;
    else if (op == OP_WRITE_CHUNK) {
        if (mutation->kind == SPARC64_FILE_CAPS_MUTATION_TRUNCATE ||
            mutation->sealed || operand != mutation->received ||
            mutation->received > mutation->count ||
            count > mutation->count - mutation->received)
            status = EINVAL;
        else {
            memcpy(mutation->bytes + mutation->received,
                   packet + REQUEST_SIZE, count);
            mutation->received += count;
        }
    } else if (op == OP_WRITE_SEAL) {
        if (mutation->kind == SPARC64_FILE_CAPS_MUTATION_TRUNCATE ||
            mutation->sealed || mutation->received != mutation->count)
            status = EINVAL;
        else
            mutation->sealed = true;
    } else if ((op == OP_TRUNCATE_EXECUTE &&
                mutation->kind != SPARC64_FILE_CAPS_MUTATION_TRUNCATE) ||
               (op == OP_WRITE_EXECUTE &&
                mutation->kind != SPARC64_FILE_CAPS_MUTATION_WRITE) ||
               (op == OP_SEQ_WRITE_EXECUTE &&
                mutation->kind != SPARC64_FILE_CAPS_MUTATION_SEQUENTIAL_WRITE) ||
               (op == OP_APPEND_PWRITE_EXECUTE &&
                mutation->kind != SPARC64_FILE_CAPS_MUTATION_APPEND_PWRITE) ||
               (mutation->kind != SPARC64_FILE_CAPS_MUTATION_TRUNCATE &&
                !mutation->sealed))
        status = EINVAL;
    else {
        if (!mutation->executed) {
            if (mutation->kind == SPARC64_FILE_CAPS_MUTATION_SEQUENTIAL_WRITE &&
                sparc64_file_caps_internal_sequential_target(mutation->fd,
                    mutation->offset, mutation->append) != 0)
                status = EIO;
            else if (mutation->kind == SPARC64_FILE_CAPS_MUTATION_APPEND_PWRITE &&
                     sparc64_file_caps_internal_pwrite_target(mutation->fd, true,
                         mutation->offset) != 0)
                status = EIO;
            else if (mutation->kind == SPARC64_FILE_CAPS_MUTATION_WRITE &&
                     sparc64_file_caps_internal_pwrite_target(mutation->fd, false,
                         mutation->offset) != 0)
                status = EIO;
            else if (native_once(mutation) != 0) {
                int saved = errno;
                close_rights(rights, right_count);
                errno = saved;
                return -1;
            } else
                mutation->executed = true;
        }
        if (status == 0) {
            native_error = mutation->native_errno;
            transferred = mutation->transferred;
            event = mutation->generated_sigxfsz;
        }
    }
    (void)send_response(rights[0], op, id, status, native_error,
                        status == 0 ? transferred : 0,
                        status == 0 && event, &context);
    close_rights(rights, right_count);
    return 0;
}
