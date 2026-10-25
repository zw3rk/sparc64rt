/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#include "file_caps_split.h"


/* An admitted handle may not be copied or nested on one native thread. */
static _Thread_local sparc64_file_caps_departure_t *active_departure;

int sparc64_file_caps_departure_begin(const sparc64_file_caps_client_t *client,
                                 sparc64_file_caps_departure_t *out)
{
    if (client == NULL || client->request_fd < 3 || client->lifetime_fd < 3 ||
        out == NULL || out->reply_fd != -1 || out->active ||
        active_departure != NULL) {
        errno = EINVAL;
        return -1;
    }
    int prior;
    int cancel_error = pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &prior);
    if (cancel_error != 0) {
        errno = cancel_error;
        return -1;
    }
    int pair[2] = {-1, -1};
    int saved = 0;
    bool submitted = false;
    if (socketpair(AF_UNIX, native_lifetime_socket_type(), 0, pair) != 0 ||
        private_fd(&pair[0]) != 0 || private_fd(&pair[1]) != 0 ||
        no_sigpipe(pair[0]) != 0 || no_sigpipe(pair[1]) != 0) {
        saved = errno;
        goto failed;
    }
    unsigned char frame[FRAME_SIZE] = {0};
    memcpy(frame, "RVFD", 4);
    frame[4] = DEPARTURE_VERSION;
    frame[5] = OP_DEPARTURE_PREPARE;
    put_u64(frame + 8, 1);
    int rights[3] = {pair[1], client->lifetime_fd, client->request_fd};
    submitted = true;
    ssize_t sent = send_packet(client->request_fd, frame, sizeof(frame), rights, 3);
    saved = sent < 0 ? errno : EIO;
    if (sent != (ssize_t)sizeof(frame))
        goto failed;
    TEST_POINT(SPARC64_FILE_CAPS_TEST_DEPARTURE_PREPARE_SENT);
    char answer = 0;
    if (departure_reply_byte(pair[0], client->lifetime_fd, &answer) != 0) {
        saved = errno;
        goto failed;
    }
    if (answer == 'E') {
        saved = EAGAIN; /* Admission refused before caller teardown. */
        submitted = false;
        goto failed;
    }
    if (answer != 'A') {
        saved = EPROTO;
        goto failed;
    }
    /* Darwin can discard a queued SCM endpoint when its producer dies.
     * Retain this local sender until ADMITTED proves server ownership. */
    (void)close(pair[1]);
    pair[1] = -1;
    *out = (sparc64_file_caps_departure_t){.reply_fd = pair[0],
        .owner_thread = pthread_self(), .prior_cancel_state = prior,
        .active = true, .finished = false};
    active_departure = out;
    return 0;
failed:
    close_two(pair[0], pair[1]);
    /* Once PREPARE may have entered the kernel, the caller must fail-stop;
     * restoring cancellation could abandon its family before that decision. */
    if (!submitted)
        (void)pthread_setcancelstate(prior, NULL);
    errno = saved;
    return submitted ? -2 : -1;
}

int sparc64_file_caps_departure_finish(sparc64_file_caps_departure_t *handle,
                                  bool *last)
{
    if (handle == NULL || last == NULL || !handle->active || handle->finished ||
        handle->reply_fd < 3 || active_departure != handle ||
        !pthread_equal(handle->owner_thread, pthread_self())) {
        errno = EINVAL;
        return -1;
    }
    char release = 'R';
    ssize_t sent = send(handle->reply_fd, &release, 1,
                        MSG_DONTWAIT | MSG_NOSIGNAL);
    if (sent != 1) {
        errno = sent < 0 ? errno : EIO;
        return -2;
    }
    if (shutdown(handle->reply_fd, SHUT_WR) != 0)
        return -2;
    char answer = 0;
    if (departure_reply_byte(handle->reply_fd, -1, &answer) != 0)
        return -2;
    if (answer != 'N' && answer != 'L') {
        errno = EPROTO;
        return -2;
    }
    *last = answer == 'L';
    handle->finished = true;
    (void)close(handle->reply_fd);
    handle->reply_fd = -1;
    return 0;
}

int sparc64_file_caps_departure_end(sparc64_file_caps_departure_t *handle)
{
    if (handle == NULL || !handle->active || !handle->finished ||
        active_departure != handle ||
        !pthread_equal(handle->owner_thread, pthread_self())) {
        errno = EINVAL;
        return -1;
    }
    int prior = handle->prior_cancel_state;
    active_departure = NULL;
    *handle = (sparc64_file_caps_departure_t)SPARC64_FILE_CAPS_DEPARTURE_INITIALIZER;
    int result = pthread_setcancelstate(prior, NULL);
    if (result != 0) {
        errno = result;
        return -1;
    }
    return 0;
}

int sparc64_file_caps_fetch(const sparc64_file_caps_client_t *client,
                       uint64_t source_id, int *out_fd)
{
    if (out_fd == NULL || source_id == 0) {
        errno = EINVAL;
        return -1;
    }
    return request(client, OP_FETCH, source_id, 0, -1, out_fd, NULL);
}

int writable_regular(int fd)
{
    struct stat status;
    if (fstat(fd, &status) != 0)
        return -1;
    int flags = fcntl(fd, F_GETFL);
    if (flags < 0)
        return -1;
    if (!S_ISREG(status.st_mode) || status.st_size < 0 ||
        (flags & O_ACCMODE) == O_RDONLY
#ifdef O_PATH
        || (flags & O_PATH) != 0
#endif
        ) {
        errno = EINVAL;
        return -1;
    }
    return 0;
}


/* The independent service has one thread. Preserve any preexisting pending
 * SIGXFSZ, but consume the new signal generated by our failed native operation
 * before restoring its mask. Otherwise RLIMIT_FSIZE can kill the service
 * before it retains EFBIG. This does not implement guest signal/limit policy. */
static int native_truncate(int fd, uint64_t length, int *native_error)
{
    sigset_t blocked, previous, pending;
    if (sigemptyset(&blocked) != 0 || sigaddset(&blocked, SIGXFSZ) != 0 ||
        sigprocmask(SIG_BLOCK, &blocked, &previous) != 0)
        return -1;
    int result = -1, saved = 0;
    if (sigpending(&pending) != 0) { saved = errno; goto restore; }
    bool already_pending = sigismember(&pending, SIGXFSZ) == 1;
    int applied = ftruncate(fd, (off_t)length);
    *native_error = applied == 0 ? 0 : errno;
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


int sparc64_file_caps_truncate_stage(const sparc64_file_caps_client_t *client,
                                 uint64_t operation_id, int borrowed_fd,
                                 uint64_t length)
{
    if (operation_id == 0 || borrowed_fd < 0 || length > INT64_MAX) {
        errno = EINVAL; return -1;
    }
    if (writable_regular(borrowed_fd) != 0)
        return -1;
    return request(client, OP_TRUNCATE_STAGE, operation_id, length, borrowed_fd, NULL, NULL);
}

int sparc64_file_caps_truncate_execute(const sparc64_file_caps_client_t *client,
                                   uint64_t operation_id, int *out_native_errno)
{
    if (out_native_errno == NULL || operation_id == 0) {
        errno = EINVAL; return -1;
    }
    return request(client, OP_TRUNCATE_EXECUTE, operation_id, 0, -1, NULL, out_native_errno);
}



static int send_response(int reply_fd, unsigned char op, uint64_t id,
                         int status, int source_fd, int native_error)
{
    unsigned char frame[FRAME_SIZE];
    frame_base(frame, op);
    put_u32(frame + 8, (uint32_t)status);
    put_u64(frame + 12, id);
    put_u32(frame + 20, (uint32_t)native_error);
    ssize_t sent = send_frame(reply_fd, frame, source_fd >= 0 ? &source_fd : NULL,
                              source_fd >= 0 ? 1u : 0u);
    if (sent != FRAME_SIZE) {
        if (sent >= 0)
            errno = EIO;
        return -1;
    }
    TEST_POINT(SPARC64_FILE_CAPS_TEST_REPLY_QUEUED);
    return 0;
}

static bool cleanup_packet_valid(const unsigned char *packet,
                                 ssize_t received, unsigned char *op,
                                 size_t *path_length)
{
    if (received != CLEANUP_FRAME_SIZE || memcmp(packet, "RVFC", 4) != 0 ||
        packet[4] != CLEANUP_VERSION || packet[6] != 0 || packet[7] != 0 ||
        (packet[5] != OP_CLEANUP_CONTROL &&
         packet[5] != OP_CLEANUP_DIRECTORY) ||
        get_u64(packet + 8) != packet[5] ||
        get_u32(packet + 20) != 0)
        return false;
    for (size_t i = 24; i < 32; ++i)
        if (packet[i] != 0)
            return false;
    *op = packet[5];
    *path_length = get_u32(packet + 16);
    if (*op == OP_CLEANUP_CONTROL && *path_length != 0)
        return false;
    if (*op == OP_CLEANUP_DIRECTORY &&
        (*path_length == 0 || *path_length >= 64 || packet[32] != '/'))
        return false;
    for (size_t i = 32; i < CLEANUP_FRAME_SIZE; ++i) {
        if (i < 32 + *path_length) {
            if (packet[i] == 0)
                return false;
        } else if (packet[i] != 0)
            return false;
    }
    return true;
}

static int process_cleanup_request(const unsigned char *packet,
                                   ssize_t received, bool truncated,
                                   int rights[MAX_RIGHTS], size_t right_count,
                                   bool rights_valid,
                                   cleanup_registration_t *cleanup,
                                   bool allowed,
                                   const sparc64_file_caps_retained_cleanup_t *retained_ops)
{
    unsigned char op = 0;
    size_t path_length = 0;
    if (truncated || !rights_valid || right_count != 4 ||
        !cleanup_packet_valid(packet, received, &op, &path_length)) {
        close_rights(rights, right_count);
        return 0;
    }
    int status = allowed ? 0 : EOPNOTSUPP;
    if (private_fd(&rights[0]) != 0 || private_fd(&rights[1]) != 0 ||
        private_fd(&rights[2]) != 0 || private_fd(&rights[3]) != 0 ||
        !unix_socket_kind(rights[0], SOCK_DGRAM) ||
        !connected_socket(rights[1], SOCK_STREAM) ||
        !connected_socket(rights[2], SOCK_DGRAM))
        status = EINVAL;
    if (status == 0 && op == OP_CLEANUP_CONTROL) {
        struct stat control;
        int flags = fcntl(rights[3], F_GETFL);
        if (cleanup->control_fd >= 0)
            status = EEXIST;
        else if (flags < 0 || fstat(rights[3], &control) != 0)
            status = errno;
        else if (!S_ISREG(control.st_mode) ||
                 (control.st_mode & 07777) != 0600 ||
                 control.st_uid != geteuid() || control.st_nlink != 1 ||
                 (flags & O_ACCMODE) != O_RDWR)
            status = EINVAL;
        else {
            cleanup->control_fd = rights[3];
            rights[3] = -1;
        }
    } else if (status == 0) {
        struct stat directory, named_control, retained_control, path_status;
        char path[64];
        memcpy(path, packet + 32, path_length);
        path[path_length] = '\0';
        if (cleanup->control_fd < 0)
            status = ENOENT;
        else if (cleanup->ready)
            status = EEXIST;
        else if (fstat(rights[3], &directory) != 0 ||
                 fstat(cleanup->control_fd, &retained_control) != 0 ||
                 fstatat(rights[3], "control", &named_control,
                         AT_SYMLINK_NOFOLLOW) != 0 ||
                 fstatat(AT_FDCWD, path, &path_status,
                         AT_SYMLINK_NOFOLLOW) != 0)
            status = errno;
        else if (!S_ISDIR(directory.st_mode) ||
                 (directory.st_mode & 07777) != 0700 ||
                 directory.st_uid != geteuid() ||
                 directory.st_dev != path_status.st_dev ||
                 directory.st_ino != path_status.st_ino ||
                 directory.st_dev != retained_control.st_dev ||
                 named_control.st_dev != retained_control.st_dev ||
                 named_control.st_ino != retained_control.st_ino)
            status = EINVAL;
        else if (retained_ops != NULL &&
                 ((retained_ops->prepare_context != NULL &&
                   retained_ops->prepare_context(cleanup->control_fd,
                       rights[3], path, &cleanup->retained,
                       retained_ops->context) != 0) ||
                  (retained_ops->prepare_context == NULL &&
                   retained_ops->prepare != NULL &&
                   retained_ops->prepare(cleanup->control_fd, rights[3], path,
                                         &cleanup->retained) != 0)))
            status = errno != 0 ? errno : EIO;
        else {
            cleanup->directory_fd = rights[3];
            rights[3] = -1;
            memcpy(cleanup->directory, path, path_length + 1u);
            cleanup->ready = true;
        }
    }
    (void)send_response(rights[0], op, op, status, -1, 0);
    close_rights(rights, right_count);
    return 0;
}

void departure_slot_close(departure_slot_t *slot)
{
    close_two(slot->reply_fd, slot->lifetime_fd);
    if (slot->sender_fd >= 0)
        (void)close(slot->sender_fd);
    *slot = (departure_slot_t){.reply_fd = -1, .lifetime_fd = -1,
                                .sender_fd = -1};
}

static bool departure_frame_valid(const unsigned char *frame, ssize_t count)
{
    if (count != FRAME_SIZE || memcmp(frame, "RVFD", 4) != 0 ||
        frame[4] != DEPARTURE_VERSION || frame[5] != OP_DEPARTURE_PREPARE ||
        frame[6] != 0 || frame[7] != 0 || get_u64(frame + 8) != 1)
        return false;
    for (size_t i = 16; i < FRAME_SIZE; ++i)
        if (frame[i] != 0)
            return false;
    return true;
}

static int process_departure_prepare(const unsigned char *frame,
                                     ssize_t count, bool truncated,
                                     int rights[MAX_RIGHTS], size_t right_count,
                                     bool rights_valid,
                                     departure_slot_t *departures,
                                     bool allowed)
{
    if (truncated || !rights_valid || right_count != 3 ||
        !departure_frame_valid(frame, count)) {
        close_rights(rights, right_count);
        return 0;
    }
    bool valid = private_fd(&rights[0]) == 0 &&
        private_fd(&rights[1]) == 0 && private_fd(&rights[2]) == 0 &&
        no_sigpipe(rights[0]) == 0 &&
        connected_socket(rights[0], SOCK_STREAM) &&
        connected_socket(rights[1], SOCK_STREAM) &&
        connected_socket(rights[2], SOCK_DGRAM);
    if (!valid || !allowed) {
        (void)send(rights[0], "E", 1, MSG_DONTWAIT | MSG_NOSIGNAL);
        close_rights(rights, right_count);
        return 0;
    }
    size_t vacant = MAX_DEPARTURES;
    for (size_t i = 0; i < MAX_DEPARTURES; ++i)
        if (departures[i].reply_fd < 0) {
            vacant = i;
            break;
        }
    if (vacant == MAX_DEPARTURES) {
        (void)send(rights[0], "E", 1, MSG_DONTWAIT | MSG_NOSIGNAL);
        close_rights(rights, right_count);
        return 0;
    }
    departures[vacant] = (departure_slot_t){.reply_fd = rights[0],
        .lifetime_fd = rights[1], .sender_fd = rights[2],
        .release_seen = false, .released = false};
    rights[0] = rights[1] = rights[2] = -1;
    if (send(departures[vacant].reply_fd, "A", 1,
             MSG_DONTWAIT | MSG_NOSIGNAL) != 1)
        departure_slot_close(&departures[vacant]);
    else
        TEST_POINT(SPARC64_FILE_CAPS_TEST_DEPARTURE_ADMITTED_SENT);
    return 0;
}



/* A closed datagram control can remain readable on Darwin. Stop polling it;
 * the independent stream lifetime still decides when retained sources retire. */
int process_request(int control_fd, source_t *sources, size_t *count,
                           uint64_t *last_id, uint64_t *last_attempt,
                           sparc64_file_caps_mutation_t *mutation,
                           cleanup_registration_t *cleanup,
                           departure_slot_t *departures, bool allow_cleanup,
                           const sparc64_file_caps_retained_cleanup_t *retained_ops)
{
    unsigned char frame[SPARC64_FILE_CAPS_V2_REQUEST_SIZE + SPARC64_FILE_CAPS_V2_CHUNK_MAX];
    struct iovec vector = {.iov_base = frame, .iov_len = sizeof(frame)};
    union {
        struct cmsghdr alignment;
        unsigned char bytes[CMSG_SPACE(MAX_RIGHTS * sizeof(int))];
    } ancillary;
    memset(&ancillary, 0, sizeof(ancillary));
    struct msghdr message = {.msg_iov = &vector, .msg_iovlen = 1,
        .msg_control = ancillary.bytes, .msg_controllen = sizeof(ancillary.bytes)};
    ssize_t received = recvmsg(control_fd, &message, MSG_DONTWAIT);
    if (received < 0) {
        if (errno == ECONNRESET || errno == ENOTCONN)
            return 1;
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
            return 0;
        return -1;
    }
    int rights[MAX_RIGHTS] = {-1, -1, -1, -1};
    size_t right_count = 0;
    bool valid_rights = collect_rights(&message, rights, &right_count) == 0;
    if (received == 0) {
        close_rights(rights, right_count);
        /* Zero payload with rights is malformed; a zero datagram from a live
         * peer must not disable request service either. */
        return right_count == 0 &&
               !connected_socket(control_fd, SOCK_DGRAM) ? 1 : 0;
    }
    if (received >= 6 && frame[4] == CLEANUP_VERSION)
        return process_cleanup_request(frame, received,
            (message.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) != 0,
            rights, right_count, valid_rights, cleanup, allow_cleanup,
            retained_ops);
    if (received >= 6 && frame[4] == DEPARTURE_VERSION)
        return process_departure_prepare(frame, received,
            (message.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) != 0,
            rights, right_count, valid_rights, departures, allow_cleanup);
    if (received >= 6 && frame[4] == 3)
        return sparc64_file_caps_internal_process_v3(frame, received,
            (message.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) != 0,
            rights, right_count, valid_rights, mutation);
    if (received >= 6 && frame[4] == 2)
        return sparc64_file_caps_internal_process_v2(frame, received,
            (message.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) != 0,
            rights, right_count, valid_rights, mutation);
    bool valid_frame = received == FRAME_SIZE &&
        (frame_valid(frame, OP_REGISTER) || frame_valid(frame, OP_FETCH) ||
         frame_valid(frame, OP_TRUNCATE_STAGE) || frame_valid(frame, OP_TRUNCATE_EXECUTE));
    unsigned char op = valid_frame ? frame[5] : 0;
    uint64_t id = valid_frame ? get_u64(frame + 8) : 0;
    uint64_t attempt = valid_frame ? get_u64(frame + 16) : 0;
    if (!valid_rights || !valid_frame || id == 0 ||
        right_count != (op == OP_REGISTER || op == OP_TRUNCATE_STAGE ? 4u : 3u) ||
        (op == OP_REGISTER ? attempt == 0 ||
         attempt > SPARC64_FILE_CAPS_MAX_ATTEMPTS :
         op == OP_TRUNCATE_STAGE ? attempt > INT64_MAX : attempt != 0))
        goto done;
    /* A caller may die after send. Its reply peer can then be disconnected,
     * while the exact queued source still has to be retained. */
    if (private_fd(&rights[0]) != 0 || private_fd(&rights[1]) != 0 ||
        private_fd(&rights[2]) != 0 ||
        !unix_socket_kind(rights[0], SOCK_DGRAM) ||
        !connected_socket(rights[1], SOCK_STREAM) ||
        !connected_socket(rights[2], SOCK_DGRAM))
        goto done;
    int result = 0;
    int source = -1;
    int native_error = 0;
    if (op == OP_TRUNCATE_STAGE) {
        if (id <= mutation->id)
            result = id == mutation->id ? EEXIST : ERANGE;
        else if (private_fd(&rights[3]) != 0 || writable_regular(rights[3]) != 0)
            result = errno;
        else {
            if (mutation->fd >= 0)
                (void)close(mutation->fd);
            memset(mutation, 0, sizeof(*mutation));
            mutation->id = id;
            mutation->length = attempt;
            mutation->fd = rights[3];
            mutation->kind = SPARC64_FILE_CAPS_MUTATION_TRUNCATE;
            mutation->protocol_version = 1u;
            rights[3] = -1;
            TEST_POINT(SPARC64_FILE_CAPS_TEST_TRUNCATE_RETAINED);
        }
    } else if (op == OP_TRUNCATE_EXECUTE) {
        if (id != mutation->id)
            result = id < mutation->id ? ERANGE : ENOENT;
        else if (mutation->kind != SPARC64_FILE_CAPS_MUTATION_TRUNCATE ||
                 mutation->protocol_version != 1u)
            result = EINVAL;
        else {
            if (!mutation->executed) {
                /* Store the complete native outcome before any fallible ACK.
                 * Repeated requests never infer it from the current size. */
                if (native_truncate(mutation->fd, mutation->length,
                                        &mutation->native_errno) != 0) {
                    int saved = errno;
                    close_rights(rights, right_count);
                    errno = saved;
                    return -1;
                }
                mutation->executed = true;
                TEST_POINT(SPARC64_FILE_CAPS_TEST_TRUNCATE_EXECUTED);
            }
            native_error = mutation->native_errno;
        }
    } else if (op == OP_REGISTER) {
        struct stat status;
        if (private_fd(&rights[3]) != 0)
            result = errno;
        else if (fstat(rights[3], &status) != 0)
            result = errno;
        else {
            int flags = fcntl(rights[3], F_GETFL);
            if (flags < 0)
                result = errno;
            else if (!S_ISREG(status.st_mode) ||
                     (flags & O_ACCMODE) == O_WRONLY
#ifdef O_PATH
                     || (flags & O_PATH) != 0
#endif
                     )
                result = EINVAL;
        }
        if (result == 0) {
            for (size_t i = 0; i < *count; ++i) {
                if (sources[i].id == id) {
                    result = EEXIST;
                    break;
                }
            }
        }
        if (result != 0) {
            /* The received source remains owned by rights[]. */
        } else if (id < *last_id || attempt <= *last_attempt)
            result = ERANGE;
        else if (*count >= SPARC64_FILE_CAPS_MAX_ATTEMPTS)
            result = ENOSPC;
        else {
            sources[*count] = (source_t){id, rights[3]};
            ++*count;
            *last_id = id;
            *last_attempt = attempt;
            rights[3] = -1;
            TEST_POINT(SPARC64_FILE_CAPS_TEST_REGISTER_RETAINED);
        }
    } else {
        result = ENOENT;
        for (size_t i = 0; i < *count; ++i) {
            if (sources[i].id == id) {
                source = sources[i].fd;
                result = 0;
                break;
            }
        }
    }
    (void)send_response(rights[0], op, id, result, result == 0 ? source : -1,
                         result == 0 ? native_error : 0);
done:
    close_rights(rights, right_count);
    return 0;
}

/* The client shuts down its write half after one R. Until EOF is observed,
 * another byte may still be queued and the handle cannot elect LAST. */
int departure_receive_release(departure_slot_t *slot)
{
    if (slot->reply_fd < 0 || slot->released)
        return 0;
    unsigned char byte;
    ssize_t n = recv(slot->reply_fd, &byte, 1, MSG_DONTWAIT);
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
            return 0;
        /* A producer can die with our ADMITTED byte unread.  Its private
         * stream then resets, but other clients still own the service. */
        if (errno == ECONNRESET) {
            departure_slot_close(slot);
            return 0;
        }
        return -1;
    }
    if (n == 1) {
        if (slot->release_seen || byte != 'R') {
            errno = EPROTO;
            return -1;
        }
        slot->release_seen = true;
        return 0;
    }
    if (!slot->release_seen) {
        departure_slot_close(slot); /* Death before RELEASE grants no last vote. */
        return 0;
    }
    close_two(slot->lifetime_fd, slot->sender_fd);
    slot->lifetime_fd = slot->sender_fd = -1;
    slot->released = true;
    return 0;
}

int departure_answer(departure_slot_t *slot, char answer)
{
    int result = send(slot->reply_fd, &answer, 1,
                      MSG_DONTWAIT | MSG_NOSIGNAL) == 1 ? 0 : -1;
    departure_slot_close(slot);
    return result;
}

int lifetime_probe(int fd)
{
    for (;;) {
        unsigned char byte;
        ssize_t n = recv(fd, &byte, 1, MSG_PEEK | MSG_DONTWAIT);
        if (n == 0)
            return 1;
        if (n > 0) {
            errno = EPROTO;
            return -1;
        }
        if (errno == EINTR)
            continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return 0;
        return -1;
    }
}
