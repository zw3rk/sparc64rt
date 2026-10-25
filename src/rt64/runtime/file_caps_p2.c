/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#include "file_caps_split.h"


static int serve_with_cleanup(sparc64_file_caps_server_t *server,
                              sparc64_file_caps_terminal_cleanup_fn terminal,
                              const sparc64_file_caps_retained_cleanup_t *retained_ops)
{
    if (server == NULL) {
        errno = EINVAL;
        return -1;
    }
    if (server->request_fd < 3 ||
        server->lifetime_fd < 3 ||
        !connected_socket(server->request_fd, SOCK_DGRAM) ||
        !connected_socket(server->lifetime_fd, SOCK_STREAM)) {
        sparc64_file_caps_server_close(server);
        errno = EINVAL;
        return -1;
    }
    source_t *sources = calloc((size_t)SPARC64_FILE_CAPS_MAX_ATTEMPTS,
                               sizeof(*sources));
    departure_slot_t *departures = calloc(MAX_DEPARTURES,
                                           sizeof(*departures));
    struct pollfd *waiters = calloc(MAX_DEPARTURES + 2, sizeof(*waiters));
    size_t *waiter_slot = calloc(MAX_DEPARTURES, sizeof(*waiter_slot));
    if (sources == NULL || departures == NULL || waiters == NULL ||
        waiter_slot == NULL) {
        free(sources);
        free(departures);
        free(waiters);
        free(waiter_slot);
        sparc64_file_caps_server_close(server);
        return -1;
    }
    for (size_t i = 0; i < MAX_DEPARTURES; ++i)
        departures[i] = (departure_slot_t){.reply_fd = -1,
            .lifetime_fd = -1, .sender_fd = -1};
    size_t count = 0;
    uint64_t last_id = 0;
    uint64_t last_attempt = 0;
    sparc64_file_caps_mutation_t mutation = {.fd = -1};
    cleanup_registration_t cleanup = {.control_fd = -1, .directory_fd = -1};
    int result = 0;
    bool request_open = true;
    size_t last_slot = MAX_DEPARTURES;
    for (;;) {
        waiters[0] = (struct pollfd){.fd = request_open ?
            server->request_fd : -1, .events = POLLIN | POLLHUP};
        waiters[1] = (struct pollfd){.fd = server->lifetime_fd,
            .events = POLLIN | POLLHUP};
        nfds_t used = 2;
        for (size_t i = 0; i < MAX_DEPARTURES; ++i) {
            if (departures[i].reply_fd < 0 || departures[i].released)
                continue;
            waiters[used] = (struct pollfd){.fd = departures[i].reply_fd,
                .events = POLLIN | POLLHUP};
            waiter_slot[used - 2] = i;
            ++used;
        }
        bool have_released = false;
        for (size_t i = 0; i < MAX_DEPARTURES; ++i)
            have_released |= departures[i].released;
        /* A prior pass may have processed RELEASE then continued to drain a
         * queued request. Never sleep while that release needs NONLAST. */
        int ready = poll(waiters, used, have_released ? 0 : -1);
        if (ready < 0) {
            if (errno == EINTR)
                continue;
            result = -1;
            break;
        }
        if (request_open &&
            (waiters[0].revents & (POLLIN | POLLHUP | POLLERR)) != 0) {
            int handled = process_request(server->request_fd, sources, &count,
                                          &last_id, &last_attempt, &mutation,
                                          &cleanup, departures,
                                          terminal != NULL || retained_ops != NULL,
                                          retained_ops);
            if (handled < 0) {
                result = -1;
                break;
            }
            if (handled > 0 || (waiters[0].revents & POLLHUP) != 0)
                request_open = false;
            continue; /* Drain queued requests before final lifetime EOF. */
        }
        for (nfds_t j = 2; j < used; ++j) {
            if ((waiters[j].revents & POLLNVAL) != 0 ||
                ((waiters[j].revents & (POLLIN | POLLHUP | POLLERR)) != 0 &&
                 departure_receive_release(&departures[waiter_slot[j - 2]]) != 0)) {
                result = -1;
                break;
            }
        }
        if (result != 0)
            break;
        if ((waiters[0].revents & (POLLERR | POLLNVAL)) != 0 ||
            (waiters[1].revents & (POLLERR | POLLNVAL)) != 0) {
            errno = EIO;
            result = -1;
            break;
        }
        size_t released = 0;
        for (size_t i = 0; i < MAX_DEPARTURES; ++i)
            released += departures[i].released ? 1u : 0u;
        if (released != 0 && request_open) {
            struct pollfd pending = {.fd = server->request_fd, .events = POLLIN};
            if (poll(&pending, 1, 0) < 0) {
                if (errno == EINTR)
                    continue;
                result = -1;
                break;
            }
            if ((pending.revents & POLLIN) != 0)
                continue; /* Drain all queued SCM rights before deciding. */
        }
        int life = lifetime_probe(server->lifetime_fd);
        if (life < 0) {
            result = -1;
            break;
        }
        if (life == 1) {
            /* At most one admitted release owns the final retirement wait. */
            for (size_t i = 0; i < MAX_DEPARTURES; ++i)
                if (departures[i].released) {
                    last_slot = i;
                    break;
                }
            for (size_t i = 0; i < MAX_DEPARTURES; ++i)
                if (i != last_slot && departures[i].released)
                    (void)departure_answer(&departures[i], 'N');
            break;
        }
        for (size_t i = 0; i < MAX_DEPARTURES; ++i)
            if (departures[i].released)
                (void)departure_answer(&departures[i], 'N');
    }
    int saved = errno;
    for (size_t i = 0; i < count; ++i)
        (void)close(sources[i].fd);
    if (mutation.fd >= 0)
        (void)close(mutation.fd);
    if (result == 0 && (terminal != NULL || retained_ops != NULL)) {
        /* An acknowledged first leg can outlive a lost second leg. The
         * caller preserves the family then; do not report clean retirement. */
        if (cleanup.control_fd >= 0 && !cleanup.ready) {
            result = -1;
            saved = EPROTO;
        }
        else if (cleanup.ready &&
                 (retained_ops != NULL ?
                  retained_ops->terminal(cleanup.control_fd,
                      cleanup.directory_fd, cleanup.directory,
                      cleanup.retained) :
                  terminal(cleanup.control_fd, cleanup.directory_fd,
                           cleanup.directory)) != 0) {
            result = -1;
            saved = errno;
        }
    }
    if (result == 0 && last_slot < MAX_DEPARTURES &&
        departure_answer(&departures[last_slot], 'L') != 0) {
        result = -1;
        saved = errno;
    }
    for (size_t i = 0; i < MAX_DEPARTURES; ++i)
        departure_slot_close(&departures[i]);
    if (retained_ops != NULL && retained_ops->release != NULL)
        retained_ops->release(cleanup.retained);
    close_two(cleanup.control_fd, cleanup.directory_fd);
    free(sources);
    free(departures);
    free(waiters);
    free(waiter_slot);
    sparc64_file_caps_server_close(server);
    errno = saved;
    return result;
}

int sparc64_file_caps_serve_with_cleanup(sparc64_file_caps_server_t *server,
                                    sparc64_file_caps_terminal_cleanup_fn terminal)
{
    return serve_with_cleanup(server, terminal, NULL);
}

int sparc64_file_caps_serve_with_retained_cleanup(
    sparc64_file_caps_server_t *server,
    const sparc64_file_caps_retained_cleanup_t *cleanup)
{
    if (cleanup == NULL || cleanup->terminal == NULL ||
        cleanup->release == NULL ||
        (cleanup->prepare != NULL && cleanup->prepare_context != NULL)) {
        sparc64_file_caps_server_close(server);
        errno = EINVAL;
        return -1;
    }
    return serve_with_cleanup(server, NULL, cleanup);
}

int sparc64_file_caps_serve(sparc64_file_caps_server_t *server)
{
    return serve_with_cleanup(server, NULL, NULL);
}

void sparc64_file_caps_internal_close_two(int first, int second)
{ close_two(first, second); }
void sparc64_file_caps_internal_close_rights(int rights[4], size_t count)
{ close_rights(rights, count); }
int sparc64_file_caps_internal_private_fd(int *fd) { return private_fd(fd); }
bool sparc64_file_caps_internal_connected_socket(int fd, int type)
{ return connected_socket(fd, type); }
bool sparc64_file_caps_internal_unix_socket_kind(int fd, int type)
{ return unix_socket_kind(fd, type); }
void sparc64_file_caps_internal_put_u32(unsigned char *at, uint32_t v)
{ put_u32(at, v); }
uint32_t sparc64_file_caps_internal_get_u32(const unsigned char *at)
{ return get_u32(at); }
void sparc64_file_caps_internal_put_u64(unsigned char *at, uint64_t v)
{ put_u64(at, v); }
uint64_t sparc64_file_caps_internal_get_u64(const unsigned char *at)
{ return get_u64(at); }
int sparc64_file_caps_internal_collect_rights(struct msghdr *m, int r[4], size_t *n)
{ return collect_rights(m, r, n); }
int sparc64_file_caps_internal_await_reply(int fd, int life, unsigned char *frame,
                                      size_t size, int rights[4], size_t *count)
{ return await_reply(fd, life, frame, size, rights, count); }
int sparc64_file_caps_internal_writable_regular(int fd) { return writable_regular(fd); }
int sparc64_file_caps_internal_no_sigpipe(int fd) { return no_sigpipe(fd); }
void sparc64_file_caps_internal_test_point(int point)
{
#ifdef SPARC64_FILE_CAPS_TESTING
    TEST_POINT((sparc64_file_caps_test_point_t)point);
#else
    (void)point;
#endif
}
