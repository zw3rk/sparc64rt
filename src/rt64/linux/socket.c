/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#define _GNU_SOURCE 1
#define _POSIX_C_SOURCE 200809L
#include "linux/socket.h"
#include "linux/message.h"
#include "linux/error.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define G_SOCK_NONBLOCK UINT32_C(0x800)
#define G_SOCK_CLOEXEC UINT32_C(0x80000)
#define G_MSG_PEEK UINT32_C(0x2)
#define G_MSG_TRUNC UINT32_C(0x20)
#define G_MSG_DONTWAIT UINT32_C(0x40)
#define G_MSG_NOSIGNAL UINT32_C(0x4000)
#define SOCKET_STAGE ((size_t)65536)

static uint64_t failure(unsigned int error)
{
    return UINT64_C(0) - error;
}

static uint64_t host_failure(int error)
{
    return failure(sparc64_linux_errno(error == 0 ? EIO : error));
}

static unsigned int output_error(sparc64_space_t *space, uint64_t address, size_t size)
{
    bool in_domain = address <= space->limit && size <= space->limit - address;
    return sparc64_fault_is_runtime(space->fault_reason) && in_domain ? 12 : 14;
}

static uint32_t read32(const unsigned char bytes[4])
{
    return (uint32_t)bytes[0] | (uint32_t)bytes[1] << 8 |
           (uint32_t)bytes[2] << 16 | (uint32_t)bytes[3] << 24;
}

static void write32(unsigned char bytes[4], uint32_t value)
{
    for (unsigned int i = 0; i < 4; ++i)
        bytes[i] = (unsigned char)(value >> (i * 8));
}

static int parse_type(uint32_t encoded, bool pair, int family,
                      int *native_type, bool *nonblocking, bool *cloexec)
{
    if ((encoded & ~(UINT32_C(0xf) | G_SOCK_NONBLOCK | G_SOCK_CLOEXEC)) != 0)
        return EINVAL;
    unsigned int base = encoded & 0xf;
    if (family != 1 && family != 2)
        return EAFNOSUPPORT;
    if (pair && family != 1)
        return EOPNOTSUPP;
    if (base == 1)
        *native_type = SOCK_STREAM;
    else if (base == 2)
        *native_type = SOCK_DGRAM;
    else if (base == 5)
        return EOPNOTSUPP; /* AF_UNIX seqpacket is a later socket slice. */
    else
        return EOPNOTSUPP;
    *nonblocking = (encoded & G_SOCK_NONBLOCK) != 0;
    *cloexec = (encoded & G_SOCK_CLOEXEC) != 0;
    return 0;
}

static int set_native_flags(int fd, bool nonblocking)
{
    if (fcntl(fd, F_SETFD, FD_CLOEXEC) < 0)
        return -1;
    int flags = fcntl(fd, F_GETFL);
    if (flags < 0 ||
        fcntl(fd, F_SETFL, nonblocking ? flags | O_NONBLOCK :
              flags & ~O_NONBLOCK) < 0)
        return -1;
#if defined(SO_NOSIGPIPE)
    int enabled = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &enabled, sizeof(enabled)) < 0)
        return -1;
#endif
    return 0;
}

static uint64_t make_socket(sparc64_linux_file_t *files, const uint64_t args[6])
{
    int family = (int)(uint32_t)args[0];
    uint32_t encoded = (uint32_t)args[1];
    int protocol = (int)(uint32_t)args[2], native_type;
    bool nonblocking, cloexec;
    int error = parse_type(encoded, false, family, &native_type,
                           &nonblocking, &cloexec);
    if (error != 0)
        return host_failure(error);
    if ((family == 1 && protocol != 0) ||
        (family == 2 && protocol != 0 &&
         protocol != (native_type == SOCK_STREAM ? IPPROTO_TCP : IPPROTO_UDP)))
        return failure(93);
    int guest_fd = sparc64_fd_reserve(&files->descriptors);
    if (guest_fd < 0)
        return host_failure(errno);
    int native_fd = socket(family == 1 ? AF_UNIX : AF_INET,
                           native_type, protocol);
    if (native_fd < 0) {
        error = errno;
        (void)sparc64_fd_cancel(&files->descriptors, (unsigned int)guest_fd);
        return host_failure(error);
    }
    if (set_native_flags(native_fd, nonblocking) < 0) {
        error = errno;
        (void)close(native_fd);
        (void)sparc64_fd_cancel(&files->descriptors, (unsigned int)guest_fd);
        return host_failure(error);
    }
    if (sparc64_fd_commit(&files->descriptors, (unsigned int)guest_fd, native_fd,
                     cloexec, 0) < 0)
        return host_failure(errno);
    return (uint64_t)guest_fd;
}

/* socketpair performs two distinct put_user(int) stores after reserving FDs
 * and before creating sockets. A failed second store leaves the first value. */
static unsigned int copy_pair(sparc64_space_t *space, uint64_t address,
                              const unsigned char encoded[8])
{
    if (!sparc64_space_write(space, address, encoded, 4))
        return output_error(space, address, 4);
    if (address > UINT64_MAX - 4)
        return 14;
    if (!sparc64_space_write(space, address + 4, encoded + 4, 4))
        return output_error(space, address + 4, 4);
    return 0;
}

static uint64_t make_pair(sparc64_linux_file_t *files, const uint64_t args[6])
{
    int family = (int)(uint32_t)args[0], protocol = (int)(uint32_t)args[2];
    int native_type;
    bool nonblocking, cloexec;
    uint32_t type = (uint32_t)args[1];
    if ((type & ~(UINT32_C(0xf) | G_SOCK_NONBLOCK | G_SOCK_CLOEXEC)) != 0)
        return failure(22);
    int first = sparc64_fd_reserve(&files->descriptors);
    if (first < 0)
        return host_failure(errno);
    int second = sparc64_fd_reserve(&files->descriptors);
    if (second < 0) {
        int error = errno;
        (void)sparc64_fd_cancel(&files->descriptors, (unsigned int)first);
        return host_failure(error);
    }
    unsigned char encoded[8];
    write32(encoded, (uint32_t)first);
    write32(encoded + 4, (uint32_t)second);
    unsigned int guest_error = copy_pair(files->space, args[3], encoded);
    if (guest_error != 0) {
        (void)sparc64_fd_cancel(&files->descriptors, (unsigned int)first);
        (void)sparc64_fd_cancel(&files->descriptors, (unsigned int)second);
        return failure(guest_error);
    }
    int error = parse_type(type, true, family, &native_type,
                           &nonblocking, &cloexec);
    if (error == 0 && protocol != 0)
        error = EPROTONOSUPPORT;
    if (error != 0)
        goto cancel_pair;
    int native[2];
    if (socketpair(AF_UNIX, native_type, 0, native) < 0) {
        error = errno;
        goto cancel_pair;
    }
    if (set_native_flags(native[0], nonblocking) < 0 ||
        set_native_flags(native[1], nonblocking) < 0) {
        error = errno;
        goto close_pair;
    }
    if (sparc64_fd_commit(&files->descriptors, (unsigned int)first,
                     native[0], cloexec, 0) < 0) {
        error = (int)sparc64_linux_errno(errno);
        (void)close(native[1]);
        (void)sparc64_fd_cancel(&files->descriptors, (unsigned int)second);
        return failure((unsigned int)error);
    }
    if (sparc64_fd_commit(&files->descriptors, (unsigned int)second,
                     native[1], cloexec, 0) < 0) {
        error = (int)sparc64_linux_errno(errno);
        (void)sparc64_fd_close(&files->descriptors, (unsigned int)first);
        return failure((unsigned int)error);
    }
    return 0;
close_pair:
    (void)close(native[0]);
    (void)close(native[1]);
cancel_pair:
    (void)sparc64_fd_cancel(&files->descriptors, (unsigned int)first);
    (void)sparc64_fd_cancel(&files->descriptors, (unsigned int)second);
    return host_failure(error);
}

static int read_address(sparc64_space_t *space, uint64_t pointer, uint32_t length,
                        struct sockaddr_storage *out, socklen_t *out_length)
{
    if (length < 16 || length > sizeof(*out))
        return EINVAL;
    unsigned char bytes[sizeof(*out)];
    if (!sparc64_space_read(space, pointer, bytes, length, SPARC64_MEM_READ))
        return sparc64_fault_is_runtime(space->fault_reason) ? ENOMEM : EFAULT;
    unsigned int family = (unsigned int)bytes[0] | (unsigned int)bytes[1] << 8;
    if (family != 2)
        return EAFNOSUPPORT;
    struct sockaddr_in in = {0};
    in.sin_family = AF_INET;
    memcpy(&in.sin_port, bytes + 2, 2);
    memcpy(&in.sin_addr.s_addr, bytes + 4, 4);
    memset(out, 0, sizeof(*out));
    memcpy(out, &in, sizeof(in));
    *out_length = sizeof(in);
    return 0;
}

static unsigned int write_address(sparc64_space_t *space, uint64_t pointer,
                                  uint64_t length_pointer,
                                  const struct sockaddr *native,
                                  socklen_t native_length)
{
    unsigned char capacity_bytes[4];
    if (!sparc64_space_read(space, length_pointer, capacity_bytes, 4, SPARC64_MEM_READ))
        return sparc64_fault_is_runtime(space->fault_reason) ? 12 : 14;
    uint32_t capacity = read32(capacity_bytes);
    if (capacity > INT32_MAX)
        return 22;
    unsigned char encoded[16] = {0};
    uint32_t actual;
    if (native_length == 0) {
        actual = 0;
    } else if (native->sa_family == AF_INET &&
        native_length >= (socklen_t)sizeof(struct sockaddr_in)) {
        const struct sockaddr_in *in = (const struct sockaddr_in *)native;
        encoded[0] = 2;
        memcpy(encoded + 2, &in->sin_port, 2);
        memcpy(encoded + 4, &in->sin_addr.s_addr, 4);
        actual = 16;
    } else if (native->sa_family == AF_UNIX) {
        encoded[0] = 1;
        actual = 2;
    } else {
        return 97;
    }
    write32(capacity_bytes, actual);
    if (!sparc64_space_write(space, length_pointer, capacity_bytes, 4))
        return output_error(space, length_pointer, 4);
    if (capacity > actual)
        capacity = actual;
    if (capacity != 0 &&
        (pointer > space->limit || capacity > space->limit - pointer))
        return 14;
    uint32_t copied = 0;
    while (copied < capacity) {
        uint64_t at = pointer + copied;
        if (at < pointer)
            return 14;
        size_t amount = (size_t)(SPARC64_PAGE_SIZE - at % SPARC64_PAGE_SIZE);
        if (amount > capacity - copied)
            amount = capacity - copied;
        if (!sparc64_space_write(space, at, encoded + copied, amount))
            return output_error(space, at, amount);
        copied += (uint32_t)amount;
    }
    return 0;
}

static uint64_t address_operation(sparc64_linux_file_t *files, uint64_t number,
                                  const uint64_t args[6])
{
    sparc64_fd_borrow_t borrowed = {0};
    if (sparc64_fd_borrow(&files->descriptors, (uint32_t)args[0], &borrowed) < 0)
        return host_failure(errno);
    uint64_t result;
    if (number == 204 || number == 205) {
        struct sockaddr_storage native = {0};
        socklen_t length = sizeof(native);
        int called = number == 204 ?
            getsockname(borrowed.host_fd, (struct sockaddr *)&native, &length) :
            getpeername(borrowed.host_fd, (struct sockaddr *)&native, &length);
        if (called < 0)
            result = host_failure(errno);
        else {
            unsigned int error = write_address(files->space, args[1], args[2],
                                               (struct sockaddr *)&native,
                                               length);
            result = error == 0 ? 0 : failure(error);
        }
    } else {
        struct sockaddr_storage native;
        socklen_t length;
        int error = read_address(files->space, args[1], (uint32_t)args[2],
                                 &native, &length);
        if (error != 0)
            result = host_failure(error);
        else {
            int called = number == 200 ?
                bind(borrowed.host_fd, (struct sockaddr *)&native, length) :
                connect(borrowed.host_fd, (struct sockaddr *)&native, length);
            result = called < 0 ? host_failure(errno) : 0;
        }
    }
    (void)sparc64_fd_unborrow(&borrowed);
    return result;
}

static uint64_t listen_socket(sparc64_linux_file_t *files, const uint64_t args[6])
{
    sparc64_fd_borrow_t borrowed = {0};
    if (sparc64_fd_borrow(&files->descriptors, (uint32_t)args[0], &borrowed) < 0)
        return host_failure(errno);
    int called = listen(borrowed.host_fd, (int32_t)(uint32_t)args[1]);
    int error = errno;
    (void)sparc64_fd_unborrow(&borrowed);
    return called < 0 ? host_failure(error) : 0;
}

static uint64_t accept_socket(sparc64_linux_file_t *files, uint64_t number,
                              const uint64_t args[6])
{
    sparc64_fd_borrow_t listening = {0};
    if (sparc64_fd_borrow(&files->descriptors, (uint32_t)args[0], &listening) < 0)
        return host_failure(errno);
    uint32_t flags = number == 242 ? (uint32_t)args[3] : 0;
    if ((flags & ~(G_SOCK_NONBLOCK | G_SOCK_CLOEXEC)) != 0) {
        (void)sparc64_fd_unborrow(&listening);
        return failure(22);
    }
    int guest_fd = sparc64_fd_reserve(&files->descriptors);
    if (guest_fd < 0) {
        int error = errno;
        (void)sparc64_fd_unborrow(&listening);
        return host_failure(error);
    }
    struct sockaddr_storage peer = {0};
    socklen_t peer_length = sizeof(peer);
    int accepted = accept(listening.host_fd, (struct sockaddr *)&peer,
                          &peer_length);
    int error = errno;
    (void)sparc64_fd_unborrow(&listening);
    if (accepted < 0) {
        (void)sparc64_fd_cancel(&files->descriptors, (unsigned int)guest_fd);
        return host_failure(error);
    }
    if (set_native_flags(accepted, (flags & G_SOCK_NONBLOCK) != 0) < 0) {
        error = errno;
        (void)close(accepted);
        (void)sparc64_fd_cancel(&files->descriptors, (unsigned int)guest_fd);
        return host_failure(error);
    }
    if (args[1] != 0) {
        unsigned int guest_error = write_address(files->space, args[1], args[2],
                                                  (struct sockaddr *)&peer,
                                                  peer_length);
        if (guest_error != 0) {
            (void)close(accepted);
            (void)sparc64_fd_cancel(&files->descriptors, (unsigned int)guest_fd);
            return failure(guest_error);
        }
    }
    if (sparc64_fd_commit(&files->descriptors, (unsigned int)guest_fd, accepted,
                     (flags & G_SOCK_CLOEXEC) != 0, 0) < 0)
        return host_failure(errno);
    return (uint64_t)guest_fd;
}

static int native_socket_option(uint32_t guest, bool setting)
{
    switch (guest) {
    case 2: return SO_REUSEADDR;
    case 9: return SO_KEEPALIVE;
    case 3: return setting ? -1 : SO_TYPE;
    case 4: return setting ? -1 : SO_ERROR;
    default: return -1;
    }
}

static unsigned int copy_option_value(sparc64_space_t *space, uint64_t address,
                                       const unsigned char *bytes, size_t size)
{
    /* sk_getsockopt copies its value before its length, byte prefixes included. */
    if (size != 0 &&
        (address > space->limit || size > space->limit - address))
        return 14;
    for (size_t i = 0; i < size; ++i) {
        if (address > UINT64_MAX - i)
            return 14;
        if (!sparc64_space_write(space, address + i, bytes + i, 1))
            return output_error(space, address + i, 1);
    }
    return 0;
}

static uint64_t socket_option(sparc64_linux_file_t *files, uint64_t number,
                              const uint64_t args[6])
{
    sparc64_fd_borrow_t borrowed = {0};
    if (sparc64_fd_borrow(&files->descriptors, (uint32_t)args[0], &borrowed) < 0)
        return host_failure(errno);
    int socket_type;
    socklen_t socket_type_size = sizeof(socket_type);
    if (getsockopt(borrowed.host_fd, SOL_SOCKET, SO_TYPE,
                   &socket_type, &socket_type_size) < 0) {
        int error = errno;
        (void)sparc64_fd_unborrow(&borrowed);
        return host_failure(error);
    }
    bool setting = number == 208;
    uint64_t result;
    int guest_level = (int32_t)(uint32_t)args[1];
    int option = guest_level == 1 ?
                 native_socket_option((uint32_t)args[2], setting) : -1;
    if (setting) {
        uint32_t length = (uint32_t)args[4];
        unsigned char encoded[4];
        if (length > INT32_MAX || length < 4)
            result = failure(22);
        else if (!sparc64_space_read(files->space, args[3], encoded, 4, SPARC64_MEM_READ))
            result = failure(sparc64_fault_is_runtime(files->space->fault_reason) ? 12 : 14);
        else if (option < 0)
            result = failure(92);
        else {
            int value = (int32_t)read32(encoded);
            int called = setsockopt(borrowed.host_fd, SOL_SOCKET, option,
                                    &value, sizeof(value));
            result = called < 0 ? host_failure(errno) : 0;
        }
    } else {
        unsigned char encoded_length[4];
        if (!sparc64_space_read(files->space, args[4], encoded_length, 4,
                           SPARC64_MEM_READ))
            result = failure(sparc64_fault_is_runtime(files->space->fault_reason) ? 12 : 14);
        else if (read32(encoded_length) > INT32_MAX)
            result = failure(22);
        else if (option < 0)
            result = failure(92);
        else {
            int value = 0;
            socklen_t host_length = sizeof(value);
            if (getsockopt(borrowed.host_fd, SOL_SOCKET, option,
                           &value, &host_length) < 0)
                result = host_failure(errno);
            else if (host_length < sizeof(value))
                result = failure(5);
            else {
                if ((uint32_t)args[2] == 2 || (uint32_t)args[2] == 9)
                    value = value != 0;
                if ((uint32_t)args[2] == 4 && value != 0)
                    value = (int)sparc64_linux_errno(value);
                unsigned char encoded[4];
                write32(encoded, (uint32_t)value);
                uint32_t copy = read32(encoded_length);
                if (copy > 4)
                    copy = 4;
                unsigned int guest_error = copy_option_value(files->space,
                                                               args[3], encoded,
                                                               copy);
                write32(encoded_length, copy);
                if (guest_error == 0 &&
                    !sparc64_space_write(files->space, args[4], encoded_length, 4))
                    guest_error = output_error(files->space, args[4], 4);
                result = guest_error == 0 ? 0 : failure(guest_error);
            }
        }
    }
    (void)sparc64_fd_unborrow(&borrowed);
    return result;
}

static int native_message_flags(uint32_t guest, bool receiving, int *native)
{
    uint32_t allowed = receiving ? G_MSG_PEEK | G_MSG_TRUNC | G_MSG_DONTWAIT :
                       G_MSG_DONTWAIT | G_MSG_NOSIGNAL;
    if ((guest & ~allowed) != 0)
        return EOPNOTSUPP;
    *native = 0;
    if ((guest & G_MSG_DONTWAIT) != 0) {
#if defined(MSG_DONTWAIT)
        *native |= MSG_DONTWAIT;
#else
        return EOPNOTSUPP;
#endif
    }
    if (receiving) {
        if ((guest & G_MSG_PEEK) != 0)
            *native |= MSG_PEEK;
        if ((guest & G_MSG_TRUNC) != 0)
            *native |= MSG_TRUNC;
    }
#if defined(MSG_NOSIGNAL)
    else if ((guest & G_MSG_NOSIGNAL) != 0)
        *native |= MSG_NOSIGNAL;
#endif
    return 0;
}

static bool numeric_buffer(sparc64_space_t *space, uint64_t address, uint64_t length)
{
    return address <= space->limit && length <= space->limit - address;
}

static uint64_t send_bytes(sparc64_linux_file_t *files, const uint64_t args[6])
{
    /* import_ubuf checks the clamped numeric range before fd lookup. */
    uint64_t imported = args[2] < UINT64_C(0x7ffff000) ?
                        args[2] : UINT64_C(0x7ffff000);
    if (!numeric_buffer(files->space, args[1], imported))
        return failure(14);
    sparc64_fd_borrow_t borrowed = {0};
    if (sparc64_fd_borrow(&files->descriptors, (uint32_t)args[0], &borrowed) < 0)
        return host_failure(errno);
    int type;
    socklen_t type_size = sizeof(type);
    if (getsockopt(borrowed.host_fd, SOL_SOCKET, SO_TYPE, &type, &type_size) < 0) {
        int error = errno;
        (void)sparc64_fd_unborrow(&borrowed);
        return host_failure(error);
    }
    int flags;
    int error = native_message_flags((uint32_t)args[3], false, &flags);
    if (error != 0) {
        (void)sparc64_fd_unborrow(&borrowed);
        return host_failure(error);
    }
    bool datagram = type == SOCK_DGRAM;
    if (datagram && args[2] > SOCKET_STAGE) {
        (void)sparc64_fd_unborrow(&borrowed);
        return failure(90);
    }
    size_t size = args[2] < SOCKET_STAGE ? (size_t)args[2] : SOCKET_STAGE;
    unsigned char *staged = malloc(size == 0 ? 1 : size);
    if (staged == NULL) {
        (void)sparc64_fd_unborrow(&borrowed);
        return failure(12);
    }
    size_t copied = 0;
    while (copied < size) {
        size_t amount = (size_t)(SPARC64_PAGE_SIZE - (args[1] + copied) % SPARC64_PAGE_SIZE);
        if (amount > size - copied)
            amount = size - copied;
        if (!sparc64_space_read(files->space, args[1] + copied, staged + copied,
                           amount, SPARC64_MEM_READ)) {
            if (sparc64_fault_is_runtime(files->space->fault_reason)) {
                free(staged);
                (void)sparc64_fd_unborrow(&borrowed);
                return failure(12);
            }
            break;
        }
        copied += amount;
    }
    if (copied < size && (datagram || copied == 0)) {
        free(staged);
        (void)sparc64_fd_unborrow(&borrowed);
        return failure(14);
    }
    struct sockaddr_storage destination;
    socklen_t destination_length = 0;
    const struct sockaddr *address = NULL;
    if (args[4] != 0) {
        error = read_address(files->space, args[4], (uint32_t)args[5],
                             &destination, &destination_length);
        if (error != 0) {
            free(staged);
            (void)sparc64_fd_unborrow(&borrowed);
            return host_failure(error);
        }
        address = (const struct sockaddr *)&destination;
    }
    ssize_t sent = sendto(borrowed.host_fd, staged, copied, flags,
                          address, destination_length);
    error = errno;
    free(staged);
    (void)sparc64_fd_unborrow(&borrowed);
    return sent < 0 ? host_failure(error) : (uint64_t)sent;
}

static uint64_t receive_bytes(sparc64_linux_file_t *files, const uint64_t args[6])
{
    uint64_t imported = args[2] < UINT64_C(0x7ffff000) ?
                        args[2] : UINT64_C(0x7ffff000);
    if (!numeric_buffer(files->space, args[1], imported))
        return failure(14);
    sparc64_fd_borrow_t borrowed = {0};
    if (sparc64_fd_borrow(&files->descriptors, (uint32_t)args[0], &borrowed) < 0)
        return host_failure(errno);
    int type;
    socklen_t type_size = sizeof(type);
    if (getsockopt(borrowed.host_fd, SOL_SOCKET, SO_TYPE, &type, &type_size) < 0) {
        int error = errno;
        (void)sparc64_fd_unborrow(&borrowed);
        return host_failure(error);
    }
    int flags;
    int error = native_message_flags((uint32_t)args[3], true, &flags);
    if (error != 0) {
        (void)sparc64_fd_unborrow(&borrowed);
        return host_failure(error);
    }
    size_t size = args[2] < SOCKET_STAGE ? (size_t)args[2] : SOCKET_STAGE;
    bool datagram = type == SOCK_DGRAM;
    if (!datagram && ((uint32_t)args[3] & G_MSG_TRUNC) != 0) {
        (void)sparc64_fd_unborrow(&borrowed);
        return failure(95);
    }
    bool full_datagram = datagram && ((uint32_t)args[3] & G_MSG_TRUNC) != 0;
    if (full_datagram) {
        struct sockaddr_storage identity = {0};
        socklen_t identity_size = sizeof(identity);
        if (getsockname(borrowed.host_fd, (struct sockaddr *)&identity,
                        &identity_size) < 0) {
            error = errno;
            (void)sparc64_fd_unborrow(&borrowed);
            return host_failure(error);
        }
        if (identity.ss_family != AF_INET) {
            (void)sparc64_fd_unborrow(&borrowed);
            return failure(95); /* Bounded full-datagram expansion is IPv4. */
        }
        flags &= ~MSG_TRUNC;
    }
    size_t writable = 0;
    while (writable < size) {
        size_t amount = (size_t)(SPARC64_PAGE_SIZE - (args[1] + writable) % SPARC64_PAGE_SIZE);
        if (amount > size - writable)
            amount = size - writable;
        if (!sparc64_space_prepare_write(files->space, args[1] + writable, amount)) {
            if (sparc64_fault_is_runtime(files->space->fault_reason)) {
                (void)sparc64_fd_unborrow(&borrowed);
                return failure(12);
            }
            break;
        }
        writable += amount;
    }
    if (!datagram && size != 0 && writable == 0) {
        unsigned char peek;
        ssize_t available = recvfrom(borrowed.host_fd, &peek, 1,
                                     flags | MSG_PEEK, NULL, NULL);
        error = errno;
        (void)sparc64_fd_unborrow(&borrowed);
        if (available < 0)
            return host_failure(error);
        if (available != 0)
            return failure(14);
        if (args[4] != 0) {
            struct sockaddr_storage empty = {0};
            error = (int)write_address(files->space, args[4], args[5],
                                       (struct sockaddr *)&empty, 0);
            return error == 0 ? 0 : failure((unsigned int)error);
        }
        return 0;
    }
    bool partial_stream = !datagram && writable < size;
    size_t host_size = full_datagram ? SOCKET_STAGE :
                       (datagram ? size : (partial_stream ? writable + 1 : writable));
    unsigned char *staged = malloc(host_size == 0 ? 1 : host_size);
    if (staged == NULL) {
        (void)sparc64_fd_unborrow(&borrowed);
        return failure(12);
    }
    struct sockaddr_storage source = {0};
    socklen_t source_length = sizeof(source);
    ssize_t received;
    bool guest_copy_fault = false;
    if (partial_stream) {
        /* A stream copy fault leaves the queued bytes in Linux. Peek one
         * byte beyond the writable prefix, then consume only when all bytes
         * observed fit that prefix. R5 must serialize this description. */
        received = recvfrom(borrowed.host_fd, staged, host_size,
                            flags | MSG_PEEK, NULL, NULL);
        if (received > 0 && (size_t)received > writable)
            guest_copy_fault = true;
        else if (received > 0)
            received = recvfrom(borrowed.host_fd, staged, (size_t)received,
                                flags,
                                args[4] != 0 ? (struct sockaddr *)&source : NULL,
                                args[4] != 0 ? &source_length : NULL);
        else if (received == 0)
            source_length = 0;
    } else {
        received = recvfrom(borrowed.host_fd, staged, host_size, flags,
                            args[4] != 0 ? (struct sockaddr *)&source : NULL,
                            args[4] != 0 ? &source_length : NULL);
    }
    error = errno;
    if (received < 0) {
        free(staged);
        (void)sparc64_fd_unborrow(&borrowed);
        return host_failure(error);
    }
    size_t copied = (size_t)received < host_size ? (size_t)received : host_size;
    if (copied > writable)
        copied = writable;
    if (copied != 0 && !sparc64_space_write(files->space, args[1], staged, copied)) {
        free(staged);
        (void)sparc64_fd_unborrow(&borrowed);
        return failure(output_error(files->space, args[1], copied));
    }
    free(staged);
    if (guest_copy_fault) {
        (void)sparc64_fd_unborrow(&borrowed);
        return failure(14);
    }
    if (datagram && (size_t)received > writable && writable < size) {
        (void)sparc64_fd_unborrow(&borrowed);
        return failure(14);
    }
    if (args[4] != 0) {
        if (source_length == sizeof(source) && source.ss_family == 0) {
            /* hl's Darwin recvfrom leaves the supplied length unchanged for
             * an unnamed AF_UNIX peer. Linux reports an empty peer address.
             * Confirm this is a local unnamed Unix endpoint before fixing
             * that host artifact; named and IPv4 results are not rewritten. */
            struct sockaddr_storage local = {0};
            socklen_t local_length = sizeof(local);
            int local_status = getsockname(borrowed.host_fd,
                                           (struct sockaddr *)&local,
                                           &local_length);
            if (local_status == 0 && local.ss_family == AF_UNIX) {
                const unsigned char *bytes = (const unsigned char *)&local;
                bool unnamed = true;
                if (local_length > sizeof(local))
                    unnamed = false;
                for (socklen_t i = 2; unnamed && i < local_length; ++i)
                    if (bytes[i] != 0)
                        unnamed = false;
                if (unnamed)
                    source_length = 0;
            }
        }
        error = (int)write_address(files->space, args[4], args[5],
                                   (struct sockaddr *)&source, source_length);
        if (error != 0) {
            (void)sparc64_fd_unborrow(&borrowed);
            return failure((unsigned int)error);
        }
    }
    (void)sparc64_fd_unborrow(&borrowed);
    return (uint64_t)received;
}

static uint64_t shutdown_socket(sparc64_linux_file_t *files, const uint64_t args[6])
{
    sparc64_fd_borrow_t borrowed = {0};
    if (sparc64_fd_borrow(&files->descriptors, (uint32_t)args[0], &borrowed) < 0)
        return host_failure(errno);
    int result = shutdown(borrowed.host_fd, (int)(uint32_t)args[1]);
    int error = errno;
    (void)sparc64_fd_unborrow(&borrowed);
    return result < 0 ? host_failure(error) : 0;
}

bool sparc64_linux_socket_dispatch(sparc64_linux_file_t *files, uint64_t number,
                              const uint64_t arguments[6], uint64_t *result)
{
    if (files == NULL || arguments == NULL || result == NULL)
        return false;
    switch (number) {
    case 198: *result = make_socket(files, arguments); break;
    case 199: *result = make_pair(files, arguments); break;
    case 200: case 203: case 204: case 205:
        *result = address_operation(files, number, arguments); break;
    case 201: *result = listen_socket(files, arguments); break;
    case 202: case 242:
        *result = accept_socket(files, number, arguments); break;
    case 206: *result = send_bytes(files, arguments); break;
    case 207: *result = receive_bytes(files, arguments); break;
    case 210: *result = shutdown_socket(files, arguments); break;
    case 208: case 209:
        *result = socket_option(files, number, arguments); break;
    case 211: case 212:
        return sparc64_linux_message_dispatch(files, number, arguments, result);
    default: return false;
    }
    return true;
}
