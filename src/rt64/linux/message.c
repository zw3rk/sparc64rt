/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#define _GNU_SOURCE 1
#define _POSIX_C_SOURCE 200809L
#define _DARWIN_C_SOURCE 1
#include "linux/message.h"
#include "linux/error.h"

#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <unistd.h>

#define G_MSG_PEEK UINT32_C(0x2)
#define G_MSG_CTRUNC UINT32_C(0x8)
#define G_MSG_DONTWAIT UINT32_C(0x40)
#define G_MSG_NOSIGNAL UINT32_C(0x4000)
#define G_MSG_CMSG_CLOEXEC UINT32_C(0x40000000)
#define MAX_IOV 1024u
#define MAX_RIGHTS 253u
#define STAGE_SIZE ((size_t)65536)
#define CONTROL_SIZE ((size_t)4096)

typedef struct {
    uint64_t base;
    size_t size;
} guest_iov_t;

typedef struct {
    uint64_t name;
    uint64_t iov_address;
    uint64_t control;
    uint64_t control_size;
    uint64_t header_address;
    uint32_t name_size;
    uint32_t input_flags;
    size_t total;
    size_t count;
    guest_iov_t *iov;
} guest_message_t;

static uint64_t fail(unsigned int error)
{
    return UINT64_C(0) - error;
}

static uint64_t host_fail(int error)
{
    return fail(sparc64_linux_errno(error == 0 ? EIO : error));
}

static uint64_t le64(const unsigned char *p)
{
    uint64_t value = 0;
    for (unsigned int i = 0; i < 8; ++i)
        value |= (uint64_t)p[i] << (i * 8);
    return value;
}

static uint32_t le32(const unsigned char *p)
{
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 |
           (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

static void put64(unsigned char *p, uint64_t value)
{
    for (unsigned int i = 0; i < 8; ++i)
        p[i] = (unsigned char)(value >> (i * 8));
}

static void put32(unsigned char *p, uint32_t value)
{
    for (unsigned int i = 0; i < 4; ++i)
        p[i] = (unsigned char)(value >> (i * 8));
}

static bool numeric(sparc64_space_t *space, uint64_t address, uint64_t size)
{
    return address <= space->limit && size <= space->limit - address;
}

static unsigned int out_error(sparc64_space_t *space, uint64_t address, size_t size)
{
    return sparc64_fault_is_runtime(space->fault_reason) &&
           numeric(space, address, size) ? 12 : 14;
}

static unsigned int load_message(sparc64_space_t *space, uint64_t address,
                                 guest_message_t *message)
{
    unsigned char bytes[56];
    if (!sparc64_space_read(space, address, bytes, sizeof(bytes), SPARC64_MEM_READ))
        return sparc64_fault_is_runtime(space->fault_reason) ? 12 : 14;
    uint64_t count = le64(bytes + 24);
    if (count > MAX_IOV)
        return 90; /* Linux UIO_MAXIOV, not this module's staging limit. */
    *message = (guest_message_t){
        .header_address = address, .name = le64(bytes),
        .name_size = le32(bytes + 8), .iov_address = le64(bytes + 16),
        .count = (size_t)count, .control = le64(bytes + 32),
        .control_size = le64(bytes + 40), .input_flags = le32(bytes + 48)
    };
    if (message->name == 0)
        message->name_size = 0;
    if (message->name_size > INT32_MAX)
        return 22;
    if (message->count == 0)
        return 0;
    if (!numeric(space, message->iov_address, message->count * 16))
        return 14;
    message->iov = calloc(message->count, sizeof(*message->iov));
    if (message->iov == NULL)
        return 12;
    for (size_t i = 0; i < message->count; ++i) {
        unsigned char entry[16];
        if (!sparc64_space_read(space, message->iov_address + i * 16,
                           entry, sizeof(entry), SPARC64_MEM_READ))
            return sparc64_fault_is_runtime(space->fault_reason) ? 12 : 14;
        uint64_t base = le64(entry), length = le64(entry + 8);
        if (length > INT64_MAX)
            return 22;
        if (!numeric(space, base, length))
            return 14;
        if (length > STAGE_SIZE - message->total)
            return 95; /* Valid larger Linux vectors are a later slice. */
        message->iov[i] = (guest_iov_t){.base = base, .size = (size_t)length};
        message->total += (size_t)length;
    }
    return 0;
}

static unsigned int host_flags(uint32_t guest, bool receiving, int *out)
{
    uint32_t allowed = receiving ?
        G_MSG_PEEK | G_MSG_DONTWAIT | G_MSG_CMSG_CLOEXEC :
        G_MSG_DONTWAIT | G_MSG_NOSIGNAL;
    if ((guest & ~allowed) != 0)
        return 95;
    *out = 0;
    if ((guest & G_MSG_PEEK) != 0)
        *out |= MSG_PEEK;
    if ((guest & G_MSG_DONTWAIT) != 0) {
#if defined(MSG_DONTWAIT)
        *out |= MSG_DONTWAIT;
#else
        return 95;
#endif
    }
    if (!receiving && (guest & G_MSG_NOSIGNAL) != 0) {
#if defined(MSG_NOSIGNAL)
        *out |= MSG_NOSIGNAL;
#endif
        /* Darwin sockets in this module have SO_NOSIGPIPE instead. */
    }
    if (receiving && (guest & G_MSG_CMSG_CLOEXEC) != 0) {
#if defined(MSG_CMSG_CLOEXEC)
        *out |= MSG_CMSG_CLOEXEC;
#endif
    }
    return 0;
}

static unsigned int unix_stream(int fd)
{
    int type;
    socklen_t type_size = sizeof(type);
    if (getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &type_size) < 0)
        return sparc64_linux_errno(errno);
    if (type != SOCK_STREAM)
        return 95;
    struct sockaddr_storage local = {0};
    socklen_t local_size = sizeof(local);
    if (getsockname(fd, (struct sockaddr *)&local, &local_size) < 0)
        return sparc64_linux_errno(errno);
    if (local.ss_family != AF_UNIX || local_size > sizeof(local))
        return 95;
    const unsigned char *bytes = (const unsigned char *)&local;
    for (socklen_t i = 2; i < local_size; ++i)
        if (bytes[i] != 0)
            return 95;
    return 0;
}

/* Regular files can carry resolver-only status and directories need a shared
 * virtual cursor under hl. Until the controlled OFD metadata transport lands,
 * this lane passes only socket and pipe descriptions. */
static bool transferable_right(int fd)
{
    struct stat status;
    return fstat(fd, &status) == 0 &&
           (S_ISSOCK(status.st_mode) || S_ISFIFO(status.st_mode));
}

static unsigned int parse_rights(sparc64_linux_file_t *files,
                                 const guest_message_t *guest,
                                 sparc64_fd_borrow_t rights[MAX_RIGHTS],
                                 size_t *right_count)
{
    *right_count = 0;
    if (guest->control_size == 0)
        return 0;
    if (guest->control_size > INT_MAX)
        return 105; /* Linux's sendmsg control allocation: ENOBUFS. */
    if (guest->control_size > CONTROL_SIZE)
        return 95;
    unsigned char control[CONTROL_SIZE];
    if (!sparc64_space_read(files->space, guest->control, control,
                       (size_t)guest->control_size, SPARC64_MEM_READ))
        return sparc64_fault_is_runtime(files->space->fault_reason) ? 12 : 14;
    if (guest->control_size < 16)
        return 22;
    uint64_t record_size = le64(control);
    if (record_size < 16 || record_size > guest->control_size)
        return 22;
    if (le32(control + 8) != 1 || le32(control + 12) != 1)
        return 95;
    size_t count = (size_t)(record_size - 16) / 4;
    if (count > MAX_RIGHTS)
        return 22; /* Linux SCM_MAX_FD is 253. */
    uint64_t aligned = (record_size + 7) & ~UINT64_C(7);
    if (aligned < guest->control_size && guest->control_size - aligned >= 16)
        return 95; /* Additional control records are a later slice. */
    for (size_t i = 0; i < count; ++i) {
        unsigned int fd = le32(control + 16 + i * 4);
        if (sparc64_fd_borrow(&files->descriptors, fd, &rights[i]) < 0)
            return sparc64_linux_errno(errno);
        *right_count = i + 1;
        if (rights[i].hidden_status_flags != 0 ||
            !transferable_right(rights[i].host_fd))
            return 95;
    }
    return 0;
}

static void release_borrows(sparc64_fd_borrow_t *rights, size_t count)
{
    for (size_t i = 0; i < count; ++i)
        (void)sparc64_fd_unborrow(&rights[i]);
}

static size_t gather(sparc64_space_t *space, const guest_message_t *guest,
                     unsigned char *staged)
{
    size_t copied = 0;
    for (size_t i = 0; i < guest->count; ++i) {
        size_t offset = 0;
        while (offset < guest->iov[i].size) {
            uint64_t at = guest->iov[i].base + offset;
            size_t amount = SPARC64_PAGE_SIZE - (size_t)(at % SPARC64_PAGE_SIZE);
            if (amount > guest->iov[i].size - offset)
                amount = guest->iov[i].size - offset;
            if (!sparc64_space_read(space, at, staged + copied, amount, SPARC64_MEM_READ))
                return copied;
            offset += amount;
            copied += amount;
        }
    }
    return copied;
}

static uint64_t send_message(sparc64_linux_file_t *files, int fd,
                             const guest_message_t *guest, int flags)
{
    sparc64_fd_borrow_t *rights = calloc(MAX_RIGHTS, sizeof(*rights));
    if (rights == NULL)
        return fail(12);
    size_t right_count = 0;
    unsigned int guest_error = parse_rights(files, guest, rights, &right_count);
    if (guest_error != 0) {
        release_borrows(rights, right_count);
        free(rights);
        return fail(guest_error);
    }
    unsigned char *staged = malloc(guest->total == 0 ? 1 : guest->total);
    if (staged == NULL) {
        release_borrows(rights, right_count);
        free(rights);
        return fail(12);
    }
    size_t copied = gather(files->space, guest, staged);
    if (copied < guest->total) {
        free(staged);
        release_borrows(rights, right_count);
        free(rights);
        return fail(sparc64_fault_is_runtime(files->space->fault_reason) ? 12 : 14);
    }
    _Alignas(struct cmsghdr) unsigned char native_control[2048] = {0};
    struct msghdr native = {0};
    struct iovec payload = {.iov_base = staged, .iov_len = copied};
    native.msg_iov = &payload;
    native.msg_iovlen = 1;
    if (right_count != 0) {
        native.msg_control = native_control;
        native.msg_controllen = CMSG_SPACE(right_count * sizeof(int));
        struct cmsghdr *header = CMSG_FIRSTHDR(&native);
        header->cmsg_level = SOL_SOCKET;
        header->cmsg_type = SCM_RIGHTS;
        header->cmsg_len = CMSG_LEN(right_count * sizeof(int));
        int *descriptors = (int *)CMSG_DATA(header);
        for (size_t i = 0; i < right_count; ++i)
            descriptors[i] = rights[i].host_fd;
    }
    ssize_t sent = sendmsg(fd, &native, flags);
    int saved = errno;
    free(staged);
    release_borrows(rights, right_count);
    free(rights);
    return sent < 0 ? host_fail(saved) : (uint64_t)sent;
}

static size_t writable_prefix(sparc64_space_t *space, const guest_message_t *guest,
                              bool *resource_error)
{
    size_t total = 0;
    *resource_error = false;
    for (size_t i = 0; i < guest->count; ++i) {
        size_t offset = 0;
        while (offset < guest->iov[i].size) {
            uint64_t at = guest->iov[i].base + offset;
            size_t amount = SPARC64_PAGE_SIZE - (size_t)(at % SPARC64_PAGE_SIZE);
            if (amount > guest->iov[i].size - offset)
                amount = guest->iov[i].size - offset;
            if (!sparc64_space_prepare_write(space, at, amount)) {
                *resource_error = sparc64_fault_is_runtime(space->fault_reason);
                return total;
            }
            offset += amount;
            total += amount;
        }
    }
    return total;
}

static unsigned int scatter(sparc64_space_t *space, const guest_message_t *guest,
                            const unsigned char *staged, size_t size)
{
    size_t copied = 0;
    for (size_t i = 0; i < guest->count && copied < size; ++i) {
        size_t amount = guest->iov[i].size;
        if (amount > size - copied)
            amount = size - copied;
        if (amount != 0 &&
            !sparc64_space_write(space, guest->iov[i].base, staged + copied, amount))
            return out_error(space, guest->iov[i].base, amount);
        copied += amount;
    }
    return 0;
}

static size_t collect_rights(struct msghdr *native, size_t control_capacity,
                             int rights[MAX_RIGHTS], bool *truncated,
                             bool *unsupported)
{
    size_t count = 0;
    size_t returned = native->msg_controllen;
    if (returned > control_capacity) {
        returned = control_capacity;
        *unsupported = true;
    }
    unsigned char *control = native->msg_control;
    size_t offset = 0;
    while (offset <= returned && returned - offset >= sizeof(struct cmsghdr)) {
        struct cmsghdr *header = (struct cmsghdr *)(void *)(control + offset);
        if (header->cmsg_len < CMSG_LEN(0)) {
            *unsupported = true;
            break;
        }
        size_t available = returned - offset;
        size_t header_bytes = CMSG_LEN(0);
        size_t declared = header->cmsg_len;
        size_t contained = declared < available ? declared : available;
        size_t bytes = contained - header_bytes;
        if (declared > available)
            *unsupported = true;
        if (header->cmsg_level != SOL_SOCKET || header->cmsg_type != SCM_RIGHTS) {
            *unsupported = true;
        } else {
            if (bytes % sizeof(int) != 0 && declared <= available)
                *unsupported = true;
            const unsigned char *given = CMSG_DATA(header);
            for (size_t i = 0; i < bytes / sizeof(int); ++i) {
                int owned;
                memcpy(&owned, given + i * sizeof(int), sizeof(owned));
                if (!transferable_right(owned))
                    *unsupported = true;
                if (count < MAX_RIGHTS)
                    rights[count++] = owned;
                else {
                    (void)close(owned);
                    *truncated = true;
                }
            }
        }
        if (declared > available)
            break;
        size_t step = CMSG_SPACE(declared - header_bytes);
        if (step == 0 || step > available)
            break;
        offset += step;
    }
    return count;
}

static void close_rights(int rights[MAX_RIGHTS], size_t count)
{
    for (size_t i = 0; i < count; ++i)
        if (rights[i] >= 0)
            (void)close(rights[i]);
}

static unsigned int copy_control(sparc64_linux_file_t *files,
                                 const guest_message_t *guest,
                                 int rights[MAX_RIGHTS], size_t count,
                                 bool cloexec, bool *truncated,
                                 uint64_t *used)
{
    *used = 0;
    if (count == 0)
        return 0;
    size_t capacity = 0;
    if (guest->control_size > 16 && guest->control != 0)
        capacity = (size_t)((guest->control_size - 16) / 4);
    if (capacity > count)
        capacity = count;
    size_t installed = 0;
    for (; installed < capacity; ++installed) {
        int guest_fd = sparc64_fd_reserve(&files->descriptors);
        if (guest_fd < 0) {
            *truncated = true;
            break;
        }
        unsigned char encoded[4];
        put32(encoded, (uint32_t)guest_fd);
        uint64_t delta = 16 + installed * 4;
        if (guest->control > UINT64_MAX - delta ||
            !numeric(files->space, guest->control + delta, 4) ||
            !sparc64_space_write(files->space, guest->control + delta,
                             encoded, 4)) {
            (void)sparc64_fd_cancel(&files->descriptors, (unsigned int)guest_fd);
            *truncated = true;
            break;
        }
        int owned = rights[installed];
        rights[installed] = -1;
        if (sparc64_fd_commit(&files->descriptors, (unsigned int)guest_fd, owned,
                         cloexec, 0) < 0)
            return sparc64_linux_errno(errno);
    }
    if (installed < count)
        *truncated = true;
    if (installed != 0) {
        unsigned char header[16];
        put64(header, 16 + installed * 4);
        put32(header + 8, 1);
        put32(header + 12, 1);
        /* Linux installs the descriptors before writing this header. A
         * header fault leaves installed guest descriptors live but reports
         * no control bytes to the caller. */
        bool header_ok = guest->control <= UINT64_MAX - 16 &&
            sparc64_space_write(files->space, guest->control + 8,
                           header + 8, 4) &&
            sparc64_space_write(files->space, guest->control + 12,
                           header + 12, 4) &&
            sparc64_space_write(files->space, guest->control, header, 8);
        if (header_ok) {
            uint64_t padded = (16 + installed * 4 + 7) & ~UINT64_C(7);
            *used = padded < guest->control_size ? padded : guest->control_size;
        }
    }
    return 0;
}

static unsigned int update_header(sparc64_space_t *space,
                                  const guest_message_t *guest,
                                  uint32_t flags, uint64_t control_used)
{
    unsigned char encoded[8];
    if (guest->name != 0) {
        if (!sparc64_space_read(space, guest->header_address + 8, encoded, 4,
                           SPARC64_MEM_READ))
            return sparc64_fault_is_runtime(space->fault_reason) ? 12 : 14;
        if (le32(encoded) > INT32_MAX)
            return 22;
        put32(encoded, 0);
        if (!sparc64_space_write(space, guest->header_address + 8, encoded, 4))
            return out_error(space, guest->header_address + 8, 4);
    }
    put32(encoded, flags);
    if (!sparc64_space_write(space, guest->header_address + 48, encoded, 4))
        return out_error(space, guest->header_address + 48, 4);
    put64(encoded, control_used);
    if (!sparc64_space_write(space, guest->header_address + 40, encoded, 8))
        return out_error(space, guest->header_address + 40, 8);
    return 0;
}

static uint64_t recv_message(sparc64_linux_file_t *files, int fd,
                             const guest_message_t *guest, int flags,
                             bool close_on_exec)
{
    bool resource_error;
    size_t writable = writable_prefix(files->space, guest, &resource_error);
    if (resource_error)
        return fail(12);
    bool partial = writable < guest->total;
    size_t requested = partial ? writable + 1 : writable;
    unsigned char *staged = malloc(requested == 0 ? 1 : requested);
    if (staged == NULL)
        return fail(12);
    int rights[MAX_RIGHTS];
    for (size_t i = 0; i < MAX_RIGHTS; ++i)
        rights[i] = -1;
    _Alignas(struct cmsghdr) unsigned char control[2048] = {0};
    struct iovec payload = {.iov_base = staged, .iov_len = requested};
    struct msghdr native = {0};
    native.msg_iov = &payload;
    native.msg_iovlen = 1;
    native.msg_control = control;
    native.msg_controllen = sizeof(control);
    /* A partial guest fault needs a non-consuming availability probe. R5
     * must serialize this peek and the subsequent consume per description. */
    int call_flags = flags | (partial ? MSG_PEEK : 0);
    ssize_t got = recvmsg(fd, &native, call_flags);
    int saved = errno;
    bool truncated = (native.msg_flags & MSG_CTRUNC) != 0;
    bool unsupported = false;
    size_t count = got >= 0 ? collect_rights(&native, sizeof(control),
                                              rights, &truncated,
                                              &unsupported) : 0;
    if (got < 0) {
        close_rights(rights, count);
        free(staged);
        return host_fail(saved);
    }
    if (partial && got > 0 && (size_t)got > writable) {
        unsigned int copy_error = scatter(files->space, guest, staged, writable);
        close_rights(rights, count);
        free(staged);
        return fail(copy_error == 0 ? 14 : copy_error);
    }
    if (partial && (flags & MSG_PEEK) == 0 && got > 0) {
        close_rights(rights, count);
        for (size_t i = 0; i < MAX_RIGHTS; ++i)
            rights[i] = -1;
        native.msg_controllen = sizeof(control);
        native.msg_flags = 0;
        payload.iov_len = (size_t)got;
        got = recvmsg(fd, &native, flags);
        saved = errno;
        truncated = (native.msg_flags & MSG_CTRUNC) != 0;
        unsupported = false;
        count = got >= 0 ? collect_rights(&native, sizeof(control),
                                           rights, &truncated,
                                           &unsupported) : 0;
        if (got < 0) {
            close_rights(rights, count);
            free(staged);
            return host_fail(saved);
        }
    }
    size_t copied = got < 0 ? 0 : (size_t)got;
    if (copied > writable)
        copied = writable;
    unsigned int guest_error = scatter(files->space, guest, staged, copied);
    free(staged);
    if (guest_error != 0 || unsupported) {
        close_rights(rights, count);
        return fail(guest_error != 0 ? guest_error : 95);
    }
    uint64_t used = 0;
    guest_error = copy_control(files, guest, rights, count,
                               close_on_exec,
                               &truncated, &used);
    close_rights(rights, count);
    if (guest_error != 0)
        return fail(guest_error);
    uint32_t output_flags = close_on_exec ?
                            G_MSG_CMSG_CLOEXEC : 0;
    if (truncated)
        output_flags |= G_MSG_CTRUNC;
    guest_error = update_header(files->space, guest, output_flags, used);
    return guest_error == 0 ? (uint64_t)got : fail(guest_error);
}

bool sparc64_linux_message_dispatch(sparc64_linux_file_t *files, uint64_t number,
                               const uint64_t arguments[6], uint64_t *result)
{
    if (files == NULL || arguments == NULL || result == NULL ||
        (number != 211 && number != 212))
        return false;
    sparc64_fd_borrow_t socket = {0};
    if (sparc64_fd_borrow(&files->descriptors, (uint32_t)arguments[0], &socket) < 0) {
        *result = host_fail(errno);
        return true;
    }
    unsigned int guest_error = unix_stream(socket.host_fd);
    guest_message_t guest = {0};
    int flags = 0;
    if (guest_error == 0)
        guest_error = host_flags((uint32_t)arguments[2], number == 212,
                                 &flags);
    if (guest_error == 0)
        guest_error = load_message(files->space, arguments[1], &guest);
    if (guest_error == 0 && number == 211 && guest.name != 0)
        guest_error = 95; /* Named Unix sendmsg is a separate slice. */
    if (guest_error == 0)
        *result = number == 211 ?
            send_message(files, socket.host_fd, &guest, flags) :
            recv_message(files, socket.host_fd, &guest, flags,
                         ((uint32_t)arguments[2] & G_MSG_CMSG_CLOEXEC) != 0);
    else
        *result = fail(guest_error);
    free(guest.iov);
    (void)sparc64_fd_unborrow(&socket);
    return true;
}
