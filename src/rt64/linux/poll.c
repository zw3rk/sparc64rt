/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#define _POSIX_C_SOURCE 200809L
#define _GNU_SOURCE
#include "linux/poll.h"
#include "linux/error.h"
#include "runtime/owned_io.h"

#include <errno.h>
#include <limits.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

typedef struct { uint64_t seconds; uint32_t nanoseconds; } interval_t;

static uint64_t failure(unsigned int error) { return UINT64_C(0) - error; }

static uint64_t load(const unsigned char *bytes, unsigned int size)
{
    uint64_t value = 0;
    for (unsigned int i = 0; i < size; ++i)
        value |= (uint64_t)bytes[i] << (i * 8);
    return value;
}

static void store(unsigned char *bytes, uint64_t value, unsigned int size)
{
    for (unsigned int i = 0; i < size; ++i)
        bytes[i] = (unsigned char)(value >> (i * 8));
}

static short native_events(uint16_t guest)
{
    /* Linux reports these regardless of requested bits. Darwin poll needs
     * them explicitly to observe a hangup on an events==0 descriptor; hl's
     * ordinary Linux poll route preserves that native request. */
    short events = POLLERR | POLLHUP;
    if ((guest & 1) != 0) events |= POLLIN;
    if ((guest & 2) != 0) events |= POLLPRI;
    if ((guest & 4) != 0) events |= POLLOUT;
    if ((guest & 0x40) != 0) events |= POLLRDNORM;
    if ((guest & 0x80) != 0) events |= POLLRDBAND;
    if ((guest & 0x100) != 0) events |= POLLWRNORM;
    if ((guest & 0x200) != 0) events |= POLLWRBAND;
#ifdef POLLRDHUP
    if ((guest & 0x2000) != 0) events |= POLLRDHUP;
#endif
    return events;
}

static uint16_t guest_events(short native, uint16_t requested)
{
    uint16_t result = 0;
    if ((native & POLLIN) != 0 && (requested & 1) != 0) result |= 1;
    if ((native & POLLPRI) != 0 && (requested & 2) != 0) result |= 2;
    if ((native & POLLOUT) != 0 && (requested & 4) != 0) result |= 4;
    if ((native & POLLERR) != 0) result |= 8;
    if ((native & POLLHUP) != 0) result |= 0x10;
    if ((native & POLLNVAL) != 0) result |= 0x20;
    if ((native & POLLRDNORM) != 0 && (requested & 0x40) != 0) result |= 0x40;
    if ((native & POLLRDBAND) != 0 && (requested & 0x80) != 0) result |= 0x80;
    if ((native & POLLWRNORM) != 0 && (requested & 0x100) != 0) result |= 0x100;
    if ((native & POLLWRBAND) != 0 && (requested & 0x200) != 0) result |= 0x200;
#ifdef POLLRDHUP
    if ((native & POLLRDHUP) != 0 && (requested & 0x2000) != 0) result |= 0x2000;
#endif
    return result;
}

static bool monotonic(interval_t *value)
{
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) < 0)
        return false;
    if (now.tv_sec < 0 || now.tv_nsec < 0 || now.tv_nsec >= 1000000000L) {
        errno = EIO;
        return false;
    }
    *value = (interval_t){(uint64_t)now.tv_sec, (uint32_t)now.tv_nsec};
    return true;
}

static bool remaining(interval_t initial, interval_t start, interval_t *value)
{
    interval_t now;
    if (!monotonic(&now))
        return false;
    if (now.seconds < start.seconds ||
        (now.seconds == start.seconds && now.nanoseconds < start.nanoseconds)) {
        errno = EIO;
        return false;
    }
    uint64_t seconds = now.seconds - start.seconds;
    uint32_t nanoseconds;
    if (now.nanoseconds < start.nanoseconds) {
        --seconds;
        nanoseconds = UINT32_C(1000000000) - start.nanoseconds + now.nanoseconds;
    } else
        nanoseconds = now.nanoseconds - start.nanoseconds;
    if (seconds > initial.seconds ||
        (seconds == initial.seconds && nanoseconds >= initial.nanoseconds)) {
        *value = (interval_t){0};
        return true;
    }
    value->seconds = initial.seconds - seconds;
    if (initial.nanoseconds < nanoseconds) {
        --value->seconds;
        value->nanoseconds = UINT32_C(1000000000) - nanoseconds + initial.nanoseconds;
    } else
        value->nanoseconds = initial.nanoseconds - nanoseconds;
    return true;
}

static int milliseconds(interval_t value)
{
    if (value.seconds > (uint64_t)INT_MAX / 1000)
        return INT_MAX;
    uint64_t amount = value.seconds * 1000 +
                      (value.nanoseconds + UINT64_C(999999)) / UINT64_C(1000000);
    return amount > INT_MAX ? INT_MAX : (int)amount;
}

/* Linux's ppoll timeout update is best-effort: a read-only timeout does not
 * turn an otherwise successful poll into EFAULT. Its small RISC-V usercopy
 * can leave a page prefix. Zero timeouts are never rewritten. */
static void finish_timeout(sparc64_space_t *space, uint64_t address,
                            interval_t initial, interval_t start)
{
    if (address == 0 || (initial.seconds == 0 && initial.nanoseconds == 0))
        return;
    interval_t rest;
    if (!remaining(initial, start, &rest) || address > space->limit ||
        UINT64_C(16) > space->limit - address)
        return;
    unsigned char bytes[16];
    store(bytes, rest.seconds, 8);
    store(bytes + 8, rest.nanoseconds, 8);
    size_t prefix = 0;
    while (prefix < sizeof(bytes)) {
        size_t amount = (size_t)(SPARC64_PAGE_SIZE - (address + prefix) % SPARC64_PAGE_SIZE);
        if (amount > sizeof(bytes) - prefix)
            amount = sizeof(bytes) - prefix;
        if (!sparc64_space_prepare_write(space, address + prefix, amount))
            break;
        prefix += amount;
    }
    if (prefix != 0)
        (void)sparc64_space_write(space, address, bytes, prefix);
}

static bool poll_terminal(const sparc64_linux_file_io_t *io)
{
    int saved_errno = errno;
    bool terminal = io->poll_cancelled != NULL &&
                    io->poll_cancelled(io->poll_context);
    errno = saved_errno;
    return terminal;
}

static uint64_t poll_files(sparc64_linux_file_t *files, const sparc64_linux_file_io_t *io,
                            const uint64_t args[6])
{
    sparc64_space_t *space = files->space;
    if (space->limit == (UINT64_C(1) << 32))
        return failure(38); /* The later RV32 profile defines its time ABI. */
    interval_t duration = {0}, start = {0};
    bool finite = args[2] != 0;
    if (finite) {
        unsigned char encoded[16];
        if (!sparc64_space_read(space, args[2], encoded, sizeof(encoded), SPARC64_MEM_READ))
            return failure(sparc64_fault_is_runtime(space->fault_reason) ? 12 : 14);
        duration.seconds = load(encoded, 8);
        uint64_t ns = load(encoded + 8, 8);
        if (duration.seconds > INT64_MAX || ns >= UINT64_C(1000000000))
            return failure(22);
        duration.nanoseconds = (uint32_t)ns;
        if (!monotonic(&start))
            return failure(sparc64_linux_errno(errno));
    }
    uint64_t temporary_mask = 0;
    if (args[3] != 0) {
        if (args[4] != 8)
            return failure(22);
        unsigned char encoded[8];
        if (!sparc64_space_read(space, args[3], encoded, sizeof(encoded), SPARC64_MEM_READ))
            return failure(sparc64_fault_is_runtime(space->fault_reason) ? 12 : 14);
        temporary_mask = load(encoded, 8);
    }
    uint32_t count = (uint32_t)args[1]; /* Kernel formal is unsigned int. */
    uint64_t result = failure(22);
    bool mask_installed = false;
    bool cancelled = false;
    unsigned char *wire = NULL;
    struct pollfd *native = NULL;
    sparc64_owned_io_flight_t *owned = NULL;
    if (args[3] != 0) {
        if (io->wait_mask_begin == NULL || io->wait_mask_finish == NULL) {
            result = failure(38);
            goto done;
        }
        if (!io->wait_mask_begin(temporary_mask, io->wait_mask_context)) {
            result = failure(sparc64_linux_errno(errno));
            goto done;
        }
        mask_installed = true;
    }
    if (count > SPARC64_FD_TABLE_LIMIT)
        goto done;
    size_t bytes = (size_t)count * 8;
    if (count != 0) {
        wire = malloc(bytes);
        native = calloc(count, sizeof(*native));
        if (wire == NULL || native == NULL) {
            result = failure(12);
            free(native);
            native = NULL;
            goto done;
        }
        for (uint32_t i = 0; i < count; ++i)
            native[i].fd = -1;
        if (!sparc64_space_read(space, args[0], wire, bytes, SPARC64_MEM_READ)) {
            result = failure(sparc64_fault_is_runtime(space->fault_reason) ? 12 : 14);
            goto done;
        }
    }
    bool invalid = false;
    for (uint32_t i = 0; i < count; ++i) {
        unsigned char *record = wire + (size_t)i * 8;
        uint32_t fd = (uint32_t)load(record, 4);
        native[i].events = native_events((uint16_t)load(record + 4, 2));
        store(record + 6, 0, 2);
        if (fd > INT_MAX)
            continue;
        int lease = sparc64_fd_acquire(&files->descriptors, fd);
        if (lease < 0) {
            if (errno != EBADF) {
                result = failure(sparc64_linux_errno(errno));
                goto done;
            }
            store(record + 6, 0x20, 2);
            invalid = true;
        } else
            native[i].fd = lease;
    }
    if (io->owned_io != NULL &&
        sparc64_owned_io_begin_poll(io->owned_io, native, count, wire, &owned) != 0) {
        result = failure(sparc64_linux_errno(errno));
        goto done;
    }
    int waited;
    for (;;) {
        interval_t rest = {0};
        if (finite && !remaining(duration, start, &rest)) {
            result = failure(sparc64_linux_errno(errno));
            goto done;
        }
        int timeout = invalid ? 0 : finite ? milliseconds(rest) : -1;
        waited = io->poll != NULL ?
                 io->poll(native, (nfds_t)count, timeout, io->poll_context) :
                 poll(native, (nfds_t)count, timeout);
        if (poll_terminal(io)) {
            cancelled = true;
            result = 0;
            goto done;
        }
        if (waited != 0 || invalid || !finite)
            break;
        if (!remaining(duration, start, &rest)) {
            result = failure(sparc64_linux_errno(errno));
            goto done;
        }
        if (rest.seconds == 0 && rest.nanoseconds == 0)
            break;
        /* Preserve long deadlines if the host clamps a single poll timeout. */
    }
    result = waited < 0 ? failure(sparc64_linux_errno(errno)) : 0;
    /* do_sys_poll checks the numeric output domain after waiting even when
     * nfds is zero, then writes only revents, leaving fd/events untouched. */
    if (args[0] > space->limit || bytes > space->limit - args[0]) {
        result = failure(14);
        goto done;
    }
    uint32_t ready = 0;
    for (uint32_t i = 0; i < count; ++i) {
        unsigned char *record = wire + (size_t)i * 8;
        uint16_t events = (uint16_t)load(record + 6, 2);
        events |= guest_events(native[i].revents, (uint16_t)load(record + 4, 2));
        if (events != 0)
            ++ready;
        store(record + 6, events, 2);
        if (!sparc64_space_write(space, args[0] + (uint64_t)i * 8 + 6, record + 6, 2)) {
            result = failure(sparc64_fault_is_runtime(space->fault_reason) ? 12 : 14);
            goto done;
        }
    }
    /* POLLNVAL is ready even if an interrupt arrives in the host scan. */
    if (waited >= 0 || (ready != 0 && result == failure(4)))
        result = ready;
    if (ready == 0 && (waited >= 0 || result == failure(4)) &&
        io->poll_guest_interrupt != NULL &&
        io->poll_guest_interrupt(io->wait_mask_context))
        result = failure(4);
done:
    if (owned != NULL) {
        int saved_errno = errno;
        sparc64_owned_io_finish(&owned);
        errno = saved_errno;
        native = NULL;
        wire = NULL;
    }
    if (native != NULL)
        for (uint32_t i = 0; i < count; ++i)
            if (native[i].fd >= 0)
                (void)sparc64_fd_release(native[i].fd);
    free(native);
    free(wire);
    if (!cancelled && mask_installed && !io->wait_mask_finish(
            result == failure(4) && io->poll_guest_interrupt != NULL &&
            io->poll_guest_interrupt(io->wait_mask_context),
            io->wait_mask_context))
        result = failure(sparc64_linux_errno(errno));
    if (!cancelled && finite)
        finish_timeout(space, args[2], duration, start);
    return result;
}

static bool fd_bit(const unsigned char *bits, uint32_t fd)
{
    return bits != NULL && (bits[fd / 8] & (unsigned char)(1u << (fd % 8))) != 0;
}

static void set_fd_bit(unsigned char *bits, uint32_t fd)
{
    bits[fd / 8] |= (unsigned char)(1u << (fd % 8));
}

/* Linux copy_to_user may publish an accessible prefix before a later page
 * faults. Keep each select set's ordered output visible at that boundary. */
static bool write_fd_set(sparc64_space_t *space, uint64_t address,
                         const unsigned char *bits, size_t bytes)
{
    for (size_t offset = 0; offset < bytes;) {
        size_t amount = (size_t)(SPARC64_PAGE_SIZE -
                                 (address + offset) % SPARC64_PAGE_SIZE);
        if (amount > bytes - offset)
            amount = bytes - offset;
        if (!sparc64_space_write(space, address + offset, bits + offset, amount))
            return false;
        offset += amount;
    }
    return true;
}

/* Linux select counts ready bits, so one descriptor present in both read and
 * write sets can contribute two to the result. POLLHUP is counted for the
 * read set only. POLLERR is counted for the read and write sets. The
 * exceptional set observes priority data or POLLNVAL. */
static unsigned int select_ready_bits(short events, bool read_set,
                                      bool write_set, bool except_set,
                                      unsigned char *read_out,
                                      unsigned char *write_out,
                                      unsigned char *except_out, uint32_t fd)
{
    unsigned int ready = 0;
    if (read_set && (events & (POLLIN | POLLRDNORM | POLLRDBAND |
                               POLLHUP | POLLERR | POLLNVAL)) != 0) {
        set_fd_bit(read_out, fd);
        ++ready;
    }
    if (write_set && (events & (POLLOUT | POLLWRNORM | POLLWRBAND |
                                POLLERR | POLLNVAL)) != 0) {
        set_fd_bit(write_out, fd);
        ++ready;
    }
    if (except_set && (events & (POLLPRI | POLLNVAL)) != 0) {
        set_fd_bit(except_out, fd);
        ++ready;
    }
    return ready;
}

static uint64_t select_files(sparc64_linux_file_t *files,
                             const sparc64_linux_file_io_t *io,
                             const uint64_t args[6])
{
    sparc64_space_t *space = files->space;
    if (space->limit == (UINT64_C(1) << 32))
        return failure(38); /* RV32 has a separate time/argument ABI. */
    uint64_t mask_address = 0, mask_size = 0;
    if (args[5] != 0) {
        unsigned char pack[16];
        if (!sparc64_space_read(space, args[5], pack, sizeof(pack), SPARC64_MEM_READ))
            return failure(sparc64_fault_is_runtime(space->fault_reason) ? 12 : 14);
        mask_address = load(pack, 8);
        mask_size = load(pack + 8, 8);
    }
    interval_t duration = {0}, start = {0};
    bool finite = args[4] != 0;
    if (finite) {
        unsigned char encoded[16];
        if (!sparc64_space_read(space, args[4], encoded, sizeof(encoded), SPARC64_MEM_READ))
            return failure(sparc64_fault_is_runtime(space->fault_reason) ? 12 : 14);
        duration.seconds = load(encoded, 8);
        uint64_t ns = load(encoded + 8, 8);
        if (duration.seconds > INT64_MAX || ns >= UINT64_C(1000000000))
            return failure(22);
        duration.nanoseconds = (uint32_t)ns;
        if (!monotonic(&start))
            return failure(sparc64_linux_errno(errno));
    }
    uint64_t temporary_mask = 0;
    if (mask_address != 0) {
        if (mask_size != 8)
            return failure(22);
        unsigned char encoded[8];
        if (!sparc64_space_read(space, mask_address, encoded, sizeof(encoded),
                           SPARC64_MEM_READ))
            return failure(sparc64_fault_is_runtime(space->fault_reason) ? 12 : 14);
        temporary_mask = load(encoded, 8);
    }
    uint64_t result = failure(22);
    bool mask_installed = false;
    bool cancelled = false;
    unsigned char *bits = NULL;
    struct pollfd *native = NULL;
    sparc64_owned_io_flight_t *owned = NULL;
    uint32_t count = 0;
    size_t bytes = 0;
    if (mask_address != 0) {
        if (io->wait_mask_begin == NULL || io->wait_mask_finish == NULL) {
            result = failure(38);
            goto done;
        }
        if (!io->wait_mask_begin(temporary_mask, io->wait_mask_context)) {
            result = failure(sparc64_linux_errno(errno));
            goto done;
        }
        mask_installed = true;
    }
    int32_t requested = (int32_t)(uint32_t)args[0];
    if (requested < 0)
        goto done;
    count = (uint32_t)requested;
    if (count > SPARC64_FD_TABLE_LIMIT)
        count = SPARC64_FD_TABLE_LIMIT;
    bytes = ((size_t)count + 63u) / 64u * 8u;
    if (bytes != 0) {
        bits = calloc(6, bytes);
        native = calloc(count, sizeof(*native));
        if (native != NULL)
            for (uint32_t i = 0; i < count; ++i)
                native[i].fd = -1;
        if (bits == NULL || native == NULL) {
            result = failure(12);
            goto done;
        }
    }
    for (unsigned int set = 0; set < 3; ++set) {
        if (args[set + 1] == 0 || bytes == 0)
            continue;
        if (!sparc64_space_read(space, args[set + 1], bits + set * bytes,
                           bytes, SPARC64_MEM_READ)) {
            result = failure(sparc64_fault_is_runtime(space->fault_reason) ? 12 : 14);
            goto done;
        }
    }
    for (uint32_t fd = 0; fd < count; ++fd) {
        bool read_set = fd_bit(args[1] != 0 ? bits : NULL, fd);
        bool write_set = fd_bit(args[2] != 0 ? bits + bytes : NULL, fd);
        bool except_set = fd_bit(args[3] != 0 ? bits + 2 * bytes : NULL, fd);
        if (!read_set && !write_set && !except_set)
            continue;
        int lease = sparc64_fd_acquire(&files->descriptors, fd);
        if (lease < 0) {
            result = failure(sparc64_linux_errno(errno));
            goto done;
        }
        native[fd].fd = lease;
        if (read_set)
            native[fd].events |= POLLIN | POLLRDNORM | POLLRDBAND;
        if (write_set)
            native[fd].events |= POLLOUT | POLLWRNORM | POLLWRBAND;
        if (except_set)
            native[fd].events |= POLLPRI;
        native[fd].events |= POLLERR | POLLHUP;
    }
    if (io->owned_io != NULL &&
        sparc64_owned_io_begin_poll(io->owned_io, native, count, bits, &owned) != 0) {
        result = failure(sparc64_linux_errno(errno));
        goto done;
    }
    int waited;
    unsigned int ready;
    bool interrupted_pause = false;
    for (;;) {
        for (;;) {
            interval_t rest = {0};
            if (finite && !interrupted_pause &&
                !remaining(duration, start, &rest)) {
                result = failure(sparc64_linux_errno(errno));
                goto done;
            }
            int timeout = interrupted_pause ? 0 :
                          finite ? milliseconds(rest) : -1;
            waited = io->poll != NULL ?
                     io->poll(native, (nfds_t)count, timeout, io->poll_context) :
                     poll(native, (nfds_t)count, timeout);
            if (poll_terminal(io)) {
                cancelled = true;
                result = 0;
                goto done;
            }
            if (waited != 0 || !finite || interrupted_pause)
                break;
            if (!remaining(duration, start, &rest)) {
                result = failure(sparc64_linux_errno(errno));
                goto done;
            }
            if (rest.seconds == 0 && rest.nanoseconds == 0)
                break;
        }
        if (waited < 0) {
            result = failure(sparc64_linux_errno(errno));
            goto done;
        }
        if (bytes != 0)
            memset(bits + 3 * bytes, 0, 3 * bytes);
        ready = 0;
        for (uint32_t fd = 0; fd < count; ++fd) {
            if (native[fd].fd < 0)
                continue;
            ready += select_ready_bits(native[fd].revents,
                                       args[1] != 0 && fd_bit(bits, fd),
                                       args[2] != 0 && fd_bit(bits + bytes, fd),
                                       args[3] != 0 && fd_bit(bits + 2 * bytes, fd),
                                       bits + 3 * bytes, bits + 4 * bytes,
                                       bits + 5 * bytes, fd);
        }
        if (ready != 0)
            break;
        if (io->poll_guest_interrupt != NULL &&
            io->poll_guest_interrupt(io->wait_mask_context)) {
            result = failure(4);
            goto done;
        }
        if (interrupted_pause) {
            result = failure(4);
            goto done;
        }
        if (waited == 0)
            break;
        /* poll reports HUP/ERR even when an exceptional-only select set
         * does not accept those bits. Wait briefly without those level
         * events, then resample the retained descriptors and deadline. */
        interval_t rest = {0};
        if (finite && !remaining(duration, start, &rest)) {
            result = failure(sparc64_linux_errno(errno));
            goto done;
        }
        if (finite && rest.seconds == 0 && rest.nanoseconds == 0)
            break;
        int pause = finite ? milliseconds(rest) : 10;
        if (pause > 10)
            pause = 10;
        int paused = io->poll != NULL ?
                     io->poll(NULL, 0, pause, io->poll_context) :
                     poll(NULL, 0, pause);
        if (poll_terminal(io)) {
            cancelled = true;
            result = 0;
            goto done;
        }
        if (paused < 0) {
            if (errno == EINTR) {
                /* Like Linux do_select, scan original readiness before
                 * reporting a signal that ended the idle wait. */
                interrupted_pause = true;
                continue;
            }
            result = failure(sparc64_linux_errno(errno));
            goto done;
        }
    }
    for (unsigned int set = 0; set < 3; ++set) {
        if (args[set + 1] == 0 || bytes == 0)
            continue;
        if (!write_fd_set(space, args[set + 1],
                          bits + (set + 3) * bytes, bytes)) {
            result = failure(sparc64_fault_is_runtime(space->fault_reason) ? 12 : 14);
            goto done;
        }
    }
    result = ready;
done:
    if (owned != NULL) {
        int saved_errno = errno;
        sparc64_owned_io_finish(&owned);
        errno = saved_errno;
        native = NULL;
        bits = NULL;
    }
    if (native != NULL)
        for (uint32_t fd = 0; fd < count; ++fd)
            if (native[fd].fd >= 0)
                (void)sparc64_fd_release(native[fd].fd);
    free(native);
    free(bits);
    if (!cancelled && mask_installed && !io->wait_mask_finish(
            result == failure(4) && io->poll_guest_interrupt != NULL &&
            io->poll_guest_interrupt(io->wait_mask_context),
            io->wait_mask_context))
        result = failure(sparc64_linux_errno(errno));
    if (!cancelled && finite)
        finish_timeout(space, args[4], duration, start);
    return result;
}

bool sparc64_linux_poll_dispatch(sparc64_linux_file_t *files, uint64_t number,
                            const uint64_t arguments[6], uint64_t *result)
{
    return sparc64_linux_poll_dispatch_io(files, NULL, number, arguments, result);
}

bool sparc64_linux_poll_dispatch_io(sparc64_linux_file_t *files,
                               const sparc64_linux_file_io_t *io, uint64_t number,
                               const uint64_t arguments[6], uint64_t *result)
{
    if ((number != 72 && number != 73) || files == NULL ||
        arguments == NULL || result == NULL)
        return false;
    const sparc64_linux_file_io_t selected = io != NULL ? *io : (sparc64_linux_file_io_t){
        .read = files->read,
        .read_context = files->read_context,
        .read_releases_guard = files->read_releases_guard,
        .poll = files->poll,
        .poll_context = files->poll_context
    };
    *result = number == 72 ? select_files(files, &selected, arguments) :
                             poll_files(files, &selected, arguments);
    return true;
}
