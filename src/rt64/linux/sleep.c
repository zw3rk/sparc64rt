/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#define _POSIX_C_SOURCE 200809L
#include "linux/sleep.h"
#include "linux/error.h"

#include <errno.h>
#include <limits.h>
#include <poll.h>

#define SPARC64_LINUX_NANOSLEEP 101
#define SPARC64_LINUX_CLOCK_NANOSLEEP 115
#define SPARC64_TIMER_ABSTIME UINT32_C(1)
#define REALTIME_RECHECK_MS 100
#define NS_PER_SECOND UINT64_C(1000000000)
#define KTIME_MAX_SECONDS ((uint64_t)INT64_MAX / NS_PER_SECOND)
#define KTIME_MAX_NANOSECONDS ((uint32_t)((uint64_t)INT64_MAX % NS_PER_SECOND))

typedef struct {
    uint64_t seconds;
    uint32_t nanoseconds;
} interval_t;

static uint64_t failure(unsigned int error)
{
    return UINT64_C(0) - error;
}

static uint64_t load64(const unsigned char bytes[8])
{
    uint64_t value = 0;
    for (unsigned int i = 0; i < 8; ++i)
        value |= (uint64_t)bytes[i] << (i * 8);
    return value;
}

static void store64(unsigned char bytes[8], uint64_t value)
{
    for (unsigned int i = 0; i < 8; ++i)
        bytes[i] = (unsigned char)(value >> (i * 8));
}

static int host_clock(clockid_t clock, struct timespec *time, void *context)
{
    (void)context;
    return clock_gettime(clock, time);
}

static bool read_clock(clockid_t clock_id, sparc64_linux_sleep_clock_fn clock,
                       void *context, interval_t *now)
{
    struct timespec value;
    if (clock(clock_id, &value, context) != 0)
        return false;
    if (value.tv_sec < 0 || value.tv_nsec < 0 ||
        value.tv_nsec >= (long)NS_PER_SECOND) {
        errno = EIO;
        return false;
    }
    now->seconds = (uint64_t)value.tv_sec;
    now->nanoseconds = (uint32_t)value.tv_nsec;
    if (now->seconds > KTIME_MAX_SECONDS ||
        (now->seconds == KTIME_MAX_SECONDS &&
         now->nanoseconds > KTIME_MAX_NANOSECONDS)) {
        errno = EIO;
        return false;
    }
    return true;
}

/* Linux timespec64_to_ktime() delegates to ktime_set(), which returns
 * KTIME_MAX whenever seconds >= KTIME_SEC_MAX. hrtimer_nanosleep then adds
 * the relative request with ktime_add_safe(), saturating the absolute expiry
 * at KTIME_MAX as well. Keep deadlines in that same representable domain. */
static interval_t request_to_ktime(interval_t value)
{
    if (value.seconds >= KTIME_MAX_SECONDS)
        return (interval_t){KTIME_MAX_SECONDS, KTIME_MAX_NANOSECONDS};
    return value;
}

static interval_t ktime_add_safe(interval_t left, interval_t right)
{
    const interval_t maximum = {KTIME_MAX_SECONDS,
                                KTIME_MAX_NANOSECONDS};

    uint64_t seconds = left.seconds + right.seconds;
    uint64_t nanoseconds = (uint64_t)left.nanoseconds + right.nanoseconds;
    if (nanoseconds >= NS_PER_SECOND) {
        nanoseconds -= NS_PER_SECOND;
        ++seconds;
    }
    if (seconds > maximum.seconds ||
        (seconds == maximum.seconds && nanoseconds > maximum.nanoseconds))
        return maximum;
    return (interval_t){seconds, (uint32_t)nanoseconds};
}

static bool remaining(interval_t deadline, interval_t started,
                      clockid_t clock_id, bool monotonic,
                      sparc64_linux_sleep_clock_fn clock, void *context,
                      interval_t *rest)
{
    interval_t current;
    if (!read_clock(clock_id, clock, context, &current))
        return false;
    if (monotonic && (current.seconds < started.seconds ||
        (current.seconds == started.seconds &&
         current.nanoseconds < started.nanoseconds))) {
        errno = EIO;
        return false;
    }
    if (current.seconds > deadline.seconds ||
        (current.seconds == deadline.seconds &&
         current.nanoseconds >= deadline.nanoseconds)) {
        *rest = (interval_t){0, 0};
        return true;
    }
    rest->seconds = deadline.seconds - current.seconds;
    if (deadline.nanoseconds < current.nanoseconds) {
        --rest->seconds;
        rest->nanoseconds = (uint32_t)NS_PER_SECOND - current.nanoseconds +
                            deadline.nanoseconds;
    } else
        rest->nanoseconds = deadline.nanoseconds - current.nanoseconds;
    return true;
}

static int poll_milliseconds(interval_t rest)
{
    if (rest.seconds >= ((uint64_t)INT_MAX + 999u) / 1000u)
        return INT_MAX;
    uint64_t millis = rest.seconds * 1000u +
                      (rest.nanoseconds + UINT64_C(999999)) / UINT64_C(1000000);
    return millis > INT_MAX ? INT_MAX : (int)millis;
}

static unsigned int memory_error(sparc64_space_t *space)
{
    return sparc64_fault_is_runtime(space->fault_reason) ? 12u : 14u;
}

/* RISC-V user copies may complete a valid page prefix before faulting on a
 * later page. Keep that copyout shape while making internal publication
 * failures distinguishable from guest EFAULT. */
static uint64_t copy_remaining(sparc64_space_t *space, uint64_t address,
                               interval_t rest)
{
    unsigned char bytes[16];
    store64(bytes, rest.seconds);
    store64(bytes + 8, rest.nanoseconds);

    size_t prefix = 0;
    while (prefix < sizeof(bytes)) {
        if (address > space->limit || prefix > space->limit - address)
            break;
        uint64_t cursor = address + prefix;
        size_t amount = (size_t)(SPARC64_PAGE_SIZE - cursor % SPARC64_PAGE_SIZE);
        if (amount > sizeof(bytes) - prefix)
            amount = sizeof(bytes) - prefix;
        if (!sparc64_space_prepare_write(space, cursor, amount)) {
            if (sparc64_fault_is_runtime(space->fault_reason))
                return failure(12);
            break;
        }
        prefix += amount;
    }
    if (prefix != 0 && !sparc64_space_write(space, address, bytes, prefix))
        return failure(memory_error(space));
    return prefix == sizeof(bytes) ? 0 : failure(14);
}

static uint64_t interrupted(sparc64_space_t *space, uint64_t address,
                            interval_t rest)
{
    if (address == 0)
        return failure(4);
    uint64_t copied = copy_remaining(space, address, rest);
    return copied == 0 ? failure(4) : copied;
}

static bool cancelled(const sparc64_linux_file_io_t *io)
{
    if (io == NULL || io->poll_cancelled == NULL)
        return false;
    int saved_errno = errno;
    bool value = io->poll_cancelled(io->poll_context);
    errno = saved_errno;
    return value;
}

static bool guest_interrupted(const sparc64_linux_file_io_t *io)
{
    return io != NULL && io->poll_guest_interrupt != NULL &&
           io->poll_guest_interrupt(io->wait_mask_context);
}

static bool dispatch(sparc64_space_t *space, const sparc64_linux_file_io_t *io,
                     sparc64_linux_sleep_clock_fn clock, void *clock_context,
                     uint64_t number, const uint64_t args[6], uint64_t *result)
{
    if ((number != SPARC64_LINUX_NANOSLEEP &&
         number != SPARC64_LINUX_CLOCK_NANOSLEEP) ||
        space == NULL || args == NULL || result == NULL)
        return false;
    if (space->limit == (UINT64_C(1) << 32)) {
        *result = failure(38);
        return true;
    }

    uint64_t request_address = args[0], remainder_address = args[1];
    clockid_t clock_id = CLOCK_MONOTONIC;
    bool absolute = false;
    if (number == SPARC64_LINUX_CLOCK_NANOSLEEP) {
        /* Linux clockid_t and flags are 32-bit formal arguments. The pinned
         * syscall ignores flag bits other than TIMER_ABSTIME. Resolve the
         * clock before copying the request, as Linux does. */
        uint32_t guest_clock = (uint32_t)args[0];
        absolute = ((uint32_t)args[1] & SPARC64_TIMER_ABSTIME) != 0;
        switch (guest_clock) {
        case 0:
            /* Relative realtime sleeps use monotonic elapsed time; only
             * absolute realtime deadlines track wall-clock adjustments. */
            if (absolute)
                clock_id = CLOCK_REALTIME;
            break;
        case 1:
            break;
        case 2: case 3: case 4: case 5: case 6: case 7:
        case 8: case 9: case 11:
        case 16: case 17: case 18: case 19:
        case 20: case 21: case 22: case 23:
            *result = failure(95);
            return true;
        default:
            /* Negative dynamic/CPU clocks require guest-owned clock/CPU
             * identity. Deliberately decline them, never use host CPU time. */
            *result = failure(guest_clock > INT32_MAX ? 95u : 22u);
            return true;
        }
        request_address = args[2];
        remainder_address = absolute ? 0 : args[3];
    }

    unsigned char request_bytes[16];
    if (!sparc64_space_read(space, request_address, request_bytes,
                       sizeof(request_bytes), SPARC64_MEM_READ)) {
        *result = failure(memory_error(space));
        return true;
    }
    uint64_t raw_seconds = load64(request_bytes);
    uint64_t raw_nanoseconds = load64(request_bytes + 8);
    if (raw_seconds > INT64_MAX || raw_nanoseconds > INT64_MAX) {
        *result = failure(22);
        return true;
    }
    int64_t signed_seconds = (int64_t)raw_seconds;
    int64_t signed_nanoseconds = (int64_t)raw_nanoseconds;
    if (signed_seconds < 0 || signed_nanoseconds < 0 ||
        signed_nanoseconds >= (int64_t)NS_PER_SECOND) {
        *result = failure(22);
        return true;
    }
    interval_t requested = {(uint64_t)signed_seconds,
                            (uint32_t)signed_nanoseconds};
    if (requested.seconds == 0 && requested.nanoseconds == 0) {
        *result = 0;
        return true;
    }

    if (clock == NULL)
        clock = host_clock;
    interval_t started;
    if (!read_clock(clock_id, clock, clock_context, &started)) {
        *result = failure(sparc64_linux_errno(errno));
        return true;
    }
    interval_t deadline = absolute ? request_to_ktime(requested) :
                          ktime_add_safe(started, request_to_ktime(requested));
    bool monotonic = clock_id == CLOCK_MONOTONIC;

    for (;;) {
        interval_t rest;
        if (!remaining(deadline, started, clock_id, monotonic,
                           clock, clock_context, &rest)) {
            *result = failure(sparc64_linux_errno(errno));
            return true;
        }
        if (rest.seconds == 0 && rest.nanoseconds == 0) {
            *result = 0;
            return true;
        }
        if (guest_interrupted(io)) {
            if (cancelled(io)) {
                *result = 0;
                return true;
            }
            if (!remaining(deadline, started, clock_id, monotonic,
                           clock, clock_context, &rest)) {
                *result = failure(sparc64_linux_errno(errno));
                return true;
            }
            if (rest.seconds == 0 && rest.nanoseconds == 0) {
                *result = 0;
                return true;
            }
            *result = interrupted(space, remainder_address, rest);
            return true;
        }

        int timeout = poll_milliseconds(rest);
        /* A relative poll cannot be notified of a wall-clock change. Bound
         * absolute realtime chunks and resample that same clock after every
         * wake; a backwards change extends the wait rather than causing EIO.
         * This is a scheduling-resolution bound, not a latency guarantee. */
        if (!monotonic && timeout > REALTIME_RECHECK_MS)
            timeout = REALTIME_RECHECK_MS;
        int waited = io != NULL && io->poll != NULL ?
                     io->poll(NULL, 0, timeout, io->poll_context) :
                     poll(NULL, 0, timeout);
        int saved_errno = errno;
        bool is_cancelled = cancelled(io);
        errno = saved_errno;
        if (is_cancelled) {
            *result = 0;
            return true;
        }

        if (waited == 0) {
            if (!remaining(deadline, started, clock_id, monotonic,
                           clock, clock_context, &rest)) {
                *result = failure(sparc64_linux_errno(errno));
                return true;
            }
            if (rest.seconds == 0 && rest.nanoseconds == 0) {
                *result = 0;
                return true;
            }
            continue;
        }
        if (guest_interrupted(io)) {
            if (cancelled(io)) {
                *result = 0;
                return true;
            }
            if (!remaining(deadline, started, clock_id, monotonic,
                           clock, clock_context, &rest)) {
                *result = failure(sparc64_linux_errno(errno));
                return true;
            }
            if (rest.seconds == 0 && rest.nanoseconds == 0) {
                *result = 0;
                return true;
            }
            *result = interrupted(space, remainder_address, rest);
            return true;
        }
        if (waited < 0 && saved_errno != EINTR) {
            *result = failure(sparc64_linux_errno(saved_errno));
            return true;
        }
        /* Host EINTR without a guest interrupt is a private wake. Recompute
         * against the same deadline, never restarting the requested delay. */
    }
}

bool sparc64_linux_sleep_dispatch_io_clock(sparc64_space_t *space,
                                     const sparc64_linux_file_io_t *io,
                                     sparc64_linux_sleep_clock_fn clock,
                                     void *clock_context,
                                     uint64_t number,
                                     const uint64_t arguments[6],
                                     uint64_t *result)
{
    return dispatch(space, io, clock, clock_context, number, arguments, result);
}

bool sparc64_linux_sleep_dispatch_io(sparc64_space_t *space,
                                const sparc64_linux_file_io_t *io,
                                uint64_t number,
                                const uint64_t arguments[6],
                                uint64_t *result)
{
    return dispatch(space, io, host_clock, NULL, number, arguments, result);
}
