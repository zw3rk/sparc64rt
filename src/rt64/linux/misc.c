/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L
#if defined(__APPLE__)
#define _DARWIN_C_SOURCE 1
#endif
#include "linux/misc.h"
#include "linux/error.h"

#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#if defined(__linux__)
#include <sys/random.h>
#include <sys/syscall.h>
#elif defined(__APPLE__)
#include <pthread.h>
#include <sys/random.h>
#endif

#define SPARC64_RANDOM_STAGE ((size_t)65536)
#define SPARC64_MAX_RW_COUNT UINT64_C(0x7ffff000)
#define SPARC64_GRND_NONBLOCK UINT32_C(1)
#define SPARC64_GRND_RANDOM UINT32_C(2)
#define SPARC64_GRND_INSECURE UINT32_C(4)
#define SPARC64_UTS_FIELD ((size_t)65)
#define SPARC64_UTS_BYTES (SPARC64_UTS_FIELD * 6)

static uint64_t fail_errno(int host_errno)
{
    unsigned int guest_errno = sparc64_linux_errno(host_errno == 0 ? EIO : host_errno);
    return UINT64_C(0) - guest_errno;
}

static uint64_t fail_guest(unsigned int guest_errno)
{
    return UINT64_C(0) - guest_errno;
}

static void put64(unsigned char output[8], uint64_t value)
{
    for (unsigned int i = 0; i < 8; ++i)
        output[i] = (unsigned char)(value >> (i * 8));
}

static bool is_rv32(const sparc64_space_t *space)
{
    return space->limit == (UINT64_C(1) << 32);
}

/* Internal write capacity failures are not bad guest pointers. */
static uint64_t output_failure(sparc64_space_t *space, uint64_t address, size_t size)
{
    bool in_domain = address >= SPARC64_PAGE_SIZE && address < space->limit &&
                     size <= space->limit - address;
    return fail_guest(sparc64_fault_is_runtime(space->fault_reason) && in_domain ? 12 : 14);
}

static uint64_t copy_output(sparc64_space_t *space, uint64_t address,
                            const unsigned char *bytes, size_t size)
{
    if (!sparc64_space_prepare_write(space, address, size) ||
        !sparc64_space_write(space, address, bytes, size))
        return output_failure(space, address, size);
    return 0;
}

#if defined(__APPLE__)
/* Native unit-test adapter only. The shipped runtime uses Linux getrandom;
 * Darwin getentropy has no nonblocking/RANDOM flag semantics and cannot
 * establish those behavior claims. */
static ssize_t host_random(unsigned char *output, size_t size, unsigned int flags)
{
    (void)flags;
    size_t done = 0;
    while (done < size) {
        size_t chunk = size - done < 256 ? size - done : 256;
        if (getentropy(output + done, chunk) != 0)
            return done != 0 ? (ssize_t)done : -1;
        done += chunk;
    }
    return (ssize_t)done;
}
#else
static ssize_t host_random(unsigned char *output, size_t size, unsigned int flags)
{
    return getrandom(output, size, flags);
}
#endif

static uint64_t random_bytes(sparc64_space_t *space, const uint64_t args[6])
{
    /* The Linux syscall formal parameter is unsigned int; high register
     * bits are discarded by the native kernel too. */
    uint32_t flags = (uint32_t)args[2];
    if ((flags & ~(SPARC64_GRND_NONBLOCK | SPARC64_GRND_RANDOM | SPARC64_GRND_INSECURE)) != 0 ||
        (flags & (SPARC64_GRND_RANDOM | SPARC64_GRND_INSECURE)) ==
        (SPARC64_GRND_RANDOM | SPARC64_GRND_INSECURE))
        return fail_guest(22);
    /* Linux validates the full MAX_RW_COUNT-clamped numeric user range before
     * copying, even though this runtime stages at most 64 KiB per call. */
    uint64_t requested = args[1] < SPARC64_MAX_RW_COUNT ? args[1] : SPARC64_MAX_RW_COUNT;
    if (args[0] > space->limit || requested > space->limit - args[0])
        return fail_guest(14);
    if (args[1] == 0)
        return 0;
    size_t size = args[1] < SPARC64_RANDOM_STAGE ? (size_t)args[1] : SPARC64_RANDOM_STAGE;
    unsigned char *staged = malloc(size);
    if (staged == NULL)
        return fail_guest(12);
    size_t prepared = 0;
    while (prepared < size) {
        uint64_t at = args[0] + prepared;
        size_t part = SPARC64_PAGE_SIZE - (size_t)(at % SPARC64_PAGE_SIZE);
        if (part > size - prepared)
            part = size - prepared;
        if (!sparc64_space_prepare_write(space, at, part)) {
            if (sparc64_fault_is_runtime(space->fault_reason) || prepared == 0) {
                uint64_t failed = output_failure(space, at, part);
                free(staged);
                return failed;
            }
            break; /* Linux returns the valid copied prefix. */
        }
        prepared += part;
    }
    /* Pagewise probing finds the valid prefix. Prepare that complete range
     * before consuming entropy: aliases can hit one epoch several times,
     * and matching copyout must already own its full scratch capacity. */
    if (!sparc64_space_prepare_write(space, args[0], prepared)) {
        uint64_t failed = output_failure(space, args[0], prepared);
        free(staged);
        return failed;
    }
    ssize_t count = host_random(staged, prepared, flags);
    int saved = errno;
    uint64_t result;
    if (count < 0)
        result = fail_errno(saved);
    else if ((size_t)count > prepared)
        result = fail_guest(5);
    else if (count != 0 && !sparc64_space_write(space, args[0], staged, (size_t)count))
        result = output_failure(space, args[0], (size_t)count);
    else
        result = (uint64_t)count;
    free(staged);
    return result;
}

/* Linux clock IDs are not native clock_t values on Darwin. Coarse clocks
 * may use a finer host clock with the same epoch; BOOTTIME/TAI are exposed
 * only when the host provides the matching clock. Dynamic negative CPU-clock
 * IDs and alarm clocks remain unsupported in this R4a subset. */
static int host_clock(uint32_t guest_id, clockid_t *host_id)
{
    switch (guest_id) {
    case 0: case 5: *host_id = CLOCK_REALTIME; return 0;
    case 1: case 6: *host_id = CLOCK_MONOTONIC; return 0;
    case 2: *host_id = CLOCK_PROCESS_CPUTIME_ID; return 0;
    case 3: *host_id = CLOCK_THREAD_CPUTIME_ID; return 0;
#ifdef CLOCK_MONOTONIC_RAW
    case 4: *host_id = CLOCK_MONOTONIC_RAW; return 0;
#endif
#ifdef CLOCK_BOOTTIME
    case 7: *host_id = CLOCK_BOOTTIME; return 0;
#endif
#ifdef CLOCK_TAI
    case 11: *host_id = CLOCK_TAI; return 0;
#endif
    default: errno = EINVAL; return -1;
    }
}

static uint64_t clock_time(sparc64_space_t *space, const uint64_t args[6])
{
    if (is_rv32(space))
        return fail_guest(38); /* RV32 time ABI follows its later profile. */
    clockid_t id;
    if (host_clock((uint32_t)args[0], &id) != 0)
        return fail_errno(errno);
    struct timespec time_value;
#if defined(__linux__)
    /* HL's libc vDSO can return its last published time while futex
     * deadlines use a fresh kernel clock. Keep both guest operations on the
     * same live clock so ETIMEDOUT is visible to an immediate clock read. */
    if (syscall(SYS_clock_gettime, id, &time_value) != 0)
#else
    if (clock_gettime(id, &time_value) != 0)
#endif
        return fail_errno(errno);
    if (time_value.tv_nsec < 0 || time_value.tv_nsec >= 1000000000L)
        return fail_guest(5);
    unsigned char output[16];
    put64(output, (uint64_t)(int64_t)time_value.tv_sec);
    put64(output + 8, (uint64_t)time_value.tv_nsec);
    return copy_output(space, args[1], output, sizeof(output));
}

static uint64_t wall_time(sparc64_space_t *space, const uint64_t args[6])
{
    if (is_rv32(space))
        return fail_guest(38); /* Do not publish an incorrect ILP32 layout. */
    struct timeval time_value;
    if (gettimeofday(&time_value, NULL) != 0)
        return fail_errno(errno);
    if (time_value.tv_usec < 0 || time_value.tv_usec >= 1000000)
        return fail_guest(5);
    unsigned char timeval_wire[16], timezone_wire[8] = {0};
    put64(timeval_wire, (uint64_t)(int64_t)time_value.tv_sec);
    put64(timeval_wire + 8, (uint64_t)(int64_t)time_value.tv_usec);
    /* Linux timezone fields are obsolete. Expose deterministic UTC zeros
     * instead of leaking host timezone or claiming mutable timezone state. */
    /* Linux publishes seconds, microseconds, then the obsolete timezone.
     * Later bad pointers leave earlier fields visible. */
    if (args[0] != 0) {
        uint64_t result = copy_output(space, args[0], timeval_wire, 8);
        if (result != 0)
            return result;
        result = copy_output(space, args[0] + 8, timeval_wire + 8, 8);
        if (result != 0)
            return result;
    }
    if (args[1] != 0) {
        uint64_t result = copy_output(space, args[1], timezone_wire, 4);
        if (result != 0)
            return result;
        return copy_output(space, args[1] + 4, timezone_wire + 4, 4);
    }
    return 0;
}

static void uts_field(unsigned char output[SPARC64_UTS_FIELD], const char *value)
{
    size_t size = strlen(value);
    if (size >= SPARC64_UTS_FIELD)
        size = SPARC64_UTS_FIELD - 1;
    memcpy(output, value, size);
}

static uint64_t guest_uname(sparc64_space_t *space, const uint64_t args[6])
{
    unsigned char output[SPARC64_UTS_BYTES] = {0};
    /* Deterministic virtual UTS identity. 6.18 is the pinned Linux UAPI
     * baseline, not a claim that every syscall of Linux 6.18 is supported.
     * In particular, never pass through the AArch64 host machine or kernel. */
    uts_field(output, "Linux");
    uts_field(output + SPARC64_UTS_FIELD, "sparc64rt");
    uts_field(output + SPARC64_UTS_FIELD * 2, "6.18.0-sparc64rt");
    uts_field(output + SPARC64_UTS_FIELD * 3, "#1 sparc64rt virtual Linux UAPI");
    uts_field(output + SPARC64_UTS_FIELD * 4, is_rv32(space) ? "riscv32" : "riscv64");
    uts_field(output + SPARC64_UTS_FIELD * 5, "(none)");
    return copy_output(space, args[0], output, sizeof(output));
}

static uint64_t identity(uint64_t number)
{
    switch (number) {
    case 172: return (uint64_t)getpid();
    case 173: return (uint64_t)getppid();
    case 174: return (uint64_t)getuid();
    case 175: return (uint64_t)geteuid();
    case 176: return (uint64_t)getgid();
    case 177: return (uint64_t)getegid();
    case 178:
#if defined(__linux__)
    {
        long tid = syscall(SYS_gettid);
        return tid < 0 ? fail_errno(errno) : (uint64_t)tid;
    }
#elif defined(__APPLE__)
    {
        uint64_t tid = 0;
        int error = pthread_threadid_np(NULL, &tid);
        return error != 0 ? fail_errno(error) : tid;
    }
#else
        return fail_guest(38);
#endif
    default: return fail_guest(38);
    }
}

bool sparc64_linux_misc_dispatch(sparc64_space_t *space, uint64_t number,
                            const uint64_t arguments[6], uint64_t *result)
{
    if (space == NULL || arguments == NULL || result == NULL)
        return false;
    switch (number) {
    case 113: *result = clock_time(space, arguments); break;
    case 160: *result = guest_uname(space, arguments); break;
    case 169: *result = wall_time(space, arguments); break;
    case 172: case 173: case 174: case 175: case 176: case 177: case 178:
        *result = identity(number); break;
    case 278: *result = random_bytes(space, arguments); break;
    default: return false;
    }
    return true;
}
