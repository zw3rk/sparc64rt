/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#define _POSIX_C_SOURCE 200809L
#include "linux/codec.h"

#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

/* Linux v6.18 include/uapi/asm-generic/stat.h is the RISC-V UAPI layout:
 * 0 dev, 8 ino, 16 mode/nlink/uid/gid, 32 rdev, 40 pad, 48 size,
 * 56 blksize/pad, 64 blocks, 72/80 atime/sec+nsec, 88/96 mtime,
 * 104/112 ctime, and 120/124 reserved words. The 64-bit form is 128 bytes. */
enum {
    STAT_DEV = 0, STAT_INO = 8, STAT_MODE = 16, STAT_NLINK = 20,
    STAT_UID = 24, STAT_GID = 28, STAT_RDEV = 32, STAT_SIZE = 48,
    STAT_BLKSIZE = 56, STAT_BLOCKS = 64, STAT_ATIME = 72,
    STAT_MTIME = 88, STAT_CTIME = 104, STAT_SIZE_BYTES = 128
};

static void put_u32(unsigned char *output, uint32_t value)
{
    for (unsigned int i = 0; i < 4; ++i)
        output[i] = (unsigned char)(value >> (i * 8));
}

static void put_u64(unsigned char *output, uint64_t value)
{
    for (unsigned int i = 0; i < 8; ++i)
        output[i] = (unsigned char)(value >> (i * 8));
}

static uint32_t get_u32_from_uintmax(uintmax_t value)
{
    return (uint32_t)value;
}

static bool signed32_value(intmax_t value, int32_t *result)
{
    if (value < INT32_MIN || value > INT32_MAX)
        return false;
    *result = (int32_t)value;
    return true;
}

static uint64_t signed64_bits(intmax_t value)
{
    /* Signed-to-unsigned conversion is defined modulo 2^64. */
    return (uint64_t)(int64_t)value;
}

static bool valid_nsec(long nsec)
{
    return nsec >= 0 && nsec <= 999999999L;
}

static void put_time(unsigned char *output, intmax_t seconds, long nsec)
{
    put_u64(output, signed64_bits(seconds));
    put_u64(output + 8, (uint64_t)nsec);
}

int sparc64_codec_stat64(unsigned char output[128], const struct stat *status)
{
    if (output == NULL || status == NULL) {
        errno = EINVAL;
        return -1;
    }
#if defined(__APPLE__)
    const struct timespec atime = {status->st_atime, status->st_atimensec};
    const struct timespec mtime = {status->st_mtime, status->st_mtimensec};
    const struct timespec ctime = {status->st_ctime, status->st_ctimensec};
#else
    const struct timespec atime = status->st_atim;
    const struct timespec mtime = status->st_mtim;
    const struct timespec ctime = status->st_ctim;
#endif
    if (!valid_nsec(atime.tv_nsec) || !valid_nsec(mtime.tv_nsec) ||
        !valid_nsec(ctime.tv_nsec)) {
        errno = EINVAL;
        return -1;
    }

    uintmax_t device = (uintmax_t)status->st_dev;
    uintmax_t inode = (uintmax_t)status->st_ino;
    uintmax_t mode = (uintmax_t)status->st_mode;
    uintmax_t links = (uintmax_t)status->st_nlink;
    uintmax_t uid = (uintmax_t)status->st_uid;
    uintmax_t gid = (uintmax_t)status->st_gid;
    uintmax_t rdevice = (uintmax_t)status->st_rdev;
    uint32_t blksize;
    int32_t signed_blksize;

#if defined(__APPLE__)
    if (status->st_dev < 0 || status->st_rdev < 0) {
        errno = EOVERFLOW;
        return -1;
    }
#endif
    if (mode > UINT32_MAX || links > UINT32_MAX || uid > UINT32_MAX ||
        gid > UINT32_MAX || !signed32_value((intmax_t)status->st_blksize,
                                            &signed_blksize)) {
        errno = EOVERFLOW;
        return -1;
    }
    blksize = (uint32_t)signed_blksize;

    unsigned char encoded[STAT_SIZE_BYTES];
    memset(encoded, 0, sizeof(encoded));
    put_u64(encoded + STAT_DEV, (uint64_t)device);
    put_u64(encoded + STAT_INO, (uint64_t)inode);
    put_u32(encoded + STAT_MODE, get_u32_from_uintmax(mode));
    put_u32(encoded + STAT_NLINK, get_u32_from_uintmax(links));
    put_u32(encoded + STAT_UID, get_u32_from_uintmax(uid));
    put_u32(encoded + STAT_GID, get_u32_from_uintmax(gid));
    put_u64(encoded + STAT_RDEV, (uint64_t)rdevice);
    put_u64(encoded + STAT_SIZE, signed64_bits((intmax_t)status->st_size));
    put_u32(encoded + STAT_BLKSIZE, blksize);
    put_u64(encoded + STAT_BLOCKS, signed64_bits((intmax_t)status->st_blocks));
    put_time(encoded + STAT_ATIME, (intmax_t)atime.tv_sec, atime.tv_nsec);
    put_time(encoded + STAT_MTIME, (intmax_t)mtime.tv_sec, mtime.tv_nsec);
    put_time(encoded + STAT_CTIME, (intmax_t)ctime.tv_sec, ctime.tv_nsec);
    memcpy(output, encoded, sizeof(encoded));
    return 0;
}
