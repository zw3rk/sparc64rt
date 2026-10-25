/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#define _GNU_SOURCE
#include "runtime/family_zero_segment.h"
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/xattr.h>
#include <unistd.h>

#define SEGMENT_VERSION 2u
#define SEGMENT_ATTRIBUTE "user.sparc64rt.zero_segment"

static int set_descriptor(int fd, const uint8_t *wire)
{
#ifdef __APPLE__
    return fsetxattr(fd, SEGMENT_ATTRIBUTE, wire,
                     SPARC64_FAMILY_ZERO_SEGMENT_WIRE_SIZE, 0, XATTR_CREATE);
#else
    return fsetxattr(fd, SEGMENT_ATTRIBUTE, wire,
                     SPARC64_FAMILY_ZERO_SEGMENT_WIRE_SIZE, XATTR_CREATE);
#endif
}

static ssize_t get_descriptor(int fd, uint8_t *wire)
{
#ifdef __APPLE__
    return fgetxattr(fd, SEGMENT_ATTRIBUTE, wire,
                     SPARC64_FAMILY_ZERO_SEGMENT_WIRE_SIZE, 0, 0);
#else
    return fgetxattr(fd, SEGMENT_ATTRIBUTE, wire,
                     SPARC64_FAMILY_ZERO_SEGMENT_WIRE_SIZE);
#endif
}

static void put32(uint8_t *p, uint32_t x)
{
    for (unsigned i = 0; i < 4; ++i)
        p[i] = (uint8_t)(x >> (i * 8u));
}

static void put64(uint8_t *p, uint64_t x)
{
    for (unsigned i = 0; i < 8; ++i)
        p[i] = (uint8_t)(x >> (i * 8u));
}

static uint32_t get32(const uint8_t *p)
{
    uint32_t x = 0;
    for (unsigned i = 0; i < 4; ++i)
        x |= (uint32_t)p[i] << (i * 8u);
    return x;
}

static uint64_t get64(const uint8_t *p)
{
    uint64_t x = 0;
    for (unsigned i = 0; i < 8; ++i)
        x |= (uint64_t)p[i] << (i * 8u);
    return x;
}

static int fill_random(uint8_t *out, size_t count)
{
#ifdef __APPLE__
    arc4random_buf(out, count);
    return 0;
#else
    return getentropy(out, count);
#endif
}

static bool valid_shape(uint32_t kind, uint64_t object_id, size_t payload_size)
{
    return (kind == SPARC64_FAMILY_ZERO_SEGMENT_CONTROL ? object_id == 0 :
            (kind == SPARC64_FAMILY_ZERO_SEGMENT_OBJECT ||
             kind == SPARC64_FAMILY_ZERO_SEGMENT_CONTROL_FRAGMENT) &&
            object_id != 0) &&
           payload_size != 0 && payload_size <= SIZE_MAX - SPARC64_FAMILY_ZERO_SEGMENT_PREFIX;
}

static int check_segment(int shmid, size_t payload_size)
{
    struct shmid_ds status;
    if (shmctl(shmid, IPC_STAT, &status) != 0)
        return -1;
    if (status.shm_segsz != payload_size + SPARC64_FAMILY_ZERO_SEGMENT_PREFIX ||
        status.shm_perm.uid != geteuid() ||
        status.shm_perm.cuid != geteuid() ||
        (status.shm_perm.mode & 0777u) != 0600u) {
        errno = EACCES;
        return -1;
    }
    return 0;
}

static int descriptor_valid(const uint8_t *wire, uint32_t kind,
                            uint64_t object_id, size_t payload_size)
{
    if (memcmp(wire, "RVZSEGM2", 8) != 0 ||
        get32(wire + 8) != SEGMENT_VERSION ||
        get32(wire + 12) != kind || get32(wire + 16) > INT_MAX ||
        get32(wire + 20) != 0 || get64(wire + 24) != payload_size ||
        get64(wire + 32) != object_id) {
        errno = EBADMSG;
        return -1;
    }
    return 0;
}

int sparc64_family_zero_segment_create(uint32_t kind, uint64_t object_id,
                                  size_t payload_size,
                                  sparc64_family_zero_segment_t *out)
{
    if (out == NULL || out->base != NULL ||
        !valid_shape(kind, object_id, payload_size)) {
        errno = EINVAL;
        return -1;
    }
    uint8_t wire[SPARC64_FAMILY_ZERO_SEGMENT_WIRE_SIZE] = {0};
    memcpy(wire, "RVZSEGM2", 8);
    put32(wire + 8, SEGMENT_VERSION);
    put32(wire + 12, kind);
    put64(wire + 24, payload_size);
    put64(wire + 32, object_id);
    if (fill_random(wire + 40, 16) != 0)
        return -1;
    int shmid = shmget(IPC_PRIVATE,
                       payload_size + SPARC64_FAMILY_ZERO_SEGMENT_PREFIX,
                       IPC_CREAT | 0600);
    if (shmid < 0)
        return -1;
    void *base = shmat(shmid, NULL, 0);
    if (base == (void *)-1) {
        int saved = errno;
        (void)shmctl(shmid, IPC_RMID, NULL);
        errno = saved;
        return -1;
    }
    if (shmctl(shmid, IPC_RMID, NULL) != 0) {
        int saved = errno;
        (void)shmdt(base);
        (void)shmctl(shmid, IPC_RMID, NULL);
        errno = saved;
        return -1;
    }
    if (check_segment(shmid, payload_size) != 0) {
        int saved = errno;
        (void)shmdt(base);
        errno = saved;
        return -1;
    }
    put32(wire + 16, (uint32_t)shmid);
    memcpy(base, wire, sizeof(wire));
    *out = (sparc64_family_zero_segment_t){.shmid = shmid,
        .base = base, .payload = (uint8_t *)base + SPARC64_FAMILY_ZERO_SEGMENT_PREFIX,
        .payload_size = payload_size};
    memcpy(out->descriptor, wire, sizeof(wire));
    return 0;
}

int sparc64_family_zero_segment_attach(
    const uint8_t descriptor[SPARC64_FAMILY_ZERO_SEGMENT_WIRE_SIZE],
    uint32_t kind, uint64_t object_id, size_t payload_size,
    sparc64_family_zero_segment_t *out)
{
    if (descriptor == NULL || out == NULL || out->base != NULL ||
        !valid_shape(kind, object_id, payload_size)) {
        errno = EINVAL;
        return -1;
    }
    if (descriptor_valid(descriptor, kind, object_id, payload_size) != 0)
        return -1;
    int shmid = (int)get32(descriptor + 16);
    void *base = shmat(shmid, NULL, 0);
    if (base == (void *)-1)
        return -1;
    if (check_segment(shmid, payload_size) != 0) {
        int saved = errno;
        (void)shmdt(base);
        errno = saved;
        return -1;
    }
    if (memcmp(base, descriptor, SPARC64_FAMILY_ZERO_SEGMENT_WIRE_SIZE) != 0) {
        (void)shmdt(base);
        errno = EBADMSG;
        return -1;
    }
    *out = (sparc64_family_zero_segment_t){.shmid = shmid,
        .base = base, .payload = (uint8_t *)base + SPARC64_FAMILY_ZERO_SEGMENT_PREFIX,
        .payload_size = payload_size};
    memcpy(out->descriptor, descriptor, SPARC64_FAMILY_ZERO_SEGMENT_WIRE_SIZE);
    return 0;
}

void sparc64_family_zero_segment_detach(sparc64_family_zero_segment_t *segment)
{
    if (segment == NULL)
        return;
    if (segment->base != NULL)
        (void)shmdt(segment->base);
    *segment = (sparc64_family_zero_segment_t){0};
}

int sparc64_family_zero_segment_publish_fd(int fd,
                                      const sparc64_family_zero_segment_t *segment)
{
    if (fd < 0 || segment == NULL || segment->base == NULL) {
        errno = EINVAL;
        return -1;
    }
    return set_descriptor(fd, segment->descriptor);
}

int sparc64_family_zero_segment_attach_fd(int fd, uint32_t kind,
                                     uint64_t object_id, size_t payload_size,
                                     sparc64_family_zero_segment_t *out)
{
    if (fd < 0 || out == NULL || out->base != NULL) {
        errno = EINVAL;
        return -1;
    }
    uint8_t descriptor[SPARC64_FAMILY_ZERO_SEGMENT_WIRE_SIZE];
    ssize_t size = get_descriptor(fd, descriptor);
    if (size < 0)
        return -1;
    if (size != (ssize_t)sizeof(descriptor)) {
        errno = EBADMSG;
        return -1;
    }
    return sparc64_family_zero_segment_attach(descriptor, kind, object_id,
                                         payload_size, out);
}
