/*
 * src/os/host_contract_identity.c — Phase 6 (L6a) cache identity,
 * family control verification, selftest, and stats (Wave U1: migrated
 * from src/rt64/runtime/host_contract_identity.c; the heavy
 * rv_family_create-based broker check is replaced by the lightweight
 * Provider-A family control in src/os/host_contract_family.c)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * AOT cache identity per HOST-CONTRACT.md section 5.2 (SHA-256
 * translator digest binds cache keys; dynamic PT_INTERP binds both
 * file digests), family broker name/sequence verification, the
 * --selftest-host report, and --stats stderr counters. The AOT cache
 * backend stays excluded from the build (frozen Makefile); admission
 * resolves up to the backend boundary and declines with a reason.
 */

#define _POSIX_C_SOURCE 200809L
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "os/host_contract.h"

#include "dbt/aot/authority.h"
#include "dbt/aot/digest.h"
#include "dbt/aot/sha256.h"
#include "os/host_contract_file_identity.h"
#include "os/host_contract_interp.h"
#include "os/syscalls_min.h"

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <unistd.h>

#if defined(__linux__)
#include <sys/auxv.h>
#include <sys/vfs.h>
#endif

static void to_hex(const uint8_t *bytes, size_t size, char *hex,
    size_t cap)
{
    static const char digits[] = "0123456789abcdef";
    size_t i;
    for (i = 0; i < size && (i * 2U + 2U) <= cap; i++) {
        hex[i * 2U] = digits[(bytes[i] >> 4) & 15U];
        hex[i * 2U + 1U] = digits[bytes[i] & 15U];
    }
    hex[(i * 2U < cap) ? i * 2U : cap - 1U] = '\0';
}

static void put_le64(uint8_t out[8], uint64_t value)
{
    unsigned i;
    for (i = 0; i < 8U; i++) {
        out[i] = (uint8_t)(value >> (8U * i));
    }
}

/* Stream fd bytes (position-independent pread; the borrowed descriptor's
 * offset never moves) into the running digest with fstat stability: the
 * file must keep device/inode/size/mtime across the hash. */
static int hash_fd(int fd, const struct stat *before, sparc64_sha256_t *ctx,
    uint64_t *length_out)
{
    uint8_t chunk[65536];
    uint64_t offset = 0;
    struct stat after;
    for (;;) {
        ssize_t got;
        size_t want = sizeof(chunk);
        uint64_t left = (uint64_t)before->st_size > offset ?
            (uint64_t)before->st_size - offset : UINT64_C(0);
        if (left == 0U) {
            break;
        }
        if (left < (uint64_t)want) {
            want = (size_t)left;
        }
        do {
            got = pread(fd, chunk, want, (off_t)offset);
        } while (got < 0 && errno == EINTR);
        if (got <= 0) {
            return -1;
        }
        sparc64_sha256_update(ctx, chunk, (size_t)got);
        offset += (uint64_t)got;
    }
    if (fstat(fd, &after) != 0 || after.st_dev != before->st_dev ||
        after.st_ino != before->st_ino ||
        after.st_size != before->st_size ||
        after.st_mtime != before->st_mtime) {
        errno = EAGAIN;
        return -1;
    }
    *length_out = offset;
    return 0;
}

/* SHA-256 of the running translator image (/proc/self/exe, falling
 * back to argv[0]); position-independent reads, no offset movement. */
static int translator_digest(const char *argv0, uint8_t out[32])
{
    sparc64_sha256_t ctx;
    struct stat before;
    char self[64];
    uint64_t length = 0;
    int fd = -1;
    int n;
    n = snprintf(self, sizeof(self), "/proc/self/exe");
    if (n > 0 && (size_t)n < sizeof(self)) {
        fd = open(self, O_RDONLY | O_CLOEXEC);
    }
    if (fd < 0 && argv0 != NULL) {
        fd = open(argv0, O_RDONLY | O_CLOEXEC);
    }
    if (fd < 0) {
        return -1;
    }
    if (fstat(fd, &before) != 0 || !S_ISREG(before.st_mode)) {
        (void)close(fd);
        return -1;
    }
    sparc64_sha256_init(&ctx);
    if (hash_fd(fd, &before, &ctx, &length) != 0 || length == 0U) {
        (void)close(fd);
        return -1;
    }
    (void)close(fd);
    sparc64_sha256_finish(&ctx, out);
    return 0;
}

static const char *fs_name(unsigned long magic, char *buf, size_t cap)
{
    if (magic == (unsigned long)0xef53UL) {
        return "ext4";
    }
    if (magic == (unsigned long)0x01021994UL) {
        return "tmpfs";
    }
    if (magic == (unsigned long)0x794c7630UL) {
        return "overlayfs";
    }
    if (magic == (unsigned long)0x6969UL) {
        return "nfs";
    }
    (void)snprintf(buf, cap, "fs-magic-0x%lx", magic);
    return buf;
}

static void cache_status(sparc64_host_cache_t *out, const char *status,
    const char *reason)
{
    size_t n = strlen(status);
    size_t m = strlen(reason);
    if (n >= sizeof(out->status)) {
        n = sizeof(out->status) - 1U;
    }
    if (m >= sizeof(out->reason)) {
        m = sizeof(out->reason) - 1U;
    }
    memcpy(out->status, status, n);
    out->status[n] = '\0';
    memcpy(out->reason, reason, m);
    out->reason[m] = '\0';
}

int sparc64_host_cache_admit(const sparc64_host_options_t *opts,
    int image_fd, const char *image_path, sparc64_host_cache_t *out)
{
    static const uint8_t dynamic_domain[] =
        "sparc64rt-aot-main-and-pt-interp-v1";
    static const uint8_t emitter_tag[] = "sparc64rt-a64-emitter-v1";
    static const uint8_t key_tag[] = "sparc64rt-cache-key-v1";
    static const uint8_t profile_tag[] = "sparc64rt-v9-profile-v1";
    uint8_t runtime_digest[32], input_digest[32], emitter_digest[32];
    uint8_t key[32];
    uint8_t lengths[16];
    uint8_t profile[40];
    struct stat main_before;
    struct stat interp_before;
    sparc64_sha256_t ctx;
    sparc64_aot_span_t spans[2];
    uint64_t main_length = 0, interp_length = 0;
    int dir_fd = -1;
    int main_fd = -1;
    int main_owned = 0;
    int rc;
    char auth_note[128];
    char interp[SPARC64RT_INTERP_PATH_MAX];
    char resolved[SPARC64RT_INTERP_PATH_MAX];
    memset(out, 0, sizeof(*out));
    cache_status(out, "unused", "no-cache-dir");
    (void)snprintf(auth_note, sizeof(auth_note), "cache-authority-declined");
    if (opts == NULL || opts->cache_dir == NULL) {
        return 0;
    }
    out->active = 1;
    dir_fd = open(opts->cache_dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dir_fd < 0 && errno == ENOENT) {
        if (mkdir(opts->cache_dir, 0700) == 0) {
            dir_fd = open(opts->cache_dir,
                O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        }
    }
    if (dir_fd < 0) {
        cache_status(out, "declined", "cannot-open-cache-dir");
        return 0;
    }
    /* Authority gates admission, never identity derivation: the key is
     * computed whenever the inputs are available so --stats and the
     * probe can verify binding even when this host's filesystem
     * declines (e.g. tmpfs without xattr support reports EOPNOTSUPP
     * instead of ENODATA and can carry no ACL by construction). */
    if (!sparc64_aot_authorize_fd(dir_fd, true,
            SPARC64_AOT_AUTHORITY_AUTO)) {
#if defined(__linux__)
        struct statfs filesystem;
        if (fstatfs(dir_fd, &filesystem) == 0) {
            char magic_name[32];
            (void)snprintf(auth_note, sizeof(auth_note),
                "cache-authority-declined:%s",
                fs_name((unsigned long)filesystem.f_type, magic_name,
                    sizeof(magic_name)));
        } else {
            (void)snprintf(auth_note, sizeof(auth_note),
                "cache-authority-declined");
        }
#else
        (void)snprintf(auth_note, sizeof(auth_note),
            "cache-authority-declined");
#endif
    } else {
        out->authorized = 1;
    }
    (void)close(dir_fd);
    if (translator_digest(opts->argv0, runtime_digest) != 0) {
        cache_status(out, "declined", "translator-digest-unavailable");
        return 0;
    }
    to_hex(runtime_digest, sizeof(runtime_digest), out->runtime_hex,
        sizeof(out->runtime_hex));
    /* Pin the main image: borrowed fd stays open, otherwise open now. */
    if (image_fd >= 0) {
        struct stat check;
        if (fstat(image_fd, &check) != 0 ||
            !S_ISREG(check.st_mode)) {
            cache_status(out, "declined", "main-image-not-regular");
            return 0;
        }
        main_fd = image_fd;
        main_before = check;
    } else {
        if (image_path == NULL) {
            cache_status(out, "declined", "no-main-image");
            return 0;
        }
        main_fd = open(image_path, O_RDONLY | O_CLOEXEC);
        if (main_fd < 0 || fstat(main_fd, &main_before) != 0 ||
            !S_ISREG(main_before.st_mode)) {
            if (main_fd >= 0) {
                (void)close(main_fd);
            }
            cache_status(out, "declined", "cannot-open-main-image");
            return 0;
        }
        main_owned = 1;
    }
    /* Input digest: main bytes, plus the resolved PT_INTERP bytes for
     * dynamic images (both pinned via pread, section 5.2). Lengths come
     * from fstat; hash_fd re-checks stability after streaming. */
    memset(interp, 0, sizeof(interp));
    rc = sparc64_interp_read_path(main_fd, interp, sizeof(interp));
    if (rc == 0) {
        int ifd;
        memset(resolved, 0, sizeof(resolved));
        if (sparc64_interp_resolve(interp, opts->sysroot, resolved,
                sizeof(resolved)) != 0) {
            if (main_owned) {
                (void)close(main_fd);
            }
            cache_status(out, "declined", "input-digest-unavailable");
            return 0;
        }
        ifd = open(resolved, O_RDONLY | O_CLOEXEC);
        if (ifd < 0 || fstat(ifd, &interp_before) != 0 ||
            !S_ISREG(interp_before.st_mode)) {
            if (ifd >= 0) {
                (void)close(ifd);
            }
            if (main_owned) {
                (void)close(main_fd);
            }
            cache_status(out, "declined", "input-digest-unavailable");
            return 0;
        }
        out->has_interp = 1;
        sparc64_sha256_init(&ctx);
        sparc64_sha256_update(&ctx, dynamic_domain,
            sizeof(dynamic_domain) - 1U);
        put_le64(lengths, (uint64_t)main_before.st_size);
        put_le64(lengths + 8, (uint64_t)interp_before.st_size);
        sparc64_sha256_update(&ctx, lengths, sizeof(lengths));
        if (hash_fd(main_fd, &main_before, &ctx, &main_length) != 0 ||
            hash_fd(ifd, &interp_before, &ctx, &interp_length) != 0) {
            (void)close(ifd);
            if (main_owned) {
                (void)close(main_fd);
            }
            cache_status(out, "declined", "input-digest-unavailable");
            return 0;
        }
        (void)close(ifd);
    } else if (rc == -ENOENT) {
        sparc64_sha256_init(&ctx);
        if (hash_fd(main_fd, &main_before, &ctx, &main_length) != 0) {
            if (main_owned) {
                (void)close(main_fd);
            }
            cache_status(out, "declined", "input-digest-unavailable");
            return 0;
        }
    } else {
        if (main_owned) {
            (void)close(main_fd);
        }
        cache_status(out, "declined", "input-digest-unavailable");
        return 0;
    }
    if (main_owned) {
        (void)close(main_fd);
        main_fd = -1;
    }
    sparc64_sha256_finish(&ctx, input_digest);
    to_hex(input_digest, sizeof(input_digest), out->input_hex,
        sizeof(out->input_hex));
    spans[0].bytes = emitter_tag;
    spans[0].size = sizeof(emitter_tag) - 1U;
    spans[1].bytes = runtime_digest;
    spans[1].size = sizeof(runtime_digest);
    if (sparc64_aot_sha256_spans(spans, 2, emitter_digest) != 0) {
        cache_status(out, "declined", "emitter-digest-unavailable");
        return 0;
    }
    /* Cache key binds runtime, input, emitter, and the guest/host page
     * profile (8192 guest, host sysconf). The backend stays excluded
     * from the build (frozen Makefile), so admission always declines
     * here with the derived key attached. */
    sparc64_sha256_init(&ctx);
    sparc64_sha256_update(&ctx, key_tag, sizeof(key_tag) - 1U);
    sparc64_sha256_update(&ctx, runtime_digest, sizeof(runtime_digest));
    sparc64_sha256_update(&ctx, input_digest, sizeof(input_digest));
    sparc64_sha256_update(&ctx, emitter_digest, sizeof(emitter_digest));
    {
        long host_page = sysconf(_SC_PAGESIZE);
        if (host_page <= 0) {
            host_page = 4096;
        }
        memcpy(profile, profile_tag, sizeof(profile_tag) - 1U);
        put_le64(profile + sizeof(profile_tag) - 1U, UINT64_C(8192));
        put_le64(profile + sizeof(profile_tag) + 7U,
            (uint64_t)host_page);
        sparc64_sha256_update(&ctx, profile,
            sizeof(profile_tag) - 1U + 16U);
    }
    sparc64_sha256_finish(&ctx, key);
    to_hex(key, sizeof(key), out->key_hex, sizeof(out->key_hex));
    if (out->authorized) {
        cache_status(out, "declined", "backend-not-linked");
    } else {
        cache_status(out, "declined", auth_note);
    }
    return 0;
}

/* Family control verification lives in src/os/host_contract_family.c
 * (Wave U1 lightweight Provider-A control, replacing the heavy
 * rv_family_create-based broker). sparc64_host_family_verify keeps the
 * exact selftest diagnostics. */

/* ---- --selftest-host ----------------------------------------------------- */

static int selftest_auxv(void)
{
#if defined(__linux__)
    int present = 0;
    int fd_value = -1;
    int key_seen = 0;
    uint8_t raw[4096];
    uint64_t words[512];
    size_t total = 0;
    size_t i;
    int fd = open("/proc/self/auxv", O_RDONLY | O_CLOEXEC);
    ssize_t got;
    if (fd < 0) {
        (void)printf("sparc64rt: selftest auxv=skip "
            "reason=no-proc-auxv\n");
        return 0;
    }
    for (;;) {
        if (total >= sizeof(raw)) {
            break;
        }
        got = read(fd, raw + total, sizeof(raw) - total);
        if (got < 0 && errno == EINTR) {
            continue;
        }
        if (got <= 0) {
            break;
        }
        total += (size_t)got;
    }
    (void)close(fd);
    if (total < 16U || (total % 16U) != 0U ||
        total / 8U > sizeof(words) / sizeof(words[0])) {
        (void)printf("sparc64rt: selftest auxv=FAIL reason=short\n");
        return -1;
    }
    for (i = 0; i < total / 8U; i++) {
        uint64_t word = 0;
        unsigned b;
        for (b = 0; b < 8U; b++) {
            word |= (uint64_t)raw[i * 8U + b] << (8U * b);
        }
        words[i] = word;
    }
    for (i = 0; i + 1U < total / 8U; i += 2U) {
        if (words[i] == (uint64_t)AT_EXECFD) {
            key_seen = 1;
        }
        if (words[i] == (uint64_t)AT_NULL) {
            break;
        }
    }
    sparc64_host_execfd_probe(&present, &fd_value);
    (void)fd_value;
    if (key_seen != present) {
        (void)printf("sparc64rt: selftest auxv=FAIL reason=execfd-mismatch "
            "key=%d probe=%d\n", key_seen, present);
        return -1;
    }
    (void)printf("sparc64rt: selftest auxv=ok execfd-present=%d\n",
        present);
    return 0;
#else
    (void)printf("sparc64rt: selftest auxv=skip reason=non-linux\n");
    return 0;
#endif
}

static int selftest_digest(void)
{
    uint8_t digest[32];
    char hex[65];
    if (translator_digest(NULL, digest) != 0) {
        (void)printf("sparc64rt: selftest translator-digest=unavailable\n");
        return -1;
    }
    to_hex(digest, sizeof(digest), hex, sizeof(hex));
    hex[16] = '\0';
    (void)printf("sparc64rt: selftest translator-digest=%s\n", hex);
    return 0;
}

/* hyper-linux presence: /dev/a32host is the Class-A host-handshake
 * device; no native Linux host provides it (a hand-made node would
 * carry the wrong device numbers). This only tunes selftest *reporting*:
 * the CLI authority gates above stay unconditionally fail-closed until
 * the coordinator qualifies the host. */
static int selftest_on_hyper_linux(void)
{
#if defined(__linux__)
    return access("/dev/a32host", F_OK) == 0;
#else
    return 0;
#endif
}

static int selftest_authorities(void)
{
    char tmp[64];
    char shm[64];
    int fd = -1;
    int failures = 0;
    int hl = selftest_on_hyper_linux();
    if (hl) {
        (void)printf("sparc64rt: selftest host=hyper-linux\n");
    }
    (void)snprintf(tmp, sizeof(tmp), "/tmp/.sparc64rt-selftest-%ld-XXXXXX",
        (long)getpid());
    if (mkdtemp(tmp) == NULL) {
        (void)printf("sparc64rt: selftest authorities=FAIL "
            "reason=mkdtemp\n");
        return -1;
    }
    fd = open(tmp, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0) {
        (void)printf("sparc64rt: selftest authorities=FAIL "
            "reason=open\n");
        (void)rmdir(tmp);
        return -1;
    }
    /* The raw primitive reports what the host does. Native Linux must
     * fail the hyper-linux value closed; under hyper-linux the APFS ACL
     * facade may authorize (reported, never blessed: the CLI gate above
     * stays fail-closed until qualification). */
    if (sparc64_aot_authorize_fd(fd,
            true, SPARC64_AOT_AUTHORITY_HYPER_LINUX_APFS_ACL_V1)) {
        if (hl) {
            (void)printf("sparc64rt: selftest cache-authority "
                "hyper-linux-apfs-acl-v1=authorized-by-host "
                "(cli-gate-still-fail-closed)\n");
        } else {
            (void)printf("sparc64rt: selftest authorities=FAIL "
                "reason=hl-cache-authorized\n");
            failures++;
        }
    } else {
        (void)printf("sparc64rt: selftest cache-authority "
            "auto-dir=%s hyper-linux-apfs-acl-v1=fail-closed\n", tmp);
    }
    (void)close(fd);
    (void)rmdir(tmp);
    /* auto certifies tmpfs ACL absence only: prove it on /dev/shm. */
    (void)snprintf(shm, sizeof(shm),
        "/dev/shm/.sparc64rt-selftest-%ld-XXXXXX", (long)getpid());
    if (mkdtemp(shm) != NULL) {
        fd = open(shm, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (fd >= 0) {
            if (sparc64_aot_authorize_fd(fd, true,
                    SPARC64_AOT_AUTHORITY_AUTO)) {
                (void)printf("sparc64rt: selftest cache-authority "
                    "auto-tmpfs=%s admit\n", shm);
            } else {
                (void)printf("sparc64rt: selftest cache-authority "
                    "auto-tmpfs=%s decline\n", shm);
            }
            (void)close(fd);
        }
        (void)rmdir(shm);
    } else {
        (void)printf("sparc64rt: selftest cache-authority "
            "auto-tmpfs=skip\n");
    }
    return failures == 0 ? 0 : -1;
}

static int selftest_identity(void)
{
    int fd = open("/proc/self/exe", O_RDONLY | O_CLOEXEC);
    sparc64_file_identity_t identity;
    if (fd < 0) {
        (void)printf("sparc64rt: selftest file-identity=skip "
            "reason=no-proc-exe\n");
        return 0;
    }
    if (sparc64_file_identity_query(fd,
            SPARC64_FILE_IDENTITY_AUTO, &identity) != 0) {
        (void)printf("sparc64rt: selftest file-identity=FAIL "
            "reason=query\n");
        (void)close(fd);
        return -1;
    }
    (void)close(fd);
    (void)printf("sparc64rt: selftest file-identity=ok provider=%u "
        "known=%d\n", (unsigned)identity.provider,
        sparc64_file_identity_valid(&identity) ? 1 : 0);
    return 0;
}

int sparc64_host_selftest(void)
{
    int failures = 0;
    (void)printf("sparc64rt: selftest begin\n");
    if (selftest_auxv() != 0) {
        failures++;
    }
    if (selftest_digest() != 0) {
        failures++;
    }
    if (selftest_authorities() != 0) {
        failures++;
    }
    if (selftest_identity() != 0) {
        failures++;
    }
    if (sparc64_host_family_verify() != 0) {
        failures++;
    }
    (void)printf("sparc64rt: selftest %s\n",
        failures == 0 ? "PASS" : "FAIL");
    return failures == 0 ? 0 : 1;
}

/* ---- --stats ------------------------------------------------------------- */

void sparc64_host_report_stats(const sparc64_host_options_t *opts,
    const sparc64_host_cache_t *cache, const char *engine_name,
    int exit_code)
{
    struct rusage usage;
    unsigned long long syscalls = sparc64_syscalls_dispatched();
    unsigned long long utime = 0, stime = 0;
    long minflt = 0, majflt = 0, nvcsw = 0, nivcsw = 0;
    char translator[17];
    const char *sysroot;
    memset(&usage, 0, sizeof(usage));
    if (getrusage(RUSAGE_SELF, &usage) == 0) {
        utime = (unsigned long long)usage.ru_utime.tv_sec * 1000000ULL +
            (unsigned long long)usage.ru_utime.tv_usec;
        stime = (unsigned long long)usage.ru_stime.tv_sec * 1000000ULL +
            (unsigned long long)usage.ru_stime.tv_usec;
        minflt = usage.ru_minflt;
        majflt = usage.ru_majflt;
        nvcsw = usage.ru_nvcsw;
        nivcsw = usage.ru_nivcsw;
    }
    if (cache != NULL && cache->runtime_hex[0] != '\0') {
        memcpy(translator, cache->runtime_hex, 16);
        translator[16] = '\0';
    } else {
        memcpy(translator, "unavailable", 12);
    }
    sysroot = (opts != NULL && opts->sysroot != NULL) ? opts->sysroot :
        "(container-root)";
    (void)fprintf(stderr,
        "sparc64rt: stats engine=%s exit=%d guest_syscalls=%llu "
        "utime_us=%llu stime_us=%llu minflt=%ld majflt=%ld nvcsw=%ld "
        "nivcsw=%ld sysroot=%s cache=%s reason=%s key=%s interp=%s "
        "translator=%s\n",
        engine_name, exit_code, syscalls, utime, stime, minflt, majflt,
        nvcsw, nivcsw, sysroot,
        (cache != NULL) ? cache->status : "unused",
        (cache != NULL && cache->reason[0] != '\0') ? cache->reason :
            "no-cache-dir",
        (cache != NULL && cache->key_hex[0] != '\0') ? cache->key_hex :
            "-",
        (cache != NULL && cache->has_interp) ? "yes" : "no",
        translator);
}
