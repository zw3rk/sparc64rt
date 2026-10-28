/* src/os/guest_proc.c — guest /proc/self emulation (Phase 5, L5a)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Synthetic /proc/self/{exe,maps,cmdline,stat,auxv}: exe resolves to
 * the guest argv[0] path (readlink) backed by the loaded host file
 * (open), maps reflects the translator's guest mapping (app + ld.so
 * spans, [stack], [heap], anon), auxv matches the initial-stack
 * bytes snapshotted at build. Read-only; anything else is -ENOENT.
 * Never touches x18 (pure C, no asm).
 */

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "core/cpu.h"
#include "os/darwin_compat.h"
#include "os/guest_proc.h"
#include "os/guest_run_priv.h"
#include "os/syscalls_ext.h"
#include "os/mem_space.h"

#define PROC_PATH_MAX 4096U
#define PROC_AT_FDCWD ((int64_t)-100)
#define PROC_MAX_ARGV 256U
#define PROC_MAX_ARG_STRLEN 65536U
#define PROC_MAX_STRING_BYTES ((uint64_t)131072)
#define PROC_MAX_AUXV 24U
#define PROC_MAX_SPANS 64U

struct sparc64_guest_proc {
    char load_path[PROC_PATH_MAX];
    char argv0[PROC_PATH_MAX];
    char *cmdline;
    size_t cmdline_len;
    uint64_t auxv_keys[PROC_MAX_AUXV];
    uint64_t auxv_vals[PROC_MAX_AUXV];
    unsigned auxv_n;
    uint64_t sp_biased;
    uint64_t stack_lo, stack_hi;
    uint64_t app_lo, app_hi;
    int have_app;
    struct {
        uint64_t lo, hi;
        char path[PROC_PATH_MAX];
    } spans[PROC_MAX_SPANS];
    unsigned nspans;
};

static guest_state_t *as_guest(void *guest)
{
    return (guest_state_t *)guest;
}

static void proc_free(guest_state_t *g)
{
    if (g != NULL && g->proc != NULL) {
        free(g->proc->cmdline);
        free(g->proc);
        g->proc = NULL;
    }
}

int sparc64_guest_proc_handles(const char *path)
{
    if (path == NULL) {
        return 0;
    }
    return strcmp(path, "/proc/self/exe") == 0 ||
        strcmp(path, "/proc/self/maps") == 0 ||
        strcmp(path, "/proc/self/cmdline") == 0 ||
        strcmp(path, "/proc/self/stat") == 0 ||
        strcmp(path, "/proc/self/auxv") == 0;
}

void sparc64_guest_proc_note_exec(void *guest, const char *load_path)
{
    guest_state_t *g = as_guest(guest);
    char abs_path[PROC_PATH_MAX];
    size_t len;
    if (g == NULL || load_path == NULL) {
        return;
    }
    /* Like the kernel (and the oracle), /proc/self/exe reports the
     * canonical absolute path: resolve a relative load path against
     * the translator's cwd (shared with the guest). */
    if (load_path[0] != '/') {
        char cwd[PROC_PATH_MAX];
        size_t clen = 0;
        if (getcwd(cwd, sizeof(cwd)) != NULL) {
            clen = strlen(cwd);
        }
        if (clen == 0U || clen + strlen(load_path) + 2U >
                (size_t)PROC_PATH_MAX) {
            return;
        }
        memcpy(abs_path, cwd, clen);
        abs_path[clen] = '/';
        {
            size_t llen = strlen(load_path) + 1U;
            memcpy(abs_path + clen + 1U, load_path, llen);
        }
        load_path = abs_path;
    }
    if (g->proc == NULL) {
        g->proc = (sparc64_guest_proc_t *)calloc(1, sizeof(*g->proc));
        if (g->proc == NULL) {
            return;
        }
    }
    len = strlen(load_path);
    if (len >= (size_t)PROC_PATH_MAX) {
        len = (size_t)PROC_PATH_MAX - 1U;
    }
    memcpy(g->proc->load_path, load_path, len);
    g->proc->load_path[len] = '\0';
}

const char *sparc64_guest_proc_exec_path(void *guest)
{
    guest_state_t *g = as_guest(guest);
    if (g == NULL || g->proc == NULL ||
            g->proc->load_path[0] == '\0') {
        return NULL;
    }
    return g->proc->load_path;
}

int sparc64_guest_proc_note_stack(void *guest, char **argv, uint64_t argc,
    const uint64_t *keys, const uint64_t *vals, unsigned nkeys,
    uint64_t sp_biased, uint64_t stack_lo, uint64_t stack_hi)
{
    guest_state_t *g = as_guest(guest);
    uint64_t total = 0, i;
    size_t off = 0;
    char *cmd = NULL;
    if (g == NULL || argv == NULL || keys == NULL || vals == NULL ||
        argc > (uint64_t)PROC_MAX_ARGV || nkeys > PROC_MAX_AUXV) {
        return -EINVAL;
    }
    for (i = 0; i < argc; i++) {
        size_t len;
        if (argv[i] == NULL) {
            return -EFAULT;
        }
        len = strlen(argv[i]);
        if (len > (size_t)PROC_MAX_ARG_STRLEN ||
            total > PROC_MAX_STRING_BYTES - (uint64_t)len - UINT64_C(1)) {
            return -E2BIG;
        }
        total += (uint64_t)len + UINT64_C(1);
    }
    cmd = (char *)malloc(total == 0U ? 1U : (size_t)total);
    if (cmd == NULL) {
        return -ENOMEM;
    }
    for (i = 0; i < argc; i++) {
        size_t len = strlen(argv[i]) + 1U;
        memcpy(cmd + off, argv[i], len);
        off += len;
    }
    if (g->proc == NULL) {
        g->proc = (sparc64_guest_proc_t *)calloc(1, sizeof(*g->proc));
        if (g->proc == NULL) {
            free(cmd);
            return -ENOMEM;
        }
    }
    free(g->proc->cmdline);
    g->proc->cmdline = cmd;
    g->proc->cmdline_len = (size_t)total;
    if (argc != 0U) {
        size_t len = strlen(argv[0]);
        if (len >= (size_t)PROC_PATH_MAX) {
            len = (size_t)PROC_PATH_MAX - 1U;
        }
        memcpy(g->proc->argv0, argv[0], len);
        g->proc->argv0[len] = '\0';
    } else {
        g->proc->argv0[0] = '\0';
    }
    for (i = 0; i < nkeys; i++) {
        g->proc->auxv_keys[i] = keys[i];
        g->proc->auxv_vals[i] = vals[i];
    }
    g->proc->auxv_n = nkeys;
    g->proc->sp_biased = sp_biased;
    g->proc->stack_lo = stack_lo;
    g->proc->stack_hi = stack_hi;
    return 0;
}

void sparc64_guest_proc_note_map(void *guest, uint64_t lo, uint64_t hi,
    const char *path)
{
    guest_state_t *g = as_guest(guest);
    size_t len;
    if (g == NULL || path == NULL || lo >= hi) {
        return;
    }
    if (g->proc == NULL) {
        g->proc = (sparc64_guest_proc_t *)calloc(1, sizeof(*g->proc));
        if (g->proc == NULL) {
            return;
        }
    }
    if (g->proc->nspans < PROC_MAX_SPANS) {
        unsigned k = g->proc->nspans++;
        g->proc->spans[k].lo = lo;
        g->proc->spans[k].hi = hi;
        len = strlen(path);
        if (len >= (size_t)PROC_PATH_MAX) {
            len = (size_t)PROC_PATH_MAX - 1U;
        }
        memcpy(g->proc->spans[k].path, path, len);
        g->proc->spans[k].path[len] = '\0';
    }
    /* The first logged file span is the app image (loaded before
     * ld.so): it anchors startcode/endcode in stat. */
    if (!g->proc->have_app && path[0] != '[') {
        g->proc->app_lo = lo;
        g->proc->app_hi = hi;
        g->proc->have_app = 1;
    } else if (g->proc->have_app && path[0] != '[' &&
        strcmp(path, g->proc->spans[0].path) == 0) {
        if (lo < g->proc->app_lo) {
            g->proc->app_lo = lo;
        }
        if (hi > g->proc->app_hi) {
            g->proc->app_hi = hi;
        }
    }
}

void sparc64_guest_proc_forget(void *guest)
{
    guest_state_t *g = as_guest(guest);
    if (g != NULL) {
        proc_free(g);
    }
}

/* ---- Content generators (deterministic across engines) ------------------ */

/* Coalesced region label: span path, [stack], [heap], or anon. */
static const char *region_label(const sparc64_guest_proc_t *proc,
    const guest_state_t *g, uint64_t start, uint64_t *offset)
{
    unsigned k;
    *offset = 0U;
    if (proc != NULL) {
        for (k = 0; k < proc->nspans; k++) {
            if (start >= proc->spans[k].lo && start < proc->spans[k].hi) {
                *offset = start - proc->spans[k].lo;
                return proc->spans[k].path;
            }
        }
        if (start >= proc->stack_lo && start < proc->stack_hi) {
            return "[stack]";
        }
    }
    if (g != NULL && g->brk_cur > g->brk_base && start >= g->brk_base &&
        start < g->brk_cur) {
        return "[heap]";
    }
    return "";
}

static char *gen_maps(const sparc64_guest_proc_t *proc,
    const guest_state_t *g, size_t *len_out)
{
    const sparc64_space_t *space = (g != NULL) ? &g->space : NULL;
    size_t cap, len = 0;
    char *buf;
    size_t n = 0;
    if (space == NULL) {
        return NULL;
    }
    cap = space->count * 160U + 4096U;
    if (cap < 4096U) {
        cap = 4096U;
    }
    buf = (char *)malloc(cap);
    if (buf == NULL) {
        return NULL;
    }
    while (n < space->count) {
        uint64_t start = space->pages[n].address;
        uint64_t end = start + SPARC64_PAGE_SIZE;
        unsigned int perms = space->pages[n].permissions;
        size_t m = n + 1U;
        char line[256];
        const char *label;
        uint64_t offset = 0;
        int wn;
        /* Coalesce adjacent pages with identical permissions. */
        while (m < space->count && space->pages[m].address == end &&
            space->pages[m].permissions == perms) {
            end += SPARC64_PAGE_SIZE;
            m++;
        }
        label = region_label(proc, g, start, &offset);
        wn = snprintf(line, sizeof(line),
            "%llx-%llx %c%c%c%c %08llx 00:00 0%s%s\n",
            (unsigned long long)start, (unsigned long long)end,
            (perms & SPARC64_MEM_READ) != 0U ? 'r' : '-',
            (perms & SPARC64_MEM_WRITE) != 0U ? 'w' : '-',
            (perms & SPARC64_MEM_EXEC) != 0U ? 'x' : '-',
            'p', (unsigned long long)offset,
            label[0] != '\0' ? " " : "", label);
        if (wn <= 0 || (size_t)wn >= sizeof(line) ||
            len + (size_t)wn + 1U > cap) {
            break;
        }
        memcpy(buf + len, line, (size_t)wn);
        len += (size_t)wn;
        n = m;
    }
    buf[len] = '\0';
    *len_out = len;
    return buf;
}

/* 52-field /proc/self/stat (Linux layout). Volatile fields (pid,
 * ppid, pgrp, session, startstack, vsize) are real; counters nobody
 * can observe deterministically stay zero/constant. */
static char *gen_stat(const sparc64_guest_proc_t *proc,
    const guest_state_t *g, size_t *len_out)
{
    const sparc64_space_t *space = (g != NULL) ? &g->space : NULL;
    char comm[16];
    char *buf;
    const char *base;
    size_t i;
    uint64_t vsize = 0, startstack = 0;
    uint64_t startcode = 0, endcode = 0;
    int wn;
    if (proc != NULL) {
        base = strrchr(proc->argv0, '/');
        base = (base != NULL) ? base + 1 : proc->argv0;
        for (i = 0; i < 15U && base[i] != '\0'; i++) {
            comm[i] = base[i];
        }
        comm[i] = '\0';
        startstack = proc->sp_biased + UINT64_C(2047) + UINT64_C(128);
    } else {
        comm[0] = '\0';
    }
    if (space != NULL) {
        vsize = (uint64_t)space->count * UINT64_C(4096);
    }
    if (proc != NULL && proc->have_app) {
        startcode = proc->app_lo;
        endcode = proc->app_hi;
    }
    buf = (char *)malloc(1024);
    if (buf == NULL) {
        return NULL;
    }
    /* Fields: pid comm state ppid pgrp session tty tpgid flags
     * minflt cminflt majflt cmajflt utime stime cutime cstime
     * priority nice threads itreal starttime vsize rss rsslim
     * startcode endcode startstack esp eip signal blocked sigign
     * sigcgt wchan nswap cnswap exit_signal processor rt_prio
     * policy blkio_ticks gtime cgtime start_data end_data start_brk
     * arg_start arg_end env_start env_end exit_code (51 values). */
    wn = snprintf(buf, 1024,
        "%d (%s) R %d %d %d %d %d %u "
        "%lu %lu %lu %lu %lu %lu %lu %lu "
        "%lu %lu %lu %lu "
        "%llu "
        "%lu %ld %lu "
        "%lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu "
        "%d %d %u %u "
        "%llu "
        "%lu %ld %lu %lu %lu %lu %lu %lu %lu %d\n",
        (int)getpid(), comm, (int)getppid(), (int)getpgrp(),
        (int)getsid(0), 0, 0, 0U,
        0UL, 0UL, 0UL, 0UL, 0UL, 0UL, 0UL, 0UL,
        20UL, 0UL, 1UL, 0UL,
        1ULL,
        (unsigned long)vsize, (long)(vsize / UINT64_C(4096)),
        18446744073709551615UL,
        (unsigned long)startcode, (unsigned long)endcode,
        (unsigned long)startstack, 0UL, 0UL, 0UL, 0UL, 0UL, 0UL,
        0UL, 0UL, 0UL,
        20, 0, 0U, 0U,
        0ULL,
        0UL, 0L, 0UL, 0UL,
        (unsigned long)((g != NULL) ? g->brk_base : 0U),
        0UL, 0UL, 0UL, 0UL, 0);
    if (wn <= 0 || (size_t)wn >= 1024U) {
        free(buf);
        return NULL;
    }
    *len_out = (size_t)wn;
    return buf;
}

/* Big-endian auxv image: snapshot pairs plus AT_NULL. */
static char *gen_auxv(const sparc64_guest_proc_t *proc, size_t *len_out)
{
    char *buf;
    size_t i;
    uint8_t *p;
    if (proc == NULL) {
        return NULL;
    }
    *len_out = ((size_t)proc->auxv_n + 1U) * 16U;
    buf = (char *)malloc(*len_out);
    if (buf == NULL) {
        return NULL;
    }
    p = (uint8_t *)buf;
    for (i = 0; i < proc->auxv_n; i++) {
        l2a_put_be64(p, proc->auxv_keys[i]);
        l2a_put_be64(p + 8U, proc->auxv_vals[i]);
        p += 16;
    }
    l2a_put_be64(p, UINT64_C(0));
    l2a_put_be64(p + 8U, UINT64_C(0));
    return buf;
}

/* ---- Synthetic fds ------------------------------------------------------ */

/* Fill a pipe with content and hand the read end to the guest;
 * write-end close failures still hand over what was written. */
static long pipe_content(const void *data, size_t len, int host_flags)
{
    int fds[2] = { -1, -1 };
#if defined(__linux__) && defined(O_CLOEXEC)
    if (pipe2(fds, ((host_flags & O_CLOEXEC) != 0) ? O_CLOEXEC : 0) != 0) {
        return -(long)errno;
    }
    if ((host_flags & O_NONBLOCK) != 0) {
        (void)fcntl(fds[0], F_SETFL, O_NONBLOCK);
    }
#else
    /* macOS has no pipe2(2): the compat shim applies CLOEXEC and
     * NONBLOCK itself, so nothing more to set here. */
    {
        int rc = rt_darwin_pipe2(fds,
            host_flags & (O_CLOEXEC | O_NONBLOCK));
        if (rc != 0) {
            return (long)rc;
        }
    }
#endif
    if (len != 0U) {
        size_t done = 0;
        while (done < len) {
            ssize_t got = write(fds[1], (const char *)data + done,
                len - done);
            if (got < 0) {
                if (errno == EINTR) {
                    continue;
                }
                break;
            }
            if (got == 0) {
                break;
            }
            done += (size_t)got;
        }
        if (done != len) {
            (void)close(fds[0]);
            (void)close(fds[1]);
            return -EIO;
        }
    }
    (void)close(fds[1]);
    return (long)fds[0];
}

long sparc64_guest_proc_openat(void *guest,
    const sparc64_syscall_mem_t *mem, const char *path, int host_flags)
{
    guest_state_t *g = as_guest(guest);
    sparc64_guest_proc_t *proc = (g != NULL) ? g->proc : NULL;
    int accmode;
    (void)mem;
    if (!sparc64_guest_proc_handles(path)) {
        return -ENOENT;
    }
    accmode = host_flags & (O_ACCMODE | O_PATH);
    if (accmode != O_RDONLY && accmode != O_PATH) {
        return -EACCES;
    }
    if ((host_flags & O_DIRECTORY) != 0) {
        return -ENOTDIR;
    }
#ifdef O_TMPFILE
    if ((host_flags & O_TMPFILE) == O_TMPFILE) {
        return -EINVAL;
    }
#endif
    if (strcmp(path, "/proc/self/exe") == 0) {
        int extra = 0;
        if (proc == NULL || proc->load_path[0] == '\0') {
            return -ENOENT;
        }
        if ((host_flags & O_NOFOLLOW) != 0) {
            return -ELOOP;
        }
        if (accmode == O_PATH) {
            extra = O_PATH;
        }
        if ((host_flags & O_CLOEXEC) != 0) {
            extra |= O_CLOEXEC;
        }
        if ((host_flags & O_NONBLOCK) != 0) {
            extra |= O_NONBLOCK;
        }
        {
            int fd = open(proc->load_path, O_RDONLY | extra);
            return (fd < 0) ? -(long)errno : (long)fd;
        }
    }
    if (strcmp(path, "/proc/self/cmdline") == 0) {
        if (proc == NULL || proc->cmdline == NULL) {
            return -ENOENT;
        }
        return pipe_content(proc->cmdline, proc->cmdline_len, host_flags);
    }
    if (strcmp(path, "/proc/self/auxv") == 0) {
        size_t len = 0;
        char *buf = gen_auxv(proc, &len);
        long rc;
        if (buf == NULL) {
            return -ENOENT;
        }
        rc = pipe_content(buf, len, host_flags);
        free(buf);
        return rc;
    }
    if (strcmp(path, "/proc/self/maps") == 0) {
        size_t len = 0;
        char *buf = gen_maps(proc, g, &len);
        long rc;
        if (buf == NULL) {
            return -ENOENT;
        }
        rc = pipe_content(buf, len, host_flags);
        free(buf);
        return rc;
    }
    {
        size_t len = 0;
        char *buf = gen_stat(proc, g, &len);
        long rc;
        if (buf == NULL) {
            return -ENOENT;
        }
        rc = pipe_content(buf, len, host_flags);
        free(buf);
        return rc;
    }
}

long sparc64_guest_proc_open(void *guest,
    const sparc64_syscall_mem_t *mem, uint64_t path_va, uint64_t flags,
    uint64_t mode)
{
    char path[PROC_PATH_MAX];
    long rc;
    int host_flags;
    uint64_t rest = flags & ~3U;
    size_t i;
    /* SPARC O_* subset accepted on synthetic paths (mirrors the
     * openat flag map in syscalls_ext.c). */
    static const struct {
        uint64_t guest;
        int host;
    } map[] = {
        { 0x0008U, O_APPEND }, { 0x4000U, O_NONBLOCK },
        { 0x8000U, O_NOCTTY }, { 0x10000U, O_DIRECTORY },
        { 0x20000U, O_NOFOLLOW }, { 0x400000U, O_CLOEXEC },
        { 0x1000000U, O_PATH },
    };
    (void)mode;
    rc = l2a_copy_cstring(mem, path_va, path, (uint64_t)PROC_PATH_MAX);
    if (rc != 0) {
        return rc;
    }
    if (!sparc64_guest_proc_handles(path)) {
        return -ENOENT;
    }
    if ((flags & (uint64_t)0x2010000U) == (uint64_t)0x2010000U) {
        return -EINVAL; /* SP_O_TMPFILE has no synthetic-file meaning. */
    }
    host_flags = (int)(flags & 3U);
    for (i = 0U; i < sizeof(map) / sizeof(map[0]); i++) {
        if ((rest & map[i].guest) != 0U) {
            host_flags |= map[i].host;
            rest &= ~map[i].guest;
        }
    }
    /* Tolerated without effect: sync/dsync, largefile, noatime,
     * direct. Anything else is -EINVAL. */
    rest &= ~(uint64_t)(0x802000U | 0x40000U | 0x200000U | 0x100000U);
    if (rest != 0U) {
        return -EINVAL;
    }
    return sparc64_guest_proc_openat(guest, mem, path, host_flags);
}

long sparc64_guest_proc_readlinkat(void *guest,
    const sparc64_syscall_mem_t *mem, uint64_t dirfd, uint64_t path_va,
    uint64_t buf_va, uint64_t bufsz)
{
    guest_state_t *g = as_guest(guest);
    char path[PROC_PATH_MAX];
    char host_buf[PROC_PATH_MAX];
    long rc = l2a_copy_cstring(mem, path_va, path,
        (uint64_t)PROC_PATH_MAX);
    size_t len;
    if (rc != 0) {
        return rc;
    }
    if (strcmp(path, "/proc/self/exe") == 0) {
        long stored;
        /* Like the kernel (and the oracle), readlink reports the
         * canonical absolute path, not argv[0] verbatim: ld.so's
         * _dl_get_origin asserts linkval[0] == '/' and computes
         * $ORIGIN from it. open() above serves the same load_path. */
        if (g == NULL || g->proc == NULL ||
                g->proc->load_path[0] == '\0') {
            return -ENOENT;
        }
        (void)dirfd;
        len = strlen(g->proc->load_path);
        if (len > (size_t)bufsz) {
            len = (size_t)bufsz;
        }
        /* readlink reports the byte count, not a status code. */
        stored = l2a_store_buf(mem, buf_va,
            (const uint8_t *)g->proc->load_path, (uint64_t)len);
        return (stored != 0) ? stored : (long)len;
    }
    if (sparc64_guest_proc_handles(path)) {
        return -EINVAL; /* Synthetic regular files, not links. */
    }
    if (bufsz == 0U) {
        return 0;
    }
    {
        int host_dirfd = ((int64_t)dirfd == PROC_AT_FDCWD) ? AT_FDCWD :
            (int)dirfd;
        ssize_t got = readlinkat(host_dirfd, path, host_buf,
            sizeof(host_buf));
        long stored;
        if (got < 0) {
            return -(long)errno;
        }
        len = (size_t)got;
        if (len > (size_t)bufsz) {
            len = (size_t)bufsz;
        }
        /* readlink reports the byte count, not a status code. */
        stored = l2a_store_buf(mem, buf_va, (const uint8_t *)host_buf,
            (uint64_t)len);
        return (stored != 0) ? stored : (long)len;
    }
}
