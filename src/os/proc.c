/*
 * src/os/proc.c — Process lifecycle syscalls (Phase 4, lane L4c)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * fork/vfork/clone-noVM via host fork() (copy-on-write snapshot of the
 * whole guest space, no family/mm protocol needed while single
 * threaded), execve via the exported guest_run.c loader entry, wait4/
 * waitid via host waitpid/waitid, pipe/pipe2/dup via host fds. SPARC
 * register conventions are oracle-grounded (qemu-sparc64 probes):
 * fork child %o0=0/%o1=1, parent %o0=pid/%o1=0; pipe(42) returns fds in
 * %o0/%o1; pipe2(321) is (pipefd_va, flags). Handlers set %o1 directly
 * and return the %o0 value for the dual-carry commit.
 */

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "core/cpu.h"
#include "os/guest_proc.h"
#include "os/guest_run_priv.h"
#include "os/proc.h"
#include "os/sysmem_file.h"
#include "os/guest_interp_map.h"

#include <unistd.h>
#include "dbt/mem_sites.h"
#include "os/sync_sig.h"
#include "os/syscalls_ext.h"

/* Exposed by the translator runtime (musl/static libc): build_stack
 * consumes it for the initial environment, and execve swaps it for the
 * guest-supplied envp across the reload. */
extern char **environ;

/* Clone flag subset (arch-generic Linux values, same on SPARC). */
#define PROC_CLONE_VM 0x100U
#define PROC_CLONE_SIGHAND 0x800U
#define PROC_CLONE_THREAD 0x10000U
#define PROC_CLONE_SETTLS 0x80000U
#define PROC_CLONE_PARENT_SETTID 0x10U
#define PROC_CLONE_CHILD_SETTID 0x1000000U
#define PROC_CLONE_CHILD_CLEARTID 0x200000U

/* SPARC signal numbers and pipe2/dup3 flag values (SP_O_* in
 * syscalls_ext.c; O_CLOEXEC grounded by an oracle dup3 trace). */
#define PROC_SPARC_SIGCHLD 20
#define PROC_O_CLOEXEC 0x400000U
#define PROC_O_NONBLOCK 0x4000U
#define PROC_O_DIRECT 0x100000U

/* Internal child table: host pids created by guest fork/clone-noVM.
 * wait4/waitid validate positive pids against it (ECHILD otherwise).
 * Single-threaded lane: no locking; lane L4b serializes when threads
 * arrive. execve keeps the table (children survive exec). */
#define PROC_MAX_CHILDREN 64U

static long proc_children[PROC_MAX_CHILDREN];
static unsigned proc_nchildren = 0U;

static void proc_note_child(long pid)
{
    if (proc_nchildren < (unsigned)PROC_MAX_CHILDREN) {
        proc_children[proc_nchildren] = pid;
        proc_nchildren++;
    }
}

static int proc_known_child(long pid)
{
    unsigned i;
    for (i = 0U; i < proc_nchildren; i++) {
        if (proc_children[i] == pid) {
            return 1;
        }
    }
    return 0;
}

static void proc_forget_child(long pid)
{
    unsigned i;
    unsigned j;
    for (i = 0U; i < proc_nchildren; i++) {
        if (proc_children[i] == pid) {
            for (j = i; j + 1U < proc_nchildren; j++) {
                proc_children[j] = proc_children[j + 1U];
            }
            proc_nchildren--;
            return;
        }
    }
}

/* Store one guest-BE int32; -EFAULT when the guest word is unmapped. */
static long proc_store_be32(const sparc64_syscall_mem_t *mem, uint64_t va,
    uint32_t v)
{
    uint8_t b[4];
    if (mem == NULL) {
        return -EFAULT;
    }
    l2a_put_be32(b, v);
    if (!mem->prepare_write(mem->context, va, (uint64_t)sizeof(b))) {
        return -EFAULT;
    }
    if (!mem->write(mem->context, va, b, (uint64_t)sizeof(b))) {
        return -EFAULT;
    }
    return 0;
}

/* Shared fork body: host fork() snapshots translator + guest (CoW).
 * Parent: %o1 = 0, returns the child pid. Child: %o1 = 1, returns 0.
 * Honors the SETTID stores when requested (BE pid_t words). */
static long proc_do_fork(sparc64_ctx_t *ctx,
    const sparc64_syscall_mem_t *mem, uint64_t parent_tid_va,
    uint64_t child_tid_va, uint64_t set_flags)
{
    pid_t pid;
    long self;
    if (ctx == NULL || mem == NULL) {
        return -EFAULT;
    }
    /* Flush userspace stdio before duplicating the address space so
     * buffered guest output is not printed twice. */
    (void)fflush(NULL);
    pid = fork();
    if (pid < 0) {
        return -(long)errno;
    }
    self = (long)((pid == 0) ? getpid() : pid);
    if (pid == 0) {
        long rc = 0;
        /* A fresh child has no children of its own. */
        proc_nchildren = 0U;
        /* Drop the inherited Soft-TLB: its addends address the
         * parent's heap backings, which munmap may free and reuse.
         * Misses re-resolve against the child's (initially shared)
         * mappings, so this is pure correctness, not a slow path. */
        sparc64_tlb_init();
        ctx->r[SPARC64_O1] = UINT64_C(1);
        if ((set_flags & (uint64_t)PROC_CLONE_CHILD_SETTID) != UINT64_C(0) &&
            child_tid_va != UINT64_C(0)) {
            rc = proc_store_be32(mem, child_tid_va, (uint32_t)self);
        }
        /* CLEARTID without threads: recorded nowhere to clear on exit
         * (no futex waiter can exist yet); documented, harmless. */
        return rc;
    }
    proc_note_child((long)pid);
    ctx->r[SPARC64_O1] = UINT64_C(0);
    if ((set_flags & (uint64_t)PROC_CLONE_PARENT_SETTID) != UINT64_C(0) &&
        parent_tid_va != UINT64_C(0)) {
        long rc = proc_store_be32(mem, parent_tid_va, (uint32_t)self);
        if (rc != 0) {
            return rc;
        }
    }
    return (long)pid;
}

long sparc64_proc_fork(sparc64_ctx_t *ctx,
    const sparc64_syscall_mem_t *mem)
{
    return proc_do_fork(ctx, mem, UINT64_C(0), UINT64_C(0), UINT64_C(0));
}

long sparc64_proc_vfork(sparc64_ctx_t *ctx,
    const sparc64_syscall_mem_t *mem)
{
    /* vfork = fork; the guest is expected to execve immediately. */
    return proc_do_fork(ctx, mem, UINT64_C(0), UINT64_C(0), UINT64_C(0));
}

long sparc64_proc_clone(sparc64_ctx_t *ctx, const sparc64_syscall_mem_t *mem,
    uint64_t flags, uint64_t stack_va, uint64_t parent_tid_va,
    uint64_t child_tid_va, uint64_t tls_va)
{
    uint64_t set_flags;
    (void)stack_va;
    (void)tls_va;
    if ((flags & (uint64_t)(PROC_CLONE_VM | PROC_CLONE_THREAD |
            PROC_CLONE_SIGHAND | PROC_CLONE_SETTLS)) != UINT64_C(0)) {
        /* Host-thread-backed threads belong to lane L4b. */
        return -EINVAL;
    }
    set_flags = flags & (uint64_t)(PROC_CLONE_PARENT_SETTID |
        PROC_CLONE_CHILD_SETTID | PROC_CLONE_CHILD_CLEARTID);
    return proc_do_fork(ctx, mem, parent_tid_va, child_tid_va, set_flags);
}

/* Close every CLOEXEC fd >= 3 (execve semantics), except the
 * translator-retained file-mapping descriptors (S64-R4-7: those stay
 * open across the sweep and are released with the replaced address
 * space instead). Portable fcntl-probe loop; no close_range
 * dependency. Runs only after the target binary validated and the new
 * image committed, never before a potentially failing execve. */
static void proc_close_cloexec(void)
{
    long maxfd = sysconf(_SC_OPEN_MAX);
    long fd;
    if (maxfd < 0L || maxfd > 1048576L) {
        maxfd = 1024L;
    }
    for (fd = 3L; fd < maxfd; fd++) {
        int flags = fcntl((int)fd, F_GETFD);
        if (flags >= 0 && (flags & FD_CLOEXEC) != 0 &&
            !sparc64_sysmem_is_retained_fd((int)fd)) {
            (void)close((int)fd);
        }
    }
}

/* Copy one NUL-terminated guest string into `out` (cap bytes incl.
 * the NUL). Chunked reads stop at mapping holes: a chunk that faults
 * is retried byte-wise, so strings ending just before an unmapped page
 * (argv/env at the stack top) still copy; a fault with no NUL seen yet
 * is a genuine -EFAULT, matching the kernel. Overlong strings read
 * as -E2BIG. */
static long proc_copy_string(const sparc64_syscall_mem_t *mem, uint64_t va,
    char *out, uint64_t cap)
{
    uint64_t done = 0U;
    uint8_t chunk[256];
    if (cap == 0U) {
        return -E2BIG;
    }
    if (l2a_range_ok(va, 1U) != 0) {
        return -EFAULT;
    }
    while (done < cap) {
        uint64_t want = cap - done;
        uint64_t i;
        if (want > (uint64_t)sizeof(chunk)) {
            want = (uint64_t)sizeof(chunk);
        }
        if (l2a_range_ok(va + done, want) != 0U) {
            out[done] = '\0';
            return -EFAULT;
        }
        if (mem->read(mem->context, va + done, chunk, want)) {
            for (i = 0U; i < want; i++) {
                out[done] = (char)chunk[i];
                done++;
                if (chunk[i] == 0U) {
                    return 0;
                }
                if (done == cap) {
                    out[cap - 1U] = '\0';
                    return -E2BIG;
                }
            }
            continue;
        }
        /* Chunk crossed an unmapped hole: finish byte-wise from the
         * same point. */
        for (i = 0U; i < want; i++) {
            uint8_t c = 0U;
            if (l2a_range_ok(va + done, 1U) != 0) {
                out[done] = '\0';
                return -EFAULT;
            }
            if (!mem->read(mem->context, va + done, &c, 1U)) {
                out[done] = '\0';
                return -EFAULT;
            }
            out[done] = (char)c;
            done++;
            if (c == 0U) {
                return 0;
            }
            if (done == cap) {
                out[cap - 1U] = '\0';
                return -E2BIG;
            }
        }
    }
    out[cap - 1U] = '\0';
    return -E2BIG;
}

/* Copy one guest argv/envp vector (NUL-terminated BE-VA array) into a
 * host NULL-terminated vector; each string is staged through `stage`
 * (PROC_MAX_ARG_STRLEN + 1 bytes) and then heap-duplicated. Caps the
 * entry count at `cap`; overlong strings read as -E2BIG. */
#define PROC_MAX_ARG_STRLEN 65536U

static long proc_copy_strvec(const sparc64_syscall_mem_t *mem,
    uint64_t vec_va, unsigned cap, char **out, unsigned *n_out, char *stage)
{
    unsigned n = 0U;
    uint64_t va = vec_va;
    for (;;) {
        uint8_t w[8];
        uint64_t p;
        long rc;
        size_t len;
        char *copy;
        if (n >= cap) {
            return -E2BIG;
        }
        if (!mem->read(mem->context, va, w, (uint64_t)sizeof(w))) {
            return -EFAULT;
        }
        p = l2a_get_be64(w);
        if (p == UINT64_C(0)) {
            break;
        }
        rc = proc_copy_string(mem, p, stage,
            (uint64_t)PROC_MAX_ARG_STRLEN + UINT64_C(1));
        if (rc != 0) {
            return rc;
        }
        len = strlen(stage) + 1U;
        copy = (char *)malloc(len);
        if (copy == NULL) {
            return -ENOMEM;
        }
        memcpy(copy, stage, len);
        out[n] = copy;
        n++;
        va += UINT64_C(8);
    }
    out[n] = NULL;
    *n_out = n;
    return 0;
}

static void proc_free_vec(char **vec, unsigned n)
{
    while (n != 0U) {
        n--;
        free(vec[n]);
        vec[n] = NULL;
    }
}

/* ELF machine check on an open fd (first 20 bytes). Returns 1 for
 * SPARC V9 (guest-loadable), 0 otherwise (host decides). */
static int proc_fd_is_sparc(int fd)
{
    uint8_t head[20];
    uint16_t mach;
    ssize_t n = read(fd, head, sizeof(head));
    if (n != (ssize_t)sizeof(head) || memcmp(head, "\177ELF", 4) != 0) {
        return 0;
    }
    if (head[5] == 1U) {
        mach = (uint16_t)head[18] | ((uint16_t)head[19] << 8);
    } else if (head[5] == 2U) {
        mach = ((uint16_t)head[18] << 8) | (uint16_t)head[19];
    } else {
        return 0;
    }
    return mach == (uint16_t)43;
}

int sparc64_proc_open_exec(void *guest, const char *path,
    char *img_path, const char **opened_path)
{
    const char *use = path;
    int fd;
    if (guest == NULL || path == NULL || img_path == NULL ||
            opened_path == NULL) {
        return -EFAULT;
    }
    if (strcmp(path, "/proc/self/exe") == 0) {
        use = sparc64_guest_proc_exec_path(guest);
        if (use == NULL) {
            return -ENOENT;
        }
    } else if (path[0] == '/') {
        if (sparc64_interp_resolve(path, getenv("SPARC64RT_SYSROOT"),
                img_path, SPARC64RT_INTERP_PATH_MAX) != 0) {
            return -ENAMETOOLONG;
        }
        fd = open(img_path, O_RDONLY | O_CLOEXEC);
        if (fd >= 0) {
            *opened_path = img_path;
            return fd;
        }
        /* Sysroot miss: a raw SPARC image still guest-loads (qemu
         * -L fallback); anything else is the host's call and is
         * decided by the execve site. */
        fd = open(path, O_RDONLY | O_CLOEXEC);
        if (fd < 0) {
            return -errno;
        }
        if (!proc_fd_is_sparc(fd)) {
            (void)close(fd);
            return -ENOENT;
        }
        *opened_path = path;
        return fd;
    }
    fd = open(use, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        return -errno;
    }
    *opened_path = use;
    return fd;
}

/* Host-native exec predicate (qemu parity): absolute guest path,
 * sysroot resolution misses, raw file exists and is not a SPARC ELF
 * (host binary, script, or foreign image). The forked guest child is
 * then replaced by the host program, the parent wait4s and continues
 * exactly like under qemu-sparc64 -L. */
static int proc_should_host_exec(const char *path)
{
    char resolved[SPARC64RT_INTERP_PATH_MAX];
    int fd;
    int sparc;
    if (path == NULL || path[0] != '/' ||
            strcmp(path, "/proc/self/exe") == 0) {
        return 0;
    }
    if (sparc64_interp_resolve(path, getenv("SPARC64RT_SYSROOT"),
            resolved, sizeof(resolved)) != 0) {
        return 0;
    }
    fd = open(resolved, O_RDONLY | O_CLOEXEC);
    if (fd >= 0) {
        (void)close(fd);
        return 0;
    }
    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        return 0;
    }
    sparc = proc_fd_is_sparc(fd);
    (void)close(fd);
    return !sparc;
}

long sparc64_proc_execve(sparc64_ctx_t *ctx, const sparc64_syscall_mem_t *mem,
    uint64_t path_va, uint64_t argv_va, uint64_t envp_va)
{
    guest_state_t *g;
    char path[4096];
    char *argv[257];
    char *envp[513];
    char *stage = NULL;
    char **saved_environ;
    unsigned argc = 0U;
    unsigned envc = 0U;
    long rc;
    int erc;
    if (ctx == NULL || mem == NULL) {
        return -EFAULT;
    }
    g = (guest_state_t *)mem->context;
    if (g == NULL) {
        return -EFAULT;
    }
    stage = (char *)malloc((size_t)PROC_MAX_ARG_STRLEN + 1U);
    if (stage == NULL) {
        return -ENOMEM;
    }
    memset(argv, 0, sizeof(argv));
    memset(envp, 0, sizeof(envp));
    rc = proc_copy_string(mem, path_va, path, (uint64_t)sizeof(path));
    if (rc == (long)-E2BIG) {
        rc = -ENAMETOOLONG;
    }
    if (rc == 0) {
        rc = proc_copy_strvec(mem, argv_va, 256U, argv, &argc, stage);
    }
    if (rc == 0) {
        rc = proc_copy_strvec(mem, envp_va, 512U, envp, &envc, stage);
    }
    free(stage);
    stage = NULL;
    if (rc != 0) {
        proc_free_vec(argv, argc);
        proc_free_vec(envp, envc);
        return rc;
    }
    if (argc == 0U) {
        proc_free_vec(argv, argc);
        proc_free_vec(envp, envc);
        return -EFAULT;
    }
    /* qemu parity: sysroot misses for non-SPARC host binaries run
     * natively (the forked guest child is replaced; the parent
     * wait4s and continues). Host execve performs its own atomic
     * CLOEXEC handling, so no sweep runs here: a failed execve must
     * destroy no guest descriptor (S64-R4-7). Only returns on
     * host-exec failure. */
    if (proc_should_host_exec(path)) {
        long erc;
        (void)execve(path, argv, envp);
        erc = -(long)errno;
        proc_free_vec(argv, argc);
        proc_free_vec(envp, envc);
        return erc;
    }
    /* build_stack consumes the translator's environ for the new stack:
     * swap in the guest envp across the reload, then restore. */
    saved_environ = environ;
    environ = envp;
    erc = sparc64_guest_exec_image(g, ctx, path, argv);
    environ = saved_environ;
    proc_free_vec(argv, argc);
    proc_free_vec(envp, envc);
    if (erc != 0) {
        return (long)erc;
    }
    /* Fresh image: caught handlers return to SIG_DFL while ignored
     * dispositions, the blocked mask, and pending signals survive the
     * replacement (Linux execve semantics); brk/tids reset, the host
     * pid is kept. Robust/futex state persists (lane L4b owns it).
     * S64-R4-7: the image committed, so the guest CLOEXEC sweep runs
     * now (skipping translator-retained mapping fds) and the replaced
     * address space's retained backing state is released. */
    proc_close_cloexec();
    sysmem_file_drop_all();
    sparc64_sync_sig_exec_reset();
    return 0;
}

/* Guest struct rusage: 2 x BE timeval + 14 x BE long (Linux LP64
 * layout, identical on SPARC64 and AArch64 hosts). */
#define PROC_RUSAGE_SIZE 144U

static long proc_store_rusage(const sparc64_syscall_mem_t *mem,
    uint64_t va, const struct rusage *ru)
{
    uint8_t b[PROC_RUSAGE_SIZE];
    unsigned i = 0U;
    int64_t secs[2];
    int64_t usecs[2];
    int64_t longs[14];
    if (mem == NULL || ru == NULL) {
        return -EFAULT;
    }
    secs[0] = (int64_t)ru->ru_utime.tv_sec;
    usecs[0] = (int64_t)ru->ru_utime.tv_usec;
    secs[1] = (int64_t)ru->ru_stime.tv_sec;
    usecs[1] = (int64_t)ru->ru_stime.tv_usec;
    longs[0] = (int64_t)ru->ru_maxrss;
    longs[1] = (int64_t)ru->ru_ixrss;
    longs[2] = (int64_t)ru->ru_idrss;
    longs[3] = (int64_t)ru->ru_isrss;
    longs[4] = (int64_t)ru->ru_minflt;
    longs[5] = (int64_t)ru->ru_majflt;
    longs[6] = (int64_t)ru->ru_nswap;
    longs[7] = (int64_t)ru->ru_inblock;
    longs[8] = (int64_t)ru->ru_oublock;
    longs[9] = (int64_t)ru->ru_msgsnd;
    longs[10] = (int64_t)ru->ru_msgrcv;
    longs[11] = (int64_t)ru->ru_nsignals;
    longs[12] = (int64_t)ru->ru_nvcsw;
    longs[13] = (int64_t)ru->ru_nivcsw;
    memset(b, 0, sizeof(b));
    l2a_put_be64(b, (uint64_t)secs[0]);
    l2a_put_be64(b + 8U, (uint64_t)usecs[0]);
    l2a_put_be64(b + 16U, (uint64_t)secs[1]);
    l2a_put_be64(b + 24U, (uint64_t)usecs[1]);
    for (i = 0U; i < 14U; i++) {
        l2a_put_be64(b + 32U + 8U * i, (uint64_t)longs[i]);
    }
    if (!mem->prepare_write(mem->context, va, (uint64_t)sizeof(b))) {
        return -EFAULT;
    }
    if (!mem->write(mem->context, va, b, (uint64_t)sizeof(b))) {
        return -EFAULT;
    }
    return 0;
}

long sparc64_proc_wait4(sparc64_ctx_t *ctx, const sparc64_syscall_mem_t *mem,
    uint64_t pid, uint64_t status_va, uint64_t options, uint64_t rusage_va)
{
    pid_t hp = (pid_t)(int64_t)pid;
    int opts = (int)(options & UINT64_C(0xffffffff));
    struct rusage ru;
    struct rusage *rup = NULL;
    int st = 0;
    pid_t r;
    long rc;
    (void)ctx;
    if (mem == NULL) {
        return -EFAULT;
    }
    if (hp > 0 && !proc_known_child((long)hp)) {
        return -ECHILD;
    }
    if (rusage_va != UINT64_C(0)) {
        memset(&ru, 0, sizeof(ru));
        rup = &ru;
    }
    r = wait4(hp, &st, opts, rup);
    if (r < 0) {
        return -(long)errno;
    }
    if (WIFEXITED(st) || WIFSIGNALED(st)) {
        proc_forget_child((long)r);
    }
    if (status_va != UINT64_C(0)) {
        rc = proc_store_be32(mem, status_va, (uint32_t)st);
        if (rc != 0) {
            return rc;
        }
    }
    if (rup != NULL) {
        rc = proc_store_rusage(mem, rusage_va, &ru);
        if (rc != 0) {
            return rc;
        }
    }
    return (long)r;
}

/* Guest siginfo128 for waitid (SPARC uapi layout): i32 signo/errno/
 * code @0/4/8, then the SIGCHLD fields pid@16, uid@20, status@24,
 * utime@32, stime@40 (BE), zero tail. */
#define PROC_SIGINFO_SIZE 128U

static long proc_store_waitid(const sparc64_syscall_mem_t *mem,
    uint64_t va, const siginfo_t *si)
{
    uint8_t b[PROC_SIGINFO_SIZE];
    if (mem == NULL || si == NULL) {
        return -EFAULT;
    }
    memset(b, 0, sizeof(b));
    l2a_put_be32(b, (uint32_t)PROC_SPARC_SIGCHLD);
    l2a_put_be32(b + 4U, (uint32_t)si->si_errno);
    l2a_put_be32(b + 8U, (uint32_t)si->si_code);
    l2a_put_be32(b + 16U, (uint32_t)si->si_pid);
    l2a_put_be32(b + 20U, (uint32_t)si->si_uid);
    l2a_put_be32(b + 24U, (uint32_t)si->si_status);
#if defined(__linux__)
    l2a_put_be64(b + 32U, (uint64_t)si->si_utime);
    l2a_put_be64(b + 40U, (uint64_t)si->si_stime);
#else
    /* macOS siginfo_t carries no SIGCHLD times: the BE slots stay zero,
     * matching the already-zeroed tail above. Layout unchanged. */
    l2a_put_be64(b + 32U, UINT64_C(0));
    l2a_put_be64(b + 40U, UINT64_C(0));
#endif
    if (!mem->prepare_write(mem->context, va, (uint64_t)sizeof(b))) {
        return -EFAULT;
    }
    if (!mem->write(mem->context, va, b, (uint64_t)sizeof(b))) {
        return -EFAULT;
    }
    return 0;
}

long sparc64_proc_waitid(sparc64_ctx_t *ctx, const sparc64_syscall_mem_t *mem,
    uint64_t idtype, uint64_t id, uint64_t infop_va, uint64_t options,
    uint64_t rusage_va)
{
    struct rusage ru;
    struct rusage *rup = NULL;
    siginfo_t si;
    int opts = (int)(options & UINT64_C(0xffffffff));
    int r;
    (void)ctx;
    if (mem == NULL) {
        return -EFAULT;
    }
    /* P_ALL = 0, P_PID = 1, P_PGID = 2. No P_PIDFD. */
    if (idtype > UINT64_C(2)) {
        return -EINVAL;
    }
    if (idtype == UINT64_C(1) && (int64_t)id > 0 &&
        !proc_known_child((long)(int64_t)id)) {
        return -ECHILD;
    }
    if (rusage_va != UINT64_C(0)) {
        memset(&ru, 0, sizeof(ru));
        rup = &ru;
    }
    memset(&si, 0, sizeof(si));
#if defined(__linux__) && defined(SYS_waitid)
    /* musl exposes only the 4-arg POSIX waitid; the kernel takes a
     * fifth rusage argument (as glibc passes on the oracle), so issue
     * it directly for exact per-child usage. (Linux only: the
     * syscall(2) function is unavailable on macOS, which takes the
     * libc waitid path below instead.) */
    r = (int)syscall((long)SYS_waitid, (idtype_t)idtype,
        (id_t)(int64_t)id, &si, opts, rup);
    if (r != 0) {
        return -(long)errno;
    }
#else
    if (rup != NULL) {
        return -ENOSYS;
    }
    r = waitid((idtype_t)idtype, (id_t)(int64_t)id, &si, opts);
    if (r != 0) {
        return -(long)errno;
    }
#endif
    /* Reaped unless the child only stopped/continued or WNOWAIT. */
    if ((opts & WNOWAIT) == 0 &&
        (si.si_code == CLD_EXITED || si.si_code == CLD_KILLED ||
         si.si_code == CLD_DUMPED)) {
        proc_forget_child((long)si.si_pid);
    }
    if (infop_va != UINT64_C(0)) {
        long rc = proc_store_waitid(mem, infop_va, &si);
        if (rc != 0) {
            return rc;
        }
    }
    if (rup != NULL) {
        long rc = proc_store_rusage(mem, rusage_va, rup);
        if (rc != 0) {
            return rc;
        }
    }
    return 0;
}

long sparc64_proc_pipe(sparc64_ctx_t *ctx,
    const sparc64_syscall_mem_t *mem)
{
    int fds[2];
    (void)mem;
    if (ctx == NULL) {
        return -EFAULT;
    }
    if (pipe(fds) != 0) {
        return -(long)errno;
    }
    ctx->r[SPARC64_O1] = (uint64_t)(uint32_t)fds[1];
    return (long)fds[0];
}

long sparc64_proc_pipe2(sparc64_ctx_t *ctx, const sparc64_syscall_mem_t *mem,
    uint64_t fds_va, uint64_t flags)
{
    uint8_t b[8];
    int hflags = 0;
    int fds[2] = { -1, -1 };
    (void)ctx;
    if (mem == NULL) {
        return -EFAULT;
    }
    if ((flags & ~(uint64_t)(PROC_O_CLOEXEC | PROC_O_NONBLOCK |
            PROC_O_DIRECT)) != UINT64_C(0)) {
        return -EINVAL;
    }
    if ((flags & (uint64_t)PROC_O_CLOEXEC) != UINT64_C(0)) {
#ifdef O_CLOEXEC
        hflags |= O_CLOEXEC;
#else
        return -EINVAL;
#endif
    }
    if ((flags & (uint64_t)PROC_O_NONBLOCK) != UINT64_C(0)) {
#ifdef O_NONBLOCK
        hflags |= O_NONBLOCK;
#else
        return -EINVAL;
#endif
    }
    if ((flags & (uint64_t)PROC_O_DIRECT) != UINT64_C(0)) {
#ifdef O_DIRECT
        hflags |= O_DIRECT;
#else
        return -EINVAL;
#endif
    }
#if defined(__linux__)
    if (pipe2(fds, hflags) != 0) {
        return -(long)errno;
    }
#else
    if (pipe(fds) != 0) {
        return -(long)errno;
    }
    if (hflags != 0 && (fcntl(fds[0], F_SETFL, hflags) != 0 ||
            fcntl(fds[1], F_SETFL, hflags) != 0)) {
        (void)close(fds[0]);
        (void)close(fds[1]);
        return -(long)errno;
    }
#endif
    l2a_put_be32(b, (uint32_t)fds[0]);
    l2a_put_be32(b + 4U, (uint32_t)fds[1]);
    if (!mem->prepare_write(mem->context, fds_va, (uint64_t)sizeof(b))) {
        (void)close(fds[0]);
        (void)close(fds[1]);
        return -EFAULT;
    }
    if (!mem->write(mem->context, fds_va, b, (uint64_t)sizeof(b))) {
        (void)close(fds[0]);
        (void)close(fds[1]);
        return -EFAULT;
    }
    return 0;
}

long sparc64_proc_dup(uint64_t fd)
{
    int r = dup((int)fd);
    return (r < 0) ? -(long)errno : (long)r;
}

long sparc64_proc_dup2(uint64_t oldfd, uint64_t newfd)
{
    int r = dup2((int)oldfd, (int)newfd);
    return (r < 0) ? -(long)errno : (long)r;
}

long sparc64_proc_dup3(uint64_t oldfd, uint64_t newfd, uint64_t flags)
{
    int r;
    if (flags != UINT64_C(0) &&
        flags != (uint64_t)PROC_O_CLOEXEC) {
        return -EINVAL;
    }
#if defined(__linux__)
    r = dup3((int)oldfd, (int)newfd,
        (flags != UINT64_C(0)) ? O_CLOEXEC : 0);
    return (r < 0) ? -(long)errno : (long)r;
#else
    if (oldfd == newfd) {
        if (fcntl((int)oldfd, F_GETFD) < 0) {
            return -(long)errno;
        }
        return (long)newfd;
    }
    r = dup2((int)oldfd, (int)newfd);
    if (r < 0) {
        return -(long)errno;
    }
    if (flags != UINT64_C(0)) {
        int fdflags = fcntl(r, F_GETFD);
        if (fdflags < 0 || fcntl(r, F_SETFD, fdflags | FD_CLOEXEC) != 0) {
            return -(long)errno;
        }
    }
    return (long)r;
#endif
}
