/*
 * src/os/syscalls_min.c — Phase-1 minimal SPARC64 Linux syscall layer
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Lane L1c owns this file (Phase 1, SPEC section 2.2). Implements the
 * Phase-1 syscall subset against the frozen src/os/syscall_nr.h:
 * exit(1), exit_group(188), read(3), write(4), brk(17), mmap(71),
 * munmap(73), mprotect(74), uname(189), set_tid_address(166).
 *
 * SPARC64 syscall convention (SPEC section 2.2, E02 oracle):
 *   number in %g1 (r[1]), args 1..6 in %o0..%o5 (r[8..13]).
 *   Success: clear BOTH carry bits (icc.C + xcc.C), %o0 = value.
 *   Error:   set BOTH carry bits, %o0 = positive SPARC errno.
 *   Always advance pc = npc; npc += 4.
 * Guest pointers are translated by the runner-supplied mem operations;
 * no host pointer ever leaks to the guest.
 *
 * Engine-loop contract (for the guest_run loop in src/os/guest_run.c):
 * sparc64_handle_syscall dispatches the number in %g1 and returns the
 * guest exit status for exit/exit_group (terminal;
 * sparc64_syscall_is_exit says so) or 0 otherwise. The loop treats
 * exit/exit_group as terminal instead of resuming at pc.
 *
 * NOTE on E02: the E02 oracle build observed only xcc.C moving across
 * ta 0x6d while icc.C was preserved. The frozen src/core/cpu.h contract
 * (both carry bits) governs this layer, so both bits move here; if the
 * coordinator reconciles the other way, only sparc64_commit changes.
 *
 * NOTE: _GNU_SOURCE must precede every #include (glibc latches the
 * feature set on first <features.h> inclusion; truncate/ftruncate
 * prototypes and struct st_ctim need the GNU spelling).
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <stdatomic.h>

/* glibc maps the compat names st_atime/st_mtime/st_ctime to the
 * st_*tim.tv_sec fields; that rewrite would corrupt the guest-layout
 * struct in sigframe_sparc64rt.h below (which spells the fields out),
 * and nothing in this TU needs the compat spellings. */
#ifdef st_atime
#undef st_atime
#endif
#ifdef st_mtime
#undef st_mtime
#endif
#ifdef st_ctime
#undef st_ctime
#endif

#include "core/cpu.h"
#include "os/proc.h"
#include "os/sigframe_sparc64rt.h"
#include "os/sync_sig.h"
#include "os/syscall_nr.h"
#include "os/syscalls_ext.h"
#include "os/syscalls_min.h"
#include "os/syscalls_sig.h"
#include "os/threads.h"

/* SPARC Linux prot/flag ABI (asm/mman.h, arch 64-bit). Defined locally so
 * this TU compiles identically on any build host. */
#define SPARC64_PROT_NONE 0U
#define SPARC64_MAP_SHARED 0x01U
#define SPARC64_MAP_PRIVATE 0x02U
#define SPARC64_MAP_FIXED 0x10U
#define SPARC64_MAP_ANONYMOUS 0x20U

/* Lane A2: guest mremap(250) lives in src/os/guest_run_sysmem.c (it
 * needs the space substrate); the truncate family below needs only the
 * host filesystem. Declared locally: the mem-op struct keeps no
 * mremap slot by design, so dispatch calls the runner directly with
 * the same context the do_* handlers receive. */
extern long sparc64_sysmem_mremap(void *context, uint64_t old_addr,
    uint64_t old_size, uint64_t new_size, unsigned flags,
    uint64_t new_addr);

/* Process-wide dispatch tally for --stats (Phase 6, L6a). Guest
 * execution is serialized under the big lock, but blocking syscalls
 * may run on worker threads, so the tally is atomic. */
/* Static storage is zero-initialized, so no explicit initializer is
 * needed (a file-scope compound literal is not a constant expression
 * under strict C11 and breaks the Darwin build). */
static _Atomic unsigned long long dispatched_total;

unsigned long long sparc64_syscalls_dispatched(void)
{
    return atomic_load(&dispatched_total);
}

static void note_dispatched(void)
{
    (void)atomic_fetch_add(&dispatched_total, 1ULL);
}

/* SPARC errnos are the asm-generic numbers except where arch/sparc
 * overrides them; ENOSYS is 90 on SPARC (E02), not asm-generic 38. Only
 * errnos this layer can produce are listed; anything else falls back to
 * the raw value, which is correct on the Linux host. */
uint64_t sparc64_host_errno_to_guest(long host_errno)
{
    switch (host_errno) {
    case EPERM: return 1U;
    case ENOENT: return 2U;
    case ESRCH: return 3U;
    case EINTR: return 4U;
    case EIO: return 5U;
    case ENXIO: return 6U;
    case E2BIG: return 7U;
    case ENOEXEC: return 8U;
    case EBADF: return 9U;
    case ECHILD: return 10U;
    case EAGAIN: return 11U;
    case ENOMEM: return 12U;
    case EACCES: return 13U;
    case EFAULT: return 14U;
    case EBUSY: return 16U;
    case EEXIST: return 17U;
    case ENODEV: return 19U;
    case ENOTDIR: return 20U;
    case EISDIR: return 21U;
    case EINVAL: return 22U;
    case ENFILE: return 23U;
    case EMFILE: return 24U;
    case ENOTTY: return 25U;
    case EFBIG: return 27U;
    case ENOSPC: return 28U;
    case ESPIPE: return 29U;
    case EROFS: return 30U;
    case EPIPE: return 32U;
    case ERANGE: return 34U;
    case ENAMETOOLONG: return 36U;
    case ENOSYS: return 90U;
    case ELOOP: return 40U;
    case EOVERFLOW: return 75U;
    default: break;
    }
    return (uint64_t)host_errno;
}

/* Host syscall result: negative errno on failure, else the value. Short
 * (partial) read/write counts are genuine results, not errors. */
static long host_ret(ssize_t n)
{
    return (n < 0) ? -(long)errno : (long)n;
}

/* Commit one handler result to %o0/ccr following the frozen dual-carry
 * convention: negative host errno fails with both carries set, anything
 * else succeeds with both carries clear (N/Z/V preserved either way). */
void sparc64_commit_sysret(sparc64_ctx_t *ctx, long ret)
{
    if (ret < 0L) {
        ctx->r[SPARC64_O0] = sparc64_host_errno_to_guest(-ret);
        ctx->ccr |= SPARC64_CCR_ICC_C | SPARC64_CCR_XCC_C;
    } else {
        ctx->r[SPARC64_O0] = (uint64_t)ret;
        ctx->ccr &= ~(SPARC64_CCR_ICC_C | SPARC64_CCR_XCC_C);
    }
}

/* Copy chunk size for read/write loops (fixed array: never a VLA). */
#define SPARC64_IO_CHUNK 4096U

static long sys_read(sparc64_ctx_t *ctx, const sparc64_syscall_mem_t *mem,
                     uint64_t fd, uint64_t buf_va, uint64_t count)
{
    uint8_t chunk[SPARC64_IO_CHUNK] = { 0 };
    uint64_t done = 0;
    (void)ctx;
    if (count == 0U) {
        return host_ret(read((int)fd, chunk, 0));
    }
    if (buf_va >= SPARC64_TASK_SIZE ||
        count > SPARC64_TASK_SIZE - buf_va) {
        return -EFAULT;
    }
    while (done < count) {
        uint64_t want = count - done;
        ssize_t got;
        if (want > (uint64_t)SPARC64_IO_CHUNK) {
            want = (uint64_t)SPARC64_IO_CHUNK;
        }
        if (!mem->prepare_write(mem->context, buf_va + done, want)) {
            return (done != 0U) ? (long)done : -EFAULT;
        }
        got = read((int)fd, chunk, (size_t)want);
        if (got < 0) {
            return (done != 0U) ? (long)done : host_ret(got);
        }
        if (got == 0) {
            break;
        }
        if (!mem->write(mem->context, buf_va + done, chunk,
                        (uint64_t)got)) {
            return (done != 0U) ? (long)done : -EFAULT;
        }
        done += (uint64_t)got;
        if ((uint64_t)got < want) {
            break;
        }
    }
    return (long)done;
}

static long sys_write(sparc64_ctx_t *ctx, const sparc64_syscall_mem_t *mem,
                      uint64_t fd, uint64_t buf_va, uint64_t count)
{
    uint8_t chunk[SPARC64_IO_CHUNK] = { 0 };
    uint64_t done = 0;
    (void)ctx;
    if (count == 0U) {
        return host_ret(write((int)fd, chunk, 0));
    }
    if (buf_va >= SPARC64_TASK_SIZE ||
        count > SPARC64_TASK_SIZE - buf_va) {
        return -EFAULT;
    }
    while (done < count) {
        uint64_t want = count - done;
        ssize_t got;
        if (want > (uint64_t)SPARC64_IO_CHUNK) {
            want = (uint64_t)SPARC64_IO_CHUNK;
        }
        if (!mem->read(mem->context, buf_va + done, chunk, want)) {
            return (done != 0U) ? (long)done : -EFAULT;
        }
        got = write((int)fd, chunk, (size_t)want);
        if (got <= 0) {
            return (done != 0U) ? (long)done : host_ret(got);
        }
        done += (uint64_t)got;
        if ((uint64_t)got < want) {
            break;
        }
    }
    return (long)done;
}

/* struct new_utsname: six NUL-padded fields of 65 bytes each (390 total),
 * matching the layout the oracle exposes for uname(189). */
#define SPARC64_UTS_FIELD 65U
#define SPARC64_UTS_FIELDS 6U
#define SPARC64_UTS_TOTAL (SPARC64_UTS_FIELD * SPARC64_UTS_FIELDS)

static long sys_uname(sparc64_ctx_t *ctx, const sparc64_syscall_mem_t *mem,
                      uint64_t buf_va)
{
    static const char *const uts_fields[SPARC64_UTS_FIELDS] = {
        "Linux", "sparc64rt", "6.1.0", "#1 SMP sparc64rt", "sparc64",
        "(none)",
    };
    uint8_t buf[SPARC64_UTS_TOTAL];
    size_t i;
    size_t j;
    (void)ctx;
    if (buf_va > SPARC64_TASK_SIZE - (uint64_t)SPARC64_UTS_TOTAL) {
        return -EFAULT;
    }
    memset(buf, 0, sizeof(buf));
    for (i = 0U; i < (size_t)SPARC64_UTS_FIELDS; i++) {
        uint8_t *field = buf + i * (size_t)SPARC64_UTS_FIELD;
        for (j = 0U; uts_fields[i][j] != '\0' &&
             j < (size_t)SPARC64_UTS_FIELD - 1U; j++) {
            field[j] = (uint8_t)uts_fields[i][j];
        }
    }
    if (!mem->prepare_write(mem->context, buf_va,
                            (uint64_t)SPARC64_UTS_TOTAL)) {
        return -EFAULT;
    }
    if (!mem->write(mem->context, buf_va, buf,
                    (uint64_t)SPARC64_UTS_TOTAL)) {
        return -EFAULT;
    }
    return 0;
}

/* RC-U4: Provider-A truncate wiring. The host call runs first; only
 * host success commits state. The sysmem file-range registry converts
 * stripped 8 KiB pages to BUS spans (and regrows extended pages back
 * to zero pages) with paired TLB invalidation, while
 * vm_file_truncate_hook commits epoch/size bookkeeping to the process
 * family table. Declared locally; implementations live in
 * src/vm/vm_file.c (hook) and src/os/guest_run_sysmem.c (registry). */
extern long vm_file_truncate_hook(uint64_t st_dev, uint64_t st_ino,
    uint64_t st_ctime_ns, int host_fd, uint64_t old_size,
    uint64_t new_size, int is_ftruncate,
    void (*discard)(uint64_t discard_base, uint64_t discard_len,
        void *discard_ctx),
    void *discard_ctx);
extern void sysmem_file_resize(void *ctx, uint64_t dev, uint64_t ino,
    uint64_t old_size, uint64_t new_size);

static uint64_t trunc_ctime_ns(const struct stat *st)
{
#if defined(__APPLE__)
    return (uint64_t)st->st_ctimespec.tv_nsec;
#else
    return (uint64_t)st->st_ctim.tv_nsec;
#endif
}

/* Lane A2: truncate(129)/truncate64(77) by path, ftruncate(130)/
 * ftruncate64(84) by fd. Lengths are signed 64-bit (SPARC takes
 * `long length`): negatives are -EINVAL like Linux, and both calls
 * exist on Linux and Darwin hosts. */
static long sys_truncate_path(const sparc64_syscall_mem_t *mem,
    uint64_t path_va, uint64_t length)
{
    char path[L2A_PATH_MAX];
    struct stat stb;
    uint64_t old_size;
    long rc;
    if (length > (uint64_t)INT64_MAX) {
        return -EINVAL;
    }
    rc = l2a_copy_cstring(mem, path_va, path, (uint64_t)L2A_PATH_MAX);
    if (rc != 0) {
        return rc;
    }
    if (stat(path, &stb) != 0) {
        return -(long)errno;
    }
    old_size = (stb.st_size < 0) ? UINT64_C(0) : (uint64_t)stb.st_size;
    if (truncate(path, (off_t)(int64_t)length) != 0) {
        return -(long)errno;
    }
    if (S_ISREG(stb.st_mode)) {
        /* No stable fd exists for the path form, so the family table
         * is left alone (hook with fd -1 is a no-op); the registry
         * still converts stripped pages to BUS spans. */
        sysmem_file_resize(mem->context, (uint64_t)stb.st_dev,
            (uint64_t)stb.st_ino, old_size, length);
        (void)vm_file_truncate_hook((uint64_t)stb.st_dev,
            (uint64_t)stb.st_ino, trunc_ctime_ns(&stb), -1, old_size,
            length, 0, NULL, NULL);
    }
    return 0;
}

static long sys_ftruncate_fd(const sparc64_syscall_mem_t *mem, uint64_t fd,
    uint64_t length)
{
    struct stat stb;
    uint64_t old_size;
    if (length > (uint64_t)INT64_MAX) {
        return -EINVAL;
    }
    if (fstat((int)fd, &stb) != 0) {
        return -(long)errno;
    }
    old_size = (stb.st_size < 0) ? UINT64_C(0) : (uint64_t)stb.st_size;
    if (ftruncate((int)fd, (off_t)(int64_t)length) != 0) {
        return -(long)errno;
    }
    if (S_ISREG(stb.st_mode)) {
        sysmem_file_resize(mem->context, (uint64_t)stb.st_dev,
            (uint64_t)stb.st_ino, old_size, length);
        (void)vm_file_truncate_hook((uint64_t)stb.st_dev,
            (uint64_t)stb.st_ino, trunc_ctime_ns(&stb), (int)fd,
            old_size, length, 1, NULL, NULL);
    }
    return 0;
}

int sparc64_syscall_is_exit(long nr)
{
    return (nr == (long)SPARC64__NR_exit ||
            nr == (long)SPARC64__NR_exit_group) ? 1 : 0;
}

int sparc64_syscall_is_group_exit(long nr)
{
    return (nr == (long)SPARC64__NR_exit_group) ? 1 : 0;
}

const char *sparc64_syscall_name(long nr)
{
    if (nr < 0L || nr >= (long)SPARC64_NR_MAX) {
        return NULL;
    }
#ifdef SPARC64RT_SYSCALL_NAMES
    return sparc64_sysent[(size_t)nr].name;
#else
    {
        static const char *const names[SPARC64_NR_MAX] = {
#define X(nr, name) [nr] = #name,
            SPARC64_SYSCALL_LIST
#undef X
        };

        return names[(size_t)nr];
    }
#endif
}

/* Dispatch the syscall in %g1 (args %o0..%o5), commit the dual-carry
 * convention, and advance pc = npc; npc += 4. Returns the guest exit
 * status for exit/exit_group (terminal), 0 otherwise. */
long sparc64_handle_syscall(sparc64_ctx_t *ctx,
                            const sparc64_syscall_mem_t *mem)
{
    long nr;
    uint64_t o0;
    uint64_t o1;
    uint64_t o2;
    uint64_t o3;
    uint64_t o4;
    uint64_t o5;
    long ret;

    if (ctx == NULL || mem == NULL) {
        return -EFAULT;
    }
    nr = (long)ctx->r[SPARC64_G1];
    o0 = ctx->r[SPARC64_O0];
    o1 = ctx->r[SPARC64_O1];
    o2 = ctx->r[SPARC64_O2];
    o3 = ctx->r[SPARC64_O3];
    o4 = ctx->r[SPARC64_O4];
    o5 = ctx->r[SPARC64_O5];

    switch (nr) {
    case (long)SPARC64__NR_exit:
    case (long)SPARC64__NR_exit_group:
        ret = (long)(o0 & 0xffU);
        ctx->r[SPARC64_O0] = o0 & 0xffU;
        ctx->ccr &= ~(SPARC64_CCR_ICC_C | SPARC64_CCR_XCC_C);
        ctx->pc = ctx->npc;
        ctx->npc += 4U;
        ctx->syscalls_executed++;
        note_dispatched();
        return ret;
    case (long)SPARC64__NR_read:
        ret = sys_read(ctx, mem, o0, o1, o2);
        break;
    case (long)SPARC64__NR_close:
        ret = host_ret(close((int)o0));
        break;
    case (long)SPARC64__NR_getdents64:
        ret = sparc64_l2a_getdents64(ctx, mem, o0, o1, o2);
        break;
    case (long)SPARC64__NR_faccessat:
        ret = sparc64_l2a_faccessat(ctx, mem, o0, o1, o2, o3);
        break;
    /* Phase-2 static-libc set (src/os/syscalls_ext.c, additive cases). */
    case (long)SPARC64__NR_getpid:
        ret = sparc64_l2a_getpid();
        break;
    case (long)SPARC64__NR_getuid:
        ret = sparc64_l2a_getuid();
        break;
    case (long)SPARC64__NR_getgid:
        ret = sparc64_l2a_getgid();
        break;
    case (long)SPARC64__NR_stat:
        ret = sparc64_l2a_stat(ctx, mem, o0, o1);
        break;
    case (long)SPARC64__NR_lstat:
        ret = sparc64_l2a_lstat(ctx, mem, o0, o1);
        break;
    case (long)SPARC64__NR_fstat:
        ret = sparc64_l2a_fstat(ctx, mem, o0, o1);
        break;
    case (long)SPARC64__NR_stat64:
        ret = sparc64_l2a_stat64(ctx, mem, o0, o1);
        break;
    case (long)SPARC64__NR_lstat64:
        ret = sparc64_l2a_lstat64(ctx, mem, o0, o1);
        break;
    case (long)SPARC64__NR_fstat64:
        ret = sparc64_l2a_fstat64(ctx, mem, o0, o1);
        break;
    case (long)SPARC64__NR_fstatat64:
        ret = sparc64_l2a_fstatat64(ctx, mem, o0, o1, o2, o3);
        break;
    case (long)SPARC64__NR_statx:
        ret = sparc64_l2a_statx(ctx, mem, o0, o1, o2, o3, o4);
        break;
    case (long)SPARC64__NR_readv:
        ret = sparc64_l2a_readv(ctx, mem, o0, o1, o2);
        break;
    case (long)SPARC64__NR_writev:
        ret = sparc64_l2a_writev(ctx, mem, o0, o1, o2);
        break;
    case (long)SPARC64__NR_openat:
        ret = sparc64_l2a_openat(ctx, mem, o0, o1, o2, o3);
        break;
    case (long)SPARC64__NR_open:
        ret = sparc64_l2a_open(ctx, mem, o0, o1, o2);
        break;
    case (long)SPARC64__NR_readlinkat:
        ret = sparc64_l2a_readlinkat(ctx, mem, o0, o1, o2, o3);
        break;
    case (long)SPARC64__NR_readlink:
        /* readlink(file, buf, len) is readlinkat(AT_FDCWD). */
        ret = sparc64_l2a_readlinkat(ctx, mem,
            (uint64_t)(int64_t)-100, o0, o1, o2);
        break;
    case (long)SPARC64__NR_fcntl:
    case (long)SPARC64__NR_fcntl64:
        ret = sparc64_l2a_fcntl(o0, o1, o2);
        break;
    case (long)SPARC64__NR_rt_sigprocmask: {
        int delivered = 0;
        ret = sparc64_sig_rt_sigprocmask(ctx, mem, o0, o1, o2, o3,
            &delivered);
        if (delivered) {
            ctx->syscalls_executed++;
            return 0;
        }
        break;
    }
    case (long)SPARC64__NR_rt_sigpending:
        ret = sparc64_sig_rt_sigpending(ctx, mem, o0, o1);
        break;
    case (long)SPARC64__NR_ioctl:
        ret = sparc64_l2a_ioctl(ctx, mem, o0, o1, o2);
        break;
    case (long)SPARC64__NR_clock_gettime:
        ret = sparc64_l2a_clock_gettime(ctx, mem, o0, o1);
        break;
    case (long)SPARC64__NR_clock_getres:
        ret = sparc64_l2a_clock_getres(ctx, mem, o0, o1);
        break;
    case (long)SPARC64__NR_gettimeofday:
        ret = sparc64_l2a_gettimeofday(ctx, mem, o0, o1);
        break;
    case (long)SPARC64__NR_getrandom:
        ret = sparc64_l2a_getrandom(ctx, mem, o0, o1, o2);
        break;
    case (long)SPARC64__NR_futex:
        ret = sparc64_thread_futex(ctx, mem, o0, o1, o2, o3, o4, o5);
        break;
    case (long)SPARC64__NR_clone:
        /* L4b owns CLONE_VM threads; L4c owns fork-like clones. */
        if ((o0 & (uint64_t)SPARC64_CLONE_VM) != UINT64_C(0)) {
            ret = sparc64_thread_clone(ctx, mem, o0, o1, o2, o3, o4);
        } else {
            ret = sparc64_proc_clone(ctx, mem, o0, o1, o2, o3, o4);
        }
        break;
    case (long)SPARC64__NR_gettid:
        ret = sparc64_thread_gettid(ctx);
        break;
    case (long)SPARC64__NR_set_robust_list:
        ret = sparc64_thread_set_robust_list(ctx, o0, o1);
        break;
    case (long)SPARC64__NR_get_robust_list:
        ret = sparc64_thread_get_robust_list(ctx, mem, o0, o1, o2);
        break;
    case (long)SPARC64__NR_rt_sigreturn:
        /* Absolute resume: the frame sets pc/npc, so the common tail
         * advance must not run on success. */
        ret = sparc64_sync_sig_return(ctx, mem);
        if (ret == 0L) {
            ctx->syscalls_executed++;
            return 0;
        }
        break;
    case (long)SPARC64__NR_rt_sigaction:
        ret = sparc64_sig_rt_sigaction(ctx, mem, o0, o1, o2, o3, o4);
        break;
    case (long)SPARC64__NR_sigaltstack:
        ret = sparc64_sig_sigaltstack(ctx, mem, o0, o1);
        break;
    case (long)SPARC64__NR_kill: {
        int delivered = 0;
        ret = sparc64_sig_kill(ctx, mem, o0, o1, &delivered);
        if (delivered) {
            ctx->syscalls_executed++;
            return 0;
        }
        break;
    }
    case (long)SPARC64__NR_tkill: {
        int delivered = 0;
        ret = sparc64_sig_tkill(ctx, mem, o0, o1, &delivered);
        if (delivered) {
            ctx->syscalls_executed++;
            return 0;
        }
        break;
    }
    case (long)SPARC64__NR_tgkill: {
        int delivered = 0;
        ret = sparc64_sig_tgkill(ctx, mem, o0, o1, o2, &delivered);
        if (delivered) {
            ctx->syscalls_executed++;
            return 0;
        }
        break;
    }
    case (long)SPARC64__NR_write:
        ret = sys_write(ctx, mem, o0, o1, o2);
        break;
    case (long)SPARC64__NR_brk:
        ret = mem->do_brk(mem->context, o0);
        break;
    case (long)SPARC64__NR_mmap:
        ret = mem->do_mmap(mem->context, o0, o1, (unsigned)o2,
                           (unsigned)o3, (int)o4, o5);
        break;
    case (long)SPARC64__NR_munmap:
        ret = mem->do_munmap(mem->context, o0, o1);
        break;
    case (long)SPARC64__NR_mprotect:
        ret = mem->do_mprotect(mem->context, o0, o1, (unsigned)o2);
        break;
    /* Lane A2: mremap(250), truncate(129/77), ftruncate(130/84). */
    case (long)SPARC64__NR_mremap:
        ret = sparc64_sysmem_mremap(mem->context, o0, o1, o2,
            (unsigned)o3, o4);
        break;
    case (long)SPARC64__NR_truncate:
    case (long)SPARC64__NR_truncate64:
        ret = sys_truncate_path(mem, o0, o1);
        break;
    case (long)SPARC64__NR_ftruncate:
    case (long)SPARC64__NR_ftruncate64:
        ret = sys_ftruncate_fd(mem, o0, o1);
        break;
    case (long)SPARC64__NR_uname:
        ret = sys_uname(ctx, mem, o0);
        break;
    case (long)SPARC64__NR_set_tid_address:
        ret = mem->set_tid_address(mem->context, o0);
        break;
    /* Phase-4 lifecycle set (src/os/proc.c, lane L4c, additive cases).
     * fork/vfork set %o1 in the handler; execve resumes absolutely
     * (fresh pc/npc, no advance), like rt_sigreturn. clone without
     * CLONE_VM is fork-like (L4c); with CLONE_VM it dispatches to
     * the L4b host-thread path above. */
    case (long)SPARC64__NR_fork:
        ret = sparc64_proc_fork(ctx, mem);
        break;
    case (long)SPARC64__NR_vfork:
        ret = sparc64_proc_vfork(ctx, mem);
        break;
    case (long)SPARC64__NR_execve: {
        long erc = sparc64_proc_execve(ctx, mem, o0, o1, o2);
        if (erc == 0L) {
            ctx->syscalls_executed++;
            note_dispatched();
            return 0;
        }
        ret = erc;
        break;
    }
    case (long)SPARC64__NR_wait4:
        ret = sparc64_proc_wait4(ctx, mem, o0, o1, o2, o3);
        break;
    case (long)SPARC64__NR_waitid:
        ret = sparc64_proc_waitid(ctx, mem, o0, o1, o2, o3, o4);
        break;
    case (long)SPARC64__NR_pipe:
        ret = sparc64_proc_pipe(ctx, mem);
        break;
    case (long)SPARC64__NR_pipe2:
        ret = sparc64_proc_pipe2(ctx, mem, o0, o1);
        break;
    case (long)SPARC64__NR_dup:
        ret = sparc64_proc_dup(o0);
        break;
    case (long)SPARC64__NR_dup2:
        ret = sparc64_proc_dup2(o0, o1);
        break;
    case (long)SPARC64__NR_dup3:
        ret = sparc64_proc_dup3(o0, o1, o2);
        break;
    default:
        ret = -ENOSYS;
        break;
    }

    /* 64-bit guest addresses never collide with the kernel -4095..-1
     * error window, so a plain sign check commits correctly for mmap/brk
     * addresses and ordinary values alike (no 32-bit window needed). */
    sparc64_commit_sysret(ctx, ret);
    ctx->pc = ctx->npc;
    ctx->npc += 4U;
    ctx->syscalls_executed++;
    note_dispatched();
    return 0;
}
