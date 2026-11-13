/*
 * tests/test_r1316_remediation.c — Rounds 13-16 regression tests.
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Host-side white-box tests for S64-R13-1/2 (canonical /proc
 * classification), S64-R13-3 (epoch invalidate), S64-R13-4 (single
 * fetch read), S64-R13-7 (guest ENOSYS 90), S64-R14-1 (taken Tcc),
 * S64-R14-2 (WR %ccr), S64-R15-1 (batched FPSR accrue) and S64-R15-2
 * (FCMP fcc commit order). DBT legs execute AArch64 code on the host
 * (arm64) through sparc64_dbt_step_one / sparc64_dbt_run; the
 * interpreter is never consulted for the asserted outcomes.
 * Deterministic stdout; exit 0 with R1316-REMEDIATION-PASS iff every
 * check passed.
 *
 * Build with `make check-r1316` from the worktree root.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "core/cpu.h"
#include "dbt/dbt.h"
#include "dbt/mem_sites.h"
#include "interp/interp.h"
#include "os/guest_proc.h"
#include "os/guest_run_priv.h"
#include "os/syscalls_min.h"

/* Internal DBT helper (declared extern here the way dbt.c does): the
 * start-page version guard bumped by sparc64_dbt_invalidate. */
extern uint32_t sparc64_dbt_page_version(sparc64_dbt_t *dbt, uint64_t va);

/* ---- Link stubs (backend/worker surface the harness never uses) ---- */

int rt_host_msync(void *host_addr, size_t len, int linux_flags)
{
    (void)host_addr;
    (void)len;
    (void)linux_flags;
    return 0;
}

int64_t rt_host_pread64(int fd, void *buf, size_t count, int64_t offset)
{
    (void)fd;
    (void)buf;
    (void)count;
    (void)offset;
    return -1;
}

int rt_host_preempt_worker(uint64_t host_tid)
{
    (void)host_tid;
    return 0;
}

uint64_t rt_host_register_self(void) { return 0U; }

void rt_host_unregister_self(void) { }

int rt_darwin_pipe2(int fds[2], int flags)
{
    int rc = pipe(fds);
    if (rc != 0) {
        return -errno;
    }
    if ((flags & O_CLOEXEC) != 0) {
        (void)fcntl(fds[0], F_SETFD, FD_CLOEXEC);
        (void)fcntl(fds[1], F_SETFD, FD_CLOEXEC);
    }
    if ((flags & O_NONBLOCK) != 0) {
        (void)fcntl(fds[0], F_SETFL, O_NONBLOCK);
        (void)fcntl(fds[1], F_SETFL, O_NONBLOCK);
    }
    return 0;
}

bool sparc64_threads_try_host_atomic(sparc64_cpu_t *cpu, void *mc,
    uint64_t pc, const sparc64_dec_t *d, sparc64_step_result_t *out)
{
    (void)cpu;
    (void)mc;
    (void)pc;
    (void)d;
    (void)out;
    return false;
}

/* ---- Flat test memory ------------------------------------------------ */

#define T_MEM_SIZE UINT64_C(0x40000)
#define T_CODE UINT64_C(0x1000)
#define T_PATH_VA UINT64_C(0x20000)
#define T_BUF_VA UINT64_C(0x21000)

static uint8_t t_mem[0x40000];

static bool t_in_range(uint64_t va, uint64_t n)
{
    return n <= T_MEM_SIZE && va <= T_MEM_SIZE - n;
}

static bool t_read(void *ctx, uint64_t va, void *out, size_t n,
    sparc64_access_t acc, sparc64_mem_fault_t *fault)
{
    (void)ctx;
    (void)acc;
    fault->address = va;
    if (!t_in_range(va, (uint64_t)n)) {
        fault->reason = SPARC64_MEM_FAULT_RANGE;
        return false;
    }
    memcpy(out, &t_mem[va], n);
    fault->reason = SPARC64_MEM_FAULT_NONE;
    return true;
}

static bool t_write(void *ctx, uint64_t va, const void *in, size_t n,
    sparc64_mem_fault_t *fault)
{
    (void)ctx;
    fault->address = va;
    if (!t_in_range(va, (uint64_t)n)) {
        fault->reason = SPARC64_MEM_FAULT_RANGE;
        return false;
    }
    memcpy(&t_mem[va], in, n);
    fault->reason = SPARC64_MEM_FAULT_NONE;
    return true;
}

static const sparc64_mem_ops_t t_ops = { t_read, t_write, NULL };

/* ---- Word builders (V9 format-3 field layout) ------------------------ */

static uint32_t t_f3m(unsigned op3, unsigned rd, unsigned rs1, unsigned ibit,
    uint32_t lo13)
{
    return 0x80000000U | ((rd & 31U) << 25) | ((op3 & 63U) << 19) |
        ((rs1 & 31U) << 14) | ((ibit & 1U) << 13) | (lo13 & 0x1FFFU);
}

static uint32_t t_fpop(unsigned op3, unsigned rd, unsigned rs1f,
    unsigned opf, unsigned rs2f)
{
    return 0x80000000U | ((rd & 31U) << 25) | ((op3 & 63U) << 19) |
        ((rs1f & 31U) << 14) | ((opf & 511U) << 5) | (rs2f & 31U);
}

static void t_poke32(uint64_t va, uint32_t w)
{
    t_mem[va] = (uint8_t)(w >> 24);
    t_mem[va + 1U] = (uint8_t)(w >> 16);
    t_mem[va + 2U] = (uint8_t)(w >> 8);
    t_mem[va + 3U] = (uint8_t)w;
}

/* ---- Check harness --------------------------------------------------- */

static int t_checks;
static int t_failures;

#define T_CHECK(cond) do { \
    t_checks++; \
    if (!(cond)) { \
        t_failures++; \
        printf("FAIL %s:%d: %s\n", __func__, __LINE__, #cond); \
    } \
} while (0)

/* ---- S64-R13-1/2: canonical /proc classification --------------------- */

static void t_proc_classify(void)
{
    char norm[4096];
    char pid_exe[64];
    char pid_mem[64];
    char other_pid[64];
    long self = (long)getpid();
    unsigned long foreign = (unsigned long)self ^ 0x40000000UL;
    int cls;
    int rootfd;

    (void)snprintf(pid_exe, sizeof(pid_exe), "/proc/%ld/exe", self);
    (void)snprintf(pid_mem, sizeof(pid_mem), "/proc/%ld/mem", self);
    (void)snprintf(other_pid, sizeof(other_pid), "/proc/%lu/mem",
        foreign);

    /* Canonical spellings. */
    cls = sparc64_guest_proc_classify(AT_FDCWD, "/proc/self/exe", norm);
    T_CHECK(cls == SPARC64_PROC_HANDLED);
    T_CHECK(strcmp(norm, "/proc/self/exe") == 0);
    cls = sparc64_guest_proc_classify(AT_FDCWD, "/proc/self", norm);
    T_CHECK(cls == SPARC64_PROC_BLOCKED);
    cls = sparc64_guest_proc_classify(AT_FDCWD, "/proc/self/maps/x",
        norm);
    T_CHECK(cls == SPARC64_PROC_BLOCKED);

    /* Non-canonical spellings never fall through to the host. */
    cls = sparc64_guest_proc_classify(AT_FDCWD, "/proc/./self/exe",
        norm);
    T_CHECK(cls == SPARC64_PROC_HANDLED);
    T_CHECK(strcmp(norm, "/proc/self/exe") == 0);
    cls = sparc64_guest_proc_classify(AT_FDCWD, "/proc//self/mem",
        norm);
    T_CHECK(cls == SPARC64_PROC_BLOCKED);
    cls = sparc64_guest_proc_classify(AT_FDCWD, "/proc/self/exe/..",
        norm);
    T_CHECK(cls == SPARC64_PROC_BLOCKED);
    cls = sparc64_guest_proc_classify(AT_FDCWD, "/proc/self/../cpuinfo",
        norm);
    T_CHECK(cls == SPARC64_PROC_OTHER);

    /* Guest-pid spellings of our own pid behave like /proc/self. */
    cls = sparc64_guest_proc_classify(AT_FDCWD, pid_exe, norm);
    T_CHECK(cls == SPARC64_PROC_HANDLED);
    T_CHECK(strcmp(norm, "/proc/self/exe") == 0);
    cls = sparc64_guest_proc_classify(AT_FDCWD, pid_mem, norm);
    T_CHECK(cls == SPARC64_PROC_BLOCKED);
    /* thread-self rewrites onto /proc/self: exe served, mem blocked. */
    cls = sparc64_guest_proc_classify(AT_FDCWD, "/proc/thread-self",
        norm);
    T_CHECK(cls == SPARC64_PROC_BLOCKED);
    cls = sparc64_guest_proc_classify(AT_FDCWD, "/proc/thread-self/exe",
        norm);
    T_CHECK(cls == SPARC64_PROC_HANDLED);
    T_CHECK(strcmp(norm, "/proc/self/exe") == 0);
    cls = sparc64_guest_proc_classify(AT_FDCWD, "/proc/thread-self/mem",
        norm);
    T_CHECK(cls == SPARC64_PROC_BLOCKED);
    /* Any other pid is unrelated to us. */
    cls = sparc64_guest_proc_classify(AT_FDCWD, other_pid, norm);
    T_CHECK(cls == SPARC64_PROC_OTHER);
    cls = sparc64_guest_proc_classify(AT_FDCWD, "/etc/hostname", norm);
    T_CHECK(cls == SPARC64_PROC_OTHER);

    /* dirfd-relative spellings with dirfd at the filesystem root. */
    rootfd = open("/", O_RDONLY | O_DIRECTORY);
    T_CHECK(rootfd >= 0);
    if (rootfd >= 0) {
        cls = sparc64_guest_proc_classify(rootfd, "proc/self/exe",
            norm);
        T_CHECK(cls == SPARC64_PROC_HANDLED);
        T_CHECK(strcmp(norm, "/proc/self/exe") == 0);
        cls = sparc64_guest_proc_classify(rootfd, "proc/./self/mem",
            norm);
        T_CHECK(cls == SPARC64_PROC_BLOCKED);
        cls = sparc64_guest_proc_classify(rootfd,
            "proc/self/../self/cmdline", norm);
        T_CHECK(cls == SPARC64_PROC_HANDLED);
        T_CHECK(strcmp(norm, "/proc/self/cmdline") == 0);
        (void)close(rootfd);
    }
}

/* ---- Syscall-mem layer over the flat test memory --------------------- */

static bool t_sys_read(void *ctx, uint64_t va, void *host, uint64_t len)
{
    (void)ctx;
    if (!t_in_range(va, len)) {
        return false;
    }
    memcpy(host, &t_mem[va], (size_t)len);
    return true;
}

static bool t_sys_write(void *ctx, uint64_t va, const void *host,
    uint64_t len)
{
    (void)ctx;
    if (!t_in_range(va, len)) {
        return false;
    }
    memcpy(&t_mem[va], host, (size_t)len);
    return true;
}

static bool t_sys_prepare(void *ctx, uint64_t va, uint64_t len)
{
    (void)ctx;
    return t_in_range(va, len);
}

static void t_put_cstring(uint64_t va, const char *s)
{
    size_t n = strlen(s) + 1U;
    memcpy(&t_mem[va], s, n);
}

static sparc64_syscall_mem_t t_sysmem;

static void t_sysmem_init(void)
{
    memset(&t_sysmem, 0, sizeof(t_sysmem));
    t_sysmem.context = NULL;
    t_sysmem.read = t_sys_read;
    t_sysmem.write = t_sys_write;
    t_sysmem.prepare_write = t_sys_prepare;
}

static void t_proc_readlinkat(void)
{
    guest_state_t *g;
    long rc;
    g = (guest_state_t *)calloc(1, sizeof(*g));
    T_CHECK(g != NULL);
    if (g == NULL) {
        return;
    }
    t_sysmem.context = g;
    sparc64_guest_proc_note_exec(g, "/w/guest_p1");

    /* Non-canonical exe spelling serves the load path. */
    t_put_cstring(T_PATH_VA, "/proc/./self/exe");
    rc = sparc64_guest_proc_readlinkat(g, &t_sysmem,
        (uint64_t)(int64_t)AT_FDCWD, T_PATH_VA, T_BUF_VA, 64U);
    T_CHECK(rc == 11L);
    T_CHECK(memcmp(&t_mem[T_BUF_VA], "/w/guest_p1", 11U) == 0);

    /* Guest-pid mem spelling is blocked, never the host tree. */
    {
        char pid_mem[64];
        (void)snprintf(pid_mem, sizeof(pid_mem), "/proc/%ld/mem",
            (long)getpid());
        t_put_cstring(T_PATH_VA, pid_mem);
        rc = sparc64_guest_proc_readlinkat(g, &t_sysmem,
            (uint64_t)(int64_t)AT_FDCWD, T_PATH_VA, T_BUF_VA, 64U);
        T_CHECK(rc == -ENOENT);
    }

    /* Synthetic regular files are EINVAL, not host links. */
    t_put_cstring(T_PATH_VA, "/proc/self/cmdline");
    rc = sparc64_guest_proc_readlinkat(g, &t_sysmem,
        (uint64_t)(int64_t)AT_FDCWD, T_PATH_VA, T_BUF_VA, 64U);
    T_CHECK(rc == -EINVAL);

    /* The self directory itself is ENOENT. */
    t_put_cstring(T_PATH_VA, "/proc/self");
    rc = sparc64_guest_proc_readlinkat(g, &t_sysmem,
        (uint64_t)(int64_t)AT_FDCWD, T_PATH_VA, T_BUF_VA, 64U);
    T_CHECK(rc == -ENOENT);

    /* Unrelated paths with bufsz 0 short-circuit before host I/O. */
    t_put_cstring(T_PATH_VA, "/etc/hostname");
    rc = sparc64_guest_proc_readlinkat(g, &t_sysmem,
        (uint64_t)(int64_t)AT_FDCWD, T_PATH_VA, T_BUF_VA, 0U);
    T_CHECK(rc == 0L);

    sparc64_guest_proc_forget(g);
    free(g);
}

static void t_proc_openat(void)
{
    guest_state_t *g = (guest_state_t *)calloc(1, sizeof(*g));
    long fd;
    T_CHECK(g != NULL);
    if (g == NULL) {
        return;
    }
    t_sysmem.context = g;

    /* Synthetic maps serve a readable pipe with no backing file. */
    fd = sparc64_guest_proc_openat(g, &t_sysmem, "/proc/self/maps",
        O_RDONLY);
    T_CHECK(fd >= 0L);
    if (fd >= 0L) {
        (void)close((int)fd);
    }
    /* No snapshot: exe and cmdline are ENOENT, not host fds. */
    fd = sparc64_guest_proc_openat(g, &t_sysmem, "/proc/self/exe",
        O_RDONLY);
    T_CHECK(fd == -ENOENT);
    fd = sparc64_guest_proc_openat(g, &t_sysmem, "/proc/self/cmdline",
        O_RDONLY);
    T_CHECK(fd == -ENOENT);
    /* Non-canonical direct spellings never open the host tree. */
    fd = sparc64_guest_proc_openat(g, &t_sysmem, "/proc//self/mem",
        O_RDONLY);
    T_CHECK(fd == -ENOENT);

    sparc64_guest_proc_forget(g);
    free(g);
}

/* ---- S64-R13-7: SPARC64 guest ENOSYS is 90 on every host ------------ */

#if SPARC64_GUEST_ENOSYS != 90L
#error "SPARC64_GUEST_ENOSYS must be 90 (arch/sparc overrides asm-generic 38)"
#endif

static void t_enosys(void)
{
    T_CHECK(SPARC64_GUEST_ENOSYS == 90L);
}

/* ---- S64-R13-4: instruction fetch is a single 4-byte read ------------ */

static unsigned t_fw_calls;
static uint64_t t_fw_n;

static bool t_fw_read(void *ctx, uint64_t va, void *out, size_t n,
    sparc64_access_t acc, sparc64_mem_fault_t *fault)
{
    (void)ctx;
    (void)acc;
    t_fw_calls++;
    t_fw_n = (uint64_t)n;
    fault->address = va;
    if (!t_in_range(va, (uint64_t)n)) {
        fault->reason = SPARC64_MEM_FAULT_RANGE;
        return false;
    }
    memcpy(out, &t_mem[va], n);
    fault->reason = SPARC64_MEM_FAULT_NONE;
    return true;
}

static void t_fetch_word(void)
{
    static const sparc64_mem_ops_t fw_ops = { t_fw_read, t_write, NULL };
    sparc64_step_result_t res;
    uint32_t out = 0U;
    bool ok;
    t_poke32(T_CODE, 0x12345678U);
    t_fw_calls = 0U;
    t_fw_n = 0U;
    ok = sparc64_fetch_word(&fw_ops, NULL, T_CODE, &out, &res);
    T_CHECK(ok);
    T_CHECK(t_fw_calls == 1U);
    T_CHECK(t_fw_n == 4U);
    T_CHECK(out == 0x12345678U);
    /* Misaligned fetch still traps without touching memory. */
    t_fw_calls = 0U;
    ok = sparc64_fetch_word(&fw_ops, NULL, T_CODE + 1U, &out, &res);
    T_CHECK(!ok);
    T_CHECK(res.kind == SPARC64_STEP_TRAP);
    T_CHECK(t_fw_calls == 0U);
}

/* ---- S64-R13-3: small invalidates evict precisely (no epoch) ----- */

static sparc64_dbt_t t_inv_dbt;

static void t_invalidate(void)
{
    sparc64_cpu_t cpu;
    sparc64_step_result_t r;
    uint32_t idx_a;
    uint32_t epoch_before;
    uint64_t blocks_b;
    uint64_t hits_b;
    T_CHECK(sparc64_dbt_init(&t_inv_dbt) == 0);

    /* Two translated single-nop blocks on different pages. */
    memset(t_mem, 0, sizeof(t_mem));
    sparc64_cpu_init(&cpu, T_CODE);
    t_poke32(T_CODE, 0x01000000U);
    t_poke32(T_CODE + 4U, t_f3m(0x3AU, 8U, 0U, 1U, 0x6DU));
    t_poke32(T_CODE + 0x2000U, 0x01000000U);
    t_poke32(T_CODE + 0x2004U, t_f3m(0x3AU, 8U, 0U, 1U, 0x6DU));
    r = sparc64_dbt_run(&cpu, &t_ops, NULL, &t_inv_dbt);
    T_CHECK(r.kind == SPARC64_STEP_SYSCALL);
    cpu.pc = T_CODE + 0x2000U;
    cpu.npc = T_CODE + 0x2004U;
    r = sparc64_dbt_run(&cpu, &t_ops, NULL, &t_inv_dbt);
    T_CHECK(r.kind == SPARC64_STEP_SYSCALL);
    T_CHECK(t_inv_dbt.stat_blocks == 2U);
    idx_a = (uint32_t)((T_CODE >> 2U) &
        (uint64_t)(SPARC64_DBT_CACHE_SIZE - 1U));
    T_CHECK(t_inv_dbt.blocks[idx_a].valid == true);

    /* Invalidate only the first page: its block dies (valid cleared,
     * host_code dropped so the Soft-TLB write guard releases) and its
     * page version bumps, while the epoch is untouched. */
    epoch_before = t_inv_dbt.epoch;
    sparc64_dbt_invalidate(&t_inv_dbt, T_CODE, 8U);
    T_CHECK(t_inv_dbt.blocks[idx_a].valid == false);
    T_CHECK(t_inv_dbt.blocks[idx_a].host_code == NULL);
    T_CHECK(sparc64_dbt_page_version(&t_inv_dbt, T_CODE) == 1U);
    T_CHECK(t_inv_dbt.epoch == epoch_before);

    /* The other page stays cached: served from the block cache or
     * the IBTC chain (which dbt_run probes first) with no
     * re-translation. */
    blocks_b = t_inv_dbt.stat_blocks;
    hits_b = t_inv_dbt.stat_hits + t_inv_dbt.stat_ibtc_hits;
    cpu.pc = T_CODE + 0x2000U;
    cpu.npc = T_CODE + 0x2004U;
    r = sparc64_dbt_run(&cpu, &t_ops, NULL, &t_inv_dbt);
    T_CHECK(r.kind == SPARC64_STEP_SYSCALL);
    T_CHECK(t_inv_dbt.stat_blocks == blocks_b);
    T_CHECK(t_inv_dbt.stat_hits + t_inv_dbt.stat_ibtc_hits ==
        hits_b + 1U);

    /* The evicted block re-translates on re-entry. */
    cpu.pc = T_CODE;
    cpu.npc = T_CODE + 4U;
    r = sparc64_dbt_run(&cpu, &t_ops, NULL, &t_inv_dbt);
    T_CHECK(r.kind == SPARC64_STEP_SYSCALL);
    T_CHECK(t_inv_dbt.stat_blocks == blocks_b + 1U);
    T_CHECK(t_inv_dbt.blocks[idx_a].valid == true);

    /* Wide sweep (9 pages): full flush clears every valid bit. */
    t_inv_dbt.ibtc[5].valid = true;
    sparc64_dbt_invalidate(&t_inv_dbt, 0U, 9U * 4096U);
    T_CHECK(t_inv_dbt.blocks[idx_a].valid == false);
    T_CHECK(t_inv_dbt.ibtc[5].valid == false);
    T_CHECK(t_inv_dbt.cached_count == 0U);

    /* Empty range: complete no-op. */
    epoch_before = t_inv_dbt.epoch;
    t_inv_dbt.cached_count = 7U;
    sparc64_dbt_invalidate(&t_inv_dbt, UINT64_C(0x1000), 0U);
    T_CHECK(t_inv_dbt.epoch == epoch_before);
    T_CHECK(t_inv_dbt.cached_count == 7U);
    sparc64_dbt_fini(&t_inv_dbt);
}

/* ---- DBT execution legs (S64-R14-1/2, S64-R15-1/2) -------------------- */

static sparc64_dbt_t t_dbt;

static void t_r141_tcc(void)
{
    sparc64_cpu_t cpu;
    sparc64_step_result_t r;

    /* Taken conditional Tcc with trap 0x6d exits SYSCALL. */
    memset(t_mem, 0, sizeof(t_mem));
    sparc64_cpu_init(&cpu, T_CODE);
    t_poke32(T_CODE, t_f3m(0x14U, 0U, 0U, 0U, 0U)); /* subcc g0,g0,g0 */
    t_poke32(T_CODE + 4U, t_f3m(0x3AU, 1U, 0U, 1U, 0x6DU)); /* BE,0x6d */
    t_poke32(T_CODE + 8U, 0x01000000U);
    r = sparc64_dbt_step_one(&t_dbt, &cpu, &t_ops, NULL);
    T_CHECK(r.kind == SPARC64_STEP_CONTINUE);
    T_CHECK(cpu.pc == T_CODE + 4U);
    r = sparc64_dbt_step_one(&t_dbt, &cpu, &t_ops, NULL);
    T_CHECK(r.kind == SPARC64_STEP_SYSCALL);

    /* Taken conditional Tcc with a non-gate trap must NOT syscall:
     * the true edge runs the trap-number sequence (TRAP here). */
    memset(t_mem, 0, sizeof(t_mem));
    sparc64_cpu_init(&cpu, T_CODE);
    t_poke32(T_CODE, t_f3m(0x14U, 0U, 0U, 0U, 0U));
    t_poke32(T_CODE + 4U, t_f3m(0x3AU, 1U, 0U, 1U, 0x10U));
    t_poke32(T_CODE + 8U, 0x01000000U);
    r = sparc64_dbt_step_one(&t_dbt, &cpu, &t_ops, NULL);
    T_CHECK(r.kind == SPARC64_STEP_CONTINUE);
    r = sparc64_dbt_step_one(&t_dbt, &cpu, &t_ops, NULL);
    T_CHECK(r.kind == SPARC64_STEP_TRAP);

    /* False conditional Tcc exits to pc + 4 (0-0 leaves C clear,
     * so BCS is false). */
    memset(t_mem, 0, sizeof(t_mem));
    sparc64_cpu_init(&cpu, T_CODE);
    t_poke32(T_CODE, t_f3m(0x14U, 0U, 0U, 0U, 0U));
    t_poke32(T_CODE + 4U, t_f3m(0x3AU, 5U, 0U, 1U, 0x6DU)); /* BCS */
    t_poke32(T_CODE + 8U, 0x01000000U);
    r = sparc64_dbt_step_one(&t_dbt, &cpu, &t_ops, NULL);
    T_CHECK(r.kind == SPARC64_STEP_CONTINUE);
    r = sparc64_dbt_step_one(&t_dbt, &cpu, &t_ops, NULL);
    T_CHECK(r.kind == SPARC64_STEP_CONTINUE);
    T_CHECK(cpu.pc == T_CODE + 8U);
}

static void t_r142_wrccr(void)
{
    sparc64_cpu_t cpu;
    sparc64_step_result_t r;
    memset(t_mem, 0, sizeof(t_mem));
    sparc64_cpu_init(&cpu, T_CODE);
    t_poke32(T_CODE, t_f3m(0x14U, 0U, 0U, 0U, 0U)); /* subcc: CCR=Z */
    t_poke32(T_CODE + 4U, t_f3m(0x30U, 2U, 0U, 1U, 0U)); /* wr 0,ccr */
    t_poke32(T_CODE + 8U, 0x02800003U); /* be +3 (target 0x1014) */
    t_poke32(T_CODE + 12U, 0x90102009U); /* delay: or g0,9,o0 */
    t_poke32(T_CODE + 16U, 0x90102007U); /* fall: or g0,7,o0 */
    t_poke32(T_CODE + 20U, 0x90102008U); /* taken: or g0,8,o0 */
    t_poke32(T_CODE + 24U, 0x01000000U);
    r = sparc64_dbt_step_one(&t_dbt, &cpu, &t_ops, NULL);
    T_CHECK(r.kind == SPARC64_STEP_CONTINUE);
    r = sparc64_dbt_step_one(&t_dbt, &cpu, &t_ops, NULL);
    T_CHECK(r.kind == SPARC64_STEP_CONTINUE);
    T_CHECK(cpu.ccr == 0U);
    r = sparc64_dbt_step_one(&t_dbt, &cpu, &t_ops, NULL);
    T_CHECK(r.kind == SPARC64_STEP_CONTINUE);
    T_CHECK(cpu.pc == T_CODE + 16U);
    r = sparc64_dbt_step_one(&t_dbt, &cpu, &t_ops, NULL);
    T_CHECK(r.kind == SPARC64_STEP_CONTINUE);
    /* Reloaded CCR (Z clear) beats the stale NZCV: not taken. */
    T_CHECK(cpu.r[8] == 7U);
}

static void t_r151_batch(void)
{
    sparc64_cpu_t cpu;
    sparc64_step_result_t r;
    memset(t_mem, 0, sizeof(t_mem));
    sparc64_cpu_init(&cpu, T_CODE);
    cpu.fp.f[1] = 0x3F800000U; /* 1.0 */
    cpu.fp.f[0] = 0x40400000U; /* 3.0 */
    cpu.fp.f[5] = 0x3F800000U; /* 1.0 */
    cpu.fp.f[4] = 0x3F800000U; /* 1.0 */
    t_poke32(T_CODE, t_fpop(0x34U, 2U, 0U, 0x4DU, 1U)); /* fdivs */
    t_poke32(T_CODE + 4U, t_fpop(0x34U, 6U, 4U, 0x41U, 5U)); /* fadds */
    t_poke32(T_CODE + 8U, t_f3m(0x3AU, 8U, 0U, 1U, 0x6DU)); /* ta 0x6d */
    t_poke32(T_CODE + 12U, 0x01000000U);
    r = sparc64_dbt_run(&cpu, &t_ops, NULL, &t_dbt);
    T_CHECK(r.kind == SPARC64_STEP_SYSCALL);
    /* The exact fadds overwrote cexc; the inexact fdivs only accrues. */
    T_CHECK((cpu.fsr & UINT64_C(0x1F)) == 0U);
    T_CHECK(((cpu.fsr >> 5) & UINT64_C(0x1F)) == UINT64_C(0x01));
    T_CHECK(cpu.fp.f[7] == 0x40000000U);
}

static void t_r152_fcmp(void)
{
    sparc64_cpu_t cpu;
    sparc64_step_result_t r;
    memset(t_mem, 0, sizeof(t_mem));
    sparc64_cpu_init(&cpu, T_CODE);
    cpu.fsr = (uint64_t)1U << 27; /* TEM.NV */
    cpu.fcc[0] = 1U;
    cpu.fsr |= (uint64_t)1U << 10; /* mirror fcc0 = 1 in FSR */
    cpu.fp.f[1] = 0x7FC00000U; /* QNaN */
    cpu.fp.f[0] = 0x3F800000U; /* 1.0 */
    t_poke32(T_CODE, t_fpop(0x35U, 0U, 0U, 0x55U, 1U)); /* fcmpes */
    t_poke32(T_CODE + 4U, 0x01000000U);
    r = sparc64_dbt_step_one(&t_dbt, &cpu, &t_ops, NULL);
    T_CHECK(r.kind == SPARC64_STEP_TRAP);
    /* The trapping compare left fcc0 untouched. */
    T_CHECK(cpu.fcc[0] == 1U);
    T_CHECK(((cpu.fsr >> 10) & UINT64_C(3)) == UINT64_C(1));
}

int main(void)
{
    t_sysmem_init();
    T_CHECK(sparc64_dbt_init(&t_dbt) == 0);
    t_proc_classify();
    t_proc_readlinkat();
    t_proc_openat();
    t_enosys();
    t_fetch_word();
    t_invalidate();
    t_r141_tcc();
    t_r142_wrccr();
    t_r151_batch();
    t_r152_fcmp();
    sparc64_dbt_fini(&t_dbt);
    if (t_failures == 0) {
        printf("R1316-REMEDIATION-PASS checks=%d\n", t_checks);
        return 0;
    }
    printf("R1316-REMEDIATION-FAIL failures=%d checks=%d\n", t_failures,
        t_checks);
    return 1;
}
