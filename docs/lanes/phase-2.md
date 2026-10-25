# Phase 2 Task Cards — Static Libc Syscalls & Base Integer AArch64 DBT (`sparc64rt`)

Run after `RC1` is merged to `master`. Frozen headers for this phase:
`src/core/cpu.h`, `src/os/syscall_nr.h`, `src/os/sigframe_sparc64rt.h`,
plus the cross-lane DBT interfaces frozen BELOW (do not change signatures
without the coordinator).

Primary adaptation templates: `../sparc32rt/src/dbt/*`,
`../sparc32rt/src/os/syscalls.c`, `../sparc32rt/include/a32host.h`,
`../sparc32rt/src/os/l2a_access.h` (guest-pointer + length validation).

## Frozen cross-lane DBT interfaces (Phase 2)

```c
/* src/dbt/dbt.h (owned by L2b) */
typedef struct sparc64_dbt sparc64_dbt_t; /* opaque dispatcher state */
int sparc64_dbt_init(sparc64_dbt_t *dbt);
void sparc64_dbt_fini(sparc64_dbt_t *dbt);
/* Run until exit/trap; falls back to sparc64_step for EXIT_UNDEF and
 * single-step cases. Owns the 4096-entry IBTC + 64-entry RAS. */
sparc64_step_result_t sparc64_dbt_run(sparc64_ctx_t *ctx,
    const sparc64_mem_ops_t *mem, void *mc, sparc64_dbt_t *dbt);
/* Invalidate translated code overlapping [va, va+len) (SMC/mprotect). */
void sparc64_dbt_invalidate(sparc64_dbt_t *dbt, uint64_t va, uint64_t len);

/* src/dbt/emit_int.h (owned by L2c) */
#include "interp/interp.h" /* sparc64_dec_t decoded form (classify_word) */
/* Emit one translated guest instruction; returns false when the op must
 * fall back to the interpreter (rare/system/privileged). Never emits
 * any read or write of AArch64 x18. */
bool sparc64_emit_int(/* emitter state, */ const sparc64_dec_t *d);
```

The DBT frontend decodes with L1b's `sparc64_classify_word`
(`src/interp/interp.h`, `sparc64_dec_t`); L1a's `decode.h` stays reserved
for the trace/disassembly frontend. Guest-memory access from emitted code
goes through the `sparc64_mem_ops_t` callbacks (no direct guest VA
dereference on the host). W^X: emit into RW staging, flip to
`PROT_READ|PROT_EXEC` + I-cache clear before execution.

---

### Lane `L2a` — Extended static-libc syscall layer (`src/os/`)
- **Worktree**: `../sparc64rt-l2a` on branch `lane/p2-l2a`
- **Exclusive Files**: `src/os/syscalls_min.c`, `src/os/syscalls_min.h`,
  `src/os/syscalls_ext.c`, `src/os/syscalls_ext.h`
- **Task**:
  1. Extend the Phase-1 dispatch in place (`syscalls_min.*`) and add
     `syscalls_ext.*` with: `stat`/`stat64`/`statx`/`lstat`, `readv`/
     `writev`, `openat`, `fcntl`/`fcntl64`, `clock_gettime`/
     `clock_getres`/`gettimeofday`, `getrandom`, `futex` (single-threaded:
     `FUTEX_WAIT`/`FUTEX_WAKE` via host futex), `rt_sigprocmask`,
     `ioctl` (pass-through for `TCGETS`/`TIOCGWINSZ` only, `ENOTTY`
     otherwise), `getpid`/`getuid`/`getgid`, `brk` stays in place.
  2. Struct translation `sparc64 <-> host` for `stat`, `iovec`,
     `timespec`, `timeval`, `winsize` (big-endian guest fields).
- **Acceptance Command**:
  ```sh
  cc -std=c11 -Werror=vla -pedantic -Wall -Wextra -Werror -Isrc -c src/os/syscalls_ext.c -o /tmp/sext.o
  ```

### Lane `L2b` — AArch64 DBT core (`src/dbt/`, `include/`)
- **Worktree**: `../sparc64rt-l2b` on branch `lane/p2-l2b`
- **Exclusive Files**: `src/dbt/dbt.c`, `src/dbt/dbt.h`,
  `src/dbt/trampoline_a64.S`, `include/a32host.h`
- **Task**:
  1. Implement `sparc64_dbt_init/fini/run/invalidate` per the frozen
     header: direct block chaining, 4096-entry IBTC, 64-entry RAS, block
     cache keyed by guest PC with page-version guards, W^X flip +
     `__builtin___clear_cache` (via `a32host.h`), interpreter fallback.
  2. `trampoline_a64.S`: host<->guest context switch (spill/fill the
     frozen `sparc64_ctx_t` prefix), never touching `x18`.
  3. `include/a32host.h`: `A32H_*` cache-maintenance + W^X helpers
     (adapt from `../sparc32rt/include/a32host.h`).
- **Acceptance Command**:
  ```sh
  cc -std=c11 -Werror=vla -pedantic -Wall -Wextra -Werror -Isrc -Iinclude -c src/dbt/dbt.c -o /tmp/dbt.o
  ```

### Lane `L2c` — AArch64 integer emitter (`src/dbt/emit_int.*`)
- **Worktree**: `../sparc64rt-l2c` on branch `lane/p2-l2c`
- **Exclusive Files**: `src/dbt/emit_int.c`, `src/dbt/emit_int.h`,
  `src/dbt/emit_priv.h`
- **Task**:
  1. Implement `sparc64_emit_int` for every integer `sparc64_dec_t` class
     the interpreter executes (ALU/shift/MOVcc/MOVr/RDASR/WRASR/JMPL/
     branches/BPcc/BPr/Tcc/SAVE/RESTORE/loads/stores/atomics, 64-bit
     semantics per the RC1 parity notes in `interp_win.c`).
  2. `emit_priv.h`: minimal A64 code-buffer + integer instruction
     encoders owned by the emitter (adapt from
     `../sparc32rt/src/dbt/emit_priv.h`).
- **Acceptance Command**:
  ```sh
  cc -std=c11 -Werror=vla -pedantic -Wall -Wextra -Werror -Isrc -Iinclude -c src/dbt/emit_int.c -o /tmp/emit.o
  ```

### Lane `L2d` — Difftest harness + static libc test suite
- **Worktree**: `../sparc64rt-l2d` on branch `lane/p2-l2d`
- **Exclusive Files**: `src/dbt/difftest.c`, `src/dbt/difftest.h`,
  `tests/test_p2_libc.c`
- **Task**:
  1. `difftest.*`: lockstep `interp` vs `dbt` comparison over the same
     guest (register + PC trace, first-divergence report, mismatch
     count). New files only; the coordinator wires `--difftest` into
     `src/main.c` after merge.
  2. `tests/test_p2_libc.c`: static-glibc guest (`hello`, `printf`,
     `malloc`/`free`, `qsort`, file `fopen`/`fread`/`fwrite`) with
     deterministic stdout. Build + oracle commands in the file header:
     `sparc64-linux-gnu-gcc -static` in the oracle image,
     `qemu-sparc64` golden output.
- **Acceptance Command**:
  ```sh
  cc -std=c11 -Werror=vla -pedantic -Wall -Wextra -Werror -Isrc -Iinclude -c src/dbt/difftest.c -o /tmp/diff.o
  ```
