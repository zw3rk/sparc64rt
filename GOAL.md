# GOAL: Build, Verify, and Harden `sparc64rt` (SPARC V9 (`sparc64`, Oracle M8 / Fujitsu SPARC64 XII) -> AArch64 Binary Translator)

## Objective

Implement, verify, and harden **`sparc64rt`** — a zero-dependency, static-PIE (`aarch64-unknown-linux-musl`) user-mode binary translator for **SPARC V9 (`sparc64`, Oracle M8 / Fujitsu SPARC64 XII)** Linux ELF binaries on AArch64 Linux and macOS on Apple Silicon (`hyper-linux`) — from **Phase E** through **Phase 7 (`H1..H4`)** in full compliance with [`SPEC.md`](SPEC.md), [`AGENTS.md`](AGENTS.md), and [`../rt-series/SPEC.md`](../rt-series/SPEC.md).

## Autonomous Coordinator & Concurrent Subagent Execution Rules

1. **Operate with Full Autonomy Through All 9 Phases (`Phase E -> Phase 0 -> Phase 1 -> Phase 2 -> Phase 3 -> Phase 4 -> Phase 5 -> Phase 6 -> Phase 7`)**:
   - Do **not** stop after completing a single phase. Advance continuously from one phase to the next until every checkbox in this `GOAL.md` is `[x]` with committed code and verified test outputs on `master`.
2. **Use Workflows & Multiple Concurrent Subagents (`subagent`) in Isolated Git Worktrees**:
   - Act as the **Coordinator** on `master`.
   - Before each phase, freeze the phase's shared headers (`src/core/cpu.h`, `src/os/syscall_nr.h`, etc.) and write/update `docs/lanes/phase-<N>.md`.
   - Spawn **multiple concurrent `subagent` worker lanes in parallel** in isolated git worktrees (`git worktree add -b lane/<phase>-<lane> ../sparc64rt-<lane> master`). Use `list_workflows` / `run_workflow` where helpful.
   - Merge completed worker branches back to `master` (`git merge --no-ff`), remove the temporary worktrees (`git worktree remove ../sparc64rt-<lane>`), and run the phase Review Checkpoint (`RC`) gate before starting the next phase.
3. **Host Toolchain & Container Discipline**:
   - Compile `sparc64rt` with `PATH=/nix/store/82ac69jwkpj68v4mx22yxnwzqj0ql4l5-aarch64-unknown-linux-musl-gcc-wrapper-15.2.0/bin:$PATH aarch64-unknown-linux-musl-gcc -static-pie -fPIE ...` (or `nix build .#sparc64rt`).
   - Run AArch64 Linux and `qemu-sparc64` verification inside bounded Docker containers (`timeout --kill-after=30s 120s docker run --rm --name sparc64rt-<id> --memory 2g --cpus 2 --platform linux/arm64 -v "$PWD:/w" -w /w ...`) and verify container cleanup.

---

## Phase Checklist & Verification Gates

### Phase E — Pre-Implementation Empirical Experiments (`RC-E`)
Read [`docs/lanes/phase-e.md`](docs/lanes/phase-e.md) and run concurrent experiment lanes `E01..E06`:
- [x] **E01 (`2047` (`0x7ff`) Stack Bias on `SAVE`/`RESTORE` & Initial `_start`)**: Verify `[%sp + 2047]` 128-byte `rwindow_64` spill/fill and initial `_start` stack bias under `qemu-sparc64`. (`experiments/E01/FINDINGS.md`)
- [x] **E02 (Dual Carry Flag Update (`CCR.icc.C` & `CCR.xcc.C`) on `ta 0x6d`)**: Verify that `ta 0x6d` updates both `icc.C` (bit 0) and `xcc.C` (bit 4) so `bcs %icc` and `bcs %xcc` both work. (`experiments/E02/FINDINGS.md`)
- [x] **E03 (`BPcc`, `BPr`, `MOVcc`, `MOVr`, `CASA`/`CASXA` & Little-Endian ASIs)**: Verify SPARC V9 conditional branches/moves and `ASI_PRIMARY` (`0x80`) / `ASI_PRIMARY_LITTLE` (`0x88`) under `qemu-sparc64`. (`experiments/E03/FINDINGS.md`)
- [x] **E04 (SPARC64 `rt_signal_frame64` (528 B, `sparc_stackf` 192 B))**: Verify exact byte offsets of `sparc_stackf` (192 B), `pt_regs` (160 B), and `rt_signal_frame64` (528 B). (`experiments/E04/FINDINGS.md`)
- [x] **E05 (SPARC V9 FPU (`%f0..%f31`, `%d0..%d62`, `%q0..%q60`, `fcc0..fcc3`) & VIS `faligndata`)**: Verify V9 extended double registers, 4 FP condition code fields, and `alignaddr`/`faligndata`. (`experiments/E05/FINDINGS.md`)
- [x] **E06 (`glibc` `sparc64-unknown-linux-gnu` TLS (`%g7`) & `clone`)**: Verify `%g7` TLS pointer and `fork`/`clone` child `%o1 = 1` semantics under `qemu-sparc64`. (`experiments/E06/FINDINGS.md`)
- [x] **Gate `RC-E`**: All `experiments/E01..E06/FINDINGS.md` committed on `master` with target cross-compiler `sizeof`/`offsetof` and `qemu-sparc64` ground-truth verification.

### Phase 0 — Repository Scaffold, Frozen Headers & Substrate Copy (`RC0`)
Read [`docs/lanes/phase-0.md`](docs/lanes/phase-0.md) and run lanes `L0a..L0b`:
- [x] **Lane `L0a`**: Copy and adapt `src/rt64/ from ../rvrt (split into <= 900 LOC files)`, create `flake.nix`, `Makefile`, `src/core/cpu.h`, and CLI entry (`--version`, `--help`, `--interp`, `--dbt`, `--difftest`, `--trace`).
- [x] **Lane `L0b`**: Create `tests/check_abi_invariants.c` verifying all `sparc64_ctx_t`, `sigframe`, `ucontext`, and `stat` `sizeof`/`offsetof` invariants with `_Static_assert` and runtime checks.
- [x] **Gate `RC0`**: `_build/sparc64rt` builds cleanly as a static-PIE `aarch64-unknown-linux-musl` binary; `make check-line-limits` (`<= 900 LOC`) and `check_abi_invariants` pass.

### Phase 1 — Base Integer Decoder, Reference Interpreter (`src/interp/`) & Minimal Syscalls (`RC1`)
Write `docs/lanes/phase-1.md` and run concurrent lanes `L1a..L1d`:
- [x] **Lane `L1a`**: Instruction decoder (`src/interp/decode.c`, `src/interp/decode.h`).
- [x] **Lane `L1b`**: Base integer reference interpreter (`src/interp/interp.c`) including all control-flow, delay-slot/annul, register-window/prefix, unaligned, and atomic instructions in `SPEC.md` §2.
- [x] **Lane `L1c`**: Minimal Linux syscall layer (`exit`, `exit_group`, `write`, `read`, `brk`, `mmap`, `munmap`, `mprotect`, `uname`, `set_tid_address`).
- [x] **Lane `L1d`**: Freestanding ISA test suite (`tests/test_p1_isa.c`) covering ALU, shifts, branches, page-final branches before `PROT_NONE` pages, atomics, and unaligned loads/stores.
- [x] **Gate `RC1`**: `test_p1_isa` under `SPARC64RT_ENGINE=interp` matches `qemu-sparc64` exit code and stdout bit-for-bit.

### Phase 2 — Static Libc Syscalls & Base Integer AArch64 DBT (`src/dbt/`) (`RC2`)
Write `docs/lanes/phase-2.md` and run concurrent lanes `L2a..L2d`:
- [ ] **Lane `L2a`**: Complete static-libc Linux syscall & struct conversion layer (`src/os/syscalls.c`, `stat`/`stat64`/`statx`, `iovec`, `openat`, `fcntl`, `clock_gettime`, `getrandom`, `futex`, `rt_sigprocmask`, `ioctl`).
- [ ] **Lane `L2b`**: AArch64 DBT core (`src/dbt/dbt.c`, `src/dbt/trampoline_a64.S`, direct block chaining, 4096-entry IBTC, RAS, D2 `EXIT_UNDEF`/`EXIT_SINGLE_STEP` interpreter fallback).
- [ ] **Lane `L2c`**: AArch64 integer instruction emitter (`src/dbt/emit_int.c`).
- [ ] **Lane `L2d`**: Differential harness (`--difftest`) + static libc test suite (`hello`, `printf`, `malloc`, `qsort`, file I/O).
- [ ] **Gate `RC2`**: `--difftest` reports `0` register/PC mismatches between `interp` and `dbt` on `test_p1_isa` and static libc binaries; outputs match `qemu-sparc64`.

### Phase 3 — Floating-Point & SIMD (`src/interp/fp.c`, `src/dbt/emit_fp.c`) (`RC3`)
Write `docs/lanes/phase-3.md` and run concurrent lanes `L3a..L3c`:
- [ ] **Lane `L3a`**: Complete FPU & SIMD reference interpreter (`src/interp/fp.c`) implementing all `SPEC.md` §2 FP/SIMD instructions, NaN rules, condition codes, and status registers.
- [ ] **Lane `L3b`**: AArch64 FP & NEON emitter (`src/dbt/emit_fp.c`) + phase-gated `AT_HWCAP` activation.
- [ ] **Lane `L3c`**: `tests/test_p3_fp_simd.c` covering scalar FP, SIMD lanes, NaN propagation, rounding modes, and conversions.
- [ ] **Gate `RC3`**: `test_p3_fp_simd` matches `qemu-sparc64` golden output bit-for-bit on both `interp` and `dbt` with `0` `--difftest` divergences.

### Phase 4 — Signals (`rt_sigframe`), Threads (`clone`/`futex`/TLS), & Process Lifecycle (`fork`/`execve`) (`RC4`)
Write `docs/lanes/phase-4.md` and run concurrent lanes `L4a..L4c`:
- [ ] **Lane `L4a`**: Exact target Linux UAPI `rt_sigframe` construction & restoration (`rt_sigaction`, `rt_sigprocmask`, `rt_sigreturn`, `sigaltstack`, synchronous `SIGSEGV`/`SIGILL`/`SIGFPE`/`SIGBUS`/`SIGTRAP` delivery).
- [ ] **Lane `L4b`**: Multithreading (`clone` with `CLONE_VM|CLONE_THREAD|CLONE_SETTLS|CLONE_CHILD_CLEARTID`, `futex`, TLS register, LL/SC reservation invalidation across helpers/signals/threads).
- [ ] **Lane `L4c`**: Process lifecycle (`fork`, `vfork`, `execve`, `wait4`, `waitid`, `pipe2`, `dup2`) and `tests/test_p4_threads_signals.c`.
- [ ] **Gate `RC4`**: `test_p4_threads_signals` (signal frame inspection/modification/restoration, pthreads + futex, `fork`+`execve`+`wait4`) matches `qemu-sparc64` on both `interp` and `dbt`.

### Phase 5 — Dynamic Linking (`PT_INTERP`), `BusyBox`, & Target `libc` Matrix (`RC5`)
Write `docs/lanes/phase-5.md` and run concurrent lanes `L5a..L5b`:
- [ ] **Lane `L5a`**: `PT_INTERP` dynamic loader (`ld.so`) mapping, complete auxiliary vector (`AT_PHDR`, `AT_ENTRY`, `AT_BASE`, `AT_HWCAP`, `AT_HWCAP2`, `AT_RANDOM`, `AT_EXECFN`), and `/proc/self/{exe,maps,cmdline,stat,auxv}` interception.
- [ ] **Lane `L5b`**: Dynamic `test_p5_dyn` (`dlopen`/`dlsym`, TLS `__thread`, shared library calls) and target `BusyBox` qualification (`sh -c 'ls / && echo ok | wc -c'`).
- [ ] **Gate `RC5`**: Dynamic `test_p5_dyn` and `BusyBox` match `qemu-sparc64` on both `interp` and `dbt`.

### Phase 6 — `hyper-linux` (`hl`) Host Contract & Dual-Host Parity (`RC6`)
Write `docs/lanes/phase-6.md` and run lanes `L6a..L6b`:
- [ ] **Lane `L6a`**: Verify full compliance with `../rt-series/docs/HOST-CONTRACT.md` (`HL_MEMORY_POLICY_RVRT, family broker, and AOT cache identity`).
- [ ] **Lane `L6b`**: Run full parity suite (`test_p1_isa`, `test_p3_fp_simd`, `test_p4_threads_signals`, `test_p5_dyn`, adjacent 4 KiB page permissions).
- [ ] **Gate `RC6`**: All Phase 1–5 suites pass cleanly under the AArch64 Linux runtime environment and host-contract harness.

### Phase 7 — Hardening (`SMC`, `libc-test`, LTP Syscall Subset, Instrumented CoreMark, C++17) (`RC-H`)
Write `docs/lanes/phase-7.md` and run concurrent hardening lanes `H1..H4`:
- [ ] **Lane `H1` (`tests/test_h1_smc.c`)**: Self-modifying code & W^X verification (rewrite guest instructions on stack/heap/anon mmap, flush cache, re-execute in `dbt`).
- [ ] **Lane `H2` (`docs/h2-report.md`)**: Run target `libc-test` (math, string, pthread, sig, functional) and LTP syscall subset; commit `docs/h2-report.md` with machine-enforced pass/skip/fail assertions (`0` unexpected failures).
- [ ] **Lane `H3` (`docs/h3-coremark.md`)**: Follow the mandatory 6-step performance loop (`AGENTS.md`: Instrument -> Measure -> Hypothesise -> Fix -> Measure again -> Validate) on CoreMark and commit `docs/h3-coremark.md` demonstrating verified `dbt > interp` throughput.
- [ ] **Lane `H4` (`tests/test_h4_cxx17.cc`)**: Compile and verify a C++17 binary exercising `try`/`catch` stack unwinding across signal/call frames, `dynamic_cast` RTTI, `std::thread`, and `thread_local` destructors.
- [ ] **Gate `RC-H`**: All `H1..H4` artifacts and tests pass on `master`; `make check` and `make check-line-limits` pass with a clean git tree.
