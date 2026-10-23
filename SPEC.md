# `sparc64rt` — Technical Specification & Execution Plan

**Target Architecture**: SPARC V9 (`sparc64`, Oracle M8 / Fujitsu SPARC64 XII)
**Target Host**: AArch64 Linux (`aarch64-unknown-linux-musl` static-PIE) & macOS on Apple Silicon via `hyper-linux` (`hl`)
**Series Tier**: Tier 2 (Wave 5 — Class-B 64-Bit Full Address Space, SPARC V9)

---

## 0. Execution Protocol (Muse Spark Coordinator + Parallel Worker-Lane DAG)

1. **Coordinator + Parallel Worker-Lane Split**:
   - The **Coordinator** (`muse` on `master`) owns frozen headers (`src/core/cpu.h`, `include/a32host.h`, `src/os/syscall_nr.h`), `Makefile`, `flake.nix`, `docs/lanes/phase-*.md`, git worktree creation/cleanup, `--no-ff` merges, and phase-level Review Checkpoints (`RC-E`, `RC0..RC6`, `RC-H`).
   - **Concurrent Subagents & Workflows**:
     - For every phase (`Phase E`, `Phase 0` .. `Phase 7`), spawn **multiple concurrent `subagent` worker lanes in parallel** using isolated git worktrees (`../sparc64rt-<lane>` on branch `lane/<phase>-<lane>`) and use `run_workflow` / `list_workflows` where helpful.
     - Each worker lane has **exclusive file ownership**, codes against **frozen headers**, and runs **one bounded acceptance check** (`timeout --kill-after=30s ...`).
2. **Dual-Oracle Verification**:
   - Every phase validates `src/interp/` against the independent **`qemu-sparc64` ground-truth oracle** first, and then validates `src/dbt/` against `src/interp/` via `--difftest` (`0` register/PC mismatches).

---

## 1. Target Profile, ELF Admission & Substrate Architecture

### 1.1 Target CPUs & ELF Admission
- **Target CPUs**: Oracle SPARC T8/M8 and Fujitsu SPARC64 XII (`SPARC-V9` + `VIS 1/2/3`)
- **ELF Admission**: `ELFCLASS64`, `ELFDATA2MSB` (big-endian), `e_machine == EM_SPARCV9 (43)`
- **Guest `TASK_SIZE`**: `1ULL << 47 (128 TiB user VA space, va_bits = 47)`
- **Ground-Truth Oracle**: `qemu-sparc64`
- **Cross Toolchains**: `pkgsCross.sparc64-linux (sparc64-unknown-linux-gnu glibc + nolibc; upstream musl has no sparc64 port)`

### 1.2 Class-B 64-Bit Full Address Space & `src/rt64/` Copy-First Substrate
- `sparc64rt` preserves strict separation between Guest VA (`uint64_t`), Translator VA, and Host GPA. Never truncate 64-bit guest addresses or force a 64-bit guest into a 4 GiB window.
- **Phase 0 Lane `L0a`** copies the proven `rt64` substrate from `../rvrt/src/` into `src/rt64/` and splits any large files so every `.c`/`.h` file is `<= 900` lines (`make check-line-limits`):
  1. `../rvrt/src/memory/{space.c,space.h}` -> `src/rt64/memory/{space.c,space.h}` (parameterized on `1ULL << 47 (128 TiB user VA space, va_bits = 47)`).
  2. `../rvrt/src/runtime/{family.c,family_mm.c,mm_view.c,file_caps.c,mm_join.c,family_wait.c,family_file_index.c,guest_memory.c,scheduler.c,native_signal.c,safe_syscall_a64.S,exec_state.c}` (+ `.h`) -> `src/rt64/runtime/` (parameterized on `.sparc64rt-family-<pid>-<seq>` and `sparc64_ctx_t`).
  3. `../rvrt/src/linux/{memory.c,file.c,io.c,poll.c,socket.c,metadata.c,exec_args.c}` (+ `.h`) -> `src/rt64/linux/` plus modular `src/main.c`, `src/rt64/runtime/worker_loop.c`, `src/rt64/linux/signal_core.c`, and `src/linux/signal_frame_sparc64rt.c` (all `< 900 LOC`, with signal trampoline placed below the profile's `TASK_SIZE`).
  4. `../rvrt/src/aot/{format.c,reader.c,writer.c}` (+ `.h`) -> `src/rt64/aot/` (parameterized on `sparc64rt` `e_machine`, `e_flags`, and endianness).

---

## 2. CPU Context, ISA Semantics & Linux ABI

### 2.1 `sparc64_ctx_t` Context, Stack Bias `2047`, VIS & SPARC64 Syscall/Signal ABI
- **64-Bit Register Windows & Mandatory `2047` (`0x7ff`) Stack Bias**:
  - Every `SAVE` and `RESTORE` spills/fills 16 × 64-bit big-endian registers (`%l0..%l7` and `%i0..%i7`, 128 bytes = `struct rwindow_64`) at **`[%sp + 2047 + 0 .. %sp + 2047 + 120]`**.
  - Initial `_start` stack sets `%sp = actual_frame_ptr - 2047`, placing `rwindow_64` (128 B) at `[%sp + 2047]` and `argc` at `[%sp + 2047 + 128]`.
- **Dual Integer Condition Codes (`CCR.icc` and `CCR.xcc`) & VIS**:
  - `*cc` integer instructions update both `icc` (bits `31:0`) and `xcc` (bits `63:0`).
  - Supports `BPcc` (`%icc`/`%xcc` with prediction), `BPr` (`BRZ`, `BRLEZ`, `BRLZ`, `BRNZ`, `BRGZ`, `BRGEZ`), `MOVcc`, `MOVr`, `FMOVcc`, `FMOVr`, `MULX`, `SDIVX`, `UDIVX`, `CASA`/`CASXA` (`ASI_PRIMARY = 0x80`, `ASI_PRIMARY_NOFAULT = 0x82`, `ASI_PRIMARY_LITTLE = 0x88`, `ASI_PRIMARY_NOFAULT_LITTLE = 0x8a`), FPU `%f0..%f31` / `%d0..%d62` / `%q0..%q60`, `FSR` (`fcc0..fcc3`), and `GSR` (`alignaddr`, **`faligndata`**).
- **SPARC64 Linux Syscall (`ta 0x6d` = `0x91d0206d`) — Dual Carry Flag Update (`arch/sparc/kernel/syscalls.S`)**:
  - Syscall number in `%g1`, args in `%o0..%o5`.
  - **Success (`ret >= 0`)**: Clears **BOTH `CCR.icc.C` (bit 0) AND `CCR.xcc.C` (bit 4)** (`TSTATE_ICARRY | TSTATE_XCARRY`), sets `%o0 = (uint64_t)ret`, and advances `pc = npc; npc += 4`.
  - **Error (`ret < 0`)**: Sets **BOTH `CCR.icc.C = 1` AND `CCR.xcc.C = 1`**, sets `%o0 = sparc_errno_from_host(-ret)` (positive SPARC errno), and advances `pc = npc; npc += 4`.
- **Complete SPARC64 `rt_signal_frame64` Layout (`src/os/sigframe_sparc64.h`, Verified in `tests/check_abi_invariants.c`)**:
  - Placed at `unbiased_sp = %sp + 2047` (16-byte aligned); handler receives biased `%sp = unbiased_sp - 2047`.
  - Per Linux `arch/sparc/include/uapi/asm/ptrace.h` and `arch/sparc/kernel/signal_64.c`, `rt_signal_frame64` (**528 bytes** fixed structure before optional FPU/rwin tail) has exact offsets:
    - `0x000..0x0bf`: **`struct sparc_stackf ss` (192 bytes)**: `uint64_t locals[8]` (64 B) + `uint64_t ins[6]` (48 B) + `uint64_t fp` (8 B) + `uint64_t callers_pc` (8 B) + `uint64_t structptr` (8 B) + `uint64_t xargs[6]` (48 B) + `uint64_t xxargs[1]` (8 B),
    - `0x0c0..0x13f`: `siginfo_t info` (128 B),
    - `0x140..0x1df`: `struct pt_regs regs` (160 B: `uint64_t u_regs[16], tstate, tpc, tnpc; uint32_t y, magic;`),
    - `0x1e0..0x1e7`: `uint64_t fpu_save` (8 B guest pointer to `sigfpu` tail or `0`),
    - `0x1e8..0x1ff`: `sparc64_stack_t stack` (24 B: `{uint64_t ss_sp; int32_t ss_flags; int32_t _pad; uint64_t ss_size;}`),
    - `0x200..0x207`: `uint64_t mask` (8 B `sigset_t`),
    - `0x208..0x20f`: `uint64_t rwin_save` (8 B guest pointer or `0`),
    - `0x210..`: optional inline `sigfpu` and `rwin_save` tails.

---

## 3. Dual-Engine Design (`src/interp/` + `src/dbt/`)

1. **Reference Interpreter (`src/interp/`)**:
   - Pure Curated C11 step-by-step and chunked interpreter (`interp_step(sparc64_ctx_t *ctx)` and `interp_run(sparc64_ctx_t *ctx)`).
   - Serves as:
     - Ground-truth reference engine (`SPARC64RT_ENGINE=interp` or `--interp`),
     - Instruction-by-instruction differential oracle (`--difftest`),
     - Single-instruction fallback (`EXIT_UNDEF` / `EXIT_SINGLE_STEP` -> `interp_step(ctx)` -> resume DBT) for rare system/unaligned/cross-page delay-slot instructions so valid instructions never abort execution.
2. **AArch64 Dynamic Binary Translator (`src/dbt/`)**:
   - Translates guest basic blocks (up to 64 guest instructions, terminating at control transfers or page boundaries) into AArch64 machine code using `a64_emit.[ch]`.
   - Direct block chaining + 4096-entry per-thread Indirect Branch Target Cache (`IBTC`) + Return Address Stack (`RAS`).
   - Enforces W^X (`PROT_READ | PROT_WRITE` during emission -> `PROT_READ | PROT_EXEC` before execution + `__builtin___clear_cache` / `A32H_CAP_ICACHE_TRAP_IALLU`) and self-modifying code (`SMC`) page-version invalidation on `mprotect` / `munmap` / `clear_cache` / guest writes to translated pages.
   - **Never touches `x18`**.

---

## 4. Nine-Phase Implementation Pipeline & Review Checkpoints (`RC`)

| Phase / Gate | Lanes (Run in Parallel Worktrees) | Required Independent Oracle & Acceptance Gate |
|---|---|---|
| **Phase E (`RC-E`)** | `E01` .. `E06` (`experiments/E01..E06/FINDINGS.md`) | All 6 empirical probes compiled with target cross-CC, executed under `qemu-sparc64`, and committed with `FINDINGS.md` (`sizeof`/`offsetof` verified). |
| **Phase 0 (`RC0`)** | `L0a` (Substrate copy + build), `L0b` (`tests/check_abi_invariants.c` + CLI smoke) | `aarch64-unknown-linux-musl-gcc -static-pie` builds `_build/sparc64rt`; `make check-line-limits` (`<= 900 LOC`) and `check_abi_invariants` pass; `--version` / `--help` pass in AArch64 Docker container. |
| **Phase 1 (`RC1`)** | `L1a` (Decoder), `L1b` (Integer `src/interp/`), `L1c` (Minimal syscalls `exit`, `write`, `brk`, `mmap`), `L1d` (`test_p1_isa`) | `test_p1_isa` (covering ALU, shifts, branches, delay slots/annul at `page_end - 4` before `PROT_NONE` page, atomics, unaligned accesses) matches `qemu-sparc64` exit code and stdout bit-for-bit under `SPARC64RT_ENGINE=interp`. |
| **Phase 2 (`RC2`)** | `L2a` (`src/os/` static libc syscalls + struct translation), `L2b` (`src/dbt/` dispatcher + block cache + IBTC), `L2c` (`src/dbt/emit_int.c`), `L2d` (`difftest` + static libc tests) | `--difftest` reports `0` register/PC mismatches between `interp` and `dbt` on `test_p1_isa`; static `hello`, `printf`, `qsort`, `malloc`, and file I/O match `qemu-sparc64` on both `interp` and `dbt`. |
| **Phase 3 (`RC3`)** | `L3a` (`src/interp/fp.c` FPU/SIMD), `L3b` (`src/dbt/emit_fp.c` NEON/FP lowering), `L3c` (`test_p3_fp_simd`) | `test_p3_fp_simd` (NaN modes, rounding, FPU/SIMD corner cases) matches `qemu-sparc64` bit-for-bit on both `interp` and `dbt` with `0` difftest divergences. |
| **Phase 4 (`RC4`)** | `L4a` (`rt_sigframe` + `rt_sigaction`/`rt_sigreturn`/altstack), `L4b` (`clone`/TLS/`futex`/reservation invalidation), `L4c` (`fork`/`vfork`/`execve`/`wait4` + `test_p4_threads_signals`) | `test_p4_threads_signals` (signal frame inspection/modification/restoration, `SIGSEGV` recovery, pthreads + futex + atomics, `fork`+`execve`+`wait4`) matches `qemu-sparc64` on both `interp` and `dbt`. |
| **Phase 5 (`RC5`)** | `L5a` (`PT_INTERP` dynamic linker loading + auxv + `/proc/self/*`), `L5b` (Dynamic `glibc`/`musl` + `BusyBox` suite) | Dynamic `test_p5_dyn` and `BusyBox` (`sh -c 'ls / && echo ok | wc -c'`) match `qemu-sparc64` on both `interp` and `dbt`. |
| **Phase 6 (`RC6`)** | `L6a` (`hyper-linux` host contract & packaging), `L6b` (Both-host parity test suite) | `test_p1_isa`, `test_p3_fp_simd`, `test_p4_threads_signals`, `test_p5_dyn`, and `BusyBox` pass on both AArch64 Linux container and `hl` (`hyper-linux`). |
| **Phase 7 (`RC-H`)** | `H1` (`test_h1_smc`), `H2` (`libc-test` + LTP syscall subset -> `docs/h2-report.md`), `H3` (6-step instrumented CoreMark -> `docs/h3-coremark.md`), `H4` (C++17 exceptions/RTTI/TLS smoke) | All 4 hardening gates committed with machine-verified pass counts (`0` unexpected failures) and measured `dbt > interp` speedup in `docs/h3-coremark.md`. |
