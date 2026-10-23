# Phase E Task Cards — Empirical Pre-Implementation Experiments (`sparc64rt`)

Spawn **concurrent `subagent` worker lanes** for `E01..E06` in isolated worktrees (`../sparc64rt-e01` .. `../sparc64rt-e06`), merge each into `master`, and verify `RC-E`.

---

### Lane `E01` — `2047` (`0x7ff`) Stack Bias on `SAVE`/`RESTORE` & Initial `_start`
- **Worktree**: `../sparc64rt-e01` on branch `lane/pe-e01`
- **Exclusive Files**: `experiments/E01/**`
- **Task**:
  1. Write a minimal Curated C11 / inline-assembly probe in `experiments/E01/probe.c` (and `Makefile` or `run.sh`).
  2. Cross-compile for `SPARC V9 (`sparc64`, Oracle M8 / Fujitsu SPARC64 XII)` and run under `qemu-sparc64` (with `timeout --kill-after=30s 60s`).
  3. Record exact empirical findings, byte offsets (`sizeof`/`offsetof`), register values, and instruction encodings in `experiments/E01/FINDINGS.md`.
- **Acceptance Command**:
  ```sh
  test -s experiments/E01/FINDINGS.md
  ```

### Lane `E02` — Dual Carry Flag Update (`CCR.icc.C` & `CCR.xcc.C`) on `ta 0x6d`
- **Worktree**: `../sparc64rt-e02` on branch `lane/pe-e02`
- **Exclusive Files**: `experiments/E02/**`
- **Task**:
  1. Write a minimal Curated C11 / inline-assembly probe in `experiments/E02/probe.c` (and `Makefile` or `run.sh`).
  2. Cross-compile for `SPARC V9 (`sparc64`, Oracle M8 / Fujitsu SPARC64 XII)` and run under `qemu-sparc64` (with `timeout --kill-after=30s 60s`).
  3. Record exact empirical findings, byte offsets (`sizeof`/`offsetof`), register values, and instruction encodings in `experiments/E02/FINDINGS.md`.
- **Acceptance Command**:
  ```sh
  test -s experiments/E02/FINDINGS.md
  ```

### Lane `E03` — `BPcc`, `BPr`, `MOVcc`, `MOVr`, `CASA`/`CASXA` & Little-Endian ASIs
- **Worktree**: `../sparc64rt-e03` on branch `lane/pe-e03`
- **Exclusive Files**: `experiments/E03/**`
- **Task**:
  1. Write a minimal Curated C11 / inline-assembly probe in `experiments/E03/probe.c` (and `Makefile` or `run.sh`).
  2. Cross-compile for `SPARC V9 (`sparc64`, Oracle M8 / Fujitsu SPARC64 XII)` and run under `qemu-sparc64` (with `timeout --kill-after=30s 60s`).
  3. Record exact empirical findings, byte offsets (`sizeof`/`offsetof`), register values, and instruction encodings in `experiments/E03/FINDINGS.md`.
- **Acceptance Command**:
  ```sh
  test -s experiments/E03/FINDINGS.md
  ```

### Lane `E04` — SPARC64 `rt_signal_frame64` (528 B, `sparc_stackf` 192 B)
- **Worktree**: `../sparc64rt-e04` on branch `lane/pe-e04`
- **Exclusive Files**: `experiments/E04/**`
- **Task**:
  1. Write a minimal Curated C11 / inline-assembly probe in `experiments/E04/probe.c` (and `Makefile` or `run.sh`).
  2. Cross-compile for `SPARC V9 (`sparc64`, Oracle M8 / Fujitsu SPARC64 XII)` and run under `qemu-sparc64` (with `timeout --kill-after=30s 60s`).
  3. Record exact empirical findings, byte offsets (`sizeof`/`offsetof`), register values, and instruction encodings in `experiments/E04/FINDINGS.md`.
- **Acceptance Command**:
  ```sh
  test -s experiments/E04/FINDINGS.md
  ```

### Lane `E05` — SPARC V9 FPU (`%f0..%f31`, `%d0..%d62`, `%q0..%q60`, `fcc0..fcc3`) & VIS `faligndata`
- **Worktree**: `../sparc64rt-e05` on branch `lane/pe-e05`
- **Exclusive Files**: `experiments/E05/**`
- **Task**:
  1. Write a minimal Curated C11 / inline-assembly probe in `experiments/E05/probe.c` (and `Makefile` or `run.sh`).
  2. Cross-compile for `SPARC V9 (`sparc64`, Oracle M8 / Fujitsu SPARC64 XII)` and run under `qemu-sparc64` (with `timeout --kill-after=30s 60s`).
  3. Record exact empirical findings, byte offsets (`sizeof`/`offsetof`), register values, and instruction encodings in `experiments/E05/FINDINGS.md`.
- **Acceptance Command**:
  ```sh
  test -s experiments/E05/FINDINGS.md
  ```

### Lane `E06` — `glibc` `sparc64-unknown-linux-gnu` TLS (`%g7`) & `clone`
- **Worktree**: `../sparc64rt-e06` on branch `lane/pe-e06`
- **Exclusive Files**: `experiments/E06/**`
- **Task**:
  1. Write a minimal Curated C11 / inline-assembly probe in `experiments/E06/probe.c` (and `Makefile` or `run.sh`).
  2. Cross-compile for `SPARC V9 (`sparc64`, Oracle M8 / Fujitsu SPARC64 XII)` and run under `qemu-sparc64` (with `timeout --kill-after=30s 60s`).
  3. Record exact empirical findings, byte offsets (`sizeof`/`offsetof`), register values, and instruction encodings in `experiments/E06/FINDINGS.md`.
- **Acceptance Command**:
  ```sh
  test -s experiments/E06/FINDINGS.md
  ```

