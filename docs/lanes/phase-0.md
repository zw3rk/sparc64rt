# Phase 0 Task Cards — Repository Scaffold, Frozen Headers & Substrate Copy (`sparc64rt`)

Run after `RC-E` is merged to `master`.

---

### Lane `L0a` — Substrate Copy, Frozen Headers (`src/core/cpu.h`), Build System (`Makefile`, `flake.nix`) & CLI Entry
- **Worktree**: `../sparc64rt-l0a` on branch `lane/p0-l0a`
- **Exclusive Files**: `Makefile`, `flake.nix`, `src/core/cpu.h`, `src/main.c`, `src/os/syscall_nr.h`, `src/rt64/**`
- **Task**:
  1. Copy and adapt the `src/rt64/ substrate from ../rvrt/src/ (memory/space.[ch], runtime/*, linux/*, aot/*), splitting runtime_main.c and signal.c so every file is <= 900 LOC`.
  2. Define `sparc64_ctx_t` in `src/core/cpu.h` matching `SPEC.md` §2.1 exact offsets.
  3. Implement `src/main.c` supporting `--version`, `--help`, `--interp`, `--dbt`, `--difftest`, `--trace`, and `SPARC64RT_ENGINE=interp|dbt`.
  4. Create `Makefile` (with `build`, `check`, `check-line-limits`, `check-abi-invariants`, `clean`, `help`) and `flake.nix`.
- **Acceptance Command**:
  ```sh
  PATH=/nix/store/82ac69jwkpj68v4mx22yxnwzqj0ql4l5-aarch64-unknown-linux-musl-gcc-wrapper-15.2.0/bin:$PATH make build check-line-limits
  ```

---

### Lane `L0b` — ABI Invariant Verification Suite (`tests/check_abi_invariants.c`)
- **Worktree**: `../sparc64rt-l0b` on branch `lane/p0-l0b`
- **Exclusive Files**: `tests/check_abi_invariants.c`, `src/os/sigframe_sparc64rt.h`
- **Task**:
  1. Define the frozen target UAPI signal frame (`sigframe_sparc64rt.h`), `ucontext`, `sigcontext`/`mcontext`, and `stat` structs matching `SPEC.md` §2 and `experiments/E04/FINDINGS.md`.
  2. Write `tests/check_abi_invariants.c` with `_Static_assert` and runtime offset checks verifying every field offset and struct size in `sparc64_ctx_t` and `sigframe_sparc64rt.h`.
- **Acceptance Command**:
  ```sh
  cc -std=c11 -Werror=vla -pedantic -Wall -Wextra -Werror -Iinclude -Isrc tests/check_abi_invariants.c -o _build/check_abi_invariants && ./_build/check_abi_invariants
  ```
