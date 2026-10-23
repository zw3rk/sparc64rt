# `sparc64rt` — SPARC V9 (`sparc64`, Oracle M8 / Fujitsu SPARC64 XII) User-Mode Binary Translator for AArch64

`sparc64rt` is a zero-dependency, static-PIE (`aarch64-unknown-linux-musl`) user-mode binary translator for **SPARC V9 (`sparc64`, Oracle M8 / Fujitsu SPARC64 XII)** Linux ELF binaries on AArch64 Linux and macOS on Apple Silicon (via [`hyper-linux`](../hyper-linux)).

- **Series Tier**: Tier 2 (Wave 5 — Class-B 64-Bit Full Address Space, SPARC V9)
- **Target CPUs**: Oracle SPARC T8/M8 and Fujitsu SPARC64 XII (`SPARC-V9` + `VIS 1/2/3`)
- **ELF Admission**: `ELFCLASS64`, `ELFDATA2MSB` (big-endian), `e_machine == EM_SPARCV9 (43)`
- **Guest `TASK_SIZE`**: `1ULL << 47 (128 TiB user VA space, va_bits = 47)`
- **Dual Execution Engines**:
  1. `src/interp/` — Portable Curated C11 reference interpreter and differential oracle (`SPARC64RT_ENGINE=interp`)
  2. `src/dbt/` — Direct-mapped + IBTC AArch64 dynamic binary translator (`SPARC64RT_ENGINE=dbt`, default) with single-instruction interpreter fallback (`EXIT_UNDEF` / `EXIT_SINGLE_STEP`)

---

## Key Documents

| Document | Purpose |
|---|---|
| [`AGENTS.md`](AGENTS.md) | Repository ground rules, Curated C11 & AArch64 ABI invariants, Muse Spark Coordinator + Parallel Worker-Lane worktree protocol, and host environment notes. |
| [`SPEC.md`](SPEC.md) | Complete technical specification for `sparc64rt` (CPU context, ISA semantics, syscall/signal/thread ABI, host contract, and 9-phase verification pipeline). |
| [`GOAL.md`](GOAL.md) | Executable `/goal` specification for autonomous Muse Spark implementation (`Phase E` -> `Phase 0..Phase 7`). |
| [`docs/lanes/`](docs/lanes/) | Phase task cards (`phase-e.md`, `phase-0.md`, and subsequent phase lane cards). |
| [`../rt-series/`](../rt-series/) | Series-wide architecture (`../rt-series/SPEC.md`), master plan (`../rt-series/PLAN.md`), and host contract (`../rt-series/docs/HOST-CONTRACT.md`). |
