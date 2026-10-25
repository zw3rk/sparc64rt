# Phase 6 — `hyper-linux` (`hl`) Host Contract & Dual-Host Parity (`RC6`)

All Phase 1–5 suites pass cleanly under the AArch64 Linux runtime
environment and host-contract harness. No guest-ISA work: this phase is
packaging, flags, broker wiring, and cross-host qualification.

## Starting facts (grounded)

- Contract: `../rt-series/docs/HOST-CONTRACT.md` v1.1. `sparc64rt` is
  Class-B (`EM_SPARCV9 (43)`, MSB, `e_flags & EF_SPARCV9_MM` in
  `{TSO,PSO,RMO}`), policy `CLASS_B`, CLI `--sparc64rt`, env
  `HL_SPARC64RT`, default sibling `../sparc64rt/_build/sparc64rt`.
- Family broker naming (`.sparc64rt-family-<pid>-<seq>`) and the `rt64`
  memory/file-cap/scheduler substrate already live in `src/rt64/`
  (copied from `rvrt` at Phase 0); AOT cache substrate likewise.
- `hl` binary runs on this host: `../hyper-linux/_build/hl` (macOS
  arm64, Hypervisor.framework). hl-side dispatch changes (if any) live
  in the `hyper-linux` repo: NOT this phase's to make — escalate.
- `SPARC64RT_ENGINE=interp|dbt` and `--interp/--dbt/--difftest` already
  exist (`src/main.c`). `SPARC64RT_SYSROOT` resolution lands in Phase 5
  (L5a); Phase 6 consumes it, never redefines it.

## Lane L6a — host-contract compliance (owns `src/main.c`, `src/rt64/` wiring)

- CLI/env table per contract §3.2 with the `SPARC64RT_` prefix:
  `--sysroot/--rootfs` (+ both env spellings), `--cache/--cache-dir`
  (+ both envs), `--engine` (+ env), `--execfn` (+ env), `--image-fd`,
  `--stats`. Explicit CLI overrides env. Unknown flags still fail hard
  (Wave-1 consumer rule: parser updates land HERE, before any hl
  change).
- `--image-fd FD` / `AT_EXECFD` descriptor hygiene per contract §3.1:
  any `FD >= 0` (including `0` with `errno`-checked `getauxval`), ELF
  load via position-independent reads, close loader-private fd after
  mapping, never touch guest fds `0,1,2` or inherited `>= 3`.
- Three authority policies (translator side only): accept
  `--cache-authority`, `--file-identity`, `--family-authority` with
  `auto` semantics (Linux ext4/tmpfs); `hyper-linux-*` values fail
  closed with a clear diagnostic until qualified on `hl`.
- Wire AOT cache identity (SHA-256 translator digest binds cache keys;
  dynamic `PT_INTERP` binds both file identities per §5.2) and verify
  the family broker name/sequence end to end.
- `--stats`: execution/dispatch counters to stderr on process exit.

Acceptance (bounded): a contract-probe script (new
`tests/check_host_contract.sh`, committed) asserting every flag/env
spelling, `AT_EXECFD=0`-with-closed-stdin handling, authority fail-
closed diagnostics, and family/AOT identity on Linux container; same
script green under `hl`. `echo L6A-HOST-PASS`.

## Lane L6b — dual-host parity suite (owns `tests/parity_*.sh`, gate log)

- Run the full suite — `test_p1_isa`, `test_p3_fp_simd`,
  `test_p4_threads_signals`, `test_p5_dyn`, BusyBox probe, adjacent
  4 KiB page-permission checks (`PROT_READ|PROT_EXEC` next to
  `PROT_READ|PROT_WRITE`, RELRO-next-to-`.bss` shape) — on (a) the
  AArch64 Linux container and (b) `hl` on this Mac, `--interp` and
  `--dbt` each, plus `--difftest` where single-threaded.
- `hl` invocation shape is lane-discovered (`hl --sparc64rt -- ...`);
  if `hl` cannot serve a leg, record the exact error and escalate —
  never paper over a host gap with a translator hack.
- Commit the runner + a gate log (`docs/rc6-parity.md`) with per-leg
  oracle/engine/host pass rows.

Acceptance (bounded): `docs/rc6-parity.md` shows every Phase 1–5 suite
green on both hosts, both engines. `echo L6B-PARITY-PASS`.

## Escalation & merge

- Contract ambiguity, any `hl`-side change, or a host gap: STOP, report.
- L6a owns `src/main.c` + `src/rt64/*` wiring; L6b owns only
  `tests/` + `docs/rc6-parity.md`. Merge `--no-ff` L6a then L6b.
- Coordinator runs gate `RC6`.

## Gate RC6 (coordinator record, master post-merge)

- Merged `--no-ff` L6a (`bbc59c6`) then L6b (`ca3a1aa`); disjoint
  files, no conflicts. `make build`, `make check`, line limits pass.
- Linux container: all Phase 1–5 suites green on both engines
  (P1-ISA-PASS, P3-PASS, P4-PASS, P5-PASS, BusyBox == golden),
  `check_host_contract.sh` 92 pass / 0 fail (`L6A-HOST-PASS`),
  difftest 0 divergences on all single-threaded legs.
- `hl` on this Mac: every leg matches the container bit-for-bit on
  both engines, except the exact BusyBox probe (G4 below).
- Coordinator rulings on recorded gaps (see `docs/rc6-parity.md`):
  G1 (qemu 10 vs 7.2 SIGBUS/FSR drift), G2 (qemu execve ENOEXEC),
  G3 (qemu cannot nested-exec SPARC; translator does) are oracle
  limitations — engines agree, accepted.
- G4 (HOST GAP, hl-side follow-up): under `hl`, guest `execve` of a
  host-foreign (Mach-O) binary traps deterministically
  (`cause=2 pc=0x60006a9b04`, 3/3) instead of failing cleanly; single
  execs fail clean ("not an ELF file" via the hl VFS layer). Only the
  forked-exec path traps, and only under `hl` (Linux runtime runs the
  host binary natively, qemu parity). Accepted for RC6 with the
  adapted SPARC-only BusyBox leg green cross-host (`3`, exit 0);
  follow-up belongs to the `hl` track (VFS identity mapping +
  foreign-binary exec policy; translator must fail closed there
  rather than trap). Translator-side fail-closed checks stay.
