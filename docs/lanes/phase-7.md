# Phase 7 — Hardening (`SMC`, `libc-test`, LTP Syscall Subset, Instrumented CoreMark, C++17) (`RC-H`)

All `H1..H4` artifacts and tests pass on `master`; `make check` and
`make check-line-limits` pass with a clean git tree. Four concurrent
lanes, disjoint files, no shared-code writes without coordinator merge
order (H1, H4 engine-adjacent first; H2, H3 evidence-only, merge last).

## Starting facts (grounded)

- `sparc64_dbt_invalidate` exists and is wired into loader/mmap paths;
  W^X holds by construction (guest data pages never mapped `PROT_EXEC`
  on the host; A64 code goes through RW-staging → RX flip + I-cache
  clear). H1 turns this into a verified test.
- Cross toolchains come from Debian containers
  (`gcc-sparc64-linux-gnu`, `g++-sparc64-linux-gnu` for H4,
  `qemu-user` oracle). Network verified.
- Static + dynamic guests, threads, and signals are green on both
  engines (RC4/RC5 gates); hardening must not regress them.

## Lane H1 — `tests/test_h1_smc.c`: SMC & W^X

- Guest rewrites its own instructions on stack, heap, and anonymous
  `mmap`, executes the new code, on both engines. Covers the SPARC
  `FLUSH` instruction (oracle first: `qemu-sparc64` ground truth for
  `FLUSH` visibility semantics, then interp, then dbt invalidation).
- W^X leg: `mmap` with `PROT_WRITE|PROT_EXEC` (and `mprotect` adding
  `PROT_EXEC` to data) must fail; RX-flipped code pages execute.
- Deterministic stdout, exit 0 iff all pass. Oracle vs `--interp` vs
  `--dbt` bit-for-bit + `--difftest` 0 divergences.
  `echo H1-SMC-PASS`.

## Lane H2 — `docs/h2-report.md`: `libc-test` + LTP syscall subset

- Build the target `libc-test` suite (libc-agnostic C tests: string,
  math, pthread, semaphore, signal, functional) with the cross
  toolchain against target glibc; run under oracle + both engines.
- LTP syscall subset: the file/process/memory/signal syscalls the
  translator claims (scope the list from `src/os/syscall_nr.h` + the
  Phase 1–5 guests; no cherry-picking failures away).
- Commit `docs/h2-report.md` with machine-enforced pass/skip/fail
  assertions: every row carries the exact command that produced it,
  `0` unexpected failures (skips enumerated with reason).
  `echo H2-LIBC-PASS`.

## Lane H3 — `docs/h3-coremark.md`: instrumented CoreMark, 6-step loop

- Port CoreMark to `sparc64` (cross build, static to isolate CPU from
  loader noise), run under oracle + `--interp` + `--dbt`.
- Mandatory loop, evidenced in the report: Instrument → Measure →
  Hypothesise → Fix → Measure again → Validate, each step with numbers.
- Commit `docs/h3-coremark.md` demonstrating verified `dbt > interp`
  throughput with the winning change identified (no vibe tuning: the
  report must show the before/after that proves the claim).
  `echo H3-COREMARK-PASS`.

## Lane H4 — `tests/test_h4_cxx17.cc`: C++17 exceptions, RTTI, threads

- Dynamic C++17 guest (`g++-sparc64-linux-gnu`) exercising:
  `try`/`catch` across signal frames (throw from a `SIGUSR1` handler,
  catch in main), `dynamic_cast` RTTI across a DSO boundary,
  `std::thread` + `thread_local` destructors ordering.
- Unwinding needs `_Unwind_*` + `.eh_frame`/`PT_GNU_EH_FRAME` handling
  in the loader (narrow touch, H4-owned) and correct
  `sigaction`/`sigaltstack` interplay (already green at RC4).
- Oracle vs `--interp` vs `--dbt` bit-for-bit. `echo H4-CXX-PASS`.

## Escalation & merge

- Any frozen-header/`Makefile` change, loader-contract conflict between
  H1/H4, or a toolchain gap (no `libstdc++` for sparc64, no CoreMark
  source): STOP, report.
- Files: H1 = `tests/test_h1_smc.c`; H2 = `docs/h2-report.md` (+ runner
  under `tests/`); H3 = `docs/h3-coremark.md` (+ port notes);
  H4 = `tests/test_h4_cxx17.cc` (+ narrow loader touch, flagged).
- Coordinator merges `--no-ff` H1, H4, H2, H3; runs `RC-H`.
