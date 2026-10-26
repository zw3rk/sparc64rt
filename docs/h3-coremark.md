# H3 — Instrumented CoreMark (SPARC V9 → AArch64)

Lane H3, worktree `sparc64rt-h3`, branch `lane/phase7-h3`.
Acceptance: committed report with before/after numbers proving
verified `dbt > interp` throughput with the winning change identified.

## 1. Port notes

- CoreMark upstream (`eembc/coremark` tarball) cross-built in the
  `sparc64rt-p5` container (debian:stable-slim + sparc64 toolchain):
  `sparc64-linux-gnu-gcc -static -O2 -mcpu=ultrasparc`. Static link
  isolates CPU translation from loader/syscall noise. Guest binary:
  `/tmp/cm-h3/coremark-sparc64-static.exe` (host), mounted as `/g`.
- Correct argv form puts `--` between engine flags and guest argv:
  `sparc64rt --interp -- /g/coremark-sparc64-static.exe 0x0 0x0 0x66
  50 7 1 2000`. A bare `--` is consumed by the runner, not passed
  through; leaking it as `argv[1]` makes the divisor zero and traps
  the guest in `udiv` (this was a real red herring mid-lane).
- Oracle: `qemu-sparc64` on the build container. 10-iter oracle CRCs:
  `seedcrc e9f5, list e714, matrix 1fd7, state 8e3a, final fcaf`.
- Runner invocations use
  `timeout --kill-after=30s <t> docker run --rm --platform
  linux/arm64 --memory 2g --cpus 2 -v "$PWD:/w" -v /tmp/cm-h3:/g`
  with `docker ps` cleanup; strays are removed, never reused.

## 2. Instrument → Measure (baseline, current tree at lane start)

Oracle first: all three benchmark CRCs match under `--interp`.
`--dbt` also matches all three CRCs (see §6 for the one misleading
line both engines print). 50-iter, 3× interleaved, `--stats`:

| run | interp Iter/s | interp utime_us | dbt Iter/s | dbt utime_us |
|-----|------|---------|------|---------|
| 1 | 5.73 | 8,803,314 | 6.05 | 8,570,060 |
| 2 | 9.49 | 5,326,487 | 8.39 | 6,133,365 |
| 3 | 12.58 | 3,995,233 | 8.68 | 6,097,846 |

Medians: interp 5,326,487 µs (9.49/s), dbt 6,133,365 µs (8.39/s).
dbt is ~0.87× interp: acceptance NOT met. Run-to-run variance is
large (cold page cache in the Docker VM warms across runs), hence
the interleaved medians. Temporary block-cache telemetry (added,
measured, then fully reverted — no `h3temp` remains in `src/`) on a
50-iter dbt run gave the decisive split:

- `blocks=12,881 translated, ibtc=8,241,243 hits`
  (direct-cache hits 0 because the IBTC front-cache absorbs them).
- Native entries 1,767,146 of ~8.24M total (21%); ~79% of dynamic
  block entries replay in the interpreter at ~5.5 insns/block.
- `stime_us` ~290 ms (interp ~30–60 ms): constant `mprotect` churn.

Sampling the replay loop showed hot CoreMark `.text` blocks
(`0x1018b0`, `0x101970`, …) with `no_host_code`, and sampling the
emit-range refusal sites showed only cold glibc FPU/delay blocks.

## 3. Hypothesise

`dbt_emit_range` reserves `DBT_EMIT_STAGE_BYTES` (12 KB) per
translation and, on success, keeps all of it. The 4 MB arena therefore
fills after ~341 translations and recycles: `arena_used = 0` plus
`host_code = NULL` on every cached block. The run translates
~12.8 K blocks (~37 fills), and each recycle drops all resident
native code. Stale descriptors stay `valid`, so the IBTC keeps
serving them (hence the 8.24 M IBTC hits) straight into the
interpreter-replay loop — permanent zombie replay, plus a full-arena
I-cache clear and `mprotect` storm per fill (~290 ms stime).
Coverage fixes applied earlier in this lane (wider delay gate, JMPL
target snapshot, native RETURN below) only increased translation
volume, making the churn worse — the rewind below harvests all of it.

## 4. Fix (minimal, measured — no vibe tuning)

Prerequisite correctness fix (interp was wrong, oracle proved it):
UMUL/SMUL/UMULCC/SMULCC now keep the full 64-bit product in `rd`,
`Y` takes the high 32, and `mulcc` sets xcc N/Z from the full 64-bit
result (`probe_umul`: `rd=64000000190 y=640` on both engines).

Coverage (kept: validated by the §6 difftest, not the perf win):

- Delay gate (`dbt_delay_emittable`) widened to match
  `e_delay_is_plain` (SETHI/nop, MEMBAR/FLUSH, LDSTUB/SWAP,
  SAVE/RESTORE); JMPL snapshots the register-indirect target across
  the delay (`sb_push64/pop64` in `emit_priv.h`) per interp
  `exec_cti` order (fixes ret-with-restore).
- Native RETURN (`e_emit_jmpl_ret` shared with JMPL in
  `src/dbt/emit_int.c`): `return` snapshots its target, runs the V9
  A.45 implicit restore (`e_call_win(rd=%g0)`, sum discarded), then
  the delay, then transfers; no `rd` write. SAVE/RESTORE delays
  under RETURN refuse (no double rotation) and replay pristinely.

Winning change (one hunk in `dbt_emit_range`, `src/dbt/dbt.c`):
on success, rewind the stage to the bytes actually emitted:

```c
dbt->arena_used = used_before + (size_t)buf.count * 4U;
```

A 12 KB scratch reservation per block becomes ~100–500 B committed.
`make build` is `-Werror`-clean; `emit_int.c` held at 899 lines via
comment condensing only (no behaviour touched).

## 5. Measure again (same 50-iter 3× interleaved protocol)

| run | interp Iter/s | interp utime_us | dbt Iter/s | dbt utime_us | dbt stime_us |
|-----|------|---------|------|---------|------|
| 1 | 7.90 | 6,365,940 | 33.00 | 1,622,427 | 65,017 |
| 2 | 10.21 | 4,947,178 | 27.69 | 1,962,337 | 56,095 |
| 3 | 7.43 | 6,806,259 | 30.12 | 1,790,378 | 74,015 |

Medians: interp 6,365,940 µs (7.90/s), dbt 1,790,378 µs (30.12/s).
**dbt is 3.56× faster than interp** (utime ratio; Iter/s 30.1 vs
7.9). `stime` collapsed 290 ms → ~65 ms (no recycle storm). Every
run prints `list e714 / matrix 1fd7 / state 8e3a`, identical to the
oracle. The staging rewind is the identified winning change: it
converts the 79% zombie-replay entries to native execution.

## 6. Validate

- `--difftest`, full program, 1 iteration: **0 divergences
  (395,136 steps, guest exit 0)**, `Correct operation validated`
  (covers startup, `sysmalloc` ret-with-restore, all three
  benchmarks, teardown). Lockstep runs slower than wall-clock
  timeouts allow at 10 iterations (~4 M steps), so 1-iteration
  lockstep plus 50-iteration CRC parity is the evidence pair.
- Probes: `probe_ret0` (GCC `return`+`sra` idiom, caller reads
  `%o0`), `probe_retv` (`ret; restore %g0,%o0,%o0` value return),
  mov/mulcc/argv/malloc probes and the `mb` microbenchmark
  (`chk=4f99b73f3c15518c`) pass identically on both engines and the
  oracle; probe difftests report 0 divergences.
- `make check` PASS; `make check-line-limits` PASS (all
  `.c/.h/.S` ≤ 900 lines).
- Caveats, measured not assumed: both engines print `Errors
  detected` below 10 iterations — that is CoreMark's
  must-run-10-seconds rule (`Total time < 10 s`), firing equally on
  oracle/interp/dbt, not a CRC failure. Difftest step counts jitter
  by ±~100 steps run to run (heap-layout ASLR through
  `sysmalloc`); CRCs are unaffected. Latent note for the owning
  lane: an arena recycle still zombies resident blocks via stale
  IBTC descriptors instead of forcing retranslation; with the
  rewind, CoreMark no longer recycles, so this is untriggered but
  un-fixed. The MULcc V-on-overflow oracle conflict stays open for
  the coordinator.

## 7. Files changed

- `src/dbt/dbt.c`: delay-gate widening + staging rewind (the win).
- `src/dbt/emit_int.c`: merged `e_emit_jmpl_ret` (native RETURN).
- `src/dbt/emit_priv.h`: `sb_push64/sb_pop64` scratch-spill words.
- `src/interp/interp_win.c`: UMUL/SMUL full-64-bit product + Y/xcc.
- `docs/h3-coremark.md`: this report.
