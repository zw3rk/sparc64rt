# Phase 3 — Floating-Point & SIMD (`RC3`)

Complete FPU/SIMD reference interpreter, AArch64 FP/NEON emitter, and a
freestanding FP/SIMD test guest verified bit-for-bit against `qemu-sparc64`.

Oracle ground truth: [`experiments/E05/FINDINGS.md`](../experiments/E05/FINDINGS.md)
(`qemu-sparc64` 7.2.22; `FPU %f0..%f31/%d0..%d62/%q0..%q60`, `fcc0..fcc3`
with `eq/lt/gt/un = 0/1/2/3`, `faligndata` splice
`src1[off..7] ++ src2[0..off-1`, `GSR = off`, initial `FSR = 0`). E05's
[`probe.S`](../experiments/E05/probe.S) is the scratch-probe template.

## Frozen & shared state (do not edit)

- Frozen headers: `src/core/cpu.h` (fp union at `0x140`, `fsr` at `0x120`,
  `gsr` at `0x128`, `fprs` at `0x130`, `fcc` at `0x240`), `include/a32host.h`,
  `src/os/syscall_nr.h`. Elevation need = stop and report to coordinator.
- `src/interp/interp.c` dispatch already routes `ICLS_FPU` to
  `sparc64_exec_fpu`; `LDFSR`/`STFSR` classify as `LOAD`/`STORE` and run
  integer-modeled in `interp_mem.c`. Do not change classification.
- Curated C11 (`-std=c11 -Werror=vla -pedantic -Wall -Wextra -Werror`),
  every `.c`/`.h`/`.S` `<= 900` lines, never emit `x18` in `.S`/emitters.
- `qemu STQF quirk` (E05 finding 11): the oracle duplicates the high half
  on `stq`. Our interpreter deliberately reproduces the quirk so the gate
  (`bit-for-bit vs qemu`) holds; `test_p3` asserts true quad halves through
  the `std`-pair and asserts the `stq` duplication observation-only.

## Lane L3a — complete FPU/SIMD interpreter (owns `src/interp/fp.c`)

Extend `src/interp/fp.c` (RC2 minimal kernel) to the full SPEC §2 set.
No shared-file edits: all helpers `static`, no `interp.h` changes needed
(`sparc64_exec_fpu` is already declared). If `fp.c` would exceed ~850
lines, split into new `src/interp/fp_*.c` files (dispatcher stays in
`fp.c`); every file `<= 900` lines.

Scope (everything else keeps the loud `ILLEGAL` trap):
- FPOP1 single/double/quad: `FADD/FSUB/FMUL/FDIV/FSQRT/FMOVS/FNEGS/FABS`
  (+`FSMULD`, `FDMULQ`), full conversion matrix
  (`FSTOI/FDTOI/FQTOI/FSTOX/FDTOX/FQTOX/FITOS/FITOD/FITOQ/FXTOS/FXTOD/FXTOQ/
  FSTOD/FSTOQ/FDTOS/FDTOQ/FQTOS/FQTOD`), `FCMPS/FCMPD/FCMPQ` +
  `FCMPES/FCMPED/FCMPEQ`.
- FPOP2: `FMOVcc` (all 11 conds x single/double/quad over `fcc0..3`),
  `FMOVr` (all 6 conds x `%icc/%xcc`), VIS `ALIGNADDR` (+`GSR` write) and
  `FALIGNDATA` data path, `FZERO/FONE` (opf `0x60/0x61`, all sizes).
- Quad arithmetic is soft (no host `float128` on AArch64): integer
  bit-manipulation with correct rounding for the active `FSR.RD`.
- Comparisons use integer bit logic (never host FP compares, never host
  FP exceptions): NaN -> `fcc = 3` (unordered); `FCMPE*` on SNaN sets
  `FSR.ftt = invalid` + `cexc.NV` and quiets the result; QNaN propagates
  quietly. SNaN (exp all-1, frac msb 0, frac != 0) arithmetic input sets
  `NV` and yields the quieted NaN.
- Rounding: honor `FSR.RD` (`0..3` -> `FE_TONEAREST/FE_DOWNWARD/FE_UPWARD/
  FE_TOWARDZERO` via `<fenv.h>` around host `float`/`double` ops, restore
  after); accumulate `cexc`/`aexc` from host flags (`FE_INVALID->NV`,
  `FE_DIVBYZERO->DZ`, `FE_OVERFLOW->OF`, `FE_UNDERFLOW->UF`,
  `FE_INEXACT->NX`). `TEM != 0` with a trapped `cexc` takes the generic
  synchronous-trap path (same as `ILLEGAL` today); note it in the header.
- `FPRS`: readable/writable state, no PEF trap (Phase 4 owns FP traps).
- Keep: FP ld/st incl. `%asi` forms, LDDA/STDA lines, `0x30-0x37`,
  VIS block ASIs `0xF0-0xF7`, `STQF` oracle-quirk duplication.

Acceptance (bounded, from the worktree root; scratch probe under `/tmp`,
never committed): build an E05-style scratch FP probe with the cross
compiler in the oracle image, then
`qemu-sparc64` golden vs `--interp` must match bit-for-bit, exit 0:
`timeout --kill-after=30s 90s docker --context default run --rm
-v "$PWD:/w" -w /w sparc32rt-oracle:latest sh -c
'sparc64-linux-gnu-gcc -fno-pie -no-pie -nostdlib -static -o
/tmp/l3a_fp /tmp/l3a_fp.S && qemu-sparc64 /tmp/l3a_fp >
/tmp/l3a_oracle.txt && timeout 60 /w/_build/sparc64rt --interp
/tmp/l3a_fp > /tmp/l3a_interp.txt; cmp /tmp/l3a_oracle.txt
/tmp/l3a_interp.txt && echo L3A-FP-PASS'`.

## Lane L3b — FP/NEON emitter + `AT_HWCAP` (owns `src/dbt/emit_fp.[ch]`)

New files `src/dbt/emit_fp.[ch]` (auto-globbed by the Makefile, no
`Makefile` edit) declaring `bool sparc64_emit_fp(sparc64_emit_ctx_t *ec,
const sparc64_dec_t *d)`; `false` = pristine interpreter fallback.
Shared-file touches (exact, nothing else in shared files):
1. `src/dbt/dbt.c` classifier: delete the single line
   `case SPARC64_ICLS_FPU:` from the `PRIV/FPU/FBR/ILLEGAL`
   `needs_interp` group (FPU falls into `default: end = cur + 4U`).
   `FBR` stays in the fallback group; FPU is already absent from
   `dbt_delay_emittable`, so delay slots stay pristine.
2. `src/dbt/dbt.c` `dbt_emit_range` non-CTI site: replace
   `if (!sparc64_emit_int(&ec, &d)) { goto fail; }` with an FPU route
   that calls `sparc64_emit_fp` first and `goto fail` on refusal.
   Add `#include "dbt/emit_fp.h"`. Net `+6` lines max (`dbt.c` ~713).
3. `src/os/guest_stack.c` auxv only: probe the oracle `AT_HWCAP` (tiny
   freestanding auxv-dumping scratch guest under `qemu-sparc64`), mirror
   the value as a new `AT_HWCAP` pair (`aux_keys` `11->12`, `vals`
   `11->12`, `put_vec(auxv, 22U->24U)`, reserve words `24->26`).
   Nothing else in that file.

Emitter contract (mirrors `emit_int.h`, x19 = ctx, never x18):
- Reuse `sb_*` word emitters + `sparc64_emit_ctx_t` from
  `dbt/emit_priv.h`; guest FP regs via `x19 + 0x140 + idx*8`
  (`%dN` = f-pair `2N/2N+1`), `fsr` at `0x120`, `fcc[i]` at `0x240+4i`.
- Exits mirror the `e_exit_imm` pattern (read-only reference in
  `emit_int.c`): resume/fault PC in `x15`, reason in `w16`.
- Lower: FPOP1 single/double arith + `FSQRT` + moves/neg/abs,
  `F{S,D}TO{I,X}` + `F{I,X}TO{S,D}` + `FSTOD/FDTOS`, plain FP ld/st
  (`LDF/STF/LDDF/STDF`), `STFSR`/`RD %fsr` reads. Punt (`false`):
  quad, VIS/FALIGNDATA/ALIGNADDR, block ASIs, `FCMP*`, `LDFSR`,
  `FBR`, everything else.
- Rounding-sensitive lowered ops (arith, sqrt, conversions) MUST emit a
  runtime `FSR.RD == 0` guard prologue (load `fsr`, test RD field,
  exit `SPARC64_EXIT_UNDEF` on nonzero) so cached blocks stay correct
  across `LDFSR` mode changes; moves/loads/stores need no guard.
- AArch64 scalar FP encodings are standard ISA (`FADD S/D 1E212800/
  1E612800`, `FSUB 1E213800/1E613800`, `FMUL 1E210800/1E610800`, `FDIV
  1E211800/1E611800`, `FSQRT 1E214800/1E614800`, `FMOV 1E204000/1E604000`,
  `LDR S/D BD400000/FD400000`, `STR S/D BD000000/FD000000`); verify
  behaviorally — wrong encodings fault loudly in the container.

Acceptance: `--dbt` on the L3a-style scratch probe matches the oracle
golden bit-for-bit AND `--difftest` reports `0 divergences` (same
bounded docker shape as L3a, `--dbt`/`--difftest` for
`/tmp/l3b_fp` + `echo L3B-FP-PASS`).

## Lane L3c — `tests/test_p3_fp_simd.c` (owns that file only)

Freestanding SPARC V9 guest (pure top-level asm + minimal C, `-nostdlib
-static`, same helper discipline as `tests/test_p1_isa.c`: helpers
clobber only `%g1-%g3/%o0-%o4`, values snapshotted to BSS, never touch
`%g6/%g7`, never `set`). Deterministic stdout, exit 0 iff all pass:
- Scalar: `fadds/subs/muls/divs`, `fsmuld`, `faddd/subd/muld/divd`,
  `fsqrts/fqrtd`, `fmovs/fmovd`, `fmovq` + `faddq` (halves asserted via
  `std`-pair; `stq` duplication asserted observation-only per the quirk).
- `fcmps/fcmpd` + `FBcc` (`fbl/fbe/fbu/fbo/fbg`, `fcc1..3` selectors),
  `FMOVcc` (`se/sne` taken + skipped with `0xdeadbeef` preservation),
  `FMOVr` (`icc.Z`), `FMOVde`.
- VIS: `alignaddr` + `faligndata` splice + `GSR` value (E05 vectors).
- Conversions: `fitos/fstoi/fdtos/fstod/fxtos/fdtox` round-trip values.
- Rounding: `LDFSR`-set `RD` down/up/zero on a halfway + overflow case,
  `NX/OF/UF/DZ/IV` `cexc` assertions, `STFSR` snapshots (E05 patterns).
- NaN: QNaN propagation bits, SNaN `-> NV` + quieted result, unordered
  `fcc = 3`.

Build: `docker --context default run --rm -v "$PWD:/w" -w /w
sparc32rt-oracle:latest sh -c 'sparc64-linux-gnu-gcc -mcpu=ultrasparc
-fno-pie -no-pie -nostdlib -static -o _build/guest_p3
tests/test_p3_fp_simd.c'` (add `-mcpu=ultrasparc` for VIS; keep the
binary committed-out of git — `_build/` is ignored — only the `.c`
is committed). Golden: `qemu-sparc64 _build/guest_p3`.

Acceptance: oracle golden vs `--interp` vs `--dbt` all bit-for-bit AND
`--difftest` `0 divergences` on `_build/guest_p3`
(`timeout --kill-after=30s 200s docker run --rm --platform linux/arm64
-v "$PWD:/w" -w /w alpine ...` per engine, `cmp` + `echo P3-FP-PASS`).

## Escalation & merge

- Acceptance fails twice, or any frozen-header/`Makefile`/outside-owned
  edit is needed: stop, report to the coordinator, do not work around.
- Commit in the worktree as `Moritz Angermann <moritz@zw3rk.com>`
  (no AI names); coordinator merges `--no-ff` and runs gate `RC3`:
  `make check` green + `guest_p1`/`guest_p2libc`/`guest_p3` bit-for-bit
  on all engines + `0` difftest divergences.
