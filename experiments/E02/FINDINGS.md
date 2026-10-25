# E02 FINDINGS — dual carry flag update (`CCR.icc.C` & `CCR.xcc.C`), `ta 0x6d`

Oracle: `qemu-sparc64 10.0.13` (Debian trixie) + `sparc64-linux-gnu-gcc 14.2.0`,
via locally built `sparc64rt-e02-oracle` image (Debian trixie-slim +
`gcc-sparc64-linux-gnu` + `qemu-user` + `binutils-sparc64-linux-gnu`).
The task card's named `sparc32rt-oracle:latest` image is not published
(pull access denied), so `run.sh` builds this equivalent image with docker
layer cache and then runs the bounded compile+run step. Status: **PASS,
exit 0.**

Probe: freestanding SPARC V9 (`-fno-pie -no-pie -nostdlib -static`),
`ELF64` / `EM_SPARC V9`, entry `0x10010c`, text `LOAD R+E` at `0x100000`.
Style adapted from `sparc32rt` E02 (freestanding `puts`/`puthex`, `ta`
syscalls, `_start`, exit-code verdict); the 32-bit E02 topic (annulled
delay slots) does not carry over — everything below is 64-bit CCR/`ta`
specific. Observed `*cc` state via `rd %ccr` into `%l0` (value) with the
ALU result in `%l1`; no `SAVE`/`RESTORE` used.

## Observed output (final oracle run)

```
E02 dual-carry probe (V9, ta 0x6d)
t1 32b-carry  ccr=0000000000000005
t2 64b-carry  ccr=0000000000000055
t3 no-carry   ccr=0000000000000000
t4 sub-borrow ccr=0000000000000099
t5 pre-syscall ccr=0000000000000099
t5 getpid-ok  ccr= pid=0000000000000089 000000000000000e
t6 pre-syscall ccr=0000000000000044
t6 bad-syscall ccr= errno=0000000000000054 000000000000005a
E02-PASS: icc.C + xcc.C dual update verified
```

(`pid` varies per run: `0x0d`, `0x0e` observed. `t5` line reads
`ccr=<ccr> pid=<pid>`; `t6` line reads `ccr=<ccr> errno=<errno>`.)

## Findings

1. `*cc` ALU ops update **both** nibbles, each from its own operand width
   (`rd %ccr` low byte = `xcc{N,Z,V,C}` in bits 7:4, `icc{N,Z,V,C}` in
   bits 3:0):
   - `0x00000000ffffffff + 1 = 0x100000000` → `ccr=0x05`
     (icc: `N=0,Z=1,V=0,C=1`; xcc: `N=0,Z=0,V=0,C=0`). 32-bit carry sets
     only `icc.C`; result high/low halves verified (`srlx 32` = 1,
     low32 = 0).
   - `0xffffffffffffffff + 1 = 0` → `ccr=0x55` (both `N=0,Z=1,V=0,C=1`).
   - `2 + 3 = 5` → `ccr=0x00`.
2. `SUBcc` carry = **borrow**: `C=1` iff `src1 < src2` unsigned
   (`0 - 1` → `ccr=0x99`, both `N=1,Z=0,V=0,C=1`; result `-1`).
   Cross-checked: `1-0` → `0x00`, `1-1` → `0x44`, `3-5` → `0x99`,
   `5-3` → `0x00`, and `blu` (synonym of `bcs`) **is taken** for `0-1`.
   The initial probe expectation (`0x88`, C=NOT-borrow) was wrong; the
   oracle is self-consistent (`blu` taken ⟺ observed `C=1`).
3. `ta 0x6d` return updates **`xcc.C` only** — `icc.C`, `N`, `Z`, `V`
   (both nibbles) are preserved. Verified with deterministic pre-states
   re-established immediately before the trap (helpers clobber CCR):
   - Success (`getpid`, nr 20, `%o0` = pid > 0): pre `0x99` → post
     `0x89` (`xcc.C` 1→0; `icc.C` stays 1; `N=1,Z=0,V=0` kept).
     Pre-clear run also observed: pre `0x44` → post `0x44`.
   - Error (syscall 9999): pre `0x44` → post `0x54` (`xcc.C` 0→1;
     rest kept); `%o0 = 90` = `ENOSYS` (SPARC `asm/errno.h` defines
     `ENOSYS` as **90**, overriding asm-generic 38 — confirmed in the
     cross headers; same `o0=90` for 9998). Pre-set run: pre `0x55` →
     post `0x55`.
4. **SPEC divergence (flagged for coordinator):** SPEC §2 says success
   *clears BOTH* `icc.C`+`xcc.C` and error *sets BOTH*. The oracle
   moves only `xcc.C` and preserves `icc.C`. `src/interp` + `src/dbt`
   must pick one: matching this oracle means syscall return =
   `xcc.C ← ok?0:1`, all other CCR bits unchanged.
5. `pc`/`npc` advance across `ta 0x6d` exactly as SPEC §2 states
   (`pc=npc; npc+=4`): every post-trap instruction ran and its values
   (`%o0`, fresh `rd %ccr`) were observed.
6. `ta 0x10` (32-bit trap) under `qemu-sparc64` → **SIGILL**
   (`Illegal instruction`, exit 132), both pre-set and pre-clear.
   Only `ta 0x6d` is usable in this oracle.
7. Exact encodings (objdump, text at `0x100000`):
   - `ta 0x6d` = `91 d0 20 6d` = `0x91d0206d` (as SPEC §2 states),
     e.g. getpid site `0x1002b4`, bad-syscall site `0x100370`.
   - `rd %ccr, %l0` = `a1 40 80 00`.
   - `addcc %g1,1,%g5` = `8a 80 60 01`; `addcc %g1,3,%g5` =
     `8a 80 60 03`; `addcc %g0,%g0,%g0` = `80 80 00 00`.
   - `subcc %g0,1,%g5` = `8a a0 20 01`.
   - `mov 20,%g1` (getpid nr) = `82 10 20 14`.
8. Toolchain quirks (V9 GAS, recorded so later lanes don't trip):
   - `%g2`/`%g3` use requires `.register %g2, #scratch` /
     `.register %g3, #scratch` (`%g4` needs none; `%g4` is not
     declarable).
   - `mov imm,reg` with an out-of-`simm13` immediate fails with
     `relocation overflow`; materialize via `sethi %hi(n)` /
     `or %lo(n)` (static link stays < 4 GiB so `%hi`/`%lo` on symbols
     is fine).
   - A `bz` whose delay slot advances the scanned pointer writes the
     NUL too (length+1); the probe's `puts` uses a `nop` delay slot.

## Translator implications

- `src/interp` + `src/dbt`: model CCR as two width-specific nibbles —
  `icc.*` from the low 32-bit result, `xcc.*` from the full 64-bit
  result — for every `*cc` op; `SUBcc`/`cmp` `C` = borrow
  (`blu`/`bleu`/`bgu`/`bcc` observations must fall out of this).
- Syscall return (`ta 0x6d`): to match this oracle, set/clear only
  `xcc.C` (`%o0` = return value / positive SPARC errno), preserve
  `icc.C`/`N`/`Z`/`V`, advance `pc=npc, npc+=4`. Reconcile with the
  SPEC §2 both-carry claim before freezing `src/os/` return-path
  semantics.
