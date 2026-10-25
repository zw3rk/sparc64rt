# E01 FINDINGS — `2047` (`0x7ff`) Stack Bias, `SAVE`/`RESTORE`, Initial `_start`

Oracle: `qemu-sparc64` 7.2.22 (Debian), image `sparc32rt-oracle:latest`.
Build: `sparc64-linux-gnu-gcc` (Debian 12.2.0-13) 12.2.0, default `-m64`
(`__sparc_v9__`, `__arch64__` predefined) with
`-fno-pie -no-pie -nostdlib -static experiments/E01/probe.S -o /tmp/probe64`.
Run: `sh experiments/E01/run.sh` (bounded `timeout --kill-after=30s 90s`).
Status: **PASS, exit 0.**

## Observed output (verbatim)

```
sp(biased,unbiased)=0000004000801561 0000004000801d60
argc@+2175=0000000000000001
argv0ptr=0000004000801f55
/tmp/probe64
envp0ptr=0000004000801f62
win+stack[unbiased..unbiased+256):
0000000000000000 0000000000000000 0000000000000000 0000000000000000
0000000000000000 0000000000000000 0000000000000000 0000000000000000
0000000000000000 0000000000000000 0000000000000000 0000000000000000
0000000000000000 0000000000000000 0000000000000000 0000000000000000
0000000000000001 0000004000801f55 0000000000000000 0000004000801f62
0000004000801f69 0000004000801f88 0000004000801fca 0000004000801fd5
0000000000000000 0000000000000003 0000000000100040 0000000000000004
0000000000000038 0000000000000005 0000000000000003 0000000000000006

after-save i0 i1=0000000000000001 0000000000000002
after-restore o0 o1 l0..l7 i0..i7 sp=
0000000000000001 0000000000000002 0000000000000003 0000000000000004
0000000000000000 0000000000000000 0000000000000000 0000000000000000
0000000000000000 0000000000000000 0000000000000000 0000000000000000
0000000000000000 0000000000000000 0000000000000000 0000000000000000
0000000000000000 0000000000000000 0000004000801561
E01-PASS: bias ok, rotation ok, no spill/fill traps
```

## Findings

1. **Bias `2047` confirmed.** Entry `%sp = 0x4000801561` (biased),
   `%sp + 2047 = 0x4000801d60` (unbiased frame base). Unbiased base is
   16-byte aligned; biased `%sp % 16 == 1` (consistent with
   `2047 % 16 == 15`). A translator must add the bias before touching
   the stack: guest frame base = `%sp + 2047`, never `%sp` itself.
2. **`argc` at `[unbiased + 128]`** (8-byte slot, value `1`), i.e. at biased
   `[%sp + 2175]`, matching `SPEC.md` §2.1 (`rwindow_64` 128 B at
   `[%sp+2047]` + `argc` at `[%sp+2047+128]`). `argv[0]` (8-byte pointer)
   at `[unbiased + 136]` = `0x4000801f55` → `"/tmp/probe64"`;
   `argv[1] = NULL`; `envp[0]` = `0x4000801f62`; 5 env pointers, then NULL,
   then auxv pairs `(3, 0x100040) = (AT_PHDR, <phdr addr near _start
   0x10010c>)`, `(4, 0x38) = (AT_PHENT, 56)`, `(5, 3) = (AT_PHNUM, 3)`,
   `(6, …) = (AT_PAGESZ, …)`.
3. **Entry window save area `[unbiased .. unbiased+128)` is 16 zero
   doublewords** (fresh stack page; no caller spilled anything there).
4. **`save %sp,-192,%sp` rotates the window in-register:** old `%o0/%o1`
   (`1`, `2`) are visible as new `%i0/%i1` (`after-save i0 i1 = 1 2`).
5. **No spill/fill traps at depth 1 (differs from 32-bit).** After `restore`:
   `%o0/%o1 = 1/2` (outs survive), `%l0/%l1 = 3/4` (pre-save markers
   preserved **in-register**, i.e. no fill trap overwrote them),
   `%l2..%l7`/`%i0..i7 = 0`, `%sp` restored to the entry value
   `0x4000801561`. The 64-bit `_start` state has all windows resident
   (contrast `sparc32rt` E01, where restore refilled `l/i` from the stack
   because window 0 was invalid). A translator must still implement
   spill/fill for call depth ≥ `NWINDOWS` (Phase-1 interp work), but depth-1
   save/restore is pure rotation with zero memory traffic.
6. **Sentinel intact:** the 16-doubleword `0x5A5A…5A` fill of the new
   window's future spill area `[unbiased-192 .. unbiased-64)` survived
   `save`/`restore` byte-for-byte → the `save` spilled nothing.
7. **Encodings (from `sparc64-linux-gnu-objdump -d`, `_start = 0x10010c`):**
   - `save %sp,-192,%sp` = `9d e3 bf 40` (at `0x100290`)
   - `restore` = `81 e8 00 00` (at `0x1002f0`)
   - `ta 0x6d` = `91 d0 20 6d` (confirms `SPEC.md` §2.1 dual-carry trap)
   - `ldx [%g6+0x80],%g2` (argc slot) = `c4 59 a0 80`
   - `stx %sp,[%g4]` = `dc 71 00 00`; `stx %o0,[%g2]` = `d0 70 80 00`
   - `sethi %hi(0x200400),%g2` = `05 00 08 01` (static low-32-bit addresses;
     explicit `sethi`/`or` pairs suffice, `-fno-pie -no-pie` required)
   - `_start = 0x10010c` (T), `sentinel = 0x2006f8` (d),
     `snap = 0x200718`, `entrysp = 0x2007b0` (b).
8. **Toolchain facts (recorded so later lanes don't rediscover them):**
   - V9 gas rejects ANY `%g2..%g7` use without a declaration, but only
     `%g2/%g3/%g6/%g7` accept `.register %gN, #scratch` (`%g1/%g4/%g5`
     are always scratch; declaring them is an error). The probe declares
     the four, mirroring Linux `arch/sparc/kernel/head_64.S`.
   - gas `set` pseudo-op is **32-bit only** (silently truncates a 64-bit
     constant — observed `set 0x5A…5A` assembling to `0x5A5A5A5A` with a
     "number not in 0..4294967295 range" warning). The probe loads the
     64-bit sentinel from a `.xword` via `sethi`/`or`/`ldx` instead.
   - `.xword` does **not** auto-align: it landed at `0x…7f5` and the first
     `ldx` faulted `SIGBUS`. An explicit `.align 8` before it fixed the
     fault (misaligned `ldx`/`stx` = bus error under `qemu-sparc64`).
   - `puts`-style length loops must subtract the delay-slot-advanced NUL
     (`sub %o2,1,%o2`), else every `write` emits one stray `NUL`.

## Host/docker notes

- `docker --context default` is broken on this host (stale
  `/var/run/docker.sock`); plain `docker` (Desktop context) works.
- `--platform linux/amd64` makes Docker Desktop report the local
  `sparc32rt-oracle:latest` image as missing; omitting the flag runs it
  under emulation with a platform-mismatch warning. `run.sh` therefore
  uses neither flag (documented in the script).

## Translator implications

- `%sp` init = host stack top mapped to guest, minus `2047`; synthesize
  `argc`/`argv`/`envp`/auxv at `unbiased+128` per (2); the 128 B at
  `[unbiased .. unbiased+128)` is the `rwindow_64` spill area, not argv.
- `src/interp`: window file `cwp/wim`, `save`/`restore` rotation with
  spill/fill to `[%sp+2047 .. %sp+2047+120]` only on overflow/underflow;
  `ta 0x6d` dual-carry semantics per `SPEC.md` §2.1 (write=4, exit=1 used
  here; verified trap encoding `91d0206d`).
- `src/dbt`: same window/spill model; depth-1 save/restore emits plain
  rotation with no memory traffic on the fast path.
