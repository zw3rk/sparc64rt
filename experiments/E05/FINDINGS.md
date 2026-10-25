# E05 FINDINGS — SPARC V9 FPU (`%f0..%f31` / `%d0..%d62` / `%q0..%q60`,
`fcc0..fcc3`) & VIS `faligndata`

Oracle: `qemu-sparc64` 7.2.22 (Debian, default CPU) in
`sparc32rt-oracle:latest`; cross-toolchain
`sparc64-linux-gnu-gcc` 12.2.0 with `-mcpu=ultrasparc -fno-pie -no-pie
-nostdlib -static`. Status: **PASS, exit 0** (`E05-PASS`).

## Observed output (complete)

```
E05 sparc64 V9 FPU+VIS
fsr0=0000000000000000
fadds=40400000
fsubs=3f800000
fmuls=40000000
fdivs=40800000
fsmuld=4000000000000000
aliasd=404000003f800000
faddd=4008000000000000
fsubd=3ff0000000000000
fmuld=4000000000000000
fdivd=4010000000000000
aliasf=4008000000000000
fsr-less=0000000000000400
br-less=0000000000000011
fsr-eq=0000000000000000
br-eq=0000000000000001
fsr-unord=0000000000000c00
br-unord=0000000000000001
fsr-123=0000003100000c00
br-123=0000000000000007
fmov-fcc=3f800000
fmov-fcc-hi=deadbeef
fmovd=3ff0000000000000
fmov-icc=3f800000
fmov-icc-hi=deadbeef
falign=0405060708111213
gsr=0000000000000003
aard=0000000000000000
quad-hi=4000800000000000
quad-lo=0000000000000000
quadmv-hi=4000800000000000
quadmv-lo=0000000000000000
stq-hi=4000800000000000
stq-lo=4000800000000000
E05-PASS
```

(The `stq-lo` line duplicates `stq-hi`: oracle quirk, finding 11.)

## Findings

1. **Assembler ground rules (V9 user code).** `%g2`/`%g3` are OS-reserved:
   GAS rejects them without `.register` (`detected global register use`).
   Usable integer scratch: `%g0/%g1/%g4/%g5` + `%o0..%o5` (never `%g6/%g7`:
   `%g7` is the TLS base per lane E06). VIS (`faligndata`, `alignaddr`,
   `rd %gsr`) needs `-mcpu=ultrasparc` (arch `v9a`); plain `-mvis` is not
   enough for the GCC driver. Syscalls: `ta 0x6d`, `write = 4`, `exit = 1`.
2. **Single precision.** `fadds/fsubs/fmuls/fdivs` of `1.0f/2.0f/8.0f` give
   `0x40400000/0x3f800000/0x40000000/0x40800000`. `fsmuld %f0,%f1,%d10`
   gives double `2.0` (`0x4000000000000000`). Encodings:
   `fadds=85 a0 08 21`, `fsubs=87 a0 48 a0`, `fmuls=89 a0 09 21`,
   `fdivs=8d a1 49 a1`, `fsmuld=95 a0 0d 21`.
3. **Double precision.** `1.0/2.0/8.0` give `3.0/1.0/2.0/4.0`
   (`0x4008…/0x3ff0…/0x4000…/0x4010…`). Encodings: `faddd=89 a0 08 42`,
   `fsubd=8d a0 88 c0`, `fmuld=91 a0 09 42`, `fdivd=9d a3 09 c2`.
   `ldd`/`std` with an even `%f` reg spell LDDF/STDF (`cN 18/38 40 00`).
4. **Aliasing.** `d2 = f2:f3` (`std %f2` stores both): after T1 the pair
   reads `0x40400000:0x3f800000`. After `faddd`, `f4:f5` reads
   `0x40080000:0x00000000`. Upper doubles `d32/d34` (loaded via `ldd`,
   `c3/c7 18 40 00`) work with `fcmpd`/`fmovde` and have no single view.
5. **fcc encoding (FSR reads).** `fcmps`/`fcmpd` write a 2-bit field with
   `equal = 0, less = 1, greater = 2, unordered = 3`: `fsr-less = 0x400`
   (`1.0 < 2.0`), `fsr-eq = 0x0`, `fsr-unord = 0xc00` (NaN `0x7fc00000`),
   `fsr-123 = 0x3100000c00` (`fcc3 = 3, fcc2 = 0, fcc1 = 1` at FSR bits
   `37:36/35:34/33:32`; `fcc0` at `11:10`). True (unreversed) operand
   order confirmed. Initial FSR is zero.
6. **FBcc branches.** All tested conds take exactly when their fcc matches:
   `br-less = 0x11` (`fbl` on single-less + `fcmpd`-double-less),
   `br-eq = 1`, `br-unord = 1`, `br-123 = 7` (`fbl %fcc1`, `fbe %fcc2`,
   `fbu %fcc3`); `fbo` correctly does not take for unordered input.
   Encodings (FBPcc form): `fbl = 09 48..`, `fbg = 0d 48..`,
   `fbe = 13 48..`, `fbu = 0f 48..`, `fbo = 1f 48..`.
   `fcmps %fcc1, %f0, %f1 = 83 a8 0a 21`,
   `fcmps %fcc2, %f0, %f0 = 85 a8 0a 20`,
   `fcmps %fcc3, %f7, %f0 = 87 a9 ca 20`,
   `fcmpd %f32, %f34 = 81 a8 4a 43`,
   `stx %fsr, [..] = c3 28 40 00`.
7. **FMOVcc.** `fmovse %fcc0` copies on equal, `fmovsne %fcc0` skips
   (`99 aa 40 20`, `9d a8 40 21`); destination keeps its old bits when the
   condition is false (marker `0xdeadbeef` preserved). `fmovde %fcc0`
   (`a1 aa 40 41`) copies a double the same way.
8. **FMOVr.** After `subcc %g1,%g1,%g0` (`icc.Z = 1`): `fmovse %icc`
   (`a1 a8 60 20`) copies, `fmovsne %icc` (`a5 aa 60 21`) skips.
9. **VIS `faligndata`.** With `v1 = 0102030405060708`,
   `v2 = 1112131415161718`, `alignaddr %g4,%g0,%o3` (offset `3`) yields
   `rd = 0` (`(rs1+rs2) & ~7`) and `faligndata %f0,%f2,%f4` yields
   `0405060708111213`: result bytes are
   `src1[off..7] ++ src2[0..off-1]`. `GSR = 0x3` (offset in bits `2:0`).
   Encodings: `alignaddr = 97 b1 03 00`, `faligndata = 89 b0 09 02`,
   `rd %gsr = 89 44 c0 00`.
10. **Quad (`float128` on the default CPU).** No `+float128` flag needed:
    `faddq 1.0Q+2.0Q` gives `0x4000800000000000_0000000000000000`;
    `fmovq` copies exactly (`quadmv-hi/lo` match via `std`-pair reads).
    `ldq` loads halves correctly (`d8 = hi, d10 = lo`).
    Encodings: `faddq = 91 a0 08 64`, `fmovq = 99 a0 00 68`,
    `stq = d1 30 40 00`.
11. **Oracle quirk — STQF duplicates the high half.** `stq` of
    `0x4000800000000000_0000000000000000` stores
    `[0x4000800000000000, 0x4000800000000000]` (`stq-hi/lo`); a distinct
    control (`0xAAAA…/0xBBBB…`) shows the same duplication while the
    `std`-pair reads the true halves. `ldq`/`faddq`/`fmovq` are correct,
    so this is a `qemu-sparc64` 7.2 STQF emulation bug, not an encoding
    error. The probe asserts quad results through the `std` pair and
    records `stq` output observation-only.
12. **Scratch lessons.** (a) SPARC delay slots: a `bz` counts its delay
    instruction even when taken — the first probe revision over-counted
    `strlen` by one. (b) Big-endian width: `stx` of a small mask then
    32-bit `ld` reads zeros — print masks with `ldx`. (c) `ld` sign-extends
    (`0xdeadbeef` marker) — compare with `lduw`. (d) `sethi` drops the low
    10 bits — rebuild them with `%lo` for constants like `0x04050607`.
    (e) `stx`/`ldd`/`std` need 8-byte alignment (a 4-mod-8 `stx` faults
    with SIGBUS); `ldq`/`stq` were given 16-byte alignment.

## Translator implications

- Emulate the full FPU register file with single/double/quad aliasing
  (`dN = fN:fN+1`, `qN = dN:dN+2`), `fcc0..fcc3` with the mapping
  `eq/lt/gt/un = 0/1/2/3`, `FMOVcc`/`FMOVr` conditional-move semantics,
  and `GSR.alignaddr_offset` + `faligndata` byte-splice semantics above.
- `difftest` against this oracle must route quad-result assertions through
  `std`-pair (or integer) reads, never `stq`, until the STQF duplication
  is fixed or deliberately matched; flag any divergence there as
  oracle-bug, not translator-bug.
- Syscall numbers observed in use: `write = 4`, `exit = 1` via `ta 0x6d`.
