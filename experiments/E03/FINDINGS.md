# E03 FINDINGS — `BPcc`, `BPr`, `MOVcc`, `MOVr`, `CASA`/`CASXA`, Little-Endian ASIs (SPARC V9, 64-bit)

Oracle: `qemu-sparc64` version 7.2.22 (Debian), default CPU (no `-cpu`
flag), image `sparc32rt-oracle:latest` built locally from
`sparc32rt/tools/Dockerfile.oracle`. Status: **PASS, exit 0**
(`E03-PASS`; phase-A marker `E03A-PASS` printed before the risky ops).

NOTE on the run command: the delegated `--platform linux/amd64` flag is
intentionally omitted in `run.sh` — on this host the image resolves
locally only *without* the explicit platform flag (with it, the daemon
attempts a remote pull and fails). QEMU-reported platform warning is
harmless (amd64 image under emulation).

## Observed snapshot (exit 0)

```
snap[bp0..bp12 movcc13..19 movr20..25]:
0000000000000001 0000000000000002
0000000000000004 0000000000000003
0000000000000005 0000000000000006
0000000000000007 0000000000000008
0000000000000009 000000000000000a
000000000000000b 000000000000000c
000000000000000d 0000000000000111
ffffffffffffffff 0000000000000001
ffffffffffffffff 0000000000000001
0000000000000001 ffffffffffffffff
ffffffffffffff33 ffffffffffffffff
ffffffffffffffff 0000000000000123
ffffffffffffff21 ffffffffffffffff

E03A-PASS
casa rd mem: 0000000011111111 0000000022222222
casxa rd mem: 1111111122222222 3333333344444444
leASI ld st: 0000000004030201 000000000d0c0b0a
E03-PASS
```

## Per-test results (all match manual expectation)

| # | test | observed | ok |
|---|------|----------|----|
| 0 | `be,a,pt %icc` taken (Z=1), delay slot runs | 1 | yes |
| 1 | `be,a,pt %icc` not-taken (Z=0), delay slot annulled | 2 | yes |
| 2 | `be,pt %icc` taken on `%g1=0x100000000` (lo32==0) | 4 | yes |
| 3 | `be,a,pt %xcc` NOT taken, same state (full64!=0) | 3 | yes |
| 4 | `bne,pn %xcc` taken, same state | 5 | yes |
| 5 | `brlz,a,pt` not-taken on `%g1=0x80000000` (64-bit positive) | 6 | yes |
| 6 | `brlez,pn` not-taken, same state | 7 | yes |
| 7 | `brgz,pt` taken, same state | 8 | yes |
| 8 | `brgez,pn` taken, same state | 9 | yes |
| 9 | `brlz,pt` taken on `%g1=-1` | 10 | yes |
| 10 | `brnz,pn` taken on `%g1=-1` | 11 | yes |
| 11 | `brz,pt` taken on `%g1=0` | 12 | yes |
| 12 | `brnz,a,pn` not-taken on `%g1=0`, annulled | 13 | yes |
| 13 | `move %icc` (Z=1) | 0x111 | yes |
| 14 | `movne %icc` not moved (Z=1) | -1 | yes |
| 15 | `move %icc` on split state (icc Z=1) | 1 | yes |
| 16 | `move %xcc` NOT moved (xcc Z=0) | -1 | yes |
| 17 | `movne %xcc` moved (xcc NZ=1) | 1 | yes |
| 18 | `movl %icc` on `%g4=0x80000000` (icc N=1) | 1 | yes |
| 19 | `movl %xcc` NOT moved (xcc N=0) | -1 | yes |
| 20 | `movrz %g1,0x333` on `%g1=0` | 0xFF..FF33 (simm10 sign-extended, see §3) | yes |
| 21 | `movrnz` not moved (`%g1=0`) | -1 | yes |
| 22 | `movrlz` NOT moved on `%g1=0x80000000` (64-bit proof) | -1 | yes |
| 23 | `movrgz` moved | 0x123 | yes |
| 24 | `movrlez` moved on `%g1=-1` | 0xFF..FF21 (sign-extended) | yes |
| 25 | `movrgez` not moved (`%g1=-1`) | -1 | yes |
| B0/B1 | CASA match: rd=old, mem=swap | 0x11111111 / 0x22222222 | yes |
| B2/B3 | CASXA match (64-bit) | rd=0x1111111122222222, mem=0x3333333344444444 | yes |
| B4 | `lda [%o0] 0x88` of `0x01020304` | 0x04030201 (byte-swapped) | yes |
| B5 | `sta %g2,[%o0] 0x88` of `0x0a0b0c0d`, BE reload | 0x0d0c0b0a | yes |

## 1. `icc`/`xcc` split (discriminators)

`%g1 = 0x100000000`, `cmp %g1, 0`: `be %icc` TAKES (lo32 zero),
`be %xcc` does NOT take (full64 nonzero) — tests #2/#3. N-split with
`%g4 = 0x80000000`: `movl %icc` takes (lo32 negative), `movl %xcc`
does not (full64 positive) — tests #18/#19. The translator must thread
*both* condition-code sets; testing only the low 32 bits is wrong.

## 2. `BPr` tests the full 64-bit register

`%g1 = 0x0000000080000000` (low32 = INT_MIN, full64 positive):
`brlz`/`brlez` NOT taken, `brgz`/`brgez` taken (tests #5–#8). A 32-bit
truncation would invert #5/#6. `brz`/`brnz` on 0/-1 behave (tests #9–#12).

## 3. `MOVr` immediate is simm10 and sign-extended

The assembler folds the immediate: `movrz %g1, 0x333` assembles as
`movre %g1, -205` (0x333 = 819 does not fit signed 10-bit; result is
sign-extended to `0xFFFFFFFFFFFFFF33`). Likewise `0x321` → `-223`
(test #24). Values ≥ 0x400 are rejected at assembly (`relocation
overflow`, same as #20–#25 originally tripped). The translator's
decoder must sign-extend MOVr's simm10.

## 4. `CASA`/`CASXA` encoding + oracle behavior (2×2 matrix)

Objdump-verified words (binutils 2.40, `sparc64-linux-gnu-objdump -d`):

| mnemonic (GAS) | word | objdump renders |
|---|---|---|
| `casa [%o0] 0x80, %o1, %o2` | `d5 e2 10 09` | `cas [ %o0 ], %o1, %o2` |
| `casxa [%o0] 0x80, %o1, %o2` | `d5 f2 10 09` | `casx [ %o0 ], %o1, %o2` |
| `casa [%o0] 0x0a, %o1, %o2` | `d5 e2 01 49` | `casa [ %o0 ] (10), %o1, %o2` |
| `casxa [%o0] 0x0a, %o1, %o2` | `d5 f2 01 49` | `casxa [ %o0 ] (10), %o1, %o2` |
| `cas [%o0], %o1, %o2` | `d5 e2 10 09` | (same as `casa … 0x80`) |
| `lda [%o0] 0x88, %g2` | `c4 82 11 00` | `lda [ %o0 ] #ASI_P_L, %g2` |
| `sta %g2, [%o0] 0x88` | `c4 a2 11 00` | `sta %g2, [ %o0 ] #ASI_P_L` |

Field breakdown for `0xD5E21009`: `op=3`, `rd=10 (%o2)`,
`op3=0x3c`, `rs1=8 (%o0)`, `asi=0x80` (bits[12:5]), `rs2=9 (%o1)`,
bit13 = 0. (Correction: an early draft inserted an `i(1)<<13` term
copied from the 32-bit template, yielding `0xD5E23009`; objdump
rejects that reading — with bit13 set GAS/objdump take the
`%asi`-register form. The low13 is exactly `asi<<5 | rs2`.)

Execution matrix on `qemu-sparc64` linux-user (each cell run in-vivo;
traps kill the guest, prior output already flushed):

| word | form | oracle result |
|---|---|---|
| `0xD5E21009` | CASA, i=0, ASI 0x80 (PRIMARY) | EXECUTES, match: rd=old, mem=swap |
| `0xD5F21009` | CASXA, i=0, ASI 0x80 | EXECUTES, match (64-bit) |
| `0xD5E20149` | CASA, i=0, ASI 0x0a | `Unhandled trap: 0x37`, guest dies |
| `0xD5E22149` | CASA, i=1 (register-ASI form), ASI field 0x0a | `Unhandled trap: 0x32`, guest dies |
| `0xD5E23009` | CASA, i=1, ASI field 0x80 | `Unhandled trap: 0x32`, guest dies |

Root cause, confirmed in qemu v7.2.0 source
(`target/sparc/translate.c:2097-2108`, `target/sparc/cpu.h:82,84`,
`target/sparc/asi.h`):

- Bit 13 (`i`) selects the ASI source: `if (IS_IMM) asi = dc->asi`
  — i=1 uses the `%asi` REGISTER, i=0 uses the 8-bit immediate ASI
  from bits[12:5]. (32-bit GAS emits i=1 for the same mnemonic
  text, which is why the 32-bit E03 word `0xD5E22149` decodes as
  `casa [%o0] %asi, …` there.)
- `/* With v9, all asis below 0x80 are privileged. */`
  `if (!supervisor(dc) && asi < 0x80) TT_PRIV_ACT (0x37)` — the
  ASI-0x0a case. V8-style user ASIs are unusable in 64-bit user mode.
- The i=1 form reads `%asi` (guest dump shows `asi: 82`; the fault
  is `TT_DATA_ACCESS (0x32)`, not `TT_PRIV_ACT`, so the register
  holds ≥ 0x80 — i.e. hex `0x82` = `ASI_PNF/ASI_PRIMARY_NOFAULT` —
  which has no direct linux-user helper mapping).
- ASI values match SPEC §2.1 (`asi.h`: `ASI_P=0x80`,
  `ASI_PNF=0x82`, `ASI_PL=0x88`, `ASI_PNFL=0x8a`,
  `ASI_USERDATA=0x0a`).

Translator consequence: decode `op=3, op3∈{0x3c,0x3e}` with 8-bit
imm ASI from bits[12:5] **and** honor bit 13 (i=1 → `%asi`
register source). Match semantics (single-threaded): compare full
width, on equal store swap-value and set rd=old, else rd=old and
memory unchanged. Unlike 32-bit E03, there is NO oracle gap for the
`(i=0, ASI≥0x80)` form — it executes and its exact result is above.

## 5. Little-endian ASIs work in the oracle

`lda`/`sta` with ASI `0x88` execute with byte-swapped data
(B4/B5). Source: `translate.c:2249-2252` —
`/* The little-endian asis all have bit 3 set. */ if (asi & 8)
memop ^= MO_BSWAP;`. `ASI_P=0x80`, `ASI_PL=0x88` (`asi.h:132,136`),
and objdump confirms the constant (`#ASI_P_L`). SPEC §2.1 LE ASIs
`0x88`/`0x8a` are therefore directly testable against the oracle.

## 6. Representative `BPcc`/`BPr`/`MOVcc` encodings (objdump-verified)

```
22480003  be,a   %icc, +disp   (T0: a=1,cond=E,op2=1,cc=icc,p=1)
22480002  be,a   %icc, +disp   (T1)
02480005  be     %icc, +disp   (T2: ,pt is default, not printed)
22680002  be,a   %xcc, +disp   (T3: cc=xcc)
12600005  bne,pn %xcc, +disp   (T4: a=0,cond=NE,p=0)
26c84002  brlz,a %g1, +disp    (T5: op=0,op2=3)
04c04005  brlez,pn %g1, +disp  (T6)
0cc84005  brgz   %g1, +disp    (T7)
0ec04005  brgez,pn %g1, +disp  (T8)
87646111  move  %icc, 0x111, %g3   (op=2,rd=3,op3=0x2c,MOVcc)
87667001  movne %xcc, 1, %g3       (cond=NE,cc=xcc)
87786733  movre %g1, -205, %g3     (op3=0x2f=MOVr; 0x333 folded to -205)
```

## 7. Assembler/toolchain notes (64-bit GAS specifics)

- `%g2/%g3/%g6` (only `%g2,%g3,%g6,%g7`) must be declared
  `.register %gN, #scratch`; `%g4/%g5` are rejected outright and
  `%g1` is implicit scratch. Helpers therefore use only
  `%g1-%g3`/`%o0-%o2` and preserve `%g6` (snap base) and `%o3-%o5`.
- Syscalls: `write=4`, `exit=1` via `ta 0x6d` (`0x91d0206d`),
  `%g1` = number — same numbers as V8, different trap.
- `MOVcc` immediate is simm13; `MOVr` immediate is simm10 (§3).
- `sethi %hi(0x80000000)` yields `0x0000000080000000` (upper 32
  zeroed) — the 64-bit-positive discriminator used throughout.

## Correction history (probe self-checks that failed before passing)

1. `puts` delay-slot bug: the length loop's `add` sat in a taken
   branch's delay slot and always executed, emitting a trailing NUL
   per line — caught from `\0` bytes in captured output, fixed by
   restructuring the loop (values unaffected).
2. T6 (`brlez` not-taken) fallthrough clobbered its own marker —
   caught (observed 0, expected 7), fixed by swapping the
   taken/fallthrough marker placement.
3. `0x333`/`0x321` MOVr immediates: observed sign-extended results
   (`0xFF..FF33`) initially looked wrong; objdump (`movre …,
   -205`) plus the simm10 format proved the machine right and the
   expectation wrong — recorded as finding §3 instead.

## Translator implications

- Thread both `icc` and `xcc` through every `*cc` site; `BPcc`
  selects via the cc field, `MOVcc` likewise; never derive one from
  the other (§1).
- `BPr`/`MOVr` consume the full 64-bit register (§2); `MOVr`
  sign-extends simm10 (§3).
- Atomics: implement `CASA`/`CASXA` per manual with the i-bit ASI
  rule; oracle parity is achievable for `(i=0, ASI≥0x80)` with the
  exact vectors above; `(ASI<0x80)` → fault `0x37`,
  `%asi`-register form → fault `0x32` in linux-user (§4).
- Endianness is per-ASI bit 3 (`asi & 8`), verified live for
  `0x88` (§5).
