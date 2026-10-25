# E06 FINDINGS — `glibc` `sparc64` TLS (`%g7`) & `clone` / fork child semantics

Oracle: `qemu-sparc64` version 7.2.22 (Debian `1:7.2+dfsg-7+deb12u18+b3`)
in image `sparc32rt-oracle:latest` (default `cpu`, no `-cpu` override).
Build: `sparc64-linux-gnu-gcc -fno-pie -no-pie -nostdlib -static
experiments/E06/probe.S -o /tmp/probe64` (see `run.sh`).
Status: **PASS, exit 0.**

Syscall numbers used (verified in the cross toolchain at
`/usr/sparc64-linux-gnu/include/asm/unistd_64.h`):
`exit=1 fork=2 write=4 wait4=7 getpid=20 clone=217`;
`SIGCHLD=20` (verified in `asm/signal.h`, NOT 17 as on some arches);
`CLONE_SETTLS=0x00080000` (verified in `linux/sched.h`).
Trap: `ta 0x6d`. Binary: `ELF64`, big-endian, `EXEC`, `Machine: Sparc v9`.

## Observed output (verbatim, one run)

```
g7init=0000000000000000
pid=000000000000000c
g7set=123456789abcdef0
tprel=0badc0de0badc0de
g7rest=123456789abcdef0
fork-c ret=0000000000000000
fork-c g7=123456789abcdef0
fork-p ret=000000000000000e
fork-p g7=123456789abcdef0
wait=000000000000000e
wstat=0000000000000000
cloneA-c g7=0000000000000000
cloneA-p ret=0000000000000010
cloneA-p g7=123456789abcdef0
waitA=0000000000000010
cloneB-c g7=5e7715b55e7715b5
cloneB-p ret=0000000000000012
cloneB-p g7=123456789abcdef0
waitB=0000000000000012
cloneC-c g7=5e771c355e771c35
cloneC-p ret=0000000000000014
cloneC-p g7=123456789abcdef0
waitC=0000000000000014
E06-PASS
```

(Output is deterministic: every parent prints only after `wait4` reaps its
child, so no parent/child interleave. Child pids `0x0e,0x10,0x12,0x14` are
sequential — one `fork` + three `clone`s, no stray processes.)

## Findings

1. **Initial `%g7` is `0`.** At `_start`, `%g7` reads `0x0000000000000000`
   — the kernel/oracle does not install a thread pointer for a
   freestanding `static` binary; userland (glibc) owns `%g7` setup.
2. **`%g7` is freely readable/writable in user mode.** `mov TP_MARK,%g7`
   then `mov %g7,%g2` reads back `0x123456789abcdef0` exactly; no trap.
   (Assembler note: `gas` only accepts `.register` for
   `%g2,%g3,%g6,%g7` — `%g4/%g5` are reserved and the probe avoids them.)
3. **TP-relative access works as glibc expects it.** With `%g7` pointed at
   a scratch area, `stx %g2,[%g7+16]` / `ldx [%g7+16],%g6` round-trips
   `0x0badc0de0badc0de`. This is the `[%g7 + off]` shape glibc TLS uses.
4. **`fork` (nr 2) inherits `%g7`.** Child sees `ret=0` with
   `%g7=0x123456789abcdef0` (parent's value at fork time); parent sees the
   child pid (`0xe`) in `%o0`, `%g7` undisturbed. `wait4(-1,&st,0,0)`
   returns the pid and `wstat=0` (child `exit(0)`).
5. **`clone` (nr 217) TLS slot is the 4th argument (`%o3`), not `%o4`.**
   With flags `SIGCHLD|CLONE_SETTLS (0x80014)` and an 8 KiB child stack:
   - cloneA (`tls` in `%o4=0x5e7715a55e7715a5`, `%o3=0`): child `%g7=0`.
   - cloneB (`tls` in `%o3=0x5e7715b55e7715b5`, `%o4=0`): child
     `%g7=0x5e7715b55e7715b5`.
   - cloneC (`%o3=0x5e771c355e771c35`, `%o4=0x5e771c455e771c45`,
     both nonzero): child `%g7=0x5e771c355e771c35` — decisive:
     **the oracle takes the child thread pointer from `%o3`.**
   
   So the sparc64 `clone` order is
   `(flags, newsp, parent_tid, tls, child_tid)` — `tls` 4th, as on 32-bit
   sparc — unlike x86-64's 5th-arg convention. Parent `%g7` is unchanged
   by `CLONE_SETTLS` in all three cases; each `wait` returns its child pid.
6. **Exact encodings** (`sparc64-linux-gnu-objdump -d`, `.text` at
   `0x10000`): `ta 0x6d` = `91 d0 20 6d` (matches SPEC §2);
   `mov %g7,%g2` = `84 10 00 07`; `mov %g2,%g7` = `8e 10 00 02`;
   `stx %g2,[%g7+0x10]` = `c4 71 e0 10`;
   `ldx [%g7+0x10],%g6` = `cc 59 e0 10`.
7. **Harness notes.** `probe.S` is 528 lines (`<= 900`). The delegated
   `--platform linux/amd64` + `--context default` flags could not be used
   verbatim: this Docker Desktop setup attempts a fresh registry pull when
   `--platform` is explicit and the `default` context daemon does not hold
   the image — `run.sh` therefore runs the same image/bound
   (`timeout --kill-after=30s 90s`) without `--platform` (the stored image
   is `linux/amd64` and runs emulated with a warning). Also, `puts` must
   not count its `call` delay slot into the length: the first version
   over-counted by one (`strlen+1`, emitting a trailing NUL) because the
   `bz` delay-slot `add` executes even when taken; fixed with `be`+`nop`.

## Translator implications

- `src/interp` + `src/dbt` (lane `L4b`): model `%g7` as the plain-writable
  thread register; `fork` copies it; `clone` with `CLONE_SETTLS` loads the
  child `%g7` from the **4th** syscall arg (`%o3`), leaving the parent's
  `%g7` alone. `clone` pids follow the normal `fork`-family
  parent-returns-pid / child-returns-0 rule with `SIGCHLD`.
- Residual risk: finding 5 is oracle behavior (`qemu-sparc64` 7.2). It
  matches sparc's documented `(flags,stack,ptid,tls,ctid)` order, but `L4b`
  should re-confirm against the real kernel/glibc `clone` wrapper when the
  thread tests land.
