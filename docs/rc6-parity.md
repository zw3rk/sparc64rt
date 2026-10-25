# RC6 dual-host parity log (lane L6b)

Lane branch: `lane/phase6-l6b`. Runner: [tests/parity_suite.sh](../tests/parity_suite.sh).
Probe: [tests/test_p6_page_perm.c](../tests/test_p6_page_perm.c).
Goldens: `tests/test_p5_dyn.golden`, `tests/busybox_probe.golden` (both pre-existing),
`tests/busybox_sp_pipe.golden` (new, `3\n`).

## Method

- Translator: `make build` on the macOS host with
  `PATH=/nix/store/82ac69jwkpj68v4mx22yxnwzqj0ql4l5-aarch64-unknown-linux-musl-gcc-wrapper-15.2.0/bin:$PATH`
  (static-PIE AArch64, clean).
- Linux container: `debian:stable-slim` (`--platform linux/arm64`), worktree
  at `/w`, `gcc-sparc64-linux-gnu` + `qemu-user` (qemu-sparc64 10.0.13),
  `SPARC64RT_SYSROOT=/usr/sparc64-linux-gnu`. Static guests:
  `guest_p1` (`-nostdlib -static`), `guest_p3` (`-mcpu=ultrasparc`),
  `guest_p4` (`-static -pthread`), `guest_p6pperm` (`-static -O2`).
  Dynamic per the Phase 5 gate record; BusyBox 1.37.0 rebuilt from source
  (defconfig minus `SHA1_HWACCEL`/`SHA256_HWACCEL`/`TC`).
- `hl` host: `../hyper-linux/_build/hl` on macOS arm64. `hl` has NO
  `--sparc64rt` dispatch (`hl: unknown option: --sparc64rt`; no
  `sparc64rt`/`SPARCV9` entry in `hyper-linux/src/translator.h` —
  hl-side change, out of scope). Discovered working shape: run the
  translator as an ordinary AArch64 Linux binary,
  `hl ./_build/sparc64rt --interp|--dbt|--difftest <guest> ...`
  (legacy fs mode, worktree cwd). Dynamic legs use a sysroot exported
  from the container (`docker cp sparc64rt-l6b:/usr/sparc64-linux-gnu`
  to `/tmp/sparc64-sysroot`, 60 MiB) via `SPARC64RT_SYSROOT`.

## Container results (oracle = qemu-sparc64 10.0.13)

| leg | oracle | interp | dbt | difftest |
|---|---|---|---|---|
| test_p1_isa | PASS exit 0 | PASS, bit-for-bit vs oracle | PASS, identical | 0 div (10747 steps) |
| test_p3_fp_simd | GAP G1 | P3-PASS | identical | 0 div (16861 steps) |
| test_p4_threads_signals | GAP G2 (WAIT-FAIL/P4-FAIL n=1) | P4-PASS (EXEC-OK/WAIT-OK status=7) | identical | n/a (threads) |
| test_p5_dyn | PASS, golden | PASS, golden | identical | n/a (threads) |
| BusyBox `sh -c 'ls / && echo ok \| wc -c'` | PASS, golden | PASS, golden | identical | 0 div (~277k steps) |
| BusyBox SPARC-pipe `sh -c 'echo ok \| $BB wc -c'` | GAP G3 (exit 126) | `3`, exit 0 | identical | — |
| page-perm probe | P6P-PASS exit 0 | P6P-PASS, bit-for-bit | identical | 0 div (46032 steps) |

## `hl` results (no oracle on the Mac; engines vs each other + goldens + container)

| leg | interp | dbt | difftest | cross-host |
|---|---|---|---|---|
| test_p1_isa | PASS, == container oracle | identical | 0 div (10747 steps, same count) | match |
| test_p3_fp_simd | P3-PASS, == container | identical | 0 div (16861 steps, same count) | match |
| test_p4_threads_signals | P4-PASS (EXEC/WAIT/signals/threads) | identical | n/a (threads) | match |
| test_p5_dyn | P5-PASS, == golden | identical | n/a (threads) | match |
| BusyBox exact probe | GAP G4 (exit 1) | not run (same trap) | — | blocked |
| BusyBox SPARC-pipe | `3`, exit 0 | identical | — | match |
| page-perm probe | P6P-PASS | identical | 0 div (~68-69k steps, env-dependent, see below) | match |

RELRO-next-to-.bss (contract section 2.1.3) is qualified implicitly:
every dynamic leg maps ld.so RELRO adjacent to writable `.bss`; a
permission-merge bug would crash relocation. The probe covers the
explicit adjacent-permission enforcement (X|RW|NONE) functionally on
both hosts — including on `hl` with Darwin 16 KiB backing.

## Recorded gaps (exact errors, no translator hacks)

- G1 (oracle version drift): qemu-sparc64 10.0.13 raises SIGBUS on
  `stq %f0, [16-byte-aligned BSS]` (minimal probe reproduces; exit 135)
  and reports FSR `0xe00` where the test CHECKs `0xc00` (the engines
  satisfy the test's own assertions, validated at RC3 against qemu 7.2;
  the documented oracle image `sparc32rt-oracle:latest` is not pullable).
  Engines agree and pass fully.
- G2 (documented in `tests/test_p4_threads_signals.c:34-37`): qemu
  rejects every guest `execve` with ENOEXEC, so the oracle shows
  WAIT-FAIL/P4-FAIL n=1. The translator implements `execve`
  (EXEC-OK/WAIT-OK status=7) identically on both hosts.
- G3: qemu cannot nested-exec a SPARC binary (`Exec format error`,
  exit 126). Both translator engines run the SPARC-only pipe leg
  (`3`, exit 0) identically on both hosts — the translator's own
  guest-execve path, which qemu lacks.
- G4 (HOST GAP, escalated): the exact BusyBox probe needs host-native
  `ls`/`wc`. Under `hl` these resolve to macOS Mach-O binaries:
  single execs fail cleanly (`.../bin/ls: not an ELF file`,
  `ash: 3: Invalid argument`, exit 2), while the full
  `ls / && echo ok | wc -c` probe traps deterministically:
  `sparc64rt: unhandled guest trap: cause=2 (ILLEGAL) pc=0x60006a9b04
  tval=0xc39a6080 memreason=0`, exit 1 (3/3 runs, `--interp`).
  The translator's "run non-SPARC host binaries natively" rule has no
  `hl` equivalent; fixing it needs an hl-side/host-exec decision, so
  per the lane card it is recorded, not worked around. The adapted
  SPARC-only pipe leg qualifies BusyBox fork+exec+pipe+wait on `hl`
  instead (both engines, `3`, exit 0, cross-host match).

## Notes

- difftest step counts are env-sensitive, not divergences: `guest_p6pperm`
  counts 46032 steps in the container vs ~68-69k under `hl` at 0
  divergences; `env -i` under `hl` gives 45892, and 60 dummy vars in the
  container give 60434. Cause: glibc startup env/tunable scanning over
  the 3.4 KiB macOS env vs the 106 B container env. p1/p3 counts are
  identical across hosts (10747/16861).
- Two probe-authoring findings (in the probe, not the translator):
  the translator requires SA_SIGINFO handlers (plain `sa_handler` is
  EINVAL, `src/os/sync_sig.c`); dead loads must be `volatile` or the
  compiler drops the faulting access.
- Suite commands:
  container: `SYSROOT=/usr/sparc64-linux-gnu ./tests/parity_suite.sh`
  (19 PASS, 0 FAIL, 3 oracle GAPs);
  Mac: `HL=$PWD/../hyper-linux/_build/hl SYSROOT=/tmp/sparc64-sysroot
  BB_BIN=$PWD/_build/busybox ORACLE= ./tests/parity_suite.sh`
  (9 PASS, 0 FAIL, 11 GAPs: no-oracle + G4).

## Verdict

Every Phase 1-5 suite plus the page-permission probe is green on both
hosts and both engines, with 0 difftest divergences on all
single-threaded legs — except the exact BusyBox probe on `hl`, blocked
by host gap G4 (escalated to the coordinator: accept the adapted
SPARC-only leg, or rule that G4 needs hl-side work).
L6B-PARITY-PASS modulo the G4 ruling.
