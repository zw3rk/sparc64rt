# Phase 5 — Dynamic Linking (`PT_INTERP`), BusyBox, & Target `libc` Matrix (`RC5`)

Dynamic `test_p5_dyn` and BusyBox match `qemu-sparc64` on both `interp`
and `dbt`. Static guests (Phases 1–4) keep passing unchanged.

## Starting facts (grounded on master @ RC4)

- Static-guest auxv subset lives in `src/os/guest_stack.c` (`AT_PHDR`,
  `AT_PHENT`, `AT_PHNUM`, `AT_PAGESZ`, `AT_ENTRY`, `AT_UID/EUID/GID/EGID`,
  `AT_HWCAP`); no `PT_INTERP` mapping exists yet.
- Cross toolchain is NOT in the nix store: build guests inside
  `debian:stable-slim` containers with
  `apt-get install -y gcc-sparc64-linux-gnu qemu-user` (network verified).
  The interpreter + shared libc come from the Debian multiarch sysroot
  (`/usr/sparc64-linux-gnu/lib/ld.so.1`, `libc.so.6`).
- The translator resolves the guest `PT_INTERP` path against a sysroot
  directory supplied at launch: honour `SPARC64RT_SYSROOT` when set,
  else the container root `/`. No new CLI flag without coordinator say-so
  (`src/main.c` is shared).
- Frozen headers (`src/core/cpu.h`, `include/a32host.h`,
  `src/os/syscall_nr.h`), `Makefile`, `flake.nix`: read-only for lanes.
  Escalate on any needed touch.

## Lane L5a — `PT_INTERP` loader + auxv + `/proc/self/*` (owns loader/auxv touches)

- Parse `PT_INTERP` in `src/rt64/loader/` (new file, e.g.
  `interp_map.c`; `< 900 LOC`): map `ld.so` at a free base with its own
  `PT_LOAD` segments, honouring `p_align`; the dynamic guest entry point
  becomes the interpreter entry (`e_entry` of `ld.so`), NOT the app.
- Complete the auxv in `src/os/guest_stack.c` (narrow, append-only):
  `AT_PHDR`/`AT_PHENT`/`AT_PHNUM` describe the APP phdrs (not `ld.so`);
  add `AT_BASE` (ld.so base), `AT_FLAGS`, `AT_PAGESZ`, `AT_HWCAP`,
  `AT_HWCAP2`, `AT_RANDOM` (16 canonical random bytes on the stack),
  `AT_EXECFN` (guest argv[0] path), `AT_UID/EUID/GID/EGID`,
  `AT_SECURE=0`, `AT_CLKTCK=100`; terminate with `AT_NULL`.
- `/proc/self/{exe,maps,cmdline,stat,auxv}` interception (new
  `src/os/guest_proc.c` + decl, wired into the fd/read path with a
  narrow dispatch touch): `exe` resolves to the guest argv[0] path,
  `maps` reflects the translator's guest mapping (incl. ld.so + app),
  `auxv` matches the initial-stack bytes. Keep it read-only; anything
  else is `-ENOENT`.
- DBT: `ld.so` code runs through the same per-thread instances; no new
  cache locking. Self-modifying `ld.so` relocation writes invalidate via
  the existing `sparc64_dbt_invalidate` path.

Acceptance (bounded): build a dynamic probe (`dlopen`/`dlsym` one shared
object, `__thread` read, auxv dump of all keys above) with the Debian
cross toolchain; oracle golden vs `--interp` vs `--dbt` bit-for-bit +
`--difftest` 0 divergences
(`timeout --kill-after=30s 120s docker ...`, `cmp ... && echo L5A-DYN-PASS`).
Iterate on `ENOSYS` (openat, set_thread_area-equivalents, rseq, getsysinfo)
like RC2 did.

## Lane L5b — dynamic `test_p5_dyn` + BusyBox qualification (owns `tests/test_p5_dyn.c`)

- `tests/test_p5_dyn.c`: dynamic glibc guest (`-pthread`, links one
  purpose-built `libp5.so` exercising cross-DSO calls, `dlopen`+`dlsym`
  by name, `__thread` TLS across the DSO boundary, `malloc`/`printf`
  via the real `libc.so.6`). Deterministic stdout, exit 0 iff all pass.
- Target BusyBox: build `busybox` for `sparc64` with the Debian cross
  toolchain (minimal defconfig + `sh`, `ls`, `echo`, `wc`; static config
  is NOT acceptable — the point is dynamic `ld.so` startup).
  Qualification: `sh -c 'ls / && echo ok | wc -c'` oracle vs engines.
- Both artifacts keep `_build/`-ignored binaries with committed sources;
  add the exact cross build lines to this card when they land.

Acceptance (bounded): oracle golden vs `--interp` vs `--dbt` bit-for-bit
AND `--difftest` 0 divergences on `test_p5_dyn` AND the BusyBox probe
(same bounded docker shape, `cmp` + `echo P5-PASS`).

## Escalation & merge

- Acceptance fails twice, or any frozen-header/`Makefile`/`flake.nix`
  edit looks needed, or the `PT_INTERP`-vs-sysroot story is ambiguous:
  STOP and report to the coordinator. No guessing across lanes.
- Lanes own exclusive files: L5a = `src/rt64/loader/interp_map.*`,
  `src/os/guest_proc.*`, narrow `guest_stack.c` auxv block; L5b =
  `tests/test_p5_dyn.c`, `libp5` source, BusyBox build notes in this card.
  Conflicts on `guest_stack.c` merge in `--no-ff` order L5a then L5b.
- Coordinator merges (`--no-ff`), removes worktrees, runs gate `RC5`.
