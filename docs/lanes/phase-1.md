# Phase 1 Task Cards — Base Integer Decoder, Reference Interpreter & Minimal Syscalls (`sparc64rt`)

Run after `RC0` is merged to `master`. Frozen headers for this phase:
`src/core/cpu.h`, `src/os/syscall_nr.h`, `src/os/sigframe_sparc64rt.h`.
`Makefile` uses `src/*/*.c` wildcards: new files are picked up automatically.

Primary adaptation template: `../sparc32rt/src/interp/*`,
`../sparc32rt/src/os/syscalls_min.*`, `../sparc32rt/tests/test_p1_isa.c`
(32-bit SPARC V8 — widen to 64-bit SPARC V9 per `SPEC.md` §2 and
`experiments/E01..E04/FINDINGS.md`).

---

### Lane `L1a` — V9 Instruction Decoder (`src/interp/decode.c`, `src/interp/decode.h`)
- **Worktree**: `../sparc64rt-l1a` on branch `lane/p1-l1a`
- **Exclusive Files**: `src/interp/decode.c`, `src/interp/decode.h`
- **Task**:
  1. Decoded-instruction representation + big-endian fetch classifier for
     every SPEC §2 base-integer instruction: Format 1 `CALL`; Format 2
     `SETHI`/`Bicc`(+`a`)/`BPcc`/`BPr`/`FBfcc`; Format 3 `SETHI`-rest,
     `Bicc`, integer ALU (`ADD`/`ADDcc`/`SUB`/`SUBcc`/`AND`/`OR`/`XOR`/…,
     `TADD`/`TSUB`/`MULScc`), `MULX`/`SDIVX`/`UDIVX`/`SDIV`/`UDIV`/`POPC`,
     shifts (`SLL`/`SRL`/`SRA`/`SLLX`/`SRLX`/`SRAX`), `SAVE`/`RESTORE`,
     `JMPL`/`RETURN`(`JMPL %i7+8`), `Tcc`/`ta 0x6d`, `FLUSHW`/`SAVED`/
     `RESTORED`/`DONE`/`RETRY` (privileged trap), `RDPR`/`WRPR`/`RDHPR`/
     `WRHPR` (privileged trap), `RDY`/`RDCCR`/`RDTICK`(priv)/`RDASI`/
     `RDFPRS`/`RDGSR`, `WRY`/`WRCCR`/`WRASI`/`WRFPRS`/`WGSR`/`ALIGNADDR`,
     `FALIGNDATA`, `CASA`/`CASXA`, `LDSTUB`/`SWAP`, `LDA`/`STA` (+`TW`/`TWA`
     trap-always), `MOVcc`/`MOVr`/`FMOVcc`/`FMOVr` (integer `MOVcc`/`MOVr`
     execute here; FP forms decode for Phase 3), `FPop1`/`FPop2`
     pass-through markers (Phase 3 executes; Phase 1 returns `EXIT_UNDEF`).
  2. `CASA` with `i == 0`, `LDD/STD` odd-`rd`, `ILLTRAP`, unassigned `op3`
     classify as illegal (L1b must never execute).
- **Acceptance Command**:
  ```sh
  cc -std=c11 -Werror=vla -pedantic -Wall -Wextra -Werror -Isrc -c src/interp/decode.c -o /tmp/decode.o
  ```

### Lane `L1b` — Base Integer Reference Interpreter (`src/interp/`)
- **Worktree**: `../sparc64rt-l1b` on branch `lane/p1-l1b`
- **Exclusive Files**: `src/interp/interp.c`, `src/interp/interp.h`,
  `src/interp/interp_mem.c`, `src/interp/interp_mem.h`,
  `src/interp/interp_win.c`, `src/interp/interp_win.h`
- **Task**:
  1. Implement `sparc64_decode`/`sparc64_step` from `src/core/cpu.h` over
     `sparc64_mem_ops_t`: delay-slot (+annul) execution, `pc`/`npc` update,
     `CALL`/`JMPL`/`RETURN`/`Bicc`/`BPcc`/`BPr`, all ALU with dual
     `icc`+`xcc` updates (E02 carry rules), `MULX`/`SDIVX`/`UDIVX`,
     `SAVE`/`RESTORE` with 128-byte spill/fill at `[%sp + 2047]` (E01),
     `RD`/`WR` of `%y`/`%ccr`/`%asi`/`%fprs`/`%gsr`, `CASA`/`CASXA`/
     `LDSTUB`/`SWAP` via host CAS, `ta 0x6d` -> `SPARC64_STEP_SYSCALL`
     (dual-carry update per E02), `Tcc` trap-if-true, unaligned
     load/store direct emulation (kernel-fixup parity), privileged ops ->
     `SPARC64_TRAP_PRIVILEGED`, FPU markers -> `EXIT_UNDEF` (Phase 3).
  2. Never truncate guest addresses; `%g0` reads as 0, writes dropped.
- **Acceptance Command**:
  ```sh
  cc -std=c11 -Werror=vla -pedantic -Wall -Wextra -Werror -Isrc -c src/interp/interp.c -o /tmp/interp.o
  ```

### Lane `L1c` — Minimal Linux Syscall Layer + Guest Runner (`src/os/`)
- **Worktree**: `../sparc64rt-l1c` on branch `lane/p1-l1c`
- **Exclusive Files**: `src/os/syscalls_min.c`, `src/os/syscalls_min.h`,
  `src/os/guest_run.c`, `src/os/guest_run.h`
- **Task**:
  1. `ta 0x6d` dispatch for `exit`, `exit_group`, `write`, `read`, `brk`,
     `mmap`, `munmap`, `mprotect`, `uname`, `set_tid_address` with the
     E02 dual-carry success/error convention (`%g1` = nr, `%o0..%o5` args).
  2. `guest_run`: `ELFCLASS64`/`ELFDATA2MSB`/`EM_SPARCV9(43)` admission,
     PT_LOAD mapping, `_start` stack synthesis (`%sp = frame - 2047`,
     `rwindow_64` at `[%sp+2047]`, `argc` at `[%sp+2047+128]`), run loop
     over `sparc64_step` until exit/trap. New files only — do NOT edit
     `src/main.c` (coordinator wires the hook after merge).
- **Acceptance Command**:
  ```sh
  cc -std=c11 -Werror=vla -pedantic -Wall -Wextra -Werror -Isrc -c src/os/syscalls_min.c -o /tmp/smin.o
  ```

### Lane `L1d` — Freestanding ISA Test Guest (`tests/test_p1_isa.c`)
- **Worktree**: `../sparc64rt-l1d` on branch `lane/p1-l1d`
- **Exclusive Files**: `tests/test_p1_isa.c`
- **Task**:
  1. Pure-asm freestanding guest (no libc): 64-bit ALU, shifts incl.
     `SLLX`, `MULX`/`SDIVX`/`UDIVX`, branches taken/not-taken/annulled both
     ways, `BPr`, delay slots, `SAVE`/`RESTORE` depth (`save %sp,-192,%sp`,
     E01), page-final branch before a `PROT_NONE` page, `LDSTUB`/`SWAP`/
     `CASA`/`CASXA`, unaligned loads/stores, `ta 0x6d` write/exit (E02).
     Deterministic stdout; exit 0 iff every check passed.
  2. Record build + oracle commands in the file header.
- **Acceptance Command**:
  ```sh
  docker --context default run --rm --platform linux/amd64 -v "$PWD:/w" -w /w sparc32rt-oracle:latest sh -c 'sparc64-linux-gnu-gcc -fno-pie -no-pie -nostdlib -static -o /tmp/test_p1_isa tests/test_p1_isa.c && qemu-sparc64 /tmp/test_p1_isa'
  ```
