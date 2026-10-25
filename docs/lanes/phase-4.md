# Phase 4 — Signals, Threads & Process Lifecycle (`RC4`)

Exact Linux UAPI signal delivery, host-thread-backed `clone`/`futex`/TLS,
and `fork`/`execve`/`wait` lifecycle, verified by a static-glibc
pthread + signals + fork/exec guest against `qemu-sparc64`.

Oracle ground truth: [`experiments/E04/FINDINGS.md`](../experiments/E04/FINDINGS.md)
(`qemu-sparc64` 7.2; `rt_sigframe64` 528 B; `I1 == I2 == &info`; `%o7` =
restorer; `fpu_save = un+0x210` inline tail always present; `tstate`
sample `0x4482001207`; 5-arg `rt_sigaction`; dual-carry convention).

## Frozen & shared state (do not edit)

- Frozen headers: `src/core/cpu.h`, `include/a32host.h`,
  `src/os/syscall_nr.h`, `src/os/sigframe_sparc64rt.h` (frame geometry,
  UAPI structs, `I1=I2=&info` contract). Elevation need = stop and report.
- `syscalls_ext.c` is at 862 lines: NO additions there; new syscalls live
  in new files. `syscalls_min.c` dispatch: append-only `case` arms.
- Curated C11 (`-std=c11 -Werror=vla -pedantic -Wall -Wextra -Werror`),
  every file `<= 900` lines, never emit `x18`.
- Delivery model (all lanes): signals deliver synchronously at fault
  traps, at self-`kill`/`tkill`, at `rt_sigprocmask`-unblock, and at the
  `futex`-WAIT EINTR check only. No async host-signal injection. Pending
  set per thread; blocked mask gates delivery; `SIGKILL`/`SIGSTOP` are
  never blocked or caught.

## Lane L4a — exact `rt_sigframe` + signal syscalls (owns `src/os/sync_sig.c`)

Extend `src/os/sync_sig.c` (204 lines, in place) to full E04 parity; new
signal syscalls go in new `src/os/syscalls_sig.c` (auto-globbed, no
`Makefile` edit) with dispatch `case` arms in `syscalls_min.c` only:
- Fix handler entry to E04: `%o1 == %o2 == base+0xC0` (`&info` both;
  current code sets `%o2` to `&regs` — wrong), `%o7` = restorer,
  biased `%sp`, `pc/npc` = handler/handler+4.
- `tstate` construction: probe the oracle with several CCR settings and
  fit the exact formula (E04 sample `0x4482001207`); `tpc`/`tnpc` =
  interrupted `pc`/`npc`, `y`, `PT_REGS_MAGIC`, full `%g/%o` view.
- Flush register windows before capture (`win_flush_all`), `rwin_save = 0`
  (leaf case, E04); document the non-leaf rule.
- `mask @0x200`: deliver with `new = (old | act.sa_mask) & ~(KILL|STOP)`;
  `rt_sigreturn` restores it. `stack @0x1e8`: current altstack state.
- `fpu_save`: inline `sigfpu` tail at `un+0x210`, always present (E04);
  probe the oracle for the tail size/fields (FP regs + `fsr`/`gsr`/`fprs`),
  write it on deliver, restore it on `sigreturn`.
- `siginfo`: `SI_USER` (`pid`/`uid`) for `kill`-family, `SEGV_MAPERR` +
  fault VA, `ILL_ILLOPC`, `BUS_ADRALN`, `FPE` for integer divide faults;
  `si_trapno` where the kernel provides one.
- `SIGFPE` (synchronous integer divide traps) + `SIGTRAP` mapping in
  `sparc64_sync_sig_for_trap`; `sigreturn(216)` stays `-ENOSYS`
  (documented).
- `rt_sigprocmask`: real blocked-mask load/store per thread + deliver
  pending-unblocked before return. `sigaltstack(28)`: store state,
  deliver on the altstack when enabled (`SS_ONSTACK`), `SS_DISABLE`.
  `kill(62)`/`tkill(187)`/`tgkill(211)`: self-thread delivery now
  (queue pending, deliver before next guest insn); cross-thread targeting
  routes to L4b's thread table when threads exist, else `ESRCH`.
- `rt_sigaction`: also persist `sa_mask`; `oact` returns the old 32 B
  kernel struct; keep the 5-arg/`sigsetsize == 8` + `SA_SIGINFO`-only
  validation.

Acceptance (bounded): build an E04-style scratch probe (raw `rt_sigaction`
+ `kill`, handler dumps `%o0/%o1/%o2/%o7`, frame words, `tstate`, `mask`,
`fpu_save` words, then `rt_sigreturn` and resume) with the cross compiler
in the oracle image; `qemu-sparc64` golden vs `--interp` must match
bit-for-bit, exit 0. Same shape as L3a's bounded command (`timeout
--kill-after=30s 90s docker --context default ...`, `cmp ... &&
echo L4A-SIG-PASS`).

## Lane L4b — threads (owns new `src/os/threads.[ch]`, narrow touches below)

Host-thread-backed `CLONE_VM` threads. New files `src/os/threads.[ch]`
hold the thread table (guest tid allocation, `SET_TID`/`CLEAR_TID`
addresses, exit status + `CLEARTID` wake), per-thread `pthread` launch
(each with its own `sparc64_cpu_t` copy + `sparc64_dbt_t`; the guest
`space` mapping is shared, never copied), `%g7` TLS install, and the
real `futex` WAIT/WAKE (host `futex(2)` on the shared mapping, private +
shared, timeout via `timespec`, `EAGAIN`/`EINTR` per man page; only
`WAIT`/`WAKE` + `PRIVATE_FLAG` variants, rest `-ENOSYS`).
- `clone(217)`: accept the pthreads subset (`CLONE_VM|CLONE_FS|
  CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD|CLONE_SETTLS|
  CLONE_PARENT_SETTID|CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|
  CLONE_SYSVSEM`); without `CLONE_VM` return `-EINVAL` (L4c owns
  fork-semantics). Child starts after the `ta` with `%o0 = 0` on the
  given stack; parent gets the tid. `exit(93)` in a thread terminates
  the group; `exit_group(188)` stops all threads with the status.
  `gettid(168)` returns the guest tid; `set_tid_address(166)` stores it.
- Atomics across threads: `CASA`/`CASXA`/`LDSTUB`/`SWAP` (interp
  `exec_atomic` + DBT `s64_rt_mem` path) become host-`__atomic`
  single-copy operations on the shared mapping. Narrow touch, one
  function each side; no reservation tracking (SPARC has no LL/SC).
- Shared-file touches (exact): `guest_run_priv.h` appends the thread
  decls; `syscalls_min.c` appends the `clone`/`futex`/`gettid` route
  (futex body moves to `threads.c`, keep the `case` line shape);
  `guest_engines.c` adds the thread entry/loop (reuse `run_interp`/
  `run_dbt` per thread; DBT instances stay per-thread, no cache locking).
  Nothing else in shared files.
- Escalation covers the `space`-to-host-address accessor: if the `rt64`
  space layer cannot hand out a host pointer for `futex(2)`, STOP and
  report (needs a `rt64` change = coordinator call).

Acceptance (bounded): scratch static-pthread probe (`pthread_create` +
join, mutex + condvar ping-pong, `__thread` TLS value check) built with
`-static -pthread` in the oracle image; oracle golden vs `--interp` vs
`--dbt` bit-for-bit + `--difftest` 0 divergences (`echo L4B-THR-PASS`).
Iterate on `ENOSYS` like RC2 did for libc (clone, futex, robust list,
rseq, set_tid, exit_group) until `pthread_create` works.

## Lane L4c — lifecycle + test guest (owns new `src/os/proc.[ch]`, `tests/test_p4_threads_signals.c`)

New `src/os/proc.[ch]` (auto-globbed) + append-only dispatch `case`s:
`fork(2)`/`vfork(66)` (space snapshot via the `rt64` family/mm fork
substrate, copied ctx, child `%o0 = 0`, parent gets the child pid;
`vfork` = `fork` + documented immediate-`execve` expectation),
`execve(59)` (validate ELF, close `CLOEXEC`, unmap guest space, load via
ONE exported loader entry pre-authorized in `guest_run.c` + decl in
`guest_run_priv.h`, reset ctx/signals/brk/tids, keep pid), `wait4(7)`/
`waitid(279)` (internal child table + exit-status delivery, `WNOHANG`
and blocking), `pipe(42)`/`pipe2(321)`/`dup(41)`/`dup2(90)`/`dup3(320)`
(via the fd layer's host fds).
- `tests/test_p4_threads_signals.c`: static glibc + `-pthread` guest
  (build: `sparc64-linux-gnu-gcc -static -pthread -o _build/guest_p4
  tests/test_p4_threads_signals.c`, `_build/` ignored, only the `.c`
  committed). Deterministic stdout, exit 0 iff all pass: libc `sigaction`
  handler that inspects `%o0/siginfo/ucontext`, modifies and resumes;
  `SIGSEGV`/`SIGILL`/`SIGFPE` self-tests via fault probes + `kill`;
  `sigprocmask` block/unblock ordering; `sigaltstack` delivery;
  pthreads + mutex + `__thread`; `fork`+`execve`(self re-exec with a
  marker argv)+`wait4` status check.
- Golden: `qemu-sparc64 _build/guest_p4`.

Acceptance: oracle golden vs `--interp` vs `--dbt` bit-for-bit AND
`--difftest` 0 divergences on `_build/guest_p4` (same bounded docker
shape, `cmp` + `echo P4-PROC-PASS`). L4c may verify `fork`/`execve`
paths against the oracle even before L4b lands (single-threaded paths
are independent); full `--dbt` parity may need L4b merged — report what
is pending for the coordinator.

## Escalation & merge

- Acceptance fails twice, or any frozen-header/`Makefile`/outside-owned
  edit is needed: stop and report. Lanes commit in their worktrees as
  `Moritz Angermann <moritz@zw3rk.com>`; coordinator merges `--no-ff`
  and runs gate `RC4`: `make check` green + `guest_p1`/`guest_p2libc`/
  `guest_p3`/`guest_p4` bit-for-bit on all engines + `0` difftest
  divergences.
