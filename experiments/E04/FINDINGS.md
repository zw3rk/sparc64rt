# E04 FINDINGS — SPARC64 `rt_signal_frame64` (528 B) layout & delivery

Oracle: `qemu-sparc64` 7.2 (Debian) + `sparc64-linux-gnu-gcc` 12.2.0 in
`sparc32rt-oracle:latest`, via `sh experiments/E04/run.sh`.
Status: **PASS, exit 0.**

## Observed output (`probe.S`, freestanding `-m64 -nostdlib -static`)

```
sp0=0000004000801561
ta6d=0000000091d0206d
pid=000000000000000c
close(-1) errno=0000000000000009
sigaction ok
sig=000000000000001e
info=0000004000801af0
uctx=0000004000801af0
hsp=0000004000801231
un=0000004000801a30
ret=0000000000100890
si_signo=000000000000001e
si_errno=0000000000000000
si_code=0000000000000000
ss_fp=0000000000000000
tpc=000000000010032c
tnpc=0000000000100330
tstate=0000004482001207
fpu=0000004000801c40
mask=0000000000000000
rwin=0000000000000000
i1-un=00000000000000c0
i2-un=00000000000000c0
resumed
E04-PASS
```

Kernel-ABI sizes (`klayout.c`, uapi headers, machine-verified):

```
k_sigset=8
k_sigaction=32
k_sa_handler=0
k_sa_flags=8
k_sa_restorer=16
k_sa_mask=24
k_stackf=192 fp=112 cpc=120
k_ptregs=160 tstate=128 tpc=136 tnpc=144
k_stackt=24 sp=0 flags=8 size=16
k_frame_total=528
```

## Findings

1. Syscall convention: `ta 0x6d`, encoding dumped from our own text as
   **`0x91d0206d`** (asserted). Number in `%g1`, args `%o0..%o5`, return in
   `%o0`. **Dual carry**: success clears BOTH `CCR.icc.C` and `CCR.xcc.C`
   (`getpid=20` → pid `0x0c`, both `bcs`/`bcs %xcc` not taken); error sets
   BOTH (`close(-1)` → C=1 in icc and xcc, `%o0 = EBADF = 9`).
2. **SPARC `rt_sigaction(102)` is a 5-argument syscall**: `sig`, `act`,
   `oact`, **`restorer` in `%o3`**, **`sigsetsize` in `%o4`**. The generic
   4-arg form (`sigsetsize` in `%o3`) fails with `EINVAL` — verified by
   strace (`rt_sigaction(SIGUSR1,...) = -1 errno=22`) and by raw-syscall
   probes with sizes 4/8/16, all `EINVAL`. Passing `restorer` in `%o3` and
   `8` in `%o4` succeeds. (Matches qemu `linux-user/syscall.c`: "For Alpha
   and SPARC this is a 5 argument syscall ... for SPARC it [restorer] is
   arg4, and arg5 is the sigsetsize".)
3. Delivered `rt_signal_frame64` is **528 B** at `unbiased_sp = %sp + 2047`
   (`un=...a30`, 16-byte aligned; handler `%sp` is biased, `hsp=...231`):
   `ss` 192 B @`0x000`, `siginfo_t` 128 B @`0x0c0`, `pt_regs` 160 B @`0x140`,
   `fpu_save` @`0x1e0`, `stack_t` 24 B @`0x1e8`, `mask` @`0x200`,
   `rwin_save` @`0x208`. `k_frame_total=528` confirms the SPEC table.
4. Handler entry (SA_SIGINFO): `%o0 = 30` (signo), `%o1 == %o2 == un+0xC0`
   (`i1-un=i2-un=0xC0`, i.e. both point at `sf->info`, exactly as kernel
   `setup_rt_frame`: `I1 = &sf->info`, `I2 = &sf->info` as sigcontext),
   `%o7` = the `restorer` argument (asserted `ret == &rest`, `0x100890`).
5. Frame contents: `si_signo=30`, `si_errno=0`, `si_code=0` (`SI_USER` from
   `kill`); `regs.tpc=0x10032c` inside probe text with `tnpc=tpc+4`;
   `tstate=0x4482001207`; `fpu_save=un+0x210` (inline `sigfpu` tail present
   even with no FP use); `mask=0`, `rwin_save=0`, `ss.fp=0` (no saved
   windows — main flow is leaf, consistent).
6. `rt_sigreturn(101)` with untouched `%sp` resumes after the `kill` trap;
   canary intact; `exit_group(188, 0)`.
7. Kernel vs libc types differ — use kernel layout: kernel `sigset_t` is
   **8 B** (1×u64, hence `sigsetsize=8`) while libc `sigset_t` is 128 B;
   kernel `struct sigaction` is **32 B** (`handler@0 flags@8 restorer@16
   mask@24`) while libc's is 152 B. (`layout.c` records both.)
8. SPARC signal constants: `SIGUSR1=30` (not 10), `SA_SIGINFO=0x200`.
9. Probe bugs fixed (not oracle issues): (a) sparc64 GAS requires
   `.register %g2/%g3, #scratch`; `%g4/%g5` are not declarable, so the
   probe uses only `%g1-%g3` + `%o*`/`%l1` with BSS snapshots (same
   snapshot-before-print discipline as the 32-bit E04); (b) `puts` length
   loop counted the NUL (branch delay slot) — fixed with a `nop` delay
   slot, verified byte-exact with `od -c`.

## Translator implications

- `src/os` signal frame (`sigframe_sparc64`): implement the exact 528 B
  layout above; `I1=I2=&info`, `I7=restorer`, `FP=sf-2047`, `tpc=handler`,
  `tnpc=handler+4`; `rt_sigreturn` must relocate `sf` from `FP+2047`.
- Syscall boundary: translate the SPARC **5-arg `rt_sigaction`**
  (`%o3` = restorer → handler return address) and the **dual-carry**
  convention (`icc.C` + `xcc.C` both set/clear, `%o0` = positive errno)
  to the AArch64 `-errno` convention.
- `run.sh` omits `--platform linux/amd64`: the oracle image is local-only
  and an explicit `--platform` forces a registry pull that fails; the
  local amd64 image runs under host emulation.
