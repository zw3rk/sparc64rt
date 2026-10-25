# Phase 5 lane L5b — build notes (dynamic guest + BusyBox)

Lane branch: `lane/phase5-l5b`. Owned files: `tests/test_p5_dyn.c`,
`tests/libp5.{c,h}`, `tests/test_p5_dyn.golden`,
`tests/busybox_probe.golden`, this file. The translator itself is
untouched; dynamic execution waits on lane L5a (`PT_INTERP` loader).

## Cross toolchain (Debian container, from the worktree root)

All guest builds run in `debian:stable-slim` (`--platform linux/arm64`):

    docker run -d --name sparc64rt-l5b-build --memory 2g --cpus 2 \
      --platform linux/arm64 -v "$PWD:/w" -w /w \
      debian:stable-slim sleep 7200
    docker exec sparc64rt-l5b-build sh -c \
      'apt-get update && apt-get install -y gcc-sparc64-linux-gnu \
      qemu-user make gcc bc bison flex wget ca-certificates file \
      lbzip2 bzip2'

(sysroot `/usr/sparc64-linux-gnu`, `qemu-sparc64` 10.0.13.)

## test_p5_dyn (dynamic glibc guest + libp5.so)

    docker exec sparc64rt-l5b-build sh -c 'cd /w && mkdir -p _build \
      && sparc64-linux-gnu-gcc -shared -fPIC -O2 -Wl,-soname,libp5.so \
           -o _build/libp5.so tests/libp5.c \
      && sparc64-linux-gnu-gcc -O2 -pthread "-Wl,-rpath,\$ORIGIN" \
           -o _build/guest_p5_dyn tests/test_p5_dyn.c \
           -L_build -l:libp5.so -ldl'

Notes: `-l:libp5.so` (not the `_build/` path) keeps `NEEDED` as
`libp5.so` so the `$ORIGIN` rpath resolves it; the same name is used
by the guest's `dlopen("libp5.so")`. `libp5` ships shared-only — no
static archive exists on purpose.

Oracle golden (run from the worktree root so `$ORIGIN` == `./_build`):

    qemu-sparc64 -L /usr/sparc64-linux-gnu ./_build/guest_p5_dyn \
      | tee tests/test_p5_dyn.golden   # exit 0, see below

Golden stdout (`tests/test_p5_dyn.golden`, bit-identical across two
runs, exit 0):

    DSO-CALL-OK sum=42 prod=42 name=libp5
    DLOPEN-OK sym=42
    TLS-OK main=7 thread=13
    MALLOC-OK sum=36
    PRINTF-OK dec=42 hex=2a
    AUXV-OK pagesz=8192 clktck=100 secure=0
    PTHREAD-OK count=2000
    P5-PASS

Grounded oracle facts worth keeping: SPARC64 pages are 8 KiB
(`AT_PAGESZ` 8192, not 4096), `AT_CLKTCK` is 100, and `snprintf`
of `"dec=42 hex=2a"` returns 13.

## BusyBox (dynamic, minimal defconfig)

    docker exec sparc64rt-l5b-build sh -c 'cd /w && mkdir -p _build/bb \
      && cd _build/bb && wget -q \
        https://busybox.net/downloads/busybox-1.37.0.tar.bz2 \
      && tar xf busybox-1.37.0.tar.bz2 && cd busybox-1.37.0 \
      && CROSS_COMPILE=sparc64-linux-gnu- make defconfig \
      && sed -i -e "s/^CONFIG_SHA1_HWACCEL=y/# CONFIG_SHA1_HWACCEL is not set/" \
               -e "s/^CONFIG_SHA256_HWACCEL=y/# CONFIG_SHA256_HWACCEL is not set/" \
               -e "s/^CONFIG_TC=y/# CONFIG_TC is not set/" .config \
      && yes "" | CROSS_COMPILE=sparc64-linux-gnu- make oldconfig \
      && CROSS_COMPILE=sparc64-linux-gnu- make -j2 \
      && cp busybox /w/_build/busybox'

`defconfig` already selects dynamic linking (`STATIC` unset),
`SH_IS_ASH`, `LS`, `ECHO`, `WC`. Three defconfig entries are
disabled, all unrelated to the qualification applets:

- `SHA1_HWACCEL` / `SHA256_HWACCEL`: reference x86-only SHA-NI
  symbols with no provider on sparc64 (upstream defconfig bug for
  non-x86); the generic hash code still backs `sha1sum`/`sha256sum`.
- `TC`: `networking/tc.c` uses CBQ UAPI (`TCA_CBQ_*`) removed from
  current kernel headers; the traffic-control applet is out of scope.

Result: `ELF 64-bit MSB pie executable, SPARC V9, dynamically
linked, interpreter /lib64/ld-linux.so.2`,
`NEEDED libm.so.6 libresolv.so.2 libc.so.6`.

Qualification probe oracle golden (`tests/busybox_probe.golden`,
bit-identical across two runs, exit 0):

    qemu-sparc64 -L /usr/sparc64-linux-gnu ./_build/busybox sh -c \
      'ls / && echo ok | wc -c'

(`ls /` reflects the build container's root — including the `/w`
bind mount — so the golden is tied to `debian:stable-slim`.)

## Engine runs (expected failure pending L5a)

Built the translator on the host per the lane card
(`make build`, aarch64-musl static-PIE, clean) and ran both guests:

    docker run --rm --memory 2g --cpus 2 --platform linux/arm64 \
      -v "$PWD:/w" -w /w -e SPARC64RT_SYSROOT=/usr/sparc64-linux-gnu \
      debian:stable-slim sh -c \
      './_build/sparc64rt --interp ./_build/guest_p5_dyn; ...'

Every combination (`--interp`/`--dbt` x `guest_p5_dyn`/`busybox`)
fails identically with exit 1 and:

    sparc64rt: './_build/guest_p5_dyn' needs an interpreter (static only)

This is the loader-missing failure the lane card anticipates: this
branch has no `PT_INTERP` support (L5a owns `src/rt64/loader/`),
so dynamic guests cannot start on the translator yet. Recorded here
as expected-pending-L5a, not a lane failure. Full `--interp` vs
`--dbt` parity plus `--difftest` 0-divergence reruns belong to RC5
after the L5a merge.

## Suggested card update (for the coordinator at merge)

Copy the two build recipes above into `docs/lanes/phase-5.md`
(L5b section); this lane leaves the coordinator-owned card untouched.
