#!/bin/sh
# E03 run: assemble the 64-bit SPARC V9 probe and run it under qemu-sparc64.
# NOTE: `--platform linux/amd64` is intentionally omitted: on this host the
# oracle image resolves locally only without the explicit platform flag
# (with it, the daemon attempts a remote pull and fails).
set -e
W="$(cd "$(dirname "$0")/../.." && pwd)"
IMG="${ORACLE_IMG:-sparc32rt-oracle:latest}"
docker --context default run --rm -v "$W:/w" -w /w "$IMG" sh -c \
  'sparc64-linux-gnu-gcc -m64 -fno-pie -no-pie -nostdlib -static experiments/E03/probe.S -o /tmp/probe64 && qemu-sparc64 /tmp/probe64'
