#!/bin/sh
# E06: build the freestanding SPARC V9 probe and run it under the
# qemu-sparc64 ground-truth oracle.
#
# NOTE: no `--platform` flag. This Docker Desktop setup attempts a fresh
# registry pull when `--platform linux/amd64` is explicit; the stored
# `sparc32rt-oracle:latest` image is linux/amd64 and runs emulated (with a
# warning) when the flag is omitted.
set -eu
WT="$(cd "$(dirname "$0")/../.." && pwd)"
timeout --kill-after=30s 90s docker run --rm \
  -v "$WT:/w" -w /w sparc32rt-oracle:latest \
  sh -c 'sparc64-linux-gnu-gcc -fno-pie -no-pie -nostdlib -static experiments/E06/probe.S -o /tmp/probe64 && qemu-sparc64 /tmp/probe64'
