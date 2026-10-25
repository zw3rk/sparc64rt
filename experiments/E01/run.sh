#!/bin/sh
# E01 oracle run: cross-compile probe.S for SPARC V9 and run under qemu-sparc64.
# Run from the worktree root:  sh experiments/E01/run.sh
#
# NOTE (host quirk, 2026-10-25): the oracle image resolves only WITHOUT
# '--platform linux/amd64' (with it, Docker Desktop reports the local
# 'sparc32rt-oracle:latest' image as missing) and without
# '--context default' (stale daemon socket). The image is amd64-only, so on
# this arm64 host it runs under emulation (platform-mismatch warning).
set -u
W="${W:-$PWD}"
timeout --kill-after=30s 90s docker run --rm --name "sparc64rt-e01-$$" \
  -v "$W:/w" -w /w sparc32rt-oracle:latest sh -c \
  'sparc64-linux-gnu-gcc -fno-pie -no-pie -nostdlib -static experiments/E01/probe.S -o /tmp/probe64 && qemu-sparc64 /tmp/probe64'
