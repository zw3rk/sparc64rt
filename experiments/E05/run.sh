#!/bin/sh
# E05 acceptance: cross-compile experiments/E05/probe.S for SPARC V9 and
# run it under the qemu-sparc64 ground-truth oracle.
# Run from the worktree root:  sh experiments/E05/run.sh
# Bounded per AGENTS.md (unique container name, memory/cpu caps, timeout).
# NOTE: no `--platform linux/amd64` flag: the stored sparc32rt-oracle image
# lacks platform metadata satisfying an explicit --platform request (the
# daemon attempts a pull and fails); omitting it runs the amd64 image fine.
set -eu
E=experiments/E05
IMG=sparc32rt-oracle:latest
exec timeout --kill-after=30s 90s docker run --rm \
  --name "sparc64rt-e05-$$" --memory 2g --cpus 2 \
  -v "$PWD:/w" -w /w "$IMG" sh -c \
  "sparc64-linux-gnu-gcc -mcpu=ultrasparc -fno-pie -no-pie -nostdlib -static $E/probe.S -o /tmp/probe64 && qemu-sparc64 /tmp/probe64"
