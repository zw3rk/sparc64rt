#!/bin/sh
# E02: dual carry-flag (CCR.icc.C / CCR.xcc.C) probe — cross-compile + qemu oracle.
# The named sparc32rt-oracle image is not published; this script builds an
# equivalent local oracle image (debian trixie + gcc-sparc64-linux-gnu +
# qemu-user, docker layer cache makes repeat runs fast), then runs the
# bounded compile+run step.
# Usage: sh experiments/E02/run.sh   (from the worktree root; needs docker)
set -eu
IMG=sparc64rt-e02-oracle
CTXDIR=$(mktemp -d)
trap 'rm -rf "$CTXDIR"' EXIT INT TERM
cat > "$CTXDIR/Dockerfile" <<'EOF'
FROM debian:trixie-slim
RUN apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq gcc-sparc64-linux-gnu qemu-user binutils-sparc64-linux-gnu && rm -rf /var/lib/apt/lists/*
EOF
docker --context default build --progress=quiet --platform linux/amd64 -t "$IMG" "$CTXDIR" > /dev/null
timeout --kill-after=30s 90s docker --context default run --rm --platform linux/amd64 \
  -v "$PWD:/w" -w /w "$IMG" sh -c \
  'sparc64-linux-gnu-gcc -fno-pie -no-pie -nostdlib -static experiments/E02/probe.S -o /tmp/probe64 && sparc64-linux-gnu-objdump -d /tmp/probe64 | grep -E "ta[[:space:]]+0x6d|addcc|subcc|rd.*%ccr" && qemu-sparc64 /tmp/probe64'
