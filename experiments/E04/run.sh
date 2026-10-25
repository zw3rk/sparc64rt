#!/bin/sh
# E04 oracle run: build freestanding probe.S + C layout check for sparc64,
# execute both under qemu-sparc64. Exit 0 = probe passed and layout ran.
# NOTE: `--platform linux/amd64` is deliberately omitted: the oracle image is
# local-only and an explicit --platform forces a registry pull that fails.
set -eu
IMG="${ORACLE_IMG:-sparc32rt-oracle:latest}"
timeout --kill-after=30s 90s docker --context default run --rm \
	-v "$PWD:/w" -w /w "$IMG" sh -c '
set -e
sparc64-linux-gnu-gcc -fno-pie -no-pie -nostdlib -static \
	experiments/E04/probe.S -o /tmp/probe64
qemu-sparc64 /tmp/probe64
echo "--- layout ---"
sparc64-linux-gnu-gcc -std=c11 -D_GNU_SOURCE -Wall -Wextra -Werror -static \
	experiments/E04/layout.c -o /tmp/lay64
sparc64-linux-gnu-gcc -std=c11 -Wall -Wextra -Werror -static \
	experiments/E04/klayout.c -o /tmp/klay64
qemu-sparc64 /tmp/lay64
echo "--- klayout ---"
qemu-sparc64 /tmp/klay64'
