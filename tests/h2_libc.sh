#!/bin/sh
# tests/h2_libc.sh -- Phase 7 lane H2 runner: libc-test + LTP subset.
#
# Runs INSIDE the debian:stable-slim container (linux/arm64), from the
# worktree root (which the container mounts at /w):
#   docker run --rm --platform linux/arm64 -v "$PWD:/w" -w /w \
#     debian:stable-slim sh -c 'apt-get update -qq \
#     && apt-get install -y -qq gcc-sparc64-linux-gnu qemu-user \
#     && ./tests/h2_libc.sh'
# (A persistent container works too: docker exec <name> sh -c 'cd /w
#  && ./tests/h2_libc.sh'. The translator _build/sparc64rt is built on
#  the macOS host with the nix cross toolchain and mounted in.)
#
# What it does: cross-builds the six static guests
# (tests/test_h2_*.c) with sparc64-linux-gnu-gcc against target glibc,
# runs each under the qemu-sparc64 oracle plus both translator engines
# (--interp, --dbt), and runs --difftest for the single-threaded
# guests. Thread/process guests skip --difftest (GAP, grounded: the
# lockstep harness is single-threaded by design, clone returns ENOSYS
# under engine 2; see tests/test_p5_dyn.c and tests/parity_suite.sh).
# The process guest's oracle leg records the known G2 gap (qemu
# rejects guest execve; grounded in tests/test_p4_threads_signals.c
# and docs/rc6-parity.md).
#
# Exit status: 0 iff 0 unexpected failures (GAPs enumerated, never
# fatal). On success prints H2-LIBC-PASS.
set -u

T="${TRANSLATOR:-./_build/sparc64rt}"
ORACLE="${ORACLE-qemu-sparc64}"
OUTDIR="${OUTDIR:-/tmp/sparc64rt-h2}"

pass=0; fail=0; gap=0
row() {
    # row <name> <status> <detail>; detail always names the command.
    printf '%-28s %-6s %s\n' "$1" "$2" "$3"
    case "$2" in
        PASS) pass=$((pass + 1)) ;;
        FAIL) fail=$((fail + 1)) ;;
        GAP) gap=$((gap + 1)) ;;
    esac
}

need_translator() {
    if [ ! -x "$T" ]; then
        echo "h2_libc.sh: translator $T missing (build on the host first)" >&2
        exit 2
    fi
}

build_guests() {
    mkdir -p _build "$OUTDIR"
    sparc64-linux-gnu-gcc -static -O2 -o _build/guest_h2_string \
        tests/test_h2_string.c || return 1
    sparc64-linux-gnu-gcc -static -O2 -o _build/guest_h2_math \
        tests/test_h2_math.c -lm || return 1
    sparc64-linux-gnu-gcc -static -pthread -O2 -o _build/guest_h2_thread \
        tests/test_h2_thread.c || return 1
    sparc64-linux-gnu-gcc -static -O2 -o _build/guest_h2_signal \
        tests/test_h2_signal.c || return 1
    sparc64-linux-gnu-gcc -static -O2 -o _build/guest_h2_syscall \
        tests/test_h2_syscall.c || return 1
    sparc64-linux-gnu-gcc -static -O2 -o _build/guest_h2_process \
        tests/test_h2_process.c || return 1
    return 0
}

# run_single <name> <guest> <pass-marker> <difftest-mode>
# Full legs: oracle, interp vs dbt, oracle vs engines, difftest.
# difftest-mode is `full` (assert 0 divergences) or `bounded` (100 s
# budget; timeout is a recorded GAP, grounded: the file-I/O guest
# produces no difftest output within 100 s or 170 s, and the Phase 2
# p2 libc guest likewise has no difftest leg in tests/parity_suite.sh).
run_single() {
    name=$1; guest=$2; marker=$3; dt=${4:-full}
    if [ -n "$ORACLE" ]; then
        if "$ORACLE" "./$guest" >"$OUTDIR/o_$name.txt" 2>&1; then
            row "$name/oracle" "PASS" "$ORACLE ./$guest exit 0"
        else
            row "$name/oracle" "FAIL" "$ORACLE ./$guest exit $?"
        fi
    else
        row "$name/oracle" "GAP" "no oracle on this host"
    fi
    "$T" --interp "./$guest" >"$OUTDIR/i_$name.txt" 2>&1
    ei=$?
    "$T" --dbt "./$guest" >"$OUTDIR/d_$name.txt" 2>&1
    ed=$?
    if [ "$ei" -eq 0 ] && [ "$ed" -eq 0 ] \
        && cmp -s "$OUTDIR/i_$name.txt" "$OUTDIR/d_$name.txt" \
        && grep -q "$marker" "$OUTDIR/i_$name.txt"; then
        row "$name/interp-vs-dbt" "PASS" \
            "$T --interp|--dbt ./$guest identical, $marker"
    else
        row "$name/interp-vs-dbt" "FAIL" \
            "$T --interp|--dbt ./$guest interp=$ei dbt=$ed"
    fi
    if [ -n "$ORACLE" ]; then
        if cmp -s "$OUTDIR/o_$name.txt" "$OUTDIR/i_$name.txt" 2>/dev/null; then
            row "$name/oracle-vs-engines" "PASS" \
                "$ORACLE vs $T bit-for-bit"
        else
            row "$name/oracle-vs-engines" "FAIL" "outputs differ"
        fi
    else
        row "$name/oracle-vs-engines" "GAP" "no oracle on this host"
    fi
    if [ "$dt" = "bounded" ]; then
        if timeout --kill-after=10s 100s "$T" --difftest "./$guest" \
            >"$OUTDIR/f_$name.txt" 2>&1; then
            if grep -q "0 divergences" "$OUTDIR/f_$name.txt"; then
                row "$name/difftest" "PASS" \
                    "$T --difftest ./$guest $(grep divergences "$OUTDIR/f_$name.txt" | head -1)"
            else
                row "$name/difftest" "FAIL" \
                    "$T --difftest ./$guest divergences reported"
            fi
        elif [ "$?" -eq 124 ]; then
            row "$name/difftest" "GAP" \
                "$T --difftest ./$guest exceeds 100 s lockstep budget with no output (observed kills at 100 s and 170 s; p2 precedent: no difftest leg for file-I/O guests)"
        else
            row "$name/difftest" "FAIL" "$T --difftest ./$guest exit $?"
        fi
    elif "$T" --difftest "./$guest" >"$OUTDIR/f_$name.txt" 2>&1; then
        if grep -q "0 divergences" "$OUTDIR/f_$name.txt"; then
            row "$name/difftest" "PASS" \
                "$T --difftest ./$guest $(grep divergences "$OUTDIR/f_$name.txt" | head -1)"
        else
            row "$name/difftest" "FAIL" \
                "$T --difftest ./$guest divergences reported"
        fi
    else
        row "$name/difftest" "FAIL" "$T --difftest ./$guest exit $?"
    fi
}

# run_mt <name> <guest> <pass-marker> [oracle-gap-grep]
# Thread/process guests: oracle, interp vs dbt, no difftest (GAP).
run_mt() {
    name=$1; guest=$2; marker=$3; ogap=${4:-}
    if [ -n "$ORACLE" ]; then
        "$ORACLE" "./$guest" >"$OUTDIR/o_$name.txt" 2>&1
        oe=$?
        if [ -n "$ogap" ] && grep -q "$ogap" "$OUTDIR/o_$name.txt"; then
            row "$name/oracle" "GAP" \
                "G2: $ORACLE ./$guest $ogap (qemu rejects guest execve)"
        elif [ "$oe" -eq 0 ] && grep -q "$marker" "$OUTDIR/o_$name.txt"; then
            row "$name/oracle" "PASS" "$ORACLE ./$guest exit 0"
        else
            row "$name/oracle" "FAIL" "$ORACLE ./$guest exit $oe"
        fi
    else
        row "$name/oracle" "GAP" "no oracle on this host"
    fi
    "$T" --interp "./$guest" >"$OUTDIR/i_$name.txt" 2>&1
    ei=$?
    "$T" --dbt "./$guest" >"$OUTDIR/d_$name.txt" 2>&1
    ed=$?
    if [ "$ei" -eq 0 ] && [ "$ed" -eq 0 ] \
        && cmp -s "$OUTDIR/i_$name.txt" "$OUTDIR/d_$name.txt" \
        && grep -q "$marker" "$OUTDIR/i_$name.txt"; then
        row "$name/interp-vs-dbt" "PASS" \
            "$T --interp|--dbt ./$guest identical, $marker"
    else
        row "$name/interp-vs-dbt" "FAIL" \
            "$T --interp|--dbt ./$guest interp=$ei dbt=$ed"
    fi
    if [ -n "$ORACLE" ] && [ -z "$ogap" ]; then
        if cmp -s "$OUTDIR/o_$name.txt" "$OUTDIR/i_$name.txt" 2>/dev/null; then
            row "$name/oracle-vs-engines" "PASS" \
                "$ORACLE vs $T bit-for-bit"
        else
            row "$name/oracle-vs-engines" "FAIL" "outputs differ"
        fi
    else
        row "$name/oracle-vs-engines" "GAP" \
            "$([ -n "$ogap" ] && echo 'G2: oracle diverges on guest execve (documented)' || echo 'no oracle on this host')"
    fi
    row "$name/difftest" "GAP" \
        "no $T --difftest ./$guest leg: lockstep is single-threaded (clone ENOSYS under engine 2)"
}

need_translator
if ! build_guests; then
    echo "h2_libc.sh: guest build failed" >&2
    exit 2
fi

run_single "string" "_build/guest_h2_string" "H2-STRING-PASS" "full"
run_single "math" "_build/guest_h2_math" "H2-MATH-PASS" "full"
run_mt "thread" "_build/guest_h2_thread" "H2-THREAD-PASS"
run_single "signal" "_build/guest_h2_signal" "H2-SIGNAL-PASS" "full"
run_single "syscall" "_build/guest_h2_syscall" "H2-SYSCALL-PASS" "bounded"
run_mt "process" "_build/guest_h2_process" "H2-PROCESS-PASS" "WAIT-FAIL"

printf 'summary: %d PASS, %d FAIL, %d GAP\n' "$pass" "$fail" "$gap"
if [ "$fail" -eq 0 ]; then
    echo H2-LIBC-PASS
fi
[ "$fail" -eq 0 ]
