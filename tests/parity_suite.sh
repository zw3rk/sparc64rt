#!/bin/sh
# tests/parity_suite.sh -- Phase 6 dual-host parity runner (lane L6b).
#
# Runs the full Phase 1-5 suite (test_p1_isa, test_p3_fp_simd,
# test_p4_threads_signals, test_p5_dyn, the BusyBox probe, and the
# adjacent page-permission probe test_p6_page_perm) with --interp and
# --dbt, plus --difftest where single-threaded, and compares outputs.
#
# Two modes (same script, environment-selected):
#   Linux container (AArch64, cross toolchain + qemu-user present):
#     ./tests/parity_suite.sh
#     Runs oracle (qemu-sparc64) + both engines + difftest legs.
#   macOS host under hyper-linux:
#     HL=../hyper-linux/_build/hl SPARC64RT_SYSROOT=/tmp/sparc64-sysroot \
#       ./tests/parity_suite.sh
#     Runs both engines via `hl <translator> ...` (hl executes the
#     AArch64 translator natively; it has no --sparc64rt dispatch).
#     Oracle legs are skipped (no qemu on the Mac); engine outputs are
#     compared against each other and, for golden-anchored legs, against
#     the committed goldens.
#
# Environment:
#   TRANSLATOR  translator binary (default ./_build/sparc64rt)
#   ORACLE      oracle binary (default qemu-sparc64; empty skips oracle)
#   HL          when set, prefix every translator run with `$HL`
#   SYSROOT     guest sysroot for dynamic legs (SPARC64RT_SYSROOT);
#               required for test_p5_dyn and BusyBox legs
#   BB_BIN      BusyBox guest path (default ./_build/busybox; export an
#               absolute path in hl mode, e.g. $PWD/_build/busybox)
#   OUTDIR      where per-leg outputs go (default /tmp/sparc64rt-parity)
#
# Known oracle/host gaps (informational, never fatal; see
# docs/rc6-parity.md for the grounded details):
#   G1 qemu-sparc64 >= 10 faults on STQF (p3 oracle stops mid-output).
#   G2 qemu rejects every guest execve (p4 oracle shows WAIT-FAIL).
#   G3 qemu cannot nested-exec a SPARC binary (adapted BusyBox pipe
#      leg oracle exits 126).
#   G4 under hl, fork+exec of a host Mach-O binary (the exact BusyBox
#      probe's `ls`/`wc`) has no native equivalent: single execs fail
#      cleanly ("not an ELF file"), the full `&&` probe traps with
#      cause=2 (ILLEGAL). The adapted SPARC-only pipe leg qualifies
#      BusyBox fork/exec/pipe/wait on hl instead.
#
# Exit status: 0 iff every applicable leg passes; gap rows are reported
# as GAP, mismatches as FAIL.
set -u

T="${TRANSLATOR:-./_build/sparc64rt}"
ORACLE="${ORACLE-qemu-sparc64}"
HL="${HL:-}"
OUTDIR="${OUTDIR:-/tmp/sparc64rt-parity}"
SYSROOT="${SYSROOT:-${SPARC64RT_SYSROOT:-}}"
BB_BIN="${BB_BIN:-./_build/busybox}"

pass=0; fail=0; gap=0
row() {
    # row <name> <status> <detail>
    printf '%-28s %-6s %s\n' "$1" "$2" "$3"
    case "$2" in
        PASS) pass=$((pass + 1)) ;;
        FAIL) fail=$((fail + 1)) ;;
        GAP) gap=$((gap + 1)) ;;
    esac
}

run_engine() {
    # run_engine <engine-flag> <guest> [args...]; stdout captured by caller
    eng=$1; shift
    if [ -n "$HL" ]; then
        "$HL" "$T" "$eng" "$@"
    else
        "$T" "$eng" "$@"
    fi
}

need_sysroot() {
    if [ -z "$SYSROOT" ]; then
        row "$1" "FAIL" "SPARC64RT_SYSROOT/SYSROOT not set"
        return 1
    fi
    return 0
}

with_sysroot() {
    # with_sysroot <cmd...>: run with dynamic-guest sysroot in env
    SPARC64RT_SYSROOT="$SYSROOT" "$@"
}

mkdir -p "$OUTDIR"

# ---- static legs: p1 (freestanding ISA) ----
if [ -n "$ORACLE" ]; then
    if "$ORACLE" ./_build/guest_p1 >"$OUTDIR/o_p1.txt" 2>&1; then
        row "p1/oracle" "PASS" "exit 0"
    else
        row "p1/oracle" "FAIL" "exit $?"
    fi
else
    row "p1/oracle" "GAP" "no oracle on this host"
fi
run_engine --interp "./_build/guest_p1" >"$OUTDIR/i_p1.txt" 2>&1
ei=$?
run_engine --dbt "./_build/guest_p1" >"$OUTDIR/d_p1.txt" 2>&1
ed=$?
if [ "$ei" -eq 0 ] && [ "$ed" -eq 0 ] && cmp -s "$OUTDIR/i_p1.txt" "$OUTDIR/d_p1.txt"; then
    row "p1/interp-vs-dbt" "PASS" "exit 0, identical"
else
    row "p1/interp-vs-dbt" "FAIL" "interp=$ei dbt=$ed"
fi
if [ -n "$ORACLE" ] && cmp -s "$OUTDIR/o_p1.txt" "$OUTDIR/i_p1.txt" 2>/dev/null; then
    row "p1/oracle-vs-engines" "PASS" "bit-for-bit"
elif [ -n "$ORACLE" ]; then
    row "p1/oracle-vs-engines" "FAIL" "outputs differ"
else
    row "p1/oracle-vs-engines" "GAP" "no oracle on this host"
fi
if run_engine --difftest "./_build/guest_p1" >"$OUTDIR/f_p1.txt" 2>&1; then
    if grep -q "0 divergences" "$OUTDIR/f_p1.txt"; then
        row "p1/difftest" "PASS" "$(grep divergences "$OUTDIR/f_p1.txt" | head -1)"
    else
        row "p1/difftest" "FAIL" "divergences reported"
    fi
else
    row "p1/difftest" "FAIL" "exit $?"
fi

# ---- static legs: p3 (FP/SIMD) ----
if [ -n "$ORACLE" ]; then
    if "$ORACLE" ./_build/guest_p3 >"$OUTDIR/o_p3.txt" 2>&1; then
        row "p3/oracle" "PASS" "exit 0"
    else
        row "p3/oracle" "GAP" "G1: qemu>=10 STQF fault (see rc6-parity.md)"
    fi
else
    row "p3/oracle" "GAP" "no oracle on this host"
fi
run_engine --interp "./_build/guest_p3" >"$OUTDIR/i_p3.txt" 2>&1
ei=$?
run_engine --dbt "./_build/guest_p3" >"$OUTDIR/d_p3.txt" 2>&1
ed=$?
if [ "$ei" -eq 0 ] && [ "$ed" -eq 0 ] && cmp -s "$OUTDIR/i_p3.txt" "$OUTDIR/d_p3.txt" \
    && grep -q "P3-PASS" "$OUTDIR/i_p3.txt"; then
    row "p3/interp-vs-dbt" "PASS" "P3-PASS, identical"
else
    row "p3/interp-vs-dbt" "FAIL" "interp=$ei dbt=$ed"
fi
if run_engine --difftest "./_build/guest_p3" >"$OUTDIR/f_p3.txt" 2>&1; then
    if grep -q "0 divergences" "$OUTDIR/f_p3.txt"; then
        row "p3/difftest" "PASS" "$(grep divergences "$OUTDIR/f_p3.txt" | head -1)"
    else
        row "p3/difftest" "FAIL" "divergences reported"
    fi
else
    row "p3/difftest" "FAIL" "exit $?"
fi

# ---- static legs: p4 (threads/signals/lifecycle; no difftest: threaded) ----
if [ -n "$ORACLE" ]; then
    "$ORACLE" ./_build/guest_p4 >"$OUTDIR/o_p4.txt" 2>&1
    if grep -q "WAIT-FAIL" "$OUTDIR/o_p4.txt"; then
        row "p4/oracle" "GAP" "G2: qemu rejects guest execve (documented)"
    else
        row "p4/oracle" "PASS" "exit $?"
    fi
else
    row "p4/oracle" "GAP" "no oracle on this host"
fi
run_engine --interp "./_build/guest_p4" >"$OUTDIR/i_p4.txt" 2>&1
ei=$?
run_engine --dbt "./_build/guest_p4" >"$OUTDIR/d_p4.txt" 2>&1
ed=$?
if [ "$ei" -eq 0 ] && [ "$ed" -eq 0 ] && cmp -s "$OUTDIR/i_p4.txt" "$OUTDIR/d_p4.txt" \
    && grep -q "P4-PASS" "$OUTDIR/i_p4.txt"; then
    row "p4/interp-vs-dbt" "PASS" "P4-PASS, identical"
else
    row "p4/interp-vs-dbt" "FAIL" "interp=$ei dbt=$ed"
fi

# ---- dynamic legs: p5 (needs SYSROOT) ----
if need_sysroot "p5/sysroot"; then
    if [ -n "$ORACLE" ]; then
        if with_sysroot "$ORACLE" -L "$SYSROOT" ./_build/guest_p5_dyn >"$OUTDIR/o_p5.txt" 2>&1; then
            row "p5/oracle" "PASS" "exit 0"
        else
            row "p5/oracle" "FAIL" "exit $?"
        fi
    else
        row "p5/oracle" "GAP" "no oracle on this host"
    fi
    (export SPARC64RT_SYSROOT="$SYSROOT"; run_engine --interp "./_build/guest_p5_dyn" >"$OUTDIR/i_p5.txt" 2>&1)
    ei=$?
    (export SPARC64RT_SYSROOT="$SYSROOT"; run_engine --dbt "./_build/guest_p5_dyn" >"$OUTDIR/d_p5.txt" 2>&1)
    ed=$?
    if [ "$ei" -eq 0 ] && [ "$ed" -eq 0 ] && cmp -s "$OUTDIR/i_p5.txt" "$OUTDIR/d_p5.txt"; then
        if cmp -s "$OUTDIR/i_p5.txt" tests/test_p5_dyn.golden; then
            row "p5/interp-vs-dbt" "PASS" "P5-PASS, matches golden"
        else
            row "p5/interp-vs-dbt" "FAIL" "engines agree but differ from golden"
        fi
    else
        row "p5/interp-vs-dbt" "FAIL" "interp=$ei dbt=$ed"
    fi
    if [ -n "$ORACLE" ]; then
        if cmp -s "$OUTDIR/o_p5.txt" "$OUTDIR/i_p5.txt" 2>/dev/null; then
            row "p5/oracle-vs-engines" "PASS" "bit-for-bit"
        else
            row "p5/oracle-vs-engines" "FAIL" "outputs differ"
        fi
    else
        row "p5/oracle-vs-engines" "GAP" "no oracle on this host"
    fi
fi

# ---- dynamic legs: BusyBox exact probe (needs SYSROOT) ----
if need_sysroot "bb/sysroot"; then
    if [ -n "$HL" ]; then
        row "bb-probe/oracle" "GAP" "no oracle on this host"
    elif [ -n "$ORACLE" ]; then
        if with_sysroot "$ORACLE" -L "$SYSROOT" "$BB_BIN" sh -c 'ls / && echo ok | wc -c' >"$OUTDIR/o_bb.txt" 2>&1; then
            row "bb-probe/oracle" "PASS" "exit 0"
        else
            row "bb-probe/oracle" "FAIL" "exit $?"
        fi
    fi
    (export SPARC64RT_SYSROOT="$SYSROOT"; run_engine --interp "$BB_BIN" sh -c 'ls / && echo ok | wc -c' >"$OUTDIR/i_bb.txt" 2>&1)
    ei=$?
    if [ -n "$HL" ]; then
        # G4: exact probe needs host-native `ls`/`wc`; record, do not hack around.
        row "bb-probe/hl-engines" "GAP" "G4: host Mach-O exec has no hl equivalent (exit $ei)"
    else
        (export SPARC64RT_SYSROOT="$SYSROOT"; run_engine --dbt "$BB_BIN" sh -c 'ls / && echo ok | wc -c' >"$OUTDIR/d_bb.txt" 2>&1)
        ed=$?
        if [ "$ei" -eq 0 ] && [ "$ed" -eq 0 ] && cmp -s "$OUTDIR/i_bb.txt" "$OUTDIR/d_bb.txt" \
            && cmp -s "$OUTDIR/i_bb.txt" tests/busybox_probe.golden; then
            row "bb-probe/interp-vs-dbt" "PASS" "matches golden"
        else
            row "bb-probe/interp-vs-dbt" "FAIL" "interp=$ei dbt=$ed"
        fi
        if (export SPARC64RT_SYSROOT="$SYSROOT"; run_engine --difftest "$BB_BIN" sh -c 'ls / && echo ok | wc -c' >"$OUTDIR/f_bb.txt" 2>&1) \
            && grep -q "0 divergences" "$OUTDIR/f_bb.txt"; then
            row "bb-probe/difftest" "PASS" "$(grep divergences "$OUTDIR/f_bb.txt" | head -1)"
        else
            row "bb-probe/difftest" "FAIL" "see $OUTDIR/f_bb.txt"
        fi
        if cmp -s "$OUTDIR/o_bb.txt" "$OUTDIR/i_bb.txt" 2>/dev/null; then
            row "bb-probe/oracle-vs-engines" "PASS" "bit-for-bit"
        else
            row "bb-probe/oracle-vs-engines" "FAIL" "outputs differ"
        fi
    fi
fi

# ---- dynamic legs: BusyBox SPARC-only pipe (fork/exec/pipe/wait, both hosts) ----
if need_sysroot "bb-sp/sysroot"; then
    if [ -n "$ORACLE" ] && [ -z "$HL" ]; then
        with_sysroot "$ORACLE" -L "$SYSROOT" "$BB_BIN" sh -c "echo ok | $BB_BIN wc -c" >"$OUTDIR/o_bbsp.txt" 2>&1
        row "bb-sp/oracle" "GAP" "G3: qemu cannot nested-exec SPARC (exit $?)"
    else
        row "bb-sp/oracle" "GAP" "no oracle on this host"
    fi
    (export SPARC64RT_SYSROOT="$SYSROOT"; run_engine --interp "$BB_BIN" sh -c "echo ok | $BB_BIN wc -c" >"$OUTDIR/i_bbsp.txt" 2>&1)
    ei=$?
    (export SPARC64RT_SYSROOT="$SYSROOT"; run_engine --dbt "$BB_BIN" sh -c "echo ok | $BB_BIN wc -c" >"$OUTDIR/d_bbsp.txt" 2>&1)
    ed=$?
    if [ "$ei" -eq 0 ] && [ "$ed" -eq 0 ] && cmp -s "$OUTDIR/i_bbsp.txt" "$OUTDIR/d_bbsp.txt" \
        && cmp -s "$OUTDIR/i_bbsp.txt" tests/busybox_sp_pipe.golden; then
        row "bb-sp/interp-vs-dbt" "PASS" "matches golden"
    else
        row "bb-sp/interp-vs-dbt" "FAIL" "interp=$ei dbt=$ed"
    fi
fi

# ---- page-permission probe (single-threaded: oracle/engines/difftest) ----
if [ -n "$ORACLE" ]; then
    if "$ORACLE" ./_build/guest_p6pperm >"$OUTDIR/o_p6p.txt" 2>&1; then
        row "p6p/oracle" "PASS" "exit 0"
    else
        row "p6p/oracle" "FAIL" "exit $?"
    fi
else
    row "p6p/oracle" "GAP" "no oracle on this host"
fi
run_engine --interp "./_build/guest_p6pperm" >"$OUTDIR/i_p6p.txt" 2>&1
ei=$?
run_engine --dbt "./_build/guest_p6pperm" >"$OUTDIR/d_p6p.txt" 2>&1
ed=$?
if [ "$ei" -eq 0 ] && [ "$ed" -eq 0 ] && cmp -s "$OUTDIR/i_p6p.txt" "$OUTDIR/d_p6p.txt" \
    && grep -q "P6P-PASS" "$OUTDIR/i_p6p.txt"; then
    row "p6p/interp-vs-dbt" "PASS" "P6P-PASS, identical"
else
    row "p6p/interp-vs-dbt" "FAIL" "interp=$ei dbt=$ed"
fi
if [ -n "$ORACLE" ]; then
    if cmp -s "$OUTDIR/o_p6p.txt" "$OUTDIR/i_p6p.txt" 2>/dev/null; then
        row "p6p/oracle-vs-engines" "PASS" "bit-for-bit"
    else
        row "p6p/oracle-vs-engines" "FAIL" "outputs differ"
    fi
else
    row "p6p/oracle-vs-engines" "GAP" "no oracle on this host"
fi
if run_engine --difftest "./_build/guest_p6pperm" >"$OUTDIR/f_p6p.txt" 2>&1; then
    if grep -q "0 divergences" "$OUTDIR/f_p6p.txt"; then
        row "p6p/difftest" "PASS" "$(grep divergences "$OUTDIR/f_p6p.txt" | head -1)"
    else
        row "p6p/difftest" "FAIL" "divergences reported"
    fi
else
    row "p6p/difftest" "FAIL" "exit $?"
fi

printf 'summary: %d PASS, %d FAIL, %d GAP\n' "$pass" "$fail" "$gap"
[ "$fail" -eq 0 ]
