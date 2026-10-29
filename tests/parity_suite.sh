#!/bin/sh
# tests/parity_suite.sh — sparc64rt cross-engine parity gate.
#
# Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
# SPDX-License-Identifier: Apache-2.0
#
# Hermetic golden-bundle suite. On every host (Darwin with or without
# qemu-sparc64, Linux with or without qemu) the script compares
# --interp, --dbt, and --difftest against the committed golden bundle
# under tests/golden/ and never records GAP for a missing oracle: the
# goldens ARE the oracle contract (live qemu-sparc64 carries documented
# bugs G1/STQF, G2/execve-refusal, G3/nested-exec, so strict
# oracle-vs-engine comparison would fail even on Linux).
#
# Runner selection:
#   static legs (guest_p1, guest_p3, guest_p6pperm): the native Darwin
#     translator (_build/sparc64rt-darwin-arm64) when present, else the
#     Linux translator.
#   threaded legs (guest_p4 static, guest_p5_dyn dynamic): the Linux
#     translator under hyper-linux on Darwin, directly on Linux; dynamic
#     legs always with a sysroot (default the committed minimal
#     tests/sysroot/: ld-linux, libc, libm, libresolv). The Darwin
#     translator cannot run threaded guests (p4: interp exits 1 with
#     cause=1 pc=0x0, dbt segfaults the translator itself; p5 traps in
#     the futex path), so HL is mandatory for them.
#   busybox SPARC-pipe leg: interp/dbt run on the fast static runner
#     (identical `3` stdout, 0.7s vs 8.5s under HL); --difftest stays on
#     HL (the faster lockstep host here).
#   AOT round-trip: --dbt --cache --stats on guest_p1 via the static
#     runner; asserts identical stdout across a cold/warm pair plus a
#     stable 64-hex identity key. The AOT cache backend is excluded from
#     the frozen build, so admission always declines (backend-not-linked
#     on Linux, cache-authority-declined on Darwin/HL): the check pins
#     that documented fail-closed contract instead of faking a cache
#     hit. Linking the backend (Coordinator decision) upgrades this leg
#     to assert stored/hit.
#
# Coverage notes (grounded, not worked around):
#   p4/p5 have no --difftest leg (lockstep harness is single-threaded by
#   design; thread behavior is verified by interp-vs-dbt output parity).
#   The exact BusyBox probe (`ls / && echo ok | wc -c`) is not run: it
#   needs host-native ls/wc, which under HL resolve to macOS Mach-O
#   binaries (G4: clean "not an ELF file" failure). The SPARC-only pipe
#   leg (`echo ok | busybox wc -c` -> `3`) qualifies BusyBox
#   fork/exec/pipe/wait on both hosts instead.
#
# Golden regeneration (review the diff before committing):
#   PARITY_UPDATE_GOLDEN=1 sh tests/parity_suite.sh
#
# Environment:
#   TRANSLATOR  translator binary (used directly for every leg; HL is
#               bypassed). Default: _build/sparc64rt-darwin-arm64 (Darwin)
#               or _build/sparc64rt (Linux).
#   HL          hyper-linux binary (default sibling
#               ../hyper-linux/_build/hl). Required on Darwin for the p4,
#               p5, and busybox legs.
#   SYSROOT / SPARC64RT_SYSROOT  guest sysroot for dynamic legs
#               (default tests/sysroot/).
#   OUTDIR      per-leg outputs (default /tmp/sparc64rt-parity).
#   PARITY_UPDATE_GOLDEN=1  refresh tests/golden/ from current engines.
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CONTRACT="$ROOT/../rt-series/tools/parity_contract.sh"
if [ ! -f "$CONTRACT" ]; then
    echo "parity_suite: missing frozen contract $CONTRACT" >&2
    exit 1
fi
# shellcheck disable=SC1090
. "$CONTRACT"
parity_init "sparc64rt"

HOST_OS="$(uname -s | tr 'A-Z' 'a-z')"
HOST_M="$(uname -m)"
HOST_TAG="${HOST_OS}-${HOST_M}"
GOLDEN_DIR="$ROOT/tests/golden"
GUEST_DIR="$ROOT/tests/guests"
OUT_DIR="${OUTDIR:-/tmp/sparc64rt-parity}"
mkdir -p "$OUT_DIR"

if [ -n "${TRANSLATOR:-}" ]; then
    STATIC_RT="$TRANSLATOR"
    LINUX_RT="$TRANSLATOR"
    HL_USED=0
elif [ "$HOST_OS" = "darwin" ]; then
    if [ -x "$ROOT/_build/sparc64rt-darwin-arm64" ]; then
        STATIC_RT="$ROOT/_build/sparc64rt-darwin-arm64"
    elif [ -x "$ROOT/_build/sparc64rt-darwin" ]; then
        STATIC_RT="$ROOT/_build/sparc64rt-darwin"
    else
        STATIC_RT=""
    fi
    LINUX_RT="$ROOT/_build/sparc64rt"
    HL_USED=1
else
    STATIC_RT="$ROOT/_build/sparc64rt"
    LINUX_RT="$ROOT/_build/sparc64rt"
    HL_USED=0
fi
if [ "$HL_USED" = "1" ]; then
    HL="${HL:-$ROOT/../hyper-linux/_build/hl}"
else
    HL="${HL:-}"
fi
if [ -n "${SPARC64RT_SYSROOT:-}" ]; then
    SYSROOT="$SPARC64RT_SYSROOT"
elif [ -n "${SYSROOT:-}" ]; then
    SYSROOT="$SYSROOT"
else
    SYSROOT="$ROOT/tests/sysroot"
fi

if [ -z "$STATIC_RT" ] || [ ! -x "$STATIC_RT" ]; then
    if [ "$HL_USED" = "1" ] && [ -x "${HL:-}" ] && [ -x "$LINUX_RT" ]; then
        STATIC_RT="$LINUX_RT"
        STATIC_VIA_HL=1
    else
        parity_row "host" "$HOST_TAG" "translator-present" "host" "GAP" 0 "no runnable translator (build sparc64rt-darwin-arm64 or _build/sparc64rt)"
        parity_summary
        exit $?
    fi
else
    STATIC_VIA_HL=0
fi

# run_static <engine> <guest> <outfile>: static leg via the preferred
# runner (native Darwin translator, or HL+Linux translator fallback).
run_static() {
    _eng="$1"; _guest="$2"; _out="$3"
    if [ "$STATIC_VIA_HL" = "1" ]; then
        "$HL" "$STATIC_RT" "--$_eng" "$_guest" >"$_out" 2>&1
    else
        "$STATIC_RT" "--$_eng" "$_guest" >"$_out" 2>&1
    fi
}

# run_dyn <engine> <guest> <outfile> [workdir]: dynamic/busybox leg
# (HL+Linux translator on Darwin, Linux translator directly on Linux).
run_dyn() {
    _eng="$1"; _guest="$2"; _out="$3"
    if [ $# -ge 4 ]; then
        _wd="$4"
    else
        _wd="$ROOT"
    fi
    if [ "$HL_USED" = "1" ]; then
        (cd "$_wd" && SPARC64RT_SYSROOT="$SYSROOT" "$HL" "$LINUX_RT" "--$_eng" "$_guest" >"$_out" 2>&1)
    else
        (cd "$_wd" && SPARC64RT_SYSROOT="$SYSROOT" "$LINUX_RT" "--$_eng" "$_guest" >"$_out" 2>&1)
    fi
}

# run_static_args <engine> <guest> <outfile> <args...>: static-runner
# leg with extra guest argv (dynamic guests still resolve their
# PT_INTERP loader through SPARC64RT_SYSROOT).
run_static_args() {
    _eng="$1"; _guest="$2"; _out="$3"
    shift 3
    if [ "$STATIC_VIA_HL" = "1" ]; then
        SPARC64RT_SYSROOT="$SYSROOT" "$HL" "$STATIC_RT" "--$_eng" "$_guest" "$@" >"$_out" 2>&1
    else
        SPARC64RT_SYSROOT="$SYSROOT" "$STATIC_RT" "--$_eng" "$_guest" "$@" >"$_out" 2>&1
    fi
}

# run_dyn_args <engine> <guest> <outfile> <workdir> <args...>: dynamic
# leg with extra guest argv (busybox applets).
run_dyn_args() {
    _eng="$1"; _guest="$2"; _out="$3"; _wd="$4"
    shift 4
    if [ "$HL_USED" = "1" ]; then
        (cd "$_wd" && SPARC64RT_SYSROOT="$SYSROOT" "$HL" "$LINUX_RT" "--$_eng" "$_guest" "$@" >"$_out" 2>&1)
    else
        (cd "$_wd" && SPARC64RT_SYSROOT="$SYSROOT" "$LINUX_RT" "--$_eng" "$_guest" "$@" >"$_out" 2>&1)
    fi
}

# --- parallel lanes (one background job per leg, MAXJOBS concurrent) --
# do_* executes the engine and records raw output, exit code, and timing
# into $OUT_DIR/job-<tag>.* ; emit_* runs in the parent afterwards and
# turns those records into contract rows in fixed order.
MAXJOBS=8
_njobs=0
launch() {
    "$@" &
    _njobs=$((_njobs + 1))
    if [ "$_njobs" -ge "$MAXJOBS" ]; then
        wait
        _njobs=0
    fi
}

# do_engine <tag> <mode:static|dyn|dynbb> <engine> <guest> [workdir] [args...]
# dynbb appends guest argv (busybox SPARC-only pipe probe).
do_engine() {
    _tag="$1"; _mode="$2"; _eng="$3"; _guest="$4"
    if [ $# -ge 5 ]; then _wd="$5"; else _wd="$ROOT"; fi
    _t0=$(parity_now_ms)
    case "$_mode" in
        staticbb)
            shift 5
            run_static_args "$_eng" "$_guest" "$OUT_DIR/job-$_tag.raw" "$@" ;;
        dynbb)
            shift 5
            run_dyn_args "$_eng" "$_guest" "$OUT_DIR/job-$_tag.raw" "$_wd" "$@" ;;
        dyn)
            run_dyn "$_eng" "$_guest" "$OUT_DIR/job-$_tag.raw" "$_wd" ;;
        *)
            run_static "$_eng" "$_guest" "$OUT_DIR/job-$_tag.raw" ;;
    esac
    printf '%s\n' "$?" >"$OUT_DIR/job-$_tag.rc"
    printf '%s %s\n' "$_t0" "$(parity_now_ms)" >"$OUT_DIR/job-$_tag.ms"
}

# do_difftest <tag> <mode:static|dyn|dynbb> <guest> [workdir]
# dynbb runs the SPARC-only pipe probe: busybox sh -c "echo ok | <bb> wc -c".
do_difftest() {
    _tag="$1"; _mode="$2"; _guest="$3"
    if [ $# -ge 4 ]; then _wd="$4"; else _wd="$ROOT"; fi
    _t0=$(parity_now_ms)
    case "$_mode" in
        static)
            run_static "difftest" "$_guest" "$OUT_DIR/job-$_tag.raw" ;;
        dyn)
            run_dyn "difftest" "$_guest" "$OUT_DIR/job-$_tag.raw" "$_wd" ;;
        dynbb)
            run_dyn_args "difftest" "$_guest" "$OUT_DIR/job-$_tag.raw" "$_wd" \
                sh -c "echo ok | $_guest wc -c" ;;
    esac
    printf '%s\n' "$?" >"$OUT_DIR/job-$_tag.rc"
    printf '%s %s\n' "$_t0" "$(parity_now_ms)" >"$OUT_DIR/job-$_tag.ms"
}

job_ms() {
    if [ -f "$OUT_DIR/job-$1.ms" ]; then
        # shellcheck disable=SC2086
        set -- $(cat "$OUT_DIR/job-$1.ms")
        echo "$(($2 - $1))"
    else
        echo "0"
    fi
}

job_rc() {
    if [ -f "$OUT_DIR/job-$1.rc" ]; then
        cat "$OUT_DIR/job-$1.rc"
    else
        echo "127"
    fi
}

# norm_out <tag>: HL harness chatter strip + difftest count normalization.
# Writes $OUT_DIR/<tag>.out (emit compares/copies that path).
norm_out() {
    parity_norm_stderr "$OUT_DIR/job-$1.raw" "$OUT_DIR/job-$1.filt"
    sed -E 's/[0-9][0-9]* steps/N steps/' \
        "$OUT_DIR/job-$1.filt" >"$OUT_DIR/$1.out"
}

# emit_engine <case> <engine> <detail>: compare job-<case>-<engine>.
emit_engine() {
    _case="$1"; _eng="$2"; _det="$3"
    _tag="$_case-$_eng"
    if [ ! -f "$OUT_DIR/job-$_tag.raw" ]; then
        parity_row "sparc64" "$HOST_TAG" "$_tag" "$_eng" "FAIL" 0 "background job produced no output"
        return
    fi
    norm_out "$_tag"
    _rc=$(job_rc "$_tag")
    _ms=$(job_ms "$_tag")
    if [ "$PARITY_UPDATE_GOLDEN" = "1" ]; then
        mkdir -p "$GOLDEN_DIR"
        cp "$OUT_DIR/$_tag.out" "$GOLDEN_DIR/$_case.out"
        printf '%s\n' "$_rc" >"$GOLDEN_DIR/$_case.exit"
        parity_row "sparc64" "$HOST_TAG" "$_tag" "$_eng" "PASS" "$_ms" "exit $_rc, golden recorded"
        return
    fi
    if [ ! -f "$GOLDEN_DIR/$_case.out" ]; then
        parity_row "sparc64" "$HOST_TAG" "$_tag" "$_eng" "GAP" "$_ms" "missing golden tests/golden/$_case.out"
        return
    fi
    if [ -f "$GOLDEN_DIR/$_case.exit" ]; then
        _exprc="$(cat "$GOLDEN_DIR/$_case.exit")"
    else
        _exprc="$_rc"
    fi
    if [ "$_rc" != "$_exprc" ]; then
        parity_row "sparc64" "$HOST_TAG" "$_tag" "$_eng" "FAIL" "$_ms" "exit $_rc, golden wants $_exprc"
    elif parity_check_golden "$GOLDEN_DIR/$_case.out" "$OUT_DIR/$_tag.out"; then
        parity_row "sparc64" "$HOST_TAG" "$_tag" "$_eng" "PASS" "$_ms" "exit $_rc, matches golden ($_det)"
    else
        parity_row "sparc64" "$HOST_TAG" "$_tag" "$_eng" "FAIL" "$_ms" "exit $_rc, output differs from golden ($_det)"
    fi
}

# emit_difftest <case> <detail>: like emit_engine plus the clean marker.
emit_difftest() {
    _case="$1"; _det="$2"
    _tag="$_case-difftest"
    if [ ! -f "$OUT_DIR/job-$_tag.raw" ]; then
        parity_row "sparc64" "$HOST_TAG" "$_tag" "difftest" "FAIL" 0 "background job produced no output"
        return
    fi
    norm_out "$_tag"
    _rc=$(job_rc "$_tag")
    _ms=$(job_ms "$_tag")
    if [ "$PARITY_UPDATE_GOLDEN" = "1" ]; then
        mkdir -p "$GOLDEN_DIR"
        cp "$OUT_DIR/$_tag.out" "$GOLDEN_DIR/$_tag.out"
        printf '%s\n' "$_rc" >"$GOLDEN_DIR/$_tag.exit"
        parity_row "sparc64" "$HOST_TAG" "$_tag" "difftest" "PASS" "$_ms" "exit $_rc, golden recorded"
        return
    fi
    if [ ! -f "$GOLDEN_DIR/$_tag.out" ]; then
        parity_row "sparc64" "$HOST_TAG" "$_tag" "difftest" "GAP" "$_ms" "missing golden tests/golden/$_tag.out"
        return
    fi
    if [ -f "$GOLDEN_DIR/$_tag.exit" ]; then
        _exprc="$(cat "$GOLDEN_DIR/$_tag.exit")"
    else
        _exprc="$_rc"
    fi
    if [ "$_rc" != "$_exprc" ]; then
        parity_row "sparc64" "$HOST_TAG" "$_tag" "difftest" "FAIL" "$_ms" "exit $_rc, golden wants $_exprc"
    elif ! grep -q "0 divergences" "$OUT_DIR/$_tag.out"; then
        parity_row "sparc64" "$HOST_TAG" "$_tag" "difftest" "FAIL" "$_ms" "exit $_rc, no '0 divergences' marker"
    elif parity_check_golden "$GOLDEN_DIR/$_tag.out" "$OUT_DIR/$_tag.out"; then
        parity_row "sparc64" "$HOST_TAG" "$_tag" "difftest" "PASS" "$_ms" "exit $_rc, 0 divergences, matches golden ($_det)"
    else
        parity_row "sparc64" "$HOST_TAG" "$_tag" "difftest" "FAIL" "$_ms" "exit $_rc, output differs from golden ($_det)"
    fi
}

# --- capability gates (fail closed, no SKIP) ---------------------------
can_static=1
if [ ! -x "$STATIC_RT" ] && [ "$STATIC_VIA_HL" != "1" ]; then
    can_static=0
fi
can_dyn=1
if [ ! -x "$LINUX_RT" ]; then
    can_dyn=0
elif [ "$HL_USED" = "1" ] && [ ! -x "$HL" ]; then
    can_dyn=0
fi
if [ ! -d "$SYSROOT" ]; then
    can_dyn=0
fi

# --- launch legs -------------------------------------------------------
if [ "$can_static" = "1" ]; then
    for _c in p1 p3 p6pperm; do
        case "$_c" in
            p1) _g="guest_p1" ;;
            p3) _g="guest_p3" ;;
            p6pperm) _g="guest_p6pperm" ;;
        esac
        if [ -f "$GUEST_DIR/$_g" ]; then
            launch do_engine "$_c-interp" "static" "interp" "$GUEST_DIR/$_g"
            launch do_engine "$_c-dbt" "static" "dbt" "$GUEST_DIR/$_g"
            launch do_difftest "$_c-difftest" "static" "$GUEST_DIR/$_g"
        fi
    done
fi
if [ "$can_dyn" = "1" ]; then
    if [ -f "$GUEST_DIR/guest_p4" ]; then
        launch do_engine "p4-interp" "dyn" "interp" "$GUEST_DIR/guest_p4"
        launch do_engine "p4-dbt" "dyn" "dbt" "$GUEST_DIR/guest_p4"
    fi
    if [ -f "$GUEST_DIR/guest_p5_dyn" ] && [ -f "$GUEST_DIR/libp5.so" ]; then
        launch do_engine "p5_dyn-interp" "dyn" "interp" "$GUEST_DIR/guest_p5_dyn" "$GUEST_DIR"
        launch do_engine "p5_dyn-dbt" "dyn" "dbt" "$GUEST_DIR/guest_p5_dyn" "$GUEST_DIR"
    fi
    if [ -f "$GUEST_DIR/busybox" ]; then
        launch do_difftest "bb-sp-difftest" "dynbb" "$GUEST_DIR/busybox" "$GUEST_DIR"
    fi
fi
if [ -f "$GUEST_DIR/busybox" ] && [ "$can_static" = "1" ] && [ -d "$SYSROOT" ]; then
    # interp/dbt run on the fast static runner (0.7s vs 8.5s under HL,
    # identical stdout); only --difftest needs the HL lockstep host.
    launch do_engine "bb-sp-interp" "staticbb" "interp" "$GUEST_DIR/busybox" \
        "$GUEST_DIR" sh -c "echo ok | $GUEST_DIR/busybox wc -c"
    launch do_engine "bb-sp-dbt" "staticbb" "dbt" "$GUEST_DIR/busybox" \
        "$GUEST_DIR" sh -c "echo ok | $GUEST_DIR/busybox wc -c"
fi
wait

# --- emit rows in fixed order ------------------------------------------
for _c in p1 p3 p6pperm; do
    case "$_c" in
        p1) _g="guest_p1" ;;
        p3) _g="guest_p3" ;;
        p6pperm) _g="guest_p6pperm" ;;
    esac
    if [ ! -f "$GUEST_DIR/$_g" ]; then
        parity_row "sparc64" "$HOST_TAG" "$_c-interp" "interp" "GAP" 0 "missing guest tests/guests/$_g"
        parity_row "sparc64" "$HOST_TAG" "$_c-dbt" "dbt" "GAP" 0 "missing guest tests/guests/$_g"
        parity_row "sparc64" "$HOST_TAG" "$_c-difftest" "difftest" "GAP" 0 "missing guest tests/guests/$_g"
    elif [ "$can_static" != "1" ]; then
        parity_row "sparc64" "$HOST_TAG" "$_c-interp" "interp" "GAP" 0 "no static runner on this host"
        parity_row "sparc64" "$HOST_TAG" "$_c-dbt" "dbt" "GAP" 0 "no static runner on this host"
        parity_row "sparc64" "$HOST_TAG" "$_c-difftest" "difftest" "GAP" 0 "no static runner on this host"
    else
        emit_engine "$_c" "interp" "static runner"
        emit_engine "$_c" "dbt" "static runner"
        emit_difftest "$_c" "static runner"
    fi
done

if [ ! -f "$GUEST_DIR/guest_p4" ]; then
    parity_row "sparc64" "$HOST_TAG" "p4-interp" "interp" "GAP" 0 "missing guest tests/guests/guest_p4"
    parity_row "sparc64" "$HOST_TAG" "p4-dbt" "dbt" "GAP" 0 "missing guest tests/guests/guest_p4"
elif [ "$can_dyn" != "1" ]; then
    parity_row "sparc64" "$HOST_TAG" "p4-interp" "interp" "GAP" 0 "no dynamic runner (need HL + Linux translator on Darwin)"
    parity_row "sparc64" "$HOST_TAG" "p4-dbt" "dbt" "GAP" 0 "no dynamic runner (need HL + Linux translator on Darwin)"
else
    emit_engine "p4" "interp" "HL/Linux translator (Darwin binary traps on p4)"
    emit_engine "p4" "dbt" "HL/Linux translator (Darwin binary traps on p4)"
fi

if [ ! -f "$GUEST_DIR/guest_p5_dyn" ] || [ ! -f "$GUEST_DIR/libp5.so" ]; then
    parity_row "sparc64" "$HOST_TAG" "p5_dyn-interp" "interp" "GAP" 0 "missing tests/guests/guest_p5_dyn or libp5.so"
    parity_row "sparc64" "$HOST_TAG" "p5_dyn-dbt" "dbt" "GAP" 0 "missing tests/guests/guest_p5_dyn or libp5.so"
elif [ "$can_dyn" != "1" ]; then
    parity_row "sparc64" "$HOST_TAG" "p5_dyn-interp" "interp" "GAP" 0 "no sysroot/dynamic runner"
    parity_row "sparc64" "$HOST_TAG" "p5_dyn-dbt" "dbt" "GAP" 0 "no sysroot/dynamic runner"
else
    emit_engine "p5_dyn" "interp" "dynamic, sysroot"
    emit_engine "p5_dyn" "dbt" "dynamic, sysroot"
fi

if [ ! -f "$GUEST_DIR/busybox" ]; then
    parity_row "sparc64" "$HOST_TAG" "bb-sp-interp" "interp" "GAP" 0 "missing guest tests/guests/busybox"
    parity_row "sparc64" "$HOST_TAG" "bb-sp-dbt" "dbt" "GAP" 0 "missing guest tests/guests/busybox"
    parity_row "sparc64" "$HOST_TAG" "bb-sp-difftest" "difftest" "GAP" 0 "missing guest tests/guests/busybox"
else
    # interp/dbt need only the static runner plus the sysroot that ships
    # the PT_INTERP loader; --difftest additionally needs the HL path.
    if [ "$can_static" = "1" ] && [ -d "$SYSROOT" ]; then
        emit_engine "bb-sp" "interp" "SPARC-only pipe leg"
        emit_engine "bb-sp" "dbt" "SPARC-only pipe leg"
    else
        parity_row "sparc64" "$HOST_TAG" "bb-sp-interp" "interp" "GAP" 0 "no static runner/sysroot"
        parity_row "sparc64" "$HOST_TAG" "bb-sp-dbt" "dbt" "GAP" 0 "no static runner/sysroot"
    fi
    if [ "$can_dyn" = "1" ]; then
        emit_difftest "bb-sp" "SPARC-only pipe leg"
    else
        parity_row "sparc64" "$HOST_TAG" "bb-sp-difftest" "difftest" "GAP" 0 "no HL/dynamic runner for lockstep"
    fi
fi

# --- AOT round-trip reload check (fail-closed contract) ----------------
# Cold run emits into a fresh cache dir, warm run reloads in a fresh
# process; stdout must be identical (and equal the p1 golden), and the
# --stats identity key must be a stable 64-hex digest on both runs.
AOT_DIR="$OUT_DIR/aot-roundtrip"
rm -rf "$AOT_DIR"
mkdir -p "$AOT_DIR"
if [ "$can_static" = "1" ] && [ -f "$GUEST_DIR/guest_p1" ]; then
    _t0=$(parity_now_ms)
    if [ "$STATIC_VIA_HL" = "1" ]; then
        "$HL" "$STATIC_RT" --stats --dbt --cache "$AOT_DIR" "$GUEST_DIR/guest_p1" \
            >"$OUT_DIR/aot-cold.out" 2>"$OUT_DIR/aot-cold.err"
    else
        "$STATIC_RT" --stats --dbt --cache "$AOT_DIR" "$GUEST_DIR/guest_p1" \
            >"$OUT_DIR/aot-cold.out" 2>"$OUT_DIR/aot-cold.err"
    fi
    _crc=$?
    if [ "$STATIC_VIA_HL" = "1" ]; then
        "$HL" "$STATIC_RT" --stats --dbt --cache "$AOT_DIR" "$GUEST_DIR/guest_p1" \
            >"$OUT_DIR/aot-warm.out" 2>"$OUT_DIR/aot-warm.err"
    else
        "$STATIC_RT" --stats --dbt --cache "$AOT_DIR" "$GUEST_DIR/guest_p1" \
            >"$OUT_DIR/aot-warm.out" 2>"$OUT_DIR/aot-warm.err"
    fi
    _wrc=$?
    _t1=$(parity_now_ms)
    _aot_ms="$((_t1 - _t0))"
    _cold_key="$(sed -n 's/.*key=\([0-9a-f]*\).*/\1/p' "$OUT_DIR/aot-cold.err" | head -1)"
    _warm_key="$(sed -n 's/.*key=\([0-9a-f]*\).*/\1/p' "$OUT_DIR/aot-warm.err" | head -1)"
    _cold_reason="$(sed -n 's/.*reason=\([^ ]*\).*/\1/p' "$OUT_DIR/aot-cold.err" | head -1)"
    if [ "$_crc" = "0" ] && [ "$_wrc" = "0" ] && cmp -s "$OUT_DIR/aot-cold.out" "$OUT_DIR/aot-warm.out" \
        && parity_norm_stderr "$OUT_DIR/aot-cold.out" "$OUT_DIR/aot-cold.norm" \
        && { [ ! -f "$GOLDEN_DIR/p1.out" ] || cmp -s "$OUT_DIR/aot-cold.norm" "$GOLDEN_DIR/p1.out"; }; then
        parity_row "sparc64" "$HOST_TAG" "aot-roundtrip-output" "dbt" "PASS" "$_aot_ms" "cold==warm rc=0 (reason=$_cold_reason)"
    else
        parity_row "sparc64" "$HOST_TAG" "aot-roundtrip-output" "dbt" "FAIL" "$_aot_ms" "cold rc=$_crc warm rc=$_wrc"
    fi
    case "$_cold_reason" in
        cache-authority-declined*|backend-not-linked|stored|hit*)
            _reason_ok=1 ;;
        *) _reason_ok=0 ;;
    esac
    if [ -n "$_cold_key" ] && [ "$_cold_key" = "$_warm_key" ] \
        && printf '%s' "$_cold_key" | grep -qE '^[0-9a-f]{64}$' && [ "$_reason_ok" = "1" ]; then
        parity_row "sparc64" "$HOST_TAG" "aot-roundtrip-key" "dbt" "PASS" 0 "stable key ${_cold_key} (reason=$_cold_reason)"
    else
        parity_row "sparc64" "$HOST_TAG" "aot-roundtrip-key" "dbt" "FAIL" 0 "cold=[$_cold_key] warm=[$_warm_key] reason=[$_cold_reason]"
    fi
else
    parity_row "sparc64" "$HOST_TAG" "aot-roundtrip-output" "dbt" "GAP" 0 "no static runner"
    parity_row "sparc64" "$HOST_TAG" "aot-roundtrip-key" "dbt" "GAP" 0 "no static runner"
fi

parity_summary
