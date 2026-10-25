#!/bin/sh
# tests/check_host_contract.sh — Phase 6 L6a host-contract probe.
#
# Asserts the HOST-CONTRACT.md section 3.2 CLI/env table (both spellings,
# CLI-over-env, unknown flags fail hard), --image-fd / AT_EXECFD hygiene
# per section 3.1, the three fail-closed authority policies, AOT cache
# identity (translator digest binds keys; dynamic PT_INTERP binds both
# file digests), family broker naming/sequence, and --stats counters.
#
# Two legs, one script:
#   MODE=direct  run "$RT" natively (AArch64 Linux container):
#     docker run --rm --platform linux/arm64 -v "$PWD:/w" -w /w \
#       <toolchain-image> sh /w/tests/check_host_contract.sh
#   MODE=hl      drive the same binary through hl (macOS host):
#     MODE=hl HL=../hyper-linux/_build/hl sh tests/check_host_contract.sh
#
# Inputs: RT (default _build/sparc64rt), HL, SYSROOT override, GUEST_DIR
# (prebuilt probe guests for MODE=hl, default _build/l6a). The direct leg
# builds the probe guests with sparc64-linux-gnu-gcc when available.
# Ends with L6A-HOST-PASS on success.

set -u

RT=${RT:-_build/sparc64rt}
MODE=${MODE:-direct}
HL=${HL:-../hyper-linux/_build/hl}
GUEST_DIR=${GUEST_DIR:-_build/l6a}
SYSROOT_OVERRIDE=${SYSROOT_OVERRIDE:-}

pass=0
fail=0

ok() {
    pass=$((pass + 1))
    echo "PASS: $1"
}

no() {
    fail=$((fail + 1))
    echo "FAIL: $1"
}

# run_tr <args...> — invoke the translator for the current leg.
run_tr() {
    if [ "$MODE" = "hl" ]; then
        "$HL" -- "$RT" "$@"
    else
        "$RT" "$@"
    fi
}

# expect_exit <want> <label> <args...> — exact exit code match.
expect_exit() {
    want=$1
    label=$2
    shift 2
    out_file=$TMPD/exit.out
    err_file=$TMPD/exit.err
    set +e
    run_tr "$@" >"$out_file" 2>"$err_file"
    code=$?
    set -e
    if [ "$code" = "$want" ]; then
        ok="$label (exit=$code)"
        ok "$ok"
    else
        no "$label (want exit=$want got=$code: $(cat "$err_file" | head -c 300))"
    fi
}

# expect_grep <file> <pattern> <label>
expect_grep() {
    if grep -q "$2" "$1" 2>/dev/null; then
        ok "$3"
    else
        no "$3 (pattern '$2' not in $(head -c 300 "$1"))"
    fi
}

TMPD=
cleanup() {
    if [ -n "$TMPD" ] && [ -d "$TMPD" ]; then
        rm -rf "$TMPD"
    fi
}
trap cleanup EXIT INT TERM
TMPD=$(mktemp -d)

if [ ! -x "$RT" ] && [ "$MODE" = "direct" ]; then
    echo "FAIL: translator missing: $RT (run make build first)"
    exit 1
fi

echo "== L6a host-contract probe (mode=$MODE rt=$RT) =="

# ---- A. CLI basics -------------------------------------------------------
expect_exit 0 "help" --help
expect_grep "$TMPD/exit.out" "Usage" "help text"
expect_exit 0 "version" --version
expect_grep "$TMPD/exit.out" "sparc64rt" "version text"
expect_exit 2 "unknown long flag fails hard" --nope-nope
expect_grep "$TMPD/exit.err" "unknown option" "unknown-flag diagnostic"
expect_exit 2 "single unknown --engine value" --engine=bogus
expect_exit 2 "no guest image" --interp
expect_exit 2 "empty --sysroot" --sysroot "" -- /bin/false

# ---- B. engine selection --------------------------------------------------
set +e
SPARC64RT_ENGINE=bogus run_tr --help >"$TMPD/exit.out" 2>"$TMPD/exit.err"
code=$?
set -e
if [ "$code" = 2 ]; then ok "bad SPARC64RT_ENGINE fails (exit=2)"; else no "bad SPARC64RT_ENGINE (want 2 got $code)"; fi
expect_grep "$TMPD/exit.err" "unknown SPARC64RT_ENGINE" "bad-engine diagnostic"
expect_exit 2 "conflicting --interp --dbt" --interp --dbt -- /bin/false
expect_exit 2 "conflicting --engine + --dbt" --engine interp --dbt -- /bin/false
expect_exit 2 "duplicate --engine" --engine interp --engine dbt -- /bin/false
expect_exit 2 "--engine jit rejected" --engine jit -- /bin/false
expect_exit 2 "duplicate --sysroot spellings" --sysroot /a --rootfs /b -- /bin/false
expect_exit 2 "duplicate --cache spellings" --cache /a --cache-dir /b -- /bin/false
expect_exit 2 "duplicate --stats" --stats --stats -- /bin/false

# ---- C. authority fail-closed ----------------------------------------------
expect_exit 2 "cache-authority hl fail-closed" \
    --cache-authority hyper-linux-apfs-acl-v1 -- /bin/false
expect_grep "$TMPD/exit.err" "fail-closed" "cache-authority diagnostic"
expect_exit 2 "cache-authority hl (=) fail-closed" \
    --cache-authority=hyper-linux-apfs-acl-v1 -- /bin/false
expect_exit 2 "file-identity hl fail-closed" \
    --file-identity hyper-linux-apfs-v1 -- /bin/false
expect_grep "$TMPD/exit.err" "fail-closed" "file-identity diagnostic"
expect_exit 2 "file-identity hl (=) fail-closed" \
    --file-identity=hyper-linux-apfs-v1 -- /bin/false
expect_exit 2 "family-authority hl fail-closed" \
    --family-authority hyper-linux-apfs-acl-v1 -- /bin/false
expect_grep "$TMPD/exit.err" "fail-closed" "family-authority diagnostic"
expect_exit 2 "family-authority hl (=) fail-closed" \
    --family-authority=hyper-linux-apfs-acl-v1 -- /bin/false
expect_exit 2 "bad cache-authority value" --cache-authority bogus -- /bin/false
expect_exit 2 "bad file-identity value" --file-identity bogus -- /bin/false
expect_exit 2 "bad family-authority value" --family-authority bogus -- /bin/false

# ---- D. descriptor validation (no guest needed) ----------------------------
expect_exit 1 "closed --image-fd rejected" --image-fd 9 -- /bin/false
expect_grep "$TMPD/exit.err" "invalid executable descriptor" "closed-fd diagnostic"
expect_exit 1 "--image-fd 2 rejected" --image-fd 2 -- /bin/false
expect_exit 2 "non-numeric --image-fd" --image-fd xyz -- /bin/false
expect_exit 2 "duplicate --image-fd" --image-fd 3 --image-fd 3 -- /bin/false

# ---- E. probe guests --------------------------------------------------------
# probe_static: static glibc SPARC guest reporting argv0, /proc/self/exe
# and AT_EXECFN. hello_dyn: dynamic glibc guest for the sysroot matrix.
mkdir -p "$GUEST_DIR"
PROBE_C=$GUEST_DIR/probe_src.c
HELLO_C=$GUEST_DIR/hello_src.c
PROBE_S=$GUEST_DIR/probe_static
HELLO_D=$GUEST_DIR/hello_dyn
cat >"$PROBE_C" <<'EOF'
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/auxv.h>
#ifndef AT_EXECFN
#define AT_EXECFN 31
#endif
int main(int argc, char **argv)
{
    char exe[4096];
    ssize_t n = readlink("/proc/self/exe", exe, sizeof(exe) - 1);
    unsigned long ef;
    printf("ARGV0=%s\n", (argc > 0 && argv[0] != 0) ? argv[0] : "(none)");
    printf("ARGC=%d\n", argc);
    if (n < 0) {
        printf("EXE=unavailable:%d\n", errno);
    } else {
        exe[n] = '\0';
        printf("EXE=%s\n", exe);
    }
    errno = 0;
    ef = getauxval(AT_EXECFN);
    if (ef == 0 && errno != 0) {
        printf("EXECFN=(none)\n");
    } else {
        printf("EXECFN=%s\n", (const char *)ef);
    }
    return 0;
}
EOF
cat >"$HELLO_C" <<'EOF'
#include <stdio.h>
int main(void)
{
    printf("HELLO-DYN\n");
    return 0;
}
EOF
if command -v sparc64-linux-gnu-gcc >/dev/null 2>&1; then
    if sparc64-linux-gnu-gcc -static -O2 -o "$PROBE_S" "$PROBE_C" 2>"$TMPD/build.err"; then
        ok "built probe_static"
    else
        no "build probe_static ($(head -c 200 "$TMPD/build.err"))"
    fi
    if sparc64-linux-gnu-gcc -O2 -o "$HELLO_D" "$HELLO_C" 2>"$TMPD/build.err"; then
        ok "built hello_dyn"
    else
        no "build hello_dyn ($(head -c 200 "$TMPD/build.err"))"
    fi
    # Sysroot tree for both legs: copy the cross lib trees so absolute
    # guest paths (PT_INTERP, libc) resolve under $GUEST_DIR/sysroot.
    SYSROOT_SRC=/usr/sparc64-linux-gnu
    if [ ! -x "$PROBE_S" ] || [ ! -x "$HELLO_D" ]; then
        no "guest build failed, cannot continue run matrix"
    elif [ -d "$SYSROOT_SRC/lib" ]; then
        rm -rf "$GUEST_DIR/sysroot"
        mkdir -p "$GUEST_DIR/sysroot"
        cp -a "$SYSROOT_SRC/lib" "$GUEST_DIR/sysroot/" 2>/dev/null || \
            no "sysroot lib copy"
        if [ -d "$SYSROOT_SRC/lib64" ]; then
            cp -a "$SYSROOT_SRC/lib64" "$GUEST_DIR/sysroot/" 2>/dev/null || \
                no "sysroot lib64 copy"
        fi
        ok "staged sysroot"
    else
        no "cross sysroot missing ($SYSROOT_SRC/lib)"
    fi
else
    if [ ! -x "$PROBE_S" ] || [ ! -x "$HELLO_D" ]; then
        no "no toolchain and no prebuilt guests in $GUEST_DIR"
    else
        ok "using prebuilt guests"
    fi
fi
if [ -n "$SYSROOT_OVERRIDE" ]; then
    SYSROOT=$SYSROOT_OVERRIDE
else
    SYSROOT=$GUEST_DIR/sysroot
fi
if [ ! -x "$PROBE_S" ] || [ ! -x "$HELLO_D" ]; then
    echo "FAIL: missing probe guests, aborting run matrix"
    exit 1
fi

# run_cap <prefix> <args...> — run, save stdout/stderr, set RUN_CODE.
run_cap() {
    prefix=$1
    shift
    set +e
    run_tr "$@" >"$TMPD/$prefix.out" 2>"$TMPD/$prefix.err"
    RUN_CODE=$?
    set -e
}

ABS_PROBE=$(cd "$(dirname "$PROBE_S")" && pwd || true)/$(basename "$PROBE_S")

# ---- F. static run matrix ----------------------------------------------------
run_cap static_plain -- "$PROBE_S" hello
[ "$RUN_CODE" = 0 ] && ok "static plain run (exit=0)" || no "static plain run (exit=$RUN_CODE)"
expect_grep "$TMPD/static_plain.out" "ARGV0=$PROBE_S" "argv0 defaults to path"
run_cap static_dbt --dbt -- "$PROBE_S" hello
[ "$RUN_CODE" = 0 ] && ok "static dbt run (exit=0)" || no "static dbt run (exit=$RUN_CODE)"
run_cap static_diff --difftest -- "$PROBE_S" hello
[ "$RUN_CODE" = 0 ] && ok "static difftest run (exit=0)" || no "static difftest run (exit=$RUN_CODE)"
run_cap static_argv -- "$PROBE_S" custom0 extra
expect_grep "$TMPD/static_argv.out" "ARGV0=$PROBE_S" "no-execfn argv0 is path"
run_cap static_stats --stats -- "$PROBE_S" hello
expect_grep "$TMPD/static_stats.err" "sparc64rt: stats engine=interp exit=0" "stats line"
expect_grep "$TMPD/static_stats.err" "guest_syscalls=[1-9]" "stats counts dispatches"
set +e
SPARC64RT_STATS=1 run_tr -- "$PROBE_S" hello >"$TMPD/env_stats.out" 2>"$TMPD/env_stats.err"
code=$?
set -e
[ "$code" = 0 ] && expect_grep "$TMPD/env_stats.err" "sparc64rt: stats " "STATS env spelling" || \
    no "STATS env run (exit=$code)"
run_cap static_eng_env --stats -- "$PROBE_S" hello
expect_grep "$TMPD/static_eng_env.err" "engine=interp" "default engine interp"
set +e
SPARC64RT_ENGINE=dbt run_tr --stats -- "$PROBE_S" hello >"$TMPD/eng_db.out" 2>"$TMPD/eng_db.err"
code=$?
set -e
[ "$code" = 0 ] && expect_grep "$TMPD/eng_db.err" "engine=dbt" "ENGINE env spelling" || \
    no "ENGINE env run (exit=$code)"
set +e
SPARC64RT_ENGINE=interp run_tr --stats --dbt -- "$PROBE_S" hello >"$TMPD/eng_cli.out" 2>"$TMPD/eng_cli.err"
code=$?
set -e
[ "$code" = 0 ] && expect_grep "$TMPD/eng_cli.err" "engine=dbt" "CLI engine overrides env" || \
    no "CLI-over-env engine (exit=$code)"
expect_exit 2 "--engine=dbt conflicts with --interp" --engine=dbt --interp -- "$PROBE_S"

# ---- G. --execfn decoupling ---------------------------------------------------
run_cap execfn --execfn "$ABS_PROBE" -- custom0 extra
[ "$RUN_CODE" = 0 ] && ok "execfn run (exit=0)" || no "execfn run (exit=$RUN_CODE)"
expect_grep "$TMPD/execfn.out" "ARGV0=custom0" "execfn preserves custom argv0"
expect_grep "$TMPD/execfn.out" "EXE=$ABS_PROBE" "execfn sets /proc/self/exe"
expect_grep "$TMPD/execfn.out" "EXECFN=$ABS_PROBE" "execfn overrides AT_EXECFN"
run_cap execfn_bare --execfn "$ABS_PROBE" --
[ "$RUN_CODE" = 0 ] && ok "execfn bare run (exit=0)" || no "execfn bare run (exit=$RUN_CODE)"
expect_grep "$TMPD/execfn_bare.out" "ARGV0=$ABS_PROBE" "bare execfn synthesizes argv0"
set +e
SPARC64RT_EXECFN="$ABS_PROBE" run_tr -- custom0 >"$TMPD/execfn_env.out" 2>"$TMPD/execfn_env.err"
code=$?
set -e
[ "$code" = 0 ] && expect_grep "$TMPD/execfn_env.out" "ARGV0=custom0" "EXECFN env spelling" || \
    no "EXECFN env run (exit=$code)"
expect_grep "$TMPD/execfn_env.out" "EXECFN=$ABS_PROBE" "EXECFN env sets AT_EXECFN"

# ---- H. --image-fd positives ----------------------------------------------------
set +e
run_tr --image-fd 3 -- "$PROBE_S" fromfd 3<"$PROBE_S" >"$TMPD/imagefd.out" 2>"$TMPD/imagefd.err"
code=$?
set -e
[ "$code" = 0 ] && ok "image-fd run (exit=0)" || no "image-fd run (exit=$code: $(head -c 200 "$TMPD/imagefd.err"))"
expect_grep "$TMPD/imagefd.out" "ARGV0=$PROBE_S" "image-fd keeps argv0 spelling"
set +e
run_tr --image-fd 0 -- "$PROBE_S" fromstdin <"$PROBE_S" >"$TMPD/fd0.out" 2>"$TMPD/fd0.err"
code=$?
set -e
[ "$code" = 0 ] && ok "image-fd 0 with image on stdin (exit=0)" || \
    no "image-fd 0 run (exit=$code: $(head -c 200 "$TMPD/fd0.err"))"
set +e
run_tr --image-fd 0 -- "$PROBE_S" closedstdin 0<&- >"$TMPD/fd0c.out" 2>"$TMPD/fd0c.err"
code=$?
set -e
[ "$code" = 1 ] && expect_grep "$TMPD/fd0c.err" "invalid executable descriptor" \
    "closed stdin fd 0 rejected" || no "closed-stdin fd 0 (want exit=1 got=$code)"

# ---- I. sysroot matrix (dynamic guest) -------------------------------------------
set +e
SPARC64RT_SYSROOT= SPARC64RT_ROOTFS= run_tr -- "$HELLO_D" >"$TMPD/dyn_nosys.out" 2>"$TMPD/dyn_nosys.err"
code=$?
set -e
if [ "$code" != 0 ]; then ok "dynamic without sysroot fails (exit=$code)"; else
    no "dynamic without sysroot unexpectedly ran"
fi
run_cap dyn_sysroot --sysroot "$SYSROOT" -- "$HELLO_D"
[ "$RUN_CODE" = 0 ] && ok "dynamic --sysroot run (exit=0)" || \
    no "dynamic --sysroot run (exit=$RUN_CODE: $(head -c 200 "$TMPD/dyn_sysroot.err"))"
expect_grep "$TMPD/dyn_sysroot.out" "HELLO-DYN" "dynamic guest output"
run_cap dyn_rootfs --rootfs "$SYSROOT" -- "$HELLO_D"
[ "$RUN_CODE" = 0 ] && ok "dynamic --rootfs run (exit=0)" || no "dynamic --rootfs run (exit=$RUN_CODE)"
set +e
SPARC64RT_SYSROOT="$SYSROOT" run_tr -- "$HELLO_D" >"$TMPD/dyn_env.out" 2>"$TMPD/dyn_env.err"
code=$?
set -e
[ "$code" = 0 ] && ok "SYSROOT env spelling (exit=0)" || no "SYSROOT env run (exit=$code)"
set +e
SPARC64RT_ROOTFS="$SYSROOT" run_tr -- "$HELLO_D" >"$TMPD/dyn_env2.out" 2>"$TMPD/dyn_env2.err"
code=$?
set -e
[ "$code" = 0 ] && ok "ROOTFS env spelling (exit=0)" || no "ROOTFS env run (exit=$code)"
set +e
SPARC64RT_SYSROOT=/nonexistent-sysroot run_tr --sysroot "$SYSROOT" -- "$HELLO_D" \
    >"$TMPD/dyn_cli.out" 2>"$TMPD/dyn_cli.err"
code=$?
set -e
[ "$code" = 0 ] && ok "CLI sysroot overrides bogus env (exit=0)" || \
    no "CLI-over-env sysroot (exit=$code: $(head -c 200 "$TMPD/dyn_cli.err"))"
set +e
SPARC64RT_ROOTFS="$SYSROOT" run_tr --stats -- "$HELLO_D" >"$TMPD/dyn_rf.out" 2>"$TMPD/dyn_rf.err"
code=$?
set -e
[ "$code" = 0 ] && expect_grep "$TMPD/dyn_rf.err" "sysroot=$SYSROOT" \
    "stats reports sysroot" || no "ROOTFS-only stats sysroot (exit=$code)"

# ---- J. cache identity ---------------------------------------------------------------
CACHE_FS=$GUEST_DIR/cache-fs
CACHE_TMP=$(mktemp -d /dev/shm/l6a-cache-XXXXXX 2>/dev/null || mktemp -d)
mkdir -p "$CACHE_FS"
run_cap cache_fs --cache "$CACHE_FS" --stats -- "$PROBE_S" hello
[ "$RUN_CODE" = 0 ] && ok "cache-dir run still executes (exit=0)" || no "cache-dir run (exit=$RUN_CODE)"
expect_grep "$TMPD/cache_fs.err" "cache=declined" "bind-mount cache declines with reason"
run_cap cache_tmp --cache-dir "$CACHE_TMP" --stats -- "$PROBE_S" hello
expect_grep "$TMPD/cache_tmp.err" "cache=declined reason=" "admission reports a reason"
# Portable verdict: admitted (backend boundary) or host-declined with the
# filesystem named. Both prove the auto gate ran; the key below must exist
# either way.
if grep -Eq "reason=(backend-not-linked|cache-authority-declined:.+)" "$TMPD/cache_tmp.err"; then
    ok "admission verdict is host-exact ($(grep -o "reason=[^ ]*" "$TMPD/cache_tmp.err" | head -1 || true))"
else
    no "admission verdict ($(grep -o "reason=[^ ]*" "$TMPD/cache_tmp.err" | head -1 || true))"
fi
expect_grep "$TMPD/cache_tmp.err" "key=[0-9a-f]\\{64\\}" "cache key is full sha256"
expect_grep "$TMPD/cache_tmp.err" "interp=no" "static guest binds no interp"
KEY_ONE=$(grep -o "key=[0-9a-f]*" "$TMPD/cache_tmp.err" | head -1 || true)
run_cap cache_tmp2 --cache-dir "$CACHE_TMP" --stats -- "$PROBE_S" hello
KEY_TWO=$(grep -o "key=[0-9a-f]*" "$TMPD/cache_tmp2.err" | head -1 || true)
if [ -n "$KEY_ONE" ] && [ "$KEY_ONE" = "$KEY_TWO" ]; then
    ok "cache key deterministic ($KEY_ONE)"
else
    no "cache key determinism ($KEY_ONE vs $KEY_TWO)"
fi
TRANS_ONE=$(grep -o "translator=[0-9a-f]*" "$TMPD/cache_tmp.err" | head -1 || true)
if [ -n "$TRANS_ONE" ]; then ok "translator digest in stats ($TRANS_ONE)"; else no "translator digest in stats"; fi
run_cap cache_dyn --cache-dir "$CACHE_TMP" --sysroot "$SYSROOT" --stats -- "$HELLO_D"
[ "$RUN_CODE" = 0 ] && ok "dynamic cached run (exit=0)" || no "dynamic cached run (exit=$RUN_CODE)"
expect_grep "$TMPD/cache_dyn.err" "interp=yes" "dynamic binds PT_INTERP identity"
KEY_DYN=$(grep -o "key=[0-9a-f]*" "$TMPD/cache_dyn.err" | head -1 || true)
if [ -n "$KEY_DYN" ] && [ "$KEY_DYN" != "$KEY_ONE" ]; then
    ok "dynamic key differs from static key"
else
    no "dynamic/static key separation ($KEY_DYN vs $KEY_ONE)"
fi
set +e
SPARC64RT_CACHE="$CACHE_TMP" run_tr --stats -- "$PROBE_S" hello >"$TMPD/cache_env.out" 2>"$TMPD/cache_env.err"
code=$?
set -e
[ "$code" = 0 ] && expect_grep "$TMPD/cache_env.err" "cache=declined reason=" \
    "CACHE env spelling" || no "CACHE env run (exit=$code)"
set +e
SPARC64RT_CACHE_DIR="$CACHE_TMP" run_tr --stats -- "$PROBE_S" hello >"$TMPD/cache_env2.out" 2>"$TMPD/cache_env2.err"
code=$?
set -e
[ "$code" = 0 ] && expect_grep "$TMPD/cache_env2.err" "cache=declined reason=" \
    "CACHE_DIR env spelling" || no "CACHE_DIR env run (exit=$code)"
rm -rf "$CACHE_TMP"

# ---- K. selftest + family --------------------------------------------------------------
run_cap selftest --selftest-host
[ "$RUN_CODE" = 0 ] && ok "selftest-host (exit=0)" || no "selftest-host (exit=$RUN_CODE)"
expect_grep "$TMPD/selftest.out" "sparc64rt: selftest PASS" "selftest PASS"
if [ "$MODE" = "hl" ]; then
    # hl serves no /proc/self/auxv; the skip is the documented host shape
    # (getauxval probing still runs; the fd-0 cases above exercise it).
    expect_grep "$TMPD/selftest.out" "auxv=skip reason=no-proc-auxv" "hl auxv shape"
    expect_grep "$TMPD/selftest.out" "selftest host=hyper-linux" "hl host detection"
    expect_grep "$TMPD/selftest.out" "authorized-by-host" "hl ACL facade reported"
else
    expect_grep "$TMPD/selftest.out" "selftest auxv=ok" "auxv/AT_EXECFD consistency"
    expect_grep "$TMPD/selftest.out" "hyper-linux-apfs-acl-v1=fail-closed" "authority matrix"
fi
expect_grep "$TMPD/selftest.out" "selftest translator-digest=" "translator digest"
expect_grep "$TMPD/selftest.out" "selftest file-identity=ok" "file identity query"
expect_grep "$TMPD/selftest.out" "family=ok sequence-step=1 cleaned-up=yes" "family broker verify"
SELF_DIGEST=$(grep -o "selftest translator-digest=[0-9a-f]*" "$TMPD/selftest.out" | head -1 | cut -d= -f2 || true)
STAT_TRANS=$(echo "$TRANS_ONE" | cut -d= -f2 || true)
if [ -n "$SELF_DIGEST" ] && [ "$SELF_DIGEST" = "$(echo "$STAT_TRANS" | cut -c1-16)" ]; then
    ok "stats translator matches selftest digest"
else
    no "digest agreement (selftest=$SELF_DIGEST stats=$STAT_TRANS)"
fi
if [ "$MODE" != "hl" ]; then
    expect_grep "$TMPD/selftest.out" "execfd-present=0" "no AT_EXECFD on plain launch"
fi

echo "== pass=$pass fail=$fail =="
if [ "$fail" = 0 ]; then
    echo L6A-HOST-PASS
    exit 0
else
    exit 1
fi
