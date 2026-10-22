#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Build and run the ztest suites on native_sim.
#
# Usage:
#   ./scripts/test.sh                       # run every suite under firmware/tests/
#   ./scripts/test.sh noise_session         # run one named suite
#   ./scripts/test.sh noise_crypto noise_session
#   ./scripts/test.sh --cmake               # legacy CMake/west runner
#
# Runs under Bazel by default — no workspace, no toolchain bundle, no setup:
#
#   bazelisk test //firmware/tests/... --config=sim
#
# plus, on a full run, //scripts:pin_agreement_test under --config=host: the
# assertion that firmware/west.yml and MODULE.bazel still pin the same tree, so
# the --cmake reference build keeps being a reference.
#
# That covers both halves of what this script used to do by hand. The suites
# themselves run on native_sim/native/64, and the four suites that mint DER
# (sign_csr, ca_bootstrap, crl_der, session_slot) additionally run
# <suite>_openssl_gate, which re-runs the binary with CANTIL_TEST_ARTIFACT_DIR
# set and checks what it wrote with scripts/openssl_gate.sh — a third
# implementation, and the only thing that catches a writer and a reader from
# the same library agreeing on wrong DER.
#
# --cmake keeps the old west path as the reference runner. It needs
# ./scripts/setup_zephyr.sh once; the Bazel path needs nothing.
#
# Environment (--cmake path only):
#   CANTIL_ZEPHYR_WS        Workspace location (default: $HOME/zephyr/cantil)
#   CANTIL_NCS_TOOLCHAIN    Host-tool bundle
#   CANTIL_TEST_BOARD       Board (default: native_sim/native/64)

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
TESTS_DIR="$PROJECT_ROOT/firmware/tests"
ZEPHYR_WS="${CANTIL_ZEPHYR_WS:-$HOME/zephyr/cantil}"
TC_DIR="${CANTIL_NCS_TOOLCHAIN:-$HOME/ncs/toolchains/7cbc0036f4}"
BAZEL="${CANTIL_BAZEL:-bazelisk}"

# native_sim/native/64, not plain native_sim: the default native_sim target is
# a 32-bit build, which needs 32-bit glibc headers (gnu/stubs-32.h, from
# glibc-devel.i686) that a stock Fedora host does not carry.  The 64-bit
# variant builds against the headers already present.  Nothing under
# firmware/tests/ is width-sensitive.
TEST_BOARD="${CANTIL_TEST_BOARD:-native_sim/native/64}"

USE_CMAKE=0
SUITES=""
for arg in "$@"; do
    case "$arg" in
        --cmake) USE_CMAKE=1 ;;
        -*) echo "Unknown option: $arg" >&2; exit 1 ;;
        *) SUITES="$SUITES $arg" ;;
    esac
done
# shellcheck disable=SC2086
set -- $SUITES

# ════════════════════════════════════════════════════════════════════════════
# Bazel path (default)
# ════════════════════════════════════════════════════════════════════════════
if [ "$USE_CMAKE" = "0" ]; then
    if ! command -v "$BAZEL" >/dev/null 2>&1; then
        echo "error: $BAZEL not found on PATH" >&2
        echo "  Install bazelisk, or set CANTIL_BAZEL, or use --cmake." >&2
        exit 1
    fi

    RUN_ALL=0
    if [ $# -eq 0 ]; then
        RUN_ALL=1
        set -- "//firmware/tests/..."
    else
        # A named suite means "everything in that package" — the suite itself
        # and, where it exists, its OpenSSL gate.
        targets=""
        for suite in "$@"; do
            if [ ! -d "$TESTS_DIR/$suite" ]; then
                echo "error: no such suite: $suite" >&2
                exit 1
            fi
            targets="$targets //firmware/tests/$suite:all"
        done
        # shellcheck disable=SC2086
        set -- $targets
    fi

    cd "$PROJECT_ROOT"
    echo "── bazel test $* --config=sim"
    "$BAZEL" test "$@" --config=sim || exit $?

    # The pin-agreement check is a plain host text comparison — no Zephyr, no
    # platform — so it cannot run in the --config=sim invocation above, whose
    # target platform is native_sim. Run it separately, and only on a full run:
    # asking for one named suite means the caller is iterating on that suite.
    if [ "$RUN_ALL" = "1" ]; then
        echo
        echo "── bazel test //scripts:pin_agreement_test --config=host"
        "$BAZEL" test //scripts:pin_agreement_test --config=host || exit $?
    fi
    exit 0
fi

# ════════════════════════════════════════════════════════════════════════════
# CMake/west path (--cmake), the reference runner
# ════════════════════════════════════════════════════════════════════════════
if [ ! -d "$ZEPHYR_WS/.west" ]; then
    echo "error: Zephyr workspace not found at $ZEPHYR_WS" >&2
    echo "Run: ./scripts/setup_zephyr.sh  (needed only for the --cmake path)" >&2
    exit 1
fi

if [ $# -eq 0 ]; then
    # Auto-discovery takes only directories that are actually ztest suites.
    # firmware/tests/ also holds non-suite material (hardware/ carries
    # devicetree overlays for on-device testing), and treating those as failed
    # suites made this script exit non-zero on a fully green run — an exit
    # code that is always red is an exit code nobody reads. An explicitly
    # named suite with no CMakeLists.txt is still an error below, because
    # there the user asserted it was a suite.
    set -- $(cd "$TESTS_DIR" && for d in */; do
        [ -f "${d}CMakeLists.txt" ] && printf '%s\n' "${d%/}"
    done)
fi

# Same host-tool setup as build.sh --cmake: bundle cmake/ninja/west/python,
# host git shimmed ahead of the bundle's (see setup_zephyr.sh).  No Zephyr SDK
# here — native_sim links against the host compiler.
GIT_SHIM="$PROJECT_ROOT/build/.host-git-shim"
mkdir -p "$GIT_SHIM"
ln -sf /usr/bin/git "$GIT_SHIM/git"

export PATH="$GIT_SHIM:$TC_DIR/usr/local/bin:$TC_DIR/usr/bin:$PROJECT_ROOT/venv/bin:/usr/local/bin:/usr/bin:$PATH"
export LD_LIBRARY_PATH="$TC_DIR/usr/local/lib:$TC_DIR/usr/lib:${LD_LIBRARY_PATH:-}"
export ZEPHYR_TOOLCHAIN_VARIANT=host

rc=0
for suite in "$@"; do
    src="$TESTS_DIR/$suite"
    build="$PROJECT_ROOT/build_$suite"

    if [ ! -f "$src/CMakeLists.txt" ]; then
        echo "error: no CMakeLists.txt under $src" >&2
        rc=1
        continue
    fi

    # Each suite carries its flash layout in boards/native_sim.overlay (the
    # stock native_sim storage_partition is 16 KB, far too small for the slot
    # blobs).  Zephyr auto-discovers a board overlay only under the fully
    # normalised target name, so that file is picked up for `native_sim` but
    # not for `native_sim/native/64` — which would silently fall back to the
    # 16 KB default and fail deep inside LittleFS with ENOSPC rather than at
    # configure time.  Pass it explicitly, and only when auto-discovery would
    # not already have applied it (applying it twice re-runs its
    # /delete-node/ directives against nodes that are already gone).
    OVERLAY_ARG=""
    if [ "$TEST_BOARD" != "native_sim" ] && [ -f "$src/boards/native_sim.overlay" ]; then
        OVERLAY_ARG="-DEXTRA_DTC_OVERLAY_FILE=$src/boards/native_sim.overlay"
    fi

    echo "════════════════════════════════════════════════════════════════"
    echo "── Building $suite"
    echo "════════════════════════════════════════════════════════════════"
    (cd "$ZEPHYR_WS" && west build -p --no-sysbuild -b "$TEST_BOARD" \
        --source-dir "$src" -d "$build" \
        ${OVERLAY_ARG:+-- $OVERLAY_ARG})

    elf="$build/zephyr/zephyr.exe"
    if [ ! -x "$elf" ]; then
        echo "error: missing $elf after build" >&2
        rc=1
        continue
    fi

    # Artifacts the suite generates for the OpenSSL gate. Exported so the
    # test binary knows where to write; wiped first so a stale file from a
    # previous run cannot pass a gate for code that no longer produces it.
    CANTIL_TEST_ARTIFACT_DIR="$build/artifacts"
    export CANTIL_TEST_ARTIFACT_DIR
    rm -rf "$CANTIL_TEST_ARTIFACT_DIR"
    mkdir -p "$CANTIL_TEST_ARTIFACT_DIR"

    echo
    echo "── Running $suite"
    suite_failed=0
    if ! "$elf"; then
        echo "FAIL: $suite (ztest)" >&2
        rc=1
        suite_failed=1
    fi

    # Independent oracle for anything this suite generated. Runs even when the
    # suite's own assertions passed — that is the entire point: the suite and
    # the code under test can share a misunderstanding of DER, and only a third
    # implementation notices. See scripts/openssl_gate.sh. The Bazel path runs
    # the same script from <suite>_openssl_gate.
    if ! "$SCRIPT_DIR/openssl_gate.sh" "$CANTIL_TEST_ARTIFACT_DIR"; then
        echo "FAIL: $suite (OpenSSL gate — ztest passed but the generated" >&2
        echo "      DER was rejected by an independent implementation)" >&2
        rc=1
        suite_failed=1
    fi

    [ "$suite_failed" -eq 0 ] && echo "PASS: $suite"
done

# A non-zero exit with nothing reported above is itself a defect: an exit code
# that is red for reasons nobody printed is an exit code nobody trusts. Every
# path that sets rc=1 above prints a FAIL line first.
if [ "$rc" -ne 0 ]; then
    echo >&2
    echo "════════════════════════════════════════════════════════════════" >&2
    echo "One or more suites FAILED — see the FAIL lines above." >&2
    echo "════════════════════════════════════════════════════════════════" >&2
fi

exit $rc
