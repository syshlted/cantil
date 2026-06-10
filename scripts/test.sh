#!/bin/sh
# Build and run a ztest suite on native_sim.
#
# Usage:
#   ./scripts/test.sh                       # run every suite under firmware/tests/
#   ./scripts/test.sh noise_session         # run one named suite
#   ./scripts/test.sh noise_crypto noise_session
#
# Each suite is a directory under firmware/tests/.  native_sim builds need
# the host toolchain (not gnuarmemb) and --no-sysbuild (sysbuild's NCS
# overlay injects partition-manager Kconfigs that don't apply to native_sim).
#
# Run from inside the ubuntu2604 distrobox, or wrap with ./scripts/dbox.sh.

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
TESTS_DIR="$PROJECT_ROOT/firmware/tests"
NCS_DIR="$HOME/ncs/v3.0.2"

if [ ! -d "$NCS_DIR/.west" ]; then
    echo "error: NCS workspace not found at $NCS_DIR" >&2
    exit 1
fi

if [ $# -eq 0 ]; then
    set -- $(cd "$TESTS_DIR" && ls -d */ | sed 's|/||')
fi

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

    echo "════════════════════════════════════════════════════════════════"
    echo "── Building $suite"
    echo "════════════════════════════════════════════════════════════════"
    (cd "$NCS_DIR" && west build -p --no-sysbuild -b native_sim \
        --source-dir "$src" -d "$build")

    elf="$build/zephyr/zephyr.exe"
    if [ ! -x "$elf" ]; then
        echo "error: missing $elf after build" >&2
        rc=1
        continue
    fi

    echo
    echo "── Running $suite"
    if ! "$elf"; then
        echo "FAIL: $suite" >&2
        rc=1
    fi
done

exit $rc
