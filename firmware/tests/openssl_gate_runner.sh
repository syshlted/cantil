#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Bazel test wrapper: run one native_sim ztest suite with an artifact directory
# set, then hand what it emitted to scripts/openssl_gate.sh.
#
# This is the Bazel half of what scripts/test.sh has always done on the CMake
# path. The gate is the independent oracle for everything Cantil *generates* —
# a suite that mints certificates cannot be its own judge, because the writer
# and the reader come from the same library and share any misunderstanding of
# DER between them. Until this existed, `bazel test` was strictly weaker than
# `scripts/test.sh` and CMake could not be retired.
#
# Usage (supplied by the ztest.bzl macro, not by hand):
#   openssl_gate_runner.sh <suite-binary> <gate-script>
#
# Deliberately stricter than test.sh in one place: a suite wired up for the
# gate that emits *no* artifacts fails here. On the CMake path an empty
# directory passes trivially, so a suite that quietly stopped generating DER
# would keep reporting green — a gate that cannot fail is not a gate. Suites
# that legitimately generate nothing simply do not set `openssl_gate = True`.

set -eu

BIN="$1"
GATE="$2"

# Runfiles paths are relative to the test's working directory; resolve them
# before cd'ing away.
BIN="$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")"
GATE="$(cd "$(dirname "$GATE")" && pwd)/$(basename "$GATE")"

# native_sim's flash simulator is file-backed (flash.bin in the working
# directory). Run in a private directory so nothing leaks between suites —
# the same isolation that caught the pre-existing volume-marker bug in
# `pairing` / `pairing_passkey` when the suites first moved to Bazel.
WORK="${TEST_TMPDIR:-$(mktemp -d)}/gate_run"
ART="$WORK/artifacts"
mkdir -p "$ART"
cd "$WORK"

CANTIL_TEST_ARTIFACT_DIR="$ART"
export CANTIL_TEST_ARTIFACT_DIR

rc=0
"$BIN" > suite.log 2>&1 || rc=$?
cat suite.log

if [ "$rc" -ne 0 ]; then
    echo "FAIL: suite binary exited $rc" >&2
    exit 1
fi

# Exit code alone is not enough — check the same signature the zephyr-bazel
# ztest runner checks, so a suite that dies before ztest reports cannot pass.
if ! grep -q 'PROJECT EXECUTION SUCCESSFUL' suite.log; then
    echo "FAIL: suite did not report PROJECT EXECUTION SUCCESSFUL" >&2
    exit 1
fi

n=$(find "$ART" -maxdepth 1 -name '*.der' | wc -l)
if [ "$n" -eq 0 ]; then
    echo "FAIL: suite emitted no DER artifacts, so the gate would pass" >&2
    echo "      vacuously. Either the suite stopped generating (a real" >&2
    echo "      regression) or it should not set openssl_gate = True." >&2
    exit 1
fi

exec "$GATE" "$ART"
