#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Runs a subset of Zephyr's scripts/ci/check_compliance.py against this
# repo's own commits (not the vendored Zephyr tree). ZEPHYR_BASE points at
# the pinned west workspace so Checkpatch finds checkpatch.pl and friends;
# GIT_TOP (this repo) is what actually gets diffed.
#
# Deliberately excludes: Identity (requires DCO Signed-off-by + rejects the
# @users.noreply.github.com email this repo commits with), LicenseAndCopy-
# rightCheck (redundant with `reuse lint`), and the ClangFormat/Ruff modules
# (redundant with our own clang-format/ruff checks; ClangFormat also crashes
# against this tree). See requirements-dev.txt for the Python deps this
# needs and AGENTS.md for the west workspace setup.
#
# Usage: run-check-compliance.sh [commit-range]
#
# With no argument the range is <compliance-baseline>..HEAD, so every commit
# since the baseline is checked, not just the newest. @{push} is not usable
# here: the syshlt remote is a history-rewriting mirror, so its range would
# cover the whole pre-lefthook history. Bump compliance-baseline once older
# commits are cleaned up (or whenever the mirror is reconciled).

set -eu

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
ZEPHYR_WORKSPACE="${CANTIL_ZEPHYR_BASE:-$HOME/zephyr/cantil/zephyr}"
BASELINE="$(cat "$REPO_ROOT/scripts/lefthook/compliance-baseline")"
RANGE="${1:-$BASELINE..HEAD}"

if [ ! -d "$ZEPHYR_WORKSPACE" ]; then
    echo "error: Zephyr west workspace not found at $ZEPHYR_WORKSPACE" >&2
    echo "       run scripts/setup_zephyr.sh once, or set" >&2
    echo "       CANTIL_ZEPHYR_BASE." >&2
    exit 1
fi

if [ ! -x "$REPO_ROOT/venv/bin/python3" ]; then
    echo "error: no venv at $REPO_ROOT/venv (see requirements-dev.txt)" >&2
    exit 1
fi

export ZEPHYR_BASE="$ZEPHYR_WORKSPACE"
export PATH="$REPO_ROOT/venv/bin:$PATH"
cd "$REPO_ROOT"

COMPLIANCE_PY="$ZEPHYR_WORKSPACE/scripts/ci/check_compliance.py"

exec "$REPO_ROOT/venv/bin/python3" "$COMPLIANCE_PY" \
    -c "$RANGE" \
    -n \
    -m Checkpatch \
    -m Nits \
    -m TextEncoding \
    -m BinaryFiles \
    -m GitDiffCheck \
    -m KeepSorted \
    -m CMakeStyle \
    -m Gitlint \
    -o "$REPO_ROOT/compliance.xml"
