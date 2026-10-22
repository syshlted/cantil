#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Refuses to run clang-format at all if its major version doesn't match
# .clang-format-version (formatting output can change between major
# releases, and .clang-format itself uses options tied to a minimum
# version). Warns, but doesn't block, on a minor-version difference.
#
# Usage: check-clang-format-version.sh

set -eu

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
PINNED="$(cat "$REPO_ROOT/.clang-format-version")"

if ! command -v clang-format > /dev/null 2>&1; then
    echo "error: clang-format not found on PATH (pinned version: $PINNED)" >&2
    exit 1
fi

ACTUAL="$(clang-format --version | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)"
if [ -z "$ACTUAL" ]; then
    echo "error: could not parse 'clang-format --version' output" >&2
    exit 1
fi

PINNED_MAJOR="${PINNED%%.*}"
ACTUAL_MAJOR="${ACTUAL%%.*}"
PINNED_MINOR="$(echo "$PINNED" | cut -d. -f2)"
ACTUAL_MINOR="$(echo "$ACTUAL" | cut -d. -f2)"

if [ "$PINNED_MAJOR" != "$ACTUAL_MAJOR" ]; then
    echo "error: clang-format major mismatch: pinned $PINNED, found $ACTUAL" >&2
    echo "       formatting isn't stable across major versions." >&2
    echo "       install clang-format $PINNED (see AGENTS.md)." >&2
    exit 1
fi

if [ "$PINNED_MINOR" != "$ACTUAL_MINOR" ]; then
    echo "warning: clang-format minor differs: pinned $PINNED, got $ACTUAL" >&2
    echo "         formatting may differ slightly; consider matching it." >&2
fi

exit 0
