#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Refuses to commit leftover merge/rebase conflict markers.

set -eu

PATTERN='^\+(<{7}|={7}|>{7})([^=<>]|$)'
HITS="$(git diff --cached -U0 -- . | grep -nE "$PATTERN" || true)"
if [ -n "$HITS" ]; then
    echo "error: conflict markers found in staged changes:" >&2
    echo "$HITS" >&2
    exit 1
fi
exit 0
