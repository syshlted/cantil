#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Refuses to commit any staged file over the size limit (bytes).

set -eu

LIMIT=1048576 # 1 MiB
TMP="$(mktemp)"
trap 'rm -f "$TMP"' EXIT

git diff --cached --name-only --diff-filter=ACM > "$TMP"

FAILED=0
while IFS= read -r f; do
    [ -f "$f" ] || continue
    SIZE="$(wc -c < "$f")"
    if [ "$SIZE" -gt "$LIMIT" ]; then
        echo "error: $f is $SIZE bytes, over the $LIMIT byte limit" >&2
        FAILED=1
    fi
done < "$TMP"

exit "$FAILED"
