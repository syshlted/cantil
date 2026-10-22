#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Refuses to commit files whose names look like key/cert material, mirroring
# the denylist in .gitignore (defense in depth against `git add -f`).

set -eu

TMP="$(mktemp)"
trap 'rm -f "$TMP"' EXIT
git diff --cached --name-only --diff-filter=ACM > "$TMP"

FAILED=0
while IFS= read -r f; do
    case "$f" in
        *.pem | *.key | signing_key* | prod_signing_key* | \
        */signing_key* | */prod_signing_key*)
            echo "error: $f looks like key/cert material, refusing" >&2
            FAILED=1
            ;;
    esac
done < "$TMP"

exit "$FAILED"
