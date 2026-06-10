#!/usr/bin/env bash
#
# publish-prep.sh — build a clean snapshot of this repo for a public github push.
#
# History is NOT preserved. The destination gets a fresh git init with a single
# "Initial public snapshot" commit. This is intentional: we keep dev noise
# (conversation logs, CLAUDE.md, MEMORY.md, .claude/, internal/) in the working
# repo and never want any of it on the public mirror, including in history.
#
# Usage:
#   scripts/publish-prep.sh [destination-dir]
#
# Default destination: ../cantil-public (sibling of this repo).
#
# After it runs:
#   cd <destination>
#   git remote add origin git@github.com:<owner>/cantil.git
#   git push -u origin main
#
# If the destination already exists the script refuses to overwrite. Delete it
# first or pass a different path.

set -euo pipefail

REPO_ROOT=$(cd "$(dirname "$0")/.." && pwd)
DEST=${1:-"$REPO_ROOT/../cantil-public"}

if [ -e "$DEST" ]; then
    echo "Destination already exists: $DEST" >&2
    echo "Remove it or pass a different path." >&2
    exit 1
fi

# Refuse if destination would land inside the source tree — rsync would then
# try to copy its own output and explode.
case "$DEST" in
    "$REPO_ROOT"|"$REPO_ROOT"/*)
        echo "Destination must be outside the source repo: $DEST" >&2
        exit 1
        ;;
esac

mkdir -p "$DEST"

# Paths that must not appear in the public repo. rsync --exclude patterns,
# relative to the source root. Keep this list in sync with internal/README.md.
EXCLUDES=(
    # local git + build artefacts
    '.git/'
    '.gitignore.local'
    'build/'
    'build_*/'
    'venv/'
    '__pycache__/'
    '*.pyc'

    # Claude harness + project notes
    '.claude/'
    'CLAUDE.md'
    'MEMORY.md'

    # internal-only working material
    'internal/'

    # full transcripts of dev sessions
    'docs/conversations/'
)

RSYNC_EXCLUDES=()
for p in "${EXCLUDES[@]}"; do
    RSYNC_EXCLUDES+=(--exclude="$p")
done

echo "Snapshotting $REPO_ROOT -> $DEST"
rsync -a "${RSYNC_EXCLUDES[@]}" "$REPO_ROOT/" "$DEST/"

# Sanity check: walk the exclude list again against the destination. If any
# excluded path leaked through (e.g. someone added a new path that matches but
# rsync ordering missed it), abort before committing.
echo
echo "Verifying excluded paths are absent in destination..."
LEAKED=0
for p in "${EXCLUDES[@]}"; do
    test_path="${p%/}"
    if compgen -G "$DEST/$test_path" > /dev/null 2>&1; then
        echo "  LEAKED: $test_path"
        LEAKED=1
    fi
done
if [ "$LEAKED" -ne 0 ]; then
    echo "Aborting — one or more excluded paths made it through." >&2
    echo "Inspect $DEST and update EXCLUDES in this script." >&2
    exit 1
fi
echo "OK — clean."

# Fresh git init in the destination. Single commit, no history from the dev
# repo.
(
    cd "$DEST"
    git init -q -b main
    git add -A
    git -c user.name="Cantil" -c user.email="noreply@cantil.local" \
        commit -q -m "Initial public snapshot"
)

cat <<EOF

Public snapshot ready at: $DEST

Next steps:
  cd "$DEST"
  git remote add origin git@github.com:<owner>/cantil.git
  git push -u origin main

To refresh the snapshot later, delete "$DEST" and re-run this script. The
public repo's history will be rewritten on the next force-push.
EOF
