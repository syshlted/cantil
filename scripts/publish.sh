#!/usr/bin/env bash
#
# publish.sh — push a filtered mirror of master to the syshlt remote.
#
# Maintains a local `publish` branch that is master + a single strip commit
# removing internal files (.claude/, CLAUDE.md, docs/conversations). History
# is preserved; the strip commit is the only extra layer on top.
#
# Usage:
#   scripts/publish.sh [--dry-run]
#
# On first run: adds the syshlt remote and force-pushes the publish branch.
# On subsequent runs: resets the publish branch to the current master tip,
# re-applies the strip commit, and force-pushes (the strip commit is always
# recreated, not accumulated).

set -euo pipefail

REMOTE="syshlt"
REMOTE_URL="git@syshlt-github:/syshlted/cantil.git"
SOURCE="master"
PUBLISH_BRANCH="publish"
DRY_RUN=0

for arg in "$@"; do
    case "$arg" in
        --dry-run) DRY_RUN=1 ;;
        *) echo "Unknown argument: $arg" >&2; exit 1 ;;
    esac
done

# Paths excluded from the public mirror (git rm --cached, index only).
STRIP=(
    ".claude"
    "CLAUDE.md"
    "docs/conversations"
)

ORIG_BRANCH=$(git symbolic-ref --short HEAD 2>/dev/null || echo "HEAD")
STASHED=0

cleanup() {
    # Return to the original branch on exit (even on error).
    # Use -f because git rm --cached leaves stripped files in the working tree
    # as "untracked" from the publish branch's perspective; without -f, git
    # refuses the checkout even though the files match master's committed state.
    if [ "$ORIG_BRANCH" != "HEAD" ] && [ "$(git symbolic-ref --short HEAD 2>/dev/null)" != "$ORIG_BRANCH" ]; then
        git checkout -f -q "$ORIG_BRANCH"
    fi
    # Restore any stashed working-tree changes.
    if [ "$STASHED" -eq 1 ]; then
        git stash pop -q
        echo "Restored stashed working-tree changes."
    fi
}
trap cleanup EXIT

# Abort if there are staged changes — they'd bleed into the strip commit.
if ! git diff --cached --quiet; then
    echo "Error: you have staged changes. Commit or reset them before publishing." >&2
    exit 1
fi

# Stash unstaged working-tree changes so checkout -B doesn't get confused when
# the strip commit removes paths that are locally modified.
if ! git diff --quiet; then
    echo "Stashing working-tree changes temporarily..."
    [ "$DRY_RUN" -eq 0 ] && git stash push -q -m "publish-prep: auto-stash" && STASHED=1
fi

# Ensure the remote exists.
if ! git remote get-url "$REMOTE" &>/dev/null; then
    echo "Adding remote $REMOTE → $REMOTE_URL"
    [ "$DRY_RUN" -eq 0 ] && git remote add "$REMOTE" "$REMOTE_URL"
fi

# Create/reset the publish branch to the current master tip.
echo "Resetting $PUBLISH_BRANCH → $SOURCE"
[ "$DRY_RUN" -eq 0 ] && git checkout -B "$PUBLISH_BRANCH" "$SOURCE"

# Strip excluded paths from the index (working tree is untouched).
STRIPPED=0
for p in "${STRIP[@]}"; do
    if git ls-files --error-unmatch "$p" &>/dev/null 2>&1; then
        echo "Stripping: $p"
        [ "$DRY_RUN" -eq 0 ] && git rm -r --cached -q "$p"
        STRIPPED=1
    fi
done

# Commit the strip layer.
if [ "$STRIPPED" -eq 1 ]; then
    echo "Committing strip layer"
    [ "$DRY_RUN" -eq 0 ] && git commit -q -m "chore: strip internal files [publish]"
else
    echo "Nothing to strip — publish branch matches master content."
fi

# Push publish branch as master on the remote.
if [ "$DRY_RUN" -eq 1 ]; then
    echo "[dry-run] would push: $PUBLISH_BRANCH → $REMOTE/master"
else
    echo "Pushing to $REMOTE/master"
    git push --force "$REMOTE" "$PUBLISH_BRANCH:master"
fi

echo "Done."
