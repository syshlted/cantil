#!/bin/sh
# Export the current session's conversation transcript and commit it.
#
# Called automatically from the PostToolUse hook after each 'git commit'.
# Runs git commit directly (not via Claude's Bash tool) so it does NOT
# re-trigger the hook.
#
# Usage: export_transcript.sh [--session-id <id>]
#
# --session-id is accepted for interface stability; extraction always uses
# --extract 1 (most-recently-modified session = the active one), since this
# script is invoked immediately after a commit within the same session.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

CLAUDE_EXTRACT="/var/home/jmelanson/git/personal/claude_projects/github.com/ZeroSumQuant/claude-conversation-extractor/venv/bin/claude-extract"
OUTPUT_DIR="$PROJECT_ROOT/docs/conversations/transcripts"

mkdir -p "$OUTPUT_DIR"

"$CLAUDE_EXTRACT" --extract 1 --detailed --output "$OUTPUT_DIR"

cd "$PROJECT_ROOT"
git add "$OUTPUT_DIR"

if git diff --cached --quiet; then
    exit 0
fi

git commit -m "docs: update conversation transcript (auto-export)"
