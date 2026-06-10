#!/bin/sh
# Run a command inside the ubuntu2604 distrobox with the project venv active.
#
# Usage:
#   ./scripts/dbox.sh <command> [args...]
#   ./scripts/dbox.sh imgtool version
#   ./scripts/dbox.sh west build -b xiao_ble/nrf52840
#   ./scripts/dbox.sh bash          # interactive shell with venv active
#
# The venv at $PROJECT_ROOT/venv is activated before running the command.
# All other build tools (gcc-arm-none-eabi, cmake, ninja, west, dtc) must
# be installed as Ubuntu packages inside the distrobox — see CLAUDE.md.

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
VENV="$PROJECT_ROOT/venv"

if [ ! -f "$VENV/bin/activate" ]; then
    echo "error: venv not found at $VENV" >&2
    echo "Run: cd $PROJECT_ROOT && python3 -m venv venv && . venv/bin/activate && pip install -r requirements.txt" >&2
    exit 1
fi

exec flatpak-spawn --host distrobox enter ubuntu2604 -- \
    sh -c ". '$VENV/bin/activate' && \"\$@\"" -- "$@"
