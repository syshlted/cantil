#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# One-time setup for the LEGACY CMake/west build.
#
# ── You probably do not need this. ─────────────────────────────────────────
# The default build is Bazel, which fetches Zephyr, the Zephyr SDK, the modules
# and the zephyr-bazel overlay itself:
#
#   ./scripts/build.sh              # firmware
#   ./scripts/test.sh               # ztest suites + the OpenSSL gate
#
# This script is needed only for `--cmake`, which survives for two things: the
# reference build used for A/B size comparisons, and boards other than the
# XIAO, which have no Bazel board package yet. (The mcuboot tier was the third
# and is gone — docs/roadmap/wolfboot-migration.md.)
#
# Replaces the nRF Connect SDK workspace at ~/ncs/v3.0.2 with a plain
# upstream Zephyr workspace pinned by firmware/west.yml.  Idempotent: safe to
# re-run after changing the manifest to pick up new pins.
#
# Usage:
#   ./scripts/setup_zephyr.sh
#
# Environment:
#   CANTIL_ZEPHYR_WS        Workspace location (default: $HOME/zephyr/cantil)
#   ZEPHYR_SDK_INSTALL_DIR  Zephyr SDK location (default: $HOME/zephyr-sdk-<ver>)
#   CANTIL_NCS_TOOLCHAIN    NCS toolchain bundle, reused for host tools
#                           (default: $HOME/ncs/toolchains/7cbc0036f4)
#
# Why the NCS toolchain bundle is still referenced: it ships matched host
# tools (cmake, ninja, dtc, gperf, git, west, python) that upstream Zephyr is
# happy to use.  Only the *compiler* is NCS-version-bound, and that comes from
# the Zephyr SDK installed below.  Nothing NCS-specific ends up in the build.

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

WS="${CANTIL_ZEPHYR_WS:-$HOME/zephyr/cantil}"
TC_DIR="${CANTIL_NCS_TOOLCHAIN:-$HOME/ncs/toolchains/7cbc0036f4}"

# Must match the SDK_VERSION file of the Zephyr revision pinned in
# firmware/west.yml.  Zephyr's find_package(Zephyr-sdk) rejects any SDK
# strictly older than this, so bumping the Zephyr pin may require bumping
# this too.
SDK_VER="1.0.1"
SDK_DIR="${ZEPHYR_SDK_INSTALL_DIR:-$HOME/zephyr-sdk-$SDK_VER}"
SDK_HOST="linux-x86_64"
SDK_URL="https://github.com/zephyrproject-rtos/sdk-ng/releases/download/v$SDK_VER"

if [ ! -d "$TC_DIR" ]; then
    echo "error: host toolchain bundle not found at $TC_DIR" >&2
    echo "Install it with the nRF toolchain manager, or set CANTIL_NCS_TOOLCHAIN." >&2
    exit 1
fi

# The bundle ships a `git` built for the NCS container: its libexec helpers
# (git-remote-https in particular) are not resolvable when the bundle is used
# in place on the host, so any fetch over https dies with
#   git: 'remote-https' is not a git command
# west shells out to whichever git is first on PATH, so shim the host's git
# ahead of the bundle's while leaving the rest of the bundle's toolset intact.
GIT_SHIM="$PROJECT_ROOT/build/.host-git-shim"
mkdir -p "$GIT_SHIM"
ln -sf /usr/bin/git "$GIT_SHIM/git"

export PATH="$GIT_SHIM:$TC_DIR/usr/local/bin:$TC_DIR/usr/bin:$PROJECT_ROOT/venv/bin:/usr/local/bin:/usr/bin:$PATH"
export LD_LIBRARY_PATH="$TC_DIR/usr/local/lib:$TC_DIR/usr/lib:${LD_LIBRARY_PATH:-}"

# ── 1. Zephyr SDK (arm-zephyr-eabi only) ────────────────────────────────────
# The full SDK carries every target Zephyr supports (~10 GB).  The minimal
# bundle plus one toolchain is ~450 MB.  Phase 4 (multi-platform) will add
# riscv64-zephyr-elf and xtensa-espressif_esp32-elf the same way:
#     $SDK_DIR/setup.sh -t riscv64-zephyr-elf
# SDK 1.0 moved the per-arch toolchains under gnu/ (was a top-level dir in
# 0.17.x); check the compiler binary directly so this stays layout-robust.
if [ -f "$SDK_DIR/sdk_version" ] && \
   [ -x "$SDK_DIR/gnu/arm-zephyr-eabi/bin/arm-zephyr-eabi-gcc" ]; then
    echo "--- Zephyr SDK $(cat "$SDK_DIR/sdk_version") already at $SDK_DIR"
else
    echo "--- Installing Zephyr SDK $SDK_VER to $SDK_DIR"
    mkdir -p "$(dirname "$SDK_DIR")"
    tmp="$(mktemp -d)"
    trap 'rm -rf "$tmp"' EXIT
    curl -fL --progress-bar \
        -o "$tmp/sdk.tar.xz" \
        "$SDK_URL/zephyr-sdk-${SDK_VER}_${SDK_HOST}_minimal.tar.xz"
    tar -xf "$tmp/sdk.tar.xz" -C "$(dirname "$SDK_DIR")"
    # The tarball unpacks to zephyr-sdk-<ver>; move it if the caller asked for
    # a different directory name.
    unpacked="$(dirname "$SDK_DIR")/zephyr-sdk-$SDK_VER"
    if [ "$unpacked" != "$SDK_DIR" ]; then
        rm -rf "$SDK_DIR"
        mv "$unpacked" "$SDK_DIR"
    fi
    # -t: install one toolchain.  -c: register the CMake package so
    # find_package(Zephyr-sdk) resolves without ZEPHYR_SDK_INSTALL_DIR set.
    # -h: install the udev/hardware rules non-interactively.
    (cd "$SDK_DIR" && ./setup.sh -t arm-zephyr-eabi -c -h)
fi

export ZEPHYR_SDK_INSTALL_DIR="$SDK_DIR"
export ZEPHYR_TOOLCHAIN_VARIANT=zephyr

# ── 2. West workspace ───────────────────────────────────────────────────────
# west requires its manifest to live in a git repository inside the workspace
# top directory.  Cantil's manifest is version-controlled at
# firmware/west.yml, so the workspace gets a thin manifest repo that mirrors
# it.  firmware/west.yml stays the single source of truth; $WS/manifest is
# derived and disposable.
echo "--- Syncing manifest to $WS/manifest"
mkdir -p "$WS/manifest"
cp "$PROJECT_ROOT/firmware/west.yml" "$WS/manifest/west.yml"

if [ ! -d "$WS/manifest/.git" ]; then
    git -C "$WS/manifest" init -q
fi
git -C "$WS/manifest" add west.yml
# No-op commit when the manifest is unchanged; --allow-empty keeps re-runs
# from failing on a clean tree.
git -C "$WS/manifest" -c user.name=cantil -c user.email=cantil@localhost \
    commit -q --allow-empty -m "cantil manifest sync"

if [ ! -d "$WS/.west" ]; then
    echo "--- west init"
    (cd "$WS" && west init -l manifest)
fi

echo "--- west update (this fetches Zephyr and its modules; several minutes)"
(cd "$WS" && west update --narrow -o=--depth=1)

echo "--- west zephyr-export"
(cd "$WS" && west zephyr-export)

# ── 3. Python requirements ──────────────────────────────────────────────────
# The build itself runs on the bundle's python3 (it comes first on PATH and is
# what CMake's find_package(Python3) resolves), and NCS ships a superset of
# what Zephyr's build scripts need.  This step only tops up the project venv
# so venv-based tooling (imgtool, scripts/) has the same base packages.
#
# requirements-base.txt, not requirements.txt: the umbrella file pulls in the
# runner extras, and one of them (hidapi) needs libusb-1.0 development headers
# to build a wheel.  Nothing in the firmware build path uses it.
if [ -x "$PROJECT_ROOT/venv/bin/pip" ]; then
    echo "--- Installing Zephyr base Python requirements into venv/"
    "$PROJECT_ROOT/venv/bin/pip" install -q \
        -r "$WS/zephyr/scripts/requirements-base.txt" \
        || echo "warning: venv requirements install failed; build uses the bundle python" >&2
else
    echo "warning: no venv at $PROJECT_ROOT/venv — skipping Python requirements" >&2
fi

cat <<EOF

--- Setup complete
  Workspace:  $WS
  Zephyr:     $(cat "$WS/zephyr/VERSION" 2>/dev/null | tr '\n' ' ')
  SDK:        $SDK_DIR ($(cat "$SDK_DIR/sdk_version" 2>/dev/null))

Build with:
  ./scripts/build.sh
EOF
