#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Build (and optionally flash) the firmware.
#
# Usage:
#   ./scripts/build.sh [options]
#
# Options:
#   -b BOARD            Zephyr board target (default: xiao_ble/nrf52840/sense).
#                       Any board other than the XIAO implies --cmake: no other
#                       board has a Bazel board package yet.
#   --flash             Copy the UF2 to every XIAO-SENSE* drive that mounts.
#                       Double-tap reset to enter UF2 mode before running, or
#                       if a drive is already mounted the copy happens directly.
#   --factory           Build the step-1 factory image (firmware/factory)
#                       instead of the Cantil firmware. Creates the LittleFS
#                       volume and writes its identity marker; contains no CA
#                       and no key material. This is the only image that can
#                       format the volume — see docs/roadmap/two-step-provisioning.md.
#   --source DIR        Build another app dir (e.g. firmware/wipe_diag).
#   --cmake             Use the legacy CMake/west build instead of Bazel. Kept
#                       as the reference build for A/B size comparisons, and
#                       required for non-XIAO boards.
#   --clean             Delete the CMake build dir (--cmake only; Bazel manages
#                       its own cache — use `bazelisk clean` if you must).
#   -d BUILD_DIR        CMake build output directory (--cmake only, default: build/)
#   -- ARGS             Extra arguments passed through (west build / CMake on
#                       the --cmake path, bazelisk on the Bazel path)
#
# Examples:
#   ./scripts/build.sh
#   ./scripts/build.sh --flash
#   ./scripts/build.sh --factory --flash
#   ./scripts/build.sh --source firmware/wipe_diag
#   ./scripts/build.sh --cmake                      # reference build, for A/B
#   ./scripts/build.sh -b nrf52840dk/nrf52840       # implies --cmake
#
# ── Which build system ──────────────────────────────────────────────────────
#
# Bazel is the default and needs no setup: it fetches Zephyr, the Zephyr SDK,
# the modules and the zephyr-bazel overlay itself. There is no workspace to
# create, no toolchain bundle, no `west update`.
#
# The CMake/west path (--cmake) still exists for two reasons: it is the
# reference build the Bazel output is checked against, and it is the only path
# that supports boards other than the XIAO. It needs ./scripts/setup_zephyr.sh
# once. (The mcuboot tier was the third reason, and the only one that needed
# `west --sysbuild`; it was dropped 2026-07-26 — see
# docs/roadmap/wolfboot-migration.md.)
#
# Environment (--cmake path only):
#   CANTIL_ZEPHYR_WS        Workspace location (default: $HOME/zephyr/cantil)
#   ZEPHYR_SDK_INSTALL_DIR  Zephyr SDK location (default: $HOME/zephyr-sdk-1.0.1)
#   CANTIL_NCS_TOOLCHAIN    Host-tool bundle (default: $HOME/ncs/toolchains/7cbc0036f4)

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
FIRMWARE_DIR="$PROJECT_ROOT/firmware"
ZEPHYR_WS="${CANTIL_ZEPHYR_WS:-$HOME/zephyr/cantil}"
TC_DIR="${CANTIL_NCS_TOOLCHAIN:-$HOME/ncs/toolchains/7cbc0036f4}"
SDK_DIR="${ZEPHYR_SDK_INSTALL_DIR:-$HOME/zephyr-sdk-1.0.1}"
BAZEL="${CANTIL_BAZEL:-bazelisk}"
# Drive(s) the Adafruit UF2 bootloader presents.  Multiple XIAO-SENSE*
# mounts (XIAO-SENSE, XIAO-SENSE1, …) appear when more than one unit is
# in DFU at once; the --flash step copies to every matching drive.
UF2_MOUNT_GLOB="/run/media/$USER/XIAO-SENSE*"

BOARD="xiao_ble/nrf52840/sense"
BUILD_DIR="$PROJECT_ROOT/build"
DO_FLASH=0
DO_CLEAN=0
DO_FACTORY=0
BUILD_DIR_SET=0
USE_CMAKE=0
SRC_OVERRIDE=""
EXTRA_ARGS=""

while [ $# -gt 0 ]; do
    case "$1" in
        -b) BOARD="$2"; shift 2 ;;
        -d) BUILD_DIR="$2"; BUILD_DIR_SET=1; shift 2 ;;
        --flash) DO_FLASH=1; shift ;;
        --clean) DO_CLEAN=1; shift ;;
        --factory) DO_FACTORY=1; shift ;;
        --source) SRC_OVERRIDE="$2"; shift 2 ;;
        --cmake) USE_CMAKE=1; shift ;;
        --) shift; EXTRA_ARGS="$*"; break ;;
        *) echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

# ── Engine selection ────────────────────────────────────────────────────────
# One thing still forces the legacy path, and it says so rather than failing
# later with something obscure.
#
# Since 2026-07-27 the other nRF52840 boards DO have Bazel board packages
# (nrf52840dk, nrf52840dongle, adafruit_feather_nrf52840). They still route
# here, because the packages are not what is missing: those boards' configs are
# NCS-era BLE (CONFIG_BT_NUS, and the NCS <bluetooth/services/nus.h> that
# src/transport/transport_ble.c includes), so the firmware builds on neither
# build system. Warn about that up front — the compile error it otherwise
# produces names a missing header and explains nothing.
if [ "$BOARD" != "xiao_ble/nrf52840/sense" ] && [ "$USE_CMAKE" = "0" ]; then
    echo "note: -b $BOARD implies --cmake (docs/roadmap/bazel-migration.md)." >&2
    USE_CMAKE=1
fi

case "$BOARD" in
    xiao_ble/*) ;;
    *)
        echo "warning: $BOARD is expected to FAIL to build." >&2
        echo "         Its firmware/boards/*.conf enables CONFIG_CANTIL_TRANSPORT_BLE," >&2
        echo "         which compiles src/transport/transport_ble.c against the NCS" >&2
        echo "         Bluetooth NUS API. This tree builds upstream Zephyr, where that" >&2
        echo "         header does not exist. Blocked on BLE enablement, not on the" >&2
        echo "         build system — see docs/roadmap/ble-enablement.md." >&2
        ;;
esac

SOURCE_DIR="$FIRMWARE_DIR"

if [ "$DO_FACTORY" = "1" ]; then
    SOURCE_DIR="$FIRMWARE_DIR/factory"
    # Separate default build tree: the factory image and the firmware share a
    # board but not a Kconfig tree, and reusing one directory produces
    # confusing stale-cache failures.
    if [ "$BUILD_DIR_SET" = "0" ]; then
        BUILD_DIR="$PROJECT_ROOT/build_factory"
    fi
    echo "--- Factory image (step 1): creates the volume + identity marker"
fi

# --source builds an arbitrary app dir (e.g. firmware/wipe_diag). Takes
# precedence over the default and --factory; on the CMake path it defaults the
# build tree to build_<appname>.
if [ -n "$SRC_OVERRIDE" ]; then
    case "$SRC_OVERRIDE" in
        /*) SOURCE_DIR="$SRC_OVERRIDE" ;;
        *)  SOURCE_DIR="$PROJECT_ROOT/$SRC_OVERRIDE" ;;
    esac
    if [ ! -d "$SOURCE_DIR" ]; then
        echo "error: --source dir not found: $SOURCE_DIR" >&2
        exit 1
    fi
    if [ "$BUILD_DIR_SET" = "0" ]; then
        BUILD_DIR="$PROJECT_ROOT/build_$(basename "$SOURCE_DIR")"
    fi
    echo "--- Custom app: $SOURCE_DIR"
fi

# ── Copy a UF2 to every bootloader drive ────────────────────────────────────
# Shared by both engines: the artifact differs, the flashing does not.
flash_uf2() {
    uf2="$1"
    # Already in DFU?  Skip the touch and flash directly.
    set -- $UF2_MOUNT_GLOB
    if [ ! -d "$1" ]; then
        # No drive yet — try the 1200bps-touch on every /dev/ttyACM* as a
        # convenience hint; the firmware ignores it since DEV_DFU_REBOOT is
        # gone, so a physical double-tap reset is required if the drive doesn't
        # appear.
        for tty in /dev/ttyACM*; do
            [ -c "$tty" ] || continue
            stty -F "$tty" 1200 >/dev/null 2>&1 || true
        done
        # Wait up to 10 s for the bootloader drive to mount.
        i=0
        while [ "$i" -lt 50 ]; do
            set -- $UF2_MOUNT_GLOB
            [ -d "$1" ] && break
            sleep 0.2
            i=$((i + 1))
        done
        set -- $UF2_MOUNT_GLOB
        if [ ! -d "$1" ]; then
            echo "error: XIAO-SENSE drive did not appear" >&2
            echo "Double-tap the reset button to enter UF2 mode." >&2
            exit 1
        fi
    fi
    for mount in $UF2_MOUNT_GLOB; do
        [ -d "$mount" ] || continue
        echo "--- Flashing to $mount"
        cp "$uf2" "$mount/"
        sync
    done
    echo "--- Done — device(s) will reset and boot the new firmware."
}

# ════════════════════════════════════════════════════════════════════════════
# Bazel path (default)
# ════════════════════════════════════════════════════════════════════════════
if [ "$USE_CMAKE" = "0" ]; then
    # Map the app directory to its Bazel target. Only apps with a BUILD.bazel
    # are reachable; anything else is a real "not ported" answer rather than a
    # confusing Bazel error.
    #
    # INVARIANTS is built alongside the image, not instead of a test: the
    # symbol-level guarantees (no formatter in production, a formatter in the
    # factory image, no mbedTLS anywhere) are assertions about the linked ELF,
    # which is a cross-compiled artifact in the app's own platform
    # configuration — nothing a host test could run against. Building them here
    # means no UF2 ever reaches a device without them holding.
    case "${SOURCE_DIR#$PROJECT_ROOT/}" in
        firmware)
            TARGET="//firmware:cantil.uf2"
            INVARIANTS="//firmware:cantil_invariants"
            ;;
        firmware/factory)
            TARGET="//firmware/factory:cantil_factory.uf2"
            INVARIANTS="//firmware/factory:cantil_factory_invariants"
            ;;
        firmware/wipe_diag)
            # A bench diagnostic — links neither littlefs nor a crypto library,
            # so it has no exposure to assert about.
            TARGET="//firmware/wipe_diag:cantil_wipe_diag.uf2"
            INVARIANTS=""
            ;;
        *)
            echo "error: no Bazel target for $SOURCE_DIR" >&2
            echo "  Add a BUILD.bazel there (see firmware/wipe_diag/BUILD.bazel)," >&2
            echo "  or build it the old way with --cmake." >&2
            exit 1
            ;;
    esac

    if ! command -v "$BAZEL" >/dev/null 2>&1; then
        echo "error: $BAZEL not found on PATH" >&2
        echo "  Install bazelisk, or set CANTIL_BAZEL, or use --cmake." >&2
        exit 1
    fi

    if [ "$DO_CLEAN" = "1" ]; then
        echo "note: --clean is a no-op on the Bazel path (it caches by content)." >&2
        echo "      Run '$BAZEL clean' yourself if you really mean it." >&2
    fi

    echo "--- Building $TARGET for $BOARD (bazel)"
    cd "$PROJECT_ROOT"
    # shellcheck disable=SC2086
    $BAZEL build "$TARGET" $INVARIANTS --config=xiao ${EXTRA_ARGS:+$EXTRA_ARGS}

    # bazel-bin is not reliable here: a target that self-transitions can clear
    # the convenience symlink. Ask for the output path instead.
    EXEC_ROOT="$($BAZEL info execution_root)"
    UF2_REL="$($BAZEL cquery "$TARGET" --config=xiao --output=files 2>/dev/null | tail -1)"
    UF2_PATH="$EXEC_ROOT/$UF2_REL"
    if [ ! -f "$UF2_PATH" ]; then
        echo "error: built $TARGET but found no UF2 at $UF2_PATH" >&2
        exit 1
    fi

    echo "--- Build complete: $UF2_PATH"
    [ "$DO_FLASH" = "1" ] && flash_uf2 "$UF2_PATH"
    exit 0
fi

# ════════════════════════════════════════════════════════════════════════════
# CMake/west path (--cmake: the reference build, and non-XIAO boards)
# ════════════════════════════════════════════════════════════════════════════
if [ ! -d "$ZEPHYR_WS/.west" ]; then
    echo "error: Zephyr workspace not found at $ZEPHYR_WS" >&2
    echo "Run: ./scripts/setup_zephyr.sh  (needed only for the --cmake path)" >&2
    exit 1
fi

if [ ! -d "$TC_DIR" ]; then
    echo "error: host-tool bundle not found at $TC_DIR" >&2
    echo "Install it with the nRF toolchain manager (nrfutil toolchain-manager)," >&2
    echo "or point CANTIL_NCS_TOOLCHAIN at another bundle." >&2
    exit 1
fi

# SDK 1.0 moved per-arch toolchains under gnu/ (was top-level in 0.17.x).
if [ ! -x "$SDK_DIR/gnu/arm-zephyr-eabi/bin/arm-zephyr-eabi-gcc" ]; then
    echo "error: Zephyr SDK (arm-zephyr-eabi) not found at $SDK_DIR" >&2
    echo "Run: ./scripts/setup_zephyr.sh" >&2
    exit 1
fi

# See setup_zephyr.sh: the bundle's git cannot resolve its own remote helpers
# when used outside the NCS container, so shim the host's git ahead of it.
GIT_SHIM="$PROJECT_ROOT/build/.host-git-shim"
mkdir -p "$GIT_SHIM"
ln -sf /usr/bin/git "$GIT_SHIM/git"

# Bundle cmake/ninja/python come first so the whole build uses one consistent,
# matched toolset (mixing host cmake with bundle west/python would break the
# cmake package lookup). venv/bin is included for nrfutil.
export PATH="$GIT_SHIM:$TC_DIR/usr/local/bin:$TC_DIR/usr/bin:$PROJECT_ROOT/venv/bin:/usr/local/bin:/usr/bin:$PATH"
export LD_LIBRARY_PATH="$TC_DIR/usr/local/lib:$TC_DIR/usr/lib:${LD_LIBRARY_PATH:-}"
export ZEPHYR_TOOLCHAIN_VARIANT=zephyr
export ZEPHYR_SDK_INSTALL_DIR="$SDK_DIR"

if [ "$DO_CLEAN" = "1" ]; then
    echo "--- Cleaning $BUILD_DIR"
    rm -rf "$BUILD_DIR"
fi

echo "--- Building for $BOARD (cmake/west)"
cd "$ZEPHYR_WS"
west build \
    -b "$BOARD" \
    --source-dir "$SOURCE_DIR" \
    -d "$BUILD_DIR" \
    ${EXTRA_ARGS:+-- $EXTRA_ARGS}

# The single-image build leaves the image at build/zephyr/; the
# build/firmware/zephyr/ location is what a multi-image (sysbuild) build used to
# produce. Probe both — an existing build tree from before the mcuboot tier was
# dropped still has the old layout.
if [ -f "$BUILD_DIR/firmware/zephyr/zephyr.uf2" ]; then
    UF2_PATH="$BUILD_DIR/firmware/zephyr/zephyr.uf2"
elif [ -f "$BUILD_DIR/zephyr/zephyr.uf2" ]; then
    UF2_PATH="$BUILD_DIR/zephyr/zephyr.uf2"
else
    echo "error: no zephyr.uf2 found under $BUILD_DIR" >&2
    exit 1
fi

echo "--- Build complete: $UF2_PATH"

[ "$DO_FLASH" = "1" ] && flash_uf2 "$UF2_PATH"

exit 0
