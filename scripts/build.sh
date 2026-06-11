#!/bin/sh
# Build (and optionally flash) the firmware.
#
# Usage:
#   ./scripts/build.sh [options]
#
# Options:
#   -b BOARD            Zephyr board target (default: xiao_ble/nrf52840/sense)
#   -d BUILD_DIR        Build output directory (default: build/)
#   --flash             Copy the UF2 to every XIAO-SENSE* drive that mounts.
#                       Double-tap reset to enter UF2 mode before running, or
#                       if a drive is already mounted the copy happens directly.
#                       Not supported for mcuboot (no UF2 bootloader).
#   --clean             Delete BUILD_DIR before building
#   --accelerated       Layer in firmware/prj_accelerated.conf (Oberon + CC3XX
#                       via nrf_security / PSA).  Selecting this backend pulls
#                       in proprietary Nordic crypto; see LICENSE-EXCEPTIONS.md.
#   --bootloader TIER   Select bootloader tier (default: uf2_only):
#                         uf2_only      — Adafruit UF2 only, no MCUboot (default)
#                         mcuboot       — MCUboot only, dual internal slots,
#                                         no UF2 (production / maximum security)
#                       Sets FILE_SUFFIX and PM_STATIC_YML_FILE accordingly.
#   --signing-key PATH  Absolute path to EC P-256 PEM private key for MCUboot
#                       tiers.  Required for mcuboot.
#                       Sets CANTIL_FW_SIGNING_KEY_PATH and passes the public
#                       key to MCUboot via SB_CONFIG_BOOT_SIGNATURE_KEY_FILE.
#   -- ARGS             Extra arguments passed to west build / CMake
#
# Examples:
#   ./scripts/build.sh
#   ./scripts/build.sh -b nrf52840dk/nrf52840
#   ./scripts/build.sh --flash
#   ./scripts/build.sh --accelerated
#   ./scripts/build.sh --bootloader mcuboot \
#       --signing-key ~/.cantil/firmware-signing/fw_signing.key.pem
#
# Requires the NCS v3.0.2 workspace at $HOME/ncs/v3.0.2.
# Run from inside the ubuntu2604 distrobox or via dbox.sh.

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
FIRMWARE_DIR="$PROJECT_ROOT/firmware"
NCS_DIR="$HOME/ncs/v3.0.2"
TC_DIR="$HOME/ncs/toolchains/7cbc0036f4"
# Drive(s) the Adafruit UF2 bootloader presents.  Multiple XIAO-SENSE*
# mounts (XIAO-SENSE, XIAO-SENSE1, …) appear when more than one unit is
# in DFU at once; the --flash step copies to every matching drive.
UF2_MOUNT_GLOB="/run/media/$USER/XIAO-SENSE*"

BOARD="xiao_ble/nrf52840/sense"
BUILD_DIR="$PROJECT_ROOT/build"
DO_FLASH=0
DO_CLEAN=0
DO_ACCELERATED=0
BOOTLOADER_TIER="uf2_only"
SIGNING_KEY=""
EXTRA_ARGS=""

while [ $# -gt 0 ]; do
    case "$1" in
        -b) BOARD="$2"; shift 2 ;;
        -d) BUILD_DIR="$2"; shift 2 ;;
        --flash) DO_FLASH=1; shift ;;
        --clean) DO_CLEAN=1; shift ;;
        --accelerated) DO_ACCELERATED=1; shift ;;
        --bootloader) BOOTLOADER_TIER="$2"; shift 2 ;;
        --signing-key) SIGNING_KEY="$2"; shift 2 ;;
        --) shift; EXTRA_ARGS="$*"; break ;;
        *) echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

if [ "$DO_ACCELERATED" = "1" ]; then
    if [ -n "$EXTRA_ARGS" ]; then
        EXTRA_ARGS="-DEXTRA_CONF_FILE=prj_accelerated.conf $EXTRA_ARGS"
    else
        EXTRA_ARGS="-DEXTRA_CONF_FILE=prj_accelerated.conf"
    fi
    echo "--- Accelerated backend selected (Oberon + CC3XX via PSA)"
fi

case "$BOOTLOADER_TIER" in
    uf2_only)
        ;;
    mcuboot)
        if [ -z "$SIGNING_KEY" ]; then
            echo "error: --bootloader $BOOTLOADER_TIER requires --signing-key <path>" >&2
            echo "  Example: --signing-key ~/.cantil/firmware-signing/fw_signing.key.pem" >&2
            exit 1
        fi
        if [ ! -f "$SIGNING_KEY" ]; then
            echo "error: signing key not found: $SIGNING_KEY" >&2
            exit 1
        fi
        echo "--- Bootloader tier: $BOOTLOADER_TIER  key: $SIGNING_KEY"
        # Kconfig string values must be delivered via conf snippets (quoted) rather
        # than raw -D flags, which Kconfig rejects as malformed string literals.
        SIGNING_SB_CONF=$(mktemp /tmp/cantil_sb_XXXXXX.conf)
        trap 'rm -f "$SIGNING_SB_CONF"' EXIT
        # Sysbuild conf: enable MCUboot + Partition Manager + signing key.
        # PARTITION_MANAGER is not auto-selected by BOOTLOADER_MCUBOOT; it must be
        # set explicitly so the NCS sysbuild PM runs before image cmake configures.
        # SB_CONFIG_BOOT_SIGNATURE_KEY_FILE is passed to MCUboot (public key embed)
        # and propagated to firmware as CONFIG_MCUBOOT_SIGNATURE_KEY_FILE so that
        # NCS's image_signing.cmake handles the post-link signing correctly.
        printf 'SB_CONFIG_BOOTLOADER_MCUBOOT=y\nSB_CONFIG_PARTITION_MANAGER=y\nSB_CONFIG_BOOT_SIGNATURE_KEY_FILE="%s"\n' \
            "$SIGNING_KEY" > "$SIGNING_SB_CONF"
        # PM static file: partition_manager.cmake reads PM_STATIC_YML_FILE from the
        # sysbuild GLOBAL cmake cache via zephyr_get(...SYSBUILD GLOBAL), so it must
        # be passed at the sysbuild cmake level, not inside the firmware CMakeLists.
        # Derive the path from the board name (/ → _) and bootloader tier.
        BOARD_NORM=$(echo "$BOARD" | tr '/' '_')
        PM_STATIC_YML="$FIRMWARE_DIR/pm_static_${BOARD_NORM}_${BOOTLOADER_TIER}.yml"
        if [ ! -f "$PM_STATIC_YML" ]; then
            echo "error: PM static file not found: $PM_STATIC_YML" >&2
            exit 1
        fi
        EXTRA_ARGS="-DFILE_SUFFIX=$BOOTLOADER_TIER \
-DSB_EXTRA_CONF_FILE=$SIGNING_SB_CONF \
-DPM_STATIC_YML_FILE=$PM_STATIC_YML \
${EXTRA_ARGS}"
        ;;
    *)
        echo "error: unknown bootloader tier: $BOOTLOADER_TIER" >&2
        echo "  Valid: uf2_only  mcuboot" >&2
        exit 1
        ;;
esac

if [ ! -d "$NCS_DIR/.west" ]; then
    echo "error: NCS workspace not found at $NCS_DIR" >&2
    echo "Run: ./scripts/dbox.sh bash (then west update in $NCS_DIR)" >&2
    exit 1
fi

# Put system git first so git-remote-https is available; toolchain compilers come after.
export PATH="/usr/local/bin:/usr/bin:$TC_DIR/usr/local/bin:$TC_DIR/usr/bin:$PATH"
export LD_LIBRARY_PATH="$TC_DIR/usr/local/lib:$TC_DIR/usr/lib:${LD_LIBRARY_PATH:-}"
export ZEPHYR_TOOLCHAIN_VARIANT=gnuarmemb
export GNUARMEMB_TOOLCHAIN_PATH=/usr

if [ "$DO_CLEAN" = "1" ]; then
    echo "--- Cleaning $BUILD_DIR"
    rm -rf "$BUILD_DIR"
fi

echo "--- Building for $BOARD"
cd "$NCS_DIR"
west build \
    -b "$BOARD" \
    --source-dir "$FIRMWARE_DIR" \
    -d "$BUILD_DIR" \
    ${EXTRA_ARGS:+-- $EXTRA_ARGS}

# Sysbuild puts the image at build/firmware/zephyr/, the legacy single-image
# build leaves it at build/zephyr/. Probe whichever exists so --flash works
# under both layouts (NCS v3.0.2 defaults to sysbuild).
#
# mcuboot produces no UF2 (no UF2 bootloader); its deploy artifact is
# merged.hex (MCUboot + signed firmware, flashed via nrfjprog/JLink).
if [ "$BOOTLOADER_TIER" = "mcuboot" ]; then
    MERGED_HEX="$BUILD_DIR/merged.hex"
    if [ ! -f "$MERGED_HEX" ]; then
        echo "error: no merged.hex found under $BUILD_DIR" >&2
        exit 1
    fi
    echo "--- Build complete: $MERGED_HEX"
    if [ "$DO_FLASH" = "1" ]; then
        echo "error: --flash is not supported for mcuboot (no UF2 bootloader)" >&2
        echo "Flash merged.hex via nrfjprog, JLink, or cantil update-firmware." >&2
        exit 1
    fi
    exit 0
fi

if [ -f "$BUILD_DIR/firmware/zephyr/zephyr.uf2" ]; then
    UF2_PATH="$BUILD_DIR/firmware/zephyr/zephyr.uf2"
elif [ -f "$BUILD_DIR/zephyr/zephyr.uf2" ]; then
    UF2_PATH="$BUILD_DIR/zephyr/zephyr.uf2"
else
    echo "error: no zephyr.uf2 found under $BUILD_DIR" >&2
    exit 1
fi

echo "--- Build complete: $UF2_PATH"

if [ "$DO_FLASH" = "1" ]; then
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
        cp "$UF2_PATH" "$mount/"
        sync
    done
    echo "--- Done — device(s) will reset and boot the new firmware."
fi
