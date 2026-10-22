#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Build and install a host wolfSSL for libcantil's WOLFSSL X.509 backend.
#
# Only needed if you build the client with -DCANTIL_HOST_CRYPTO=wolfssl.  The
# default backend is openssl, which almost every Linux host already has
# (openssl-devel), so the CLI builds with no extra setup.  wolfSSL is *not*
# packaged by Fedora (`rpm-ostree search wolfssl` finds nothing), which is why
# this exists — use it when you want the client to share the firmware's library.
#
# Usage:
#   ./scripts/setup_wolfssl_host.sh
#   cmake -B build_host -DCANTIL_HOST_CRYPTO=wolfssl libcantil
#
# Environment:
#   CANTIL_WOLFSSL_PREFIX  Install prefix (default: $HOME/.local)
#   CANTIL_WOLFSSL_SRC     Source tree to build from.  Defaults to the copy
#                          west already fetched into the Zephyr workspace, so
#                          host and firmware are guaranteed to be the same
#                          revision.  Falls back to a shallow clone.
#   CANTIL_ZEPHYR_WS       Zephyr workspace (default: $HOME/zephyr/cantil)
#
# Idempotent: re-run after moving the west.yml pin to rebuild against it.
#
# Built with CMake rather than autotools deliberately: the checkout has no
# ./configure (it is a git tree, not a release tarball), regenerating one
# needs libtool, and this host has autoconf/automake but no libtool.

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

PREFIX="${CANTIL_WOLFSSL_PREFIX:-$HOME/.local}"
WS="${CANTIL_ZEPHYR_WS:-$HOME/zephyr/cantil}"

# Single source of truth for the version: firmware/west.yml.  A host wolfSSL
# that disagrees with the firmware's would let a DER incompatibility hide.
#
# Anchored on `remote: wolfssl`, not `name: wolfssl`: the manifest also has a
# *remote* by that name declared above the projects, and a range starting there
# runs into the Zephyr project block and returns Zephyr's revision instead.
PIN="$(sed -n '/remote: wolfssl/,/path: modules\/crypto\/wolfssl/s/.*revision: *//p' \
        "$PROJECT_ROOT/firmware/west.yml" | head -1)"
if [ -z "$PIN" ]; then
    echo "error: could not read the wolfssl revision from firmware/west.yml" >&2
    exit 1
fi
echo "--- wolfSSL pin from firmware/west.yml: $PIN"

SRC="${CANTIL_WOLFSSL_SRC:-$WS/modules/crypto/wolfssl}"

if [ ! -f "$SRC/CMakeLists.txt" ]; then
    echo "--- no wolfSSL source at $SRC, cloning $PIN"
    SRC="$PROJECT_ROOT/build_wolfssl_host/src"
    if [ ! -d "$SRC" ]; then
        mkdir -p "$(dirname "$SRC")"
        git clone --depth 1 --branch "$PIN" \
            https://github.com/wolfSSL/wolfssl "$SRC"
    fi
else
    echo "--- building from the west workspace copy: $SRC"
fi

BUILD="$PROJECT_ROOT/build_wolfssl_host/build"

# Out-of-tree: never write into the west workspace, since `west update` owns it
# and an in-tree build would show up as local modifications there.
rm -rf "$BUILD"
mkdir -p "$BUILD"

# The option set is the host mirror of firmware/include/cantil_wolfssl_user_settings.h,
# with two deliberate differences:
#
#   - Not WOLFCRYPT_ONLY.  libcantil verifies certificate *chains*, and
#     wolfSSL's chain walker (wolfSSL_CertManager*) lives above wolfCrypt in
#     the TLS layer.  There is no wolfCrypt-only chain verifier.
#   - Cert *generation* is off.  The host only reads certificates; the device
#     is the CA.  (The firmware has it on — that is the asymmetry.)
#
# TLS itself is unused but comes with the CertManager; it costs disk, not
# runtime, and cutting it out is not worth diverging from a stock build.
# CMAKE_INSTALL_LIBDIR=lib is not cosmetic.  On a 64-bit Fedora, CMake's
# GNUInstallDirs defaults to lib64 and wolfSSL installs libwolfssl.a there —
# but the wolfssl.pc it generates hardcodes `libdir=${exec_prefix}/lib`.
# pkg-config then reports a -L that contains no library and the link dies with
# "cannot find -lwolfssl".  Forcing both to lib makes the .pc true.
cmake -S "$SRC" -B "$BUILD" -G Ninja \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX="$PREFIX" \
    -DCMAKE_INSTALL_LIBDIR=lib \
    -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
    -DBUILD_SHARED_LIBS=OFF \
    -DWOLFSSL_ECC=yes \
    -DWOLFSSL_KEYGEN=yes \
    -DWOLFSSL_CERTGEN=no \
    -DWOLFSSL_CERTEXT=yes \
    -DWOLFSSL_RSA=no \
    -DWOLFSSL_DH=no \
    -DWOLFSSL_EXAMPLES=no \
    -DWOLFSSL_CRYPT_TESTS=no \
    -DWOLFSSL_HARDEN=yes

cmake --build "$BUILD"
cmake --install "$BUILD"

# Verify what actually landed, rather than trusting that the source tree was at
# the pin.  When SRC is the west workspace it is whatever `west update` last
# left there, which is only the pin if the workspace is in sync.
INSTALLED="$(PKG_CONFIG_PATH="$PREFIX/lib64/pkgconfig:$PREFIX/lib/pkgconfig:$PKG_CONFIG_PATH" \
             pkg-config --modversion wolfssl 2>/dev/null || echo "unknown")"
WANT="$(echo "$PIN" | sed -e 's/^v//' -e 's/-stable$//')"
if [ "$INSTALLED" != "$WANT" ]; then
    echo >&2
    echo "warning: installed wolfSSL $INSTALLED does not match the west.yml pin $WANT" >&2
    echo "         ($SRC is not at $PIN — run 'west update' in $WS, or set" >&2
    echo "          CANTIL_WOLFSSL_SRC to a tree that is)" >&2
    echo "         Host and firmware disagreeing on wolfSSL can hide a DER bug." >&2
fi

echo
echo "--- wolfSSL $INSTALLED installed to $PREFIX"
echo
echo "Add the prefix to pkg-config if it is not already there:"
echo "    export PKG_CONFIG_PATH=$PREFIX/lib64/pkgconfig:$PREFIX/lib/pkgconfig:\$PKG_CONFIG_PATH"
echo
echo "Then build the client against it:"
echo "    cmake -B build_host -DCANTIL_HOST_CRYPTO=wolfssl libcantil"
echo "    cmake --build build_host"
