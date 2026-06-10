#!/usr/bin/env bash
#
# build-appimage.sh — build the cantil CLI as a self-contained AppImage.
#
# What this produces:
#   cantil-<arch>.AppImage at the repo root — a single executable that runs on
#   any modern Linux distro with glibc >= the build host's glibc, no install
#   step required.
#
# How it works:
#   1. Builds libcantil + cantil-cli with -DCANTIL_CLI_STATIC=ON, which
#      statically links libsodium into the binary. The only remaining runtime
#      dependency is glibc.
#   2. Stages an AppDir containing the binary, an AppRun launcher, a
#      .desktop file, and an icon.
#   3. Downloads upstream appimagetool to build/appimage/.cache/ on first run.
#   4. Runs appimagetool against the AppDir.
#
# Build environment:
#   Run inside the ubuntu2604 distrobox (the project's standard build env).
#   The wrapper handles that:
#       ./scripts/dbox.sh bash scripts/build-appimage.sh
#
# Host requirements (inside the distrobox):
#   - cmake, a C compiler, pkg-config, libsodium + libsodium-dev (with
#     static archive). Already required for the regular CLI build.
#   - python3 — used to generate a placeholder icon (stdlib only, no PIL).
#   - curl, file — used to fetch and verify appimagetool.
#
# Override the icon by placing a 256x256 PNG at contrib/cantil-icon.png
# before running this script.

set -euo pipefail

REPO_ROOT=$(cd "$(dirname "$0")/.." && pwd)
LIBCANTIL=$REPO_ROOT/libcantil
BUILD_DIR=$REPO_ROOT/build/appimage
APPDIR=$BUILD_DIR/AppDir
CACHE_DIR=$BUILD_DIR/.cache
ICON_SRC=$REPO_ROOT/contrib/cantil-icon.png

ARCH=$(uname -m)
APPIMAGETOOL_URL="https://github.com/AppImage/appimagetool/releases/download/continuous/appimagetool-${ARCH}.AppImage"
APPIMAGETOOL=$CACHE_DIR/appimagetool.AppImage

OUTPUT=$REPO_ROOT/cantil-${ARCH}.AppImage

log()  { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
fail() { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

# ── 1. Build static CLI ────────────────────────────────────────────────────
log "Configuring (static libsodium link)"
mkdir -p "$BUILD_DIR/build"
cmake -S "$LIBCANTIL" -B "$BUILD_DIR/build" \
    -DCANTIL_CLI_STATIC=ON \
    -DCMAKE_BUILD_TYPE=Release \
    > "$BUILD_DIR/cmake-configure.log"

log "Building cantil-cli"
cmake --build "$BUILD_DIR/build" --target cantil-cli -j \
    > "$BUILD_DIR/cmake-build.log"

CANTIL_BIN=$BUILD_DIR/build/cantil
[ -x "$CANTIL_BIN" ] || fail "build did not produce $CANTIL_BIN"

# Make sure the static link actually worked. Anything beyond glibc / linux-vdso
# / ld-linux is a leak that would break the AppImage on other distros.
log "Verifying static link"
if ldd "$CANTIL_BIN" 2>&1 | grep -Eqv 'linux-vdso|ld-linux|libc\.so|libm\.so|libpthread\.so|libdl\.so|librt\.so|libresolv\.so|not a dynamic executable'; then
    echo "ldd output:" >&2
    ldd "$CANTIL_BIN" >&2
    fail "binary has non-glibc dynamic dependencies; static link incomplete"
fi

# ── 2. Stage AppDir ────────────────────────────────────────────────────────
log "Staging AppDir at $APPDIR"
rm -rf "$APPDIR"
mkdir -p "$APPDIR/usr/bin"
install -m 755 "$CANTIL_BIN" "$APPDIR/usr/bin/cantil"

# .desktop file. Terminal=true because the CLI doesn't open a window.
cat > "$APPDIR/cantil.desktop" <<'EOF'
[Desktop Entry]
Type=Application
Name=Cantil
GenericName=Hardware CA CLI
Comment=Command-line client for the Cantil hardware Certificate Authority
Exec=cantil
Icon=cantil
Terminal=true
Categories=Utility;Security;
EOF

# AppRun launcher. exec the binary with all forwarded args, plus a PATH that
# finds it inside the mounted AppImage.
cat > "$APPDIR/AppRun" <<'EOF'
#!/bin/sh
HERE=$(dirname "$(readlink -f "$0")")
export PATH="$HERE/usr/bin:$PATH"
exec "$HERE/usr/bin/cantil" "$@"
EOF
chmod 755 "$APPDIR/AppRun"

# Icon. Use the committed one if present; otherwise generate a flat-colour
# placeholder via a stdlib-only Python PNG writer. The user can replace it
# with a real 256x256 PNG at contrib/cantil-icon.png whenever they want.
if [ -f "$ICON_SRC" ]; then
    log "Using existing icon $ICON_SRC"
    cp "$ICON_SRC" "$APPDIR/cantil.png"
else
    log "Generating placeholder icon (256x256 flat colour)"
    command -v python3 > /dev/null \
        || fail "python3 not found; install it, or commit a 256x256 PNG at contrib/cantil-icon.png"
    python3 - "$APPDIR/cantil.png" <<'PY'
import struct, sys, zlib
path = sys.argv[1]
w = h = 256
r, g, b = 0x1a, 0x1a, 0x2e  # deep navy, matches marketing palette stub
sig = b'\x89PNG\r\n\x1a\n'
def chunk(name, data):
    crc = zlib.crc32(name + data) & 0xffffffff
    return struct.pack('>I', len(data)) + name + data + struct.pack('>I', crc)
ihdr = struct.pack('>IIBBBBB', w, h, 8, 2, 0, 0, 0)  # 8-bit truecolour
row  = b'\x00' + bytes([r, g, b]) * w                # filter byte + pixels
idat = zlib.compress(row * h, 9)
with open(path, 'wb') as f:
    f.write(sig + chunk(b'IHDR', ihdr) + chunk(b'IDAT', idat) + chunk(b'IEND', b''))
PY
fi

# ── 3. Fetch appimagetool ─────────────────────────────────────────────────
mkdir -p "$CACHE_DIR"
if [ ! -x "$APPIMAGETOOL" ]; then
    log "Fetching appimagetool ($ARCH)"
    command -v curl > /dev/null || fail "curl not found"
    curl -fL --progress-bar "$APPIMAGETOOL_URL" -o "$APPIMAGETOOL.partial"
    chmod +x "$APPIMAGETOOL.partial"
    mv "$APPIMAGETOOL.partial" "$APPIMAGETOOL"
fi

# ── 4. Build the AppImage ─────────────────────────────────────────────────
log "Running appimagetool"
# --appimage-extract-and-run avoids needing FUSE inside containers.
ARCH="$ARCH" "$APPIMAGETOOL" --appimage-extract-and-run \
    "$APPDIR" "$OUTPUT" \
    > "$BUILD_DIR/appimagetool.log" 2>&1 \
    || { cat "$BUILD_DIR/appimagetool.log"; fail "appimagetool failed"; }

log "Built $OUTPUT"
ls -lh "$OUTPUT"
