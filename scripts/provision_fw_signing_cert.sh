#!/bin/sh
# Provision a firmware code-signing leaf cert signed by the Cantil on-device CA.
#
# What it does:
#   1. Generates an EC P-256 keypair on the host (for use with imgtool).
#   2. Creates a CSR with an appropriate subject DN.
#   3. Submits the CSR to the Cantil device (slot 0 CA) and retrieves the cert.
#   4. Saves key, cert, and CA cert to OUT_DIR (defaults to ~/.cantil/firmware-signing/).
#
# Prerequisites:
#   - cantil CLI built: cd libcantil && cmake -B build_static -DCANTIL_CLI_STATIC=ON . && cmake --build build_static
#   - Device paired (run 'cantil pair <port>' first)
#   - Device CA provisioned (slot 0 has a cert — run 'cantil provision-ca' first)
#   - Device UNLOCKED (tap the unlock sequence before running this)
#   - openssl available on the host
#
# Usage:
#   ./scripts/provision_fw_signing_cert.sh [--port <port>] [--out <dir>]
#                                          [--cn <CN>] [--issuer-slot <n>]
#
# Options:
#   --port         USB port for the Cantil device (default: auto-detect /dev/ttyACM0)
#   --out          Output directory (default: ~/.cantil/firmware-signing)
#   --cn           Certificate CN (default: "Cantil Firmware Signing")
#   --issuer-slot  On-device CA slot to sign with (default: 0)
#
# imgtool usage after provisioning:
#   imgtool sign \
#     --key ~/.cantil/firmware-signing/fw_signing.key.pem \
#     --version X.Y.Z --align 4 --slot-size 0xF0000 \
#     zephyr.bin zephyr.signed.bin

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

PORT=""
OUT_DIR="$HOME/.cantil/firmware-signing"
CN="Cantil Firmware Signing"
ISSUER_SLOT=0

usage() {
    cat <<EOF
Usage: $(basename "$0") [OPTIONS]

Provision a firmware code-signing leaf cert signed by the Cantil on-device CA.

What it does:
  1. Generates an EC P-256 keypair on the host (for use with imgtool).
  2. Creates a CSR with an appropriate subject DN.
  3. Submits the CSR to the Cantil device CA and retrieves the signed cert.
  4. Saves the key, cert, and CA cert to OUT_DIR.

Prerequisites:
  - cantil CLI built: cd libcantil && cmake -B build_static -DCANTIL_CLI_STATIC=ON . && cmake --build build_static
  - Device paired (run 'cantil pair <port>' first)
  - Device CA provisioned (slot 0 has a cert — run 'cantil provision-ca' first)
  - Device UNLOCKED (tap the unlock sequence before running this)
  - openssl available on the host

Options:
  --port <port>       USB port for the Cantil device (default: auto-detect /dev/ttyACM*)
  --out <dir>         Output directory (default: ~/.cantil/firmware-signing)
  --cn <CN>           Certificate CN (default: "Cantil Firmware Signing")
  --issuer-slot <n>   On-device CA slot to sign with (default: 0)
  --help              Show this help message and exit

Output files (stored in OUT_DIR, mode 700):
  fw_signing.key.pem  EC P-256 private key — pass to 'imgtool --key'
  fw_signing.cert.pem Signed leaf cert (PEM)
  fw_signing.cert.der Signed leaf cert (DER)
  ca.cert.pem         Device CA root cert (PEM)
  ca.cert.der         Device CA root cert (DER)

imgtool usage after provisioning:
  imgtool sign \\
    --key ~/.cantil/firmware-signing/fw_signing.key.pem \\
    --version X.Y.Z --align 4 --slot-size 0xF0000 \\
    zephyr.bin zephyr.signed.bin
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --port)         PORT="$2";         shift 2 ;;
        --out)          OUT_DIR="$2";      shift 2 ;;
        --cn)           CN="$2";           shift 2 ;;
        --issuer-slot)  ISSUER_SLOT="$2";  shift 2 ;;
        --help)         usage; exit 0 ;;
        *) echo "Unknown option: $1" >&2; usage >&2; exit 1 ;;
    esac
done

# Locate the cantil binary. Prefer the static build (no host-lib deps) so the
# binary can run via flatpak-spawn --host without needing container libraries.
CANTIL=""
for candidate in \
    "$PROJECT_ROOT/libcantil/build_static/cantil" \
    "$PROJECT_ROOT/libcantil/build/cantil" \
    "$PROJECT_ROOT/libcantil/build_host/cantil"; do
    if [ -x "$candidate" ]; then
        CANTIL="$candidate"
        break
    fi
done
if [ -z "$CANTIL" ]; then
    echo "error: cantil binary not found. Build it first:" >&2
    echo "  cd libcantil && cmake -B build_static -DCANTIL_CLI_STATIC=ON . && cmake --build build_static" >&2
    exit 1
fi

# When running inside a flatpak sandbox the host USB devices are only reachable
# via flatpak-spawn --host.  Detect the sandbox and wrap cantil accordingly.
if [ -n "$FLATPAK_ID" ] || [ -f "/.flatpak-info" ]; then
    _CANTIL_RUN="flatpak-spawn --host"
else
    _CANTIL_RUN=""
fi
run_cantil() { $_CANTIL_RUN "$CANTIL" "$@"; }

# Auto-detect port if not given.
if [ -z "$PORT" ]; then
    for dev in /dev/ttyACM0 /dev/ttyACM1 /dev/ttyACM2; do
        [ -c "$dev" ] && PORT="$dev" && break
    done
    if [ -z "$PORT" ]; then
        echo "error: no /dev/ttyACM* found. Plug in the Cantil device." >&2
        exit 1
    fi
    echo "--- Auto-detected port: $PORT"
fi

# Check openssl.
if ! command -v openssl >/dev/null 2>&1; then
    echo "error: openssl not found in PATH" >&2
    exit 1
fi

# Create output dir with restricted permissions.
mkdir -p "$OUT_DIR"
chmod 700 "$OUT_DIR"
echo "--- Output directory: $OUT_DIR"

KEY_PEM="$OUT_DIR/fw_signing.key.pem"
CSR_PEM="$OUT_DIR/fw_signing.csr.pem"
CSR_DER="$OUT_DIR/fw_signing.csr.der"
CERT_DER="$OUT_DIR/fw_signing.cert.der"
CERT_PEM="$OUT_DIR/fw_signing.cert.pem"
CA_DER="$OUT_DIR/ca.cert.der"
CA_PEM="$OUT_DIR/ca.cert.pem"

# Step 1: Generate EC P-256 private key (unencrypted — imgtool needs raw access).
if [ -f "$KEY_PEM" ]; then
    echo "--- $KEY_PEM already exists — skipping key generation (delete it to regenerate)"
else
    echo "--- Generating EC P-256 private key..."
    openssl ecparam -genkey -name prime256v1 -noout -out "$KEY_PEM"
    chmod 600 "$KEY_PEM"
    echo "--- Key written: $KEY_PEM"
fi

# Step 2: Generate a CSR from the key.
echo "--- Generating CSR (CN='$CN')..."
openssl req -new \
    -key "$KEY_PEM" \
    -out "$CSR_PEM" \
    -subj "/CN=$CN/O=Cantil/OU=Firmware Signing"

# Convert CSR to DER (the cantil CLI takes DER).
openssl req -in "$CSR_PEM" -outform DER -out "$CSR_DER"
echo "--- CSR written: $CSR_DER"

# Step 3: Submit the CSR to the Cantil device and capture the signed cert.
echo "--- Sending CSR to device (slot $ISSUER_SLOT) on $PORT..."
echo "    (Device must be UNLOCKED)"
CERT_HEX="$(run_cantil sign-csr-slot "$ISSUER_SLOT" "$CSR_DER" "$PORT")"

if [ -z "$CERT_HEX" ]; then
    echo "error: sign-csr-slot returned empty output" >&2
    exit 1
fi

# Decode hex → binary. Prefer xxd, fall back to python3 (xxd absent on some distros).
hex_to_bin() {
    if command -v xxd >/dev/null 2>&1; then
        xxd -r -p
    else
        python3 -c "import sys,binascii; sys.stdout.buffer.write(binascii.unhexlify(sys.stdin.read().strip()))"
    fi
}

# sign-csr-slot prints info to stderr and the hex cert to stdout.
printf '%s' "$CERT_HEX" | hex_to_bin > "$CERT_DER"
echo "--- Signed cert written: $CERT_DER"

# Convert to PEM for convenience (imgtool can use either).
openssl x509 -inform DER -in "$CERT_DER" -out "$CERT_PEM"
echo "--- Cert PEM written: $CERT_PEM"

# Step 4: Fetch the CA cert for chain reference (key-chain returns leaf-first DER chain;
# for a self-signed root the chain is a single cert, so we take the first cert in the
# chain.  Split out the first DER cert with openssl x509 -inform DER -out).
echo "--- Fetching CA cert from device (slot $ISSUER_SLOT)..."
CA_CHAIN_TMP="$OUT_DIR/.ca_chain.der"
if run_cantil key-chain "$ISSUER_SLOT" "$PORT" | hex_to_bin > "$CA_CHAIN_TMP" 2>/dev/null; then
    # Extract only the first (leaf / self-signed root) cert from the chain blob.
    openssl x509 -inform DER -in "$CA_CHAIN_TMP" -out "$CA_PEM" 2>/dev/null && \
        openssl x509 -in "$CA_PEM" -outform DER -out "$CA_DER" 2>/dev/null
    rm -f "$CA_CHAIN_TMP"
    echo "--- CA cert written: $CA_DER / $CA_PEM"
else
    echo "warning: could not fetch CA cert (non-fatal)" >&2
    rm -f "$CA_CHAIN_TMP"
fi

# Summary.
echo ""
echo "=== Firmware signing cert provisioned ==="
echo ""
echo "Private key:  $KEY_PEM"
echo "Signed cert:  $CERT_PEM"
echo "CA cert:      $CA_PEM"
echo ""
echo "Cert details:"
openssl x509 -in "$CERT_PEM" -noout -subject -issuer -dates -fingerprint -sha256
echo ""
echo "imgtool usage:"
echo "  imgtool sign \\"
echo "    --key $KEY_PEM \\"
echo "    --version 1.0.0 --align 4 --slot-size 0xF0000 \\"
echo "    build/firmware/zephyr/zephyr.bin build/firmware/zephyr/zephyr.signed.bin"
