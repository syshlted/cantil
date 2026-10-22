#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Fetch Nordic's CC310 crypto blobs (OPTIONAL, opt-in hardware acceleration).
#
# Cantil ships no binary blobs and does not need one. The default build is
# fully open source and software-only. This script exists so that users who
# deliberately choose CC310 acceleration can obtain the blob themselves,
# having been shown the license terms first.
#
# The blob is fetched into third_party/nrfxlib/ which is gitignored — it is
# never committed to this repository.
#
# Usage:
#   scripts/fetch_cc310_blob.sh                 Show license, prompt, fetch
#   scripts/fetch_cc310_blob.sh --print-license Show license only, fetch nothing
#   scripts/fetch_cc310_blob.sh --yes           Skip the prompt (CI)
#
# See docs/crypto-blobs.md for the licensing analysis.

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
DEST="$PROJECT_ROOT/third_party/nrfxlib"
NRFXLIB_URL="https://github.com/nrfconnect/sdk-nrfxlib"
# Pin rather than tracking main, so a fetch is reproducible. Bump deliberately.
NRFXLIB_REF="v3.0.2"

ASSUME_YES=0
PRINT_ONLY=0

while [ $# -gt 0 ]; do
    case "$1" in
        --yes|-y)        ASSUME_YES=1; shift ;;
        --print-license) PRINT_ONLY=1; shift ;;
        -h|--help)       sed -n '2,20p' "$0"; exit 0 ;;
        *) echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

print_license_summary() {
    cat <<'EOF'
────────────────────────────────────────────────────────────────────────
  Nordic CC310 crypto blobs — LicenseRef-Nordic-5-Clause
  THIS IS NOT A FREE SOFTWARE LICENSE.
────────────────────────────────────────────────────────────────────────

  Two clauses materially restrict what you may do:

    4. This software, with or without modification, must only be used
       with a Nordic Semiconductor ASA integrated circuit.

    5. Any software provided in binary form under this license must not
       be reverse engineered, decompiled, modified and/or disassembled.

  Consequences of enabling CC310 in your build:

    * Your firmware is no longer fully open source.
    * It may only be used with Nordic silicon (clause 4).
    * Redistribution requires reproducing Nordic's notice and license.
    * Recipients inherit clauses 4 and 5; your Apache 2.0 grant no
      longer describes what they may do with the binary.
    * The build is no longer portable to non-Nordic targets.

  You do not need this. The default software-only build is correct,
  portable, and fast enough for Cantil's workload. CC310 saves
  milliseconds on operations gated behind seconds of human input.

  Full terms: docs/crypto-blobs.md
              third_party/nrfxlib/crypto/nrf_cc310_platform/license.txt
              (after fetching)
────────────────────────────────────────────────────────────────────────
EOF
}

print_license_summary

if [ "$PRINT_ONLY" = "1" ]; then
    exit 0
fi

if [ -d "$DEST/.git" ]; then
    echo "nrfxlib already present at $DEST — nothing to do."
    echo "Remove it and re-run to re-fetch."
    exit 0
fi

if [ "$ASSUME_YES" != "1" ]; then
    printf '\nType "I accept the Nordic license" to fetch, anything else to abort: '
    read -r reply
    if [ "$reply" != "I accept the Nordic license" ]; then
        echo "Aborted. No blob fetched. The default build needs nothing further."
        exit 1
    fi
fi

command -v git >/dev/null 2>&1 || { echo "error: git not found" >&2; exit 1; }

echo "--- Fetching sdk-nrfxlib ($NRFXLIB_REF) into $DEST"
mkdir -p "$(dirname "$DEST")"
git clone --depth 1 --branch "$NRFXLIB_REF" "$NRFXLIB_URL" "$DEST"

CC310_LIB_DIR="$DEST/crypto/nrf_cc310_platform/lib/cortex-m4/hard-float"
if [ ! -d "$CC310_LIB_DIR" ]; then
    echo "warning: expected CC310 libraries not found at:" >&2
    echo "  $CC310_LIB_DIR" >&2
    echo "The nrfxlib layout may have changed for ref $NRFXLIB_REF." >&2
    exit 1
fi

cat <<EOF

--- Done.

Libraries:  $CC310_LIB_DIR
License:    $DEST/crypto/nrf_cc310_platform/license.txt

This directory is gitignored and will not be committed.

To build with CC310 you must ALSO opt in via Kconfig — the blob being
present is deliberately not sufficient:

    CONFIG_CANTIL_CRYPTO_HW_CC310=y
    CONFIG_CANTIL_CRYPTO_HW_CC310_I_ACCEPT_NORDIC_LICENSE=y

Status: SPIKE. Not a supported configuration. See
docs/crypto-blobs.md for known unknowns before relying on it.
EOF
