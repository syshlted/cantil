#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later WITH cantil-additional-permissions
#
# Host-side OpenSSL smoke test for the crl_der ztest suite.
#
# Workflow:
#   1. Build + run firmware/tests/crl_der via scripts/test.sh. The
#      test_13_smoke_dump_for_openssl case writes the device-generated CRL
#      DER and the issuer's self-signed cert DER to /tmp.
#   2. This script runs `openssl crl -inform DER -text -noout` to confirm
#      OpenSSL can parse the CRL, and `openssl crl -CAfile -verify` to
#      confirm the device's ECDSA signature validates under the issuer
#      pubkey extracted from the cert.
#
# OpenSSL is Apache 2.0 since 3.0, so this gate is AGPL-clean. If openssl
# is missing the script reports a skip rather than failing.
#
# Usage:
#   ./scripts/dbox.sh sh firmware/tests/crl_der/smoke_openssl.sh
#
# Exit codes:
#   0  smoke passed (or skipped because openssl missing)
#   1  smoke failed (CRL did not parse, or signature did not verify)

set -e

CRL_DER=/tmp/cantil_crl_smoke.der
CERT_DER=/tmp/cantil_crl_smoke_cert.der

if ! command -v openssl >/dev/null 2>&1; then
    echo "SKIP: openssl not installed in this environment"
    exit 0
fi

if [ ! -f "$CRL_DER" ] || [ ! -f "$CERT_DER" ]; then
    echo "ERROR: expected $CRL_DER and $CERT_DER — run scripts/test.sh crl_der first" >&2
    exit 1
fi

# Convert the issuer cert to PEM for -CAfile.
CERT_PEM=$(mktemp --suffix=.pem)
trap 'rm -f "$CERT_PEM"' EXIT
openssl x509 -inform DER -in "$CERT_DER" -out "$CERT_PEM" >/dev/null

echo "── openssl crl -text -noout ─────────────────────────────────"
openssl crl -inform DER -in "$CRL_DER" -text -noout

echo
echo "── openssl crl -verify -CAfile ──────────────────────────────"
# OpenSSL prints either "verify OK" or "verify failure" and exits 0 in both
# cases; grep for the OK message to decide.
if openssl crl -inform DER -in "$CRL_DER" -CAfile "$CERT_PEM" -noout 2>&1 | tee /dev/stderr | grep -q "verify OK"; then
    echo "PASS: CRL signature verified by OpenSSL"
    exit 0
else
    echo "FAIL: OpenSSL could not verify the CRL signature" >&2
    exit 1
fi
