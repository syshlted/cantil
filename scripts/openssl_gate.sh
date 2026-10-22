#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Check DER artifacts produced by a ztest suite with the OpenSSL CLI.
#
# This is the independent oracle for everything Cantil *generates*. The suites
# that mint certificates, CSRs and CRLs cannot be their own judge: a writer and
# a reader from the same library share any misunderstanding of DER between
# them, so a round trip proves only self-consistency. Two real bugs in step 4
# of docs/roadmap/wolfssl-migration.md — a CSR emitted with version 2 instead
# of 1, and a certificate with an empty subjectPublicKeyInfo — would both have
# survived a wolfCrypt-checks-wolfCrypt test.
#
# OpenSSL rather than mbedTLS because it needs only the `openssl` binary: no
# -devel headers, no linking, no Zephyr integration. It is also the same
# implementation libcantil/tests/gen_fixtures.sh already uses to mint fixtures.
#
# Usage:
#   ./scripts/openssl_gate.sh <artifact-dir>
#
# Files are dispatched by suffix, so a suite decides what it is claiming just
# by how it names the file:
#
#   <name>.cert.der    a certificate; must parse
#   <name>.csr.der     a PKCS#10 CSR; must parse AND its self-signature verify
#   <name>.crl.der     a CRL; must parse, and if <name>.ca.der is also present
#                      its signature must verify under that issuer
#   <name>.leaf.der    verified against <name>.ca.der (both must be present)
#   <name>.ca.der      the anchor for the matching .leaf.der / .crl.der
#
# Exits 0 if every artifact passes, 1 otherwise. An empty directory is not an
# error — most suites generate nothing.
#
# WHAT THIS DELIBERATELY DOES NOT CHECK
#
# Validity dates. The device has no RTC and issues a synthetic validity window
# on purpose, so `openssl verify` runs with -no_check_time. Without that the
# gate would report a deliberate architectural decision as a failure on every
# run, and a gate that cries wolf is a gate people switch off. Everything else
# — DER well-formedness, signatures, chain linkage — is checked.

set -e

DIR="${1:?usage: openssl_gate.sh <artifact-dir>}"

if [ ! -d "$DIR" ]; then
    # Nothing dumped: the suite generates no artifacts. Not a failure.
    exit 0
fi

if ! command -v openssl >/dev/null 2>&1; then
    echo "openssl-gate: ERROR: openssl not found on PATH" >&2
    echo "  The generation suites have no independent oracle without it." >&2
    exit 1
fi

VER_FULL="$(openssl version 2>/dev/null)"
VER="$(echo "$VER_FULL" | awk '{print $2}')"
VER_MAJ="$(echo "$VER" | cut -d. -f1)"

# Floor at 3.0 rather than something newer: 3.0 is what Debian 12, Ubuntu 24.04
# LTS and RHEL 9 ship, and every subcommand used below is stable across all of
# 3.x. Drift also runs in the safe direction — a newer, stricter openssl
# surfaces a real latent problem rather than inventing one.
if [ "${VER_MAJ:-0}" -lt 3 ] 2>/dev/null; then
    echo "openssl-gate: ERROR: need OpenSSL 3.0 or newer, found: $VER_FULL" >&2
    exit 1
fi

# Count first, so an empty directory can say so rather than printing nothing
# and leaving the reader to guess whether the gate ran.
n_files=$(find "$DIR" -maxdepth 1 -name '*.der' 2>/dev/null | wc -l)
if [ "$n_files" -eq 0 ]; then
    exit 0
fi

echo "── OpenSSL gate ($VER_FULL): $n_files artifact(s) in $DIR"

fails=0
checked=0

fail() {
    echo "   FAIL  $1" >&2
    [ -n "$2" ] && echo "         $2" >&2
    fails=$((fails + 1))
}

pass() {
    echo "   ok    $1"
    checked=$((checked + 1))
}

for f in "$DIR"/*.der; do
    [ -e "$f" ] || continue
    base="$(basename "$f")"

    case "$base" in
    *.cert.der)
        if out=$(openssl x509 -inform DER -in "$f" -noout -text 2>&1); then
            pass "$base (certificate parses)"
        else
            fail "$base (certificate does not parse)" "$(echo "$out" | head -3)"
        fi
        ;;

    *.csr.der)
        # -verify checks the CSR's self-signature, not just its syntax: a CSR
        # whose signature does not match its own embedded public key is the
        # exact failure a wolfCrypt-judges-wolfCrypt test cannot see.
        if out=$(openssl req -inform DER -in "$f" -verify -noout 2>&1); then
            pass "$base (CSR parses, self-signature verifies)"
        else
            fail "$base (CSR bad)" "$(echo "$out" | head -3)"
        fi
        ;;

    *.crl.der)
        if ! out=$(openssl crl -inform DER -in "$f" -noout 2>&1); then
            fail "$base (CRL does not parse)" "$(echo "$out" | head -3)"
            continue
        fi

        # Parsing alone is weak for a CRL: Cantil's encoder is hand-rolled
        # (src/ca/der_write.c) and its signature is assembled by hand from
        # crypto_sign + cantil_der_mpint, so the ECDSA-Sig-Value encoding has
        # no library checking it on the way out. Verify it whenever the suite
        # supplies the issuer.
        ca="${f%.crl.der}.ca.der"
        if [ ! -f "$ca" ]; then
            pass "$base (CRL parses; no issuer supplied, signature unchecked)"
            continue
        fi

        ca_pem="$DIR/.gate_crl_ca.pem"
        openssl x509 -inform DER -in "$ca" -outform PEM -out "$ca_pem" 2>/dev/null || {
            fail "$base (issuer will not convert to PEM — malformed)"; continue; }

        if out=$(openssl crl -inform DER -in "$f" -noout -verify \
                     -CAfile "$ca_pem" 2>&1); then
            pass "$base (CRL parses, signature verifies under $(basename "$ca"))"
        else
            fail "$base (CRL signature does NOT verify)" "$(echo "$out" | head -3)"
        fi
        rm -f "$ca_pem"
        ;;

    *.leaf.der)
        ca="${f%.leaf.der}.ca.der"
        if [ ! -f "$ca" ]; then
            fail "$base (no matching $(basename "$ca") to verify against)"
            continue
        fi
        # openssl verify wants PEM for both -CAfile and the target.
        leaf_pem="$DIR/.gate_leaf.pem"
        ca_pem="$DIR/.gate_ca.pem"
        openssl x509 -inform DER -in "$f"  -outform PEM -out "$leaf_pem" 2>/dev/null || {
            fail "$base (leaf will not convert to PEM — malformed)"; continue; }
        openssl x509 -inform DER -in "$ca" -outform PEM -out "$ca_pem" 2>/dev/null || {
            fail "$base (anchor will not convert to PEM — malformed)"; continue; }

        # -no_check_time: see the header. -partial_chain lets a sub-CA act as
        # the anchor, which is exactly how Cantil anchors on a key slot.
        #
        # -check_ss_sig is not optional here. A trusted certificate is matched
        # by identity, and its signature is taken on faith — so a suite that
        # supplies the same self-signed cert as both leaf and anchor (the
        # session slot does exactly this) would get an OK back without one
        # signature ever being verified, which is the self-oracle hole this
        # gate exists to close. The flag also covers the self-signed root at
        # the top of a real chain.
        if out=$(openssl verify -no_check_time -partial_chain -check_ss_sig \
                     -CAfile "$ca_pem" "$leaf_pem" 2>&1); then
            pass "$base (chain verifies to $(basename "$ca"))"
        else
            fail "$base (chain does NOT verify)" "$(echo "$out" | head -3)"
        fi
        rm -f "$leaf_pem" "$ca_pem"
        ;;

    *.ca.der)
        # Consumed by its matching .leaf.der above; still confirm it parses on
        # its own so a corrupt anchor is not reported as a chain failure.
        if out=$(openssl x509 -inform DER -in "$f" -noout -text 2>&1); then
            pass "$base (anchor parses)"
        else
            fail "$base (anchor does not parse)" "$(echo "$out" | head -3)"
        fi
        ;;

    *)
        fail "$base (unrecognised suffix — the gate does not know how to check it)"
        ;;
    esac
done

if [ "$fails" -ne 0 ]; then
    echo "── OpenSSL gate: $fails FAILED, $checked passed" >&2
    exit 1
fi

echo "── OpenSSL gate: all $checked passed"
exit 0
