#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# shellcheck disable=SC2086,SC2312
#
# Regenerate libcantil/tests/fixtures.h — the certificates test_x509.c runs
# every X.509 backend against.
#
# The output is COMMITTED.  Building the tests must not require openssl, and
# more importantly the fixtures must not move: they are the fixed reference
# that makes "openssl and wolfssl agree" a meaningful statement rather than
# two backends being asked different questions.  Only re-run this when adding
# a case, and expect to re-check the golden subject DER in test_x509.c if the
# DNs change.
#
# Uses the openssl CLI rather than either library under test, so the fixtures
# come from a third implementation neither backend can bias.
#
# Usage:  ./libcantil/tests/gen_fixtures.sh

set -e

DIR="$(cd "$(dirname "$0")" && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

cd "$WORK"

# $P256 is a multi-word option string, deliberately unquoted below.
P256="-newkey ec -pkeyopt ec_paramgen_curve:P-256"

# ── root CA ───────────────────────────────────────────────────────────────
openssl req -x509 -nodes $P256 -sha256 -days 3650 \
    -keyout root.key -out root.pem \
    -subj "/CN=Cantil Test Root/O=Cantil/C=CA" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null

# ── intermediate (sub-CA), signed by the root ─────────────────────────────
openssl req -nodes $P256 -keyout inter.key -out inter.csr \
    -subj "/CN=Cantil Test Sub-CA/O=Cantil/C=CA" 2>/dev/null
openssl x509 -req -in inter.csr -CA root.pem -CAkey root.key -sha256 \
    -days 3650 -out inter.pem \
    -extfile /dev/stdin <<'EOF' 2>/dev/null
basicConstraints=critical,CA:TRUE,pathlen:0
keyUsage=critical,keyCertSign,cRLSign
EOF

# ── leaf, signed by the intermediate ──────────────────────────────────────
# The DN exercises all six RDNs Cantil issues, so the subject-DER comparison
# covers a realistic name and not just a bare CN.
openssl req -nodes $P256 -keyout leaf.key -out leaf.csr \
    -subj "/CN=Cantil-TESTSERIAL01/O=Cantil/OU=Session/C=CA/ST=Ontario/L=Ottawa" 2>/dev/null
openssl x509 -req -in leaf.csr -CA inter.pem -CAkey inter.key -sha256 \
    -days 3650 -out leaf.pem \
    -extfile /dev/stdin <<'EOF' 2>/dev/null
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyAgreement
EOF

# ── an unrelated root, for the negative case ──────────────────────────────
openssl req -x509 -nodes $P256 -sha256 -days 3650 \
    -keyout other.key -out other.pem \
    -subj "/CN=Unrelated Root/O=Somebody Else/C=CA" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null

# ── a leaf signed by the UNRELATED root, for the trust-anchor trap ────────
# This is the attacker's certificate: a perfectly valid leaf issued by a CA
# that the verifier was never told to trust.  Presenting `other` as an
# "intermediate" must not launder it into the `root` chain.  Without this
# fixture the trap test is vacuous — a rogue leaf that its rogue CA never
# signed gets refused for the wrong reason, and the test passes even against a
# verifier that trusts every supplied intermediate.
openssl req -nodes $P256 -keyout rogue.key -out rogue.csr \
    -subj "/CN=Rogue Leaf/O=Somebody Else/C=CA" 2>/dev/null
openssl x509 -req -in rogue.csr -CA other.pem -CAkey other.key -sha256 \
    -days 3650 -out rogue.pem \
    -extfile /dev/stdin <<'EOF' 2>/dev/null
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
EOF

# ── an expired leaf, to prove dates are deliberately ignored ──────────────
# Cantil devices have no RTC and issue a synthetic validity window, so a
# backend that enforces dates would reject every real device certificate.
openssl req -nodes $P256 -keyout expired.key -out expired.csr \
    -subj "/CN=Cantil-EXPIRED/O=Cantil/C=CA" 2>/dev/null
openssl x509 -req -in expired.csr -CA inter.pem -CAkey inter.key -sha256 \
    -not_before 20200101000000Z -not_after 20210101000000Z \
    -out expired.pem \
    -extfile /dev/stdin <<'EOF' 2>/dev/null
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
EOF

# ── an RSA leaf, to prove the P-256/SHA-256 profile is enforced ───────────
# Neither backend should accept this: mbedTLS rejects it via the profile
# struct, wolfSSL via the explicit OID check in x509_wolfssl.c.  Without this
# case the two backends could disagree silently, since only one of them gets
# the restriction for free.
openssl req -x509 -nodes -newkey rsa:2048 -sha256 -days 3650 \
    -keyout rsaroot.key -out rsaroot.pem \
    -subj "/CN=RSA Root/O=Cantil/C=CA" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null
openssl req -nodes -newkey rsa:2048 -keyout rsaleaf.key -out rsaleaf.csr \
    -subj "/CN=RSA Leaf/O=Cantil/C=CA" 2>/dev/null
openssl x509 -req -in rsaleaf.csr -CA rsaroot.pem -CAkey rsaroot.key \
    -sha256 -days 3650 -out rsaleaf.pem 2>/dev/null

# ── emit the header ───────────────────────────────────────────────────────

emit() {
    name="$1"; file="$2"
    openssl x509 -in "$file" -outform DER -out "$file.der"
    printf 'static const unsigned char %s[] = {' "$name"
    od -An -v -tu1 "$file.der" | tr -s ' ' | tr ' ' '\n' | grep -v '^$' | \
        awk 'BEGIN{n=0} {if (n%12==0) printf "\n\t"; printf "%3d,", $1; n++}'
    printf '\n};\n\n'
}

{
    printf '/* SPDX-License-%s: GPL-3.0-or-later */\n' Identifier
    printf '/* GENERATED by libcantil/tests/gen_fixtures.sh'
    printf ' — do not edit. */\n\n'
    printf '#ifndef CANTIL_TEST_FIXTURES_H\n#define CANTIL_TEST_FIXTURES_H\n\n'
    emit fx_root     root.pem
    emit fx_inter    inter.pem
    emit fx_leaf     leaf.pem
    emit fx_other    other.pem
    emit fx_rogue    rogue.pem
    emit fx_expired  expired.pem
    emit fx_rsa_root rsaroot.pem
    emit fx_rsa_leaf rsaleaf.pem
    printf '#endif /* CANTIL_TEST_FIXTURES_H */\n'
} > "$DIR/fixtures.h"

echo "wrote $DIR/fixtures.h"

# Print the leaf's subject DN in DER, so test_x509.c's golden value can be
# updated by eye when the fixtures change.
echo
echo "leaf subject DN (DER, hex) — the golden value for the TLV test:"
openssl asn1parse -in leaf.pem -strparse 0 2>/dev/null | grep -i "SEQUENCE" | head -1 >/dev/null
python3 - "$WORK/leaf.pem.der" <<'PY'
import sys
der = open(sys.argv[1],'rb').read()
# Walk the TBSCertificate to the subject: it is the 6th element
# (version, serial, sigalg, issuer, validity, subject).
def tlv(b, i):
    t = b[i]; i += 1
    l = b[i]; i += 1
    if l & 0x80:
        n = l & 0x7f
        l = int.from_bytes(b[i:i+n], 'big'); i += n
    return t, i, l
_, i, _ = tlv(der, 0)          # Certificate SEQUENCE
_, i, _ = tlv(der, i)          # TBSCertificate SEQUENCE
for _ in range(5):             # version, serial, sigalg, issuer, validity
    t, j, l = tlv(der, i)
    i = j + l
t, j, l = tlv(der, i)          # subject
print(der[i:j+l].hex())
PY
