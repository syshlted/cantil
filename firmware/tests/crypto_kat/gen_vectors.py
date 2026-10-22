#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Generate known-answer vectors for the crypto.h backends (crypto.c against
# mbedTLS, crypto_wolfssl.c against wolfCrypt).
#
# Run: ./venv/bin/python gen_vectors.py > src/vectors.h
#
# Where a published standard supplies the answer, this file uses it and only
# checks its own arithmetic against it — the ECDSA vectors are RFC 6979 §A.2.5
# verbatim.  That matters more here than it does for a self-generated vector:
# the point of the suite is that two independent libraries agree, and a vector
# produced by a third implementation is the only kind that can say so without
# nominating one of them as the oracle.

import hashlib
import hmac
import sys

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def c_bytes(name, data):
    body = ", ".join(f"0x{b:02x}" for b in data)
    return f"static const uint8_t {name}[{len(data)}] = {{ {body} }};"


# ── HKDF-SHA256, RFC 5869 ────────────────────────────────────────────────────

def hkdf_sha256(salt, ikm, info, length):
    if not salt:
        salt = b"\x00" * 32
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    okm, t, i = b"", b"", 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        okm += t
        i += 1
    return okm[:length]


# ── RFC 6979 deterministic ECDSA over P-256 / SHA-256 ────────────────────────

P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
QLEN = 256
RLEN = 32


def _bits2int(b):
    i = int.from_bytes(b, "big")
    blen = len(b) * 8
    return i >> (blen - QLEN) if blen > QLEN else i


def _int2octets(i):
    return i.to_bytes(RLEN, "big")


def _bits2octets(b):
    z1 = _bits2int(b)
    z2 = z1 - P256_N if z1 >= P256_N else z1
    return _int2octets(z2)


def rfc6979_k(x, h1):
    v = b"\x01" * 32
    k = b"\x00" * 32
    for byte in (b"\x00", b"\x01"):
        k = hmac.new(k, v + byte + _int2octets(x) + _bits2octets(h1),
                     hashlib.sha256).digest()
        v = hmac.new(k, v, hashlib.sha256).digest()
    while True:
        t = b""
        while len(t) * 8 < QLEN:
            v = hmac.new(k, v, hashlib.sha256).digest()
            t += v
        cand = _bits2int(t)
        if 1 <= cand < P256_N:
            return cand
        k = hmac.new(k, v + b"\x00", hashlib.sha256).digest()
        v = hmac.new(k, v, hashlib.sha256).digest()


def ecdsa_sign_det(x, digest):
    k = rfc6979_k(x, digest)
    point = ec.derive_private_key(k, ec.SECP256R1()).public_key()
    r = point.public_numbers().x % P256_N
    s = (pow(k, -1, P256_N) * (_bits2int(digest) + r * x)) % P256_N
    return k, r, s


# ── Vectors ─────────────────────────────────────────────────────────────────

# crypto_device_id() on a non-Nordic build returns a fixed UID: the little
# endian bytes of 0xDEADBEEF then 0xCAFEF00D (src/crypto/device_id.c).  This
# is what makes crypto_storage_key_derive() reproducible off-target at all.
UID = (0xDEADBEEF).to_bytes(4, "little") + (0xCAFEF00D).to_bytes(4, "little")
STORAGE_KEY = hkdf_sha256(b"", UID, b"cantil-storage-key", 32)

# RFC 6979 §A.2.5 — P-256, SHA-256, message "sample".
RFC6979_PRIV = 0xC9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721
RFC6979_UX = 0x60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6
RFC6979_UY = 0x7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299
RFC6979_K = 0xA6E3C57DD01ABE90086538398355DD4C3B17AA873382B0F24D6129493D8AAD60
RFC6979_R = 0xEFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716
RFC6979_S = 0xF7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8

DIGEST = hashlib.sha256(b"sample").digest()
k, r, s = ecdsa_sign_det(RFC6979_PRIV, DIGEST)

# Self-check: if the arithmetic above and the transcribed RFC literals ever
# disagree, the generator must fail rather than emit a plausible-looking vector
# that only one of the two is right about.
assert k == RFC6979_K, f"k mismatch: {k:064x}"
assert r == RFC6979_R, f"r mismatch: {r:064x}"
assert s == RFC6979_S, f"s mismatch: {s:064x}"

pub = ec.derive_private_key(RFC6979_PRIV, ec.SECP256R1()).public_key()
assert pub.public_numbers().x == RFC6979_UX, "pubkey X mismatch"
assert pub.public_numbers().y == RFC6979_UY, "pubkey Y mismatch"

PUBKEY = (b"\x04" + RFC6979_UX.to_bytes(32, "big")
          + RFC6979_UY.to_bytes(32, "big"))
SIG = r.to_bytes(32, "big") + s.to_bytes(32, "big")

# RFC 5869 Test Case 1 — SHA-256, non-empty salt.  Pins crypto_hkdf_sha256()
# in its general form against a published answer, so neither backend is judged
# by the other.  (STORAGE_KEY above exercises only the salt=NULL path.)
RFC5869_IKM  = b"\x0b" * 22
RFC5869_SALT = bytes(range(0x00, 0x0d))
RFC5869_INFO = bytes(range(0xf0, 0xfa))
RFC5869_OKM  = bytes.fromhex(
    "3cb25f25faacd57a90434f64d0362f2a"
    "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
    "34007208d5b887185865")
assert hkdf_sha256(RFC5869_SALT, RFC5869_IKM, RFC5869_INFO,
                   42) == RFC5869_OKM, "RFC 5869 TC1 mismatch"

# The pairing PSK (src/clients/pairing.c derive_psk): IKM is the 6-digit
# passkey big-endian, salt is local_pub || remote_pub, info is "cantil-psk-v1".
# Pinned because the two peers derive this independently — a backend that
# disagreed would not fail loudly, it would simply never complete a handshake,
# and the device offers no way to see why.
PSK_PASSKEY = 123456
PSK_LOCAL   = bytes(range(0x00, 0x20))
PSK_REMOTE  = bytes(range(0x20, 0x40))
PSK = hkdf_sha256(PSK_LOCAL + PSK_REMOTE,
                  PSK_PASSKEY.to_bytes(4, "big"),
                  b"cantil-psk-v1", 32)

# AES-256-GCM blob in Cantil's on-disk layout: [12-byte nonce][ct][16-byte tag].
# Fixed nonce, because crypto_encrypt_blob() picks its own from the TRNG and so
# can only be checked by round trip; crypto_decrypt_blob() is the direction a
# known answer can pin, and it is the one that matters — it is what reads the
# CA key back after a reboot.
BLOB_KEY = bytes(range(32))
BLOB_NONCE = bytes(range(12))
BLOB_PT = b"cantil key blob plaintext, 44 bytes long...."
_ct = AESGCM(BLOB_KEY).encrypt(BLOB_NONCE, BLOB_PT, None)
BLOB = BLOB_NONCE + _ct

out = sys.stdout
out.write("""/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Generated by gen_vectors.py — do not edit. */

#pragma once

#include <stdint.h>

""")
out.write(c_bytes("KAT_STORAGE_KEY", STORAGE_KEY) + "\n\n")
out.write(c_bytes("KAT_P256_PRIV", RFC6979_PRIV.to_bytes(32, "big")) + "\n")
out.write(c_bytes("KAT_P256_PUB", PUBKEY) + "\n")
out.write(c_bytes("KAT_P256_DIGEST", DIGEST) + "\n")
out.write(c_bytes("KAT_P256_SIG", SIG) + "\n\n")
out.write(c_bytes("KAT_HKDF_IKM", RFC5869_IKM) + "\n")
out.write(c_bytes("KAT_HKDF_SALT", RFC5869_SALT) + "\n")
out.write(c_bytes("KAT_HKDF_INFO", RFC5869_INFO) + "\n")
out.write(c_bytes("KAT_HKDF_OKM", RFC5869_OKM) + "\n\n")
out.write(f"#define KAT_PSK_PASSKEY {PSK_PASSKEY}u\n")
out.write(c_bytes("KAT_PSK_LOCAL", PSK_LOCAL) + "\n")
out.write(c_bytes("KAT_PSK_REMOTE", PSK_REMOTE) + "\n")
out.write(c_bytes("KAT_PSK", PSK) + "\n\n")
out.write(c_bytes("KAT_BLOB_KEY", BLOB_KEY) + "\n")
out.write(c_bytes("KAT_BLOB_PT", BLOB_PT) + "\n")
out.write(c_bytes("KAT_BLOB", BLOB) + "\n")
