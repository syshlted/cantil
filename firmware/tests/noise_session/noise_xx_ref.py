# SPDX-License-Identifier: GPL-3.0-or-later WITH cantil-additional-permissions
"""
Reference implementation of Noise_XX_25519_ChaChaPoly_SHA256 used by the
cantil ztest vector generators.

This is a from-scratch Python re-implementation of the spec subset that
session.c uses, plus the extensions Cacophony's published vectors exercise
(non-empty prologue and per-handshake-message payloads).  The Cacophony
validator in gen_cacophony_vector.py drives this with Cacophony's published
inputs and asserts every wire byte matches, which is what gives us
confidence the spec interpretation is correct.

Primitives use python-cryptography; this module has no other deps.
"""

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding, PublicFormat,
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives import hashes, hmac
import hashlib

PROTOCOL_NAME = b"Noise_XX_25519_ChaChaPoly_SHA256"
assert len(PROTOCOL_NAME) == 32


# ── Primitives ──────────────────────────────────────────────────────────────

def sha256(data):
    return hashlib.sha256(data).digest()


def hkdf_extract(salt, ikm):
    h = hmac.HMAC(salt, hashes.SHA256())
    h.update(ikm)
    return h.finalize()


def hkdf_expand_2(prk):
    h1 = hmac.HMAC(prk, hashes.SHA256())
    h1.update(b"\x01")
    out1 = h1.finalize()
    h2 = hmac.HMAC(prk, hashes.SHA256())
    h2.update(out1 + b"\x02")
    out2 = h2.finalize()
    return out1, out2


def hkdf2(salt, ikm):
    return hkdf_expand_2(hkdf_extract(salt, ikm))


def dh(priv_bytes, pub_bytes):
    return X25519PrivateKey.from_private_bytes(priv_bytes).exchange(
        X25519PublicKey.from_public_bytes(pub_bytes)
    )


def derive_pub(priv_bytes):
    return X25519PrivateKey.from_private_bytes(priv_bytes).public_key().public_bytes(
        Encoding.Raw, PublicFormat.Raw,
    )


def nonce_bytes(n):
    # Noise: 4 zero bytes || 8-byte little-endian counter.
    return b"\x00" * 4 + n.to_bytes(8, "little")


def aead_encrypt(k, n, ad, pt):
    return ChaCha20Poly1305(k).encrypt(nonce_bytes(n), pt, ad)


def aead_decrypt(k, n, ad, ct):
    return ChaCha20Poly1305(k).decrypt(nonce_bytes(n), ct, ad)


# ── Symmetric state ─────────────────────────────────────────────────────────

class Sym:
    def __init__(self):
        self.h = PROTOCOL_NAME
        self.ck = PROTOCOL_NAME
        self.k = None
        self.n = 0

    def mix_hash(self, data):
        self.h = sha256(self.h + data)

    def mix_key(self, ikm):
        self.ck, k = hkdf2(self.ck, ikm)
        self.k = k
        self.n = 0

    def encrypt_and_hash(self, pt):
        if self.k is None:
            self.mix_hash(pt)
            return pt
        ct = aead_encrypt(self.k, self.n, self.h, pt)
        self.n += 1
        self.mix_hash(ct)
        return ct

    def decrypt_and_hash(self, ct):
        if self.k is None:
            self.mix_hash(ct)
            return ct
        pt = aead_decrypt(self.k, self.n, self.h, ct)
        self.n += 1
        self.mix_hash(ct)
        return pt

    def split(self):
        return hkdf2(self.ck, b"")


# ── XX trace ────────────────────────────────────────────────────────────────

def run_xx(*, iS_priv, iE_priv, rS_priv, rE_priv,
           prologue=b"", handshake_payloads=(b"", b"", b""),
           transport_messages=()):
    """
    Drive a Noise_XX_25519_ChaChaPoly_SHA256 handshake from both sides,
    returning every wire byte + derived intermediates.  Both initiator and
    responder are simulated so we can cross-check that they agree on ck/h.

    handshake_payloads is a 3-tuple of payloads encrypted-and-hashed into
    msg1/msg2/msg3 respectively (empty bytes for session.c's wire format).

    transport_messages is an iterable of (sender, plaintext) tuples where
    sender is 'i' or 'r'; each is encrypted under the appropriate post-split
    key with nonce 0 (first message), 1, … per direction.
    """
    assert len(handshake_payloads) == 3
    iS_pub = derive_pub(iS_priv)
    iE_pub = derive_pub(iE_priv)
    rS_pub = derive_pub(rS_priv)
    rE_pub = derive_pub(rE_priv)
    p1, p2, p3 = handshake_payloads

    # ── Initiator state ──
    ih = Sym()
    ih.mix_hash(prologue)

    # Initiator → msg1: e, [payload1]
    ih.mix_hash(iE_pub)
    pt1 = ih.encrypt_and_hash(p1)  # unkeyed: pt1 == p1, hashed in
    msg1 = iE_pub + pt1

    # ── Responder processes msg1 ──
    rh = Sym()
    rh.mix_hash(prologue)
    eI_pub = msg1[:32]
    rh.mix_hash(eI_pub)
    _ = rh.decrypt_and_hash(msg1[32:])  # unkeyed: returns p1 unchanged

    # Responder → msg2: e, ee, s, es, [payload2]
    rh.mix_hash(rE_pub)
    rh.mix_key(dh(rE_priv, eI_pub))               # ee
    enc_s = rh.encrypt_and_hash(rS_pub)           # 48 bytes
    rh.mix_key(dh(rS_priv, eI_pub))               # es
    enc_p2 = rh.encrypt_and_hash(p2)              # len(p2) + 16
    msg2 = rE_pub + enc_s + enc_p2

    # ── Initiator processes msg2 ──
    eR_pub = msg2[:32]
    ih.mix_hash(eR_pub)
    ih.mix_key(dh(iE_priv, eR_pub))               # ee
    sR_pub_dec = ih.decrypt_and_hash(msg2[32:80])
    assert sR_pub_dec == rS_pub, "responder static pub decrypt mismatch"
    ih.mix_key(dh(iE_priv, rS_pub))               # es
    _ = ih.decrypt_and_hash(msg2[80:])

    # Initiator → msg3: s, se, [payload3]
    msg3_s = ih.encrypt_and_hash(iS_pub)          # 48 bytes
    ih.mix_key(dh(iS_priv, eR_pub))               # se
    enc_p3 = ih.encrypt_and_hash(p3)              # len(p3) + 16
    msg3 = msg3_s + enc_p3

    # ── Responder processes msg3 ──
    sI_pub_dec = rh.decrypt_and_hash(msg3[:48])
    assert sI_pub_dec == iS_pub, "initiator static pub decrypt mismatch"
    rh.mix_key(dh(rE_priv, sI_pub_dec))           # se
    _ = rh.decrypt_and_hash(msg3[48:])

    # ── Split ──
    ik1, ik2 = ih.split()
    rk1, rk2 = rh.split()
    assert (ik1, ik2) == (rk1, rk2), "split must agree on both sides"
    assert ih.h == rh.h, "final handshake hash must agree"

    initiator_tx_key = ik1
    responder_tx_key = ik2

    # ── Transport messages ──
    tx_counters = {"i": 0, "r": 0}
    transport_out = []
    for sender, pt in transport_messages:
        if sender == "i":
            k = initiator_tx_key
        elif sender == "r":
            k = responder_tx_key
        else:
            raise ValueError(f"sender must be 'i' or 'r', got {sender!r}")
        ct = aead_encrypt(k, tx_counters[sender], b"", pt)
        transport_out.append((sender, pt, ct))
        tx_counters[sender] += 1

    return {
        "iS_priv": iS_priv, "iS_pub": iS_pub,
        "iE_priv": iE_priv, "iE_pub": iE_pub,
        "rS_priv": rS_priv, "rS_pub": rS_pub,
        "rE_priv": rE_priv, "rE_pub": rE_pub,
        "prologue": prologue,
        "msg1": msg1, "msg2": msg2, "msg3": msg3,
        "handshake_hash": ih.h,
        "initiator_tx_key": initiator_tx_key,
        "responder_tx_key": responder_tx_key,
        "transport": transport_out,
    }


# ── Header emitter ──────────────────────────────────────────────────────────

def c_array(name, data, indent=4):
    """Emit a C99 static const uint8_t array literal."""
    lines = [f"static const uint8_t {name}[{len(data)}] = {{"]
    for i in range(0, len(data), 12):
        chunk = data[i:i + 12]
        hex_bytes = ", ".join(f"0x{b:02x}" for b in chunk)
        lines.append(" " * indent + hex_bytes + ",")
    lines.append("};")
    return "\n".join(lines)