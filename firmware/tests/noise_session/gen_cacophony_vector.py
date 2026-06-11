#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later WITH cantil-additional-permissions
"""
Cross-check noise_xx_ref.py against the published Cacophony reference vector
for Noise_XX_25519_ChaChaPoly_SHA256, then emit xx_vector_cacophony.h: a
second deterministic trace that drives the ztest suite with a different key
set than xx_vector.h.

The Cacophony vector data is released under the Unlicense (public domain
dedication); see vectors/ATTRIBUTION.md for credit details.

Pipeline:
  1. Load vectors/cacophony_xx_25519_chachapoly_sha256.json (extracted from
     https://github.com/centromere/cacophony/blob/master/vectors/cacophony.txt).
  2. Re-derive every wire byte using noise_xx_ref.run_xx() with Cacophony's
     exact inputs (keys, prologue "John Galt", per-message payloads).
  3. Assert every produced ciphertext matches Cacophony's published bytes
     and that handshake_hash matches.  This is the keystone correctness
     check: if it passes, we have strong evidence the spec interpretation
     in noise_xx_ref.py is right.
  4. Emit xx_vector_cacophony.h using Cacophony's *keys* but session.c's
     wire format (empty prologue, empty handshake payloads).  The ZTEST
     suite drives session.c with this header.

The output header is structurally identical to xx_vector.h so a single
ZTEST source can be compiled twice against different vectors.
"""

import json
import os
import sys

from noise_xx_ref import run_xx, c_array


HERE = os.path.dirname(__file__)
CACOPHONY_JSON = os.path.join(
    HERE, "vectors", "cacophony_xx_25519_chachapoly_sha256.json",
)


def _h(s):
    return bytes.fromhex(s)


def validate_against_cacophony():
    """Run Cacophony's exact inputs through noise_xx_ref and assert every
    ciphertext + handshake_hash matches the published vector."""
    with open(CACOPHONY_JSON) as f:
        ref = json.load(f)

    assert ref["protocol_name"] == "Noise_XX_25519_ChaChaPoly_SHA256"
    assert ref["init_prologue"] == ref["resp_prologue"], (
        "Cacophony XX vector should have matching init/resp prologues"
    )

    # Cacophony's six "messages" entries are the three handshake messages
    # (with payloads) followed by transport messages alternating
    # initiator → responder, responder → initiator, …
    msgs = ref["messages"]
    handshake_payloads = tuple(_h(m["payload"]) for m in msgs[:3])

    # Cacophony's "messages" simply continues alternating after msg3.  XX's
    # last handshake message (msg3) is initiator → responder, so the first
    # transport message is responder → initiator.
    transport_in = []
    senders = ["r", "i"]
    for i, m in enumerate(msgs[3:]):
        transport_in.append((senders[i % 2], _h(m["payload"])))

    v = run_xx(
        iS_priv=_h(ref["init_static"]),
        iE_priv=_h(ref["init_ephemeral"]),
        rS_priv=_h(ref["resp_static"]),
        rE_priv=_h(ref["resp_ephemeral"]),
        prologue=_h(ref["init_prologue"]),
        handshake_payloads=handshake_payloads,
        transport_messages=transport_in,
    )

    # 1. Handshake hash
    expected_h = _h(ref["handshake_hash"])
    assert v["handshake_hash"] == expected_h, (
        f"handshake_hash mismatch\n  ours: {v['handshake_hash'].hex()}\n"
        f"  ref:  {expected_h.hex()}"
    )

    # 2. Handshake wire bytes
    for i, (got, ref_ct) in enumerate(zip(
        [v["msg1"], v["msg2"], v["msg3"]],
        [_h(m["ciphertext"]) for m in msgs[:3]],
    )):
        assert got == ref_ct, (
            f"handshake msg{i+1} mismatch\n  ours: {got.hex()}\n"
            f"  ref:  {ref_ct.hex()}"
        )

    # 3. Transport ciphertexts
    for i, ((sender, pt, ct), ref_msg) in enumerate(
        zip(v["transport"], msgs[3:])
    ):
        ref_ct = _h(ref_msg["ciphertext"])
        assert ct == ref_ct, (
            f"transport msg {i} (sender={sender}) mismatch\n"
            f"  ours: {ct.hex()}\n  ref:  {ref_ct.hex()}"
        )

    print(f"✓ noise_xx_ref matches Cacophony Noise_XX_25519_ChaChaPoly_SHA256")
    print(f"  - handshake_hash: {v['handshake_hash'].hex()}")
    print(f"  - {len(msgs)} messages verified ({len(msgs[3:])} transport)")
    return ref


def emit_session_compatible_header(ref, out_path):
    """Re-derive a vector using Cacophony's *keys* but session.c's wire
    format (empty prologue, empty handshake payloads, + two transport
    messages so the ZTEST has something to verify)."""
    v = run_xx(
        iS_priv=_h(ref["init_static"]),
        iE_priv=_h(ref["init_ephemeral"]),
        rS_priv=_h(ref["resp_static"]),
        rE_priv=_h(ref["resp_ephemeral"]),
        prologue=b"",
        handshake_payloads=(b"", b"", b""),
        transport_messages=[
            ("i", b"hello from initiator"),
            ("r", b"hello from responder"),
        ],
    )

    msg_a_pt = v["transport"][0][1]
    msg_a_ct = v["transport"][0][2]
    msg_b_pt = v["transport"][1][1]
    msg_b_ct = v["transport"][1][2]

    parts = [
        "/* SPDX-License-Identifier: GPL-3.0-or-later WITH cantil-additional-permissions */",
        "/* GENERATED by firmware/tests/noise_session/gen_cacophony_vector.py — do not edit. */",
        "",
        "#pragma once",
        "",
        "#include <stdint.h>",
        "",
        "/* Noise_XX_25519_ChaChaPoly_SHA256 trace using the Cacophony reference",
        " * vector's keypairs (init_static, init_ephemeral, resp_static,",
        " * resp_ephemeral from vectors/cacophony_xx_25519_chachapoly_sha256.json).",
        " *",
        " * The published Cacophony entry uses a non-empty prologue and payloads",
        " * in every handshake message; session.c does neither.  We therefore",
        " * re-derive the trace with the Cacophony keys but session.c's wire",
        " * format (empty prologue, empty handshake payloads).  The spec",
        " * primitives are validated against Cacophony separately — see the",
        " * keystone check in gen_cacophony_vector.py:validate_against_cacophony.",
        " */",
        "",
    ]
    fields = [
        ("XX_IS_PRIV", v["iS_priv"]), ("XX_IS_PUB", v["iS_pub"]),
        ("XX_IE_PRIV", v["iE_priv"]), ("XX_IE_PUB", v["iE_pub"]),
        ("XX_RS_PRIV", v["rS_priv"]), ("XX_RS_PUB", v["rS_pub"]),
        ("XX_RE_PRIV", v["rE_priv"]), ("XX_RE_PUB", v["rE_pub"]),
        ("XX_MSG1", v["msg1"]), ("XX_MSG2", v["msg2"]), ("XX_MSG3", v["msg3"]),
        ("XX_HANDSHAKE_HASH", v["handshake_hash"]),
        ("XX_INITIATOR_TX_KEY", v["initiator_tx_key"]),
        ("XX_RESPONDER_TX_KEY", v["responder_tx_key"]),
        ("XX_MSG_A_PT", msg_a_pt), ("XX_MSG_A_CT", msg_a_ct),
        ("XX_MSG_B_PT", msg_b_pt), ("XX_MSG_B_CT", msg_b_ct),
    ]
    for name, data in fields:
        parts.append(c_array(name, data))
        parts.append("")

    with open(out_path, "w") as f:
        f.write("\n".join(parts))
    print(f"wrote {out_path}")


def main():
    ref = validate_against_cacophony()
    out = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
        HERE, "src", "xx_vector_cacophony.h",
    )
    emit_session_compatible_header(ref, out)


if __name__ == "__main__":
    main()
