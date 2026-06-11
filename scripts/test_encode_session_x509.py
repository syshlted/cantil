#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later WITH cantil-additional-permissions
"""Unit tests for scripts/encode_session_x509.py (transport + pairing T-01).

Pure-Python, no Zephyr/dbox needed — runs on the Fedora host:

    python3 scripts/test_encode_session_x509.py

Covers a known-good encode (exact byte check) and a battery of known-bad
inputs that must each raise EncodeError, matching the build-fails-on-malformed
contract in the design doc.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import encode_session_x509 as enc  # noqa: E402

GOOD = {
    "subject": {"cn": "Cantil", "o": "Org", "ou": "", "c": "CA",
                "st": "", "l": ""},
    "validity": {"days": 3650},
    "key_usage": {"digital_signature": True, "key_agreement": True,
                  "key_cert_sign": False, "crl_sign": False},
}

_passed = 0
_failed = 0


def ok(name: str, cond: bool) -> None:
    global _passed, _failed
    if cond:
        _passed += 1
    else:
        _failed += 1
        print(f"  FAIL: {name}")


def expect_error(name: str, doc: dict) -> None:
    global _passed, _failed
    try:
        enc.encode(doc)
    except enc.EncodeError:
        _passed += 1
    else:
        _failed += 1
        print(f"  FAIL: {name}: expected EncodeError, none raised")


def test_known_good() -> None:
    blob = enc.encode(GOOD)
    # validity_days = 3650 = 0x0E42
    expected = bytes([
        0x0E, 0x42,        # validity_days BE
        0x00,              # is_ca
        0x00,              # path_len
        0x00, 0x88,        # key_usage: digital_signature(0x80) | key_agreement(0x08)
        0x06, *b"Cantil",  # cn
        0x03, *b"Org",     # o
        0x00,              # ou
        0x02, *b"CA",      # c
        0x00,              # st
        0x00,              # l
    ])
    ok("known-good exact bytes", blob == expected)
    ok("known-good length", len(blob) == len(expected))


def test_round_trip_lengths() -> None:
    # Re-derive each length-prefixed string field walks cleanly to the end.
    blob = enc.encode(GOOD)
    cur = 6  # skip validity(2) + is_ca(1) + path_len(1) + key_usage(2)
    for _ in range(6):
        n = blob[cur]
        cur += 1 + n
    ok("string fields consume whole blob", cur == len(blob))


def test_bad_inputs() -> None:
    def mut(**over):
        d = {k: dict(v) for k, v in GOOD.items()}
        for section, kv in over.items():
            d[section].update(kv)
        return d

    expect_error("key_cert_sign true", mut(key_usage={"key_cert_sign": True}))
    expect_error("crl_sign true", mut(key_usage={"crl_sign": True}))
    expect_error("unknown KU bit",
                 mut(key_usage={"data_encipherment": True}))
    expect_error("no KU asserted",
                 mut(key_usage={"digital_signature": False,
                                "key_agreement": False}))
    expect_error("empty cn", mut(subject={"cn": ""}))
    expect_error("cn too long", mut(subject={"cn": "x" * 65}))
    expect_error("country 1 char", mut(subject={"c": "C"}))
    expect_error("country 3 char", mut(subject={"c": "CAN"}))
    expect_error("o too long", mut(subject={"o": "x" * 65}))
    expect_error("days zero", mut(validity={"days": 0}))
    expect_error("days too big", mut(validity={"days": 70000}))
    expect_error("days not int", mut(validity={"days": "3650"}))
    expect_error("days bool", mut(validity={"days": True}))
    expect_error("missing validity", {"subject": GOOD["subject"],
                                      "key_usage": GOOD["key_usage"]})


def test_malformed_toml(tmpdir: Path) -> None:
    bad = tmpdir / "bad.toml"
    bad.write_text("this is = = not toml\n")
    try:
        enc.encode_file(bad)
    except enc.EncodeError:
        ok("malformed TOML raises", True)
    else:
        ok("malformed TOML raises", False)

    missing = tmpdir / "nope.toml"
    try:
        enc.encode_file(missing)
    except enc.EncodeError:
        ok("missing file raises", True)
    else:
        ok("missing file raises", False)


def test_real_toml() -> None:
    # The committed firmware/session_x509.toml must encode cleanly.
    repo = Path(__file__).resolve().parent.parent
    toml = repo / "firmware" / "session_x509.toml"
    if toml.is_file():
        blob = enc.encode_file(toml)
        ok("firmware/session_x509.toml encodes", len(blob) <= enc.BLOB_MAX)
        ok("real CN is the placeholder", blob[7:7 + blob[6]] == b"Cantil")


def main() -> int:
    import tempfile
    test_known_good()
    test_round_trip_lengths()
    test_bad_inputs()
    with tempfile.TemporaryDirectory() as d:
        test_malformed_toml(Path(d))
    test_real_toml()
    print(f"encode_session_x509 tests: {_passed} passed, {_failed} failed")
    return 1 if _failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
