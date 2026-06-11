#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later WITH cantil-additional-permissions
"""Encode the session X.509 identity TOML into a packed x509_data_t blob.

Transport + pairing task T-01. The output blob is byte-compatible with
``x509_parse()`` in ``firmware/src/ca/ca.c`` (the same wire format the
PUSH_KEY_X509 opcode accepts), so the firmware can hand the constant straight
to ``build_self_signed_cert()`` at first boot.

Packed layout (big-endian multi-byte ints; strings are ``[len:u8][bytes]``)::

    offset  size  field
    0       2     validity_days   (BE u16, required, non-zero)
    2       1     is_ca           (always 0 for the session cert)
    3       1     path_len        (always 0; ignored when is_ca = 0)
    4       2     key_usage       (BE u16, RFC 5280 BIT STRING numbering)
    6       1     cn_len
    7       N     cn
    ...           o   ([len][bytes])
    ...           ou  ([len][bytes])
    ...           c   ([len][bytes], len 0 or 2)
    ...           st  ([len][bytes])
    ...           l   ([len][bytes])

Usage::

    encode_session_x509.py <input.toml> --bin <out.bin>
    encode_session_x509.py <input.toml> --c <out.c> [--symbol NAME]

On malformed input the script raises ``EncodeError`` and (from main) exits
non-zero so the CMake custom command fails the build.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

try:
    import tomllib  # Python 3.11+
except ModuleNotFoundError:  # pragma: no cover - fallback for older hosts
    import tomli as tomllib  # type: ignore

# Field length caps mirror x509_params_t in firmware/src/ca/ca.c (char[65] ->
# 64 usable bytes + NUL) and X509_DATA_MAX (512) for the whole blob.
CN_MAX = 64
FIELD_MAX = 64
BLOB_MAX = 512

# RFC 5280 §4.2.1.3 / mbedtls MBEDTLS_X509_KU_* BIT STRING numbering. These are
# the same constants build_self_signed_cert() forwards to mbedtls verbatim.
KU_DIGITAL_SIGNATURE = 0x0080  # bit 0
KU_KEY_AGREEMENT = 0x0008      # bit 4
KU_KEY_CERT_SIGN = 0x0004      # bit 5
KU_CRL_SIGN = 0x0002           # bit 6

# Keys recognised in [key_usage]. digital_signature / key_agreement are the
# only ones a session cert may assert; the cert-signing bits MUST stay false
# (the session slot may never act as an issuer — see the design doc).
KU_ALLOWED_TRUE = {"digital_signature", "key_agreement"}
KU_MUST_BE_FALSE = {"key_cert_sign", "crl_sign"}
KU_BITS = {
    "digital_signature": KU_DIGITAL_SIGNATURE,
    "key_agreement": KU_KEY_AGREEMENT,
    "key_cert_sign": KU_KEY_CERT_SIGN,
    "crl_sign": KU_CRL_SIGN,
}


class EncodeError(ValueError):
    """Raised on a missing/malformed TOML or a disallowed key-usage bit."""


def _require(cond: bool, msg: str) -> None:
    if not cond:
        raise EncodeError(msg)


def _str_field(table: dict, key: str, *, cap: int) -> bytes:
    val = table.get(key, "")
    _require(isinstance(val, str), f"[subject].{key} must be a string")
    raw = val.encode("utf-8")
    _require(len(raw) <= cap, f"[subject].{key} exceeds {cap} bytes ({len(raw)})")
    return raw


def encode(doc: dict) -> bytes:
    """Turn a parsed TOML document into the packed x509_data_t blob."""
    subject = doc.get("subject", {})
    validity = doc.get("validity", {})
    key_usage = doc.get("key_usage", {})

    _require(isinstance(subject, dict), "[subject] table is required")
    _require(isinstance(validity, dict), "[validity] table is required")
    _require(isinstance(key_usage, dict), "[key_usage] table is required")

    # ── validity ──
    days = validity.get("days")
    _require(isinstance(days, int) and not isinstance(days, bool),
             "[validity].days must be an integer")
    _require(1 <= days <= 0xFFFF,
             f"[validity].days must be in 1..65535 (got {days})")

    # ── key usage ──
    for k in key_usage:
        _require(k in KU_BITS, f"[key_usage].{k} is not a recognised bit")
    for k in KU_MUST_BE_FALSE:
        if bool(key_usage.get(k, False)):
            raise EncodeError(
                f"[key_usage].{k} must be false: the session cert is never a "
                f"CA and the session slot may never act as an issuer")
    ku = 0
    for k in KU_ALLOWED_TRUE:
        if bool(key_usage.get(k, False)):
            ku |= KU_BITS[k]
    _require(ku != 0,
             "[key_usage] must assert at least one of digital_signature / "
             "key_agreement")

    # ── subject ──
    cn = _str_field(subject, "cn", cap=CN_MAX)
    _require(len(cn) > 0, "[subject].cn is required and must be non-empty")
    o = _str_field(subject, "o", cap=FIELD_MAX)
    ou = _str_field(subject, "ou", cap=FIELD_MAX)
    c = _str_field(subject, "c", cap=2)
    _require(len(c) in (0, 2),
             f"[subject].c must be empty or a 2-letter country code (got "
             f"{len(c)} bytes)")
    st = _str_field(subject, "st", cap=FIELD_MAX)
    l = _str_field(subject, "l", cap=FIELD_MAX)

    out = bytearray()
    out += days.to_bytes(2, "big")
    out.append(0)            # is_ca: the session cert is never a CA
    out.append(0)            # path_len: ignored when is_ca = 0
    out += ku.to_bytes(2, "big")
    for field in (cn, o, ou, c, st, l):
        out.append(len(field))
        out += field

    _require(len(out) <= BLOB_MAX,
             f"encoded blob is {len(out)} bytes, exceeds X509_DATA_MAX "
             f"({BLOB_MAX})")
    return bytes(out)


def encode_file(path: str | Path) -> bytes:
    p = Path(path)
    _require(p.is_file(), f"session X.509 TOML not found: {p}")
    try:
        with p.open("rb") as fh:
            doc = tomllib.load(fh)
    except tomllib.TOMLDecodeError as exc:
        raise EncodeError(f"malformed TOML in {p}: {exc}") from exc
    return encode(doc)


def emit_c(blob: bytes, symbol: str) -> str:
    lines = [
        "/* Auto-generated by scripts/encode_session_x509.py — do not edit. */",
        "/* Source: firmware/session_x509.toml (transport + pairing T-01).   */",
        "#include <stddef.h>",
        "#include <stdint.h>",
        "",
        f"const uint8_t {symbol}[] = {{",
    ]
    for i in range(0, len(blob), 12):
        chunk = blob[i:i + 12]
        lines.append("\t" + " ".join(f"0x{b:02x}," for b in chunk))
    lines.append("};")
    lines.append(f"const size_t {symbol}_len = {len(blob)}u;")
    lines.append("")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("toml", help="input session_x509.toml")
    ap.add_argument("--bin", help="write the raw packed blob to this path")
    ap.add_argument("--c", help="write a C source array to this path")
    ap.add_argument("--symbol", default="cantil_session_x509_constant",
                    help="C symbol name (default: cantil_session_x509_constant)")
    args = ap.parse_args(argv)

    if not args.bin and not args.c:
        ap.error("one of --bin or --c is required")

    try:
        blob = encode_file(args.toml)
    except EncodeError as exc:
        print(f"encode_session_x509: {exc}", file=sys.stderr)
        return 1

    if args.bin:
        Path(args.bin).write_bytes(blob)
    if args.c:
        Path(args.c).write_text(emit_c(blob, args.symbol))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
