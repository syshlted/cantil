# Task 06 — AUTO_EXPIRE

**Status:** Landed 2026-05-28
**Opcode:** `CMD_AUTO_EXPIRE` (0x14)
**Touches:** [firmware/src/ca/ca.c](../../firmware/src/ca/ca.c), [firmware/src/protocol/protocol.c](../../firmware/src/protocol/protocol.c), [libcantil/src/ca.c](../../libcantil/src/ca.c)

---

## What this task adds

`AUTO_EXPIRE` — host supplies a Unix timestamp, device walks the issued
cert store and marks every cert whose `not_after_unix < now` with the
`ISSUED_FLAG_EXPIRED` bit. Returns the count of certs newly flipped.

**Why host-supplied time?** The nRF52840 has no battery-backed RTC; the
device has no authoritative wall clock between reboots. Pushing the
timestamp from the client at op time is the simplest, smallest-attack-
surface design — the client is already inside a Noise session, and the
worst a malicious client can do is mark certs expired early. The device
never relies on its own (absent) clock for any security decision.

**Request:** 8-byte big-endian `uint64` Unix timestamp.
**Response:** 4-byte big-endian `uint32` count of newly-expired certs.

---

## Timestamp plumbing into the cert store

Up to now `issued_cert_meta_t.not_after_unix` was always 0 — sign-time
metadata had nowhere to source a wall clock from. Task 6 introduces a
**synthetic baseline**: the existing `NOT_BEFORE_BASE` string used by
mbedtls cert writers (`"20260101000000"`) is paired with
`SIGN_CSR_NOT_BEFORE_UNIX = 1767225600` (2026-01-01 00:00:00 UTC).
`ca_sign_csr` populates each cert's meta at issuance:

```c
meta.not_before_unix = SIGN_CSR_NOT_BEFORE_UNIX;
meta.not_after_unix  = SIGN_CSR_NOT_BEFORE_UNIX + 365 * 86400;
```

The two cert representations (ASN.1 `NOT_BEFORE_BASE` string in DER
versus packed `not_after_unix` in meta) refer to the same instant, so a
relying party that parses the cert sees the same expiry the device
reports through `AUTO_EXPIRE`.

When a client-supplied validity arrives in a future task, both the meta
timestamp and the cert string get derived from the same base.

---

## Sequence

```mermaid
sequenceDiagram
    participant Cli as libcantil
    participant Disp as protocol_handle_one
    participant Ca as ca_auto_expire
    participant St as storage_issued_certs_iter
    participant Lfs as /lfs/certs/*/meta.bin

    Cli->>Disp: CBOR {cmd=0x14, data=<8 B BE uint64 now>}
    Disp->>Ca: ca_auto_expire(now, &count)
    Ca->>St: walk /certs/
    loop per cert
        St->>Ca: serial
        Ca->>Lfs: read meta
        alt no validity / already expired / now < not_after
            Ca-->>Ca: skip
        else now ≥ not_after
            Ca->>Lfs: meta.flags |= EXPIRED; write back
            Ca-->>Ca: count++
        end
    end
    Ca-->>Disp: 0, count
    Disp->>Cli: CBOR {err=0, data=<4 B BE uint32 count>}
```

---

## Failure modes

| Condition | `ca_auto_expire` | Wire err |
| --- | --- | --- |
| `expired_count == NULL` | `-EINVAL` | `ERR_STORAGE` |
| `now_unix == 0` | `-EINVAL` | `ERR_STORAGE` |
| Request bstr < 8 B | (dispatcher) | `ERR_INVALID_ARGS` |
| Meta write fails mid-walk | `-errno` (count not committed) | `ERR_STORAGE` |
| Corrupt meta entries | silently skipped | — |

---

## Code map

| File | Role |
| --- | --- |
| [firmware/src/ca/ca.c](../../firmware/src/ca/ca.c) | `ca_auto_expire` + `expire_cb`; `SIGN_CSR_NOT_BEFORE_UNIX` baseline; `ca_sign_csr` now populates `not_before/after_unix` |
| [firmware/src/protocol/protocol.c](../../firmware/src/protocol/protocol.c) | New `CMD_AUTO_EXPIRE` case (decode 8 B BE uint64, encode 4 B BE uint32) |
| [libcantil/src/ca.c](../../libcantil/src/ca.c) | `cantil_auto_expire` |

---

## Tests (sign_csr — 20/20 PASS)

- `test_17_auto_expire_no_certs` — clean walk, count=0.
- `test_18_auto_expire_invalid_now_zero` — `now=0` → `-EINVAL`.
- `test_19_auto_expire_flips_expired_bit` — two signs at the default
  baseline; `now = 2030-01-01` → count=2, second run → count=0
  (idempotent), meta bit set on inspection.
- `test_20_auto_expire_before_validity_no_op` — `now == not_before` →
  count=0.

protocol_cbor and ca_bootstrap suites still pass (no regression from the
meta extension).

## Session log

Wrestled briefly with how to surface a wall clock. Considered:

1. Persisting a "last seen timestamp" in NVS — device monotonic-clocks
   forward from there. Adds complexity for marginal benefit; the device
   still can't *prove* freshness.
2. Adding a separate `SET_TIME` command. More attack surface and the
   value only matters at expire time anyway.
3. **Picked: per-command host-supplied `now`.** Smallest API, matches the
   CLAUDE.md spec note "device has no RTC".

Build: FLASH 212336 B / 972 KB (21.33%, +256 B).
