# Task 03 — GET_CA_SERIAL

**Status:** Landed 2026-05-28
**Opcode:** `CMD_GET_CA_SERIAL` (0x04)
**Touches:** [firmware/src/ca/ca.c](../../firmware/src/ca/ca.c), [libcantil/src/ca.c](../../libcantil/src/ca.c)

---

## What this task adds

Returns the serial number of slot 0's own (self-signed) CA certificate.
Small read-only command — useful for relying parties that want to identify
which CA signed a given child cert without downloading the full cert DER.

**Request:** none.
**Response:** raw serial bytes (1..20).

---

## Implementation

```mermaid
sequenceDiagram
    participant Cli as libcantil
    participant Disp as protocol_handle_one
    participant Ca as ca_get_serial
    participant Mbed as mbedtls X.509 parser
    participant Lfs as LittleFS

    Cli->>Disp: CBOR {cmd=0x04}
    Disp->>Ca: ca_get_serial(buf, &len)
    Ca->>Lfs: read /keys/0/cert.der
    Ca->>Mbed: x509_crt_parse_der
    Mbed-->>Ca: parsed.serial (ptr+len into cert)
    Ca-->>Disp: memcpy(buf, serial); *len = serial_len
    Disp-->>Cli: CBOR {err=0, data=serial}
```

Identical bytes to `parsed.serial.p / .len` after parsing slot 0's cert.

---

## Failure modes

| Condition | `ca_get_serial` | wire err |
| --- | --- | --- |
| `buf == NULL` or `*len == 0` | `-EINVAL` | `ERR_STORAGE` |
| Slot 0 cert missing (not yet bootstrapped) | `-ENOENT` | `ERR_STORAGE` |
| Cert parse fails (corrupt) | `-EIO` | `ERR_STORAGE` |
| Caller buffer smaller than serial | `-ENOMEM` | `ERR_STORAGE` |

---

## Code map

| File | Role |
| --- | --- |
| [firmware/src/ca/ca.c](../../firmware/src/ca/ca.c) | `ca_get_serial` — parse cert, copy `parsed.serial` |
| [libcantil/src/ca.c](../../libcantil/src/ca.c) | `cantil_get_ca_serial` (caller-supplied fixed buffer per the header signature) |

---

## Tests (extended sign_csr suite — now 9 PASS)

- `test_07_get_ca_serial_matches_cert` — round-trip parity with `mbedtls_x509_crt_parse_der(slot0_cert).serial`.
- `test_08_get_ca_serial_before_bootstrap_errors` — pre-bootstrap fails and clears `*len`.
- `test_09_get_ca_serial_buffer_too_small` — 4-byte buffer for 8-byte serial → `-ENOMEM`.

## Session log

Small task. The client header [libcantil/include/cantil.h](../../libcantil/include/cantil.h)
already declared `cantil_get_ca_serial` with a caller-supplied buffer (no
heap), so the implementation pattern differs from `cantil_sign_csr` /
`cantil_get_ca_cert` (which malloc and return heap pointers). Matched the
declared signature rather than rewriting the header.
