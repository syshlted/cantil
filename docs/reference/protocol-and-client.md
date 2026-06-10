# Reference: Host Client, CBOR Wire Protocol & libcantil

> Relocated verbatim from CLAUDE.md (token-cost trim). Authoritative protocol/client reference.
> Per-command implementation detail: [docs/ca/NN-*.md](../ca/). Transport/session-cert detail: [docs/transport-and-pairing.md](../transport-and-pairing.md).

## Host Client Utility

Communicates with the device over `/dev/ttyACM0` (Linux/macOS) or `COMx` (Windows).

**USB device identity.** The firmware enumerates with VID:PID **0x1209:0x00CA** (`CONFIG_USB_DEVICE_VID` / `CONFIG_USB_DEVICE_PID` in `firmware/prj.conf`), manufacturer `Cantil`, product `Cantil Hardware CA`. The USB iSerial is the FICR-derived per-unit string and is stable across reboots. `0x1209` is the [pid.codes](https://pid.codes/) shared open-source hardware VID; `0x00CA` is registered at [https://pid.codes/1209/00CA/](https://pid.codes/1209/00CA/).

**Discovery.** `cantil_list_usb_devices()` walks `/sys/bus/usb/devices` and returns one entry per attached Cantil device with both ACM nodes resolved (protocol = interface :1.0, console = interface :1.2). Use `cantil list` from the CLI as a smoke test.

Protocol:

1. Open serial port (115200 baud or USB CDC native speed)
2. Noise_XX handshake (authenticate device, establish session key)
3. Length-prefixed CBOR messages inside encrypted session
4. Commands: `SIGN_CSR`, `GET_CERT`, `LIST_CERTS`, `REVOKE_CERT`, `DEVICE_STATUS`

### Building the cantil CLI

```bash
# Standard (dynamic) build — inside the ubuntu2604 distrobox
cd libcantil && cmake -B build . && cmake --build build
# → libcantil/build/cantil  (needs libsodium.so.23 + libmbedx509.so.7 at runtime)

# Static build — no runtime lib deps beyond glibc; can run on the Fedora host
cd libcantil && cmake -B build_static -DCANTIL_CLI_STATIC=ON . && cmake --build build_static
# → libcantil/build_static/cantil  (preferred for flatpak-spawn --host use)
```

Running from inside a flatpak (Claude Code) requires `flatpak-spawn --host` to reach USB CDC/ACM devices. The static binary satisfies that requirement because it doesn't need container-installed libraries. See [docs/build-and-release.md](../build-and-release.md) for the ttyACM1 echo workaround and `provision_fw_signing_cert.sh` usage.

## Client Library (libcantil)

C library that manages the client-side transport, Noise_XX session, and CBOR device protocol. Both USB and BLE transports are supported; the Noise session is identical for both, so a single client codebase handles both paths.

See [libcantil/include/cantil.h](../../libcantil/include/cantil.h) for the full public API.

### Directory Layout

```text
libcantil/
├── include/
│   ├── cantil.h           ← transport, session, CA ops, key slots, cert store
│   └── cantil_random.h    ← standalone TRNG utilities (independently importable)
├── src/
│   ├── transport.c        ← transport abstraction
│   ├── transport_usb.c    ← CDC/ACM via POSIX termios / Win32
│   ├── transport_ble.c    ← BLE NUS via BlueZ D-Bus (Linux)
│   ├── session.c          ← Noise_XX handshake and framing
│   ├── protocol.c         ← CBOR command encoding / decoding
│   ├── ca_ops.c           ← CA management, cert signing, cert store
│   ├── key_ops.c          ← key slot management (gen, CSR, push cert)
│   └── random.c           ← TRNG device call + format converters
└── CMakeLists.txt        ← links mbedtls (X25519 + ChaCha20-Poly1305 + SHA-256)
```

### API Surface Summary

| Group | Header | Key functions |
| --- | --- | --- |
| Session keys | `cantil.h` | `cantil_keygen`, `cantil_pubkey_from_privkey` |
| USB discovery | `cantil.h` | `cantil_list_usb_devices` (Linux sysfs walk; matches VID:PID 0x1209:0x00CA) |
| Transport | `cantil.h` | `cantil_transport_open_usb/ble`, `cantil_transport_close` |
| Session | `cantil.h` | `cantil_session_open/close`, `cantil_session_get_device_pubkey` |
| Device | `cantil.h` | `cantil_get_status` |
| CA management | `cantil.h` | `cantil_get_ca_cert/chain/serial`, `cantil_get_ca_csr`, `cantil_push_ca_cert` |
| Cert signing | `cantil.h` | `cantil_sign_csr` |
| Cert store | `cantil.h` | `cantil_list_certs`, `cantil_get_cert`, `cantil_get_cert_count` |
| Revocation/CRL | `cantil.h` | `cantil_revoke_cert`, `cantil_auto_expire`, `cantil_get_crl` |
| Key slots | `cantil.h` | `cantil_list_keys`, `cantil_gen_key`, `cantil_delete_key`, `cantil_push_key_x509`, `cantil_gen_key_csr`, `cantil_get_key_csr`, `cantil_push_key_cert`, `cantil_get_key_chain`, `cantil_protect_slot`, `cantil_unprotect_slot`, `cantil_sign_csr_slot` |
| Configuration | `cantil.h` | `cantil_set_unlock_sequence` |
| TRNG (device) | `cantil.h` | `cantil_random_bytes` |
| TRNG utilities | `cantil_random.h` | `cantil_rand_*` — all format converters, pluggable source |

## CBOR Wire Protocol

All commands are length-prefixed CBOR maps inside the Noise session.

Request: `{ "cmd": <uint>, "seq": <uint>, "data": <bstr optional> }`
Response: `{ "seq": <uint>, "err": <uint>, "data": <bstr optional> }`

**CA management (0x01–0x0F):**

Convenience aliases that always target **slot 0** (the master CA slot, created on first boot). Prefer the generic key-slot commands (0x20–0x2F) for multi-CA use.

| Command | Code | Request | Response |
| --- | --- | --- | --- |
| `SIGN_CSR` | 0x01 | CSR DER | Signed cert DER (slot 0 signs; use `SIGN_CSR_SLOT` for other slots) |
| `GET_CA_CERT` | 0x02 | — | CA cert DER (slot 0) |
| `GET_CA_CHAIN` | 0x03 | optional BE u32 slot (empty = slot 0) | Concatenated chain DER (leaf first, walker recurses to issuer slots / appends pushed chain.der) |
| `GET_CA_SERIAL` | 0x04 | — | Serial bytes (slot 0) |
| `GET_CA_CSR` | 0x05 | — | CA CSR DER (slot 0, for subordinate CA enrolment) |
| `PUSH_CA_CERT` | 0x06 | cert DER + chain DER | — (slot 0) |

**Certificate store (0x10–0x1F):**

Each issued cert records its `issuer_slot` in metadata. `REVOKE_CERT` and `AUTO_EXPIRE` update the CRL for the issuer slot. Certs with the `protected` flag set are immune to manual revocation; automatic expiry still applies.

| Command | Code | Request | Response |
| --- | --- | --- | --- |
| `LIST_CERTS` | 0x10 | optional issuer slot ID | Array of cert info maps |
| `GET_CERT` | 0x11 | Serial bytes | Cert DER |
| `GET_CERT_COUNT` | 0x12 | optional issuer slot ID | uint32 |
| `REVOKE_CERT` | 0x13 | Serial bytes | — (issuer slot's CRL updated; blocked for protected certs) |
| `AUTO_EXPIRE` | 0x14 | Unix timestamp uint64 | Count of newly expired uint32 (device has no RTC; host provides timestamp) |
| `GET_CRL` | 0x15 | issuer slot ID uint32 | CRL DER for that slot |

**Key slot management (0x20–0x2F):**

A slot binds a private key, x509 subject data, and certificates. The device auto-generates a self-signed cert whenever both a key and x509 data are present in the slot. Replacing either the key (via `GEN_KEY`) or the x509 data (via `PUSH_KEY_X509`) regenerates the self-signed cert. An externally-signed cert pushed via `PUSH_KEY_CERT` takes precedence until the key or x509 data changes, at which point the self-signed cert is restored.

CSRs are stored only for key slots (max 8); CSRs from external signing requests are not stored (the signed cert is the output).

| Command | Code | Request | Response |
| --- | --- | --- | --- |
| `LIST_KEYS` | 0x20 | — | Array of key slot info maps (includes protection flag, cert status) |
| `GEN_KEY` | 0x21 | slot ID uint32 + key type uint8 | — (auto-generates self-signed cert if x509 data present; blocked for protected slots) |
| `GEN_KEY_CSR` | 0x22 | slot ID + subject DN | — (generates external-enrollment CSR stored in slot) |
| `GET_KEY_CSR` | 0x23 | slot ID | CSR DER |
| `PUSH_KEY_CERT` | 0x24 | slot ID + cert DER + chain DER | — (installs externally-signed cert; overrides self-signed) |
| `SIGN_KEY_SLOT` | 0x25 | issuer slot ID + subject slot ID | — (cert stored in subject slot; issuer slot must be unlocked and is a CA) |
| `PUSH_KEY_X509` | 0x26 | slot ID + packed x509 data blob (format below) | — (updates subject DN, validity, extensions; auto-regenerates self-signed cert if key present) |
| `DELETE_KEY` | 0x27 | slot ID | — (blocked for protected slots; deletes key, certs, x509 data, and CSR) |
| `PROTECT_SLOT` | 0x28 | slot ID + protect_issued_certs bool | — (tap confirmation required within 10 s; LED: confirm sequence → confirmed/fail) |
| `UNPROTECT_SLOT` | 0x29 | slot ID | — (tap confirmation required within 10 s; LED: confirm sequence → confirmed/fail) |
| `SIGN_CSR_SLOT` | 0x2A | issuer slot ID + CSR DER | Signed cert DER + issuer cert DER |

**x509 data wire format** (the payload that follows the 4-byte BE slot ID in the `PUSH_KEY_X509` request — packed binary, NOT CBOR; matches `x509_parse` in [firmware/src/ca/ca.c](../../firmware/src/ca/ca.c)). Total ≤ 512 bytes (`X509_DATA_MAX`):

```text
offset  size  field
0       2     validity_days   (BE u16, required, non-zero)
2       1     is_ca           (0 or 1)
3       1     path_len        (0..253; 0xFF = unconstrained; ignored when is_ca=0)
4       2     key_usage       (BE u16 bitmask, RFC 5280 §4.2.1.3 BIT STRING numbering)
6       1     cn_len          (required, > 0)
7       N     cn bytes        (≤ 64)
…             O               ([len u8][bytes], len may be 0)
…             OU              ([len u8][bytes])
…             C               ([len u8][bytes], len must be 0 or 2)
…             ST              ([len u8][bytes])
…             L               ([len u8][bytes])
```

**`key_usage` bits** (only the three the firmware emits today):

| Constant | Hex | RFC 5280 bit |
| --- | --- | --- |
| `KU_DIGITAL_SIGNATURE` / `CANTIL_KU_DIGITAL_SIGNATURE` | `0x0080` | bit 0 |
| `KU_KEY_CERT_SIGN` / `CANTIL_KU_KEY_CERT_SIGN` | `0x0004` | bit 5 |
| `KU_CRL_SIGN` / `CANTIL_KU_CRL_SIGN` | `0x0002` | bit 6 |

Client helper: `cantil_push_key_x509(s, slot, &(cantil_x509_data_t){…})` in [libcantil/include/cantil.h](../../libcantil/include/cantil.h) takes ordinary C strings (NULL or "" for optional fields) and `int8_t path_len = -1` for unconstrained — the helper does the encoding.

**Slot protection rules:**

- `PROTECT_SLOT` requires a tap-confirmation gesture within 10 seconds (configurable). Device emits confirm-sequence LED pattern while waiting; emits confirmed or fail on result.
- `protect_issued_certs = true`: all certs currently signed by this slot, and any future certs signed by it, are marked protected. Protected certs cannot be manually revoked but do expire automatically.
- Protected slots cannot be overwritten by `GEN_KEY`, `PUSH_KEY_CERT`, `PUSH_KEY_X509`, or `DELETE_KEY`.
- Slot 0 (master CA) is protected on first boot by default.

**Device (0x30–0x3F):**

| Command | Code | Request | Response |
| --- | --- | --- | --- |
| `DEVICE_STATUS` | 0x30 | — | Status map |
| `SET_UNLOCK_SEQ` | 0x31 | Tap sequence bytes | — |
| `RESET_DEVICE` | 0x32 | — | — (tap confirmation required; erases all keys, certs, and config; restores factory defaults) |

**TRNG (0x40–0x4F):**

| Command | Code | Request | Response |
| --- | --- | --- | --- |
| `GET_RANDOM` | 0x40 | Length uint16 | Random bytes |

**Baby names (0x50–0x5F):**

| Command | Code | Request | Response |
| --- | --- | --- | --- |
| `GET_RANDOM_NAMES` | 0x50 | Count uint16 | Packed 6-bit bitstream (see below) |

**Session identity / pairing (0x60–0x6F):** see [docs/transport-and-pairing.md](../transport-and-pairing.md) for the full opcode set and status.

**Baby name encoding:**

- Source: SSA top-1000 baby names (2025), boy + girl lists deduplicated → 1919 unique names
- Names stored and transmitted as raw UTF-8 bytes (lowercase)
- Separator: `0xFF` — an invalid UTF-8 byte, safe delimiter for any language or script
- Format: `<name-utf8-bytes> 0xFF <name-utf8-bytes> 0xFF …` (last name also terminated)
- `count` is clamped to `NAMES_BATCH_MAX = 64` by the device
- Client decodes by splitting on `0xFF`; see `cantil_names_decode()` / `cantil_rand_names()` in `cantil_random.h`

**Regenerating name data** (after updating the source HTML):

```bash
python3 scripts/extract_names.py \
    "contrib/www.ssa.gov - Top Baby Names for 2025.html" \
    firmware/src/names/names_data
```

## Key Slot Storage Layout

```text
LittleFS on external QSPI (or internal flash partition):
/keys/
  0/                  ← CA key (always slot 0, created on first boot; protected by default)
    meta.bin          ← key type, creation timestamp, protected flag, protection scope
    key.bin           ← AES-256-GCM encrypted key blob
    x509_data.bin     ← packed-binary subject DN, validity, extensions (PUSH_KEY_X509 — see wire format above)
    cert.der          ← self-signed cert (auto-generated when key + x509_data both present)
    chain.der         ← optional; concatenated DER chain above this slot's cert,
                        written by PUSH_CA_CERT / PUSH_KEY_CERT when a chain is supplied;
                        cleared on self-signed regen and on PUSH_*_CERT with no chain
    csr.der           ← optional, written by GEN_KEY_CSR for external CA enrollment
    crl.der           ← CRL for certs signed by this slot (updated by REVOKE_CERT/AUTO_EXPIRE)
  1/ 2/ ...           ← general-purpose key slots (GEN_KEY allocates next free)
    meta.bin
    key.bin
    x509_data.bin     ← optional; triggers self-signed cert regen when written
    cert.der          ← self-signed (auto) or externally-signed (PUSH_KEY_CERT)
    chain.der         ← optional; chain above the externally-signed cert
    csr.der           ← optional, written by GEN_KEY_CSR
    crl.der           ← optional; present if this slot has ever signed a cert
/certs/
  <hex-serial>/
    cert.der
    meta.bin          ← subject DN, issuer_slot, timestamps, revocation status, protected flag
/config.bin           ← tap sequences, unlock timeout, LED parameters, protect-confirm timeout
```

(Session-identity slot `/session/` — see [docs/transport-and-pairing.md](../transport-and-pairing.md).)

## BLE Transport Notes

`transport_ble.c` communicates with BlueZ via D-Bus (`org.bluez.GattCharacteristic1`). BlueZ sees only Noise ciphertext — BLE LESC provides link-layer encryption as a bonus, but Noise_XX is the actual security gate.

## Trust-on-First-Use

Pass `device_pub = NULL` to `cantil_session_open` for the first connection. Retrieve and persist the device's static public key with `cantil_session_get_device_pubkey`. On subsequent connections, pass the pinned key to detect device substitution.
