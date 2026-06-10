# Transport Security and Pairing — Design

**Status:** Design locked 2026-05-30 (session 048). Phase A complete — T-01, T-02, T-03, T-04 done; T-03 hardware-verified (session 049) and T-04 hardware-verified (session 051). Phase B T-05 done and **hardware-verified** (2026-05-31, session 052). Phase B T-06 (`SIGN_SESSION_FROM_SLOT`, 0x62) done and **hardware-verified** (session 054, 2026-05-31). Phase B T-07 (`PUSH_SESSION_CERT`, 0x63) done and **hardware-verified** (session 055, 2026-06-02). T-08 done (2026-06-02, session 055). T-09 done (2026-06-03). Phase C T-10 + T-11 done (2026-06-03, session 056). T-12 done (2026-06-04, session 060). T-13 done (2026-06-04, session 061). T-14 done (2026-06-04, session 062). **Phase C complete.** T-15 done (2026-06-04, session 063): `/clients/` storage layout (`client_meta_t`, `client_bond_*` module), Kconfig caps, `CMD_LIST_CLIENTS`/`CMD_UNPAIR_CLIENT`/`CMD_SET_CLIENT_NAME` opcodes (0x70–0x72), libcantil `cantil_list_clients`/`cantil_unpair_client`/`cantil_set_client_name` + CLI `clients`/`unpair`/`name` subcommands; 9/9 ztests on native_sim. T-16 done (2026-06-04, session 064): `CANTIL_PAIRING_METHOD` Kconfig `choice` (PROMISCUOUS/TOFU; PROMISCUOUS = dev default until T-17), `pairing_check_and_bond()` in new `firmware/src/clients/pairing.c` — known client: pass; unknown + room: silent TOFU bond + pass; unknown + cap full: `-EACCES` reject; `main.c` passes `NULL` to `session_open` and calls the gate post-handshake; legacy `storage_client_pubkey_{write,read}` (`/noise/client_pub.bin`) removed; 3/3 ztests on native_sim. **T-17 done (2026-06-04, session 065):** `PAIRING_TAP_CONFIRM` Kconfig choice (release default), `CANTIL_STATE_AWAITING_PAIR` gesture state, `LED_PATTERN_PAIRING_PROMPT` (cyan 200/200 loop), `gesture_request_pair_confirm()` API (LOCKED or UNLOCKED origin; `Orange Orange` confirms; `CONFIG_CANTIL_PAIR_TIMEOUT_SEC` default 30 s); `pairing_check_and_bond()` TAP_CONFIRM path — cap-full rejected without prompt, unknown client blocks on semaphore until gesture callback fires; `firmware/tests/pairing/src/gesture_stub.c` drives 5/5 ztests on native_sim. **T-18 done (2026-06-04, session 066):** passkey — see T-18 entry below. **T-19 done (2026-06-05, session 067):** Method 4 CA-anchored — see T-19 entry below. **T-20 done (2026-06-05, session 068):** `PAIRING_CA_ANCHOR_PLUS_PASSKEY` Kconfig choice; shared passkey helpers (`generate_passkey`, `blink_passkey`, `derive_psk`, `send_reply`, `passkey_exchange_and_bond`) extracted to a `#if PAIRING_PASSKEY || PAIRING_CA_ANCHOR_PLUS_PASSKEY` section in `pairing.c`; Method 5 `pairing_check_and_bond()`: (1) known client → pass immediately; (2) validate client cert chain against anchor slot; (3) cap check; (4) passkey exchange + tap-confirm + PSK bond; `CONFIG_CANTIL_CA_ANCHOR_SLOT` now depends on either Method 4 or 5; passkey timeout/blink Kconfig items likewise extended; `tests/pairing_ca_anchor_passkey/` 8/8 ztests on native_sim (valid cert+passkey bonded; no cert; wrong CA; wrong passkey; timeout; gesture denied; known client; cap full). **T-21 done (2026-06-05, session 069):** promiscuous disallowed in release via Kconfig `depends on !CANTIL_SESSION_X509_STRICT` + `BUILD_ASSERT` defense-in-depth; 5/5 pairing ztests native_sim. **Phase D complete. T-22 done (2026-06-05, session 070):** documentation contract header comment block added to top of `firmware/src/session/session.c` and `libcantil/src/session.c`; build clean 237,376 B. **T-23 done (2026-06-05, session 071):** new [docs/transport-security.md](transport-security.md) end-user guide (trust tiers, pairing methods, threat model, cert lifecycle, deployment recipes). **T-24 done (2026-06-05, session 072):** CLAUDE.md + Open Questions updated. **T-25 done (2026-06-05, session 073):** per-task design notes written for `PUSH_SESSION_CERT` (T-07/0x63), `LIST_CLIENTS`/`UNPAIR_CLIENT`/`SET_CLIENT_NAME` (T-15/0x70–72), and `PAIRING_PASSKEY_REPLY` + Methods 4/5 (T-18–T-20/0x73) — see [docs/ca/18-push-session-cert.md](../docs/ca/18-push-session-cert.md), [docs/ca/19-client-bond-management.md](../docs/ca/19-client-bond-management.md), [docs/ca/20-pairing-passkey-reply.md](../docs/ca/20-pairing-passkey-reply.md). **Phase E complete.**
**Revised 2026-05-30 (T-02 prep):** the session cert uses a **P-256 identity key**, not an RFC 8410 `id-X25519` SPKI — an X25519 key cannot sign and this mbedtls has no Ed25519/X25519 X.509 support. See [Session slot](#session-slot) and decision #2.
**Supersedes ad-hoc statements in:** [CLAUDE.md](../CLAUDE.md) "Transport Security" section, [libcantil/include/cantil.h](../libcantil/include/cantil.h) TOFU notes.

---

## TL;DR

- Wire protocol stays **Noise_XX_25519_ChaChaPoly_SHA256**. No TLS.
- The device's Noise static key is packaged as an **X.509 certificate** stored in a dedicated **session slot** (`/session/`). Subject-side x509 fields come from a build-time **TOML** constant.
- The certificate is **metadata about the static key**, not a TLS credential. Validation is done by libcantil against an application-supplied trust policy — no standard PKI path validation, no system trust store, no OCSP/CRL fetch.
- The cert is **self-signed by default**. It may be optionally signed by an on-device CA slot or by an external CA via a CSR round-trip. All signing flows are **manual**.
- The cert chain is delivered inside the encrypted payload of Noise msg2, dynamically assembled by the existing chain walker.
- Four **client-side trust tiers** (none / pinned self-signed / CA-allowlist / CA + CN pin) and six **device-side pairing methods** (promiscuous through CA+passkey), both build-time selectable.
- Release default: **Method 2 (tap-confirmed bond)** on the device, **Tier 2 or 3** on the client depending on deployment.
- Device-to-device pairing piggy-backs on the same mechanism over BLE NUS. Key replication between paired devices is sketched here and deferred to a follow-up task.

---

## Threat model

Defenses we want from the transport+pairing layer:

| Threat | Defense |
|---|---|
| Passive USB-bus sniffer | Noise_XX ChaCha20-Poly1305 session encryption |
| Active USB-bus MitM | Noise_XX mutual auth + tap-confirmed bond on first contact |
| Stolen device after pairing | Device-side state (LOCKED, unlock sequence, rate limit) — orthogonal to transport |
| Stolen client static-key file | Method 3 (passkey-derived PSK) if enabled; otherwise out of scope |
| Compromised on-device CA | Tier 4 (CN pin) on client; otherwise accepted as a trust-root compromise |
| Device-identity substitution by malicious firmware | Strict mismatch boot check + recovery mode |
| Quantum break of X25519 (future) | Out of scope today; PSK modifier (`Noise_XXpsk2_...`) is a hardening knob if needed later |

**Non-goals:**

- Standard PKI compatibility (cert chains are *not* expected to validate under OpenSSL/Browsers; the cert is a libcantil-internal artifact).
- Network-distributed revocation (no OCSP, no CRL HTTP endpoint).
- Hiding the *fact* that a device is a Cantil (USB descriptors expose VID:PID 0x1209:0x00CA and product string).

---

## Wire protocol — what changes vs. today

Noise_XX_25519_ChaChaPoly_SHA256 stays unchanged at the cryptographic level. The only change is **msg2 carries a CBOR payload** instead of being a fixed 96 B `e || ee_mixed || s_encrypted || es_mixed`.

```text
msg1 (initiator → responder):
    e                                  32 B    (unchanged)

msg2 (responder → initiator):
    e                                  32 B
    s_encrypted                        48 B    (32 B s + 16 B tag)
    cbor_payload_encrypted             N+16 B  (NEW; N ≥ 1 for empty map)

msg3 (initiator → responder):
    s_encrypted                        48 B
    cbor_payload_encrypted             M+16 B  (NEW; M ≥ 1)
```

**msg2 CBOR payload (responder → initiator):**

```cbor
{
  1: [ <cert_der_leaf>, <cert_der_intermediate>, ... ]   ; leaf always present
}
```

The chain is leaf-first. **The leaf (the session cert) is always element 0**, including for a self-signed device — so a self-signed device sends a single-element array `[leaf]`, not an empty one. (Decided 2026-05-30 during T-04: the earlier "empty array = self-signed" note contradicted the schema's explicit `<cert_der_leaf>` element and would have left Tier-2 fingerprint pinning with nothing to pin from the handshake. A genuinely empty payload now means only "device has no session cert yet", which cannot happen after T-02 first-boot init.) Phase A devices are self-signed, so T-04 assembles `[session_cert.der]` directly from the session slot; CA-signed chains (`chain.der`, Phase B) extend the array above the leaf.

**msg3 CBOR payload (initiator → responder):**

```cbor
{
  1: [ <cert_der_leaf>, ... ]   ; optional — only present under Method 4/5 (CA-anchored client)
}
```

When the client side has no cert (Tier 1/2/3 clients without a CA-issued client cert), msg3 payload is an empty CBOR map (`{}`, 1 byte).

The payload encryption uses the existing symmetric state — after the `es` (msg2) / `se` (msg3) DH steps mix into the key, the payload is encrypted with the resulting key and authenticated with Poly1305. **Tampering with or stripping the chain causes the handshake to fail at the next decrypt step.** This matters: certs are integrity-protected by the Noise math, not by their own signatures.

**Length-prefixed framing already accommodates variable msg2/msg3 sizes.** The fixed-96/64-byte handshake-size checks in [firmware/src/session/session.c](../firmware/src/session/session.c) (responder) and [libcantil/src/session.c](../libcantil/src/session.c) (initiator) are relaxed to minimums (`msg2 ≥ 96`, `msg3 ≥ 64`); the trailing payload length is recovered as `msg_len − 80` / `msg_len − 48`. An empty payload still emits a 16-byte AEAD token, collapsing msg2/msg3 to the legacy 96/64 sizes — which keeps the precomputed Noise_XX reference vectors in [firmware/tests/noise_session/](../firmware/tests/noise_session/) valid unchanged. (Implemented in T-04, 2026-05-30.)

---

## Session slot

A dedicated key slot for the Noise static key + its cert. **Not accessible via the regular `0x20–0x2F` key-slot opcodes.** Lives at `/session/` on LittleFS, not `/keys/N/`.

### Storage layout

```text
/session/
    key.bin           ; AES-256-GCM encrypted Curve25519 scalar (X25519 Noise key, 32 B plaintext)
    id_key.bin        ; AES-256-GCM encrypted P-256 scalar (cert-signing identity key)
    meta.bin          ; protect flags, init timestamp, "has been CA-signed" flag, raw X25519 pubkey
    cert.der          ; X.509 cert, ECDSA-self-signed at first boot
    chain.der         ; optional; non-empty after CA signing with chain
    csr.der           ; optional; written by GET_SESSION_CSR
```

The slot holds **two** keys: the Curve25519 scalar used for the Noise X25519 handshake (`key.bin`), and a separate **P-256 identity key** (`id_key.bin`) used only to sign the certificate. The cert's `SubjectPublicKeyInfo` is the P-256 identity key, and it is a standard **ECDSA-self-signed** X.509 cert built by the existing on-device cert writer (`build_self_signed_cert` in `ca.c`). The 32-byte X25519 Noise pubkey is bound into the cert as a **signed private-OID extension** (`1.3.6.1.4.1.58270.1.1` — a placeholder enterprise arc, replace before distribution), so a client validating the cert can confirm it attests to the same static key the Noise handshake authenticated. `meta.bin` also caches the raw X25519 pubkey for local checks.

> **Why P-256 and not RFC 8410 `id-X25519` (revised 2026-05-30, T-02 prep):** the X25519 static key is key-agreement-only and **cannot produce a signature**, so it can self-sign neither a cert nor a CSR. The mbedtls in NCS v3.0.2 has **no Ed25519/X25519 support** in its `x509write`/`mbedtls_pk` layer (it emits only ECDSA/RSA), so an `id-X25519` SPKI with an Ed25519 self-signature would need a hand-rolled ASN.1 writer plus a vendored Ed25519 signer. Instead a P-256 identity key signs a standard ECDSA cert via the existing, hardware-tested path, and the X25519 key rides in a signed extension. This drops the RFC-8410 SPKI purity the original design called for — which the **Non-goals** above already disclaim ("cert chains are *not* expected to validate under OpenSSL/Browsers") — in exchange for reusing the entire existing cert / CSR / sign path. CSRs and external-CA signing (Phase B) use standard ECDSA tooling too. The client's trust check (Phase C) compares the extension's X25519 key against the handshake static key, not the SPKI.

### TOML build-time constant

Source file: `firmware/session_x509.toml` (path overridable via `CONFIG_CANTIL_SESSION_X509_TOML`).

```toml
# firmware/session_x509.toml
[subject]
cn = "Cantil"                 # OVERRIDDEN at init with FICR-derived device serial
o  = "My Organization"
ou = "Hardware CA — Transport"
c  = "CA"                     # 2-letter country code or empty
st = ""
l  = ""

[validity]
days = 3650                   # 10 years

[key_usage]
digital_signature = true
key_agreement     = true
# All others MUST be false. Explicit:
key_cert_sign     = false
crl_sign          = false
```

A CMake `add_custom_command` runs the Python helper `scripts/encode_session_x509.py`, which parses this into a packed `x509_data_t` blob and emits it as a generated C source (`build/firmware/cantil_session_x509_constant.c`) defining `const uint8_t cantil_session_x509_constant[]` + `const size_t cantil_session_x509_constant_len`, linked into the firmware. **Build fails if the file is missing, malformed, or sets disallowed KU bits.** (T-01, done — see [session_x509.h](../firmware/src/session/session_x509.h).)

### Boot-time init / verify

```text
session_init():
    if /session/key.bin does not exist:
        generate fresh X25519 keypair via TRNG          (Noise handshake key)
        generate fresh P-256 identity keypair via TRNG  (cert-signing key)
        derive FICR device serial → "Cantil-<hex16>" CN string
        build x509_data_t from constant, overriding CN
        build ECDSA self-signed cert with the P-256 identity key, embedding
            the X25519 pubkey in the 1.3.6.1.4.1.58270.1.1 extension
        write key.bin, id_key.bin, meta.bin, cert.der
        return OK

    else:
        read stored cert.der
        compare subject-side fields (O, OU, C, ST, L, validity_days, KU)
            against constant. CN comparison ignored (FICR-derived per-device).
            Issuer and signature ignored (legitimately change on CA signing).

        if match:
            return OK
        if CANTIL_SESSION_X509_STRICT=y:
            enter recovery mode (see below)
        else:
            log warning, return OK
```

### Strict mode + recovery

When `CANTIL_SESSION_X509_STRICT=y` and the boot-time comparison fails:

- LED enters `LED_PATTERN_IDENTITY_MISMATCH` (sustained red↔yellow alternation, distinct from `FAIL` and `SEQ_ERROR`).
- Dispatcher rejects every opcode **except**:
  - `DEVICE_STATUS` (0x30) — for the client to know the device is in recovery
  - `UPDATE_FIRMWARE` (0x33) — push a corrected firmware image (`mcuboot` builds only)
  - `ACCEPT_IDENTITY_MIGRATION` (new opcode, TBD code) — tap-confirmed; overwrites stored cert with the new build's constant, exits recovery mode
- `RESET_DEVICE` (0x32) is also accepted in recovery mode, since wiping always works.

MCUboot image validation is upstream of all this and unaffected. A bad-identity firmware can be replaced via the normal MCUboot path.

Dev builds default to `CANTIL_SESSION_X509_STRICT=n` (warn + continue).

### Session slot opcodes

| Code | Name | Args | Response | Notes |
|---|---|---|---|---|
| `0x60` | `GET_SESSION_CERT` | — | cert DER | Useful for tier-2 pinning at first contact via out-of-band channel. (T-05, done.) |
| `0x61` | `GET_SESSION_CSR` | — | CSR DER | Builds a PKCS#10 CSR over the P-256 identity key; subject DN rebuilt from the build constant + FICR CN (byte-identical to the cert subject); X25519 key rides in a non-critical extensionRequest. Persisted to `/session/csr.der`. (T-05, done.) |
| `0x62` | `SIGN_SESSION_FROM_SLOT` | issuer_slot (u32) + force (bool) | — | Signs the session cert with the named CA slot. `force` required if cert is already CA-signed. (T-06, done.) |
| `0x63` (planned) | `PUSH_SESSION_CERT` | cert DER + chain DER + force (bool) | — | Pushes externally-signed cert. Validates SPKI matches stored Noise pubkey. `force` required if cert is already CA-signed |

Opcode numbers are reserved in the `0x60–0x6F` range. `0x60`/`0x61` assigned in T-05; `0x62` assigned in T-06; `0x63` assigned in T-07.

**Authorization:**

- All four require `UNLOCKED` state.
- `SIGN_SESSION_FROM_SLOT` and `PUSH_SESSION_CERT` additionally require **tap-confirm** (the cert is the device's identity to the world; changes shouldn't be silent).
- The session slot may **never** be used as `issuer_slot` in any opcode. Enforced at the dispatcher *and* by the KU bits in the cert.

### Re-signing rules

| From | To | Behavior |
|---|---|---|
| Self-signed | CA-signed (on-device or external) | Allowed without `force`. Warning logged. |
| CA-signed | Different CA-signed | Requires `force=true`. |
| CA-signed | Self-signed (downgrade) | Requires `force=true`. Reachable only via a new `RESET_SESSION_CERT` opcode (deferred). |

---

## Client trust tiers

libcantil exposes a `cantil_trust_policy_t`:

```c
typedef enum {
    CANTIL_TRUST_NONE,                  /* Tier 1: plaintext / promiscuous */
    CANTIL_TRUST_PINNED_SELF_SIGNED,    /* Tier 2: fingerprint + subject pin */
    CANTIL_TRUST_CA_ALLOWLIST,          /* Tier 3: chain validates to allowlisted root */
    CANTIL_TRUST_CA_PLUS_CN_PIN,        /* Tier 4: tier 3 + per-device CN match */
} cantil_trust_mode_t;

typedef struct {
    cantil_trust_mode_t mode;

    /* Tier 2 */
    const uint8_t       *expected_fingerprint;  /* SHA-256 of cert DER */
    const uint8_t       *expected_subject_der;  /* optional, for stronger pin */

    /* Tier 3, 4 */
    const cantil_trust_store_t *trust_store;    /* opaque, populated via cantil_trust_add_ca */

    /* Tier 4 */
    const char          *expected_cn;           /* FICR-derived device serial */
} cantil_trust_policy_t;
```

`cantil_session_open()` takes this policy and applies it after the Noise handshake delivers the chain via msg2.

| Tier | What's validated | When to use |
|---|---|---|
| 1 | Nothing (Noise still encrypts; cert ignored) | Plaintext-comparison testing on `native_sim`; talks to devices with TLS disabled |
| 2 | SHA-256 fingerprint match, optional subject DN match | Solo user, 1–3 devices, TOFU upgrade path |
| 3 | Cert chain validates to a CA in the allowlist | Fleet deployment with a trusted root |
| 4 | Tier 3 + leaf CN equals pinned per-device value | Production fleet — defends against rogue cert from compromised allowlisted CA |

**Trust store API:**

```c
cantil_trust_store_t *cantil_trust_store_new(void);
int  cantil_trust_add_ca(cantil_trust_store_t *s, const uint8_t *cert_der, size_t len);
int  cantil_trust_load_dir(cantil_trust_store_t *s, const char *path);   /* loads all *.der */
void cantil_trust_store_free(cantil_trust_store_t *s);
```

No default trust store is baked in. Applications decide what they trust.

**Revocation: deferred.** Tier 3 has no built-in revocation mechanism in v1. Document in client header that revocation requires a host-maintained fingerprint blocklist or upgrading to Tier 4 (CN pin acts as an effective per-device allowlist). Revisit when device count > 5.

---

## Device-side pairing methods

Build-time `choice CANTIL_PAIRING_METHOD`, default `METHOD2_TAP_CONFIRM` in release.

| ID | Kconfig | What it does | Defense | Storage / UX |
|---|---|---|---|---|
| 0 | `PAIRING_PROMISCUOUS` | Any client static key accepted. No bond. | None. | 0 / zero friction. **Disallowed in release builds.** |
| 1 | `PAIRING_TOFU` | First client to handshake successfully is bonded; others rejected. | Post-bond impostors. | 32 B per client / zero friction. |
| 2 | `PAIRING_TAP_CONFIRM` | Method 1 + tap-confirm gesture required to commit bond. | Bus-racing attackers. | 32 B per client / one tap per new client. |
| 3 | `PAIRING_PASSKEY` | Method 2 + 6-digit passkey blinked on LED, echoed by client. PSK from passkey mixed into all future sessions via `Noise_XXpsk2_...`. | Concurrent bus attacker, stolen-static-key-file impersonation. | 64 B per client / one tap + 6-digit entry per new client. |
| 4 | `PAIRING_CA_ANCHOR` | Client presents cert chain on msg3, validated against device's trust anchor (typically slot 0). No per-client bond. | Anything tier 4 catches at the device side. | 0 per-client / zero friction post-enrollment. |
| 5 | `PAIRING_CA_ANCHOR_PLUS_PASSKEY` | Method 4 + Method 3 layered. | Compromised-CA-mints-rogue-client. | Same as Method 3 / same UX as Method 3. |

### Pairing bond storage

```text
/clients/
    <hex-pubkey-prefix-8>/
        pubkey.bin        ; 32 B Curve25519 static pubkey
        meta.bin          ; kind (host/peer-device), created_at, friendly_name, last_seen
        psk.bin           ; optional, Method 3/5: 32 B PSK encrypted under FICR storage key
        cert.der          ; optional, Method 4/5: cached client cert for inspection / fingerprinting
```

Caps:
- `CONFIG_CANTIL_MAX_CLIENT_BONDS` (kind=HOST) default 4
- `CONFIG_CANTIL_MAX_PEER_BONDS` (kind=PEER_DEVICE) default 4
- Independent budgets; a fleet of peer devices doesn't consume host-client allowance.

### Pairing wire protocol

After Noise_XX completes:

1. Responder (device) checks if the initiator's static pubkey is in `/clients/`.
2. **Match found:** session opens normally. (For Method 3/5, the PSK is also loaded and used to validate a per-session challenge response on the first encrypted frame — TBD detail.)
3. **No match:**
   - Method 0: session opens.
   - Method 1: bond is created silently. Session opens.
   - Method 2: device enters `AWAITING_PAIR`, blinks `LED_PATTERN_PAIRING_PROMPT`. Tap-confirm gesture (`Orange Orange`, reuses existing pairing trigger) commits bond; timeout/denial rejects.
   - Method 3: device generates passkey, blinks digits. Client sends `PAIRING_PASSKEY_REPLY` frame with the digits. Device validates → tap-confirm → commit bond, store PSK.
   - Method 4: client should have sent its cert chain on msg3. Validate. If valid, session opens; if not, session aborts.
   - Method 5: Method 4 validation + Method 3 passkey + tap-confirm.

### New opcodes for bond management

| Code | Name | Args | Response | Notes |
|---|---|---|---|---|
| TBD | `LIST_CLIENTS` | — | CBOR array of bond metadata | One entry per `/clients/<id>/` |
| TBD | `UNPAIR_CLIENT` | pubkey (32 B) | — | Tap-confirmed. Removes bond. |
| TBD | `SET_CLIENT_NAME` | pubkey (32 B) + name (utf-8) | — | Friendly name for `LIST_CLIENTS` display |

Reserved range: `0x70–0x7F`.

---

## Device-to-device pairing — sketch

A Cantil device can act as a client to another Cantil device. Use cases: secure key replication, multi-master CA setups, paired-device redundancy.

### Transport

Two peer transports, picked by deployment:

- **Wired UART + presence pin (preferred for co-located units).** Two XIAOs jumpered together — see [Wired peer link](#wired-peer-link--uart--presence-pin) below. Reliable, high-throughput (≤1 Mbaud ≈ ~100 KB/s), low-power, no radio congestion. Right answer for docked / same-enclosure / bench-paired devices.
- **BLE NUS, central role (wireless / non-adjacent units).** USB host mode on nRF52840 is OTG-capable but XIAO BLE Sense doesn't expose the OTG ID pin, so USB-between-devices is out. BLE central is the workable wireless common-denominator path.

Both peer transports share the same encrypted CBOR core but use a **dedicated command map** — see [Peer-link command isolation](#peer-link-command-isolation).

### Wired peer link — UART + presence pin

For two physically-adjacent Cantil units, a wired link avoids USB-host limitations and 2.4 GHz congestion entirely. Same-ground, short-range only — not a wireless substitute.

**Physical layer.** Hardware UARTE (not bit-banged — nRF52840 routes UARTE to any GPIO via `PSEL`, EasyDMA moves bytes while the CPU sleeps):

| Wire | Purpose | Mechanism |
|---|---|---|
| TX → RX, RX ← TX | bidirectional data | UARTE, ≤1 Mbaud, optional RTS/CTS (2 more wires) for high-throughput backpressure |
| PRESENCE_A → IN_B, PRESENCE_B → IN_A | peer alive/ready detect + wake | GPIO input w/ pull-down; peer drives high when booted + transport up. Disconnected/unpowered reads low. GPIOTE PORT event wakes a sleeping device on connect |
| GND | shared reference | mandatory |

Reliability is **not** UART's job — it has no ACK/retransmit/framing. The existing CBOR length-prefix + CRC + Noise framing (reused unchanged from the USB/BLE transports) provides message boundaries and corruption detection; bit errors over a short jumper are negligible. Add RTS/CTS or generous DMA buffers if the link is ever saturated.

**Heartbeat / sleep / wake lifecycle.** Steady state: each side sends a heartbeat every **250 ms**. After **4 missed beats (~1 s)** the peer is presumed gone: the UART device is suspended (`pm_device_action_run(..., PM_DEVICE_ACTION_SUSPEND)` applies the pinctrl sleep state), the **RX pin is reconfigured to a GPIO sense input** (idle UART line is HIGH; a start bit is a falling edge to LOW), and the device sleeps. Wake re-applies the UART pinctrl state and resumes.

Two design constraints, both handled:
- **Lost wake byte.** The falling edge that wakes the receiver *is* the first start bit, but the UART isn't running yet to capture it. The transmitting side prepends a short **wake preamble** (e.g. `0x00 0x00`) that the woken side discards before the first framed message.
- **Mutual-sleep deadlock.** If both peers sleep, neither can spontaneously transmit to wake the other. The wake source is therefore **the presence pin** (physical reconnect / peer power-up drives it, firing a GPIOTE wake) — not the RX-line edge alone. The heartbeat-loss path handles "peer left"; the presence pin handles "peer returned." Only the **RX pin** (an input) is monitored for the data-line edge; TX is an output and is not watched.

Runtime pin-function switching (UART ⇄ GPIO-sense) is supported on the nRF52840 via Zephyr pinctrl states (`pinctrl-0` active / `pinctrl-1` sleep) + device PM; pins are not statically bound to the peripheral.

### Peer-link command isolation

**Decision: the device-to-device link uses a dedicated CBOR command map, disjoint from the `ttyACM`/host map, enforced by a separate fail-closed dispatch table.** This is a deliberate command-confinement / confused-deputy mitigation: a peer device must never be able to invoke a host-only operation (e.g. `SIGN_CSR`, `GEN_KEY`, `SIGN_KEY_SLOT`, `RESET_DEVICE`), and a host must never reach peer-only replication opcodes.

Enforcement model (in order of robustness):

- **Separate dispatch tables per transport, not one table with an allow/deny filter.** A shared table filtered by a denylist is fail-*open* by omission — a newly-added opcode leaks unless someone remembers to gate it. Two distinct dispatchers (or two `switch`es selected by `session->transport`) are fail-*closed*: any opcode absent from the peer-link table falls through to `default → ERR_INVALID_CMD`. Given the sensitivity of the host command set, fail-closed is mandatory here.
- **Disjoint opcode numbering, deliberately.** The peer-link map uses its own reserved block (**`0xA0–0xBF`**), never reusing the host `0x01–0x6F` numbers, so a misrouted frame cannot alias a host command by opcode-number collision. Same byte = same meaning is exactly the leakage being prevented; separate namespaces make overlap impossible, not merely disallowed.
- **`cantil_session_t` carries its origin transport.** A `transport`/`channel` tag is added to the session and branched on *before* the dispatch `switch` in [protocol.c](../firmware/src/protocol/protocol.c) (`protocol_handle_one` already receives `session`). The recovery-mode and LOCKED-state allowlists can become transport-aware off the same tag if needed.
- **Same wire machinery, different vocabulary.** CBOR codec + Noise_XX encryption are reused verbatim; only the command semantics are isolated.

This is recorded so it's an on-record active decision, not an accident of routing.

### Code structure

Two options:

- **(A)** Link a trimmed libcantil into firmware.
- **(B)** Add a thin on-device client SDK that calls the shared `common/` Noise + CBOR core directly, with a Zephyr-BLE-central transport stub.

**Recommend (B).** libcantil's POSIX transport, sysfs discovery, and D-Bus BLE glue would mostly be deleted in a port anyway. The genuinely-shared code (Noise state machine, CBOR codec, opcode handling) is already in `common/` and can be refactored to be host/device-agnostic.

### Pairing UX adapted for device-to-device

- **Method 2 (recommended default for device-to-device).** Both devices enter `AWAITING_PAIR` simultaneously, blink `LED_PATTERN_PAIRING_PROMPT`. User taps confirm on each. Two taps total.
- **Method 3 — Numeric Comparison variant.** Both devices derive the same 6-digit passkey from the Noise handshake transcript (HKDF over handshake hash + a domain separator). Both blink it. User watches both LEDs, tap-confirms if the patterns match. (BLE Numeric Comparison model.) Recommend this over tap-replay for device-to-device.
- **Method 4 (recommended for owned fleets).** Both devices share a common root CA — either one device's slot 0 acts as the fleet root, or both are enrolled under a third "fleet root" slot 0. They authenticate to each other purely via cert chains. Cleanest UX for >2 devices.

### Key replication mechanics (deferred)

Sketch only; full design when this task is picked up.

- `REPLICATE_SLOT(source_slot, dest_peer_pubkey)` — issued to the source device, which then opens a Noise session to the bonded peer and sends slot contents inside it.
- Key material cannot be pre-encrypted under the destination's storage key (FICR-derived, intrinsic to destination silicon). Instead the raw key travels inside the Noise session and is re-encrypted under the destination's storage key on receipt.
- Destination tap-confirms (`AWAITING_REPLICATION_ACCEPT`) before committing.
- `TRANSFER_SLOT` variant: source slot wiped on confirmed receipt. `REPLICATE_SLOT`: source slot retained (multi-master backup).
- Slot 0 (master CA) replication is its own opcode (`REPLICATE_ROOT_CA`) with extra tap-confirms on both sides. Disaster-recovery feature, not casual.

### Open questions for the device-to-device task

- Discovery: BLE scan + manufacturer-data filter, or explicit "introduce me to device B" semantics?
- Authorization granularity per peer: per-slot ACLs, or coarse "any bonded peer reads/replicates any slot"?
- Conflict resolution on replication target collision: refuse without `--overwrite`, or version chain?

---

## Documentation contract

The transport security story in user-facing docs **must** state, plainly:

> The wire protocol is Noise_XX_25519_ChaChaPoly_SHA256. Mutual authentication, forward secrecy, and confidentiality come from the Noise handshake, not from TLS or any PKI library. The session slot's X.509 certificate is metadata about the device's Noise static key, not a TLS credential. Certificate validation is performed by libcantil against an application-supplied trust policy (TOFU pin, fingerprint pin, or allowlisted root). It is not delegated to a standard X.509 path-validation library, does not involve a system trust store, and does not consult OCSP or network-distributed CRLs. The certificate binds an identity to the static key for client-side policy decisions; handshake security does not depend on the certificate at all.

Places this lands:

- New top-of-file header comments in `firmware/src/session/session.c` and `libcantil/src/session.c`.
- New "Transport security model" section in [docs/storage.md](storage.md) or this file (already here).
- Update CLAUDE.md "Architecture Decisions → Transport Security" entry to point here.
- README, when written.

---

## Implementation roadmap

Ordered so each task can be built and tested independently. Reference task numbers in commit messages: `task T-NN: ...`.

### Phase A — Session slot foundation

- **T-01.** TOML schema, `scripts/encode_session_x509.py`, CMake glue. Build fails on missing/malformed TOML. Unit test: load known-good and known-bad TOMLs.
- **T-02.** ✅ Done (2026-05-30). `/session/` storage layout (`storage_session_*` in [storage.c](../firmware/src/storage/storage.c)), `session_slot_init()` boot-time logic + first-boot keygen ([session_slot.c](../firmware/src/session/session_slot.c)), ECDSA self-signed cert with the X25519 binding extension via new `ca_build_session_cert()` ([ca.c](../firmware/src/ca/ca.c)). 5-test ztest at [firmware/tests/session_slot/](../firmware/tests/session_slot/). The X25519 key is still sourced from the canonical `/noise/` store (single source of truth); T-04 flips `session.c` over to read the slot. The `session_slot_init()` "already present" branch is the hook for T-03's strict comparison.
- **T-03.** ✅ Done (2026-05-30). Boot-time subject comparison: `ca_session_cert_matches_constant()` ([ca.c](../firmware/src/ca/ca.c)) re-parses the stored cert and compares O/OU/C/ST/L + validity window + key_usage against the build constant, ignoring CN (per-device) and issuer/signature (change on CA signing). `session_slot_init()`'s "already present" branch now calls it: match → boot normally; mismatch under `CONFIG_CANTIL_SESSION_X509_STRICT` (default n dev, y in [release .conf](../firmware/boards/xiao_ble_nrf52840_sense_release.conf)) → latch recovery (`session_slot_in_recovery()`), else warn + continue. Recovery mode: `main.c` shows new `LED_PATTERN_IDENTITY_MISMATCH` (red↔yellow 500/500 loop); `protocol.c` rejects every opcode except `DEVICE_STATUS` / `RESET_DEVICE` with new `ERR_IDENTITY_MISMATCH` (UPDATE_FIRMWARE / ACCEPT_IDENTITY_MIGRATION join the allowlist when they exist). ztests: 4 new cases in [session_slot](../firmware/tests/session_slot/) (compare match + DN/KU/validity tamper + non-strict warn-continue), plus the dedicated strict-mode [session_recovery](../firmware/tests/session_recovery/) app (matching cert → no recovery, planted mismatch → recovery latched). FREE 225,208 B / ACCELERATED 289,204 B, both clean. **Hardware-verified on a real XIAO (session 049):** strict + matching constant → normal LOCKED (no false-positive); strict + drifted constant (changed `o` in the TOML, device cert untouched) → red↔yellow recovery LED while a second unit stayed normal; in recovery the `cantil` client got a successful `DEVICE_STATUS` but a rejected `GET_RANDOM` (err 9, surfaced as the client's "Unexpected response" since its enum lacks code 9 — a merely-locked unit would map to the known "Device is locked"); reverting the constant restored normal operation (the test perturbs only the build constant, never the stored cert, so it is fully reversible with no wipe). **Deferred:** DEVICE_STATUS does not yet surface a recovery bit — clients infer recovery from the `ERR_IDENTITY_MISMATCH` rejection.
- **T-04.** ✅ Done (2026-05-30). Wire format change: CBOR `{1:[bstr,…]}` payload on encrypted msg2 (responder identity chain, leaf-first) and msg3 (initiator payload — empty map `{}` until Method 4). Responder ([session.c](../firmware/src/session/session.c)): `collect_local_certs` (session slot in production, injected in tests) + `encode_chain_cbor` build the payload; msg2/msg3 are variable-length and share one static handshake buffer; msg3's client payload is decrypt-authenticated and ignored (Method 4 / T-19 will parse it). Initiator ([libcantil/src/session.c](../libcantil/src/session.c)): `parse_device_chain` decodes the chain into the session (`cantil_session_device_cert` / `_count` accessors, [internal.h](../libcantil/src/internal.h)) and sends `{}` on msg3. **`/noise/` retired** — `session_slot_init()` now generates the X25519 key directly and `session.c` loads it from `/session/key.bin` (single source of truth); existing units already mirror the key there from T-02, so no migration. ztest [firmware/tests/session_chain/](../firmware/tests/session_chain/): a live in-test initiator drives the responder through empty (96-byte msg2, self-signed) / single-cert / 3-cert chains and asserts the bytes round-trip leaf-first. Builds clean: FREE 225,368 B / 76,128 B, ACCELERATED 289,360 B / 69,472 B. **Hardware-verified on a real XIAO (session 051, 2026-05-31):** dev FREE firmware flashed to unit #1; `cantil status` and `cantil random 16` both succeed over the Noise session — proving the device's X25519 static key now loads from `/session/key.bin` (`/noise/` retired), the variable-length msg2 `{1:[leaf]}` chain is parsed by the T-04 client, and encrypted CBOR round-trips both ways. Device identity unchanged across the `/noise/ → /session/` flip (clean TOFU), as predicted (existing units mirrored the key into `/session/` at T-02).

### Phase B — Session slot opcodes

- **T-05.** ✅ Done (2026-05-31). `GET_SESSION_CERT` (0x60) → `session_slot_get_cert` (existing reader). `GET_SESSION_CSR` (0x61) → new `session_slot_get_csr` ([session_slot.c](../firmware/src/session/session_slot.c)): decrypts the P-256 id key, derives the FICR CN, and calls new `ca_build_session_csr` ([ca.c](../firmware/src/ca/ca.c)) — mirrors `ca_build_session_cert` (subject DN via `build_dn`, KU from the constant, X25519 key as a non-critical extensionRequest), persists to `/session/csr.der`. Dispatcher in [protocol.c](../firmware/src/protocol/protocol.c) (both gated by the LOCKED + recovery checks like the other reads). libcantil: `cantil_get_session_cert` / `cantil_get_session_csr` ([ca.c](../libcantil/src/ca.c)). Storage helpers `storage_session_csr_{write,read}`. ztests 10–12 in [session_slot](../firmware/tests/session_slot/) (pre-init `-ENOENT`; CSR parses, subject DN + SPKI match the cert; X25519 extensionRequest matches the cached Noise pubkey) — 12/12 pass on native_sim. FREE 226,344 B, ACCELERATED links clean. **HARDWARE-VERIFIED (session 052, real XIAO unit #1):** `cantil session-cert` → 534 B self-signed cert (CN `Cantil-69A3031F0204C8EE`, FICR-derived); `cantil session-csr` → 379 B CSR, `openssl req -verify` self-signature OK, subject DN matches the cert, KU + the `1.3.6.1.4.1.58270.1.1` X25519 binding ride as extensionRequests, and the CSR SPKI equals the cert SPKI. **Bug found + fixed on hardware:** `ca_build_session_csr` built the CSR live in the dispatcher call chain with a 2 KB `der[CERT_DER_MAX]` stack local on top of the dispatcher's ~4 KB `resp_data` scratch — under the 8 KB main stack this overflowed and hard-faulted the device the first time `GET_SESSION_CSR` ran (the cert path never hit this because the cert is read from flash, not rebuilt). Fix: write the CSR straight into the caller's output buffer (no second stack scratch) and bump `CONFIG_MAIN_STACK_SIZE` 8192→12288 for the CSR/cert-signing opcodes' headroom (RAM ~80 KB / 256 KB). Two CLI subcommands `cantil session-cert` / `session-csr` (hex DER → pipe to openssl) were added to drive the smoke test.
- **T-06.** ✅ Done (2026-05-31, native_sim + **hardware-verified** session 054). `SIGN_SESSION_FROM_SLOT` (0x62): CA-sign the device's session transport-identity cert with an on-device CA slot. New `ca_sign_session_cert` ([ca.c](../firmware/src/ca/ca.c)) merges the two existing paths — subject side identical to `ca_build_session_cert` (subject DN via `build_dn` from the build constant + FICR CN, P-256 identity key as SPKI, KU from the constant, `is_ca` rejected, X25519 binding extension preserved) but the issuer DN + signature come from CA slot `issuer_slot` (`load_issuer_x509_params` + `load_slot_privkey`, mirroring `ca_sign_csr_slot`). New `session_slot_sign_from_slot(issuer_slot, force)` ([session_slot.c](../firmware/src/session/session_slot.c)) decrypts the P-256 id key, calls the new ca helper, overwrites `/session/cert.der`, and latches `meta.flags` bit0 (`SESSION_META_FLAG_CA_SIGNED`). **Re-signing rule:** self-signed → CA-signed is free; an already-CA-signed cert refuses re-sign with `-EEXIST` unless `force` (the broader CA-signed→anything matrix is T-08). Dispatcher ([protocol.c](../firmware/src/protocol/protocol.c)) gates on **tap-confirm** (reuses `await_protect_confirm`, same semaphore path as `PROTECT_SLOT`) + the existing LOCKED/recovery checks; request is BE u32 `issuer_slot` + 1-byte `force`. The session slot can never be an issuer (it isn't a numbered `/keys/` slot; `issuer_slot` is range-checked — full refuse-as-issuer sweep is T-09). A CA-signed cert still matches the build constant because the T-03 comparison ignores issuer/signature — no false recovery on next boot. libcantil: `cantil_sign_session_from_slot(s, issuer_slot, force)` ([ca.c](../libcantil/src/ca.c)); CLI `cantil session-sign <slot> [--force] <port>`. ztests 13–16 in [session_slot](../firmware/tests/session_slot/) (self→CA-signed: issuer≠subject, sig verifies under the CA cert pubkey, subject DN + SPKI + X25519 ext preserved; force-required re-sign; CA-signed-still-matches-constant; bad issuer slot `-ENOENT`/`-EINVAL`) — 16/16 pass on native_sim. FREE 228,260 B / ACCELERATED 292,252 B, both link clean.
- **T-07.** ✅ Done (2026-06-02, native_sim + **hardware-verified** session 055). `PUSH_SESSION_CERT` (0x63): install an externally-signed session leaf (+ issuer chain) over the Noise session. New `ca_validate_pushed_session_cert` ([ca.c](../firmware/src/ca/ca.c)) gates the pushed cert in order: (1) **SPKI** must equal the device's P-256 identity key (`mbedtls_pk_write_pubkey` vs `crypto_pubkey_from_privkey`); (2) the **X25519** binding extension must equal the stored Noise static key; (3) subject-side fields must match the build constant (reuses T-03 `ca_session_cert_matches_constant`, so a pushed cert can't drift the device into boot recovery); (4) for a CA-signed leaf, the **chain links are verified** — the concatenated-DER chain is split on the ASN.1 SEQUENCE length, the topmost cert is the trust anchor, and every link is signature-checked via `mbedtls_x509_crt_verify_with_profile` with a callback that clears `EXPIRED`/`FUTURE` (the device has no RTC, so only signatures/trust are judged). A self-signed leaf needs no chain; a CA-signed leaf with no chain is refused. New `session_slot_push_cert(cert, chain, force)` ([session_slot.c](../firmware/src/session/session_slot.c)) enforces the re-sign rule (`-EEXIST` unless `force`), derives the id pubkey for the SPKI gate, validates, then overwrites `/session/cert.der`, writes/clears `/session/chain.der`, and latches `SESSION_META_FLAG_CA_SIGNED` iff the leaf is CA-signed. New storage helpers `storage_session_chain_{write,read,exists,delete}`. The T-04 msg2 chain builder (`collect_local_certs`, [session.c](../firmware/src/session/session.c)) now splits and serves the stored chain after the leaf so a pushed chain reaches clients. Dispatcher ([protocol.c](../firmware/src/protocol/protocol.c)) gates on **tap-confirm** + LOCKED/recovery; request is `1-byte force ‖ BE u16 cert_len ‖ cert DER ‖ chain DER`. libcantil: `cantil_push_session_cert(s, cert, len, chain, chain_len, force)` ([ca.c](../libcantil/src/ca.c)); CLI `cantil session-push <cert.der> [--chain f] [--force] <port>` plus a `cantil ca-cert` fetch helper. ztests 17–21 in [session_slot](../firmware/tests/session_slot/) (self-signed round-trip, CA-signed + chain + force matrix, foreign-cert reject, CA-signed-without-chain reject, broken-chain reject) — 21/21 pass on native_sim. FREE 233,540 B / ACCELERATED 297,628 B, both link clean. **Hardware-verified (session 055, unit #1):** self-signed push, device-CA round-trip push (leaf+chain, `--force`), and a true **external openssl CA** push (CSR round-trip, fixed-window-mirrored, KU + X25519 ext copied) all installed and reflected by `session-cert`; wrong-validity-window and non-issuer-chain pushes both **rejected** with the stored cert left unchanged. **External-CA constraint surfaced:** because the session cert's validity window is a fixed synthetic constant (no RTC) and T-03/T-07 compare `notAfter`, an upstream CA must reproduce the device's exact window (`notBefore 20260101000000Z`, `notAfter` from `validity_days`) or the push is refused — see T-08 / a possible T-03 relaxation.
- **T-08.** ✅ Done (2026-06-02, session 055). Validity-window relaxation in `ca_session_cert_matches_constant` ([ca.c](../firmware/src/ca/ca.c)): a CA-signed session cert is allowed to have a different `notAfter` than the build constant (CA timestamps are host-controlled), while a self-signed cert is still strict. ztest_22 in [session_slot](../firmware/tests/session_slot/) confirms.
- **T-09.** ✅ Done (2026-06-03). Refuse-as-issuer enforcement: session slot may never be `issuer_slot` in any opcode. The session slot lives at `/session/` with no numbered `/keys/N/` ID; the guard is `issuer_slot >= CONFIG_CANTIL_MAX_KEY_SLOTS`. Added **dispatcher-level** range checks in [protocol.c](../firmware/src/protocol/protocol.c) for all four issuer-taking opcodes (`CMD_SIGN_SESSION_FROM_SLOT` before the tap-confirm, `CMD_SIGN_CSR_SLOT`, `CMD_SIGN_KEY_SLOT`, `CMD_GET_CRL`) — the check fires at the dispatcher before reaching the ca functions (which already have the same guard as defense-in-depth). ztests 23–24 in [session_slot](../firmware/tests/session_slot/) (out-of-range issuer for `ca_sign_csr_slot` and `ca_sign_key_slot`) — 24/24 pass on native_sim.

### Phase C — Client trust policy

- **T-10.** ✅ Done (2026-06-03, session 056). `cantil_trust_policy_t` API. `cantil_trust_mode_t` enum (Tier 1–4), `cantil_trust_store_t` opaque struct (internal `struct cantil_trust_store` holds a dynamic DER array), trust store lifecycle (`cantil_trust_store_new/add_ca/load_dir/free`) in new [libcantil/src/trust.c](../libcantil/src/trust.c) / [trust.h](../libcantil/src/trust.h). Public API in [libcantil/include/cantil.h](../libcantil/include/cantil.h): `CANTIL_ERR_TRUST = -15`, `cantil_trust_policy_t` struct (mode + `expected_fingerprint`/`expected_subject_der` for Tier 2, `trust_store` for Tier 3/4, `expected_cn` for Tier 4). `cantil_session_open` signature changed: `device_pub` replaced by `const cantil_trust_policy_t *policy` (`NULL` = Tier 1). CLI all call sites updated to `NULL` policy with T-14 TODO; raw X25519 pubkey pin dropped until T-14. Library builds clean.
- **T-11.** ✅ Done (2026-06-03, session 056). Tier 1 (NULL or `CANTIL_TRUST_NONE` → `CANTIL_OK` immediately) and Tier 2 (`CANTIL_TRUST_PINNED_SELF_SIGNED` → `crypto_hash_sha256` of leaf cert DER compared with `expected_fingerprint` via `sodium_memcmp`) implemented in `cantil_trust_check_policy` ([libcantil/src/trust.c](../libcantil/src/trust.c)). Tier 3/4 return `CANTIL_ERR_NOT_SUPPORTED` (T-12/T-13). Called from `cantil_session_open` after handshake. `cantil_trust_load_dir` uses POSIX `opendir/readdir`, loads all `*.der` files up to 64 KiB each, skips silently on read error. Libcantil builds clean; firmware 24/24 ztests pass unchanged.
- **T-12.** ✅ Done (2026-06-04, session 060). Tier 3 (`CANTIL_TRUST_CA_ALLOWLIST`) chain validation in [libcantil/src/trust.c](../libcantil/src/trust.c). Added mbedtls dependency (`mbedtls + mbedx509 + mbedcrypto`) to [libcantil/CMakeLists.txt](../libcantil/CMakeLists.txt). New `cantil_crt_profile` (P-256/SHA-256 only). `chain_vrfy_cb` clears EXPIRED/FUTURE (matches firmware policy; device has no RTC). `tier3_chain_validate`: parses the leaf (index 0) and intermediates (1..n) from the session chain, links them as `leaf.next`, then iterates over all CAs in `trust_store` calling `mbedtls_x509_crt_verify_with_profile`; passes on any CA that produces `rc==0 && flags==0`. Also adds the Tier 2 optional subject DN check: `tier2_check_subject` compares `cert.subject_raw` (raw DER, parsed via mbedtls) against `policy->expected_subject_der`; called after the fingerprint check when non-NULL. `CANTIL_TRUST_CA_PLUS_CN_PIN` still returns `CANTIL_ERR_NOT_SUPPORTED` (T-13).
- **T-13.** ✅ Done (2026-06-04, session 061). Tier 4 (`CANTIL_TRUST_CA_PLUS_CN_PIN`) in [libcantil/src/trust.c](../libcantil/src/trust.c). New `extract_cn_from_crt` helper walks `mbedtls_x509_name` chain looking for `MBEDTLS_OID_AT_CN`. `tier4_cn_validate`: runs `tier3_chain_validate`, then parses the leaf, extracts its CN into a 128-byte stack buffer, and `strcmp`s against `policy->expected_cn`. New public function `cantil_session_get_leaf_cn(session, buf, buflen)` (declared in [libcantil/include/cantil.h](../libcantil/include/cantil.h)): extracts CN from the session leaf cert — persistence helper for TOFU upgrade path (connect Tier 3, record CN, use Tier 4 next time). Builds clean.
- **T-14.** ✅ Done (2026-06-04, session 062). CLI trust policy flags. `--trust none|pin|ca|ca+cn`, `--ca-dir`, `--ca-cert`, `--cn` added globally to all commands (except `pair`/`list`). Default: Tier 2 when `session_fp.bin` is stored, Tier 1 otherwise. `pair` now saves `session_fp.bin` (SHA-256 of leaf DER) and `session_cn.bin` (FICR CN string) via four new helpers in `key_store.c`. All TODO T-14 markers cleared. Build clean. **Phase C complete.**

### Phase D — Device-side pairing

- **T-15.** ✅ Done (2026-06-04, session 063). `/clients/` storage layout (`client_meta_t`, `client_bond_*` module), Kconfig caps, `CMD_LIST_CLIENTS`/`CMD_UNPAIR_CLIENT`/`CMD_SET_CLIENT_NAME` opcodes (0x70–0x72), libcantil `cantil_list_clients`/`cantil_unpair_client`/`cantil_set_client_name` + CLI `clients`/`unpair`/`name` subcommands; 9/9 ztests on native_sim.
- **T-16.** ✅ Done (2026-06-04, session 064). Method 1 (silent TOFU) — `CANTIL_PAIRING_METHOD` Kconfig `choice` (PROMISCUOUS/TOFU), new `firmware/src/clients/pairing.c/.h` with `pairing_check_and_bond()`: known client passes, unknown client silently bonded (TOFU), cap-full rejects with `-EACCES`. `main.c` now passes `NULL` to `session_open` and calls the gate post-handshake on the authenticated `remote_s_pub`. Legacy `storage_client_pubkey_{write,read}` (`/noise/client_pub.bin`, single-key TOFU) removed. 3/3 ztests on native_sim (`tests/pairing/`): known allowed, TOFU bond created, cap-full rejected.
- **T-17.** ✅ Done (2026-06-04, session 065). Method 2 (tap-confirmed bond) — `CANTIL_STATE_AWAITING_PAIR` in `gesture.h/.c`, `LED_PATTERN_PAIRING_PROMPT` (cyan 200/200) in `led.h/.c`, `gesture_request_pair_confirm()` in `gesture.c`; `PAIRING_TAP_CONFIRM` Kconfig choice added to `firmware/Kconfig` and made the release default; `pairing.c` TAP_CONFIRM path (semaphore + callback); `firmware/tests/pairing/` updated with gesture stub and 5 ztests covering known-bond / tap-confirmed / tap-denied / tap-timeout / cap-full. 5/5 pass on native_sim.
- **T-18.** ✅ Done (2026-06-04, session 066). Method 3 (passkey) — `PAIRING_PASSKEY` Kconfig choice, `CONFIG_CANTIL_PASSKEY_TIMEOUT_SEC` + `CONFIG_CANTIL_PASSKEY_BLINK_PAUSE_MS`; `LED_PATTERN_PASSKEY_PROMPT` (purple 150/150); `CMD_PAIRING_PASSKEY_REPLY` (0x73) + `ERR_AUTH` (10) / `ERR_PASSKEY_REQUIRED` (11) in `protocol.h`; `pairing_check_and_bond()` Method 3 path: random 6-digit passkey (TRNG), digit blink via `led_blink_digit()`, `session_recv()` wait for reply, digit validation, `gesture_request_pair_confirm()` tap-confirm, PSK derivation (HKDF-SHA256, salt=device_pub‖client_pub, IKM=passkey_BE), PSK encrypted with FICR storage key and stored in `/clients/<id>/psk.bin`; `pairing_check_and_bond()` now takes `cantil_session_t *session`; `pairing_test_passkey_hook()` weak symbol for test interception; `cantil_pairing_passkey_reply()` in libcantil/src/pairing.c; `cantil pair --passkey <digits>` CLI flag with interactive fallback prompt; `CANTIL_ERR_AUTH`/`CANTIL_ERR_PASSKEY_REQUIRED` error codes + `cantil_strerror()` entries; `tests/pairing_passkey/` 6/6 ztests on native_sim. **Note:** PSK stored for future use; per-session PSK enforcement (challenge-response or Noise_XXpsk3 variant) deferred as "TBD" in design doc — currently known PSK clients connect without PSK verification (bond-only gate).
- **T-19.** ✅ Done (2026-06-05, session 067). Method 4 (CA-anchored) — `PAIRING_CA_ANCHOR` Kconfig choice + `CONFIG_CANTIL_CA_ANCHOR_SLOT` (default 0); `session.c` now parses the client cert CBOR `{1:[bstr,…]}` from the authenticated msg3 payload and stores it in the session struct; `session_get_client_cert()` / `session_get_client_cert_count()` accessors in [session.h](../firmware/src/session/session.h); new `ca_validate_client_cert_chain(cert_ders[], cert_lens[], count, anchor_slot)` in [ca.c](../firmware/src/ca/ca.c) — loads the trust anchor cert from the slot's stored cert.der, then verifies the client chain (leaf → [intermediates] → anchor) via mbedtls with the existing `chain_vrfy_cb` (validity ignored, no RTC); `pairing_check_and_bond()` Method 4 path: no bond stored, no cap check — client with a valid cert chain is accepted, any other is rejected with `-EACCES`; libcantil `cantil_client_cert_t` struct + updated `cantil_session_open()` signature (new `const cantil_client_cert_t *client_cert` parameter before `timeout_ms` — `NULL` → sends `{}` on msg3); msg3 CBOR chain encoding with ASN.1 SEQUENCE split for intermediate certs; `key_store_save/load_client_cert/chain()` persistence helpers; CLI `cantil pair --client-cert <f> [--client-chain <f>]` saves cert to key store; all commands auto-load stored cert; `tests/pairing_ca_anchor/` 5/5 ztests on native_sim (valid cert, no cert, wrong CA, missing anchor, corrupted DER). FREE 237,376 B, libcantil + CLI build clean.
- **T-20.** ✅ Done (2026-06-05, session 068). `PAIRING_CA_ANCHOR_PLUS_PASSKEY` Kconfig choice. Shared passkey helpers extracted from the PAIRING_PASSKEY block into a common `#if PAIRING_PASSKEY || PAIRING_CA_ANCHOR_PLUS_PASSKEY` section. Method 5 flow: known client → pass; cert chain validation (Method 4 gate); cap check; passkey + tap-confirm + PSK bond (Method 3 gate). Bond stored with PSK. `tests/pairing_ca_anchor_passkey/` 8/8 ztests on native_sim.
- **T-21.** ✅ Done (2026-06-05, session 069). Promiscuous mode disabled in release builds via Kconfig guard: `PAIRING_PROMISCUOUS` in [firmware/Kconfig](../firmware/Kconfig) gains `depends on !CANTIL_SESSION_X509_STRICT` — when `CANTIL_SESSION_X509_STRICT=y` (set in the release overlay) the choice option is unavailable, preventing selection in `menuconfig` and forcing the config resolution to the default (`PAIRING_TAP_CONFIRM`). Defense-in-depth `BUILD_ASSERT(!IS_ENABLED(CONFIG_CANTIL_SESSION_X509_STRICT), ...)` added in the `#else PAIRING_PROMISCUOUS` block of [firmware/src/clients/pairing.c](../firmware/src/clients/pairing.c) to give a clear compile error if the configs ever drift into an inconsistent state. 5/5 pairing ztests pass on native_sim; firmware builds clean (237,376 B FLASH). **Phase D complete.**

### Phase E — Documentation & polish

- **T-22.** ✅ Done (2026-06-05, session 070). Header comment block added to top of `firmware/src/session/session.c` and `libcantil/src/session.c` with the full documentation contract paragraph (Noise_XX security model, cert-as-metadata, libcantil trust-policy scope, no system trust store / OCSP / CRL, cert does not gate handshake security) and a pointer to `docs/transport-and-pairing.md`.
- **T-23.** ✅ Done (2026-06-05, session 071). New [docs/transport-security.md](transport-security.md) — end-user-facing guide covering: what Noise_XX provides (encryption/mutual-auth/forward-secrecy table); the session cert (what it is and isn't, common misconceptions); client trust tiers 1–4 (when to use each, TOFU upgrade path, revocation note); device pairing methods 0–5 (when to use each, bond caps, management commands); threat model (protected/non-goals table); cert lifecycle (self-signed, on-device CA signing, external CSR round-trip, firmware-update mismatch recovery); three deployment recipes (solo/small-team/fleet).
- **T-24.** ✅ Done (2026-06-05, session 072). `CLAUDE.md` Current focus updated to T-24 complete + advance pointer to T-25. Open Questions transport security entry updated with T-24 status and new resume pointer.
- **T-25.** ✅ Done (2026-06-05, session 073). Per-task design notes written for all non-trivial Phase B/D opcodes: [docs/ca/18-push-session-cert.md](../docs/ca/18-push-session-cert.md) (`PUSH_SESSION_CERT` / T-07), [docs/ca/19-client-bond-management.md](../docs/ca/19-client-bond-management.md) (`LIST_CLIENTS`/`UNPAIR_CLIENT`/`SET_CLIENT_NAME` / T-15), [docs/ca/20-pairing-passkey-reply.md](../docs/ca/20-pairing-passkey-reply.md) (`PAIRING_PASSKEY_REPLY` / T-18, plus Methods 4 and 5 from T-19/T-20). **Phase E complete.**

### Phase F — Device-to-device pairing (separate roadmap)

Picked up after Phase A–E land and stabilize. Sketch in [Device-to-device pairing — sketch](#device-to-device-pairing--sketch). Will get its own design doc when scheduled.

---

## Decisions captured

| # | Question | Decision |
|---|---|---|
| 1 | Transport wire | Noise_XX, no TLS |
| 2 | Session credential | X.509 cert with a **P-256 identity key** SPKI (ECDSA-self-signed via the existing cert writer), binding the Noise **X25519** key in a signed private-OID extension (`1.3.6.1.4.1.58270.1.1`). RFC 8410 `id-X25519` SPKI **rejected 2026-05-30** — X25519 can't sign and this mbedtls has no Ed25519/X25519 X.509 support. |
| 3 | Session slot storage | `/session/`, dedicated opcodes in `0x60–0x6F` |
| 4 | x509 source format | TOML, compiled to packed binary at build time |
| 5 | x509 mismatch behavior | Strict default in release, recovery mode allows FW update |
| 6 | Cert lifecycle | Self-signed default; signing manual; `force` to re-sign |
| 7 | Chain delivery | CBOR `{1: [bstr, …]}` inside encrypted msg2 / msg3 payload. Leaf always element 0 (self-signed → single-element array, **not** empty — revised T-04 2026-05-30). Empty payload = legacy 96/64-byte handshake. |
| 8 | Client trust tiers | 1 (none), 2 (pinned self-signed), 3 (CA allowlist), 4 (CA + CN pin) |
| 9 | CN pin source | FICR-derived device serial |
| 10 | Tier 3 revocation | Document gap, defer mechanism |
| 11 | Device-side pairing | Methods 0–5, Method 2 release default, Kconfig-selectable |
| 12 | Bond cap | 4 host clients + 4 peer devices, independent |
| 13 | Promiscuous in release | Disallowed via Kconfig guard |
| 14 | Device-to-device transport | BLE NUS central (wireless), **or** wired UART + presence pin (co-located). See [Wired peer link](#wired-peer-link--uart--presence-pin) |
| 15 | Device-to-device default | Method 2 for ad-hoc, Method 4 for owned fleets |
| 16 | Wired peer-link physical | Hardware UARTE (≤1 Mbaud) on 2 GPIO + GND; per-direction presence pin (GPIO sense, GPIOTE wake); 250 ms heartbeat, sleep after 4 misses, presence pin is the wake source (RX-edge alone deadlocks if both sleep); wake preamble discards the lost first byte |
| 17 | Peer-link command map | **Dedicated, disjoint from the host/`ttyACM` map.** Separate fail-closed dispatch table keyed on `session->transport`; peer opcodes reserved in `0xA0–0xBF`, never aliasing host `0x01–0x6F`. Prevents cross-channel command leakage. See [Peer-link command isolation](#peer-link-command-isolation) |

---

## Cross-references

- [CLAUDE.md](../CLAUDE.md) — Architecture Decisions → Transport Security
- [docs/storage.md](storage.md) — LittleFS layout (add `/session/`, `/clients/`)
- [docs/ca/15-get-ca-chain.md](ca/15-get-ca-chain.md) — chain walker, used by msg2 payload assembly
- [firmware/src/session/session.c](../firmware/src/session/session.c) — Noise_XX responder, will gain CBOR payload handling
- [libcantil/src/session.c](../libcantil/src/session.c) — Noise_XX initiator, will gain trust policy evaluation
- [libcantil/include/cantil.h](../libcantil/include/cantil.h) — public API, will gain `cantil_trust_policy_t`
