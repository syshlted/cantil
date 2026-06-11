# Transport Security — User Guide

> **Audience:** operators, integrators, and security-conscious users.
> For implementation internals and design rationale see
> [docs/transport-and-pairing.md](transport-and-pairing.md).

---

## What this document covers

This page explains how a Cantil device authenticates to its clients, how clients decide
whether to trust a device, and how new clients are admitted to a device. After reading
it you should be able to choose a trust tier and pairing method that fit your threat
model, and know what to do when you set up a new device or rotate its identity.

---

## How communication is protected

Every command between the `cantil` client and the device travels over an encrypted,
mutually-authenticated session. The protocol is
**Noise_XX_25519_ChaChaPoly_SHA256** — a well-specified, widely-audited handshake
framework used in WireGuard, WhatsApp, and similar products.

**What you get from the Noise handshake, every session:**

| Property | What it means in practice |
|---|---|
| **Confidentiality** | The byte stream on the USB or BLE bus is ChaCha20-Poly1305 encrypted; a bus sniffer sees only ciphertext. |
| **Mutual authentication** | Both sides prove they hold their long-term static key before any command executes. An impersonator without that key cannot complete the handshake. |
| **Forward secrecy** | Each session generates fresh ephemeral keys. Recording today's bus traffic and later stealing the static key does not decrypt past sessions. |
| **Integrity** | Every frame carries a Poly1305 authentication tag. Tampered or replayed frames are rejected. |

These properties come from the Noise math, not from X.509 or TLS. The device does not
have TLS, does not use a system trust store, and never fetches OCSP or CRL from a
network endpoint.

---

## The session certificate — what it is and what it isn't

Each Cantil device holds a **session certificate** in its `/session/` storage slot. This
certificate is a standard X.509 DER file, but it plays a very different role from a TLS
server certificate:

- It is **metadata about the device's Noise static key**, not a TLS credential.
- The certificate binds a device identity (organisation, subject name, FICR-derived
  serial) to the public half of the Noise key. Clients use this to build their trust
  policy — but **handshake security does not depend on the certificate at all**. If the
  cert is missing or malformed the Noise session still works; the cert is used only for
  client-side policy decisions after the handshake.
- Validation is performed by the `libcantil` client library against a policy you supply.
  It is not delegated to an OS trust store, a browser root list, or any standard
  X.509 path-validation library. It does not involve OCSP or CRL fetches.
- The cert is **self-signed by default** using a P-256 identity key generated on first
  boot. You can optionally have it signed by an on-device CA slot (`SIGN_SESSION_FROM_SLOT`)
  or by an external CA via a CSR round-trip (`GET_SESSION_CSR` / `PUSH_SESSION_CERT`).
  See [Cert lifecycle](#cert-lifecycle) below.
- The cert carries the device's X25519 Noise pubkey in a private OID extension
  (`1.3.6.1.4.1.58270.1.1`). Clients that validate cert chains compare this extension
  against the key the Noise handshake authenticated — confirming the cert attests to the
  device that actually answered.

**If someone hands you a DER file from `cantil session-cert` and asks "is this a
legitimate cert?" the answer is: it's a legitimate Cantil identity binding, validated
by libcantil against your trust policy, not by OpenSSL or a browser.** Don't plug it
into standard PKI tooling and expect chain validation to work the way it would for a
web server cert.

---

## Client trust tiers — how the client decides to trust a device

Build `libcantil` into your application with a `cantil_trust_policy_t` that matches your
deployment. The `cantil` CLI auto-selects Tier 2 after a first `cantil pair` and stores
the fingerprint in `~/.config/cantil/session_fp.bin`.

| Tier | Policy constant | What's checked | When to use |
|---|---|---|---|
| **1** | `CANTIL_TRUST_NONE` | Nothing. Noise still encrypts; the session cert is ignored. | Local test environments, `native_sim`, or any context where you'll never connect to an adversary's device. |
| **2** | `CANTIL_TRUST_PINNED_SELF_SIGNED` | SHA-256 fingerprint of the leaf cert DER. Optionally also the full subject DN. | Single user with 1–3 personal devices. Set it up once with `cantil pair`; the fingerprint is stored and checked automatically from then on. The best "just works" option for personal use. |
| **3** | `CANTIL_TRUST_CA_ALLOWLIST` | The cert chain validates to a CA whose cert you loaded into the trust store. | Small team or fleet managed by a Cantil CA slot. All devices get certs from the same on-device CA; clients load that CA cert as the trust root. No per-device configuration. |
| **4** | `CANTIL_TRUST_CA_PLUS_CN_PIN` | Chain validates to an allowlisted CA **and** the leaf CN matches the expected FICR device serial. | Production fleet where a compromised CA or rogue cert must not silently substitute a different device. Requires tracking the expected serial per device. |

**Recommendation for most personal use: Tier 2.** Run `cantil pair <port>` on first
contact; it records the device fingerprint. Future sessions verify it automatically.

**Recommendation for a managed fleet: Tier 3 or 4.** Use `cantil session-sign <slot>`
or the CSR round-trip to have all device certs signed by a dedicated CA slot. Distribute
that CA cert to clients. Upgrade to Tier 4 if you need per-device enforcement.

### Tier 2 upgrade path (TOFU → pinned)

On first contact with a device you haven't seen before, the `cantil` CLI is in TOFU
(Trust On First Use) mode — it accepts whatever cert the device presents and saves the
fingerprint. On all subsequent sessions it enforces that fingerprint. You are trusting
that the first connection was not intercepted. Reduce this window by doing the first
connection over a physically controlled channel (USB, not BLE over a shared RF
environment), or by verifying the fingerprint out of band:

```
cantil session-cert <port> | openssl x509 -inform der -fingerprint -noout
```

Compare that fingerprint against the stored `~/.config/cantil/session_fp.bin`.

### Revocation note

Tier 3 has no built-in revocation in v1. If a device cert is compromised, remove its CA
from your trust store and re-deploy updated CA certs to all clients. For a fleet where
per-device control matters, use Tier 4 — the CN pin acts as an effective per-device
allowlist. A host-maintained fingerprint blocklist is the other option for Tier 3
deployments until a revocation mechanism is added.

---

## Device pairing methods — how the device decides to accept a new client

When a new client connects for the first time, the device needs to decide whether to
admit it. This is selected at build time via `CANTIL_PAIRING_METHOD` in Kconfig. The
release default is **Method 2 (tap-confirmed bond)**.

| Method | Kconfig | What happens on first contact | Strongest threat defended |
|---|---|---|---|
| **0 — Promiscuous** | `PAIRING_PROMISCUOUS` | Any client is accepted. No record is kept. | Nothing. Testing only. **Unavailable in release builds.** |
| **1 — Silent TOFU** | `PAIRING_TOFU` | The first client to connect is bonded automatically. Further clients are rejected. | Impostors after the initial bond. |
| **2 — Tap-confirmed bond** | `PAIRING_TAP_CONFIRM` *(release default)* | Device blinks cyan and waits for an `Orange Orange` tap sequence from the owner before recording the bond. | Bus-racing attackers — an attacker who happens to connect at the same moment as the legitimate client cannot steal the bond without physical access to the device. |
| **3 — Passkey** | `PAIRING_PASSKEY` | Device blinks a 6-digit passkey; client must echo the correct digits and owner must confirm with a tap. A per-client PSK is derived from the passkey and stored. | Concurrent USB-bus attackers; client-file impersonation (a stolen client static-key file can't connect without the stored per-session PSK). |
| **4 — CA-anchored** | `PAIRING_CA_ANCHOR` | Client presents an X.509 cert chain on the handshake. Device validates it against a trust anchor slot. No per-client bond is stored. | Arbitrary clients — only clients enrolled with the CA can connect. Zero friction for enrolled clients; zero UX for new enrollment beyond cert issuance. |
| **5 — CA + passkey** | `PAIRING_CA_ANCHOR_PLUS_PASSKEY` | Method 4 cert check, then Method 3 passkey + tap-confirm on top. Bond + PSK stored. | All of Method 4's threats plus a compromised CA issuing rogue client certs. |

**Recommendation for personal devices: Method 2.** One tap per new client; robust
against bus-racing; minimal friction for the owner.

**Recommendation for shared or managed devices: Method 4 or 5.** Issue client
certs from an on-device CA and configure the anchor slot. Method 5 adds a hardware-
confirmed passkey for defense against a compromised CA.

### Bond storage and caps

Bonded clients are stored under `/clients/<pubkey-prefix>/` on the device flash. Caps:

- Up to `CONFIG_CANTIL_MAX_CLIENT_BONDS` host clients (default **4**)
- Up to `CONFIG_CANTIL_MAX_PEER_BONDS` peer devices (default **4**) — separate budget

When the cap is full, new clients are rejected until an existing bond is removed:

```
cantil clients <port>          # list bonded clients
cantil unpair <pubkey> <port>  # remove a bond (tap-confirmed on device)
```

---

## Threat model — what's protected and what isn't

| Threat | Defense | Notes |
|---|---|---|
| Passive USB or BLE bus sniffer | Noise_XX ChaCha20-Poly1305 session encryption | All transports. |
| Active USB bus MitM on first connect | Tap-confirmed bond (Method 2+) | Attacker needs physical access to the device to steal the bond. |
| Stolen client static-key file (host compromise) | Method 3+ PSK | Without the per-client PSK stored on the device, a stolen key file cannot connect. |
| Rogue device substituted on the bus | Client trust tier 2+ fingerprint / tier 3+ CA chain | Client rejects a device that doesn't match the expected identity. |
| Compromised CA issuing rogue client certs | Method 5 passkey + tap-confirm | Device still requires a hardware-confirmed passkey even for cert-bearing clients. |
| Stolen device | Device lock/unlock sequence (gesture or PIN), rate limit | Orthogonal to transport — handled by the device state machine. |
| Firmware backdoor via device software | MCUboot image validation + CANTIL_SESSION_X509_STRICT recovery mode | A firmware with a drifted session identity triggers recovery mode rather than silently misbehaving. |
| Quantum break of X25519 | Out of scope today | `Noise_XXpsk2_...` with a pre-shared secret is a forward-compatible hardening path if needed. |

**Non-goals:**

- Standard PKI compatibility. Cantil certs do not validate under `openssl verify` or any
  browser trust store by design — the cert format is a libcantil-internal artifact.
- Network-distributed revocation (no OCSP endpoint, no CRL distribution point).
- Hiding the fact that the device is a Cantil (USB VID:PID `0x1209:0x00CA` and the
  product string are visible to any USB host).

---

## Cert lifecycle

### Self-signed (default)

On first boot the device generates a fresh X25519 Noise key and a P-256 identity key
via the hardware TRNG and writes a self-signed X.509 cert. No action is needed.

### Signing with an on-device CA

```bash
cantil session-sign 0 <port>          # sign with CA slot 0 (tap-confirm required)
cantil session-sign 0 --force <port>  # re-sign if cert is already CA-signed
```

After signing, the cert chain (leaf + issuer) is automatically included in every
Noise handshake and available to clients that validate at Tier 3 or 4.

### Signing with an external CA (CSR round-trip)

```bash
cantil session-csr <port> > device.csr   # extract the CSR
# sign device.csr with your CA — constraints:
#   notBefore / notAfter must match the device's constant window
#   SubjectPublicKeyInfo must be the same P-256 key as the CSR
#   OID 1.3.6.1.4.1.58270.1.1 extension must be preserved
cantil session-push device_signed.der <port>           # install the signed cert
cantil session-push device_signed.der --chain ca.der --force <port>  # with chain
```

The device validates the pushed cert before installing it. It checks that the P-256
SPKI matches the stored identity key, that the X25519 extension matches the stored
Noise key, and that the subject fields match the build constant.

### After a firmware update that changes the session TOML

If the build-time session constant (organisation, OU, key usage, validity window) is
changed in a new firmware, the device detects the mismatch on boot:

- **Dev builds** (`CANTIL_SESSION_X509_STRICT=n`, the default): log a warning, continue
  normally.
- **Release builds** (`CANTIL_SESSION_X509_STRICT=y`): enter recovery mode — the LED
  shows a red↔yellow alternation and only `DEVICE_STATUS` and `RESET_DEVICE` are
  accepted. Push a corrected firmware or use `ACCEPT_IDENTITY_MIGRATION` (tap-confirmed)
  to update the cert to match the new constant.

Changing only the firmware logic without touching `firmware/session_x509.toml` will
never trigger this condition.

---

## Common deployment recipes

### Solo user — personal key management

1. Flash the device; it self-signs on first boot.
2. Run `cantil pair <port>` — the fingerprint is stored (Tier 2).
3. All future `cantil` commands verify the fingerprint automatically.
4. No further cert management needed unless you change devices.

### Small team — shared CA device

1. Designate one device as the signing CA (slot 0 by default).
2. On each user's device, issue a session cert signed by the CA device:
   `cantil session-sign 0 <device_port>` (requires a session to the CA device).
3. Export the CA cert: `cantil ca-cert <ca_port>`.
4. Each client loads the CA cert in its trust store: `--ca-cert ca.der --trust ca`.
5. New team members load the CA cert and connect automatically — no per-device
   fingerprint management.

### Fleet — CA-anchored pairing

1. Build firmware with `CANTIL_PAIRING_METHOD = PAIRING_CA_ANCHOR` and
   `CONFIG_CANTIL_CA_ANCHOR_SLOT = 0`.
2. Each user has a client cert issued by the fleet CA (slot 0 of the fleet CA device).
3. `cantil pair --client-cert user.der <port>` — device validates the cert chain on
   the msg3 handshake payload; no tap required.
4. Revoke access by re-issuing client certs from a new CA and rotating the anchor slot.

---

## See also

- Full design, wire format, and implementation roadmap:
  [docs/transport-and-pairing.md](transport-and-pairing.md)
- Storage layout (`/session/`, `/clients/`):
  [docs/storage.md](storage.md)
- Architecture decisions (Noise backend, crypto backend):
  [docs/reference/architecture.md](reference/architecture.md)
- Public client API (`cantil_trust_policy_t`, `cantil_session_open`):
  [libcantil/include/cantil.h](../libcantil/include/cantil.h)
