# Cantil vs. Hardware PKI Devices — Feature Comparison

> **Scope:** Devices capable of storing a CA private key on hardware and signing X.509 certificates on-device. Consumer authentication tokens (FIDO2-only, TOTP-only) are excluded.

## What makes a hardware CA different from a hardware auth token

A **hardware auth token** (YubiKey 5 in FIDO2/PIV mode, OpenPGP card) stores *your* private key and lets you prove your identity — one keypair, one user, one signature type.

A **hardware CA** is a signing oracle: it stores a *Certificate Authority* private key and issues certificates to *other* entities on demand. The threat model is different — the CA key is the trust root for many devices, not just one person. Hardware isolation of that key is the entire point.

Cantil is built from the ground up as a hardware CA. The others below started as authentication tokens and gained CA-adjacent features over time (or are full enterprise HSMs at a different price tier).

---

## Cantil

| | |
|---|---|
| **Form factor** | Seeed XIAO BLE Sense (thumb-sized), or any nRF52840 board via devicetree overlay |
| **Transport** | USB CDC/ACM (zero-driver on Linux/macOS/Windows) + BLE NUS |
| **Session security** | Noise_XX (Curve25519 + ChaCha20-Poly1305): mutual auth, forward secrecy, E2E encrypted — no cleartext ever crosses the wire |
| **Crypto engine** | Nordic CryptoCell-310: hardware TRNG, ECC P-256/384 signing, AES-256, SHA-256 |
| **Key generation** | On-device via CC310 TRNG; key never leaves device |
| **Key storage** | AES-256-GCM encrypted in LittleFS on QSPI flash; encryption key derived from FICR device UID |
| **SWD/debug access** | APPROTECT disabled in production builds |
| **CA key slots** | Slot 0 (master CA, protected by default) + up to 8 general-purpose key slots; multi-CA hierarchy possible |
| **Certificate algorithms** | ECC P-256 (signing), CSR input can specify any subject |
| **CSR signing** | Native — `SIGN_CSR`, `SIGN_CSR_SLOT`; core design goal |
| **CRL management** | Per-slot CRLs; `REVOKE_CERT`, `AUTO_EXPIRE` (host provides timestamp; device has no RTC) |
| **Cert store** | Issued certs stored on-device; `LIST_CERTS`, `GET_CERT`, `GET_CERT_COUNT`, `GET_CRL` |
| **Slot protection** | Tap-gesture confirmation required to protect/unprotect a slot; protected slots block key overwrite and cert revocation |
| **Physical unlock** | Configurable tap-gesture sequence (PDM microphone onset or GPIO button); lockout after failure |
| **Network interface** | None — air-gapped by design |
| **Host driver** | None required (CDC/ACM native; BLE via BlueZ D-Bus on Linux) |
| **Host API** | `libcantil` — C library; CLI (`cantil`); Noise_XX session management built in |
| **Protocol** | Custom CBOR over Noise_XX (no PKCS#11, no smart card stack) |
| **TRNG export** | `GET_RANDOM` command exposes CC310 TRNG to host |
| **Open source** | Yes — Apache 2.0 |
| **Price** | ~$15–20 (XIAO BLE Sense module) + open firmware |

---

## YubiKey 5 Series

*Models: 5 NFC ($58), 5C NFC ($65), 5 Nano ($68), 5C Nano ($68), 5Ci ($85). FIPS variants +$30–$50.*

| | |
|---|---|
| **Form factor** | USB key (nano variants) or USB + NFC |
| **Transport** | USB HID (CCID smart card mode) + NFC |
| **Session security** | None — USB HID carries PIV/OpenPGP commands in the clear; transport security depends on OS CCID stack |
| **Crypto engine** | Proprietary secure element (not disclosed) |
| **Key generation** | On-device |
| **Key storage** | In secure element; non-extractable |
| **SWD/debug access** | N/A — proprietary SE |
| **PIV key slots** | 4 primary (9A, 9C, 9D, 9E) + 20 retired key management slots (82–95) + attestation (F9) |
| **PIV cert algorithms** | RSA-2048, ECC P-256, P-384 |
| **OpenPGP key slots** | 3 (sign, encrypt, auth); RSA up to 4096-bit, ECC P-256/384/Ed25519 |
| **CSR signing** | Not a native command — requires external tooling (e.g. `yubikey-sign-csr`, manual PKCS#11 integration). **The YubiKey is not designed to be a CA.** |
| **CRL management** | None |
| **Cert store** | Certs are stored in PIV slots; no general-purpose issued-cert store |
| **Slot protection** | PIN/touch policy per slot |
| **Physical unlock** | Capacitive touch |
| **Network interface** | None |
| **Host driver** | None required (USB HID/CCID); smart card middleware (PCSC) typically needed for PIV |
| **Host API** | `ykman` CLI; PKCS#11 via `ykcs11`; PIV via libykpiv; CCID smart card APIs |
| **Protocol** | PIV (NIST SP 800-73), OpenPGP card, FIDO2/CTAP2, OATH, Yubico OTP |
| **TRNG export** | No |
| **Open source** | No (firmware closed; `ykman` and some libraries are open source) |
| **Price** | $58–$85 ($98–$115 FIPS) |

**YubiKey CA use notes:** A YubiKey 5 *can* hold a subordinate CA key and sign certs, but this is not its intended use case. There is no built-in cert store, CRL, or revocation management. Setting up CSR signing requires integrating PIV PKCS#11 with OpenSSL or a CA software layer (EJBCA, step-ca, etc.). The YubiKey is an authentication token, not a CA appliance.

---

## Nitrokey HSM 2

*~$80–$100 from Nitrokey shop.*

| | |
|---|---|
| **Form factor** | USB key |
| **Transport** | USB, PKCS#11 |
| **Session security** | None at transport layer — relies on OS/host stack |
| **Crypto engine** | NXP JCOP 4 security controller, Common Criteria EAL 6+ |
| **Key generation** | On-device |
| **Key storage** | 76 KB EEPROM — up to ~300 AES-256/ECC keys or ~19 RSA-4096 keys |
| **CA support** | Yes — full CA use case is a primary design goal |
| **CSR signing** | Yes via PKCS#11 + OpenSSL or EJBCA integration |
| **CRL management** | Via host CA software (not on-device) |
| **Cert store** | Limited — PKCS#11 object store, not a purpose-built cert DB |
| **Physical unlock** | PIN only |
| **Network interface** | None |
| **Host driver** | PKCS#11 library required; OpenSC supports it |
| **Protocol** | PKCS#11, OpenSC |
| **TRNG export** | Via PKCS#11 `C_GenerateRandom` |
| **Open source** | Yes — hardware and software |
| **Price** | ~$80–$100 |

**Vs. Cantil:** Nitrokey HSM 2 is the closest direct competitor in intent and price tier. It has a certified SE (EAL 6+), more key capacity, and integrates with standard CA software (OpenSSL, EJBCA, step-ca) via PKCS#11. Cantil has: zero-driver USB, E2E Noise_XX session encryption, physical gesture unlock, a built-in cert store with CRL management, a purpose-built host library, and BLE transport — all without requiring PKCS#11 middleware. Cantil trades certified silicon for a more self-contained, air-gapped-friendly workflow.

---

## YubiHSM 2

*$650 (standard) / $950 (FIPS).*

| | |
|---|---|
| **Form factor** | USB-A nano (12 × 13 × 3.1 mm, 1 g) |
| **Transport** | USB, proprietary `yubihsm-connector` daemon + PKCS#11 |
| **Session security** | Encrypted sessions between host library and device |
| **Crypto engine** | Proprietary (undisclosed) |
| **Key storage** | 256 object slots, 128 KB — up to ~255 ECC keys or 68 RSA-4096 |
| **Algorithms** | RSA, ECC P-256/384/521, Ed25519, AES-128/256, SHA-2, HMAC, HKDF, PBKDF2 |
| **CA support** | Yes — can protect root CA and intermediate CA keys; integrates with ADCS |
| **CSR signing** | Yes via PKCS#11 |
| **CRL management** | Via host CA software |
| **Physical unlock** | None |
| **Network interface** | None |
| **Host driver** | `yubihsm-connector` daemon + PKCS#11 library required |
| **Open source** | No |
| **Price** | $650–$950 |

**Vs. Cantil:** YubiHSM 2 is a purpose-built small HSM, priced and targeted for server/enterprise use. It has much greater key capacity, FIPS certification, and integrates with Windows CA infrastructure. Cantil is ~35× cheaper, adds physical-presence gesture unlock, E2E session encryption over USB, BLE transport, and on-device cert/CRL management — targeting personal and small-org CA use, not rack/server deployment.

---

## SmartCard-HSM (CardContact)

*Price not publicly listed; contact distributor.*

| | |
|---|---|
| **Form factor** | ISO/IEC 7816 smartcard, SIM variants (2FF/3FF), USB token |
| **Transport** | Contact smartcard (CCID), contactless NFC (dual-interface), USB (token variant) |
| **Session security** | Smartcard CCID — no application-layer encryption |
| **Algorithms** | RSA up to 4096-bit, ECC up to 521-bit, AES-256 |
| **CA support** | Yes — Device Authentication Key signs all generated key pairs; remote key attestation |
| **CSR signing** | Yes via PKCS#11 / PKCS#15 |
| **Physical unlock** | PIN |
| **Open source** | No (CardContact proprietary) |
| **Notable feature** | Remote key attestation; card form factor for smartcard readers |

---

## Summary Table

| | **Cantil** | **YubiKey 5** | **Nitrokey HSM 2** | **YubiHSM 2** | **SmartCard-HSM** |
|---|---|---|---|---|---|
| **Primary purpose** | Hardware CA | Auth token | HSM / CA | HSM / CA | HSM / CA |
| **Price** | ~$15–20 | $58–85 | $80–100 | $650–950 | Undisclosed |
| **Open source** | Yes | Partial | Yes | No | No |
| **Native CSR signing** | Yes | No (external tools) | Yes | Yes | Yes |
| **On-device cert store** | Yes | No | No | No | No |
| **On-device CRL** | Yes | No | No | No | No |
| **Session encryption** | Noise_XX E2E | None | None | Encrypted sessions | None |
| **Zero-driver USB** | Yes (CDC/ACM) | No (CCID/HID) | No (PKCS#11) | No (connector daemon) | No (CCID) |
| **BLE transport** | Yes | NFC only | No | No | NFC (dual-iface models) |
| **Physical gesture unlock** | Yes (tap sequence) | Touch (capacitive) | PIN only | None | PIN only |
| **Physical-presence confirm** | Yes (slot protection) | Touch (per-slot policy) | No | No | No |
| **Host API** | libcantil + CLI | ykman / PKCS#11 | OpenSC / PKCS#11 | PKCS#11 | PKCS#11 |
| **TRNG export** | Yes | No | Yes | Yes | No |
| **Network interface** | None | None | None | None | None |
| **Certified silicon** | No (nRF52840 CC310) | Proprietary SE | EAL 6+ (JCOP 4) | Undisclosed | Yes |
| **Multi-CA hierarchy** | Yes (8 slots) | Limited (PIV retired slots) | Yes | Yes | Yes |
| **PKCS#11 required** | No | Optional | Yes | Yes | Yes |

---

## Cantil's differentiated position

Most hardware PKI devices — including the best open-source option (Nitrokey HSM 2) — expose a PKCS#11 interface and rely on host-side CA software (OpenSSL, EJBCA, step-ca, ADCS) to do certificate management. The device is a signing oracle; the CA logic lives on the host.

Cantil inverts this: the device *is* the CA. Cert storage, CRL management, revocation, slot lifecycle, and physical-presence confirmation are all on-device. The host library (`libcantil`) is a thin client; there is no CA software layer to configure or harden separately.

Other differentiators with no direct equivalent:

- **Noise_XX session encryption over USB.** Other devices carry crypto commands in cleartext over CCID/HID. Cantil's Noise_XX layer provides mutual authentication and forward-secret E2E encryption from the moment the cable is plugged in — the host client authenticates the device before any CA operation.
- **Tap-gesture physical unlock.** The unlock sequence (configurable arbitrary tap pattern) is a second factor that is distinct from a PIN — it requires physical access and produces no observable electrical signal. It can be changed over the wire from an authenticated session.
- **Tap-confirmation for destructive operations.** Slot protection and unprotection require an on-device gesture within 10 seconds — not a PIN entered on the host keyboard.
- **Zero-driver install.** CDC/ACM enumeration is native on all major OSes. No PKCS#11 library, no smart card middleware (pcsc-lite), no connector daemon.
- **BLE transport with identical session security.** The Noise_XX session is transport-independent; USB and BLE paths share the same session code and security properties.
- **~$15–20 hardware cost.** Open firmware on commodity nRF52840 hardware.

**Where Cantil trails:**

- No third-party hardware security certification (EAL, FIPS). The CC310 is a production-quality crypto engine but Cantil has not undergone a formal evaluation.
- No PKCS#11 interface — software that expects PKCS#11 (OpenSSL engines, EJBCA, ADCS) cannot use Cantil without a shim. This is by design (PKCS#11 middleware adds complexity and attack surface), but it is a real integration gap for established CA infrastructure.
- RSA signing not currently implemented (ECC P-256 only). Systems requiring RSA CA certs (some legacy PKI) cannot use Cantil as a signer.
- No RTC — cert expiry and CRL timestamps rely on the host providing a current Unix timestamp. Not a security weakness, but a protocol detail to be aware of. This is not unique to Cantil: none of the USB-dongle/smartcard-tier devices compared here have battery-backed RTCs — YubiKey 5, Nitrokey HSM 2, and SmartCard-HSM all rely on the host for time as well. Battery-backed RTCs are a feature of enterprise rack HSMs (Thales Luna, Utimaco), not personal-scale hardware.
