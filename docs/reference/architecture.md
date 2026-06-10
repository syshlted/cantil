# Reference: Architecture Decisions

> Relocated verbatim from CLAUDE.md (token-cost trim). Authoritative architecture-decision reference.

## USB Protocol: CDC/ACM, not FIDO2

FIDO2/CTAP2 has no CSR signing, no cert management, and no general-purpose crypto API. It is narrow by design. We use USB CDC/ACM (virtual serial port) with a custom framing layer. No host driver needed on Linux/macOS/Windows.

## Transport Security: Noise Protocol (Noise_XX pattern)

USB is a local bus — no network-layer encryption. We use **Noise_XX** at the application layer:

- Both device and client have static Curve25519 keypairs
- Mutual authentication + forward secrecy in the handshake
- Session encrypted with ChaCha20-Poly1305
- On-device: mbedtls (called directly, not through PSA) via a thin crypto abstraction layer
- Host client: mbedtls (same primitives, same abstraction) — see [libcantil/src/session.c](../../libcantil/src/session.c)

Full design (wire format, session cert, trust tiers, pairing methods, opcodes):
[docs/transport-and-pairing.md](../transport-and-pairing.md).
End-user guide (how to choose a trust tier and pairing method, deployment recipes):
[docs/transport-security.md](../transport-security.md).

## Noise Crypto Backend Architecture

The Noise_XX state machine in `session.c` calls only a thin abstraction (`noise_crypto.h` — 6 functions: DH keygen, DH, AEAD encrypt, AEAD decrypt, hash, HKDF2). Two backends ship; selection is build-time via `CONFIG_CANTIL_CRYPTO_BACKEND_FREE` (default) vs. `CONFIG_CANTIL_CRYPTO_BACKEND_ACCELERATED`. The CMakeLists' `target_sources_ifdef` gates guarantee exactly one is linked.

| Backend | File | Notes |
| --- | --- | --- |
| FREE (mbedtls direct) | `noise_crypto_mbedtls.c` | X25519 + ChaCha20-Poly1305 + SHA-256 + HKDF-SHA-256 via mbedtls' public C API; no PSA layer. AGPL-clean default. |
| ACCELERATED (PSA) | `noise_crypto_psa.c` | Same six primitives via PSA: `psa_generate_random`+clamp+`psa_import_key` / `psa_raw_key_agreement` (Montgomery X25519 — direct `psa_generate_key` is not supported by Nordic PSA for Montgomery, see session 046), `psa_aead_*` (ChaCha20-Poly1305), `psa_hash_*` (SHA-256), `psa_key_derivation_*` (HKDF). Design intent: dispatch X25519 + ChaChaPoly to Oberon software and SHA-256 / HKDF to CC3XX hardware under NCS. **Status (2026-05-29):** does not pair end-to-end on real hardware — NCS PSA dispatcher routes Montgomery 255 to CC3XX (which CC310 silicon does not implement). See the open-questions item on `ca.c` PSA-opaque PK plumbing and `project_psa_runtime_gate_findings.md`. Proprietary nrfxlib blobs linked; not redistributable under Apache 2.0 alone. |

**Wire-format invariants are bit-identical by design** between backends: X25519 scalars are clamped on import, scalars / pubkeys are 32-byte little-endian, ChaCha20-Poly1305 nonces are `4×0x00 || 8-byte LE counter`, AEAD ciphertext is `ct || 16-byte tag`. The intent is that a Noise static keypair persisted under one backend reloads under the other without re-derivation — **this is unverified on hardware as of 2026-05-29 and may be broken** (a FREE-era blob did not decrypt under PSA in session 046; isolation between HKDF-divergence and AES-GCM-divergence was not completed before the legacy blob was wiped to chase a separate bug).

**Why mbedtls direct as the FREE backend:** see the 2026-05-21 Path A decision in conversation_008. mbedtls direct is AGPL-clean, ships with NCS, gives one library covering both CA (P-256) and Noise (X25519/ChaChaPoly), and avoids known NCS PSA bugs and Oberon's Nordic-only binary license. The ACCELERATED backend trades that AGPL-cleanness for CC3XX silicon dispatch.

## CryptoCell-310 Usage

CC310 acceleration is available through nrf_security's mbedtls alt-implementations for the curves and primitives it supports. The Noise session primitives (X25519, ChaCha20-Poly1305) are not in CC310's instruction set and run as portable mbedtls software on the M4F.

| Operation | Backend | Hardware-accelerated |
| --- | --- | --- |
| TRNG (CA key generation) | mbedtls + CC310 alt | Yes |
| ECC P-256 signing (CA ops) | mbedtls + CC310 alt | Yes |
| AES-256 (key storage encryption) | mbedtls + CC310 alt | Yes |
| SHA-256 (hashing, HKDF) | mbedtls + CC310 alt | Yes |
| X25519 (Noise handshake DH) | mbedtls software | No (~10–20ms on M4F) |
| ChaCha20-Poly1305 (Noise session) | mbedtls software | No (50+ MB/s on M4F) |

Software X25519/ChaChaPoly are not the bottleneck; USB Full Speed tops out at ~1 MB/s and cert messages are small.

## Key Storage: Runtime Generation, Encrypted External Flash

- CA private key generated on first boot using CryptoCell-310 TRNG
- Stored encrypted in LittleFS on external QSPI flash (2MB P25Q16H)
- Storage encryption key derived from FICR device UID
- **Never embedded at compile time** (compile-time keys appear in firmware binaries, can't rotate, catastrophic if binary leaks)

## On-Device Signing

All CA signing operations happen on the Cantil device. The private key is:

1. Decrypted from external flash into RAM
2. Loaded into CryptoCell-310
3. Used to sign the CSR
4. Zeroed from RAM

The signed cert (not the key) travels over USB. Host never sees the private key.

## Lower-Layer Encryption: Not Used

Moving Noise below CDC/ACM (encrypting the UART emulation itself) would require a custom USB vendor class and host-side libusb driver, eliminating the zero-driver-install ergonomic advantage of CDC/ACM. For this threat model, CDC/ACM control signals (DTR, RTS) carry no sensitive data. Performance difference is immeasurable — USB FS bandwidth and QSPI flash latency dominate, not Noise framing overhead.
