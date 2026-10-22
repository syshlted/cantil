# Reference: Architecture Decisions

> Relocated verbatim from AGENTS.md (token-cost trim). Authoritative architecture-decision reference.

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

The Noise_XX state machine in `session.c` calls only a thin abstraction (`noise_crypto.h` — 6 functions: DH keygen, DH, AEAD encrypt, AEAD decrypt, hash, HKDF2). Two backends ship; selection is build-time via `CONFIG_CANTIL_CRYPTO_BACKEND_FREE` (default) vs. `CONFIG_CANTIL_CRYPTO_BACKEND_WOLFSSL`. The CMakeLists' `target_sources_ifdef` gates guarantee exactly one is linked.

| Backend | File | Notes |
| --- | --- | --- |
| FREE (mbedtls direct) | `noise_crypto_mbedtls.c` | X25519 + ChaCha20-Poly1305 + SHA-256 + HKDF-SHA-256 via mbedtls' public C API; no PSA layer. AGPL-clean default. |
| WOLFSSL (wolfCrypt) | `noise_crypto_wolfssl.c` | The same six primitives via wolfCrypt's C API: `wc_curve25519_*`, `wc_ChaCha20Poly1305_*`, `wc_Sha256*`, `wc_HKDF`. Built `WOLFCRYPT_ONLY` (no TLS layer) from `firmware/include/cantil_wolfssl_user_settings.h`. Two behaviour differences from mbedTLS are handled at the seam: wolfCrypt rejects empty-plaintext AEAD (Noise handshake messages need it, so a 1-byte stand-in is used) and refuses an all-zero X25519 shared secret (stricter than mbedTLS — the handshake fails rather than continuing weakened). |

**Wire-format invariants are bit-identical between backends**, and unlike the PSA arm that preceded wolfCrypt this is gated rather than merely intended: X25519 scalars are clamped on import, scalars / pubkeys are 32-byte little-endian, ChaCha20-Poly1305 nonces are `4×0x00 || 8-byte LE counter`, AEAD ciphertext is `ct || 16-byte tag`. `firmware/tests/noise_crypto{,_wolfssl}/` runs one set of fixed vectors against both backends and `firmware/tests/crypto_kat{,_wolfssl}/` does the same for `crypto.h` — including `crypto_storage_key_derive` against a fixed answer, where a divergence would mean an unreadable CA key. A Noise static keypair persisted under one backend therefore reloads under the other. (The old FREE↔PSA claim was never gated and was probably false; see `project_psa_runtime_gate_findings.md`.)

**Why mbedtls direct as the FREE backend:** see the 2026-05-21 Path A decision in conversation_008. mbedtls direct is AGPL-clean, ships with NCS, gives one library covering both CA (P-256) and Noise (X25519/ChaChaPoly), and avoids known NCS PSA bugs and Oberon's Nordic-only binary license.

**The ACCELERATED (PSA / Oberon + CC3XX) backend was removed on 2026-07-23.** It had been unselectable since the Phase 1 move to upstream Zephyr — nrf_security, the Oberon archives and the CC3XX driver all ship in sdk-nrf, which the workspace no longer contains — and it never paired end-to-end on real hardware even when it could be built (the NCS PSA dispatcher routed Montgomery 255 to CC3XX, which CC310 silicon does not implement; see `project_psa_runtime_gate_findings.md`). Under GPL-3.0-or-later the Nordic 5-Clause blobs cannot be distributed linked at all (§7 bars the further restrictions — docs/crypto-blobs.md), so it was not a shippable configuration either. Hardware acceleration returns via wolfCrypt, which drives CC310 directly and needs neither nrf_security nor the blobs.

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
