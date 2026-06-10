# HSM Positioning — Internal Analysis

**Decision (2026-05-28):** Cantil is positioned externally as a **hardware Certificate Authority**, not a Hardware Security Module. The "HSM" framing has been removed from all externally-facing documentation, source banners, README, marketing copy, and roadmap. This document captures the reasoning so we don't relitigate it.

Origin of the analysis: conversation_024 (2026-05-27).

---

## Why not call it an HSM

A real HSM (Hardware Security Module, in the FIPS / PKCS#11 / enterprise-vendor sense) has properties Cantil does not currently meet:

- **No PKCS#11 token interface.** HSMs are typically driven through Cryptoki (PKCS#11) so existing software (OpenSSL, GnuPG, ssh-agent, NSS) can use them transparently. Cantil has its own CBOR-over-Noise protocol and `libcantil`. A PKCS#11 shim could be added later as a host-side `libcantil_pkcs11.so` (the YubiKey / SoftHSM / OpenSC pattern), but it doesn't exist today.
- **Brief plaintext key exposure in RAM.** Cantil decrypts the slot key from LittleFS into RAM, loads it into CC310, signs, and zeroes the RAM. A FIPS-grade HSM keeps the key in crypto registers throughout its lifetime — never in general-purpose memory. CC310 supports a locked-key mode that could close this gap; it's not on the immediate roadmap.
- **No formal certification.** Real HSMs carry FIPS 140-2 or 140-3 certification at a defined level. Cantil makes no certification claims and currently doesn't target any.
- **No tamper response / zeroize-on-tamper hardware.** Enterprise HSMs include physical tamper detection that zeroizes keys. Cantil's only physical protection is APPROTECT disabling SWD in production builds.

Calling Cantil an HSM in marketing copy invites a comparison it loses. Calling it a **hardware CA** matches what it actually is and does — and the CA framing is more distinctive than yet-another-HSM positioning.

---

## What Cantil does have (the HSM-like properties)

These are accurate to claim and worth keeping in body copy under names other than "HSM":

- Hardware TRNG (CC310) for all key generation and entropy export.
- Private keys generated on-device; never traverse the host wire in plaintext.
- Keys stored encrypted at rest in LittleFS, with the storage key derived from FICR UID (no compile-time secrets).
- On-device signing — host receives signed artefacts, not key material.
- Slot-based key management with per-slot protection flags.
- End-to-end Noise_XX encryption between host and device with mutual static-key authentication.
- APPROTECT in production builds disables SWD access to the MCU.

In external copy these are described as **"hardware-backed key storage"**, **"on-device crypto"**, **"keys never leave the device"** — descriptive phrasing that doesn't overload the HSM term.

---

## Alternate terms considered

- **"Personal HSM"** / **"lightweight HSM"** — still inherits the HSM expectation set. Rejected.
- **"Hardware-backed key store"** — accurate but doesn't capture the CA function. Useful as a body-copy phrase, weak as a headline.
- **"Hardware crypto device"** — too vague.
- **"Hardware CA"** — chosen. Names the primary function. Doesn't promise enterprise-HSM features.

---

## If we ever want to claim HSM status

Path to legitimately claiming it would require, at minimum:

1. **PKCS#11 host shim** so existing tooling treats it as a token.
2. **CC310 locked-key mode** for slot keys, eliminating the RAM-plaintext window.
3. **Optional FIPS 140-3 L1 software path** — would require an audited crypto provider (e.g., the FIPS-validated wolfCrypt build), strict mode separation, and an algorithm cert. Achievable in principle on Cortex-M4F; substantial work.
4. **Physical tamper story** — at the spec/threat-model level if not the hardware level.

Tracked at idea-level only. Not on the immediate roadmap. See [docs/roadmap.md](../docs/roadmap.md) M11 for related standards-compatibility thoughts (FIDO2, FIPS L1) when the time comes.

---

## Audit — files updated when "HSM" was removed externally

- [README.md](../README.md)
- [docs/marketing.md](../docs/marketing.md)
- [docs/roadmap.md](../docs/roadmap.md) (project description, M5 heading, M9 Kconfig comment)
- [CLAUDE.md](../CLAUDE.md) (project purpose line, firmware-update Kconfig note)
- [libcantil/include/cantil.h](../libcantil/include/cantil.h) (file banner)
- [libcantil/cli/main.c](../libcantil/cli/main.c) (file banner)
- [firmware/Kconfig](../firmware/Kconfig) (CRYPTO_BACKEND_FREE help text)

Historical conversation transcripts in `docs/conversations/` are left as-is — they're the record of how the decision was made.
