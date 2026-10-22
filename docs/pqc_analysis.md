# Post-Quantum Cryptography Analysis for Cantil

> Research notes from session 2026-06-09. Covers threat model, algorithm selection,
> integration design, key sizes, licensing, and implementation risks for a potential
> PQC migration of the Cantil hardware CA.

---

## Threat Model

The relevant quantum attack is **Harvest Now, Decrypt Later (HNDL)**: an adversary
records encrypted Noise sessions today and decrypts them retroactively once a
cryptographically-relevant quantum computer exists. Classical EC keys are not broken
immediately — they require a large fault-tolerant quantum computer — but the threat
window opens the day a CRQC is built, retroactively exposing all captured sessions.

### Component Threat Ranking

| Component | Quantum Vulnerable | Urgency | Notes |
|---|---|---|---|
| Noise_XX X25519 key exchange | Yes | **Highest** | HNDL threat; captured sessions are retroactively decryptable |
| EC P-256 device identity certs | Yes | Lower | Requires a real CRQC; attack is forward-only, not retroactive |
| EC P-256 firmware signing cert | Yes | Lower | Same as above |
| MCUboot EC P-256 image verification | Yes | Lowest / hardest | No imgtool PQC support yet |

**Takeaway:** The Noise transport session is the only component with a *retroactive* threat.
Upgrading it to a hybrid handshake addresses the HNDL risk; the others can wait for the
ecosystem to catch up (imgtool PQC, widespread NIST tool support).

---

## Algorithm Selection

### Key Encapsulation: ML-KEM-512 (Kyber)

NIST FIPS 203 (2024). The primary candidate for the Noise handshake hybrid.
ML-KEM-512 is the smallest security tier (matching AES-128 against classical attacks,
quantum-secure at ~NIST Level 1). Chosen over ML-KEM-768/1024 for flash and RAM budget.

**Key sizes for ML-KEM-512:**

| Artifact | Size |
|---|---|
| Public key (encapsulation key) | 800 bytes |
| Ciphertext | 768 bytes |
| Secret key (device-side only) | 1,632 bytes |
| Shared secret output | 32 bytes |

**Performance on Cortex-M4 at 64 MHz (software, no hardware acceleration):**

| Operation | Approximate time |
|---|---|
| Key generation | 300–400 ms |
| Encapsulation | ~300 ms |
| Decapsulation | ~300 ms |

Total handshake overhead: ~600–800 ms added to the existing Noise_XX handshake.
The CC310 has no PQC acceleration; this is pure software.

### Signature: ML-DSA (Dilithium)

NIST FIPS 204 (2024). Would replace EC P-256 for device identity certs and firmware
signing when the ecosystem is ready. Not urgent — no HNDL threat for signatures.
FALCON is the other NIST signature standard but requires 64-bit float emulation on
Cortex-M4, making it impractical here. ML-DSA is the correct choice for this target.

---

## Integration Design

### Hybrid Noise_XXhfs

The standard approach for quantum-resistant session establishment is a **hybrid handshake**
that runs X25519 and ML-KEM in parallel. If either primitive is broken, the session key
is still secure.

The Noise Protocol Forum has defined the `hfs` (Hybrid Forward Secrecy) modifier for
exactly this. The resulting pattern is `Noise_XXhfs`:

- The `e` message grows to include the initiator's ephemeral ML-KEM-512 public key (+800 bytes)
- The response carries the ML-KEM ciphertext (+768 bytes)
- Both shared secrets (X25519 output, ML-KEM shared secret) are XORed and fed into the
  Noise key schedule together
- The static keys remain X25519 — the `hfs` modifier only affects the *ephemeral* KEM

### mbedtls Relationship

ML-KEM **augments** mbedtls; it does not replace it. mbedtls continues to handle:
- Noise X25519 DH (static and ephemeral)
- AES-256-GCM session cipher
- SHA-256 (Noise handshake hash)
- EC P-256 CA and signing operations

ML-KEM is a separate, thin library providing only the ephemeral KEM primitive.
The two concerns (CA crypto library, PQC transport) are independent and should not be coupled.

**Recommended implementation library:** PQClean `ml-kem-512` — standalone C, no external
dependencies, ~15–25 KB flash, constant-time, designed for embedded targets.

### Session Key: No Size Change

The post-handshake CipherState keys are **still 32-byte AES-256-GCM keys**. The hybrid
KEM changes *how* they are derived, not their size. The ML-KEM-512 shared secret (32 bytes)
is HKDF-mixed with the X25519 shared secret during the handshake key schedule; the output
is still 32 bytes. Both directions = 64 bytes in RAM, zeroed on session teardown.

### RAM Impact

The ephemeral ML-KEM keypair exists only during the handshake:

| Ephemeral artifact | Size | Lifetime |
|---|---|---|
| ML-KEM-512 secret key | 1,632 bytes | Handshake only, then zeroed |
| ML-KEM-512 public key | 800 bytes | Handshake only |
| Ciphertext (in handshake buffer) | 768 bytes | Until shared secret extracted |

Peak additional RAM during handshake: ~3.2 KB. Post-handshake RAM is identical to today.
The nRF52840 has 256 KB RAM; this is manageable but needs to be accounted for against
whatever else is live during the handshake (stack, BLE buffers, Noise handshake state).

### Flash Budget

Current build: 214 KB / 486 KB (43% used), leaving ~272 KB headroom.
PQClean ML-KEM-512: ~15–25 KB additional flash. Fits comfortably.

### On-Device Key Generation

PQC key generation happens on-device in two distinct contexts:

**Ephemeral ML-KEM keypairs (Noise_XXhfs, urgent)**

A fresh ML-KEM-512 keypair is generated on every handshake — that is the
mechanism that provides forward secrecy. The nRF52840 TRNG supplies the
64-byte seed (two draws vs. one for X25519), keygen runs ~300–400 ms in
software, and the keypair is zeroed after the shared secret is extracted.
No persistent storage involved. PQClean handles this.

**Long-term ML-DSA identity keypairs (future, deferred)**

When ML-DSA replaces EC P-256 for device identity certs and firmware signing,
the device must generate and store ML-DSA keypairs. The key size difference
versus EC P-256 is substantial:

| | EC P-256 (today) | ML-DSA-44 (smallest) |
|---|---|---|
| Private key | 32 bytes | 2,528 bytes |
| Public key | 64 bytes | 1,312 bytes |
| Signature | ~64 bytes | ~2,420 bytes |

The current LittleFS key slot layout is sized for EC P-256. ML-DSA private
keys are ~80× larger — adopting ML-DSA requires a storage layout revision
for the key slots, a CSR wire format update to handle 1,312-byte public keys,
and consideration of keygen time (several seconds on Cortex-M4 in software).
This is scoped to the deferred ML-DSA milestone, not the Noise_XXhfs work.

---

## Filesystem Encryption: Already Quantum-Resistant

The LittleFS filesystem encryption does **not** require PQC augmentation.

Quantum computers attack asymmetric crypto efficiently via Shor's algorithm,
but only attack symmetric crypto weakly via Grover's algorithm (square-root
speedup). AES-256 under Grover's drops from 256-bit to ~128-bit effective
security — still above NIST's post-quantum security threshold.

On the nRF52840, the filesystem encryption key is an AES-256 key derived
from the CC310 hardware Device Root Key (KDR) via HKDF. The entire chain —
KDR → HKDF → AES-256-GCM — is symmetric. There is no asymmetric component
to replace.

**Full component summary — what needs PQC work vs. what is already safe:**

| Component | Crypto type | Quantum threat | Action |
|---|---|---|---|
| Noise X25519 session | Asymmetric (DH) | HNDL — retroactive | ML-KEM hybrid (M12) |
| EC P-256 identity certs | Asymmetric (ECC) | Forward-only | ML-DSA (future) |
| EC P-256 firmware signing | Asymmetric (ECC) | Forward-only | ML-DSA (future) |
| FS encryption (AES-256-GCM) | Symmetric | Grover → ~128-bit | None needed |
| KDR key derivation (HKDF/SHA-256) | Symmetric | Grover → ~128-bit | None needed |
| Session cipher (AES-256-GCM) | Symmetric | Grover → ~128-bit | None needed |

---

## Licensing

All major ML-KEM implementations are **AGPLv3-compatible**:

| Implementation | License |
|---|---|
| pq-crystals/kyber (NIST reference) | CC0 OR Apache 2.0 |
| PQClean `ml-kem-512` | CC0 |
| liboqs Kyber (legacy) | CC0 OR Apache 2.0 |
| liboqs ML-KEM (mlkem-native) | MIT OR Apache 2.0 OR ISC |
| liboqs top-level | MIT |

CC0 is public domain dedication — maximally permissive, compatible with everything.
Apache 2.0 is NOT GPLv2-compatible, but is GPLv3/AGPLv3-compatible (relevant for this project).

### Patent Clearance

NIST negotiated royalty-free patent abeyance for ML-KEM from:
- **Algo Consulting Inc.** (holds a relevant US patent portfolio)
- **CNRS** (Centre national de la recherche scientifique — holds French patents)

These cover any implementer or end-user of ML-KEM. No per-unit royalties, no licensing
hurdles for this project or its users.

---

## Integration Risks and Open Questions

### 1. Noise-C Library hfs Support

**Highest integration risk.** The `hfs` modifier is defined in the Noise spec extensions
but is not universally implemented. If the current Noise-C version in the tree does not
support `Noise_XXhfs` natively, options are:
- Fork/patch Noise-C to add `hfs` pattern support
- Implement the `Noise_XXhfs` state machine manually alongside Noise-C
- Replace with a Noise library that has `hfs` support

Must check the Noise-C version and its pattern registry before designing the binding layer.

### 2. Wire Protocol Versioning

The `e` message in `Noise_XXhfs` grows by ~800 bytes (the ephemeral ML-KEM public key).
Old `cantil` clients speaking plain `Noise_XX` would misparse this. Need either:
- A version byte in the framing layer
- A capability flag in the initial connection handshake

Without version negotiation, a PQC firmware update silently breaks all existing host clients.

### 3. RNG Seed Size

ML-KEM-512 key generation requires a 64-byte random seed (vs. 32 bytes for X25519).
The nRF52840 TRNG handles this fine — just requires two draws. Not a blocker.

### 4. Constant-Time Requirements

ML-KEM implementations must be constant-time to prevent timing side-channels.
PQClean's implementation is designed to be constant-time, but verification on Cortex-M4
(which has some data-dependent timing in certain operations) is worth confirming.

### 5. Transport Buffer Sizing

The CDC/ACM framing handles variable-length payloads, but the larger handshake messages
(~1.5 KB bigger than today) need to fit in the framing layer's max message size.
Worth auditing `transport_usb.c` buffer sizes before designing the Noise_XXhfs binding layer.

---

## What PQC Does NOT Change

- EC P-256 device identity certs (stored in LittleFS key slots)
- EC P-256 firmware signing cert
- MCUboot image verification (EC P-256)
- Key slot storage layout
- Pairing / trust tier model
- Session cert logic
- Long-term Noise static keys (remain X25519 — `hfs` only affects the ephemeral path)

No migration is required for existing provisioned devices when this lands — it is a
firmware update that changes how the session is *established*, not the stored keys.

---

## Recommended Implementation Sequence

1. Verify Noise-C `hfs` support (or prototype a patch)
2. Integrate PQClean `ml-kem-512` as a Zephyr module
3. Implement the `Noise_XXhfs` binding layer (~100–200 lines)
4. Add wire protocol version negotiation to the framing layer
5. Update libcantil host side to match
6. Audit transport buffer sizes for the larger handshake messages
7. Benchmark handshake latency on hardware (expect +600–800 ms)
