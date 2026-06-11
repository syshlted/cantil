# FIPS 140-3 Alignment Discussion — 2026-05-18

Working session between project author and Claude on what it would take to make
`cantil` FIPS 140-3 *aligned* (not certified) while keeping the codebase
licensable under AGPLv3.

---

## TL;DR

- **FIPS-aligned with AGPL-only libraries is achievable.** mbedTLS (Apache 2.0)
  provides every FIPS-approved primitive needed; everything else in the stack
  is already AGPL-compatible.
- **FIPS-*certified* is much harder under an AGPL-only constraint** — current
  140-3 validated modules suitable for embedded are mostly commercial. The
  project's plan is to stay aligned and leave certification as a downstream
  exercise for whoever wants to fund the lab work.
- **One current design choice must change to keep the alignment story coherent:**
  the Noise_XX cipher suite. The existing `Noise_XX_25519_ChaChaPoly_SHA256`
  uses primitives that are not on NIST's approved list. Switching to
  `Noise_XX_P256_AESGCM_SHA256` is a net win — it's FIPS-approved *and*
  CC310-accelerated, where the current suite is neither.
- **Self-tests and zeroization** are tractable engineering, a few days of
  focused work each.
- **APPROTECT-hw is compatible with field updates** — MCUboot DFU works
  independently of the debug port lockout.

---

## 1. Self-Tests (FIPS 140-3 §7.10)

Three layers required, all implementable with AGPL-compatible code:

| Layer | What it is | Implementation |
| --- | --- | --- |
| Pre-operational integrity test | HMAC or ECDSA signature over the firmware image, verified at boot | MCUboot already does ECDSA image verification; formalize it as the FIPS PIT and add a Kconfig stub that halts boot if verification didn't occur |
| CAST (Cryptographic Algorithm Self-Tests) | Known-Answer Tests for every approved algorithm before first use each boot | NIST CAVP vectors → one PSA call per algorithm at boot → compare output → fail-closed on mismatch. AES-256-GCM, SHA-256/384, HMAC, ECDSA P-256, HKDF, HMAC-DRBG. ~10–30 ms total on CC310 |
| Conditional self-tests | Per-operation health checks | Pairwise consistency on every ECDSA keygen (sign+verify a test vector with the new key before accepting it); SP 800-90B Repetition Count Test (RCT) and Adaptive Proportion Test (APT) on TRNG output; legacy CRNGT block-vs-previous-block comparison |

Effort estimate: 2–3 focused days for the full CAST suite, mostly typing in
vectors. PIT formalization is half a day. Health tests are another day or two.

---

## 2. Key Zeroization & Storage Hardening (FIPS 140-3 §7.9)

### Current state (correct)

- AES-256-GCM at rest with a FICR-derived KEK
- On-device signing only; private keys never leave the device
- RAM zeroing after each crypto op (per CLAUDE.md)
- Pattern: decrypt → load CC310 → sign → zero

### Gaps

1. **FICR-derived KEK is not tamper-resistant storage.** FICR is readable over
   SWD when APPROTECT is disabled, and the derivation is deterministic — anyone
   who dumps the chip recovers the KEK.
2. **`memset`-based zeroization is insufficient.** Need `explicit_bzero` /
   `mbedtls_platform_zeroize` (volatile-write barrier so the compiler can't
   elide it), plus zeroing CC310 register state and any stack frames that
   touched key material.
3. **No tamper detection.** The nRF52840 has no dedicated tamper pins (this is
   a real limitation vs. a secure element like ATECC608 or SE050).

### Correction from earlier in the discussion

**The nRF52840 does NOT have a KMU (Key Management Unit) peripheral.** KMU
exists on nRF9160, nRF5340, and nRF54L — not on nRF52840. My initial suggestion
to "use CC310's KMU" was wrong for this chip.

### Actual nRF52840 mechanisms for key-at-rest hardening

| Mechanism | What it does |
| --- | --- |
| **ACL** (Access Control List peripheral) | Locks up to 8 flash regions against read/write from outside the CPU (blocks SWD). 4KB-aligned regions, configured once per boot. |
| **APPROTECT-hw** | Disables SWD entirely; one-way and irreversible. The "soft" APPROTECT had a bypass (Errata 249); the "hw" variant does not. |
| **UICR salt + FICR UID + HKDF → KEK** | Per-device random salt written once to UICR on first boot; combined with FICR UID via HKDF. Means dumping a sibling device's FICR doesn't recover *this* device's KEK. |
| **CC310 internal key slots** | Holds keys during a crypto op only; cleared after use. Volatile. |

### Suggested module structure

```text
firmware/src/secure_storage/
├── secure_storage.h     ← public API: kek_init(), kek_wrap(), kek_unwrap(), lock_regions()
├── acl.c                ← configure ACL regions at boot; ~50 lines of register writes
├── approtect.c          ← arm APPROTECT-hw in release builds via Kconfig; ~20 lines
├── kek.c                ← UICR salt provisioning on first boot + HKDF KEK derivation
└── Kconfig
```

No new library, no assembly, no reverse engineering. The nRF52840 Product
Specification (Nordic, public PDF, ~600 pages) documents every register
involved.

### Zeroization triggers

- Explicit command (`RESET_DEVICE` 0x32)
- N consecutive auth failures
- Self-test failure
- Tamper event (best-effort heuristics: brownout below safe-write threshold,
  IMU-based "case opened" detection)

---

## 3. APPROTECT-hw and Field Updates

**APPROTECT only blocks the debug interface (SWD/JTAG); it does *not* block
MCUboot DFU.** Field firmware updates work normally:

- Routine field updates → MCUboot DFU over USB/BLE. The host sends a signed
  image; MCUboot verifies its ECDSA signature against a public key baked into
  the bootloader, swaps slots, reboots. No debug port involved.
- "I bricked the bootloader" → device is dead unless the next path is taken.

### Hardware reset path — destructive by design

`nrfjprog --recover` issues `CTRL-AP ERASEALL`, which:

- Wipes all flash (app, MCUboot, UICR including KEK salt)
- Re-opens SWD
- Destroys the CA private key and all device state

This is the correct semantics for "this CA is decommissioned" and provides the
tamper-zeroize property for free: an attacker who tries to extract the key via
SWD either finds it blocked, or `--recover`s and destroys what they came for.

### Caveat to verify

There is a Nordic register called `ERASEPROTECT` that, if set, disables even
`CTRL-AP ERASEALL`, making the chip permanently unrecoverable. It exists on
nRF5340/9160; I'm not certain it exists on nRF52840. **Verify against the
current nRF52840 PS before committing to a design that depends on either
behaviour.**

### Operational notes

1. **Back up the MCUboot signing private key offline.** It's separate from the
   CA private key. If lost, the fleet is stuck on whatever firmware is
   currently installed. YubiKey or air-gapped machine is the right home.
2. **Design the DFU UX with the lock state in mind.** Two policies to choose
   between:
   - "DFU always accepted if signature verifies" (firmware-signing key is the
     root of trust). Simplest.
   - "DFU requires UNLOCKED state + tap confirmation" (physical device holder
     is a second factor). More paranoid; consistent with the existing
     gesture-confirmation pattern for `PROTECT_SLOT` / `RESET_DEVICE`.

---

## 4. AGPL Compatibility — Libraries Inventory

| Library | License | AGPLv3-compatible? | Role |
| --- | --- | --- | --- |
| Zephyr | Apache 2.0 | Yes | RTOS |
| MCUboot | Apache 2.0 | Yes | Secure boot / DFU |
| mbedTLS | Apache 2.0 | Yes | Crypto core (FIPS-approved primitives) |
| Noise-C | BSD-3-Clause | Yes | Noise protocol implementation |
| LittleFS | BSD-3-Clause | Yes | Storage |
| zcbor | Apache 2.0 | Yes | CBOR codec |
| Oberon ocrypto | Nordic 5-Clause (proprietary, Nordic-SoC-only) | **No** | Optional "free beer" PSA backend |
| Nordic nrf_cc310 (driver beyond what PSA exposes) | Closed | **No** | Optional "free beer" path |
| wolfCrypt | **GPLv2-only** or commercial | **No** (GPLv2-only is incompatible with AGPLv3) | Not usable for AGPL build, even though it has 140-3 certs |

**Pattern:** AGPL-compatible libraries are the default. "Free beer" backends
(Oberon, deeper CC310 driver, commercial wolfCrypt FIPS) are selectable at
build time via Kconfig, following the same pattern already established for the
Noise crypto backend (Noise-C default, PSA/Oberon optional).

### AGPL §13 (network use) — open question

The AGPL's source-disclosure trigger fires on "interaction over a network."
USB-CDC and BLE to a single local host occupy a gray area. Worth deciding
explicitly what the AGPL is intended to protect against:

- (a) Someone forking the firmware and shipping a closed product — covered by
  AGPL §5 (distribution) regardless of network status.
- (b) Someone running this as a service for others — only matters if §13
  applies.

Recommendation: write the policy down in `LICENSE.md` or `NOTICE` so downstream
users know.

---

## 5. The Noise Cipher Suite Problem

### Current spec

```text
Noise_XX_25519_ChaChaPoly_SHA256
       └──┬───┘  └────┬─────┘  └─┬──┘
        DH       AEAD          Hash
```

- **Curve25519** for DH — X25519 is not on the NIST SP 800-56A approved KAS
  list (the 25519 family is documented in SP 800-186 as "additional curves,"
  but X25519 KAS approval is still in flux).
- **ChaCha20-Poly1305** for AEAD — **not** FIPS-approved. AES-GCM is the
  approved AEAD.
- SHA-256 is fine.

### Why this matters

The cipher suite is the visible cryptographic surface of the device. Anything
making a FIPS-alignment claim must use only FIPS-approved primitives in
FIPS-approved modes — otherwise the claim is misleading even informally.

### The fix

Switch to:

```text
Noise_XX_P256_AESGCM_SHA256
```

This is **a cipher-suite swap, not a library swap.** Noise-C supports
configurable suites out of the box. The handshake framing, transport, and CBOR
layers remain identical. Only the handshake math changes.

### Triple win

1. **FIPS-aligned** — P-256 ECDH + AES-256-GCM + SHA-256 are all on the
   approved list.
2. **Hardware-accelerated** — CC310 accelerates all three primitives natively;
   it accelerates neither of the current suite's primitives.
3. **Cert-path-friendly** — keeps the door open for a downstream organization
   to take this to CMVP without redesigning the protocol.

### Cost

- Existing client/device pairs using the old suite would need re-pairing
  (the static public keys are 32 bytes of Curve25519 today, 64 bytes of P-256
  uncompressed tomorrow — different key types).
- The `noise_crypto.h` abstraction layer already supports backend swapping;
  this is the exact case it was designed for.

### Timing

**Do the swap before building out self-tests and other FIPS-alignment work.**
Doing it later means re-testing the entire crypto path, plus re-pinning
device public keys in any clients already in the field. Doing it now, while
the project is pre-deployment, is essentially free.

---

## Library Decision: mbedTLS Everywhere (for now)

- **Firmware:** mbedTLS via PSA Crypto is essentially mandatory. Only path to
  CC310 hardware acceleration on nRF52840; OpenSSL is 3–5 MB of code and won't
  fit. Routes AES-GCM, SHA-2, ECDSA/ECDH P-256, HMAC through CC310 in hardware.
- **Client:** mbedTLS chosen over OpenSSL libcrypto for v1. Unified crypto
  story across firmware and client — identical test vectors, identical CVE
  surface, single mental model. CA tooling is less polished than OpenSSL's
  but sufficient for the protocol's needs (CSR/cert signing, X.509 parse,
  ECDSA/ECDH/AES-GCM, HMAC, HKDF).
- **OpenSSL is roadmapped** as a future build option for ports to larger SoCs
  where the flash/RAM budget allows it (3–5 MB libcrypto fits comfortably on
  anything with 4 MB+ of flash). Selection would follow the existing Kconfig
  backend pattern. Apache 2.0 since OpenSSL 3.0, so AGPL-compatible. Added to
  CLAUDE.md's "Future crypto/library options" list.

### RAM budget context (nRF52840)

256 KB total SRAM. Rough split for the full-feature build:

| Consumer | RAM |
| --- | --- |
| Zephyr kernel + drivers | ~15–25 KB |
| Bluetooth Host + Controller | ~30–50 KB |
| USB CDC/ACM | ~5–10 KB |
| LittleFS buffers | ~4–8 KB |
| PSA Crypto + mbedTLS state | ~10–20 KB |
| Noise session state | ~1 KB per session |
| zcbor stack/scratch | ~1–2 KB |
| Free for application | ~120–160 KB |

Plenty of headroom. The actual constraint on this chip is *flash*, not RAM —
crypto operations touch RAM in the low single-digit KB.

---

## Action Items

- [ ] **Swap Noise_XX cipher suite to P-256 + AES-GCM + SHA-256.** Tracked
      next; this discussion's immediate follow-on.
- [ ] Write `docs/licensing.md` with per-dependency AGPL compatibility table
      and a §13 policy statement.
- [ ] Verify whether `ERASEPROTECT` exists on nRF52840 (search PS for
      "ERASEPROTECT" and "CTRL-AP"). Decide whether to expose it.
- [ ] Design `firmware/src/secure_storage/` module: ACL region locking,
      APPROTECT-hw arming gated by `CONFIG_CANTIL_RELEASE_BUILD`, UICR salt +
      HKDF KEK derivation with first-boot bootstrap state machine.
- [ ] Replace `memset`-style zeroization with `explicit_bzero` /
      `mbedtls_platform_zeroize` throughout the key-handling paths.
- [ ] Implement CAST self-tests at boot using NIST CAVP vectors for each
      approved algorithm.
- [ ] Implement SP 800-90B RCT/APT health tests on TRNG output path.
- [ ] Decide DFU policy: signature-only vs. requires-UNLOCKED + tap.
- [ ] Back up MCUboot signing key to offline storage; document the procedure.
- [ ] Add `LICENSE.md` clarifying AGPL §13 intent (USB/BLE-as-network policy).
