# Project Roadmap

## Vision

A production-quality, open-source hardware CA running on commodity nRF52840 hardware. The device is self-contained: keys are generated and never leave the hardware, all crypto happens on-chip, and communication with host tooling is end-to-end encrypted. The accompanying C client library makes the device usable as a drop-in hardware trust anchor for any project.

---

## Milestones

### M1 — Foundation (USB + CA on XIAO BLE Sense)

**Goal:** Minimal working device. Sign CSRs over USB. Nothing breaks.

- [x] Zephyr project skeleton for `xiao_ble` board target
- [x] USB CDC/ACM transport (device side)
- [x] Noise_XX session (device side) — mbedtls direct, not PSA
- [x] LittleFS on external QSPI flash (key store + cert store)
- [x] First-boot key generation: CC310 TRNG → ECC P-256 CA keypair → encrypted blob in LittleFS
- [x] `SIGN_CSR` command — full sign path with key decrypt → CC310 sign → RAM zero
- [x] `GET_CA_CERT`, `GET_CA_CHAIN`, `GET_CA_SERIAL` commands
- [x] `DEVICE_STATUS` command
- [ ] MCUboot integration (signed image, USB DFU update path) — **deferred**; dev builds use UF2 bootloader + `cantil dfu` 1200bps-touch
- [x] `libcantil` client library: USB transport + session + `cantil_sign_csr`
- [x] Basic CLI tool using libcantil

---

### M2 — Gesture Input + LED Feedback

**Goal:** Device is usable standalone. Locked on boot, unlock via taps, LED feedback throughout.

- [ ] ~~LSM6DS3TR-C driver integration~~ — **abandoned**: IMU dead on every tested XIAO unit. PDM mic + GPIO button are the supported tap inputs.
- [x] Hardware tap detection: GPIO button works end-to-end on XIAO; PDM mic path captures audio in smoketest only (production build regression deferred)
- [x] Sequence buffer with timeout-based completion
- [x] LOCKED / UNLOCKED state machine (+ PAIRING, CHANGE_SEQ_*, AWAITING_*)
- [x] Auto-lock timeout (configurable via `CONFIG_CANTIL_INACTIVITY_TIMEOUT_SEC`, default 300 s)
- [x] LED blink sequences — full palette in `firmware/src/led/led.c` (LOCKED warm-cycle, UNLOCKED rainbow, PAIRING, CONFIRM/RESET prompts, TAP/DIGIT_ACK, FAIL, SEQ_ERROR, etc.)
- [x] Factory unlock sequence stored in LittleFS on first boot
- [x] `SET_UNLOCK_SEQ` command
- [x] `cantil_set_unlock_sequence()` in client library

**Board variant — GPIO button:**

- [x] `CONFIG_CANTIL_INPUT_BUTTON` Kconfig option
- [x] Software debounce + single/double-tap timing
- [x] `nrf52840dk/nrf52840` board overlay
- [x] `generic_nrf52840` minimal board overlay (USB + button + single LED)

---

### M3 — Full Certificate Store + CRL

**Goal:** Device is a complete CA, not just a signer.

- [x] Issued cert store in LittleFS (`/certs/<serial>/cert.der + meta.bin`)
- [x] `LIST_CERTS`, `GET_CERT`, `GET_CERT_COUNT` commands
- [x] `REVOKE_CERT` command + CRL update — current format is a custom packed v1 blob at `/lfs/crl.bin` capped at 64 entries; **RFC 5280 DER CRL v2 still TODO** (mbedtls has no CRL writer; hand-rolled ASN.1 via `mbedtls_asn1_write_*` is the planned approach)
- [x] `AUTO_EXPIRE` command (host provides Unix timestamp; device marks expired, updates CRL)
- [x] `GET_CRL` command
- [ ] Internal-flash-only storage mode (`CONFIG_CANTIL_STORAGE_INTERNAL`)
- [x] `cantil_list_certs`, `cantil_get_cert`, `cantil_revoke_cert`, `cantil_auto_expire`, `cantil_get_crl` in client library

---

### M4 — BLE Transport + Pairing

**Goal:** Wireless operation with the same security guarantees as USB.

- [ ] Zephyr BLE peripheral stack (`CONFIG_CANTIL_TRANSPORT_BLE`)
- [ ] Nordic UART Service (NUS) GATT profile
- [ ] Noise_XX session over BLE NUS (identical session code to USB path)
- [ ] BLE Passkey Entry pairing: device generates 6-digit passkey (digits 1–9), displays via LED
- [ ] BLE bond store: max bonds configurable via Kconfig (default 3)
- [ ] Resolvable Private Address + whitelist mode (bonded centrals only)
- [ ] PAIRING state in gesture state machine, `[DT, DT, ST, ST]` trigger
- [ ] `transport_ble.c` in client library (Linux: BlueZ D-Bus; macOS: CoreBluetooth stub)

---

### M5 — General-Purpose Key Slots

**Goal:** Device manages multiple key slots, not just the CA key. On-device CA hierarchy.

- [x] Key slot table in LittleFS (`/keys/<slot_id>/meta.bin + key.bin + csr.der + cert.der + x509_data.bin`)
- [x] `GEN_KEY` command (EC P-256; first free slot assigned)
- [x] `GEN_KEY_CSR` command (generates and stores CSR for a slot)
- [x] `GET_KEY_CSR` command
- [x] `PUSH_KEY_CERT` command (validates cert against slot public key before storing)
- [x] `LIST_KEYS` command (returns slot metadata + cert/csr presence flags)
- [x] `SIGN_KEY_SLOT` command — sign one device key with another, fully on-device (no CSR round-trip)
- [x] `SIGN_CSR_SLOT` command — generic per-slot CSR signing (enables sub-CA hierarchies)
- [x] `PUSH_KEY_X509`, `DELETE_KEY`, `PROTECT_SLOT`, `UNPROTECT_SLOT` commands
- [x] Max key slots via Kconfig (`CONFIG_CANTIL_MAX_KEY_SLOTS`, default 8)
- [x] `cantil_gen_key`, `cantil_gen_key_csr`, `cantil_get_key_csr`, `cantil_push_key_cert`, `cantil_list_keys`, `cantil_sign_key_slot`, `cantil_sign_csr_slot`, `cantil_delete_key`, `cantil_protect_slot`, `cantil_unprotect_slot` in client library

---

### M6 — Hardware TRNG Export

**Goal:** Device usable as a trusted entropy source independent of CA operations.

- [x] `GET_RANDOM` command (up to 4096 bytes per request, CC310 TRNG)
- [x] `cantil_random_bytes()` in `cantil.h`
- [x] `cantil_random.h` standalone header with pluggable source:
  - [x] `cantil_rand_source_device()` — device TRNG source
  - [x] Raw bytes (`cantil_rand_bytes`)
  - [x] Integers: `uint8/16/32/64`, `uint64_range` (rejection sampling, no modulo bias)
  - [x] Float: `double` [0,1), `float` [0,1), `double_range`
  - [x] UUID v4 (`cantil_rand_uuid`)
  - [x] Hex: plain, colon-separated, uppercase
  - [x] Strings from character sets (`cantil_rand_string` with `cantil_charset_t`)
  - [x] Pre-built charsets: lower, upper, digits, hex, alpha, alnum, printable
  - [x] Feature macros (`CANTIL_RAND_ENABLE_FLOAT`, `_UUID`, `_HEX`, `_STRING`) for selective compilation
- [x] Bonus: `GET_RANDOM_NAMES` (0x50) — packed 6-bit bitstream of SSA 2025 baby names, `cantil_rand_names()` decoder

---

### M7 — Broader Board Support

**Goal:** Runs on any nRF52840 board out of the box.

- [x] `nrf52840dongle/nrf52840` overlay (has button + RGB LED + 2MB flash)
- [x] `adafruit_feather_nrf52840` overlay
- [ ] Hardware abstraction documented: what a new board overlay must provide
- [ ] CI builds for all supported board targets

---

### M8 — Production Hardening

**Goal:** Safe to deploy for real use.

- [ ] APPROTECT enabled in release builds (disables SWD debug)
- [ ] Production signing key workflow (air-gapped MCUboot signing key)
- [ ] Flash wear monitoring (alert via `DEVICE_STATUS` when wear estimated high)
- [x] Secure wipe command (`RESET_DEVICE` 0x32 — overwrites slot 0 blob then rm_rf, reboots)
- [ ] Bond management command (list/remove BLE bonds via client library)
- [x] Rate limiting on failed unlock sequences — 3 free attempts then 10s/30s/2m/10m/1h lockouts; counter persists across reboot via `/lfs/config_unlock_attempts.bin`
- [ ] Firmware anti-rollback (MCUboot security counter)
- [ ] Security audit

---

### M9 — RNG-Only Build Mode

**Goal:** A stripped-down firmware build that exposes only the CC310 TRNG — no CA, no cert store, no gesture lock. Intended as the device-side target for the Linux hwrng kernel module, and as the foundation for a standalone RNG appliance project built on top of libcantil.

- [ ] `CONFIG_CANTIL_MODE_RNG_ONLY` Kconfig option — mutually exclusive with CA features
- [ ] When enabled: only `GET_RANDOM` and `DEVICE_STATUS` commands accepted; all others return `ERR_NOT_SUPPORTED`
- [ ] Device starts in permanently-unlocked state; gesture state machine and auto-lock timer are compiled out
- [ ] LED feedback reduced to: idle heartbeat (connected + session open), error flash
- [ ] Flash savings: cert store, key slots, LittleFS CA partition, and LSM6DS3TR-C tap driver all excluded
- [ ] Noise_XX session retained — entropy is still delivered over an authenticated, encrypted channel
- [ ] Validate that a `GET_RANDOM` request loop saturates USB FS bandwidth without stalling or rebooting
- [ ] **Separate project consideration:** This build mode, combined with libcantil and the hwrng kernel module (M10), constitutes a self-contained hardware RNG appliance. Evaluate splitting into a separate repo (`nrf-hwrng`) that takes libcantil as a dependency once the library API is stable.

---

### M10 — Linux hwrng Kernel Module

**Goal:** Expose the nRF52840 CC310 TRNG as a standard Linux entropy source. The module operates in two modes depending on whether mutual pubkey provisioning has been completed. In both modes the same character device (`/dev/cantilX`) is present with the same file-operation interface; what changes is the behaviour of `read()` and which ioctls are accepted.

#### Character device interface

All file operations are available in both modes:

| Operation | Unconfigured | Configured |
| --------- | ----------- | ---------- |
| `open()` | Opens USB CDC/ACM connection | Opens USB CDC/ACM connection, performs Noise_XX handshake |
| `close()` | Closes USB connection | Closes session, zeroes session keys, closes USB connection |
| `read()` | Returns raw bytes from the CDC/ACM stream (Noise ciphertext) | Returns decrypted hardware random bytes (identical behaviour to `/dev/urandom`) |
| `ioctl()` | Raw-channel and provisioning ioctls only; CA/RNG ioctls return `ENOKEY` | All ioctls accepted |
| `mmap()` | Maps the raw CDC/ACM ring buffer | Maps a ring buffer of decrypted random bytes |

#### Unconfigured mode — raw channel ioctls

Accepted when either pubkey has not been provisioned. Intended for userspace programs that implement their own Noise session or provisioning tooling.

- [ ] `CANTIL_IOC_GET_MODULE_PUBKEY` — copy module's Curve25519 static pubkey to userspace (32 bytes)
- [ ] `CANTIL_IOC_SET_DEVICE_PUBKEY` — provision the device's expected static pubkey (32 bytes); persists to kernel keyring; transitions to configured mode if device has already been provisioned with module pubkey
- [ ] `CANTIL_IOC_GET_STATUS` — return connection state: `DISCONNECTED`, `CONNECTED_RAW`, `CONNECTED_SESSION`
- [ ] `CANTIL_IOC_SEND_RAW` — write a raw frame to the CDC/ACM connection
- [ ] `CANTIL_IOC_RECV_RAW` — read a raw frame from the CDC/ACM connection (non-blocking variant of `read()`)
- [ ] All other ioctls return `ENOKEY`

#### Configured mode — transparent RNG

Active when both sides have each other's static pubkey provisioned. The Noise_XX session is handled entirely inside the kernel module; no userspace process is involved.

- [ ] `read()` returns plaintext random bytes — callers see an infinite, non-blocking stream of hardware entropy, identical in interface to `/dev/urandom`
- [ ] `mmap()` maps a kernel-managed ring buffer populated by a background `GET_RANDOM` prefetch loop; reads from the mapped region consume bytes and trigger refill
- [ ] `hwrng_register` called on session open; `hwrng_unregister` on disconnect — device contributes to the kernel entropy pool and appears as `/dev/hwrng`
- [ ] `hwrng.quality` default 1000 (CC310 is a certified hardware RNG); configurable via module parameter
- [ ] All raw-channel ioctls remain available in configured mode (useful for diagnostics)
- [ ] Additional ioctls: `CANTIL_IOC_GET_SESSION_STATS` (bytes delivered, reconnect count), `CANTIL_IOC_CLEAR_DEVICE_PUBKEY` (unprovision, returns to unconfigured mode)

#### In-kernel Noise_XX client

libcantil is a userspace library and cannot be linked into a kernel module. The Noise_XX session is reimplemented in kernel space using existing kernel crypto primitives — no userspace helper daemon required.

- [ ] Curve25519 ephemeral + static DH via `crypto_kpp` (`curve25519` driver, available since kernel 4.17)
- [ ] ChaCha20-Poly1305 AEAD for session encryption via `crypto_aead` (`rfc7539` driver)
- [ ] SHA-256 for Noise handshake hash via `crypto_shash`
- [ ] Full Noise_XX three-message handshake (`-> e`, `<- e, ee, s, es`, `-> s, se`) implemented in kernel space
- [ ] Handshake performed on each `open()` in configured mode; session keys held in kernel memory, never exposed to userspace
- [ ] Session keys zeroed on `close()` or USB disconnect; keypair regenerated on next connect

#### Mutual authentication — pinned static public keys

Both sides know each other's public key before the first session. No TOFU, no external CA — "self-signed" means self-generated Curve25519 keypairs.

- [ ] Module generates its own Curve25519 static keypair on first load; private key stored in kernel keyring
- [ ] Handshake aborted and connection closed if device presents an unrecognised static key
- [ ] Device-side (M9): stores module pubkey via provisioning command; rejects handshakes from unpinned peers in RNG-only mode
- [ ] Provisioning tool `cantil-hwrng-provision`: reads module pubkey via `CANTIL_IOC_GET_MODULE_PUBKEY`, pushes it to device via libcantil, reads device pubkey from device, writes it via `CANTIL_IOC_SET_DEVICE_PUBKEY`

#### USB transport + packaging

- [ ] `usb_driver` bind/unbind on CDC/ACM with Cantil VID/PID (0x0867:0x5309 placeholder; replace with allocated VID before distribution)
- [ ] `hwrng_register` / `hwrng_unregister` lifecycle tied to session open/close
- [ ] Out-of-tree module build with DKMS packaging (`dkms.conf`)
- [ ] udev rule for device node permissions and stable `/dev/cantil` symlink
- [ ] `rngd` / `jitterentropy-rngd` compatibility verified
- [ ] Basic selftest: `cat /dev/cantil0 | rngtest -c 1000`
- [ ] Verify that an unpinned device is silently refused (`EACCES`), not kernel-panic'd

---

### M12 — Post-Quantum Cryptography (long-term, exploratory)

**Goal:** Harden the Cantil session transport against Harvest Now, Decrypt Later (HNDL)
attacks. The Noise_XX X25519 key exchange is the primary threat: captured sessions are
retroactively decryptable once a cryptographically-relevant quantum computer exists.
EC P-256 identity certs and firmware signing are secondary (forward-only threat, no
retroactive exposure) and tracked separately as the ecosystem matures.

Full analysis: [docs/pqc_analysis.md](pqc_analysis.md)

#### Hybrid Noise_XXhfs session transport

- [ ] Audit Noise-C library version for `hfs` pattern support; patch or replace if absent
- [ ] Integrate PQClean `ml-kem-512` as a Zephyr module (~15–25 KB flash, CC0 license)
- [ ] Implement `Noise_XXhfs` binding layer: interleave X25519 + ML-KEM ephemeral paths, XOR shared secrets before feeding the Noise key schedule
- [ ] Wire protocol version negotiation: version byte or capability flag in framing layer so old clients fail cleanly rather than misparse the larger `e` message
- [ ] Update libcantil host side to support both `Noise_XX` (legacy) and `Noise_XXhfs` (PQC)
- [ ] Audit CDC/ACM transport buffer sizes for the larger handshake (~1.5 KB bigger than today)
- [ ] Benchmark handshake latency on hardware (expect +600–800 ms; ML-KEM-512 on Cortex-M4 is ~300 ms per operation, software only — CC310 has no PQC acceleration)

**Key constraints:**

- Session key output remains 32 bytes (AES-256-GCM) — the KEM hybrid changes derivation, not key size
- Ephemeral ML-KEM keypair (~3.2 KB: 800-byte pubkey + 1,632-byte secret key + 768-byte ciphertext) lives in RAM only during the handshake, then is zeroed
- Static Noise keys remain X25519; `hfs` only affects the ephemeral path
- No impact on stored keys, key slots, pairing model, or trust tiers
- No migration required for existing provisioned devices

#### Post-quantum identity (future, ecosystem-gated)

- [ ] ML-DSA (Dilithium, NIST FIPS 204) device identity certs when imgtool/MCUboot add PQC support
- [ ] ML-DSA firmware signing cert — same gating
- [ ] FALCON excluded: requires 64-bit float emulation on Cortex-M4, impractical

**Licensing:** PQClean ML-KEM-512 is CC0 (public domain). pq-crystals reference and liboqs
are CC0 OR Apache 2.0. All AGPLv3-compatible. Patent clearance via NIST royalty-free
abeyance from Algo Consulting Inc. and CNRS covers all implementers and end-users.

---

### M11 — Standards Compatibility (long-term, exploratory)

Both items below are exploratory long-term roadmap options. They are *not* blockers for any earlier milestone and may never ship.

#### FIDO2 / CTAP2 as a parallel feature

Add a FIDO2 authenticator interface alongside the existing CDC/ACM CBOR protocol — *not* a replacement. Cantil's CA / key-slot model and FIDO2's WebAuthn credential model are different problem spaces; we want both, gated by Kconfig (`CONFIG_CANTIL_FIDO2=y`).

- USB composite: CDC/ACM (existing) + HID (new CTAP2 endpoint). Zephyr supports this natively.
- CTAP2 protocol stack: CBOR over HID. zcbor (already in tree) handles the encoding.
- Credential storage: reuse the LittleFS storage layer; resident keys go into a new `/fido/` namespace.
- User presence / user verification: map to the existing tap gesture state machine. A pending CTAP2 request enters an `AWAITING_FIDO_UP` state with its own LED pattern.
- Reuses CC310 ECDSA P-256, SHA-256, TRNG.
- Estimated flash cost: +100–200 KB on top of current ~200 KB build; comfortable within the 972 KB image budget.
- Targeting **FIDO Alliance functional conformance** (spec compliance) — *not* FIPS certification, which is a separate process (see below).

#### FIPS 140-2/3 Level 1

Pursue FIPS 140-2 (or 140-3) **Level 1** validation. Higher levels are gated by hardware Cantil does not have: L2 requires tamper-evident enclosure, L3+ requires tamper response. The nRF52840 has no tamper pins and no KMU — see `docs/fips_discussion_2026-05-18.md` for the full chip-level analysis.

L1 is paperwork-heavy more than code-heavy. Code work:

- Switch all crypto operations to **CAVP-validated** implementations. CC310 via nrf_security has CAVP certs for some primitives; need to audit which ones cover our exact use (P-256 ECDSA, SHA-256, AES-256-GCM, HMAC-SHA-256, X25519, ChaCha20-Poly1305).
- Define the **cryptographic module boundary** — likely the entire firmware image. Anything outside the boundary (e.g., host CLI) is out of scope.
- Add an **approved-mode-only** Kconfig (`CONFIG_CANTIL_FIPS_MODE=y`) that disables non-approved algorithms (e.g., refuses Ed25519 if not on the approved list).
- Self-tests on boot: known-answer tests for each approved primitive; halt on failure.
- Integrity check of firmware image on boot.

Non-code work (the real cost):

- **Security Policy** document — module description, ports/interfaces, roles, services, key lifecycle, self-tests, mitigation of attacks.
- **CMVP lab engagement** — third-party validation lab does the review. Typical cost $50–200k, timeline 6–18 months.
- Cantil is OSS; needs a sponsoring entity to fund and own the certificate.

This is realistically a "if there is commercial interest" milestone, not a hobby-time milestone.

---

## Deferred / Out of Scope (for now)

- RSA key slots — CC310 supports RSA-2048 but the flash/RAM cost is significant; deferring until there is a concrete use case
- OCSP responder — client-side CRL distribution is the intended model
- Network interface (USB ECM/NCM) — out of scope; this is a local device, not a network service
- Windows BLE transport — `transport_ble.c` targets Linux first; Windows WinRT BLE is a later addition
- Web interface — not in scope; CLI and C library are the interface
- Multi-device replication / key backup — intentionally not supported (the point is that keys don't leave)

---

## Component Dependency Map

```text
M1 (USB + CA core)
  └── M2 (gesture input + LED)
       └── M4 (BLE transport + pairing)
  └── M3 (cert store + CRL)
       └── M5 (key slots + intra-device signing)
  └── M6 (TRNG export)       ← independent, can ship with M1
       └── M9 (RNG-only build mode)
            └── M10 (Linux hwrng kernel module)
M7 (board support)           ← parallel with M2–M5
M8 (hardening)               ← gated on M1–M5 completion
```
