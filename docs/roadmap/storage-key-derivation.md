# Storage key derivation — current weakness and target design

> **Status:** planned, **sequenced after the Bazel migration (Phase 3).**
> Owner decision 2026-07-25: deferred behind Bazel rather than shipped
> immediately. The **finalized design and phased implementation plan are at the
> end of this document** ("Finalized design — encrypted volume, 2026-07-25");
> the analysis below is the reasoning that produced them and is unchanged.
>
> Correction to earlier framing (this block used to claim otherwise): the phase
> order actually executed was upstream Zephyr → **wolfSSL → Bazel** — the two
> were swapped — and mbedTLS is now gone from both firmware and client. The old
> note that this "should not wait for a phase" and could ship on mbedTLS PBKDF2
> is moot: it now rides behind Bazel by choice, and the KDF is wolfCrypt
> `wc_scrypt` (memory-hard — stronger than PBKDF2 for the low-entropy tap
> secret). The security weakness described below is real and still unfixed; the
> only change is that closing it is scheduled after Phase 3, not before.

## The problem

`crypto_storage_key_derive()` is the sole source of the storage key. Every
encrypted-at-rest path goes through it — `storage.c` (noise keypair read and
write), `session_slot.c` (four call sites), and `session.c`.

Both backends derive it the same way. From `firmware/src/crypto/crypto.c`:

```c
uint32_t d0 = FICR_DEVICEID0;
uint32_t d1 = FICR_DEVICEID1;
/* ... */
mbedtls_hkdf(md, NULL, 0,            /* empty salt   */
             uid, sizeof(uid),       /* ikm = FICR device ID */
             info, sizeof(info) - 1, /* "cantil-storage-key" */
             key_out, 32);
```

Nothing else contributes. No unlock gesture, no user secret, no HUK.

FICR DEVICEID is a **readable device identifier, not a secret**. The
derivation is a fixed, public function of it, in a codebase published under
GPLv3. Anyone who can read flash can recompute the key and decrypt every key
blob on the device.

The encryption therefore only defeats an attacker who can read flash but
*not* FICR — close to an empty set, since both are available to the same
attacker in every realistic scenario. **"Encrypted at rest" is currently
obfuscation, not encryption.**

## Why the nRF52840 HUK is not the fix

The obvious instinct is to swap FICR for a hardware secret. The nRF52840
does not have a usable one.

CC310 has a **KDR**, a 128-bit device root key held in the always-on power
domain, and NCS exposes a `hw_unique_key` library over it. But the nRF52840
has **no KMU** (Key Management Unit). Per Nordic's documentation:

> In devices without a KMU, like nRF52840, the bootloader writes the key to
> the Arm CryptoCell and locks the flash memory page where the key is stored.

So on this part the HUK is stored **in flash, in plaintext**. The bootloader
loads it into CC310 at every boot and then ACL-locks the page. Consequences:

- The protection is runtime state, not a fuse. It resets on every boot.
- It depends on the bootloader running correctly and winning the race.
- APPROTECT is the real perimeter, and nRF52 APPROTECT has a public history
  of voltage-glitch bypasses.

Genuine fused key storage arrives with CC312 + KMU on the nRF5340 and
nRF9160. The nRF52840 has neither a KMU nor TrustZone-M.

Using the HUK would also pull in the `nrf_cc3xx` binary blob and an
NCS-specific library, on a Nordic-only code path — directly against the
Phase 1 and 4 goals of dropping NCS and going multi-platform.

## Target design — wrapped master key with multiple KEK slots

Derive nothing. Generate a master key, and wrap it once per unlock method.
This is the LUKS keyslot model, and it maps onto the slot vocabulary already
used in `session_slot.c`.

```text
master_storage_key  = TRNG(32)                      # random, never derived
salt                = TRNG(16)                      # per-device, stored plain

KEK_taps            = scrypt(tap_secret, salt, N, r, p)
wrapped_slot[0]     = AEAD_encrypt(KEK_taps, master_storage_key)

KEK_passphrase      = scrypt(passphrase, salt, N, r, p)   # optional
wrapped_slot[1]     = AEAD_encrypt(KEK_passphrase, master_storage_key)

KEK_huk             = HUK_derive("cantil-storage")        # optional, Nordic only
wrapped_slot[2]     = AEAD_encrypt(KEK_huk, master_storage_key)
```

Unlock unwraps the master key from whichever slot the available secret
opens. Properties:

- **Rotating the tap sequence rewraps one slot** instead of re-encrypting
  every stored blob.
- **Slot 0 is fully portable** — no platform primitives, works identically
  on nRF, ESP32, STM32, RISC-V, and `native_sim`.
- **Slot 2 is optional defense in depth**, gated behind Kconfig, and its
  absence degrades cleanly rather than breaking the build.

Use a memory-hard KDF (`wc_scrypt` in wolfCrypt), not plain HKDF. The input
secret is low entropy, so KDF cost is the only thing standing between a
flash dump and the master key.

## Honest limit: tap entropy

This must be documented rather than glossed, because it bounds what the
product can claim.

| Configuration | Combinations | Entropy |
| --- | --- | --- |
| Default — 6 colors, 4 digits | 6⁴ = 1,296 | ≈ 10.3 bits |
| Maximum — 9 colors, 6 digits | 9⁶ ≈ 531,441 | ≈ 19 bits |

Against an attacker holding a flash dump, even at a punishing 1 second per
guess, the default falls in roughly 22 minutes and the maximum in a few
days. Online lockout policy does not apply — an offline attacker ignores it.

So the tap-derived slot:

- **Fixes** the current logical hole, where the key is a public function of
  a readable identifier.
- **Does not** survive physical flash extraction.

Only a high-entropy secret the device never stores — the optional passphrase
slot, delivered over the authenticated Noise session at unlock — resists
that attacker. On the nRF52840 there is no hardware alternative.

## Runtime controls: necessary, not sufficient

Proposed controls — keep the LittleFS volume unmounted and the Noise session
disabled until the unlock sequence is entered.

**Adopt both.** They buy real things:

- They bound how long the master key and decrypted material live in RAM.
- They block interface-level attack on a locked device.
- They shrink the blast radius of a pre-unlock firmware bug: a flaw in the
  transport or protocol layer cannot reach decrypted key material that was
  never unwrapped.

But they are **runtime access control, not protection of the bytes**, and
they cannot substitute for encryption at rest. An unmounted filesystem is
still a filesystem sitting in flash.

This matters more here than on a typical board, because of where the data
lives. Per the partition layout, `littlefs_storage` is the **full 2 MB of
external QSPI flash** — a separate chip on the XIAO. Reading an external SPI
part needs a clip and a cheap programmer. It does not involve the nRF52840
at all: no APPROTECT, no glitching, no code execution, no bootloader. The
firmware's mount state is irrelevant to an attacker who never powers it.

So the CA private keys sit on the single most easily extracted component on
the board. Encryption at rest is not defense in depth here; it is the only
thing standing between a $20 tool and the keys.

## The circular dependency in the proposal

As specified, the design cannot boot. The Noise keypair is itself stored in
the encrypted volume — `storage_noise_keypair_read()` reads it via
`crypto_storage_key_derive()`. So:

```text
Noise session   needs → transport keypair
transport key   needs → master storage key
master key      needs → passphrase
passphrase      arrives over → Noise session
```

Deadlock. The passphrase cannot be delivered over a channel whose key is
locked behind the passphrase.

## Resolution: two-stage unlock

Split the secret by what it protects, and match entropy to exposure.

```text
boot:     volume LOCKED, Noise DOWN, CA opcodes not registered

stage 1 — taps  (low entropy; firmware-mediated, rate-limited, online only)
    KEK_taps = scrypt(tap_secret, salt_boot)
    unwrap transport_keypair from the boot slot        [INTERNAL flash]
    → Noise session may come up
    → only pairing / unlock opcodes exposed

stage 2 — passphrase over the now-authenticated Noise session
    KEK_pass = scrypt(passphrase, salt_vol)
    unwrap master_storage_key from the volume header   [QSPI]
    → mount LittleFS, register CA opcodes
```

Why the entropy split is the right way round:

- **Taps guard the transport identity only.** Their 10–19 bits are
  acceptable *there* because that slot lives in internal flash (which at
  least costs an APPROTECT bypass) and because guessing is rate-limited by
  firmware that must be running to accept a tap at all.
- **The passphrase guards the CA keys**, which live on the trivially
  readable external chip. That is where high entropy is mandatory, and it is
  the only slot that survives chip extraction.

Put the boot slot in **internal** flash, not QSPI. It is small — one wrapped
32-byte key plus a salt — and moving it inside the MCU means stage 1 is not
defeated by the same clip that reads the main volume.

## Answer: yes, nothing secret gets stored

The conclusion in the proposal is correct, though it follows from the
keyslot model rather than from unmounting.

Both stages verify **implicitly**. A wrong tap sequence produces a KEK that
fails the AEAD tag check on the boot slot; a wrong passphrase fails it on the
volume header. Neither secret — nor any hash or verifier derived from
either — is ever written to the device. The only persisted artefacts are
random salts and wrapped ciphertext, both of which are safe in the clear.

## Supporting controls

To make "locked means unusable" hold in practice:

- Zeroize the master key, KEKs, and all decrypted material on lock, session
  teardown, inactivity timeout, and USB disconnect.
- Unmount LittleFS on lock, not just at boot.
- Do not register CA opcodes until stage 2 completes — absent, not merely
  refusing. An opcode that returns `ERR_LOCKED` still exercises parser code.
- Keep failed-attempt lockout for stage 1. State plainly in user docs that it
  constrains **online** guessing only and is irrelevant to an attacker
  holding the flash contents.

## Security tiers (feeds Phase 4)

Multi-platform support must not silently downgrade the security claim.
Each target declares a tier:

| Tier | Backing | Example targets |
| --- | --- | --- |
| 0 — dev/eval | No key protection; must be labelled in-product | `native_sim`, QEMU, generic boards |
| 1 — software root | Taps + scrypt, portable slot only | Most Zephyr targets |
| 2 — hardware-assisted | Tier 1 + platform key storage | ESP32 (eFuse flash encryption, HMAC/DS), nRF5340/nRF9160 (CC312 + KMU) |

Note that the nRF52840 lands in Tier 1, and **ESP32 is capable of Tier 2** —
so Phase 4 may raise the security ceiling rather than lower it.

## Migration

Devices in the field hold data encrypted under the FICR-derived key. New
firmware needs a one-time rewrap on first boot:

1. Detect legacy format (no salt / no wrapped-slot header present).
2. Derive the legacy key via the existing FICR HKDF path.
3. Decrypt all blobs, generate a fresh master key, re-encrypt, write slots.
4. Mark the new format and erase the legacy layout.

This interacts with the identity-recovery and `ACCEPT_IDENTITY_MIGRATION`
work still open in `docs/open-questions.md`, and should be sequenced with it.

## Compounding problem: the unlock sequence is stored in plaintext

`gesture.c` keeps the sequence as raw digits in `unlock_seq[]` and persists
it verbatim:

```c
int wr = storage_unlock_seq_write(unlock_seq, unlock_seq_len);   /* gesture.c:449 */
```

with `storage_unlock_seq_read()` reloading it at init and `seq_match()`
comparing entered digits against it directly.

**This would defeat the tap-derived KEK entirely.** An attacker who dumps
flash reads the unlock sequence in the clear — no brute force needed, not
even the ~22 minutes above. Deriving a KEK from a secret that is stored
next to the ciphertext gains nothing.

So the target design must also **stop storing the sequence**, which the
keyslot model gives for free:

- Verification becomes implicit. If the entered taps produce a KEK that
  successfully unwraps the master key, the AEAD tag validates and the
  sequence was correct. A wrong sequence fails the tag check.
- `storage_unlock_seq_write()` / `storage_unlock_seq_read()` are deleted.
  Nothing derived from the secret is persisted except the wrapped blob.
- `seq_match()` disappears along with any constant-time comparison concern —
  the AEAD tag check replaces it.

One small thing to re-home: `is_factory_default()` / `using_default_seq`
currently infers "still on factory defaults" by inspecting the stored
sequence. With nothing stored, that becomes a separate non-secret flag.

Good news on effort: the entered digits already exist as data in
`digit_buf`, and the configured sequence as `unlock_seq[]`, so the secret
material is available at the point it is needed. Plumbing it into the crypto
layer is wiring, not re-architecture.

## Open questions

- scrypt parameters: needs measurement on a 64 MHz M4F with 256 KB RAM.
  Target roughly 1 second per attempt without starving the transport.
- Should the passphrase slot be mandatory for Tier 1 deployments, or opt-in?
- Does a wipe-on-N-failures policy still make sense once an offline attacker
  can bypass it entirely?

---

# Finalized design — encrypted volume, 2026-07-25

This supersedes the exploratory keyslot sketch above where they differ. It is
the version to build. **Scheduled to start after the Bazel migration (Phase 3)
lands.**

## Decisions locked (owner, 2026-07-25)

- **Whole-volume file encryption.** Every file *content* on `cantil_storage`
  is AEAD-encrypted, not just the key blobs. A short plaintext bootstrap set
  is the only exception (see below).
- **Tap-unlock required at every boot.** The volume is undecryptable until a
  human enters the sequence on the physical tap input. **This deliberately
  ends headless autonomous operation** — after any power loss the device
  enumerates but cannot sign until someone is present to unlock. Accepted as
  the intended security posture, not a regression.
- **No recovery.** The sequence is never stored; forgetting it means the CA is
  cryptographically unrecoverable, and the only path forward is wipe +
  reprovision. No backdoor, no escrow slot. (The optional passphrase-backup
  slot sketched earlier is explicitly *not* being built.)

## Two-factor: tap sequence peppered with an on-board secret

The user secret (taps) is combined with a device secret (`pepper`) so that
neither a QSPI clip nor an APPROTECT bypass is sufficient alone:

```text
pepper         = TRNG(32)                              # INTERNAL flash (UICR CUSTOMER[]),
                                                       #   APPROTECT-protected, ERASEALL-wiped
salt           = TRNG(16)                              # QSPI volume header, plaintext (safe)
master_key     = TRNG(32)                              # the real file-encryption root, random
KEK            = HKDF( scrypt(tap_seq, salt), pepper ) # both factors required
wrapped_master = AEAD(KEK, master_key)                 # QSPI volume header, plaintext-safe
file_key(path) = HKDF(master_key, info=path)           # per-file / per-CA separation + GCM domain sep
```

- Unlock = taps → derive `KEK` → unwrap `master_key`. A wrong sequence yields a
  wrong `KEK` and fails the AEAD tag — **verification is implicit; nothing
  derived from the sequence is stored.** This also deletes today's
  plaintext-sequence hole (`storage_unlock_seq_*`, `seq_match`).
- Rotating the sequence re-wraps `master_key` under a new `KEK` only — the
  volume is never re-encrypted.
- **No boot deadlock** (unlike the passphrase-over-Noise sketch): taps arrive
  over the physical button, so the volume unlocks before Noise needs the
  transport keypair.

## Implementation seams (both already exist)

- **Whole-volume encryption = one choke point.** Every file goes through
  `write_file()` / `read_file()` in `firmware/src/storage/storage.c`. Wrap
  those two with per-path AEAD; the ~20 typed accessors above them are
  untouched. Directory *names* stay plaintext; only contents are encrypted.
- **Sequence material is already in hand.** `gesture.c` holds the entered
  digits (`digit_buf`) and configured sequence (`unlock_seq[]`); feeding them
  to the KDF is wiring, not re-architecture.
- **Plaintext bootstrap allowlist** (read before unlock, none secret): the
  volume identity marker, the `salt`, and the `wrapped_master` header.

## Entropy and the length knob

- New `CONFIG_CANTIL_UNLOCK_SEQ_MIN_LEN`, **default 8**, enforced at
  sequence-set time in `gesture.c`. Test builds set **2** via a gitignored
  `prj_local.conf` — never committed to the default.
- Each digit is a count `1..CANTIL_UNLOCK_PALETTE_SIZE` (default **6**, range
  2–9). So length-8 gives 6⁸ ≈ 20.7 bits at the default palette; the oft-cited
  9⁸ ≈ 25.4 bits needs `CANTIL_UNLOCK_PALETTE_SIZE=9` as well.
- Those bits are the *offline* wall **only if the pepper is already
  extracted**. With the pepper intact (APPROTECT holding), tap guessing is
  online and rate-limited. State both in any product claim — the pepper is the
  primary factor, the tap entropy the secondary.

## Phased plan (tree stays green each step; nothing touches the dev units until Phase 5)

0. **Length knob** — add `CANTIL_UNLOCK_SEQ_MIN_LEN` (default 8), enforce on
   set. Low risk, no behaviour change.
1. **Crypto core** (`native_sim` KATs) — new `crypto_volume_key.c`:
   `pepper_get()` (UICR; fixed value on native_sim), `kek_derive()` on
   `wc_scrypt`, `master_wrap/unwrap`, `file_key(path)`. Pin with fixed vectors.
   *Resolve here:* `wc_scrypt` N/r/p that hit ~1 s without OOM on 256 KB RAM.
2. **Storage seam** (`native_sim`) — AEAD-wrap `write_file`/`read_file` with
   per-path keys, active only while unlocked; plaintext bootstrap allowlist;
   round-trip + wrong-key tests.
3. **Gesture rewrite** — unlock becomes "did the taps unwrap the master";
   delete `storage_unlock_seq_*` + `seq_match`; `is_factory_default` → separate
   non-secret flag; change-sequence re-wraps.
4. **Boot/lifecycle + pepper provisioning** — boot LOCKED (FS mounts, header
   readable, CA opcodes unregistered); tap-unlock holds master in RAM and
   registers CA opcodes; zeroize + deregister on lock/timeout/USB-disconnect;
   write TRNG pepper to UICR `CUSTOMER[]` once at provision (NVMC write-once).
5. **Hardware** — wipe + reprovision unit #1/#2, provision pepper, set a
   length-2 test sequence, validate lock→tap→unlock→sign→relock. Gated by the
   flaky tap-button on unit #2.
6. **Docs/tests** — fold results back here; full ztest suite.

## Risks / notes carried forward

- **Do not brick the dev units.** This is the change class that wiped unit #2
  once; all logic proven on `native_sim` before Phase 5.
- **Logical vectors remain.** The pepper is readable by firmware, so malicious
  signed firmware (the `UPDATE_FIRMWARE` recovery path) or an RCE extracts it
  with no lab — the FW-signing key stays as sensitive as the storage key. The
  two-factor still helps: a pepper-extracting attacker also needs the taps.
- **UICR write-once.** `CUSTOMER[]` can only be written after erase (whole
  UICR), and `ERASEALL` clears it — that erase-on-recover *is* the tamper-wipe.
- **Migration.** Field devices need a one-time rewrap (detect legacy →
  FICR-derive → re-encrypt under the new scheme); for the two dev units,
  wipe + reprovision is simpler and matches the no-recovery decision.
