# Storage resilience — flash failure, redundancy, and health warning

> **Status:** assessed 2026-07-22, **not started**. Prompted by the question
> "does littlefs or Zephyr support parity/striping across flash, so we can
> recover from a bad block and warn the user of impending failure?"
>
> Short answer: neither does, and for this part parity is the wrong tool.
> Replication of the small critical blobs is cheaper, simpler, and recovers
> from strictly more failures. Related: [two-step-provisioning.md](two-step-provisioning.md).

## What exists today

**Zephyr: nothing.** There is no RAID, parity, or erasure-coding layer
anywhere in `subsys/fs`, and no UBI/MTD equivalent. The only ECC references
in the entire flash driver tree are two NXP QSPI controllers — vendor
hardware, not a portable facility.

**littlefs: redundancy, but only for metadata.**

| Mechanism | Covers | Note |
| --- | --- | --- |
| Metadata pairs | metadata only | every metadata log is two blocks written alternately — inherently 2× redundant, survives one bad block |
| CRC on read | metadata | why corruption surfaces promptly as `LFS_ERR_CORRUPT` (-84) |
| Bad-block detection + relocation | both | a block failing program/erase/read is evicted and its contents moved |
| Dynamic wear levelling | both | `block_cycles`, currently 512 |
| **Parity / striping / erasure coding** | — | **does not exist** |

File data has **no** redundancy. It lives in CTZ skip-lists; a bad block
means that file's data is gone — detected, not recoverable.

The `Corrupted dir pair at {0x0, 0x1}` seen during
[destructive testing](zephyr-upstream.md#destructive-testing-2026-07-22) was
the metadata-pair mechanism reporting that *both* halves were unreadable.

## Finding: the CA key blobs are already 2× redundant, by accident

littlefs stores files smaller than `inline_max` *inline in the directory
metadata pair* rather than allocating data blocks. `inline_max` is left at 0
by Zephyr's `FS_LITTLEFS_DECLARE_DEFAULT_CONFIG`, so littlefs defaults it to
the largest possible value — `min(cache_size, attr_max, block_size/8)`. With
our geometry (`rd 16 ; pr 16 ; ca 64 ; la 32`, 4 KB blocks) that is **64
bytes**.

An encrypted key blob is **60 bytes** (12-byte GCM nonce + 32-byte
ciphertext + 16-byte tag). It is therefore stored inline, inside a metadata
pair, and already enjoys the pair's 2× redundancy.

**This is accidental, undocumented, and fragile.** Three ordinary changes
would silently drop it to zero redundancy:

- raising `CONFIG_FS_LITTLEFS_CACHE_SIZE` above 64 does *not* help — but
  lowering it below 60 pushes the blob out of line;
- any key type with a longer blob (`KEY_BLOB_MAX` is already declared 128,
  more than double the inline limit);
- adding a field to the stored blob format.

In each case the blob quietly becomes a CTZ data block with no redundancy at
all, and nothing in the build or tests would notice.

**Closed 2026-07-23.** The property is now checked at three points, and is
deliberate rather than lucky:

- `CANTIL_KEY_BLOB_LEN` in [storage.h](../../firmware/src/storage/storage.h)
  is the single definition of the 60-byte blob. `SESSION_ENC_LEN` and
  `NOISE_PRIV_ENC_LEN` were separate copies of `(12 + 32 + 16)` and now derive
  from it.
- A `BUILD_ASSERT` in [storage.c](../../firmware/src/storage/storage.c)
  recomputes littlefs's `inline_max` from the same inputs `lfs_init()` uses
  and fails the build if the blob no longer fits. Verified by building with
  `-DCONFIG_FS_LITTLEFS_CACHE_SIZE=32`, which fails with the explanation
  rather than a bare assertion.
- `storage_init()` re-checks after mount against the real `inline_max`, since
  the `block_size/8` term depends on the erase size the flash driver reports
  at runtime and is invisible to the compiler. `write_key_blob()` warns per
  write for the same reason.

The runtime checks log rather than refuse: an oversized blob is still written
correctly and the key is still readable — it has only lost its second copy —
so failing the write would turn a redundancy regression into an outage.

`KEY_BLOB_MAX` (128) in `ca.c` stays as a scratch buffer, with an assertion
tying it to the real constant and a comment saying which of the two governs.

## Why parity is the wrong tool here

**The medium is NOR, not NAND.** The board declares
`compatible = "nordic,qspi-nor"`, JEDEC `85 60 15` — a Puya P25Q16H, 16 Mbit
SPI NOR. Striping-with-parity is a NAND/SSD mental model. NOR differs in ways
that matter:

- no factory bad blocks and no bad-block-table concept;
- typically no on-die ECC (NAND mandates it, NOR usually omits it);
- ~100k erase cycles per sector, ~20 year retention;
- failure presents as a sector that won't erase or program, or retention loss
  over years — not the random bit-rot parity is designed for.

Cantil writes rarely and the volume is nearly empty, so wear is effectively a
non-issue.

**The payload is tiny.** What actually matters — a CA private key blob — is
60 bytes, under 1.5% of one 4 KB erase block. Striping parity across 512
blocks to protect 60 bytes is a great deal of machinery for the payload.

**Replication dominates parity at this size.** RAID5-style parity survives
exactly one failed stripe unit. Three copies survive two failures, cost 12 KB
of 2 MB (0.6%), need no new filesystem layer, and — the decisive part — the
recovery logic already exists. Every blob is AES-256-GCM, so a corrupted
copy fails authentication and identifies itself. Recovery is "try each
replica until one authenticates."

This is what secure elements and HSMs actually do for small critical
objects. They do not RAID them.

## Proposed design

### What to replicate

Everything irreplaceable and small:

- `/keys/<slot>/key.bin` for **every** slot, not just slot 0 — Cantil manages
  multiple CAs (slot 0 root, slots 1..`CONFIG_CANTIL_MAX_KEY_SLOTS`-1
  including subordinate CAs), and a sub-CA key is exactly as unexportable as
  the root's;
- `/session/key.bin` and `/session/id_key.bin`;
- the Noise static keypair.

Certificates and chains are **not** included: they are reconstructible from
the key plus stored X.509 parameters, which `ca_init()` already does in its
crash-window recovery path.

At 8 slots (the default; max 64) that is under 1.5 KB of live payload.

### The placement problem

This is the crux, and the reason it is not simply "write the file three
times". **littlefs gives no control over block placement.** Three replica
files may land in the same metadata pair or adjacent blocks; worse, being
inline, they would likely land in the *same* pair — replicas sharing the one
failure they are meant to survive.

Two options:

1. **Replicas as ordinary files.** Trivial to implement at the
   `storage_key_write` / `storage_key_read` chokepoints
   ([storage.c:182](../../firmware/src/storage/storage.c#L182),
   [storage.c:190](../../firmware/src/storage/storage.c#L190)). Weak
   guarantee — no assurance replicas occupy distinct erase blocks.
2. **A raw vault outside the littlefs partition.** Reserve a small region of
   QSPI, outside `cantil_storage`, and write replicas to fixed offsets a
   known distance apart using the `flash_area` API directly. Strong
   guarantee, and no dependence on littlefs allocator behaviour.

**Option 2 is preferred**, and it composes with the two-step work already
designed: the factory image is what carves and initialises the vault, and the
volume identity marker is the natural place to record its offsets. Doing this
after the partition layout is settled avoids a second flash-layout migration.

Note the ordering consequence: this should land *with* or *after*
[two-step-provisioning.md](two-step-provisioning.md), not before.

## Health counters and failure warning

Achievable and cheap, but worth being honest about what it can deliver.

**Available signals:** program/erase failures from the flash driver,
`LFS_ERR_CORRUPT` from CRC mismatches, and littlefs block relocations. These
can be counted at the flash callbacks Zephyr's littlefs already routes
through, persisted, and surfaced via `DEVICE_STATUS` plus a dedicated LED
pattern. A replica that fails GCM authentication during recovery is itself a
strong signal, and the repair (rewrite from a good copy) is free.

**Limits.** NOR provides far less telemetry than NAND — no raw bit-error
counts, no read-retry levels, no margining. You learn "this block just
failed", not "this block is degrading", and retention loss is invisible until
something reads. So this is an honest health counter and a warn-on-first-error,
**not** SMART-style prediction, and user-facing wording should not overclaim.

## Decisions needed

- Vault (option 2) versus plain replica files (option 1) — recommendation is
  the vault, sequenced with the factory image.
- Replica count. Three is the natural default; two is enough to detect and
  repair, three lets a majority resolve ambiguity.
- ~~Whether the build-time inline-threshold assertion lands **now**, ahead of
  the rest.~~ Done 2026-07-23, see above.
- Whether repair is automatic on read (rewrite the bad replica immediately)
  or requires an explicit command. Automatic repair writes to flash during
  what the caller thinks is a read; given the auto-format and
  auto-provisioning defects found in `aa99efe`, "quietly writes when it
  thinks it should" deserves scrutiny rather than a default.
