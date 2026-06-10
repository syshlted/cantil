# Storage Layer

> **Broadly stale (pre–CA-wire-up snapshot). Pending rewrite.** This document
> was written before the slot/meta/issued-cert/CRL implementation across the
> sign_csr + ca_bootstrap ztest pushes. The "wired vs. specced" tables below
> still list `meta.bin`, `x509_data.bin`, the issued-cert meta, and most CA
> ops as missing or `-ENOSYS` — all of those are wired now (see CLAUDE.md §
> "Future commands" `[x]` entries from `SIGN_CSR` (0x01) through
> `SIGN_CSR_SLOT` (0x2A)). The pieces of this doc that are **still current**
> are: the medium description (LittleFS on QSPI P25Q16H), the noise/keypair
> layout, and the chain `ARG_UNUSED` gap (§"CA components specifically").
> The chain gap has a queued fix — see the "On-device CA chain walker" entry
> in CLAUDE.md's open-questions block.

Reference for the on-device persistence model: medium, layout, what's
wired vs. specced, and the runtime characteristics that should inform
future design choices (counters, indexing, caching).

## Medium

A single **LittleFS** volume mounted at `/lfs`, backed by either an
internal flash partition or external QSPI flash depending on Kconfig
(`CANTIL_STORAGE_EXTERNAL` / `CANTIL_STORAGE_INTERNAL`). On the XIAO BLE
Sense the active medium is the external 2 MB QSPI (P25Q16H) — confirmed
by the boot log: `512 × 4 KB blocks = 2 MB`.

LittleFS provides wear leveling and power-loss safety. One filesystem
holds everything: keys, certs, Noise material, device config.

## Slot model

A "slot" is a directory `/lfs/keys/<N>/`, where N is in the range
`0..CONFIG_CANTIL_MAX_KEY_SLOTS - 1` (Kconfig default 8, range 1..64).

- **Slots are not fixed size.** LittleFS allocates 4 KB blocks per file
  on demand; a slot's storage cost is the sum of its files rounded up
  to the block size.
- **Slot 0** is the master CA, provisioned on first boot and protected
  by default.
- **Slots 1..N** are general-purpose, allocated by `GEN_KEY`.

## Per-slot files (spec vs. wired)

| File in `/lfs/keys/<N>/` | Purpose                                            | `storage.c` API                  | `ca.c` caller            |
| ------------------------ | -------------------------------------------------- | -------------------------------- | ------------------------ |
| `key.bin`                | AES-256-GCM(FICR-derived key) over privkey         | `storage_key_{read,write}`       | slot 0 only (provision)  |
| `cert.der`               | self-signed or externally-signed cert              | `storage_slot_cert_{read,write}` | partial (CA push)        |
| `csr.der`                | optional CSR                                       | `storage_slot_csr_{read,write}`  | none yet                 |
| `meta.bin`               | key type, timestamp, **protected flag**, scope     | **missing**                      | —                        |
| `x509_data.bin`          | packed-binary subject DN, validity, extensions     | `storage_slot_x509_{read,write}` | `push_key_x509` wired    |
| `crl.der` (per-slot)     | CRL for certs signed by this slot                  | **missing** (only a global one)  | —                        |

## Issued-cert store `/lfs/certs/<hex-serial>/`

| File                                                                    | `storage.c` API                       | Status      |
| ----------------------------------------------------------------------- | ------------------------------------- | ----------- |
| `cert.der`                                                              | `storage_issued_cert_{read,write}`    | wired       |
| `meta.bin` (subject DN, issuer_slot, timestamps, revoked, protected)    | **missing**                           | —           |

## Other top-level paths

```text
/lfs/session/
    key.bin        ; X25519 Noise static privkey, AES-256-GCM encrypted (60 B: nonce+ct+tag)
    id_key.bin     ; P-256 identity privkey, encrypted — signs session cert only
    meta.bin       ; 44 B: version, flags (bit0=CA-signed), init_unix, cached X25519 pubkey
    cert.der       ; ECDSA self-signed X.509 cert; X25519 key bound via OID 1.3.6.1.4.1.58270.1.1
    chain.der      ; optional — CA-signed issuer chain above cert.der (PUSH_SESSION_CERT, T-07)
    csr.der        ; optional — written by GET_SESSION_CSR on demand (T-05)

/lfs/clients/<hex8>/        ; one dir per bonded peer, named by first 4 bytes of their pubkey
    pubkey.bin     ; 32 B plaintext Curve25519 static pubkey — existence marker for the bond (T-15)
    meta.bin       ; 44 B client_meta_t v1: kind (HOST=0/PEER=1), timestamps, friendly_name[32]
    psk.bin        ; optional — encrypted PSK (Method 3/5, T-18)
    cert.der       ; optional — cached client cert (Method 4/5, T-19)

/lfs/noise/client_pub.bin   ; RETIRED (T-16) — single-key TOFU; superseded by /clients/ store
/lfs/noise/key.bin          ; RETIRED (T-04) — device static key now at /session/key.bin
/lfs/noise/pub.bin          ; RETIRED (T-04) — secure_wipe still erases these on old units

/lfs/config.bin             ; device config (tap sequences, unlock timeout, LED params)
/lfs/crl.der                ; legacy single-file CRL — predates the per-slot CRL design
```

## CA components specifically

- **Private key** → `/lfs/keys/0/key.bin`, encrypted with
  `crypto_storage_key_derive` (FICR UID → AES-256-GCM key). Loaded into
  RAM only for the duration of a sign op; zeroed after.
- **Self-signed CA cert** → would live at `/lfs/keys/0/cert.der`.
  Currently **never written** (`ca_provision` logs "not yet
  implemented"). That's why `certs_issued = 0` and `ca_get_serial`
  returns `-ENOSYS`.
- **Chain** → `ca_get_chain` walks recursively via `ca_get_chain_slot`.
  Self-signed root returns the slot's own cert; on-device sub-CA chains
  recurse to the `issuer_slot` recorded in the issued-cert meta and
  concatenate each level's cert.der; externally-enrolled slots append
  the chain bytes pushed via `PUSH_CA_CERT` / `PUSH_KEY_CERT` (persisted
  at `/lfs/keys/<slot>/chain.der`) and stop. Stale chain.der is dropped
  when the slot's cert is regenerated (PUSH_KEY_X509 self-signed regen,
  `SIGN_KEY_SLOT`, or `PUSH_*_CERT` with no chain).
- **Serial** → not stored separately; parsed out of stored CA cert DER
  on demand. `ca_get_serial` is `-ENOSYS`.
- **CSR** → `/lfs/keys/0/csr.der`, written by `GEN_KEY_CSR` (unwired).
- **CRL** → spec says per-slot at `/lfs/keys/<N>/crl.der`. Code still
  uses a single `/lfs/crl.der`. `ca_revoke_cert` is `-ENOSYS` so nothing
  writes it yet.
- **Index** → no index file. Enumeration is by directory walk:
  `storage_count_slots_used` probes `key.bin` per slot,
  `storage_count_issued_certs` walks `/lfs/certs/`. Detailed listings
  (`ca_list_certs`, `ca_list_keys`) remain `-ENOSYS`.

## Caching and runtime cost

LittleFS keeps **small bounded RAM buffers** — there is no Linux-style
page cache. From the device boot log:

```
littlefs: partition sizes: rd 16 ; pr 16 ; ca 64 ; la 32
```

| Buffer       | Size            | What it does                                                |
| ------------ | --------------- | ----------------------------------------------------------- |
| `rd` read    | 16 B            | Aligns/buffers one flash read op                            |
| `pr` prog    | 16 B            | Aligns/buffers one flash write op                           |
| `ca` file    | 64 B / open fd  | Per open file: active block window                          |
| `la` lookahead | 32 B = 256 bits | Bitmap of free/used blocks, scanned in 256-block chunks   |

Implications:

- Reads outside the 64 B file cache hit flash directly. Sequential reads
  inside one block benefit; random seeks across blocks don't.
- **No cross-file caching.** Closing a file drops its cache; reopening
  re-reads from flash.
- Writes aren't write-back in the OS sense — they hit the prog buffer
  and are flushed on `fs_sync` / `fs_close`. LittleFS itself is
  power-loss safe, but a crash before close can lose the un-flushed
  write.
- Zephyr's `fs.h` layer adds no further caching — `fs_read` / `fs_write`
  are thin pass-throughs.
- **Directory walks re-read from flash on every call.**
  `fs_opendir` / `fs_readdir` are not cached. Any code that walks
  `/lfs/certs/` to count or filter does O(N) flash work each time.

## Design implication: counters need to be persisted

Because there is no FS cache to repopulate from quickly, any derived
state that must survive reboot needs to live on disk. Specifically:

- **Lifetime `certs_issued`** — increment-on-sign counter, persisted
  to a small file (e.g. `/lfs/state/counters.bin`).
- **Next-free-slot hint** — write the highest-allocated slot index so
  `GEN_KEY` doesn't always re-scan.
- **Issued-cert count** — could be persisted as a number rather than
  recomputed by directory walk every `DEVICE_STATUS`.

In-RAM state is wiped on every reboot and there is no warm cache to
make rebuilding from disk cheap.

## How many certs can this device hold?

Rough math against the 2 MB QSPI:

- Free space after CA provisioning: **~2016 KB**.
- One issued cert occupies one directory (`/lfs/certs/<hex-serial>/`)
  plus `cert.der` and eventually `meta.bin`.
- A typical end-entity cert DER is ~600–1200 B. LittleFS rounds each
  file up to a **4 KB block**, and the directory itself consumes blocks
  for metadata.
- Realistic per-cert cost on this config: **~8–12 KB**
  (cert.der block + meta.bin block + directory entry overhead).
- Theoretical ceiling: `2016 / 10 ≈ 200` certs comfortably; **a few
  hundred at most**, not thousands.

### Why "thousands" would be a stretch even with more flash

Even on a larger medium, the dispatch path costs scale with the cert
count:

- `DEVICE_STATUS` walks `/lfs/certs/` every time → O(N) flash reads.
- `LIST_CERTS` walks the whole tree.
- `REVOKE_CERT` (once wired) would need to find the cert by serial.
  Today the path *is* the serial (`/lfs/certs/<hex>/`) so lookup is
  O(1), but only because we never put more than one entry per directory
  — flat naming gives accidental O(1) random access.

If we want thousands or tens-of-thousands of certs (e.g. a small
enterprise CA, or a CA managing per-session ephemeral certs at high
turnover), three things would have to change:

1. **Storage medium** — larger flash, or accept that this is a personal
   CA scoped to single-digit hundreds of certs.
2. **Indexing** — see below.
3. **CRL representation** — at thousands of revoked entries a single
   monolithic `crl.der` becomes unwieldy to re-sign on every revocation.

## Open questions for future discussion

- **LittleFS indexing.** LittleFS exposes a B-tree-ish on-disk layout
  but no application-level secondary index. There's no equivalent of
  "find all certs where issuer_slot = 3" without walking. If the
  dispatcher needs filtered queries (per-issuer cert lists, revoked
  vs. valid filters, expiry-bucket sweeps for `AUTO_EXPIRE`), we'd want
  to maintain index files ourselves — e.g. `/lfs/index/by_issuer/<N>`
  containing a list of serials. That's an application-level decision,
  not a LittleFS feature.

- **Custom CA-purpose filesystem.** Worth weighing if the cert count is
  expected to scale, or if specific access patterns are bottlenecked.
  Trade-offs:
  - Pro: pack metadata, cert DER, and revocation status into a single
    record format with O(1) random access by serial, avoid LittleFS
    block rounding (currently ~4 KB per file regardless of payload),
    cache hot records in RAM.
  - Pro: explicit append-only journal makes the security audit story
    cleaner — every CA operation produces a traceable on-disk delta.
  - Con: power-loss safety and wear leveling must be reimplemented
    from scratch, and they're hard to get right. LittleFS has had a
    decade of bug-fixing.
  - Con: locks the data format to this firmware family; LittleFS files
    can be extracted and inspected with off-the-shelf tools, a custom
    format can't.
  - Middle ground: stay on LittleFS but design a single packed CA
    journal file (e.g. `/lfs/ca.log` as an append-only record stream)
    plus a sparse index. Gets most of the density and lookup wins
    without throwing away the FS.
