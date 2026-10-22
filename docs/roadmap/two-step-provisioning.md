# Two-step provisioning

> **Status: complete, 2026-07-23.** Shipped: the volume identity marker, the
> step-1 factory image, `CONFIG_FILE_SYSTEM_MKFS=n` in production,
> `CMD_PROVISION_CA`, marker *enforcement* / degraded mode, the RAM-only
> identity, and — closing the last route — the `--wrap` on `lfs_format` that
> removes littlefs's own formatter from the production image.
>
> This supersedes the `CANTIL_STORAGE_NO_AUTOFORMAT` /
> `CANTIL_NO_AUTO_PROVISION` guards added in `aa99efe`, which were policy where
> this is structure. `CANTIL_NO_AUTO_PROVISION` has since been **removed**: the
> behaviour it made optional is now unconditional, and a guard against
> unrecoverable key loss that a board `.conf` can switch off is not a guard.
> `CANTIL_STORAGE_NO_AUTOFORMAT` remains, scoped to builds that keep MKFS on.

## Why

Two defects found by [destructive testing on hardware](zephyr-upstream.md#destructive-testing-2026-07-22):

1. A misdeclared partition caused a **format** of live flash, from inside
   `fs_mount()`, in a build specifically built to be incapable of it.
2. A misdeclared partition **mounted successfully** over live data, whereupon
   `ca_init()` read an empty slot 0, concluded the device was factory-fresh,
   and started minting a replacement root CA.

Both are the same underlying mistake: **production firmware treats "storage
looks blank" as an instruction to create irreplaceable key material.** For a
device whose CA private key has no backup and cannot be exported, that
reaction turns a wiring error into permanent, silent key loss.

The guards in `aa99efe` make the firmware *decline* to do this. The point of
this document is to make it *unable* to.

## What is actually shipped today

> **Updated 2026-07-23.** Production sets `CONFIG_FILE_SYSTEM_MKFS=n`, and
> links `-Wl,--wrap=lfs_format`. All three of `fs_mkfs`, `littlefs_mkfs` and
> `lfs_format` are gone from the image; a post-link check
> ([firmware/cmake/assert_no_mkfs.cmake](../../firmware/cmake/assert_no_mkfs.cmake))
> fails the build if any of them returns, or if the wrapper that replaced
> `lfs_format` goes missing.

`lfs_format` (200 B) and `littlefs_mkfs` (116 B) were linked into the
production image — about 316 bytes, pulled in by `CONFIG_FILE_SYSTEM_MKFS=y`,
which was not requested anywhere in `firmware/prj.conf`. It arrived implicitly.

Size is not the argument. 316 bytes of 199,512 is noise. The argument is
reachability: until `aa99efe` that code was reachable from an error path.

**Nothing in production needs it.** `storage_secure_wipe()` — the
`RESET_DEVICE` path — overwrites key blobs with `0xA5` and then `rm_rf`s the
directories. It never formats. Removing mkfs from the production image costs
no existing feature.

Nor does it cost diagnostics. littlefs has no `fsck` in the ext4 sense
because it doesn't need one: every metadata pair carries a CRC verified on
read, so corruption surfaces as `LFS_ERR_CORRUPT` (-84) at access time. A
whole-volume sweep is `lfs_fs_traverse` + `lfs_fs_size`, both already linked
and independent of `lfs_format`. A `storage_verify()` command is fully
buildable with mkfs gone; only *repair by destruction* leaves.

## The CA model this has to respect

Cantil manages **multiple CAs**, not one:

- Slot 0 (`CA_SLOT`) is the root. `ca_ready()` means slot 0 has a key *and* a
  certificate.
- Slots `1 .. CONFIG_CANTIL_MAX_KEY_SLOTS-1` hold further keys, including
  subordinate CAs. Any slot may act as an issuer via
  `ca_sign_csr_slot(issuer_slot, ...)`, and chains are stored per slot.

This makes the fix more natural than it first appears. **Slots 1..N-1 are
already created only by explicit command** (`GEN_KEY`, `GEN_KEY_CSR`,
`SIGN_KEY_SLOT`). Slot 0 is the sole exception that self-creates on boot.
Requiring an explicit command for slot 0 does not add a special case — it
removes one.

## The two steps

### Step 1 — factory image

> **Implemented 2026-07-23.** [firmware/factory/](../../firmware/factory/),
> built with `scripts/build.sh --factory` into `build_factory/`. 89,524 B
> against production's 201,500 B, and no crypto stack at all — the one mbedtls
> string in the ELF is a Kconfig symbol, not code.

A separate, minimal firmware, flashed once at the bench. It:

- creates the littlefs volume on `cantil_storage` (`fs_mkfs`), and
- writes the **volume identity marker** (below), then reads it back and
  verifies it. A device leaving the bench with a marker production will
  reject is worse than one with no marker, since the latter can still be
  adopted.

It does **not** generate a CA. Per the decision below, all CA creation is an
explicit command in Cantil firmware, for slot 0 exactly as for every other
slot.

It optionally installs MCUboot, so the device is ready for signed installs.

**Its refusal policy is the strictest in the codebase**, because it is the one
image that formats flash for a living. It proceeds on exactly one state:

| Probe result | Action |
| --- | --- |
| mount **fails** | format + marker — the only good evidence of a blank part |
| mount OK, `VALID` | refuse; already initialised, formatting discards live keys |
| mount OK, `UNMARKED` | refuse; **ambiguous** between fresh and provisioned-pre-marker |
| mount OK, `MISMATCH` | refuse; wrong partition or another die — formatting is the worst response |

The `UNMARKED` refusal is the one that matters most in practice: both
development units are in exactly that state, and formatting on that evidence
would destroy an unexportable CA key. `CONFIG_CANTIL_FACTORY_FORCE` overrides
the refusals for an operator who has decided the contents are expendable; it
is not needed for a genuinely new device.

The mount probe is read-only *only* because the mount sets
`FS_MOUNT_FLAG_NO_FORMAT`. Without it Zephyr's littlefs backend formats from
inside `fs_mount()`, erasing the volume before the policy above ever runs.

**Shared sources, deliberately.** The factory board overlay `#include`s the
production one rather than restating the `cantil_storage` node, and the
partition macros live in one header
([storage_partition.h](../../firmware/src/storage/storage_partition.h)) read
by both. If the two could drift, every device made in between would be born
with a marker its own production firmware rejects. Verified: both builds
resolve `cantil_storage` to `0x0 0x200000`.

To keep the image free of a crypto stack, two things were extracted:
[device_id.c](../../firmware/src/crypto/device_id.c) (the FICR accessor, which
had been copy-pasted into both crypto backends) and
[volume_marker.c](../../firmware/src/storage/volume_marker.c) (the marker
itself, previously inside storage.c). The factory app links those two files
and its own `main.c`, nothing else of Cantil's.

Note there is nothing to do about encryption. Cantil's littlefs is **not an
encrypted volume** — the filesystem is plaintext and individual secrets are
AEAD-encrypted per blob (AES-256-GCM) under a key derived from FICR DEVICEID.
That key is intrinsic to the silicon, so it needs no provisioning step.

### Step 2 — Cantil firmware

> **Implemented 2026-07-23.** `CONFIG_FILE_SYSTEM_MKFS=n` in
> [firmware/prj.conf](../../firmware/prj.conf). Production is 200,920 B, 580 B
> smaller. Marker *enforcement* landed the same day — see the marker section.

Built with `CONFIG_FILE_SYSTEM_MKFS=n`, so no bug, no error path, and no
compromised command handler can ask the filesystem layer to format the volume.
On boot it mounts, verifies the marker, and refuses to proceed if the marker is
absent or does not match.

Deployed by DFU or, once MCUboot is installed, by signed update.

#### Correction: `MKFS=n` does not remove `lfs_format`

This document previously asserted that `CONFIG_FILE_SYSTEM_MKFS=n` leaves
`lfs_format` out of the image. **That is wrong, and it was checked against the
linked ELF rather than assumed a second time.** What each symbol actually does:

| Symbol | Gated by `FILE_SYSTEM_MKFS`? | In production today |
| --- | --- | --- |
| `fs_mkfs` | yes ([`fs.c:785`](https://github.com/zephyrproject-rtos/zephyr/blob/v4.3.1/subsys/fs/fs.c#L785)) | **absent** |
| `littlefs_mkfs` | yes ([`littlefs_fs.c:998`](https://github.com/zephyrproject-rtos/zephyr/blob/v4.3.1/subsys/fs/littlefs_fs.c#L998)) | **absent** |
| `lfs_format` | **no** | **absent** — wrapped out, see below |

`littlefs_mount()` calls `lfs_format()` from a branch that is compiled
unconditionally and guarded only at *runtime*, by `FS_MOUNT_FLAG_NO_FORMAT` on
the mount point ([`littlefs_fs.c:960`](https://github.com/zephyrproject-rtos/zephyr/blob/v4.3.1/subsys/fs/littlefs_fs.c#L960)).
This is the same code path that wiped unit #2, so its residual presence is not
a technicality.

The honest statement of what `MKFS=n` alone achieved is therefore: **nothing
in the image can ask the filesystem layer to format, but littlefs's own
formatter is still there, one runtime flag away.** `storage.c` derives a single
`CANTIL_STORAGE_MAY_FORMAT` macro from `CONFIG_FILE_SYSTEM_MKFS` and uses it
for both the mount flag and the `fs_mkfs()` fallback, precisely so the two
layers cannot be closed independently again.

#### Closing it: `-Wl,--wrap=lfs_format`

> **Implemented 2026-07-23.**
> [firmware/src/storage/no_format.c](../../firmware/src/storage/no_format.c)
> plus two lines in [firmware/CMakeLists.txt](../../firmware/CMakeLists.txt).
> Production is 203,720 B, 4 B smaller: the real formatter's 200 bytes leave,
> a 72-byte refusing wrapper arrives.

The production link passes `-Wl,--wrap=lfs_format`, so `littlefs_mount()`'s
call resolves to `__wrap_lfs_format()`, which logs and returns
`LFS_ERR_INVAL` without touching flash. Nothing then references
`__real_lfs_format`, so `--gc-sections` drops the original. Verified against
the linked ELF:

```console
$ arm-zephyr-eabi-nm --print-size build/zephyr/zephyr.elf | grep -i 'lfs_format\|mkfs'
000087f0 00000048 T __wrap_lfs_format
```

The `-EINVAL` this produces lands in `storage_init()`'s existing "configuration
error, not a filesystem error" branch, which is the correct diagnosis: the only
way to reach the wrapper is a mount point that failed to set
`FS_MOUNT_FLAG_NO_FORMAT`.

**Why a link-time wrap rather than a patched Zephyr.** A Kconfig gate on that
branch upstream is the right end state and is worth proposing. But the west
workspace lives outside this repository, so a patch applied there would be
reverted by the next `west update` with nothing in the build log — restoring
the erase path invisibly, which is the precise failure mode this whole arc
exists to prevent. The wrap lives in the repo, travels with it, and its absence
is a build error.

**What still cannot be proven.** That a future Zephyr formats via some other
symbol. The wrap covers `lfs_format` by name. What changed is the class of
guarantee: from "a runtime flag is set correctly" to "the code is not in the
image", which is a property [assert_no_mkfs.cmake](../../firmware/cmake/assert_no_mkfs.cmake)
can check on every build — and it now also requires `__wrap_lfs_format` to be
present, because a `--wrap` flag that silently stopped applying produces an ELF
with no `lfs_format` in it either.

Builds that legitimately format take neither the wrap nor the assertion: the
step-1 factory image and the ztest suites set `CONFIG_FILE_SYSTEM_MKFS=y`, and
both guards hang off the same `NOT CONFIG_FILE_SYSTEM_MKFS` predicate. The
factory ELF still carries all three symbols, as it must.

## Volume identity marker

> **Implemented 2026-07-23.** `struct storage_volume_marker` in
> [storage.h](../../firmware/src/storage/storage.h), verification in
> [storage.c](../../firmware/src/storage/storage.c), 21 tests in
> [firmware/tests/volume_marker/](../../firmware/tests/volume_marker/).
> Enforcement landed on 2026-07-23 (see Decisions): `storage_volume_trusted()`
> gates the dispatcher and the wipe, `storage_volume_may_mint()` gates
> `ca_provision()` and `ca_gen_key()`. Between 07-22 and 07-23 an invalid
> volume was detected, logged, and then used exactly as if it had verified.

Written when the volume is created, verified on every boot. 28 bytes at
`/lfs/volume.bin`:

| Field | Purpose |
| --- | --- |
| magic | this is a Cantil volume |
| layout version | migration control; a *newer* version is refused, not guessed at |
| partition offset | **the field that catches defect 2** |
| partition size | ditto |
| FICR DEVICEID | volume belongs to *this* die, not a cloned image |
| crc32 | catches a torn write, not forgery — see below |

Three states, and the distinction between the latter two is the whole point:

- `STORAGE_VOLUME_VALID` — marker present, every field agrees.
- `STORAGE_VOLUME_UNMARKED` — no marker. **Ambiguous by construction**: a
  volume predating markers and a partition pointing somewhere wrong both
  simply lack the file, and nothing on the volume can separate them. This is
  why adoption is an explicit, opt-in build (`CANTIL_VOLUME_MARKER_ADOPT`)
  rather than something the firmware does when it looks reasonable.
- `STORAGE_VOLUME_MISMATCH` — marker present and disagrees. Never ambiguous,
  never benign.

The marker is **plaintext with a CRC, not authenticated**. It is a safety
interlock against misconfiguration, not a security boundary: an attacker who
can write flash has already won, and the secrets are individually AEAD-encrypted
under a key derived from the FICR ID the marker merely records. A cloned image
is still detected, because the clone's recorded ID will not match the new die.

### Both development units adopted, 2026-07-23

Both are pre-marker devices — the exact `UNMARKED` case the opt-in build
exists for — and both are now `VALID`, still on the normal build:

| | unit #1 `69A3031F0204C8EE` | unit #2 `80CBF7E00C42DBE4` |
| --- | --- | --- |
| CA | provisioned | provisioned |
| Key slots | 3 / 8 | 1 / 8 |
| Certs stored | 3 | 0 |
| Flash free | 1892 KB | 1988 KB |
| Noise static key | `1b558a8788a33897` | `6325e1df050df8be` |

Device keys, slot counts and free space are identical before and after
adoption on both units: the marker is a 28-byte inline file and costs no
block.

**What was verified before writing anything**, since the Kconfig help asks
for evidence that the volume is the right one and *"a mounted filesystem is
not sufficient"*:

- **The partition.** Both report ~2 MB free against a 2048 KB volume. The
  misdeclared partition from the destructive test is `0x180000 0x80000` — 128
  blocks, 512 KB — which cannot report those figures at all. Unit #2 was
  confirmed a second, independent way, from its boot log:
  `littlefs: FS at p25q16h@0:0x0 is 512 0x1000-byte blocks`.
- **The contents.** `CA: provisioned` on both, i.e. slot 0 reads back. Unit
  #1's 3 slots / 3 certs are its real history.

Both were flashed over the wire (`cantil update-firmware`, authenticated
Noise session, no tap on the uf2 tier) rather than by hand at the bootloader,
so the adopt build was on each device for exactly one boot.

The adopt build is **not** a weakened build: it carries `MKFS=n` and the
`lfs_format` wrap like production. Its only additional power is writing the
marker file onto an already-mounted volume.

> **Ordering note.** Adoption is a boot-time action in `storage_init()`, so it
> needs no session, no unlock and no tap. That makes it *easy to do before
> verifying*, which is exactly backwards. Verify first; the marker is never
> overwritten (`-EEXIST`) and a wrong one puts the device into a degraded mode
> from which `RESET_DEVICE` is refused by design.

#### Reading an unpaired device

Unit #2 had no bond for this host, and pairing needs a physical tap-confirm,
so nothing could be asked of it over the wire. Its console — the *second* CDC
interface, `ID_USB_INTERFACE_NUM=02` — needs neither.
[scripts/capture_boot_log.sh](../../scripts/capture_boot_log.sh) resolves that
port by FICR serial and reads it.

Worth knowing, because it is not obvious: **Zephyr buffers the whole boot log
until that port is first opened**, so a device that booted twenty minutes ago
still yields its startup sequence. The buffer drains on read — the second
capture returns nothing until the device boots again.

Two properties worth stating because they are easy to break later:

- **It is never overwritten.** `storage_volume_marker_write()` returns
  `-EEXIST` if one exists. A marker that can be rewritten to agree with
  whatever partition happens to be mounted asserts nothing at all.
- **It survives `storage_secure_wipe()`.** The keys are destroyed; the claim
  "this volume belongs to this die at this offset" remains true and remains
  useful. Dropping it would leave a wiped device indistinguishable from one
  with a misdeclared partition — the exact confusion the marker exists to end.

At 28 bytes it also stays under the littlefs inline threshold, so it inherits
the metadata pair's 2x redundancy like the key blobs do. A marker lost to one
bad block would strand an otherwise healthy volume, so a test asserts this.

The offset/size fields are the point. A filesystem at the wrong offset mounts
perfectly well and looks merely empty; a marker that disagrees with
`FIXED_PARTITION_OFFSET(cantil_storage)` is unambiguous, and turns tonight's
silent re-provisioning into a named error.

This is a stronger requirement than "guard against stale filesystems". The
[most likely explanation](zephyr-upstream.md#why-the-wrong-offset-mount-succeeded)
for the observed mount at `0x180000` is that littlefs's wear levelling had
relocated a root metadata pair — which *is* a superblock — high into the
volume. If so, no stale data and no prior format are needed to reproduce
this: normal wear levelling on a perfectly healthy device is sufficient for a
misdeclared partition to mount and look factory-fresh.

## Decisions

Taken 2026-07-22.

**CA provisioning lives in Cantil firmware, behind an explicit command.** Not
in the factory image. A new opcode (`CMD_PROVISION_CA`, next free is `0x34`)
provisions slot 0, authenticated over the Noise session and tap-confirmed
like other destructive operations. This keeps the gesture/LED confirmation
UX, allows re-provisioning in the field after a deliberate wipe, and makes
slot 0 behave like slots 1..N-1. `ca_init()` never provisions.

> **Landed 2026-07-23.** `ca_init()` no longer provisions under any
> configuration; an empty slot 0 is a normal, non-error state that it reports
> and leaves alone. `CMD_PROVISION_CA` (0x34) requires an unlocked device, an
> authenticated session and a tap, and is refused in identity-recovery mode.
>
> Two things the design did not spell out, both consequences of moving
> `ca_provision()` from a boot path to the wire:
>
> - **It must refuse to overwrite.** As a boot path it was only ever called on
>   a slot that had just been found empty, so it needed no check of its own.
>   Reachable from a client, it is the last line before unrecoverable key loss.
>   It now returns `-EEXIST`, checked independently of the dispatcher's check
>   (`test_07_provision_never_overwrites_an_existing_key` asserts the key blob
>   is byte-identical afterwards, not merely that the call failed).
> - **Clients need to see the state.** With no CA minted at boot, "does this
>   device have one?" became a routine question. `DEVICE_STATUS` grew a
>   `ca_provisioned` byte at offset 26, and the master-CA opcodes (0x01–0x06)
>   return `ERR_NOT_PROVISIONED` instead of a generic storage error. The client
>   parses the new byte only when the response is long enough, so it still
>   works against firmware that predates the field.
>
> `cantil provision-ca` now performs both device steps — generate the key if
> slot 0 is empty, then push the X.509 subject data — so the user-facing
> workflow is unchanged from before the split.

**A device that cannot validate its volume refuses CA operations but keeps
the transport and `UPDATE_FIRMWARE` alive.** It is recoverable in the field
rather than requiring a bench reflash, consistent with the existing recovery
allowlist, where a wipe always recovers. It is not a hard brick.

**The marker is in scope**, not deferred — it is the only thing that closes
defect 2 properly. Refusing to auto-provision prevents the catastrophe but
cannot distinguish "wrong partition" from "genuinely blank"; the marker can.

> **Landed 2026-07-23.** Two gates in `storage.h`, both derived from the
> marker state cached at mount:
>
> - `storage_volume_trusted()` — false only for `MISMATCH`. The dispatcher then
>   refuses every opcode but `DEVICE_STATUS` and `UPDATE_FIRMWARE`, and
>   `storage_secure_wipe()` refuses outright.
> - `storage_volume_may_mint()` — additionally false for `UNMARKED`-and-empty.
>   `ca_provision()` and `ca_gen_key()` return `-EPERM`; the wire sees
>   `ERR_VOLUME_INVALID` (17).
>
> Three points the design had not settled:
>
> - **`UNMARKED` had to be split by what the volume holds.** Refusing all
>   minting on `UNMARKED` would have stranded every device provisioned before
>   markers existed — including both dev units. Refusing none of it would have
>   left the hole wide open. The split is on slot 0: an `UNMARKED` volume that
>   already holds a CA key cannot be the misdeclared case (which presents
>   empty), and nothing destructive is reachable from it anyway. Slot 0 is the
>   right signal rather than the session slot precisely because nothing creates
>   it implicitly — `session_slot_init()` still mints on first boot, so a
>   misdeclared volume grows a session identity by itself and would unlock a
>   gate keyed on that.
> - **`RESET_DEVICE` is refused in degraded mode**, which breaks the "a wipe
>   always recovers" rule the recovery allowlist follows. Erasing a volume the
>   device cannot identify destroys something unidentified and leaves the real
>   keys untouched at the offset this build is not looking at. A wipe that does
>   not wipe what the operator believes it wipes is worse than a refusal. The
>   guard lives inside `storage_secure_wipe()` so a third caller cannot miss it.
> - **The state has to be visible.** `ERR_VOLUME_INVALID` alone does not tell an
>   operator what to do — `MISMATCH` means "fix the partition", `UNMARKED` means
>   "this may be a pre-marker device, adopt it deliberately". `DEVICE_STATUS`
>   grew a volume-state byte at offset 27, which is why it stays reachable in
>   degraded mode.
>
> **Identity, 2026-07-23 (same day).** `session_slot_init()` no longer mints a
> persistent identity on a volume it cannot verify, and neither does
> `client_bond_add()` persist a bond there. Both mint into RAM / accept for the
> session instead.
>
> The framing "not key loss" in the first draft of this section was too
> generous. A misdeclared partition is typically a **subset** of the correct
> one — the hardware recipe points a build at `0x180000 + 0x80000` inside a real
> volume of `0x0 + 0x200000` — so any block the wrong mount allocates lands
> inside the live filesystem's extent. Writing an identity there is not merely
> untidy; it can corrupt the real volume, including the CA key's metadata pair.
>
> Refusing to have an identity was the alternative and is worse: no Noise static
> key means no handshake and no wire, and on the mcuboot tier
> (`CONFIG_MCUBOOT_SERIAL=n`, no UF2) no recovery short of SWD. A RAM-only
> identity keeps the two opcodes degraded mode deliberately leaves open.
>
> It is **not** derived from the FICR device ID, which would survive reboots and
> spare a re-pair. That ID is the USB iSerial; an identity anyone who has seen
> the device could reproduce is a false one. Unpinnable is the honest state for
> a device that cannot reach its own key.
>
> Checked before choosing this, not after: the host key store is keyed by the
> device's Noise static key, so a degraded device looks like a stranger and
> **cannot overwrite the real device's pinned entry**. Tiers 2-4 refuse it, and
> `--trust none` plus a fresh `cantil pair` is the documented recovery path
> (see [protocol-and-client.md](../reference/protocol-and-client.md)). Note
> that this was already the situation before the change — the old code minted a
> *persistent* new identity on the wrong volume, which no pinned client would
> accept either. The change costs no reachability; it only stops the writes.
>
> Still open: `storage_fw_pending_set()` writes a small sentinel to the volume
> on the UPDATE_FIRMWARE path. Left alone deliberately — it is on the one route
> out of degraded mode, and the image itself goes to internal flash.

## A third key-loss route, found while building the marker

Not caused by the marker work — surfaced by it. `storage_init()` special-cased
only `-ENODEV` and treated **every** other `fs_mount()` failure as evidence
that the filesystem needed formatting. But `fs_mount()` returns `-EBUSY` when
the volume is *already mounted*, and neither `fs_mkfs()` nor Zephyr's
`littlefs_mkfs()` refuses to format a mounted volume — both go straight to
`lfs_format`.

So on a default build, calling `storage_init()` twice would have erased a live
volume and the CA key with it. Same shape as the two defects found on
hardware: **an error meaning "your call was wrong" was being read as "the flash
is wrong."** `-EINVAL`, `-ENOTSUP` and `-ENOENT` had the same problem — all
configuration or programming errors, none fixed by erasing user data.

Fixed by handling `-EBUSY` as an idempotent no-op and refusing to format on
any error that is not a filesystem-integrity error. Covered by
`test_16_storage_init_is_idempotent`.

The general lesson is worth keeping in view for the rest of this work: the
recurring bug in this codebase is not "formats when it shouldn't" but
**treating an ambiguous signal as licence to destroy data**. Every remaining
step below should be read with that in mind.

## Consequences to work through

- **Transport identity on a fresh volume.** An authenticated session needs
  the Noise static keypair, so `CMD_PROVISION_CA` cannot be the very first
  thing that ever runs. Proposal: the marker gates it — with a *valid* marker
  the volume is provably ours and freshly made, so auto-creating the
  transport keypair there is safe; the CA, being higher-stakes and
  externally-trusted, still requires the explicit command. Without a valid
  marker, nothing is auto-created.
- **`session_slot_init()`** also mints identity material at boot and needs
  the same treatment.
- **Recovery when the volume is genuinely gone** now means reflashing the
  factory image — a deliberate physical act. That is the intended trade-off
  and should be documented for users, not just developers.
- **`main.c` still documents the 23-second first-boot format**; that comment
  and the USB-ordering constraint it justifies move to the factory image.
- **Replica placement.** [storage-resilience.md](storage-resilience.md)
  proposes a small raw vault outside the littlefs partition holding redundant
  copies of the key blobs. If that lands, the factory image is what carves
  and initialises it, and the marker is where its offsets are recorded —
  worth settling before the partition layout is frozen, to avoid a second
  flash-layout migration.
- **ztest suites** set `CONFIG_FILE_SYSTEM_MKFS=y` and format their own
  volumes. They should keep doing so — they are not the production image —
  but they consequently do not exercise the no-mkfs path. *Addressed
  2026-07-23* by the post-link check rather than by a test: the suites cannot
  cover a configuration they do not build, so the guarantee is asserted
  against the production ELF instead.
- **Gate `littlefs_mount()`'s format branch.** The one route this work did not
  close (see the correction above). Wants a Kconfig gate upstream in Zephyr;
  a local patch is the fallback. Until then `FS_MOUNT_FLAG_NO_FORMAT` is a
  runtime guard where the rest of this design has compile-time absence.
