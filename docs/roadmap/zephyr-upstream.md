# Phase 1 — upstream Zephyr

> **Status:** landed 2026-07-22 against Zephyr v4.3.1. **Pin advanced to
> v4.4.0 on 2026-07-25** as the de-risking prerequisite for Phase 3 (Bazel) —
> both conditions in [When to move the pin](#version-choice) were met (wolfCrypt
> is the crypto backend; `transport_usb.c` is on `usbd_*` and hardware-validated).
> The `v4.4.0` tag peels to commit `684c9e8f`, exactly what `zephyr-bazel` pins,
> so the CMake build proves the tree Bazel will build. Both tiers rebuilt with
> **zero source changes** (uf2_only 251,996 B; mcuboot merged.hex) and all ztest
> suites pass; v4.4 required Zephyr SDK **1.0.1** (up from 0.17.4 — SDK 1.0 moved
> per-arch toolchains under `gnu/`, so `setup_zephyr.sh` and `build.sh` were
> adjusted). The uf2_only tier was confirmed on hardware on v4.3.1 — see
> [Hardware validation](#hardware-validation--uf2_only-on-unit-1-2026-07-22).
>
> Phase order: **1 upstream Zephyr** → 2 wolfSSL → 3 Bazel → 4 multi-platform.
> (Phases 2 and 3 were swapped on 2026-07-22 — see
> [bazel-migration.md](bazel-migration.md).)

Drop the nRF Connect SDK and build against upstream Zephyr. The point is not
Zephyr features — it is removing sdk-nrf as a hard dependency, so that Phase 4
(ESP32, STM32, RISC-V) and Phase 2 (wolfCrypt driving the CC310 directly) are
not gated on a Nordic-only toolchain.

## Which Zephyr — and why not the LTS

The original plan said "latest LTS". Taken literally that is the wrong target:

| | Version | Released | Supported to | mbedTLS |
| --- | --- | --- | --- | --- |
| Was on (NCS v3.0.2) | `v4.0.99-ncs1-2` | — | — | NCS fork |
| Current upstream LTS | **v3.7.2** | Jul 2024 | ~2029 | 3.6 |
| **Picked** | **v4.3.1** | Nov 2025 | Nov 2026 | **3.6.6** |
| Latest stable | v4.4.1 | Apr 2026 | Apr 2027 | **4.1.0** |
| Next LTS | v4.6 | Apr 2027 | ~2032 | ? |

Two findings decided this:

**The current LTS is older than what NCS ships.** Zephyr's LTS cadence is
2.5–3 years; v3.7.0 (July 2024) is still the LTS line and v4.6 does not land
until April 2027. Moving to v3.7 would have meant giving up nine months of
upstream work relative to NCS's 4.0.99 base and then facing a much larger
3.7 → 4.6 jump later.

**v4.4 bumps mbedTLS to 4.1, which deletes the API this codebase is built
on.** Mbed TLS 4.x splits crypto into TF-PSA-Crypto and removes the legacy
`mbedtls_*` crypto C API in favour of PSA. Every Cantil crypto call site —
`src/crypto/crypto.c`, `src/session/noise_crypto_mbedtls.c`, `src/ca/ca.c` —
is written against that legacy API, and the FREE backend exists precisely to
avoid PSA (see [architecture.md](../reference/architecture.md)). Zephyr v4.3.1
is the newest release still on the Mbed TLS 3.6 LTS line.

Porting to PSA to reach v4.4 would be throwaway work twice over: Phase 3
replaces mbedTLS with wolfCrypt anyway, and the last attempt at a PSA port
failed on hardware (three stacked bugs in the ACCELERATED X25519 path).

**When to move the pin past v4.3.1:** when Phase 2 lands and wolfCrypt is the
crypto backend, the mbedTLS API question disappears and the pin should go
straight to whatever is current — ideally the v4.6 LTS once it exists. Until
then, v4.3.1 is maintained until roughly November 2026, which is the real
deadline on this decision.

## What was actually coupled to NCS

Less than expected. The application code is essentially portable; the coupling
was in the build system.

| Coupling | Resolution |
| --- | --- |
| `west.yml` imported `sdk-nrf` | Rewritten to import upstream `zephyr` with a `name-allowlist` of the 8 modules actually linked |
| **Partition Manager** (`pm_static_*.yml`, `CONFIG_PM_PARTITION_*`, `PM_STATIC_YML_FILE`) | Replaced by devicetree `fixed-partitions` in the board overlays. PM has no upstream equivalent |
| `nrf_security` / PSA ACCELERATED backend | Kconfig option now `depends on ZEPHYR_NRF_MODULE`, so it disappears on an upstream build. Sources retained |
| NCS toolchain bundle as compiler | Zephyr SDK 1.0.1 (`arm-zephyr-eabi`), installed by `scripts/setup_zephyr.sh` |
| Sysbuild on by default | Upstream needs explicit `--sysbuild`; `build.sh` passes it for the mcuboot tier |
| `merged.hex` emitted by PM | Merged by `build.sh` with `hexmerge.py`, which also fails loudly on overlapping records |
| Vestigial `noise-c` manifest pin | Deleted. Nothing referenced it — the Noise implementation is hand-rolled in `src/session/` |

### Things that changed shape

**Storage partition.** `storage.c` used `FIXED_PARTITION_ID(storage_partition)`
unconditionally; Partition Manager synthesised that label and redirected it to
QSPI when `CONFIG_PM_PARTITION_REGION_LITTLEFS_EXTERNAL` was set. Upstream the
two cases are different devicetree nodes, so the macro is now selected by
`CONFIG_CANTIL_STORAGE_EXTERNAL`: `cantil_storage` (QSPI) or
`storage_partition` (internal, from the board's own DTS).

**MCUboot secondary slot.** `fw_update.c` referred to `mcuboot_secondary`, a
Partition Manager name. It is now `slot1_partition`, the standard upstream
label. Same region.

**MCUboot signature type and swap mode.** These have to be set at *sysbuild*
level (`SB_CONFIG_BOOT_SIGNATURE_TYPE_ECDSA_P256`,
`SB_CONFIG_MCUBOOT_MODE_SWAP_USING_MOVE`), not in `sysbuild/mcuboot.conf`.
Upstream's `BOOTLOADER_image_default.cmake` force-sets every keytype and
bootmode symbol on the MCUboot image from its own `SB_CONFIG_*` values, so
image-level settings are silently overwritten. Getting this wrong builds
MCUboot with RSA-2048 and fails at link with `undefined reference to
'rsa_pub_key'`.

**Board flash layout.** `xiao_ble` pulls in `nrf52840_partition_uf2_sdv7.dtsi`,
which assumes SoftDevice S140 v7 is present. The factory UF2 bootloader on this
board has no SoftDevice, so those partitions describe a layout the device does
not have; the overlays now `/delete-node/` them rather than leave them
overlapping the real application region.

## USB device stack — ported to `usbd_*` (2026-07-24)

**Done, build-verified, hardware validation pending.** `transport_usb.c` was
rewritten against the `usbd_*` ("device_next") stack; the legacy
`usb_enable()` / `<zephyr/usb/usb_device.h>` path is gone. This was the single
largest follow-up from Phase 1 and, now that the Mbed TLS 4.x concern is moot
(wolfCrypt), was the last thing pinning the tree to v4.3.1.

What changed: `prj.conf` sets `CONFIG_USB_DEVICE_STACK_NEXT=y` +
`CONFIG_USBD_CDC_ACM_CLASS=y` + `CONFIG_HWINFO=y` and drops the legacy
`USB_DEVICE_VID/PID/MANUFACTURER/PRODUCT`; those, plus the two string
descriptors, now live in C in `transport_usb.c`. The device context is built
and enabled from `transport_usb_init()` (called from `main()`), so the enable
happens after every SYS_INIT — the SET_ADDRESS race the legacy port guarded by
calling `usb_enable()` by hand can no longer occur. Board `.conf` files shed
`CONFIG_USB_DEVICE_STACK=y` / `CONFIG_USB_CDC_ACM=y`.

Preserved by construction (verified against the pinned v4.3.1 tree):
- **iSerial = FICR serial.** `USBD_DESC_SERIAL_NUMBER_DEFINE` with
  `use_hwinfo = true` reads the same hwinfo device ID the legacy build's
  `__weak usb_update_sn_string_descriptor()` filled — same 16-hex format, so
  `scripts/capture_boot_log.sh` still matches a unit by its FICR serial.
- **Interface order protocol=IF0, console=IF2.** `usbd_register_all_classes`
  iterates class instances in devicetree-instance order (`board_cdc_acm_uart`
  = instance 0 before `cdc_acm_uart1` = instance 1), which the host's
  `discover_usb.c` `:1.0`/`:1.2` matching depends on. The built ELF carries
  exactly two CDC instances (`cdc_acm_desc_0`/`_1`).

**The one non-obvious gotcha — the board's automatic console device.** Because
the console is a CDC-ACM node, the board defconfig defaults
`CONFIG_CDC_ACM_SERIAL_INITIALIZE_AT_BOOT=y`, which pulls in
`subsys/usb/device_next/app/cdc_acm_serial.c`. That file builds its *own* usbd
context on `zephyr_udc0` (Zephyr VID `0x2fe3`), enables it at boot, and — per
its own comment — "only registers the first CDC-ACM instance." Left on, it
would seize the controller before `cantil_usbd`, enumerate as the wrong vendor,
and expose the console CDC with no protocol port. `prj.conf` sets it `=n`;
`transport_usb.c` owns the single context and registers both CDC instances. The
`nm` check confirms no `cdc_acm_serial` context is linked.

**Hardware validation still owed (cannot be done off-device):** enumeration as
`1209:00ca`, the dual-port order (`:1.0` protocol / `:1.2` console), a full
pair + session over the protocol port, and `capture_boot_log.sh` against a live
unit. On the nRF UDC (`can_detect_vbus = true`) enable happens on the
`USBD_MSG_VBUS_READY` message; if a unit ever fails to come up on the bus, that
callback path is the first place to look.

## Deliberately out of scope

**Factory image console.** `firmware/factory/` has its own crypto-free CDC
console (not `transport_usb.c`) and is a separate build; it was left on its
current path and is a small follow-up of its own.

**Non-xiao boards.** `nrf52840dk`, `nrf52840dongle`,
`adafruit_feather_nrf52840` and `generic_nrf52840` were not built or verified.
The three internal-storage boards should work unchanged, since they resolve
`storage_partition` from their own board DTS. `adafruit_feather_nrf52840` sets
`CONFIG_CANTIL_STORAGE_EXTERNAL=y` but declares no partition node, so it will
now fail at build time with an unresolved-node error — under Partition Manager
it silently got an invented default. That is the honest behaviour, but it does
mean the feather overlay needs a `cantil_storage` node before it builds again.
Tracked under M7 in [roadmap.md](../roadmap.md), which already lists "CI builds
for all supported board targets" as outstanding.

**`ACCELERATED` crypto backend.** Kept in tree, unselectable upstream. Phase 2
brings hardware acceleration back via wolfCrypt, which drives the CC310
directly and needs neither `nrf_security` nor the Nordic binary blobs — see
[wolfssl-migration.md](wolfssl-migration.md) and
[crypto-blobs.md](../crypto-blobs.md).

## Defects found but not fixed

Both predate this phase; neither is a regression.

**`CONFIG_CANTIL_FW_IMAGE_VERSION` does nothing on the mcuboot tier.** The
custom `imgtool sign` step in `firmware/CMakeLists.txt` is skipped when
`CONFIG_BOOTLOADER_MCUBOOT=y`, and Zephyr's own signing uses
`CONFIG_MCUBOOT_IMGTOOL_SIGN_VERSION`, which nothing sets. Verified: the built
image reports `Image version: 0.0.0+0` while `CANTIL_FW_IMAGE_VERSION` is
`"0.1.0"`. This matters for M8's firmware anti-rollback (MCUboot security
counter), which needs a real version.

**`scripts/test.sh` was already broken.** It referenced the removed
`ubuntu2604` distrobox and set up no `PATH`, so it could not have run since the
build went native. It now shares `build.sh`'s environment handling.

## Verification

```sh
scripts/setup_zephyr.sh                     # Zephyr SDK 1.0.1 + west workspace
scripts/build.sh                            # uf2_only  — 199,712 B / 972 KB (20.1%)
scripts/build.sh --bootloader mcuboot \
    --signing-key ~/.cantil/firmware-signing/fw_signing.key.pem
                                            # mcuboot   — 203,632 B / 486 KB (41.6%)
scripts/test.sh                             # 14 suites, all pass
```

Checked on the produced artifacts:

- `imgtool verify` against the production signing key: *Image was correctly validated*
- `merged.hex` segments — MCUboot `0x001000–0x0096AC` inside `boot_partition`
  (`0x1000`, 48 KB); application `0x00D000–0x03EC08` inside `slot0_partition`
  (`0xD000`, 486 KB). No overlap.
- uf2_only: `CONFIG_FLASH_LOAD_OFFSET=0x1000`, UF2 start address `0x1000` —
  matches what the factory bootloader expects.
- Generated devicetree carries `xiao_app_partition`, `cantil_storage` and the
  board's `boot_partition`, with the SoftDevice-era partitions gone.

### Hardware validation — uf2_only on unit #1 (2026-07-22)

The single largest risk in this phase was the partition migration: every
board's storage region was rewritten by hand from Partition Manager to
devicetree `fixed-partitions`, and the old `storage_init()` responded to a
misdeclared partition by **formatting it** — which on a provisioned unit
destroys the unexportable CA key. The two attached XIAOs were the first
hardware this firmware would ever have touched.

Validated by flashing unit #1 (`69A3031F0204C8EE`) with a
`CONFIG_CANTIL_STORAGE_NO_AUTOFORMAT=y` build.

> **That guard was ineffective at the time, and the safety margin claimed
> here originally did not exist.** It removed `storage_init()`'s explicit
> `fs_mkfs()` fallback, verified by checking that no application object
> referenced `fs_mkfs`. The check was accurate but measured the wrong layer:
> Zephyr's littlefs backend formats from *inside* `fs_mount()` when the mount
> point does not set `FS_MOUNT_FLAG_NO_FORMAT`. Unit #1 was never protected —
> it was safe only because its partition was correct, so the mount succeeded
> and no format path was reached. The result below stands; the reasoning that
> made it look pre-verified does not. Both layers are now closed, and the
> gap was found by [deliberately misdeclaring the partition on
> hardware](#destructive-testing-2026-07-22) rather than by more inspection.

Boot log from the console (`cdc_acm_uart1`):

```text
littlefs: FS at p25q16h@0:0x0 is 512 0x1000-byte blocks with 512 cycle
storage: LittleFS mounted at /lfs
ca: CA key slot present
session_slot: session slot present; identity matches build constant
gesture: loaded persisted unlock sequence (2 digits)
```

`p25q16h@0:0x0`, 512 × 4096 B = `0x200000` — byte-identical to the region the
NCS/Partition Manager build reported. It **mounted**; it did not format. The
CA key slot, session slot, and persisted gesture state all survived the move
off Partition Manager, which is the result that matters: the devicetree
`cantil_storage` node addresses exactly the same flash as `nordic,pm-ext-flash`
did, and existing provisioned data remains readable.

Also confirmed on hardware: USB CDC/ACM enumeration (both interfaces),
`crypto ready (mbedtls direct, P-256 + AES-256-GCM)`, and clean boot of the
upstream-Zephyr image on the factory UF2 bootloader.

**Still not verified:** the gesture state machine end-to-end, a live Noise_XX
session (blocked on host `libsodium-devel` / `mbedtls-devel` for the `cantil`
CLI), the mcuboot tier on hardware, and the full firmware-update flow.

## Destructive testing (2026-07-22)

With both units in DFU, the storage guard was tested the only way it can
meaningfully be tested: by pointing `cantil_storage` at a deliberately wrong
QSPI offset and flashing it to a provisioned device. The overlay used is
[`firmware/tests/hardware/wrong_partition.overlay`](../../firmware/tests/hardware/wrong_partition.overlay).

It found two defects that no amount of code reading had.

**Defect 1 — the guard did not stop the format.** Unit #2, built with
`CONFIG_CANTIL_STORAGE_NO_AUTOFORMAT=y` and `cantil_storage` moved to
`0x100000`:

```text
littlefs: FS at p25q16h@0:0x100000 is 256 0x1000-byte blocks
littlefs: Corrupted dir pair at {0x0, 0x1}
littlefs: can't mount (LFS -84); formatting
storage: LittleFS mounted at /lfs
```

Zephyr's littlefs backend formats from inside `fs_mount()` unless the mount
point sets `FS_MOUNT_FLAG_NO_FORMAT`. Compiling out `storage_init()`'s own
`fs_mkfs()` fallback does nothing about that, so the region was wiped by a
build specifically intended not to be able to wipe anything. Fixed by setting
the flag on `cantil_lfs_mount` under the same Kconfig symbol.

**Defect 2 — a wrong partition can mount, and then the device re-provisions
itself.** Retested on unit #1 with the flag fix in place and the offset moved
to `0x180000`:

```text
littlefs: FS at p25q16h@0:0x180000 is 128 0x1000-byte blocks
storage: LittleFS mounted at /lfs
ca: no CA key found — first boot provisioning required
ca: generating CA keypair on CC310 TRNG
fs: failed to create directory (-17)
```

No format this time — the flag held. But the mount *succeeded* on a region
that is part of the live filesystem, `ca_init()` read an empty CA slot,
concluded the device was factory-fresh, and began minting a replacement CA
over real data. This is the worse of the two failures: it needs no format at
all, so `CANTIL_STORAGE_NO_AUTOFORMAT` is structurally incapable of catching
it, and the device comes up looking healthy while the original key is still
sitting on the part, orphaned along with every certificate it ever issued.

Fixed by adding `CANTIL_NO_AUTO_PROVISION`, which makes `ca_init()` refuse
rather than provision when the slot reads empty. The two symbols are
complementary and bring-up builds should set both — one covers "mount
failed", the other covers "mounted the wrong thing".

> **Superseded 2026-07-23.** `CANTIL_NO_AUTO_PROVISION` is gone. `ca_init()`
> now refuses in *every* configuration, and minting a CA requires
> `CMD_PROVISION_CA` (0x34) — unlocked, authenticated, tap-confirmed. The
> symbol was removed rather than defaulted to `y`: a guard against
> unrecoverable key loss that a board `.conf` or a module `select` can switch
> off is not a guard. Bring-up builds now need only
> `CANTIL_STORAGE_NO_AUTOFORMAT`, and only if they turn `FILE_SYSTEM_MKFS`
> back on. See [two-step-provisioning.md](two-step-provisioning.md).

The general lesson, which is why this section exists: **an empty CA slot is
not evidence of a factory-fresh device**, and the default reaction to storage
that looks blank should not be to create irreplaceable key material.

### Outcome: both units survived

Both were reflashed with the correct partition and both guards set — an image
that can neither format nor provision — and both came up fully intact:

```text
littlefs: FS at p25q16h@0:0x0 is 512 0x1000-byte blocks
storage: LittleFS mounted at /lfs
ca: CA key slot present
session_slot: session slot present; identity matches build constant
```

Unit #1 additionally still had its persisted unlock sequence. Unit #2 logged
two benign `-2` (ENOENT) opens for optional files it never had.

**This was luck, not design.** Both volumes are nearly empty and littlefs
allocates from the low end, so the stray writes — unit #2's format of
`0x100000`–`0x200000`, unit #1's partial CA at `0x180000` — landed in blocks
that had never been allocated. On a device with more history, the same
mistakes would have destroyed live data.

### Why the wrong-offset mount succeeded

Worth recording, because it is the part that most justifies the volume
marker. Mounting at `0x180000` should have found nothing, yet it mounted, and
`mkdir` then returned `-EEXIST`, meaning a directory structure was visible.

The explanation most consistent with the evidence — **not proven** — is
littlefs's wear levelling. `block_cycles` is 512, and littlefs relocates
metadata pairs to distribute wear. littlefs's superblock *is* a metadata
pair, so a relocated root pair sitting high in the volume looks exactly like
a superblock to a mount that begins there. That accounts for all three
observations together: the mount succeeded, the directory structure was
present, and `fs: file open error (-14)` followed because the CTZ data
pointers referenced blocks outside the 128-block window the misdeclared
partition exposed.

If that is right, the consequence is sharper than "a stale filesystem might
be lying around": **a wrong-offset mount can pick up the live filesystem's own
relocated metadata and present as a valid, empty volume.** No stale data or
prior format is required — normal wear levelling on a healthy device is
enough. A marker recording the offset the volume was created for is the only
thing that distinguishes the two cases.

## Environment

The NCS install at `~/ncs/v3.0.2` is no longer used for building. The
toolchain bundle at `~/ncs/toolchains/7cbc0036f4` is still used, but only for
matched **host** tools (cmake, ninja, dtc, gperf, west, python) — nothing
Nordic-specific reaches the build. Replacing it with distro packages plus a
`pip install west` is possible and would remove the last NCS path; it was not
done here because the bundle works and swapping it is orthogonal to the phase.

One wrinkle: the bundle's `git` cannot resolve its own remote helpers when run
outside the NCS container (`git: 'remote-https' is not a git command`). Both
`setup_zephyr.sh` and `build.sh` shim the host's `/usr/bin/git` ahead of it.
