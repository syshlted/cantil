# Roadmap: wolfBoot replaces MCUboot

**Decided 2026-07-25. MCUboot deprecated 2026-07-26, dropped the same day.**

MCUboot *was* the project's secure-boot tier
([bootloader-tiers.md](bootloader-tiers.md), [mcuboot-validation.md](mcuboot-validation.md),
[firmware-update.md](firmware-update.md)). It is being replaced by
[wolfBoot](https://github.com/wolfSSL/wolfBoot).

> **The tier is gone from the tree as of 2026-07-26** — see
> [What was removed](#what-was-removed-2026-07-26). It went from deprecated to
> deleted within a day, on the reasoning that a frozen tier nobody may build,
> validate, or port is not a safety net: it is a second flash layout, a second
> signing pipeline and a `--sysbuild` code path that every future change has to
> keep compiling for no return. `uf2_only` is the only tier until wolfBoot
> lands, and that is an accepted, temporary regression in the security story.

## Why

- **One crypto library, not two.** The firmware is wolfCrypt-only since Phase 2
  ([wolfssl-migration.md](wolfssl-migration.md)). MCUboot brings its own crypto
  (its own mbedTLS/tinycrypt build) into the bootloader, so a device running the
  MCUboot tier ships two independent implementations of the same primitives.
  wolfBoot verifies with wolfCrypt — the library already audited, already
  pinned, already GPLv3-compatible.
- **Licensing lines up.** wolfBoot is GPLv3, matching Cantil's relicense to
  GPL-3.0-or-later on 2026-07-22 (done partly to allow wolfSSL ≥ 5.8.2).
- **Standalone nRF52840 support**, with Ed25519 signing — no sysbuild multi-image
  machinery, no Partition Manager, no `merged.hex` merge step.
- **It removed the last *hard* west/CMake dependency.** The MCUboot tier was the
  only build path needing `west build --sysbuild`; dropping it (2026-07-26) left
  west alive for two soft reasons only — the A/B reference build and non-XIAO
  boards. See [bazel-migration.md](bazel-migration.md).

## What was removed (2026-07-26)

Deleted outright:

| Gone | Was |
| --- | --- |
| `firmware/sysbuild/mcuboot.{conf,overlay}` | the MCUboot child image |
| `firmware/boards/xiao_ble_nrf52840_sense_mcuboot.{conf,overlay}` | the tier's app config + BOOT/slot0/slot1 flash layout |
| `firmware/src/fw_update/{fw_update.c,fw_update.h}` | secondary-slot streaming: `boot_request_upgrade`, `flash_area_*` against `slot1_partition` |
| `protocol.c`'s BEGIN/CHUNK/COMMIT handler | the device half of image streaming |
| `CANTIL_BOOTLOADER_MCUBOOT` + six `CANTIL_FW_*` Kconfig symbols | tier selection, imgtool signing inputs, slot mechanics |
| the `mcuboot` project in `firmware/west.yml` | the module itself |
| `--bootloader` / `--signing-key` in `scripts/build.sh`, and the `merged.hex` step | the `--sysbuild` multi-image path |
| the imgtool signing block in `firmware/CMakeLists.txt`, and `imgtool` from `requirements.txt` | the P-256 signing pipeline |

Thrown away with it: the **P-256 firmware signing pipeline** and the
CA-signs-the-firmware-key arrangement. wolfBoot verifies against a raw
**Ed25519** public key compiled into the bootloader (decided 2026-07-25: smaller
and faster to verify, and it is wolfBoot's default). A new key has to be
generated; the old one does not carry over. `scripts/provision_fw_signing_cert.sh`
is left in the tree but now provisions a key nothing consumes.

Kept deliberately, because wolfBoot needs it:

- **`UPDATE_FIRMWARE` (0x33) and the `ERR_FW_UPDATE_*` codes.** The opcode still
  works on `uf2_only` — it always meant "reboot into the UF2 bootloader" there,
  and still does. What went away is the streaming half. The error numbers stay
  reserved; a deployed client still maps them.
- **The whole client side** — `libcantil`'s `cantil_stream_firmware_image()` and
  `cantil fw-update`. No device implements the device half, so it returns
  `CANTIL_ERR_NOT_SUPPORTED` today. Re-deriving the wire format later from a
  deleted implementation would be strictly worse than keeping it.
- **`storage_fw_pending_*`** (the `/lfs/fw_pending` sentinel) and
  `LED_PATTERN_FW_INVALID` / `LED_PATTERN_FW_APPLIED`. Bootloader-neutral,
  currently without callers.

Non-XIAO board `.conf` files keep `CONFIG_BOOTLOADER_MCUBOOT=y`. That is not
Cantil's tier — it is a statement that *those boards'* stock bootloaders
chain-load the image, and the symbol is defined in Zephyr's own
`modules/Kconfig.mcuboot` (sourced unconditionally), so it needs no mcuboot
module in the manifest. Those board builds are build-only and were not
re-verified.

Still deferred to the wolfBoot tier, unchanged: `LED_PATTERN_FW_VALIDATING` /
`LED_PATTERN_FW_WIPING`, the `firmware/tests/fw_update/` ztest suite, and the
hardware end-to-end update test.

## Integration model

**Standalone, not the Zephyr integration.** wolfBoot's headline Zephyr support
(2.8.0+) is for ARMv8-M TrustZone — a TF-M replacement via PSA — which does not
apply to the Cortex-M4 nRF52840. Use the standalone build:
`make TARGET=nrf52840 SIGN=ED25519`, `hal/nrf52.c`, BOOT/UPDATE/SWAP partitions
in `include/target.h`, and the app signed with `tools/keytools/sign --ed25519`.
wolfBoot builds independently of Zephyr, which also makes it *simpler* to bring
to Bazel than MCUboot was — a genrule around its Makefile rather than
`zephyr_sysbuild`. wolfBoot 2.9.0 is current (2026-07-02).

## Ordering

After the Bazel app-port, **CMake-first, then Bazel** — the same de-risking
argument as every prior phase: bring the bootloader up under the build system
that is known to work, so a failure has one candidate cause rather than two.
This is the new Phase 4.

## Change surface

- A new `firmware/src/fw_update/` written against libwolfboot
  (`wolfBoot_update_trigger()`, `wolfBoot_success()`, write to the UPDATE
  partition). The MCUboot version was deleted rather than ported — read it back
  out of git (`git show cd1fc3e:firmware/src/fw_update/fw_update.c`) for the
  chunk-writer and tap-confirm flow, which are worth reusing. **The trickiest
  part:** libwolfboot needs a flash HAL bound to Zephyr's flash_map / flash
  driver.
- App ROM offset changes (wolfBoot's header size vs MCUboot's 0x200).
- DTS partitions: a BOOT/UPDATE/SWAP layout on the 1 MB internal flash.
- ~~Removed: `firmware/sysbuild/mcuboot.*`, `boards/*_mcuboot.*`, the mcuboot
  entry in `firmware/west.yml`, the `CONFIG_BOOTLOADER_MCUBOOT` signing in
  `firmware/CMakeLists.txt`, imgtool.~~ **Done 2026-07-26** — see
  [What was removed](#what-was-removed-2026-07-26).
- wolfBoot added as a pinned dependency.

## Open questions

- **Update transport.** wolfBoot expects the application to stage the image and
  set the update-partition trailer. Confirm the `UPDATE_FIRMWARE` chunk-writer
  maps cleanly onto that, since it is currently written against MCUboot's
  `flash_area` + `boot_request_upgrade` API.
- **Anti-rollback.** MCUboot's security counter has a wolfBoot equivalent
  (version-based rollback protection). Whether it is enabled from day one is
  open — see [../roadmap.md](../roadmap.md).
- **Break-glass recovery** on a device with no UF2 bootloader and APPROTECT set.
  Unchanged in substance from the MCUboot tier, but it has to be re-answered
  for wolfBoot's recovery story.
