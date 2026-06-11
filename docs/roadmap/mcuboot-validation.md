# Roadmap: Configure MCUboot for image validation

**Shipped (2026-06-09, session 079).** Boot-time image validation implemented via `fw_update_boot_check()` in `firmware/src/fw_update/fw_update.c`, called from `main.c` on every boot.

**Shipped behavior:**

- **Boot-time validation:** MCUboot verifies the image signature against the public key built into the bootloader before swap (standard MCUboot `BOOT_SWAP_TYPE_TEST` flow). Signing key = separate MCUboot root at `~/.cantil/firmware-signing/fw_signing.key.pem` (not CA slot 0 double-duty).
- **Valid new image:** `boot_set_img_confirmed()` — swap permanent, normal boot continues.
- **MCUboot-rejected image:** `LED_PATTERN_FW_INVALID` (magenta↔red 500/500 loop, looped idle). Tap-confirm:
  - **Accept:** `CANTIL_FW_UPDATE_WIPE_ON_INVALID=y` → secure-wipe LittleFS partition via `flash_area_erase`, then `boot_set_pending(true)` → reboot with the new image anyway.
  - **Deny / timeout (`CANTIL_FW_INVALID_CONFIRM_TIMEOUT_SEC`, default 30 s):** erase secondary slot, stay on old primary.
- **Implemented LED patterns:** `LED_PATTERN_FW_INVALID` (looped idle — rejected image alarm), `LED_PATTERN_FW_APPLIED` (orange 1000 ms one-shot — pre-reboot after accepted update).
- **Flash layout:** dual internal slots 0xD000 (486 KB) and 0x86800 (486 KB). UF2 and QSPI secondary-slot options dropped with `uf2_mcuboot` tier removal.

**Remaining:**

- `LED_PATTERN_FW_VALIDATING` (during MCUboot verify if >150 ms — reuse `THINKING`) — not yet added.
- `LED_PATTERN_FW_WIPING` (during secure wipe — reuse `RESET_WIPING`) — not yet added.
- ztest suite `firmware/tests/fw_update/` — not yet written. Planned cases: (1) clean swap of valid image, (2) reject + tap-confirm → wipe path, (3) reject + tap-deny → discard path, (4) reject + timeout → discard path, (5) crash mid-wipe is idempotent on reboot.
- Hardware end-to-end test: push a signed image via `cantil fw-update`, confirm swap on real XIAO.
