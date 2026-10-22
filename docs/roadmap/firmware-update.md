# Roadmap: Authenticated firmware update over the Noise session

> **Half removed (2026-07-26).** The **wire protocol below survives** — the
> `UPDATE_FIRMWARE` (0x33) opcode, its CBOR BEGIN/CHUNK/COMMIT framing and the
> tap-confirm flow are Cantil's, not MCUboot's, and carry over to wolfBoot. The
> client still implements all of it (`cantil fw-update`). The **device half was
> deleted**, not deprecated: `firmware/src/fw_update/` and `protocol.c`'s
> streaming handler went with the mcuboot tier, so no firmware answers the
> streaming sub-operations today and the client gets
> `CANTIL_ERR_NOT_SUPPORTED`. On `uf2_only`, opcode 0x33 still means what it
> always meant there — reboot into the UF2 bootloader. See
> [wolfboot-migration.md](wolfboot-migration.md); the deleted implementation is
> `git show cd1fc3e:firmware/src/fw_update/fw_update.c`.

**Shipped (2026-06-09, session 079).** `UPDATE_FIRMWARE` opcode (0x33) — chunked streaming firmware update over the authenticated Noise session, `mcuboot` build tier only.

**Wire protocol** (inner CBOR map per request):

- `BEGIN`: `{0: 0, 1: total_size}` — allocates secondary slot, checks image fits
- `CHUNK`: `{0: 1, 1: offset, 2: <bstr chunk_data>}` — streams up to `CANTIL_FW_CHUNK_MAX` bytes per call
- `COMMIT`: `{0: 2}` — tap-confirm before `boot_request_upgrade` + reboot; deny = erase secondary slot + continue running

**Boot-time outcome** (`fw_update_boot_check()` called from `main.c`):

- Valid new image: MCUboot swaps, app auto-confirms, boots normally
- MCUboot-rejected image: `LED_PATTERN_FW_INVALID` (magenta↔red loop); tap-confirm → secure-wipe LittleFS then force-accept image; tap-deny/timeout → erase secondary, stay on old primary

**Kconfig surface:** `CANTIL_FW_CHUNK_MAX` (default 3968 B), `CANTIL_FW_INVALID_CONFIRM_TIMEOUT_SEC` (default 30 s), `CANTIL_FW_UPDATE_WIPE_ON_INVALID` (default y).

**New LED patterns:** `LED_PATTERN_FW_INVALID` (magenta↔red 500/500 loop — rejected image alarm), `LED_PATTERN_FW_APPLIED` (orange 1000 ms one-shot — pre-reboot after accepted update).

**Error codes:** `ERR_FW_UPDATE_BUSY` (12), `ERR_FW_UPDATE_FLASH` (13), `ERR_FW_UPDATE_ARGS` (14).

**Access control:** allowed while device is locked and in identity-recovery mode (cert-mismatch). `mcuboot` builds only — `protocol.c` guards behind `#if CONFIG_CANTIL_BOOTLOADER_MCUBOOT_ONLY`; other tiers send `ERR_NOT_SUPPORTED`.

**Host side:** `cantil_fw_update(session, path)` in `libcantil/src/device.c` — reads a signed `.bin`, sends BEGIN, streams CHUNK, sends COMMIT; 3968-byte default chunk size. CLI: `cantil fw-update <signed.bin> <port>`.

**Storage:** `/lfs/fw_pending` zero-byte sentinel written after `boot_request_upgrade`, cleared after successful boot or on error.

**Build size (mcuboot_only):** 214 KB / 486 KB slot (43%).

**Remaining:** `LED_PATTERN_FW_VALIDATING` / `LED_PATTERN_FW_WIPING` (for long-running wipes), ztest coverage for the `fw_update` module (`firmware/tests/fw_update/` not yet written), hardware end-to-end test on a real XIAO.
