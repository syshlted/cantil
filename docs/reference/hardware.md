# Reference: Hardware

> Relocated verbatim from CLAUDE.md (token-cost trim). Authoritative hardware reference.

## Reference Target: Seeed XIAO BLE Sense

| Component | Details |
| --- | --- |
| MCU | Nordic nRF52840 (ARM Cortex-M4F, 64MHz) |
| Internal flash | 1MB |
| External flash | 2MB QSPI (P25Q16H or compatible) |
| IMU | ST LSM6DS3TR-C (accel + gyro) — **dead on all tested units, abandoned** (see [[project-tap-imu-debug]]) |
| Microphone | PDM digital mic — tap gesture input via onset detection |
| Crypto engine | CryptoCell-310 (ECC P-256/384/521, AES, SHA-2, TRNG) |
| USB | USB 2.0 Full Speed, CDC/ACM class |
| LED | RGB LED on GPIO |

## Flash Budget (full feature set, BLE + USB)

| Component | Flash |
| --- | --- |
| MCUboot | ~32KB |
| Zephyr kernel | ~35–50KB |
| USB CDC/ACM | ~15–20KB |
| BLE stack + NUS + SMP | ~70–90KB |
| LittleFS code | ~10–15KB |
| PSA Crypto + Oberon + CC310 HAL | ~50–80KB |
| mbedtls (X25519 + ChaChaPoly + SHA-256) | ~8–12KB |
| zcbor | ~4–6KB |
| Application (all features) | ~50–80KB |
| **Total firmware** | **~275–387KB** |

**560–675KB remains free** for a LittleFS data partition on internal flash alone. The 2MB QSPI is preferred for cert storage (better wear leveling, larger capacity), but not required. A personal CA signing occasional certs fits comfortably on 1MB internal flash only.

## Generic nRF52840 Support

The firmware targets any nRF52840 board via Kconfig feature flags and per-board devicetree overlays:

```kconfig
CONFIG_CANTIL_INPUT_MIC=y        # PDM microphone onset detection (XIAO BLE Sense)
CONFIG_CANTIL_INPUT_BUTTON=y     # GPIO button tap detection (any board)
CONFIG_CANTIL_STORAGE_EXTERNAL=y # QSPI LittleFS (boards with external flash)
CONFIG_CANTIL_STORAGE_INTERNAL=y # Internal NVS/LittleFS fallback
CONFIG_CANTIL_TRANSPORT_USB=y
CONFIG_CANTIL_TRANSPORT_BLE=y
```

Provided board overlays: `xiao_ble`, `nrf52840dk/nrf52840`, `nrf52840dongle/nrf52840`, `adafruit_feather_nrf52840`, `generic_nrf52840` (USB + GPIO button + single LED, no external flash).

**GPIO button tap detection:** Software single/double-tap timing from GPIO interrupt. Debounce window: 20ms. Double-tap window: 300ms (matches IMU hardware timing so sequences feel identical). Defined in `boards/<board>/<board>.overlay` via the `cantil,tap-button` devicetree binding.

**Key MCU features used:**

- CryptoCell-310 TRNG for key generation and entropy export
- CryptoCell-310 for ECC signing (key material stays in CC310 registers in locked mode)
- FICR device UID → storage encryption key derivation
- APPROTECT disables SWD in production builds

## Flash Layout

```text
Internal 1MB flash:
  [0x00000000] MCUboot bootloader        ~32KB
  [0x00008000] Application image         ~950KB
  [0x000F8000] NVS / Zephyr settings     ~32KB

External 2MB QSPI flash (LittleFS):
  CA private key blob (encrypted)
  Issued certificate store
  Tap gesture unlock sequence
  LED blink pattern definitions
  Device configuration
```

## Security Properties

| Property | How achieved |
| --- | --- |
| Private key never leaves device | On-device signing, key zeroed after use |
| Key protected at rest | Encrypted with FICR-derived key in LittleFS |
| Physical access protection | APPROTECT disables SWD in production |
| Session confidentiality | Noise_XX + ChaCha20-Poly1305 (mbedtls) |
| Mutual authentication | Noise_XX static keypair exchange |
| Key generation entropy | CryptoCell-310 hardware TRNG |
| CA signing acceleration | CryptoCell-310 ECC P-256/384 hardware |
