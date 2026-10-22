# Changelog

All notable changes to this project will be documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Added
- Noise_XX handshake and encrypted session layer (`firmware/src/session/`)
- Noise crypto abstraction (`noise_crypto.h`): Noise-C backend (default, BSD
  licensed, portable) and PSA/Oberon backend (Nordic platforms, opt-in via
  `CONFIG_CANTIL_NOISE_BACKEND_PSA`)
- CBOR wire protocol skeleton and command dispatcher (`firmware/src/protocol/`)
- USB CDC/ACM and BLE NUS transport abstraction (`firmware/src/transport/`)
- CA operations stub (`firmware/src/ca/`)
- Gesture state machine (`firmware/src/gesture/`) with IMU tap (LSM6DS3TR-C)
  and GPIO button backends
- LED driver stub (`firmware/src/led/`)
- LittleFS storage stub (`firmware/src/storage/`)
- `CMD_GET_RANDOM` (0x40): export raw CC310 TRNG bytes over the encrypted session
- `CMD_GET_RANDOM_NAMES` (0x50): stream randomly selected baby names as UTF-8
  bytes with `0xFF` separator; 1918 SSA 2025 names compiled into firmware
- `scripts/extract_names.py`: maintenance tool — extracts SSA HTML → `contrib/names.txt`
- `scripts/gen_names_data.py`: build tool — `contrib/names.txt` → C data arrays
- `libcantil/include/cantil.h`: full public API for `libcantil` client library (headers)
- `libcantil/include/cantil_random.h`: pluggable TRNG utilities including
  `cantil_rand_names()` and `cantil_names_decode()` (headers)
- Board overlays: `xiao_ble/nrf52840/sense` (primary target)
- Build environment: `ubuntu2604` distrobox with NCS v3.0.2, `scripts/dbox.sh`
  wrapper, `scripts/build.sh` build script

### Architecture decisions recorded
- USB CDC/ACM over FIDO2 (FIDO2 has no CSR/cert management API)
- Noise_XX at application layer (not below CDC/ACM — preserves zero-driver ergonomics)
- Noise-C as default crypto backend (fully open source, portable, no license restrictions)
- CA private key never leaves device; generated at first boot via CC310 TRNG
- Flash layout: MCUboot at 0x00000000, app at 0x00008000, NVS at 0x000F8000
