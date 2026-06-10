# Build and Release Process

## Prerequisites

- [nRF Connect SDK](https://developer.nordicsemi.com/nRF_Connect_SDK/doc/latest/nrf/getting_started.html) (includes Zephyr, west, arm-zephyr-eabi-gcc)
- `nrfutil` — DFU package generation and USB flashing
- `imgtool` — MCUboot image signing (bundled with nRF Connect SDK)
- `nrfjprog` — SWD/JTAG flashing for development (requires J-Link)
- `jq` — used by automation hooks

---

## Building the Host Client (cantil CLI)

The `cantil` CLI lives in `libcantil/` and is built with CMake against libsodium and mbedtls. Two build modes:

### Standard (dynamic) build

Built inside the `ubuntu2604` distrobox (where the libraries are installed):

```bash
distrobox enter ubuntu2604
cd libcantil
cmake -B build .
cmake --build build
# Binary: libcantil/build/cantil
```

The dynamic binary needs `libsodium.so.23` and `libmbedx509.so.7` at runtime — these exist inside the distrobox but not on the Fedora host.

### Static build (recommended for flatpak / host use)

Links libsodium and mbedtls as static archives. The resulting binary has no runtime dependencies beyond glibc, so it can run directly on the Fedora host via `flatpak-spawn --host`:

```bash
distrobox enter ubuntu2604
cd libcantil
cmake -B build_static -DCANTIL_CLI_STATIC=ON .
cmake --build build_static
# Binary: libcantil/build_static/cantil
```

### Device access from a flatpak sandbox

Claude Code runs inside a flatpak. USB CDC/ACM devices (`/dev/ttyACM*`) are only reachable via `flatpak-spawn --host`. Always prefix cantil commands with it:

```bash
flatpak-spawn --host libcantil/build_static/cantil status /dev/ttyACM0
flatpak-spawn --host libcantil/build_static/cantil pair /dev/ttyACM0
```

`scripts/provision_fw_signing_cert.sh` auto-detects the flatpak sandbox (checks `$FLATPAK_ID` / `/.flatpak-info`) and wraps cantil automatically.

### ttyACM1 echo workaround

The device enumerates two ACM nodes: `ttyACM0` (protocol) and `ttyACM1` (Zephyr shell/log). Linux defaults to `ECHO=true` on serial ports, so Zephyr console output on ttyACM1 is echoed back as input — this creates a tight shell feedback loop that starves the firmware main thread and can corrupt the Noise handshake.

Set ttyACM1 to raw mode immediately after the device enumerates:

```python
# flatpak-spawn --host python3 -c "..."
import termios, os
fd = os.open('/dev/ttyACM1', os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
tty = termios.tcgetattr(fd)
tty[0] &= ~(termios.IGNBRK | termios.BRKINT | termios.PARMRK | termios.ISTRIP |
             termios.INLCR | termios.IGNCR | termios.ICRNL | termios.IXON)
tty[1] &= ~termios.OPOST
tty[2] &= ~(termios.ECHO | termios.ECHONL | termios.ICANON | termios.ISIG |
             termios.IEXTEN | termios.CSIZE | termios.PARENB)
tty[2] |= termios.CS8
tty[3] &= ~(termios.ECHO | termios.ECHONL | termios.ICANON | termios.ISIG | termios.IEXTEN)
termios.tcsetattr(fd, termios.TCSANOW, tty)
os.close(fd)
```

A permanent fix via udev rule (`/tmp/99-cantil.rules`) is possible but not yet installed.

### Firmware signing cert provisioning

```bash
# After building build_static/cantil and pairing the device:
./scripts/provision_fw_signing_cert.sh [--port /dev/ttyACM0]
# Output: ~/.cantil/firmware-signing/{fw_signing.key.pem, fw_signing.cert.pem, ca.cert.pem}
```

The device must be **unlocked** (tap unlock sequence) before running. The script is idempotent — skips key generation if the key already exists.

---

## Development Build Flow

```mermaid
flowchart TD
    A([Clone repo]) --> B[west init / west update]
    B --> C[Configure prj.conf\nand board overlay]
    C --> D{Build type}

    D -->|dev| E["west build\n-b xiao_ble/nrf52840"]
    D -->|release| F["west build\n-b xiao_ble/nrf52840\n-- -DFILE_SUFFIX=release"]

    E --> G[build/zephyr/zephyr.bin\nunsigned]
    F --> G

    G --> H{Flash method}

    H -->|SWD J-Link\ndevelopment only| I[west flash\nvia nrfjprog]
    H -->|USB DFU\nrequires signed image| J[Sign and package\nsee Release Flow]

    I --> K([Device running\ndevelopment build])
```

---

## Release Flow

```mermaid
flowchart TD
    A([Signed release build]) --> B["imgtool sign\n--key signing_key.pem\n--version X.Y.Z\n--align 4\n--slot-size 0xF0000\nzephyr.bin → zephyr.signed.bin"]

    B --> C{Signing key type}
    C -->|development\nself-signed| D[dev_signing_key.pem\ngenerated locally]
    C -->|production\noffline key| E[prod_signing_key.pem\nair-gapped machine]

    D --> F[zephyr.signed.bin]
    E --> F

    F --> G["nrfutil pkg generate\n--hw-version 52\n--application zephyr.signed.bin\n--application-version N\napp_dfu.zip"]

    G --> H{Distribution method}

    H -->|USB serial DFU\nproduction path| I["nrfutil dfu usb-serial\n-pkg app_dfu.zip\n-p /dev/ttyACM0"]
    H -->|SWD factory flash\nmanufacturing only| J["nrfjprog --program\nzephyr.signed.bin\n--sectorerase"]

    I --> K([Device updated])
    J --> K
```

---

## First Boot: Key Provisioning

```mermaid
flowchart TD
    A([Device powered on]) --> B{LittleFS\ninitialized?}

    B -->|No — first boot| C[Format external\nQSPI flash\nwith LittleFS]
    C --> D[Read FICR unique\ndevice ID registers]
    D --> E[Derive storage\nencryption key\nfrom FICR UID via HKDF]
    E --> F[CryptoCell-310 TRNG\ngenerates ECC P-256\nCA keypair]
    F --> G[Encrypt private key\nwith storage key\nvia AES-256-GCM]
    G --> H[Write encrypted\nkey blob to LittleFS]
    H --> I[Write self-signed\nCA root cert to LittleFS]
    I --> J([Device ready\nLOCKED state])

    B -->|Yes — subsequent boots| K[Load encrypted\nkey blob from LittleFS]
    K --> J
```

---

## Full Device State Machine

```mermaid
flowchart TD
    BOOT([Power on / Reset]) --> LOCKED

    LOCKED([LOCKED\nBLE advertising\nCA ops blocked])
    LOCKED --> TAP1[Tap interrupt fires\nbuffer event + timestamp]
    TAP1 --> TIMEOUT1{Sequence\ntimeout?}
    TIMEOUT1 -->|No — keep buffering| TAP1
    TIMEOUT1 -->|Yes — sequence complete| CMP1{Match\nunlock sequence?}
    CMP1 -->|No| FAIL1[Emit FAIL blink]
    FAIL1 --> LOCKED
    CMP1 -->|Yes| UNLOCKED

    UNLOCKED([UNLOCKED\nCA ops available\nauto-lock timer running])
    UNLOCKED --> TAP2[Tap interrupt fires\nbuffer event + timestamp]
    TAP2 --> TIMEOUT2{Sequence\ntimeout?}
    TIMEOUT2 -->|No| TAP2
    TIMEOUT2 -->|Yes| CMP2{Which sequence\nmatches?}

    CMP2 -->|pairing trigger\nDT DT ST ST| PAIRING
    CMP2 -->|change-seq trigger\nDT ST DT ST| CHG_CONFIRM
    CMP2 -->|no match| FAIL2[Emit FAIL blink]
    FAIL2 --> UNLOCKED

    UNLOCKED --> IDLE{Inactivity\ntimeout 5min\nor USB unplug?}
    IDLE -->|Yes| LOCKED

    %% BLE Pairing flow
    PAIRING([PAIRING\npasskey display window\n60s timeout])
    PAIRING --> GEN[Generate 6-digit passkey\ndigits 1–9 only]
    GEN --> BLINK[Blink passkey via LED\n2 groups of 3 digits\n500ms between digits\n1s between groups]
    BLINK --> PAIR_WAIT{Pairing complete\nor timeout?}
    PAIR_WAIT -->|Success| PAIR_OK[Add central to\nbond whitelist\nEmit PAIRING_SUCCESS blink]
    PAIR_OK --> UNLOCKED
    PAIR_WAIT -->|Timeout / fail| PAIR_FAIL[Emit FAIL blink]
    PAIR_FAIL --> UNLOCKED

    %% Change-sequence flow
    CHG_CONFIRM([CHANGE_SEQ_CONFIRM\nwaiting for new sequence])
    CHG_CONFIRM --> NEW_SEQ[User taps new sequence]
    NEW_SEQ --> CHG_VERIFY
    CHG_VERIFY([CHANGE_SEQ_VERIFY\nwaiting for re-entry])
    CHG_VERIFY --> RE_ENTRY[User re-taps sequence]
    RE_ENTRY --> CHG_CMP{Sequences\nmatch?}
    CHG_CMP -->|Yes| SAVE[Save to LittleFS\nEmit UNLOCKED blink]
    SAVE --> UNLOCKED
    CHG_CMP -->|No| CHG_FAIL[Emit FAIL blink\ndo not save]
    CHG_FAIL --> UNLOCKED

    %% BLE connected while locked
    LOCKED --> BLE_CONN{Bonded central\nconnects via BLE?}
    BLE_CONN -->|Yes — whitelist pass| BLE_LOCKED[Accept connection\nNoise_XX handshake OK\nCA commands → ERR_LOCKED\nDEVICE_STATUS allowed]
    BLE_LOCKED --> LOCKED

    %% CA operations while unlocked
    UNLOCKED --> CLIENT{Client connects\nUSB or BLE?}
    CLIENT -->|Yes| NOISE[Noise_XX handshake\nover CDC-ACM or BLE NUS]
    NOISE --> CMD[Receive CBOR command]
    CMD --> CMD_TYPE{Command}
    CMD_TYPE -->|SIGN_CSR| SIGN[Decrypt key → RAM\nCC310 ECC sign\nZero key from RAM\nReturn cert]
    CMD_TYPE -->|GET_CA_CERT\nGET_CA_CHAIN\nGET_CSR\nLIST_CERTS\nREVOKE_CERT\nPUSH_CERT\nDEVICE_STATUS| READ[LittleFS read/write\nReturn response]
    SIGN --> CMD
    READ --> CMD
```

---

## Crypto Backend Options

> **Stale — pending rewrite.** This section was written before the
> FREE-vs-ACCELERATED split in conversation_008 (2026-05-21) and before
> the PSA port across sessions 043–046. The current truth lives in
> CLAUDE.md § "Noise Crypto Backend Architecture" and § "CryptoCell-310
> Usage": (1) the FREE backend calls mbedtls *directly* (no PSA layer);
> (2) only the ACCELERATED backend routes through PSA; (3) the
> Curve25519 → Oberon routing diagrammed below is the **design intent**
> but does **not** currently fire — NCS PSA's dispatcher claims
> Montgomery 255 for CC3XX, which CC310 silicon does not implement, so
> Noise pair fails end-to-end on real hardware as of 2026-05-29 (session
> 046). See `project_psa_runtime_gate_findings.md` for the full trace.

The firmware has two crypto backend configurations. Both expose the same PSA
Crypto API — application `.c` files are identical. The choice affects only
`prj.conf` (and per-board `.conf` overlays) and has licensing and performance
implications.

### Comparison

| | nrfxlib (default) | mbedTLS (AGPLv3-clean) |
| --- | --- | --- |
| `prj.conf` | `CONFIG_NRF_SECURITY=y` + CC3XX + Oberon | `CONFIG_MBEDTLS=y` + `CONFIG_MBEDTLS_PSA_CRYPTO_C=y` |
| ECC P-256/384 signing | CC310 hardware ~1ms | mbedTLS software ~100–200ms |
| AES-256-GCM, SHA-256/384 | CC310 hardware | mbedTLS software (negligible difference) |
| Curve25519, ChaCha20-Poly1305 | Oberon software | mbedTLS software (both are software) |
| TRNG | CC310 hardware (Zephyr entropy driver) | CC310 hardware (same — unaffected) |
| Application code changes | — | none |
| License | Nordic proprietary (nrfxlib) | Apache 2.0 (mbedTLS) + Apache 2.0 (nrfx) |
| AGPLv3 firmware release | **No** — nrfxlib has no source | **Yes** |

### Why nrfxlib blocks AGPLv3

`CONFIG_NRF_SECURITY=y` causes the linker to include `libnrf_cc3xx` and
`libnrf_oberon` from Nordic's `nrfxlib` repository. These are pre-built static
libraries distributed with no source under a Nordic proprietary license.
AGPLv3 §6 requires complete corresponding source for all modules in the binary.
Since nrfxlib provides no source, that requirement cannot be satisfied.

### Switching to mbedTLS

In `prj.conf` (and any board-specific `.conf` files that duplicate these lines),
replace:

```kconfig
CONFIG_NRF_SECURITY=y
CONFIG_PSA_CRYPTO_DRIVER_CC3XX=y
CONFIG_PSA_CRYPTO_DRIVER_OBERON=y
```

with:

```kconfig
CONFIG_MBEDTLS=y
CONFIG_MBEDTLS_PSA_CRYPTO_C=y
```

No other files change.

### Crypto Backend Routing (PSA API)

**Default build — nrfxlib, hardware-accelerated:**

```mermaid
flowchart LR
    A([Application code]) --> B[PSA Crypto API\nnRF Connect SDK]

    B --> C{Algorithm}

    C -->|ECC P-256/384\nAES-256\nSHA-256/384\nTRNG| D[CryptoCell-310\nHardware\nnrfxlib nrf_cc3xx]
    C -->|Curve25519\nChaCha20-Poly1305| E[Oberon\nSoftware on M4F\nnrfxlib nrf_oberon]

    D --> F([Hardware-accelerated\nCA operations])
    E --> G([Noise session\nhandshake + traffic])
```

**AGPLv3-clean build — mbedTLS, fully open-source:**

```mermaid
flowchart LR
    A([Application code]) --> B[PSA Crypto API\nnRF Connect SDK]

    B --> C{Algorithm}

    C -->|ECC P-256/384\nAES-256\nSHA-256/384| D[mbedTLS\nSoftware on M4F\nApache 2.0]
    C -->|Curve25519\nChaCha20-Poly1305| D
    C -->|TRNG| E[Zephyr CC310\nEntropy Driver\nnrfx Apache 2.0]

    E --> F([CC310 hardware RNG\nunchanged])
    D --> G([All crypto in software\n~100-200ms for ECC sign])
```
