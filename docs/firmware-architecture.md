# Firmware Architecture

```mermaid
flowchart TB
    main["main.c<br/>boot + main loop"]

    subgraph input["Input layer"]
        tap_btn["gesture/tap_button.c<br/>GPIO tap source"]
        tap_mic["gesture/tap_mic.c<br/>PDM mic onset"]
        tap_imu["gesture/tap_imu.c<br/>IMU (abandoned)"]
        gesture["gesture/gesture.c<br/>state machine<br/>LOCKED ↔ UNLOCKED ↔ AWAITING_*"]
    end

    subgraph ui["UI layer"]
        led["led/led.c<br/>PWM HSV animator<br/>idle loops + one-shots"]
    end

    subgraph transport_layer["Transport"]
        usb["transport/transport_usb.c<br/>CDC/ACM (ACM0=proto, ACM1=log)"]
        ble["transport/transport_ble.c<br/>NUS"]
        transport["transport/transport.c<br/>vtable"]
    end

    subgraph sess["Session (Noise_XX)"]
        session["session/session.c<br/>handshake + framing"]
        nc_free["noise_crypto_mbedtls.c<br/>FREE backend"]
        nc_psa["noise_crypto_psa.c<br/>ACCELERATED backend<br/>(CONFIG gated)"]
    end

    subgraph proto["Protocol"]
        protocol["protocol/protocol.c<br/>CBOR dispatch<br/>cmd → handler"]
        cbor["common/cbor/cantil_cbor.c<br/>canonical CBOR codec"]
    end

    subgraph ca_layer["CA / key ops"]
        ca["ca/ca.c<br/>SIGN_CSR, GEN_KEY,<br/>PUSH_*, CRL, chain walker"]
        names["names/names.c<br/>GET_RANDOM_NAMES"]
    end

    subgraph crypto_layer["Crypto"]
        crypto_free["crypto/crypto.c<br/>mbedtls direct (FREE)"]
        crypto_psa["crypto/crypto_psa.c<br/>PSA (ACCELERATED)"]
        cc310["CryptoCell-310<br/>TRNG, AES, SHA, ECC"]
    end

    subgraph store["Storage"]
        storage["storage/storage.c<br/>LittleFS wrapper"]
        lfs[("QSPI LittleFS<br/>/keys/ /certs/ /session/<br/>/noise/ (client pin) /config*")]
    end

    dev["dev_dfu.c<br/>1200bps-touch reboot<br/>(dev only)"]

    main --> gesture
    main --> transport
    main --> session
    main --> protocol
    main --> led
    main --> dev

    tap_btn --> gesture
    tap_mic --> gesture
    tap_imu -.-> gesture
    gesture --> led
    gesture --> storage

    usb --> transport
    ble --> transport
    transport --> session
    session --> nc_free
    session --> nc_psa
    session --> storage

    protocol --> cbor
    protocol --> ca
    protocol --> names
    protocol --> gesture
    protocol --> storage
    session --> protocol

    ca --> crypto_free
    ca --> crypto_psa
    ca --> storage
    ca --> cbor

    nc_free --> mbedtls["mbedtls software"]
    nc_psa --> psa["PSA: Oberon + CC3XX"]
    crypto_free --> mbedtls
    crypto_psa --> psa
    mbedtls -.alt impls.-> cc310
    psa --> cc310

    storage --> lfs
```

**Flow:** taps → gesture FSM drives LED + unlock state; USB/BLE → Noise session → CBOR dispatch → CA/storage. Crypto routes through one of two compile-time backends (FREE = mbedtls direct, ACCELERATED = PSA → Oberon/CC3XX).
