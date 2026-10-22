# Roadmap: BLE on upstream Zephyr 4.4.0

**Assessed 2026-07-27. Not started.** BLE has been off in the default build since
the beginning, on a licensing argument that **was true under NCS and is no longer
true upstream**. This doc records what actually blocks it now (nothing, on the
licensing axis), what it would take, and what is still unmeasured.

> **Headline: no binary blobs are required.** The whole BLE path — controller,
> host, HCI, and the PSA crypto the host needs — is source, and the licenses are
> GPLv3-compatible. [../crypto-blobs.md](../crypto-blobs.md)'s claim that "Cantil
> ships no binary blobs; nothing in this repository requires one" survives BLE
> being turned on.

## The old reason is stale

[firmware/boards/xiao_ble_nrf52840_sense.conf](../../firmware/boards/xiao_ble_nrf52840_sense.conf)
still carries this:

> BLE is intentionally not enabled in the default (FREE crypto backend) build.
> Zephyr's BT stack pulls in `CONFIG_BT_HOST_CRYPTO`, which auto-implies
> `NRF_SECURITY`, which in turn requires a PSA crypto driver (Oberon or CC3XX)
> to back AES/SHA — both are closed-source under the Nordic 5-Clause license
> and would taint the GPLv3 default build.

That reasoning was correct **for NCS**. `NRF_SECURITY` is an sdk-nrf symbol; it
does not exist in upstream Zephyr. Since Phase 1 the tree builds against
upstream `v4.4.0` and the implication chain is gone. The comment should be
rewritten (or deleted) whenever that file is next touched — as written it tells
a future reader that BLE is license-blocked, which is wrong.

The same staleness affects the flash-budget table in
[../reference/hardware.md](../reference/hardware.md), whose "PSA Crypto +
Oberon + CC310 HAL | ~50–80KB" row describes a stack we no longer build.

## What upstream v4.4.0 actually gives us

Verified against the v4.4.0 checkout (tag peels to `684c9e8f`, the commit both
`firmware/west.yml` and `MODULE.bazel` pin).

**The controller is in-tree source.** `dts/arm/nordic/nrf52840.dtsi` already
sets `zephyr,bt-hci = &bt_hci_controller` with
`compatible = "zephyr,bt-hci-ll-sw-split"` — Zephyr's own software Link Layer
(`CONFIG_BT_LL_SW_SPLIT`), Apache-2.0. The nRF5 back half
(`subsys/bluetooth/controller/ll_sw/nordic/hal/nrf5/`: `radio/`, `ecb.c`,
`cntr.c`, `ticker.c`) is plain C. There is no SoftDevice Controller here — SDC
and MPSL live in `nrfxlib` under sdk-nrf, which we do not use.

**No blobs anywhere on the path.** Checked, not assumed:

| Check | Result |
| --- | --- |
| `softdevice` / `nrfxlib` / `SOFTDEVICE` referenced anywhere in `subsys/bluetooth/` or `drivers/bluetooth/` | zero hits |
| `*.a` / `*.lib` / `*.o` / `*.so` / `*.bin` / `*.hex` in the pinned `hal_nordic` (`44fd3d44`) | zero files |
| `nrfx` license | BSD-3-Clause, source |
| `ll_sw/nordic/hal/nrf5/ecb.c` license | Apache-2.0, source |

`ecb.c` drives the nRF52840's AES-ECB peripheral directly; that is what backs
`BT_CTLR_CRYPTO`. Two binaries in the picture are **not** blobs in the sense
that matters, and neither is new: the Zephyr SDK toolchain (a build tool, never
linked into the image) and the XIAO's factory UF2 bootloader (already resident,
not something we build or distribute — that one is a live question for the
wolfBoot tier, not for BLE).

## The real requirement: a PSA Crypto provider

This is the one genuine cost, and it is unavoidable — the controller providing
AES does **not** exempt us.

- `BT_CTLR_CRYPTO` defaults `y` with the in-tree LL, so `BT_HOST_CRYPTO`
  (`default y if !BT_CTLR_CRYPTO`) stays off. Good, but not sufficient.
- `CONFIG_BT_SMP` (`subsys/bluetooth/host/Kconfig:502`) does
  `select BT_CRYPTO` and `select BT_ECC if !BT_SMP_OOB_LEGACY_PAIR_ONLY`.
- `BT_ECC` → `select PSA_CRYPTO` + `PSA_WANT_ALG_ECDH` + SECP-R1 P-256
  keypair generate/import/export.
- `BT_CRYPTO` → `subsys/bluetooth/crypto/bt_crypto_psa.c`, i.e. AES-CMAC via
  `psa_mac_compute`.

So LE Secure Connections — which the passkey flow in
[firmware/src/clients/pairing.c](../../firmware/src/clients/pairing.c) assumes —
requires PSA no matter what.

**The surface is small.** Excluding mesh (not built), only four files use PSA:
`host/crypto_psa.c`, `host/ecc.c`, `host/gatt.c`, `crypto/bt_crypto_psa.c`.
Between them:

| Need | PSA calls | wolfCrypt equivalent |
| --- | --- | --- |
| init | `psa_crypto_init` | no-op |
| RNG | `psa_generate_random` | already wired (`firmware/src/crypto/wc_rand.c`) |
| key slots | `psa_import_key`, `psa_export_key`, `psa_export_public_key`, `psa_generate_key`, `psa_destroy_key`, `psa_reset_key_attributes`, the `psa_set_key_*` setters | — |
| AES-ECB, one block | `psa_cipher_encrypt` + `PSA_ALG_ECB_NO_PADDING` | `wc_AesEcbEncrypt` |
| AES-CMAC | `psa_mac_compute`, `psa_mac_sign_setup/update/finish` | `wc_InitCmac` / `wc_CmacUpdate` / `wc_CmacFinal` |
| ECDH P-256 | `psa_raw_key_agreement`, SECP-R1 keygen/import/export | `wc_ecc_make_key`, `wc_ecc_import_unsigned`, `wc_ecc_export_x963`, `wc_ecc_shared_secret` |

No AEAD, no hashing, no key derivation, **no persistence** — `psa_set_key_lifetime`
and `psa_set_key_id` appear only in the mesh path, so every key BT creates is
volatile. All the wolfCrypt entry points above exist in the pinned v5.9.2.

### Provider options

| Option | Blobs | Second crypto lib in image | Bazel work |
| --- | --- | --- | --- |
| **wolfPSA** (preferred) | none | no | one flat `src/` → small BUILD |
| Mbed TLS / tf-psa-crypto | none | **yes** | two repos, multi-target CMake subproject |
| Hand-rolled shim | none | no | small, but we own ~800 lines of crypto glue |
| Replace `p256-m` with wolfCrypt | none | **yes** — doesn't remove Mbed TLS | all the Mbed TLS work, plus a custom driver |

Note that **none** of these reintroduces a blob. The choice is about library
count and build-system cost, not licensing.

**Mbed TLS is a legitimate answer** — it is upstream's supported provider, and
it is Apache-2.0 / GPL-2.0-or-later, which combines fine with GPLv3. The case
against it is that it puts a second crypto library back in an image the wolfSSL
migration deliberately reduced to one, and that `zephyr-bazel` has **no** mbedtls
module BUILD (its `modules/` holds only cmsis, cmsis_6, hal_*, littlefs,
openair, segger, wolfssl) while v4.4 splits Mbed TLS into two repos building
`mbedtls`/`mbedx509`/`tfpsacrypto`/`p256-m`/`everest`/`pqcp`/…

**Replacing `p256-m` is a dead end** for our purposes. Its six transparent-driver
entry points (`p256_transparent_import_key`, `export_public_key`, `generate_key`,
`key_agreement`, `sign_hash`, `verify_hash`) are easy to reimplement over
`wc_ecc_*`, but the PSA *core* is still tf-psa-crypto, so every Mbed TLS cost is
paid in full to save p256-m's ~3–4 KB. Mbed TLS 4.x also generates
`psa_crypto_driver_wrappers.c` from driver JSON, and Zephyr's module exposes no
hook for adding one — we would be patching the module or its generator.

## wolfPSA

<https://github.com/wolfSSL/wolfPSA> — "a PSA Crypto engine that implements the
PSA Crypto API on top of wolfCrypt." This is precisely the shim we would
otherwise write, already written, by the vendor of the library we already use.

- **GPL-3.0**, matching the 2026-07-22 relicense. (Confirm from `COPYING`
  whether it is "or later" — if GPLv3-only, a combined Cantil binary is
  distributable under GPLv3 only, not "or later." Small, but ours to state.)
- **Active**: created 2025-12-22, 263 commits, last push **2026-07-22**. 5 stars,
  1 open issue, 486 KB.
- **Standard include path**: headers live at `wolfpsa/psa/crypto.h` plus
  `crypto_types.h` / `crypto_values.h` / `crypto_sizes.h` / `crypto_struct.h` /
  `error.h`. Zephyr's `#include <psa/crypto.h>` resolves with an include-path
  entry and nothing else — that was the largest single chunk of the
  hand-rolled plan, and it disappears.
- **Coverage exceeds our need** (AEAD, RSA, ECC, Montgomery, KDF, XOF, ML-DSA,
  ML-KEM, LMS/XMSS). The only `PSA_ERROR_NOT_SUPPORTED` stubs in
  `src/psa_api_stub.c` are PAKE, the interruptible-operation family, hash
  suspend/resume, and `psa_purge_key` — **none of the functions BT needs**.
  `src/psa_mac.c` implements `psa_mac_compute` / `sign_setup` / `update` /
  `sign_finish` for `PSA_ALG_CMAC` over `wc_InitCmac`/`wc_CmacUpdate`/`wc_CmacFinal`.
- Passes 65/78 Arm PSA Architecture Test Suite crypto tests; 13 skipped, 0 failures.

### Unmeasured, and the reason to spike before planning

- **It allocates.** `psa_mac.c` gets its operation context from `XMALLOC`. Our
  posture is the opposite — `WOLFSSL_SP_NO_MALLOC` is set deliberately so there
  is no heap-allocation failure path while the CA key is in RAM. Not a blocker
  (Zephyr has a heap; BT uses pools anyway), but it deserves a decision rather
  than a drift.
- **Footprint unknown.** ~600 KB of source; `src/psa_key_storage.c` alone is
  80 KB of it. How cleanly it gates down to AES-ECB + CMAC + ECDH-P256 + RNG is
  untested.
- **Unproven on our target.** Makefile-only build with an ASAN target; no
  evidence anyone has run it under Zephyr or on a Cortex-M. We would plausibly
  be first. Seven months old, 5 stars.
- `src/psa_store_posix.c` is the persistence backend; BT needs only volatile
  keys, so it should compile out, but that is untested too.

## What it would take

1. **Spike first** (cheap, self-contained, no board): build wolfPSA for
   `native_sim/native/64` and run upstream's own `tests/bluetooth/bt_crypto`
   PSA variant against it. That suite is gated on exactly
   `CONFIG_PSA_CRYPTO_CLIENT`, allows `native_sim/native/64`, and checks the SMP
   f4/f5/f6/g2/h6/h7 functions against Core-spec vectors. One target answers
   gating, correctness and rough footprint at once.
2. **Build glue.** wolfPSA ships a Makefile only — no CMake, no
   `zephyr/module.yml`, no Bazel. But the tree already compiles wolfSSL's
   sources directly from `firmware/BUILD.bazel` rather than via a module target,
   and wolfPSA is a flat `src/` producing one library, so the same pattern
   applies. Avoid double-linking wolfCrypt: the upstream Makefile bundles
   wolfCrypt objects into `libwolfpsa.a` and we build wolfCrypt ourselves.
3. **Our own `user_settings.h` for wolfPSA**, gating out everything except
   AES-ECB, CMAC, ECDH P-256, RNG. Exclude `psa_store_posix.c`.
4. **Kconfig**: `PSA_CRYPTO_PROVIDER_CUSTOM`, plus a Cantil symbol that
   `select`s `PSA_CRYPTO_CLIENT`. That symbol is promptless and currently only
   `MBEDTLS_PSA_CRYPTO_CLIENT` and TF-M select it; without it the whole
   `PSA_WANT_*` tree sits behind an unmet `if` in `Kconfig.psa.auto` and BT's
   `select PSA_WANT_ALG_ECDH` warns.
5. **wolfCrypt config delta** in
   [firmware/include/cantil_wolfssl_user_settings.h](../../firmware/include/cantil_wolfssl_user_settings.h):
   BT needs **AES-128** (we build `WOLFSSL_AES_256` only), `HAVE_AES_ECB`,
   `WOLFSSL_AES_DIRECT`, and `WOLFSSL_CMAC` — the last of which goes through
   AES-CBC, so the current `NO_AES_CBC` has to come off. This widens a
   deliberately-pruned primitive set and should be a conscious call.
6. **Port `transport_ble.c`.** [firmware/src/transport/transport_ble.c](../../firmware/src/transport/transport_ble.c)
   includes `<bluetooth/services/nus.h>` — the **NCS** header. Upstream is
   `<zephyr/bluetooth/services/nus.h>`, and the callback signature differs:
   `void (*received)(struct bt_conn *conn, const void *data, uint16_t len, void *ctx)`,
   registered via `bt_nus_cb_register(&cb, ctx)`, sent via
   `bt_nus_send(conn, data, len)`.
7. **A `_ble.conf` overlay** (`FILE_SUFFIX=ble` / `EXTRA_CONF_FILE`) carrying the
   `CONFIG_BT*` switches, as the board conf already anticipates. `CANTIL_TRANSPORT_BLE`
   already exists in `firmware/Kconfig` and `firmware/CMakeLists.txt` already
   has the `target_sources_ifdef`.

## Ordering

After Phase 4 (wolfBoot). This is not urgent — USB CDC/ACM is the working
transport and BLE adds a second attack surface to a device whose pitch is key
custody. But the *reason* it was deferred has changed from "we cannot ship this
freely" to "we have not done the work," and the roadmap should say so.

The one piece worth doing early is step 1, the wolfPSA spike: it is independent
of the NUS port, needs no hardware, and its outcome decides whether this is a
small integration or a from-scratch shim.

## Open questions

- Is wolfPSA's `COPYING` GPLv3-only or GPLv3-or-later?
- Does wolfPSA gate down to a sane footprint on Cortex-M, and what does it cost
  in flash and stack?
- Do we accept `XMALLOC` in the BT crypto path, or push a static-context patch
  upstream?
- BLE + USB simultaneously, or mutually exclusive transports? (Existing board
  confs set both `CONFIG_BT=y` and USB for the non-XIAO boards; the interaction
  has never been exercised.)
- Does enabling BLE change the pairing/gesture story — `PAIRING_TAP_CONFIRM` was
  designed with BLE passkey flows in mind
  ([../reference/gesture-and-led.md](../reference/gesture-and-led.md),
  [../transport-and-pairing.md](../transport-and-pairing.md)) but has only ever
  run over USB.
