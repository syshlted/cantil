# Phase 3 — Bazel

> **Status: the full `//firmware:cantil` firmware links under Bazel (2026-07-26).**
> The uf2_only tier for `xiao_ble/nrf52840/sense` builds to a real nRF52840
> image — **FLASH 253,176 B / RAM 81,184 B**, within **0.47 %** of the CMake
> reference (251,996 B). Security invariants verified on the linked ELF: the
> `--wrap=lfs_format` guard applied (`__wrap_lfs_format` present, no
> `lfs_format` / `__real_lfs_format` / `fs_mkfs` / `littlefs_mkfs`), and zero
> `mbedtls_*` code symbols (only two `CONFIG_*MBEDTLS*` Kconfig flags remain,
> which are harmless). Build it with:
>
> ```bash
> bazelisk build //firmware:cantil --config=xiao   # no setup step
> ```
>
> **No setup step:** Bazel fetches and patches zephyr-bazel itself — see
> [Hermetic zephyr-bazel](#hermetic-zephyr-bazel-2026-07-26).
>
> Note the **`nrf52840_sense`** platform (not `:nrf52840`) — the transition maps
> the underscore-joined qualifier to board_id `xiao_ble/nrf52840/sense`, which is
> what selects the app's `*_sense.conf` / `*_sense.overlay` (FLASH, PWM, LED,
> button, partitions). The `:nrf52840` platform resolves to the plain board and
> is kept only for `//bazel_smoke:smoke`.
>
> **What it took** (all captured in `bazel/zephyr-bazel-cantil.patch`, applied by
> Bazel itself; see [Firmware app port](#firmware-app-port-2026-07-26)):
> three module BUILDs (wolfssl/littlefs/segger) + their Zephyr in-tree glue,
> `firmware/BUILD.bazel`, and **nine classes of zephyr-bazel gap** the smoke
> test never exercised — app `Kconfig` (KCONFIG_ROOT) and app-symbol/DT_HAS
> schema generation, the sense board variant, app DTS bindings, the three USB
> `device_next` coverage gaps, cross-repo module headers, and the nrfx
> peripheral-driver set.
>
> **The 17 ztest suites also run under Bazel (2026-07-26)** — see
> [ztest suites](#ztest-suites-on-bazel-2026-07-26):
>
> ```bash
> bazelisk test //firmware/tests/... --config=sim   # 17/17 pass
> ```
>
> **The OpenSSL gate is now a Bazel test (2026-07-26)** — see
> [The OpenSSL gate under Bazel](#the-openssl-gate-under-bazel-2026-07-26).
> `bazel test //firmware/tests/...` is no longer weaker than `scripts/test.sh`.
>
> **zephyr-bazel is hermetic (2026-07-26)** — no machine-local checkout, no
> setup script; see [Hermetic zephyr-bazel](#hermetic-zephyr-bazel-2026-07-26).
>
> **Bazel is now the default build (2026-07-26).** `scripts/build.sh` and
> `scripts/test.sh` drive Bazel; `--cmake` selects the legacy west path, which
> survives for exactly two things — the reference build for A/B size checks,
> and boards other than the XIAO. (The mcuboot tier was the third and the only
> *hard* one; it was dropped the same day —
> [wolfboot-migration.md](wolfboot-migration.md).) See
> [libcantil](#libcantil-on-bazel-2026-07-26),
> [the bench images](#factory--wipe_diag-2026-07-26),
> [UF2 output](#uf2-output-2026-07-26) and
> [what is left of west](#what-is-left-of-west-2026-07-26).
>
> **The build asserts its own security invariants (2026-07-26)** — see
> [Symbol invariants](#symbol-invariants-as-build-actions-2026-07-26) and
> [Pin agreement](#pin-agreement-2026-07-26). The `nm` checks in the status
> block above are build actions now, not prose.
>
> **Board packages for the other nRF52840 boards landed (2026-07-27)** — see
> [Board packages](#board-packages-for-the-other-nrf52840-boards-2026-07-27).
> This did **not** let `-b` stop implying `--cmake`, for a reason that was not
> visible when the item was written: those boards cannot build the firmware on
> *either* build system, because their configs are still NCS-era BLE.
>
> **Remaining:** upstreaming the generator fixes; BLE enablement, which is what
> actually gates the non-XIAO boards; and Phase 4 (wolfBoot), after which west
> and `firmware/west.yml` can go entirely.
>
> **The mcuboot tier port is cancelled — and the tier itself is gone
> (2026-07-26).** Porting `zephyr_sysbuild` + imgtool signing + `merged.hex`
> would have been written against a bootloader being deleted, the same waste
> argument that put wolfSSL ahead of Bazel below. Rather than freeze it on the
> west path, it was deleted outright the same day
> ([wolfboot-migration.md](wolfboot-migration.md)) — which removed the only
> reason west was *required* rather than merely useful.
>
> The original 2026-07-22 assessment below is kept for context.

## ztest suites on Bazel (2026-07-26)

All 17 suites under `firmware/tests/` build and pass as `bazel test` targets on
`native_sim/native/64`, the same board the CMake runner uses. Each suite is its
own Zephyr application (its `prj.conf`, `Kconfig` and `boards/native_sim.overlay`
are picked up unchanged), declared through the `cantil_ztest` macro in
[firmware/tests/ztest.bzl](../../firmware/tests/ztest.bzl), which wraps
zephyr-bazel's `ztest()` rule. `.bazelrc` carries the two platform shortcuts,
since no target implies its platform:

```bash
bazelisk build //firmware:cantil --config=xiao   # xiao_ble/nrf52840/sense
bazelisk test //firmware/tests/... --config=sim  # native_sim/native/64
```

**`--config=sim` is `native_sim/native/64`, not `native_sim/native`.** The
CMake runner picks the 64-bit variant because a stock Fedora host lacks 32-bit
glibc headers; under Bazel the reason is sharper — the plain `native` board
leaves `CONFIG_64BIT` unset while the toolchain still compiles 64-bit, so Zephyr
and the compiler disagree about pointer width. `native_sim/native/64` maps to
the `@zephyr//boards/native/native_sim:native_64` platform (the transition
underscore-joins the qualifiers) and had to be added to `manual_boards`.

What the port needed beyond the BUILD files:

1. **Firmware sources exposed across the package boundary.** The suites compile
   the real firmware translation units; Bazel `srcs` cannot use `../` paths, so
   `//firmware` exports its `src/**/*.c` and carries `fw_headers` /
   `fw_crypto_headers` / `fw_session_headers` — one target per include path the
   suites' `target_include_directories` grant, rather than one wide target.
2. **Suite-local headers must be declared.** `.h` and `.inc` files (test
   vectors, control shims) are staged only if a target lists them, so
   `cantil_ztest` globs `src/**/*.{h,inc}` into `hdrs`.
3. **Two zephyr-bazel native_sim gaps** (in the overlay patch). Zephyr adds the
   host-side half of the native_sim drivers with
   `target_sources(native_simulator INTERFACE ...)`, which the BUILD generator
   does not translate — only the embedded half is emitted. Without them
   `entropy_native_seed` (`drivers/entropy/fake_entropy_native_bottom.c`) and
   `flash_mock_init_native` / `flash_mock_cleanup_native`
   (`drivers/flash/flash_simulator_native.c`) are undefined at link, which hits
   any native_sim app that mounts a filesystem. Both are now `cc_library`
   targets in their driver packages, pulled into `//:native_simulator` under
   `CONFIG_FAKE_ENTROPY_NATIVE_SIM` / `CONFIG_FLASH_SIMULATOR`. The same class
   of gap remains for every other bottom-half driver (serial PTY, ethernet
   TAP, display SDL, …) — worth upstreaming as one fix.
4. **A real test-isolation bug, found by sandboxing.** `pairing` and
   `pairing_passkey` passed under CMake only because native_sim's flash
   simulator is file-backed: `flash.bin` in the working directory survives
   between runs, so those suites inherited a volume marker written by an
   earlier suite. Bazel gives each test a fresh sandbox, and both failed with
   *"volume is unmarked — bond not persisted"*. Confirmed pre-existing by
   running the **CMake** binaries in an empty directory — same 3 failures.
   Fixed the way the other suites already do it: `suite_setup()` calls
   `storage_volume_marker_write()`, as the factory image does. Both runners are
   green now.

Discovery gotcha: adding a new app package (a new `BUILD.bazel` next to a
`prj.conf`) is not picked up by a running Bazel server — `bazelisk shutdown`
first, or the transition fails with *"filtered out by heuristics"*.

## libcantil on Bazel (2026-07-26)

The host client — library, `cantil` CLI and the X.509 conformance test — is the
largest chunk of CMake that was never Zephyr's.
[libcantil/BUILD.bazel](../../libcantil/BUILD.bazel) ports all of it; the CLI
gets its own package ([libcantil/cli](../../libcantil/cli/BUILD.bazel)) so the
binary is named `cantil` rather than the target name the library already owns.

```bash
bazelisk build //libcantil/cli:cantil --config=host
bazelisk test //libcantil/... --config=host
```

Two things are worth recording, because neither is obvious:

- **`--config=host` exists because of the toolchain, not the platform.**
  libcantil links the *system* libsodium and libcrypto — deliberately, since
  libcrypto is a base-system library, no distro ships `libcrypto.a`, and
  upstream OpenSSL discourages static linking. Pigweed's `host_clang`, which
  this workspace registers and would otherwise be the default host toolchain,
  ships **its own sysroot**, where `<openssl/x509.h>` and `<sodium.h>` do not
  exist. `--config=host` switches to Bazel's auto-detected local toolchain,
  which needs three flags together: `--repo_env=BAZEL_DO_NOT_DETECT_CPP_TOOLCHAIN=0`
  (Pigweed's vendored `common.bazelrc` turns detection off — right for Pigweed,
  wrong for a client that wants the distro's OpenSSL), `--extra_toolchains`,
  and `--extra_execution_platforms=@platforms//host`, because MODULE.bazel
  registers native_sim as an execution platform and it otherwise wins by
  registration order.
- **The X.509 backend is a `string_flag`**, the port of
  `-DCANTIL_HOST_CRYPTO=openssl|wolfssl`:
  `--//libcantil:x509_backend=wolfssl`. Only the openssl path is exercised here
  — wolfSSL is not packaged by Fedora and needs `scripts/setup_wolfssl_host.sh`
  first, exactly as under CMake.

Not ported: `CANTIL_CLI_STATIC`, which exists only to bundle libsodium into a
self-contained AppImage. `scripts/build-appimage.sh` still drives CMake for
release packaging.

## factory + wipe_diag (2026-07-26)

Both bench images build under Bazel:

```bash
bazelisk build //firmware/factory:cantil_factory --config=xiao
bazelisk build //firmware/wipe_diag:cantil_wipe_diag --config=xiao
```

| Image | Bazel FLASH / RAM | CMake FLASH / RAM | Δ FLASH |
| --- | --- | --- | --- |
| factory | 88,552 / 32,368 | 90,168 / 32,996 | −1.8 % |
| wipe_diag | 67,640 / 42,496 | 69,212 / 43,128 | −2.3 % |
| firmware | 253,176 / 81,184 | 251,996 / 81,496 | +0.5 % |

The deltas are small and constant (−1,616 B and −1,572 B, RAM −628 B and
−632 B), so they are a systematic flag difference rather than anything
app-specific — note the production firmware differs in the *other* direction.

The security-relevant invariant holds under both build systems: the factory
image is the only one that carries a formatter, and the Bazel-built ELF has all
three symbols exactly as the CMake one does —

```console
$ arm-zephyr-eabi-nm bazel-bin/firmware/factory/cantil_factory.elf | grep -E 'lfs_format|mkfs'
00006bc8 T fs_mkfs
0000c06c T lfs_format
000070f8 t littlefs_mkfs
```

— while `//firmware:cantil` has none of them (`--wrap=lfs_format`, verified in
the status block at the top).

`firmware/wipe_diag` needed a `BUILD.bazel` even though it is a single source
file: app-discovery does a recursive `find <apps_dir> -name prj.conf`, so
without its own package its `prj.conf` collides with the production app.
Both are also named explicitly in `apps_dirs`, because a *new* app package is
otherwise invisible to an already-fetched app index.

## UF2 output (2026-07-26)

A ninth zephyr-bazel gap, and the one that actually blocked retiring west:
**zephyr-bazel had no `CONFIG_BUILD_OUTPUT_UF2` equivalent**, so a Bazel-built
image could not be flashed at all. The XIAO exposes SWD only on tiny underside
test points; dragging a `.uf2` onto the mass-storage drive is the only routine
way to program one.

`zephyr_app` now takes `uf2_family` (overlay patch) and emits `<name>.uf2`:

```python
zephyr_app(
    name = "cantil",
    uf2_family = UF2_FAMILY_NRF52840,   # "0xada52840"
    deps = [":app_lib"],
)
```

It has to live inside `zephyr_app` rather than in a genrule here, because the
conversion must happen **inside the app's platform transition** — the objcopy
that produces the intermediate hex only resolves in that configuration; a
top-level `elf_to_hex` fails with *"No matching toolchains found for
@bazel_tools//tools/cpp:toolchain_type"*. The chain is ELF → HEX (zephyr-bazel's
own `elf_to_hex`) → UF2 (Zephyr's `scripts/build/uf2conv.py`, newly exposed as
a `py_binary`, with `uf2families.json` as `data`). CMake goes ELF → BIN → UF2
and passes the load address with `-b`; going through HEX carries the addresses
in the records, which is why no base address appears. Both produce start
address `0x1000`, and the sizes track the ELF delta above (506,368 B vs
504,320 B).

## What is left of west (2026-07-26)

`scripts/build.sh` and `scripts/test.sh` now drive Bazel by default and take
`--cmake` for the legacy path. Nothing about the daily workflow needs a west
workspace, the NCS host-tool bundle, or `scripts/setup_zephyr.sh` any more:

```bash
./scripts/build.sh                        # //firmware:cantil.uf2
./scripts/build.sh --flash                # + copy to the XIAO-SENSE drive
./scripts/build.sh --factory              # //firmware/factory:cantil_factory.uf2
./scripts/build.sh --source firmware/wipe_diag
./scripts/test.sh                         # bazel test //firmware/tests/...
./scripts/test.sh sign_csr                # one suite, gate included
```

west survives for two things, and each announces itself rather than failing
obscurely:

1. **The reference build.** `--cmake` is how the Bazel output keeps being
   checked against a known-good tree. Worth keeping until Bazel-built firmware
   has as much hardware history as the CMake build.
2. **Non-XIAO boards.** `-b nrf52840dk/nrf52840` implies `--cmake` — no other
   board has a Bazel board package yet.

Both are *soft*: neither is a capability Bazel lacks, only work not yet done or
confidence not yet earned. The third reason — the mcuboot tier, and the
`west build --sysbuild` it needed — was the one hard dependency, and it was
dropped on 2026-07-26 ([wolfboot-migration.md](wolfboot-migration.md)).

One hazard while both exist: **the pins are stated twice**, as a Zephyr
revision + name-allowlist in `firmware/west.yml` and as explicit SHAs in
`MODULE.bazel`. If they drift, the "reference build" stops being a reference —
it would be proving a different tree from the one Bazel builds. That is now
[a test](#pin-agreement-2026-07-26) rather than a comment.

## Board packages for the other nRF52840 boards (2026-07-27)

Three board packages were added to the overlay patch, modeled on the existing
`seeed/xiao_ble` one:

| Package | Platforms | Verified with `//bazel_smoke:smoke` |
| --- | --- | --- |
| `boards/nordic/nrf52840dk` | `:nrf52840` | FLASH 1 MB @ `0x0`, RAM 256 KB |
| `boards/nordic/nrf52840dongle` | `:nrf52840` | FLASH 1020 KB @ `0x1000`, RAM 256 KB |
| `boards/adafruit/feather_nrf52840` | `:nrf52840`, `:nrf52840_uf2` | FLASH 1 MB @ `0x0`, RAM 256 KB |

`bazel_smoke/` is the reason this was verifiable at all, and it is **no longer
deletable on the "once `//firmware:cantil` builds" condition** in its header
comment: it is now the only app that can exercise a board package whose real
app does not yet build. Delete it when the firmware builds for every board, not
before.

### This does not retire `--cmake` for those boards

The premise of the original item — write the packages and `-b` stops implying
`--cmake` — was wrong, and the packages alone cannot fix it. **All three boards
fail to build the firmware on both build systems**, and did before this change:

- `firmware/boards/{nrf52840dk_nrf52840,nrf52840dongle_nrf52840,adafruit_feather_nrf52840}.conf`
  each set `CONFIG_CANTIL_TRANSPORT_BLE=y`, `CONFIG_BT=y` and `CONFIG_BT_NUS=y`.
- `CONFIG_BT_NUS` is an **NCS** symbol. Upstream Zephyr 4.4's NUS is
  `CONFIG_BT_ZEPHYR_NUS`, at `<zephyr/bluetooth/services/nus.h>`.
- `src/transport/transport_ble.c` includes the NCS path
  `<bluetooth/services/nus.h>` and calls `bt_nus_init` / `bt_nus_send`, and
  `firmware/CMakeLists.txt:101` compiles it under `CONFIG_CANTIL_TRANSPORT_BLE`.

So this is not a Bazel gap — it is the NCS coupling that
[Phase 1](zephyr-upstream.md) removed, still present in the board configs that
nothing has built since. The blocker is
[BLE enablement](ble-enablement.md), not the build system. The board packages
are the half of the work that BLE does not gate, done and verified now so it is
not in the way later.

Two smaller findings, both app-level rather than package-level:

- **The Feather UF2 variant needs `CONFIG_USE_DT_CODE_PARTITION=y` from the
  app.** Unlike `xiao_ble_nrf52840_sense_defconfig`, Zephyr's
  `adafruit_feather_nrf52840_nrf52840_uf2_defconfig` does not set it, so the
  image links at `0x0` across the full 1 MB — over the UF2 bootloader — rather
  than into the partition. `firmware/boards/adafruit_feather_nrf52840.conf`
  does not set it either. Fix that with BLE, not before, since nothing can
  build the target until then.
- **The DK and the base Feather have no CDC ACM node.** Their board DTS files
  do not include `cdc_acm_serial.dtsi` (the dongle's and the Feather UF2's do),
  yet all three confs set `CONFIG_CANTIL_TRANSPORT_USB=y`, and the app overlays
  add only the `cantil,tap-button` node. Those two boards need a `zephyr_udc0`
  / CDC ACM overlay before USB transport works.

### Notes on the packages themselves

- **The dongle compiles `board.c`.** It is the only one of the three with board
  sources: `board_early_init_hook()` raises `REGOUT0` to 3.0 V so the LEDs work
  in USB high-voltage mode. `BOARD_NRF52840DONGLE` selects
  `BOARD_EARLY_INIT_HOOK`, and `kernel/init.c:559` calls the hook with **no weak
  default**, so omitting the source is a link error, not a silent behaviour
  change. It is wired through the `hal_soc_extra_srcs` label flag — the same
  hook the other boards point at `@zephyr//:empty_files`. Verified present in
  the linked ELF, and absent from the other four boards' ELFs.
- **Adafruit's directory name is not its board name** (`feather_nrf52840` vs
  `adafruit_feather_nrf52840`). This turns out not to matter:
  `resolve_board_id` works off the discovery index, which is keyed by package
  path and reads the name from `board.yml`, so platform `:nrf52840` resolves
  through the SoC/variant rule to `adafruit_feather_nrf52840/nrf52840`.
- **`manual_boards` entries are bare board names**, not full board IDs. The
  filter in `setup.bzl:706` matches `board_id == mb or board_id.split("/")[0] ==
  mb`, so `adafruit_feather_nrf52840` covers all its variants — including the
  `sense` ones no platform is defined for.
- **Only the variants something targets are defined.** Not written: the DK's
  `nrf52811` emulation target (it also needs the `DEVELOP_IN_NRF52840` and
  `NRFX_COREDEP_DELAY_US_LOOP_CYCLES` defines from the board CMakeLists), the
  dongle's `bare` variant, and the Feather's two `sense` variants.
- **`generic_nrf52840` got no package, because it is not a board.** It is a
  fork-me template — its own conf says "Fork this config and the matching
  overlay for any nRF52840 board that lacks an IMU or QSPI flash." There is
  nothing in `@zephyr//boards` to write a package against.

## Hermetic zephyr-bazel (2026-07-26)

zephyr-bazel used to be a **machine-local checkout** — `local_path_override`
pointing at `~/zephyr/zephyr-bazel`, with `scripts/setup_bazel.sh` applying the
22-file overlay patch to it by hand. That made the build unreproducible in the
most basic sense: a fresh machine could not build the firmware, and the state of
the checkout was invisible to the repo.

It is now a `git_override` with `patches` in
[MODULE.bazel](../../MODULE.bazel), pinned at the same SHA
(`a7ff7030`) the patch was generated against. Bazel clones and patches it.
`scripts/setup_bazel.sh` is deleted — there is no setup step for Bazel builds
at all:

```bash
bazelisk build //firmware:cantil --config=xiao
bazelisk test //firmware/tests/... --config=sim
```

Verified by moving `~/zephyr/zephyr-bazel` out of the way, deleting the fetched
repo and rebuilding: the firmware links and all 21 sim tests pass from a
git-fetched, Bazel-patched tree. The action cache hit on every action
afterwards, which is the useful proof — the fetched-and-patched tree is
byte-identical to the checkout it replaced.

Advancing the pin now means regenerating the patch (recipe in the MODULE.bazel
comment). That is the same work the local checkout needed; the difference is
that the result is committed rather than living in one developer's home
directory.

### The OpenSSL gate under Bazel (2026-07-26)

**Ported — `bazel test` is now as strong as `scripts/test.sh`.** The gate is the
independent oracle for everything the device *generates*: a suite that mints
certificates cannot be its own judge, because writer and reader come from the
same library and share any misunderstanding of DER between them. Two real bugs
(a CSR emitted with version 2, a certificate with an empty subjectPublicKeyInfo)
would both have survived a wolfCrypt-checks-wolfCrypt test.

`cantil_ztest` gained `openssl_gate = True`, set on the four suites that emit
DER (`sign_csr`, `ca_bootstrap`, `crl_der`, `session_slot`). It adds a
`<suite>_openssl_gate` `sh_test` that runs
[firmware/tests/openssl_gate_runner.sh](../../firmware/tests/openssl_gate_runner.sh):
sets `CANTIL_TEST_ARTIFACT_DIR` to a private dir under `$TEST_TMPDIR`, runs the
suite binary there, then hands the emitted DER to the *same*
[scripts/openssl_gate.sh](../../scripts/openssl_gate.sh) the CMake path uses —
one implementation, two runners, so they cannot drift.

```console
$ bazelisk test //firmware/tests/... --config=sim
//firmware/tests/sign_csr:sign_csr_openssl_gate         PASSED
//firmware/tests/ca_bootstrap:ca_bootstrap_openssl_gate PASSED
//firmware/tests/crl_der:crl_der_openssl_gate           PASSED
//firmware/tests/session_slot:session_slot_openssl_gate PASSED
   ok    generated.csr.der (CSR parses, self-signature verifies)
   ok    signed_leaf.leaf.der (chain verifies to signed_leaf.ca.der)
   …
```

Three details worth keeping:

- **The suite binary runs twice** (once as `<suite>_sim`, once under the gate).
  Bazel tests have no post-run hook and the artifact directory must exist in the
  environment *before* the suite starts. A native_sim suite costs well under a
  second, so a duplicate run is cheaper than any mechanism that would avoid it.
- **`tags = ["no-sandbox"]`** — the gate shells out to the host's `openssl`,
  which is the point: an oracle built by this build system would not be
  independent of it. The gate script already enforces OpenSSL ≥ 3.0.
- **Stricter than `test.sh` in one place:** a gated suite that emits *no*
  artifacts fails. On the CMake path an empty directory passes trivially, so a
  suite that quietly stopped generating DER would keep reporting green — a gate
  that cannot fail is not a gate. Verified by temporarily setting
  `openssl_gate = True` on `protocol_cbor` (which emits nothing): the test
  fails as intended.

## Symbol invariants as build actions (2026-07-26)

The status block at the top of this file reports three properties that were
checked once, by hand, with `arm-zephyr-eabi-nm`: production carries no
formatter, the factory image does, and no `mbedtls_*` code survives anywhere.
Prose is a bad place for a security guarantee. All three are build actions now:

```python
genrule(
    name = "cantil_invariants",
    srcs = [":cantil.elf"],
    cmd = "$(execpath //scripts:check_elf_symbols) $(execpath :cantil.elf) " +
          "--require __wrap_lfs_format --forbid lfs_format " +
          "--forbid __real_lfs_format --forbid fs_mkfs --forbid littlefs_mkfs " +
          "--forbid-pattern '^mbedtls_' --out $@",
    tools = ["//scripts:check_elf_symbols"],
)
```

`//firmware/factory:cantil_factory_invariants` is the mirror image, and the half
that is easier to forget: it `--require`s the formatter. A factory image that
quietly lost `lfs_format` would not fail to build — it would fail at a bench,
leaving an unformatted device, which is a much worse place to find out.

Three decisions worth recording:

- **A genrule, not a test.** The ELF is a cross-compiled artifact inside the
  app's platform transition; a `sh_test` there would be configured for
  `nrf52840_sense` and could not run on the host. Making it a build action is
  the stronger form anyway — `bazel build //firmware:cantil.uf2` cannot produce
  a flashable image that violates it, and there is no `--test_filter` that skips
  it. `scripts/build.sh` builds the invariants target alongside the UF2.
- **The checker parses the symtab itself** rather than shelling out to `nm`
  ([scripts/check_elf_symbols.py](../../scripts/check_elf_symbols.py)). It runs
  in the exec configuration over a target artifact, and pulling
  `arm-zephyr-eabi-nm` into that configuration is far more machinery than
  reading an ELF symbol table needs. It also keeps one implementation for the
  arm and native_sim images.
- **This is parity, not a new idea.** `firmware/CMakeLists.txt` already asserted
  the no-format invariant on the linked ELF, for exactly the reason given there:
  "a board .conf, snippet, sysbuild fragment or a module's Kconfig `select` can
  turn MKFS back on without a word in the build log." The Bazel path had no
  equivalent, which meant the *default* build system was the weaker one.

Verified both ways: the reports read `RESULT: PASS` for both images, and
inverting the assertions (`--require lfs_format` against production) fails with
the offending symbols named.

## Pin agreement (2026-07-26)

`firmware/west.yml` and `MODULE.bazel` state the same pins in two idioms. While
the reference build's whole job is to prove the tree Bazel builds, a silent
drift between them is worse than ordinary duplication: both builds stay green
and the A/B comparison quietly stops meaning anything.

The obstacle is that the two files speak different languages — west names a tag
(`revision: v4.4.0`), Bazel names the commit it peels to (`684c9e8f…`) — and
resolving one to the other needs a network. So each file carries a marker naming
both halves:

```
# PIN: zephyr v4.4.0 684c9e8f32e4373a21098559f748f06915f950c9
```

and `//scripts:pin_agreement_test` closes the loop: the two files' markers must
agree with each other, each marker's commit must be what `MODULE.bazel` really
pins, and each marker's version must be what `west.yml` really names. Any
one-sided edit fails — bump `revision:` and the third check breaks, bump
`commit =` and the second does, touch one marker and the first does.

What stays a human's job is asserting the tag really peels to that commit. That
needs a network and happens once, when the pin moves; the recipe is in the
`MODULE.bazel` comment above the pin.

It runs under `--config=host`, not `--config=sim`: it is a plain text
comparison with no Zephyr in it, and under the sim config its target platform
would be `native_sim`, where a host test cannot run. `scripts/test.sh` runs it
after the suites on a full run.

The cost is real and worth stating: switching config mid-script trips Bazel's
*"build options have changed, discarding analysis cache"*, so a full
`scripts/test.sh` re-analyses (~12 s here) and leaves the sim analysis cold for
the next run. Cheap against 21 suites, and the alternative — a second Bazel
workspace, or making the check a genrule nobody builds — is worse.

## Firmware app port (2026-07-26)

`firmware/BUILD.bazel` defines the app plus three module compile targets. The
external module libraries (wolfSSL, littlefs, SEGGER) are compiled **here**
rather than auto-linked as zephyr-bazel modules, because each needs an include
path this package owns (firmware/include for the wolfCrypt user settings; the
`@littlefs` / `@segger` library headers paired with the `@zephyr` in-tree glue).
wolfSSL stays a discovered **config-only** module so its Kconfig
(`CONFIG_WOLFSSL`) is sourced. Support packages: `//scripts` (the
`encode_session_x509` py_binary → session-x509 genrule), `//common/cbor`, and
empty package-markers at `firmware/factory` and `firmware/tests` so app
discovery's recursive `find -name prj.conf` doesn't collide those onto
`//firmware`.

The nine zephyr-bazel gaps fixed (in the overlay patch):

1. **App `Kconfig` never sourced.** `kconfig_gen_values.py` hard-coded
   `$ZEPHYR_BASE/Kconfig` as the tree root; Zephyr's KCONFIG_ROOT convention
   makes `<app>/Kconfig` the root (it defines the app symbols then
   `source "Kconfig.zephyr"`). Without it every `CANTIL_*` / `PAIRING_*` symbol
   is undefined.
2. **App symbols absent from the global schema.** The per-app platform sets a
   flag for every symbol in the app `.config`, but `@zephyr_kconfig` only had
   Zephyr+module symbols → the flag doesn't exist. Fixed by passing `--app-dirs`
   to `kconfig_gen_symbols.py` (scans app Kconfig via the dynamic-symbol path).
3. **App DTS bindings ignored.** A node using a custom compatible
   (`cantil,tap-button`) in the app overlay parsed, but its typed properties
   (gpios, …) got no macros — the app dir wasn't a DTS root. Added it in both
   the values path (edt bindings) and the symbols path (so the generated
   `CONFIG_DT_HAS_<compat>_ENABLED` exists as a flag).
4. **Board variant.** The transition maps a platform *name* to a board_id;
   `:nrf52840` matched the plain board, not `/sense`. Added a `:nrf52840_sense`
   platform.
5. **USB `device_next`, 3 gaps:** `udc_nrf.c` needed a dep+include on
   `nrf_usbd_common`; `drivers/serial` emitted a literal
   `${ZEPHYR_BASE}/misc/empty_file.c`; and `lib/net_buf` had no generated BUILD
   (undefined `net_buf_*`). Plus `device_next` class sources needed the package
   root on the include path (`usbd_msg.h`).
6. **Cross-repo module headers.** `@zephyr//subsys/fs/littlefs_fs.c` needs
   `<lfs_util.h>` and the `LFS_CONFIG` glue; `log_backend_rtt.c` needs
   `<SEGGER_RTT.h>`. `@zephyr` can't reference an external module repo, so
   littlefs/segger are `inject_repo`'d into `@zephyr` and added as gated deps.
7. **nrfx peripheral drivers.** `hal_nordic.BUILD` shipped only clock/gpiote;
   added NVMC/POWER/PWM/QSPI/SPI(M)/TWI(S)/TWIM/UARTE gated on `CONFIG_NRFX_*`.
8. **App `-Werror`.** Zephyr's CMake doesn't `-Werror` the app library;
   zephyr-bazel does, which turned Zephyr's `__DEPRECATED_MACRO`
   (`FIXED_PARTITION_*` in v4.4) into a hard error. `app_lib` compiles with a
   bare `-Wno-error` to match the reference.
9. **No UF2 output** — added later, see [UF2 output](#uf2-output-2026-07-26).
   `zephyr_app` gained `uf2_family`, and `scripts/build/uf2conv.py` is exposed
   as a `py_binary`. The best upstreaming candidate of the nine: it is
   CMake-side functionality (`CONFIG_BUILD_OUTPUT_UF2`) with no Bazel
   equivalent, and it affects every board whose only flashing route is a
   mass-storage bootloader.

## Blocker status now (2026-07-25)

Re-checked against the current tree (wolfCrypt-only firmware, upstream Zephyr
`v4.4.0`):

| Blocker (2026-07-22) | Status |
| --- | --- |
| 1. Zephyr 4.4 deletes the mbedTLS API | **Gone.** Firmware is wolfCrypt-only. zephyr-bazel pins commit `684c9e8f` = exactly `v4.4.0` in `firmware/west.yml`. |
| 2. `modules/mbedtls.BUILD` (large, disposable) | **Gone.** No mbedTLS. Need `wolfssl.BUILD` (written once, stays) + small `littlefs.BUILD` / `segger.BUILD`. |
| 3. `xiao_ble` board unsupported | **Reduced to a board package.** Board BUILD files are hand-written overlays (`bazel_overlay/boards/<vendor>/<board>/`), not auto-generated; `manual_boards` only filters combos. A `seeed/xiao_ble` package was written and the smoke app links — see below. |

## Phase 1 done: workspace + xiao_ble board (2026-07-25)

Repo-root Bazel workspace (`MODULE.bazel`, `BUILD.bazel`, `.bazelrc`,
`common.bazelrc`, `.bazelversion` = Bazel 8.7.0, `.bazelignore`), adapted from
zephyr-bazel `examples/`. Deviations that mattered: no root package initially
(reverted — `zephyr_setup` needs `//:MODULE.bazel` resolvable, so a minimal root
`BUILD.bazel` is required; `apps_dirs` is narrowed to explicit app packages so
app-discovery never scans the CMake `build_*/` dirs); Pigweed dep inlined; the
two example zephyr patches dropped (not needed for nRF52840).

zephyr-bazel needs three additions (candidates to upstream), captured in
`bazel/zephyr-bazel-cantil.patch`. This originally pointed at a hand-patched
`~/zephyr/zephyr-bazel` via `local_path_override`; it is now fetched and
patched by Bazel — see
[Hermetic zephyr-bazel](#hermetic-zephyr-bazel-2026-07-26).

1. `bazel_overlay/boards/seeed/xiao_ble/BUILD.bazel` — the board package
   (platform `@zephyr//boards/seeed/xiao_ble:nrf52840`), modeled on
   `nordic/nrf52833dk`; soc `@zephyr//soc/nordic/nrf52`, cortex-m4/armv7e-m.
2. `bazel_overlay/boards/BUILD.bazel` — a `common_usb_dts` filegroup so the
   board's `dts_library` can pull in `boards/common/usb/cdc_acm_serial.dtsi`.
3. `modules/hal_nordic.BUILD` — `CONFIG_SOC_NRF52840=true → NRF52840_XXAA`
   (there is no per-part `SOC_COMPATIBLE_NRF52840`; `SOC_NRF52840` is the symbol
   the QIAA/QFAA parts select).

Proof:

```console
$ bazelisk build //bazel_smoke:smoke \
    --platforms=@zephyr//boards/seeed/xiao_ble:nrf52840
Memory region  Used Size  Region Size  %age Used
       FLASH:    20644 B       788 KB      2.56%
         RAM:     6600 B       256 KB      2.52%
INFO: Build completed successfully
```

`bazel_smoke/` is a throwaway app (delete once `//firmware:cantil` builds) that
proves the board + arm-zephyr toolchain + nRF52840 SoC + link in isolation from
Cantil's modules. It disables USB, which surfaced three **zephyr-bazel USB
`device_next` coverage gaps** the real app (Phase 3) must fix, since Cantil needs
USB CDC:

- `drivers/usb/udc` `udc_nrf.c` needs `<nrf_usbd_common.h>` — the generated
  `udc` target has no dep on `@zephyr//drivers/usb/common/nrf_usbd_common`.
- `drivers/serial/BUILD.bazel` emits a literal, unexpanded
  `${ZEPHYR_BASE}/misc/empty_file.c` for `CONFIG_USB_CDC_ACM` /
  `USBD_CDC_ACM_CLASS` — a BUILD-generator (converter) bug.
- `subsys/usb/device_next` + `drivers/usb/common/buf` reference `net_buf_*`
  with no `net_buf` library linked.

Replace CMake/Kconfig with Bazel, using Google's
[`zephyr-bazel`](https://pigweed.googlesource.com/zephyr/zephyr-bazel) (a
Pigweed project) rather than hand-rolling Zephyr build rules.

## What zephyr-bazel is

A Bazel overlay that is applied *on top of* a Zephyr checkout — it does not
fork Zephyr. `MODULE.bazel` declares a `zephyr_patch_file` extension that
fetches Zephyr and patches in the generated `BUILD.bazel` files, after which
apps are ordinary Bazel targets:

```python
zephyr_app(name = "cantil", deps = [":app_main"])
zephyr_cc_library(name = "app_main", srcs = ["main.c"])
```

```bash
bazelisk build //firmware --platforms=//firmware:xiao_ble
```

It is **actively developed** — HEAD was committed the same day this assessment
was written. Boards become Bazel platforms, Kconfig symbols become
`config_setting`s (`@zephyr_kconfig//:CONFIG_FOO=true`), devicetree and
`autoconf.h` generation are wired into the build graph, and `zephyr_sysbuild`
covers multi-image builds. It ships Zephyr SDK 1.0.1 toolchains for arm,
riscv64, xtensa, arc, arm64, mips, rx, sparc and x86 as `http_archive`s —
which is directly useful for Phase 4 and for the multi-compiler goal, since
Pigweed's LLVM toolchain is registered alongside the GCC ones.

So the foundation is real and the parts Cantil would need to write by hand are
smaller than starting from nothing.

## The three blockers

### 1. It pins Zephyr 4.4, which deletes the crypto API Cantil uses

`MODULE.bazel` pins Zephyr at commit `684c9e8f` — `VERSION_MAJOR = 4`,
`VERSION_MINOR = 4`. The pin is manual and openly marked as drifting:

```python
zephyr_patch_file.checkout(
    # The autoroller is broken. Manually update on 2026-5-8.
    commit = "684c9e8f32e4373a21098559f748f06915f950c9",
)
```

Zephyr 4.4 ships **Mbed TLS 4.1**, which removes the legacy `mbedtls_*` crypto
C API in favour of PSA. That is exactly the version
[Phase 1](zephyr-upstream.md) pinned *away* from, for exactly this reason:
`src/crypto/crypto.c`, `src/session/noise_crypto_mbedtls.c` and `src/ca/ca.c`
are written against that API.

Adopting zephyr-bazel today therefore silently drags in the PSA port — the work
Phase 1 deliberately deferred, that Phase 3 makes moot, and that already failed
once on hardware. The patch overlay is generated against a specific Zephyr
tree, so "just pin it to 4.3.1" is not a one-line change; the BUILD files and
the patch would have to be regenerated against v4.3.1 and kept there.

### 2. None of Cantil's non-Zephyr modules have BUILD files

zephyr-bazel covers the Zephyr tree itself — kernel, arch, soc, drivers,
`subsys/` — thoroughly. External Zephyr *modules* are a separate matter: each
needs either its own `BUILD.bazel` using the `zephyr_module` macro, or an
in-tree overlay at `modules/{repo_name}.BUILD`. What exists today:

```
modules/cmsis.BUILD      modules/hal_nordic.BUILD    modules/hal_rpi_pico.BUILD
modules/cmsis_6.BUILD    modules/hal_nxp.BUILD       modules/hal_xtensa.BUILD
modules/hal_atmel.BUILD  modules/openair.BUILD
```

Cantil links eight modules. `cmsis`, `cmsis_6` and `hal_nordic` are covered.
The other four are not, and all four are load-bearing:

| Module | Used for | Effort |
| --- | --- | --- |
| **mbedtls** | the entire CA + Noise crypto layer | **Large.** Hundreds of sources under a generated config system (`Kconfig.psa.auto`, `create_psa_files.py`, `config-tls-generic.h`) that has no Bazel equivalent |
| **littlefs** | key/cert store | Small — `lfs.c`/`lfs_util.c`. Zephyr's `littlefs_fs.c` glue is already covered by `subsys/fs` |
| **segger** | RTT log backend | Small |
| **mcuboot** | `mcuboot` bootloader tier + imgtool signing | Medium — `zephyr_sysbuild` exists, but the signing pipeline and `merged.hex` step do not |

The auto-generated `third_party/zephyr/tests/crypto/mbedtls*/BUILD.bazel`
targets are not evidence to the contrary: they were mechanically generated from
Zephyr's CMakeLists and build only each test's own `src/main.c`. Nothing
provides the mbedtls library itself.

mbedtls is the expensive one, and it is the one that would be thrown away.

### 3. The target board is not supported

Board BUILD files are generated at fetch time, not stored in the repo, so the
coverage is not visible by reading it. Measured against the fetched
`@zephyr` repository:

**20 `BUILD.bazel` files across 973 board directories.** Excluding QEMU,
`native_sim` and shared `common/` dirs, that is **five real hardware boards**:

```text
nordic/nrf52833dk    nxp/mimxrt595_evk    raspberrypi/rpi_pico
tdk/robokit1         raspberrypi/rpi_pico2
```

`seeed/xiao_ble` is not among them, and neither is any other nRF52840 board —
`nrf52833dk` is an nRF52833 (512 KB flash / 128 KB RAM against the 52840's
1 MB / 256 KB). Querying it directly:

```text
ERROR: no such package '@zephyr//boards/seeed/xiao_ble':
BUILD file not found in directory 'boards/seeed/xiao_ble'
```

This one is the least severe of the three. The SoC layer is generic —
`soc/nordic/nrf52/BUILD.bazel` exists and the 52840 variant is selected through
Kconfig and devicetree, not a separate BUILD file — so `nrf52833dk` is a
workable template for writing a `xiao_ble` board package. Call it medium
effort, not a wall. But it does mean the primary target has to be brought up
from scratch, and the same applies to every board in
[M7](../roadmap.md) for Phase 4.

## Recommendation

**Swap Phase 2 and Phase 3 — do wolfSSL first, then Bazel.**

New order: 1 upstream Zephyr ✓ → **2 wolfSSL** → **3 Bazel** → 4 multi-platform.

This is not a deferral; it makes Phase 2 dramatically cheaper and dissolves
both blockers at once:

- **The Mbed TLS 4.x problem disappears entirely.** If wolfCrypt is the crypto
  backend, it does not matter that Zephyr 4.4 deleted the legacy mbedtls API —
  Cantil no longer calls it. The zephyr-bazel 4.4 pin stops being a conflict,
  and the pin can keep rolling forward with upstream as intended.
- **The most expensive BUILD file never has to be written.** wolfSSL is a
  single library with a conventional `configure`-style option set, far easier
  to express in Bazel than mbedtls's generated PSA config machinery. Writing
  `modules/mbedtls.BUILD` only to delete it one phase later is pure waste.
- **It de-risks the harder phase.** Phase 3's own analysis notes the crypto
  abstraction is unusually narrow — 8 functions in `crypto.h`, 6 in
  `noise_crypto.h`, both designed for backend substitution. Doing that swap
  under the known-good CMake build isolates crypto bugs from build-system bugs.
  Doing both at once means every failure has two candidate causes.
- **wolfSSL restores hardware acceleration on the Free path.** It has native
  CC310 support, so it needs neither `nrf_security` nor the Nordic binary
  blobs — which is what
  [zephyr-upstream.md](zephyr-upstream.md) already records as the intended
  replacement for the gated-off ACCELERATED backend.

The one real cost is that wolfSSL is an
[official optional Zephyr module](https://docs.zephyrproject.org/latest/develop/manifest/external/wolfssl.html)
present in the upstream manifest, but it has no BUILD file in zephyr-bazel
either — so a `modules/wolfssl.BUILD` still has to be written. That work is
unavoidable in either order; the difference is that in this order it is written
*once*, against the library that stays.

Note also that Phase 3 carries a licensing decision that is
[still unresolved](wolfssl-migration.md): wolfSSL's open-source license is
GPLv3 (since 5.8.2), and the tree is currently in an inconsistent state — the
Apache 2.0 relicense in `9e84dba` changed `LICENSE` but no source headers, and
deleted the `LICENSE-EXCEPTIONS.md` that 16 files still reference. That should
be settled before wolfSSL work starts, independent of build systems.

## If Phase 2 goes first anyway

Should the ordering stand, the work is roughly:

1. Regenerate the zephyr-bazel overlay against Zephyr v4.3.1, or accept the
   Mbed TLS 4.x port as part of Phase 2. (The latter is the PSA port that
   already failed once; budget accordingly.)
2. Write a `boards/seeed/xiao_ble` package, using `nordic/nrf52833dk` as the
   template, and a platform for `xiao_ble/nrf52840/sense`.
3. Write `modules/mbedtls.BUILD` — the large item, and disposable.
4. Write `modules/littlefs.BUILD` and `modules/segger.BUILD` — small.
5. Port `firmware/CMakeLists.txt`: `zephyr_app` + `zephyr_cc_library`, the
   `encode_session_x509.py` codegen step as a `genrule`, and the STDT_PLAIN
   alphabet guard as a Bazel failure.
6. Port the `mcuboot` tier onto `zephyr_sysbuild`, plus imgtool signing and the
   `merged.hex` merge step.
7. Keep CMake working in parallel until the Bazel build is verified on
   hardware, then retire it.

Run both build systems side by side throughout — the CMake build is the
reference that says whether a Bazel-built image is correct.

## Verified on this machine

The infrastructure itself works — this assessment is not theoretical.

- `bazel` 9.0.0 / `bazelisk` 9.2.0 already installed on the host.
- zephyr-bazel's own `//nrf52` example **builds and links a real Zephyr image**
  for `nrf52833dk`, fetching the LLVM and Zephyr SDK toolchains itself with no
  host setup beyond bazelisk:

  ```console
  $ bazelisk build //nrf52 --platforms=@zephyr//boards/nordic/nrf52833dk:nrf52833
  Memory region         Used Size  Region Size  %age Used
             FLASH:       49788 B       512 KB      9.50%
               RAM:       10760 B       128 KB      8.21%
  INFO: Build completed successfully, 334 total actions
  ```

  334 actions, ~3 minutes cold, ~2 GB of Bazel cache. Note that the platform
  label in `examples/nrf52/README.md` (`//nrf52:nrf52833dk`) is stale and does
  not resolve; the working label is the one above.

So the blockers above are about *coverage* — missing module and board BUILD
files, and an inconvenient Zephyr pin — not about whether the approach works.
That is a good position to be in; it just means the work is real and is best
sequenced after wolfSSL.
