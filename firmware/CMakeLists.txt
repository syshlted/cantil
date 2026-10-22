# SPDX-License-Identifier: GPL-3.0-or-later

cmake_minimum_required(VERSION 3.20.0)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(cantil VERSION 0.2.0)

# STDT_PLAIN tap alphabet is the least-secure option (1 bit per tap).
# Refuse to build it unless the user has explicitly acknowledged the trade-off
# by also setting CONFIG_CANTIL_ALPHABET_STDT_PLAIN_I_UNDERSTAND=y.
if(CONFIG_CANTIL_ALPHABET_STDT_PLAIN AND NOT CONFIG_CANTIL_ALPHABET_STDT_PLAIN_I_UNDERSTAND)
    message(WARNING
        "================================================================\n"
        "  CANTIL_ALPHABET_STDT_PLAIN selected.\n"
        "\n"
        "  This alphabet uses raw single-tap / double-tap, giving only one\n"
        "  bit of entropy per tap. A 4-tap unlock is just 16 combinations.\n"
        "\n"
        "  This is a developer escape hatch for early bring-up. The\n"
        "  default (CANTIL_ALPHABET_COUNT_COLOR) gives 1296+ combinations\n"
        "  for the same input effort.\n"
        "\n"
        "  To proceed anyway, set:\n"
        "      CONFIG_CANTIL_ALPHABET_STDT_PLAIN_I_UNDERSTAND=y\n"
        "  in your project or board .conf file.\n"
        "================================================================")
    message(FATAL_ERROR
        "CANTIL_ALPHABET_STDT_PLAIN requires explicit confirmation. "
        "Add CONFIG_CANTIL_ALPHABET_STDT_PLAIN_I_UNDERSTAND=y to proceed.")
endif()

if(CONFIG_CANTIL_PDM_SMOKETEST)
    # Diagnostic build: only the PDM smoke-test main is compiled.
    # The production CA stack (Noise, CBOR, LittleFS, gesture, transport)
    # is gated out so this build has a minimal surface area.
    target_sources(app PRIVATE src/pdm_smoketest/pdm_smoketest.c)
else()
    target_sources(app PRIVATE
        src/main.c
        src/gesture/gesture.c
        src/led/led.c
        src/storage/storage.c
        src/storage/volume_marker.c
        src/crypto/device_id.c
        src/crypto/zeroize.c
        src/transport/transport.c
        src/session/session.c
        src/session/session_slot.c
        src/protocol/protocol.c
        ${CMAKE_CURRENT_SOURCE_DIR}/../common/cbor/cantil_cbor.c
        src/ca/ca.c
        src/ca/der_write.c
        src/clients/client_bond.c
        src/clients/pairing.c
        src/names/names.c
        src/names/names_data.c
    )

    target_include_directories(app PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/../common/cbor
    )

    # ── Session X.509 identity constant (transport + pairing T-01) ──
    # Parse the TOML identity source into a packed x509_data_t blob and emit it
    # as a C array linked into the firmware. The custom command exits non-zero
    # (failing the build) if the TOML is missing, malformed, or sets a
    # disallowed key-usage bit. CONFIG_CANTIL_SESSION_X509_TOML is relative to
    # this firmware/ source directory.
    string(STRIP "${CONFIG_CANTIL_SESSION_X509_TOML}" SESSION_X509_TOML_REL)
    set(SESSION_X509_TOML ${CMAKE_CURRENT_SOURCE_DIR}/${SESSION_X509_TOML_REL})
    set(SESSION_X509_GEN ${CMAKE_CURRENT_BINARY_DIR}/cantil_session_x509_constant.c)
    add_custom_command(
        OUTPUT ${SESSION_X509_GEN}
        COMMAND ${PYTHON_EXECUTABLE}
                ${CMAKE_CURRENT_SOURCE_DIR}/../scripts/encode_session_x509.py
                ${SESSION_X509_TOML}
                --c ${SESSION_X509_GEN}
        DEPENDS ${SESSION_X509_TOML}
                ${CMAKE_CURRENT_SOURCE_DIR}/../scripts/encode_session_x509.py
        COMMENT "Encoding session X.509 identity constant from ${SESSION_X509_TOML_REL}"
        VERBATIM
    )
    target_sources(app PRIVATE ${SESSION_X509_GEN})

    target_sources_ifdef(CONFIG_CANTIL_INPUT_IMU app PRIVATE
        src/gesture/tap_imu.c
    )

    target_sources_ifdef(CONFIG_CANTIL_INPUT_BUTTON app PRIVATE
        src/gesture/tap_button.c
    )

    target_sources_ifdef(CONFIG_CANTIL_INPUT_MIC app PRIVATE
        src/gesture/tap_mic.c
    )

    target_sources_ifdef(CONFIG_CANTIL_TRANSPORT_USB app PRIVATE
        src/transport/transport_usb.c
    )

    target_sources_ifdef(CONFIG_CANTIL_TRANSPORT_BLE app PRIVATE
        src/transport/transport_ble.c
    )

    # wolfCrypt backs all four crypto interfaces — crypto.h, noise_crypto.h,
    # ca/certgen.h (X.509 writer) and ca/certparse.h (reader). It is the only
    # backend since the FREE (in-tree mbedTLS) one was removed at the end of
    # docs/roadmap/wolfssl-migration.md. Linking the wolfSSL target carries the
    # WOLFSSL_USER_SETTINGS / WOLFSSL_ZEPHYR defines its headers need, so `app`
    # compiles them under the same configuration the library was built with.
    target_sources(app PRIVATE
        src/crypto/crypto_wolfssl.c
        src/crypto/wc_rand.c
        src/session/noise_crypto_wolfssl.c
        src/ca/certgen_wolfssl.c
        src/ca/certparse_wolfssl.c
    )
    target_link_libraries(app PRIVATE wolfSSL)

    target_sources_ifdef(CONFIG_CANTIL_DIAG_BOOT app PRIVATE src/diag_boot.c)
endif()

target_include_directories(app PRIVATE src)

# Expose firmware/include globally so the wolfssl module finds
# cantil_wolfssl_user_settings.h (CONFIG_WOLFSSL_SETTINGS_FILE).
zephyr_include_directories(include)

# ── Bootloader tier: flash layout ───────────────────────────────────────────
# Flash layout used to come from NCS's Partition Manager (pm_static_*.yml,
# selected here via PM_STATIC_YML_FILE).  Partition Manager is an sdk-nrf
# feature with no upstream equivalent, so on upstream Zephyr the layout is
# expressed as devicetree `fixed-partitions` in the board overlays:
#
#   boards/xiao_ble_nrf52840_sense.overlay          uf2_only tier
#
# Nothing to do here — devicetree is applied by the normal overlay mechanism.
# There is one tier again: the mcuboot tier's overlay, and the sysbuild
# boot_partition / slot0_partition / slot1_partition layout it defined, were
# dropped 2026-07-26 (docs/roadmap/wolfboot-migration.md). wolfBoot will need a
# BOOT/UPDATE/SWAP layout of its own.

# ── No filesystem-format entry point: enforcement, then verification ────────
# prj.conf sets CONFIG_FILE_SYSTEM_MKFS=n so that fs_mkfs() and the littlefs
# mkfs op are not compiled into an image that holds an unexportable CA key.
# That leaves littlefs's own lfs_format(), which littlefs_mount() calls from an
# unconditionally-compiled branch gated only at runtime — the branch that
# erased unit #2. --wrap redirects it to a wrapper that refuses (see
# src/storage/no_format.c), and with nothing left referencing the real one,
# --gc-sections drops it from the image.
#
# The assertion then checks the linked ELF rather than the config, because a
# board .conf, snippet, sysbuild fragment or a module's Kconfig `select` can
# turn MKFS back on without a word in the build log — and because a --wrap flag
# that silently stopped applying looks exactly like one that worked.
#
# It runs as its own ALL target ordered after zephyr_final rather than as a
# POST_BUILD on it: zephyr_final is created in Zephyr's own directory, and
# add_custom_command(TARGET) is only legal in the directory that created the
# target. Hanging it off `app` instead would run it before zephyr.elf is linked.
#
# The Bazel path asserts the same thing (and more) from
# //firmware:cantil_invariants, via scripts/check_elf_symbols.py.
if(NOT CONFIG_FILE_SYSTEM_MKFS AND NOT CONFIG_CANTIL_PDM_SMOKETEST)
    target_sources(app PRIVATE src/storage/no_format.c)
    target_link_options(app PUBLIC -Wl,--wrap=lfs_format)

    if(NOT TARGET zephyr_final)
        message(FATAL_ERROR
            "Cannot order the no-format assertion: no zephyr_final target. "
            "Zephyr's build structure has changed; fix the hook rather than "
            "shipping an image whose format entry points are unverified.")
    endif()
    add_custom_target(cantil_assert_no_mkfs ALL
        COMMAND ${CMAKE_COMMAND}
            -DNM=${CMAKE_NM}
            -DELF=${CMAKE_BINARY_DIR}/zephyr/zephyr.elf
            -P ${CMAKE_CURRENT_SOURCE_DIR}/cmake/assert_no_mkfs.cmake
        COMMENT "Checking no format entry point was linked"
        VERBATIM
    )
    add_dependencies(cantil_assert_no_mkfs zephyr_final)
endif()

# (The nrf_security MBEDTLS_X509_CRT_WRITE_C workaround that lived here went
# with the ACCELERATED backend on 2026-07-23. It only ever applied to
# sdk-nrf builds; upstream Zephyr declares the symbol itself and prj.conf sets
# it directly.)
