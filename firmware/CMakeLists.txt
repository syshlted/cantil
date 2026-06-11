cmake_minimum_required(VERSION 3.20.0)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(cantil VERSION 0.1.0)

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
        src/transport/transport.c
        src/session/session.c
        src/session/session_slot.c
        src/protocol/protocol.c
        ${CMAKE_CURRENT_SOURCE_DIR}/../common/cbor/cantil_cbor.c
        src/ca/ca.c
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

    # noise_crypto_mbedtls.c implements noise_crypto.h via the legacy
    # mbedtls C API and is the FREE backend's noise primitive provider.
    # When CANTIL_CRYPTO_BACKEND_ACCELERATED is selected, a sibling
    # noise_crypto_psa.c (currently TODO — see CLAUDE.md) takes over and
    # implements the same noise_crypto.h surface against psa_* directly,
    # so the build never pulls in two impls of the same symbols.
    target_sources_ifdef(CONFIG_CANTIL_CRYPTO_BACKEND_FREE app PRIVATE
        src/crypto/crypto.c
        src/session/noise_crypto_mbedtls.c
    )

    target_sources_ifdef(CONFIG_CANTIL_CRYPTO_BACKEND_ACCELERATED app PRIVATE
        src/crypto/crypto_psa.c
        src/session/noise_crypto_psa.c
    )

    target_sources_ifdef(CONFIG_CANTIL_DIAG_BOOT app PRIVATE src/diag_boot.c)

    target_sources_ifdef(CONFIG_CANTIL_BOOTLOADER_MCUBOOT app PRIVATE
        src/fw_update/fw_update.c
    )
endif()

target_include_directories(app PRIVATE src)

# Expose firmware/include globally so mbedtls translation units can find
# cantil_mbedtls_user_config.h (selected via CONFIG_MBEDTLS_USER_CONFIG_FILE).
zephyr_include_directories(include)

# ── Bootloader tier: partition manager file selection ───────────────────────
# NCS auto-discovers pm_static_<board>.yml; for non-default tiers we override
# PM_STATIC_YML_FILE here so the right flash layout is used automatically when
# build.sh passes -DFILE_SUFFIX=uf2_mcuboot or -DFILE_SUFFIX=mcuboot.
if(CONFIG_CANTIL_BOOTLOADER_UF2_MCUBOOT)
    set(PM_STATIC_YML_FILE
        ${CMAKE_CURRENT_SOURCE_DIR}/pm_static_xiao_ble_nrf52840_sense_uf2_mcuboot.yml
        CACHE INTERNAL "")
elseif(CONFIG_CANTIL_BOOTLOADER_MCUBOOT)
    set(PM_STATIC_YML_FILE
        ${CMAKE_CURRENT_SOURCE_DIR}/pm_static_xiao_ble_nrf52840_sense_mcuboot.yml
        CACHE INTERNAL "")
endif()

# ── Firmware image signing (imgtool / MCUboot) ──────────────────────────────
# Custom signing step for non-MCUboot builds only.  When CONFIG_BOOTLOADER_MCUBOOT=y
# NCS's image_signing.cmake handles signing via CONFIG_MCUBOOT_SIGNATURE_KEY_FILE
# (propagated from SB_CONFIG_BOOT_SIGNATURE_KEY_FILE by sysbuild) — do not add a
# second signing step or it will run before zephyr.bin is linked.
if(NOT "${CONFIG_CANTIL_FW_SIGNING_KEY_PATH}" STREQUAL "" AND NOT CONFIG_BOOTLOADER_MCUBOOT)
    # Use the project venv's imgtool directly — the NCS tree also ships an
    # imgtool.py stub that find_program would pick up first, but it lacks the
    # venv's dependencies (click, etc.) and cannot be run standalone.
    set(CANTIL_IMGTOOL ${CMAKE_CURRENT_SOURCE_DIR}/../venv/bin/imgtool)
    if(NOT EXISTS ${CANTIL_IMGTOOL})
        message(FATAL_ERROR "imgtool not found at ${CANTIL_IMGTOOL} — is the project venv set up?")
    endif()
    set(FW_SIGNED_BIN ${CMAKE_BINARY_DIR}/zephyr/zephyr.signed.bin)
    add_custom_command(
        TARGET app POST_BUILD
        COMMAND ${CANTIL_IMGTOOL} sign
            --key   "${CONFIG_CANTIL_FW_SIGNING_KEY_PATH}"
            --version "${CONFIG_CANTIL_FW_IMAGE_VERSION}"
            --header-size 0x200
            --pad-header
            --slot-size "${CONFIG_CANTIL_FW_SLOT_SIZE}"
            ${CMAKE_BINARY_DIR}/zephyr/zephyr.bin
            ${FW_SIGNED_BIN}
        COMMENT "Signing firmware -> zephyr.signed.bin"
        VERBATIM
    )
    message(STATUS "Firmware signing enabled (${CONFIG_CANTIL_FW_SIGNING_KEY_PATH})")
endif()

# Workaround for nrf_security Kconfig gap on the accelerated backend.
#
# nrf_config.cmake calls kconfig_check_and_set_base(MBEDTLS_X509_CRT_WRITE_C),
# which would emit the #define into nrf-config.h — but only if the Kconfig
# symbol CONFIG_MBEDTLS_X509_CRT_WRITE_C is set at the time that macro runs.
# nrf_security's Kconfig.tls exposes every other X.509 sub-knob (USE_C,
# CREATE_C, CRT_PARSE_C, CSR_WRITE_C, etc.) but happens to omit CRT_WRITE_C
# from its public surface, so even a local Kconfig declaration doesn't
# propagate in time. x509write_crt.c itself IS in nrf_security's mbedx509
# source list, gated only by `#if defined(MBEDTLS_X509_CRT_WRITE_C)` —
# define the macro on the mbedx509 target (PUBLIC so callers see it too)
# and the certificate-writing API surface comes back.
if(CONFIG_CANTIL_CRYPTO_BACKEND_ACCELERATED)
    if(TARGET mbedx509)
        target_compile_definitions(mbedx509 PUBLIC MBEDTLS_X509_CRT_WRITE_C)
    endif()
    # Belt-and-braces: also define for our own translation units so #include
    # <mbedtls/x509_crt.h> exposes the mbedtls_x509write_crt_* prototypes
    # regardless of how mbedx509's PUBLIC interface is propagated.
    zephyr_compile_definitions(MBEDTLS_X509_CRT_WRITE_C)
endif()
