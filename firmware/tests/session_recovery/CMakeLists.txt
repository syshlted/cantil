# SPDX-License-Identifier: GPL-3.0-or-later WITH cantil-additional-permissions
#
# Transport + pairing T-03 strict-mode conformance: build session_slot.c with
# CONFIG_CANTIL_SESSION_X509_STRICT=y and confirm that a stored session cert
# whose identity fields no longer match the build constant latches recovery
# mode, while a matching cert does not. The non-strict comparison helper and
# warn-continue path are covered by the session_slot test app.
#
# Build:
#   ZEPHYR_TOOLCHAIN_VARIANT=host \
#     west build -p -b native_sim firmware/tests/session_recovery --no-sysbuild
#   west build -t run

cmake_minimum_required(VERSION 3.20.0)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(session_recovery_tests LANGUAGES C)

set(FW ${CMAKE_CURRENT_SOURCE_DIR}/../..)

# Encode the real session X.509 identity constant from the production TOML.
set(SESSION_X509_TOML ${FW}/session_x509.toml)
set(SESSION_X509_GEN ${CMAKE_CURRENT_BINARY_DIR}/cantil_session_x509_constant.c)
add_custom_command(
    OUTPUT ${SESSION_X509_GEN}
    COMMAND ${PYTHON_EXECUTABLE}
            ${FW}/../scripts/encode_session_x509.py
            ${SESSION_X509_TOML}
            --c ${SESSION_X509_GEN}
    DEPENDS ${SESSION_X509_TOML}
            ${FW}/../scripts/encode_session_x509.py
    COMMENT "Encoding session X.509 identity constant for ztest"
    VERBATIM
)

target_sources(app PRIVATE
    src/main.c
    ${SESSION_X509_GEN}
    ${FW}/src/session/session_slot.c
    ${FW}/src/session/noise_crypto_mbedtls.c
    ${FW}/src/ca/ca.c
    ${FW}/src/crypto/crypto.c
    ${FW}/src/storage/storage.c
    ${FW}/../common/cbor/cantil_cbor.c
)

target_include_directories(app PRIVATE
    ${FW}/src
    ${FW}/include
    ${FW}/../common/cbor
)

# Expose firmware/include globally so mbedtls translation units can find
# cantil_mbedtls_user_config.h (selected via CONFIG_MBEDTLS_USER_CONFIG_FILE).
zephyr_include_directories(${FW}/include)
