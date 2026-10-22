# SPDX-License-Identifier: GPL-3.0-or-later
#
# Transport + pairing T-02 conformance: drive session_slot.c through its real
# storage + CA crypto path on native_sim. Exercises first-boot identity keygen,
# self-signed cert generation, the X25519-key binding extension, and the
# no-op re-init path.
#
# Build:
#   ZEPHYR_TOOLCHAIN_VARIANT=host \
#     west build -p -b native_sim firmware/tests/session_slot --no-sysbuild
#   west build -t run

cmake_minimum_required(VERSION 3.20.0)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(session_slot_tests LANGUAGES C)

set(FW ${CMAKE_CURRENT_SOURCE_DIR}/../..)

# Encode the real session X.509 identity constant from the production TOML,
# exactly as firmware/CMakeLists.txt does. The test links the generated array
# so it exercises the build-time constant session_slot_init() consumes.
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
    ${FW}/src/session/noise_crypto_wolfssl.c
    ${FW}/src/ca/ca.c
    ${FW}/src/ca/der_write.c
    ${FW}/src/ca/certparse_wolfssl.c
    ${FW}/src/ca/certgen_wolfssl.c
    ${FW}/src/crypto/crypto_wolfssl.c
    ${FW}/src/crypto/wc_rand.c
    ${FW}/src/crypto/zeroize.c
    ${FW}/src/storage/storage.c
    ${FW}/src/storage/volume_marker.c
    ${FW}/src/crypto/device_id.c
    ${FW}/../common/cbor/cantil_cbor.c
)

target_include_directories(app PRIVATE
    ${FW}/src
    ${FW}/include
    ${FW}/tests/common
    ${FW}/../common/cbor
)

# cantil_wolfssl_user_settings.h lives here.
zephyr_include_directories(${FW}/include)

# Carries WOLFSSL_USER_SETTINGS / WOLFSSL_ZEPHYR defines.
target_link_libraries(app PRIVATE wolfSSL)
