# SPDX-License-Identifier: GPL-3.0-or-later
#
# SIGN_CSR (CMD 0x01) conformance on native_sim.
#
# Drives ca_sign_csr() end-to-end against the real storage layer:
# provision slot 0, push x509, generate a fresh P-256 CSR, sign it, then
# parse the resulting cert and verify issuer/subject/signature/store layout.
#
# Build:
#   ZEPHYR_TOOLCHAIN_VARIANT=host \
#     west build -p -b native_sim firmware/tests/sign_csr --no-sysbuild
#   west build -t run

cmake_minimum_required(VERSION 3.20.0)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(sign_csr_tests LANGUAGES C)

set(FW ${CMAKE_CURRENT_SOURCE_DIR}/../..)

target_sources(app PRIVATE
    src/main.c
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
