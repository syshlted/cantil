# SPDX-License-Identifier: GPL-3.0-or-later
#
# Tier-2 conformance: drive ca.c through its real storage layer on native_sim,
# exercising the slot 0 bootstrap flow end-to-end (first boot -> PUSH_KEY_X509
# -> self-signed cert -> crash-recovery cert regen -> protected-slot refusal).
#
# ca.c builds and reads certificates through the wolfCrypt certgen/certparse
# backends — the only ones now that the FREE (mbedTLS) backend is gone. Field
# values are read back with certparse; the DER structure and the self-signature
# are checked independently by the OpenSSL gate (test_10 exports the root).
#
# Build:
#   ZEPHYR_TOOLCHAIN_VARIANT=host \
#     west build -p -b native_sim firmware/tests/ca_bootstrap --no-sysbuild
#   west build -t run

cmake_minimum_required(VERSION 3.20.0)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(ca_bootstrap_tests LANGUAGES C)

set(FW ${CMAKE_CURRENT_SOURCE_DIR}/../..)

target_sources(app PRIVATE
    src/main.c
    ${FW}/src/ca/ca.c
    ${FW}/src/ca/der_write.c
    ${FW}/src/ca/certgen_wolfssl.c
    ${FW}/src/ca/certparse_wolfssl.c
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
