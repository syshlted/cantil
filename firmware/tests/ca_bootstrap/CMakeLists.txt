# SPDX-License-Identifier: GPL-3.0-or-later WITH cantil-additional-permissions
#
# Tier-2 conformance: drive ca.c through its real storage layer on native_sim,
# exercising the slot 0 bootstrap flow end-to-end (first boot -> PUSH_KEY_X509
# -> self-signed cert -> crash-recovery cert regen -> protected-slot refusal).
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
