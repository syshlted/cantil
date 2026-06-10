# SPDX-License-Identifier: GPL-3.0-or-later WITH cantil-additional-permissions
#
# Method 4 (PAIRING_CA_ANCHOR) pairing gate conformance on native_sim (T-19).
#
# Drives pairing.c (CA_ANCHOR path) + ca.c + storage.c against a simulated
# LittleFS partition.  A session stub injects client cert chains; ca.c
# (provisioned with a real slot-0 CA) is used to sign test client certs.
#
# Build:
#   ZEPHYR_TOOLCHAIN_VARIANT=host \
#     west build -p -b native_sim firmware/tests/pairing_ca_anchor --no-sysbuild
#   west build -t run

cmake_minimum_required(VERSION 3.20.0)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(pairing_ca_anchor_tests LANGUAGES C)

set(FW ${CMAKE_CURRENT_SOURCE_DIR}/../..)

target_sources(app PRIVATE
    src/main.c
    src/session_stub.c
    ${FW}/src/clients/pairing.c
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

zephyr_include_directories(${FW}/include)
