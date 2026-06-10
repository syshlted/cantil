# SPDX-License-Identifier: GPL-3.0-or-later WITH cantil-additional-permissions
#
# Method 5 (PAIRING_CA_ANCHOR_PLUS_PASSKEY) pairing gate conformance on native_sim (T-20).
#
# Drives pairing.c (CA_ANCHOR_PLUS_PASSKEY path) + ca.c + storage.c against a
# simulated LittleFS partition.  Suite setup provisions slot 0 as a CA (the
# trust anchor) and generates a test client cert signed by it.
#
# Build:
#   ZEPHYR_TOOLCHAIN_VARIANT=host \
#     west build -p -b native_sim firmware/tests/pairing_ca_anchor_passkey --no-sysbuild
#   west build -t run

cmake_minimum_required(VERSION 3.20.0)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(pairing_ca_anchor_passkey_tests LANGUAGES C)

set(FW ${CMAKE_CURRENT_SOURCE_DIR}/../..)

target_sources(app PRIVATE
    src/main.c
    src/session_stub.c
    src/gesture_stub.c
    src/led_stub.c
    ${FW}/src/clients/pairing.c
    ${FW}/src/clients/client_bond.c
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
