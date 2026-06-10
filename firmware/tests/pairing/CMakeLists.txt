# SPDX-License-Identifier: GPL-3.0-or-later WITH cantil-additional-permissions
#
# Pairing gate conformance on native_sim (transport + pairing T-16).
# Exercises pairing.c + client_bond.c + storage.c on a simulated LittleFS
# partition, with PAIRING_TOFU=y selected via prj.conf.
#
# Build:
#   ZEPHYR_TOOLCHAIN_VARIANT=host \
#     west build -p -b native_sim firmware/tests/pairing --no-sysbuild
#   west build -t run

cmake_minimum_required(VERSION 3.20.0)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(pairing_tests LANGUAGES C)

set(FW ${CMAKE_CURRENT_SOURCE_DIR}/../..)

target_sources(app PRIVATE
    src/main.c
    src/gesture_stub.c
    ${FW}/src/clients/pairing.c
    ${FW}/src/clients/client_bond.c
    ${FW}/src/storage/storage.c
    ${FW}/src/crypto/crypto.c
    ${FW}/../common/cbor/cantil_cbor.c
)

target_include_directories(app PRIVATE
    ${FW}/src
    ${FW}/include
    ${FW}/../common/cbor
)

zephyr_include_directories(${FW}/include)
