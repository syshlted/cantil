# SPDX-License-Identifier: GPL-3.0-or-later WITH cantil-additional-permissions
#
# Client bond store conformance on native_sim (transport + pairing T-15).
# Exercises client_bond.c + storage.c on a simulated LittleFS partition.
#
# Build:
#   ZEPHYR_TOOLCHAIN_VARIANT=host \
#     west build -p -b native_sim firmware/tests/client_bond --no-sysbuild
#   west build -t run

cmake_minimum_required(VERSION 3.20.0)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(client_bond_tests LANGUAGES C)

set(FW ${CMAKE_CURRENT_SOURCE_DIR}/../..)

target_sources(app PRIVATE
    src/main.c
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
