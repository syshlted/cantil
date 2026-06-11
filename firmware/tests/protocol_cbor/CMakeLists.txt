# SPDX-License-Identifier: GPL-3.0-or-later WITH cantil-additional-permissions
#
# Wire-protocol CBOR codec conformance on native_sim.
#
# Build:
#   ZEPHYR_TOOLCHAIN_VARIANT=host \
#     west build -p -b native_sim firmware/tests/protocol_cbor --no-sysbuild
#   west build -t run

cmake_minimum_required(VERSION 3.20.0)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(protocol_cbor_tests LANGUAGES C)

set(REPO ${CMAKE_CURRENT_SOURCE_DIR}/../../..)

target_sources(app PRIVATE
    src/main.c
    ${REPO}/common/cbor/cantil_cbor.c
)

target_include_directories(app PRIVATE
    ${REPO}/common/cbor
)
