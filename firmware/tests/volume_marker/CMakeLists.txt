# SPDX-License-Identifier: GPL-3.0-or-later
#
# Volume identity marker conformance on native_sim.
#
# Build:
#   ZEPHYR_TOOLCHAIN_VARIANT=host \
#     west build -p -b native_sim firmware/tests/volume_marker --no-sysbuild
#   west build -t run

cmake_minimum_required(VERSION 3.20.0)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(volume_marker_tests LANGUAGES C)

set(FW ${CMAKE_CURRENT_SOURCE_DIR}/../..)

target_sources(app PRIVATE
    src/main.c
    ${FW}/src/crypto/crypto_wolfssl.c
    ${FW}/src/crypto/wc_rand.c
    ${FW}/src/crypto/zeroize.c
    ${FW}/src/storage/storage.c
    ${FW}/src/storage/volume_marker.c
    ${FW}/src/crypto/device_id.c
)

target_include_directories(app PRIVATE
    ${FW}/src
    ${FW}/include
)

zephyr_include_directories(${FW}/include)

# Carries WOLFSSL_USER_SETTINGS / WOLFSSL_ZEPHYR defines.
target_link_libraries(app PRIVATE wolfSSL)
