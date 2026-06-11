# SPDX-License-Identifier: GPL-3.0-or-later WITH cantil-additional-permissions
#
# ztest suite for noise_crypto_mbedtls.c — RFC/known-answer vectors for the
# six primitives that back the Noise_XX state machine.
#
# Build:
#   ./scripts/dbox.sh west build -b native_sim firmware/tests/noise_crypto
#   ./scripts/dbox.sh west build -t run -d build/

cmake_minimum_required(VERSION 3.20.0)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(noise_crypto_tests LANGUAGES C)

set(FW ${CMAKE_CURRENT_SOURCE_DIR}/../..)

target_sources(app PRIVATE
    src/main.c
    ${FW}/src/session/noise_crypto_mbedtls.c
)

target_include_directories(app PRIVATE
    src
    ${FW}/src
    ${FW}/src/session
)
