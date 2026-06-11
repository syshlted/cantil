# SPDX-License-Identifier: GPL-3.0-or-later WITH cantil-additional-permissions
#
# T-04 conformance: drive session.c's responder over a loopback transport with
# a live in-test Noise_XX initiator, and assert the device identity cert chain
# carried on encrypted msg2 round-trips intact for empty / single / 3-cert
# chains. The responder's keypairs and the chain it emits are injected via
# test_inject.c (CONFIG_CANTIL_TEST_INJECT_NOISE_KEYS).
#
# Build (native_sim needs the host toolchain, not gnuarmemb):
#   ZEPHYR_TOOLCHAIN_VARIANT=host \
#     west build -p -b native_sim firmware/tests/session_chain --no-sysbuild
#   west build -t run

cmake_minimum_required(VERSION 3.20.0)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(session_chain_tests LANGUAGES C)

set(FW ${CMAKE_CURRENT_SOURCE_DIR}/../..)
set(NOISE ${CMAKE_CURRENT_SOURCE_DIR}/../noise_session/src)

target_sources(app PRIVATE
    src/main.c
    src/test_inject.c
    ${NOISE}/loopback.c
    ${FW}/src/session/session.c
    ${FW}/src/session/noise_crypto_mbedtls.c
    ${FW}/../common/cbor/cantil_cbor.c
)

target_include_directories(app PRIVATE
    src
    ${NOISE}
    ${FW}/src
    ${FW}/src/session
    ${FW}/../common/cbor
)
