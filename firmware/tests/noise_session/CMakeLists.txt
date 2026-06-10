# SPDX-License-Identifier: GPL-3.0-or-later WITH cantil-additional-permissions
#
# Tier-2 conformance: drive session.c through a loopback transport on
# native_sim, with the responder's static + ephemeral keypairs injected
# from a precomputed Noise_XX_25519_ChaChaPoly_SHA256 trace.  Two ZTEST
# suites run in parallel:
#   - noise_session            — fixed 0x11/0x22/0x33/0x44 keys (regression)
#   - noise_session_cacophony  — keys from the published Cacophony reference
#     vector, re-derived through primitives that have been independently
#     validated against the full Cacophony trace (gen_cacophony_vector.py).
#
# Build (native_sim needs the host toolchain, not gnuarmemb):
#   ZEPHYR_TOOLCHAIN_VARIANT=host \
#     west build -p -b native_sim firmware/tests/noise_session --no-sysbuild
#   west build -t run
#
# Regenerate vectors after touching noise_xx_ref.py:
#   python3 gen_xx_vector.py
#   python3 gen_cacophony_vector.py   # also validates against cacophony.txt

cmake_minimum_required(VERSION 3.20.0)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(noise_session_tests LANGUAGES C)

set(FW ${CMAKE_CURRENT_SOURCE_DIR}/../..)

target_sources(app PRIVATE
    src/main.c
    src/main_cacophony.c
    src/loopback.c
    src/test_inject.c
    ${FW}/src/session/session.c
    ${FW}/src/session/noise_crypto_mbedtls.c
    ${FW}/../common/cbor/cantil_cbor.c
)

target_include_directories(app PRIVATE
    src
    ${FW}/src
    ${FW}/src/session
    ${FW}/../common/cbor
)
