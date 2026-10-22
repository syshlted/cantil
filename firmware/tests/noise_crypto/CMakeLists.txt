# SPDX-License-Identifier: GPL-3.0-or-later
#
# ztest suite for noise_crypto_wolfssl.c — RFC/known-answer vectors for the six
# primitives that back the Noise_XX state machine.
#
# A sibling directory used to run this same src/main.c against the mbedTLS
# backend, and that cross-check is what made the vectors meaningful while two
# backends existed. It is not what makes them meaningful now: gen_vectors.py
# produces every vector from published test data and Python, so a pass says
# wolfCrypt agrees with a third implementation rather than with itself. That
# matters beyond this device — a host speaking Noise to it derives the same
# keys from the same standard, and a handshake fails opaquely if they diverge.
#
# Build + run:
#   ./scripts/test.sh noise_crypto

cmake_minimum_required(VERSION 3.20.0)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(noise_crypto_tests LANGUAGES C)

set(FW ${CMAKE_CURRENT_SOURCE_DIR}/../..)

target_sources(app PRIVATE
    src/main.c
    ${FW}/src/session/noise_crypto_wolfssl.c
    ${FW}/src/crypto/zeroize.c
    ${FW}/src/crypto/wc_rand.c
)

target_include_directories(app PRIVATE
    src
    ${FW}/src
    ${FW}/src/session
)

# cantil_wolfssl_user_settings.h lives here; the wolfSSL module resolves
# CONFIG_WOLFSSL_SETTINGS_FILE against the include path.
zephyr_include_directories(${FW}/include)

# Carries WOLFSSL_USER_SETTINGS / WOLFSSL_ZEPHYR.  Without it `app` would
# compile the wolfssl headers under a different configuration than the library
# was built with — which fails in ways that look like ABI corruption rather
# than a missing define.
target_link_libraries(app PRIVATE wolfSSL)
