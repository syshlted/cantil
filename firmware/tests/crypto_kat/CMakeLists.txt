# SPDX-License-Identifier: GPL-3.0-or-later
#
# Known-answer tests for crypto.h against the wolfCrypt backend
# (src/crypto/crypto_wolfssl.c).
#
# There used to be a second directory here running the same src/main.c against
# the mbedTLS backend, and that cross-check is what made the vectors meaningful
# while two backends existed. It is not what makes them meaningful now: every
# vector in src/vectors.h comes from a third implementation (RFC 6979 §A.2.5,
# RFC 5869 TC1, and Python's hmac/AESGCM), so a pass says wolfCrypt agrees with
# the standard rather than with itself. See gen_vectors.py.
#
# Build + run:
#   ./scripts/test.sh crypto_kat

cmake_minimum_required(VERSION 3.20.0)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(crypto_kat_tests LANGUAGES C)

set(FW ${CMAKE_CURRENT_SOURCE_DIR}/../..)

target_sources(app PRIVATE
    src/main.c
    ${FW}/src/crypto/crypto_wolfssl.c
    ${FW}/src/crypto/zeroize.c
    ${FW}/src/crypto/wc_rand.c
    ${FW}/src/crypto/device_id.c
)

target_include_directories(app PRIVATE
    src
    ${FW}/src
    ${FW}/src/crypto
)

# cantil_wolfssl_user_settings.h lives here.
zephyr_include_directories(${FW}/include)

# Carries WOLFSSL_USER_SETTINGS / WOLFSSL_ZEPHYR.
target_link_libraries(app PRIVATE wolfSSL)
