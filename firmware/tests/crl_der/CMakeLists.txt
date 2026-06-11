# SPDX-License-Identifier: GPL-3.0-or-later WITH cantil-additional-permissions
#
# RFC 5280 v2 CRL DER export — task 2 of the CRL roadmap.
#
# Builds the firmware CA + storage layers against ztest on native_sim and
# drives ca_get_crl() / ca_revoke_cert() end-to-end. Each test parses the
# returned DER with mbedtls_x509_crl_parse_der and verifies the signature
# against the issuing slot's public key.
#
# Build:
#   ZEPHYR_TOOLCHAIN_VARIANT=host \
#     west build -p -b native_sim firmware/tests/crl_der --no-sysbuild
#   west build -t run

cmake_minimum_required(VERSION 3.20.0)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(crl_der_tests LANGUAGES C)

set(FW ${CMAKE_CURRENT_SOURCE_DIR}/../..)

target_sources(app PRIVATE
    src/main.c
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
