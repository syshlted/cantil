# SPDX-License-Identifier: GPL-3.0-or-later
#
# RFC 5280 v2 CRL DER conformance — task 2 of the CRL roadmap.
#
# Builds the firmware CA + storage layers against ztest on native_sim and
# drives ca_get_crl() / ca_revoke_cert() end-to-end. Each returned CRL is read
# with a self-contained forward-DER walker in src/main.c (certparse reads certs
# and CSRs, not CRLs), and the DER structure + signature are checked
# independently by scripts/openssl_gate.sh via test_13's artifact export.
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
    ${FW}/src/ca/der_write.c
    ${FW}/src/ca/certparse_wolfssl.c
    ${FW}/src/ca/certgen_wolfssl.c
    ${FW}/src/crypto/crypto_wolfssl.c
    ${FW}/src/crypto/wc_rand.c
    ${FW}/src/crypto/zeroize.c
    ${FW}/src/storage/storage.c
    ${FW}/src/storage/volume_marker.c
    ${FW}/src/crypto/device_id.c
    ${FW}/../common/cbor/cantil_cbor.c
)

target_include_directories(app PRIVATE
    ${FW}/src
    ${FW}/include
    ${FW}/tests/common
    ${FW}/../common/cbor
)

# cantil_wolfssl_user_settings.h lives here.
zephyr_include_directories(${FW}/include)

# Carries WOLFSSL_USER_SETTINGS / WOLFSSL_ZEPHYR defines.
target_link_libraries(app PRIVATE wolfSSL)
