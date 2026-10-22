# SPDX-License-Identifier: GPL-3.0-or-later

cmake_minimum_required(VERSION 3.16)
project(libcantil C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_EXTENSIONS OFF)

find_package(PkgConfig REQUIRED)
pkg_check_modules(SODIUM REQUIRED libsodium)

# ── X.509 backend ─────────────────────────────────────────────────────────
#
# Step 5 of docs/roadmap/wolfssl-migration.md, then the mbedTLS drop of
# 2026-07-24. Everything libcantil needs from a certificate library is the three
# functions in src/x509.h; exactly one implementation is compiled, so the
# backends never collide.
#
#   openssl  default — libcrypto is the certificate library a Linux host is most
#                      likely to already have, and it is the same third
#                      implementation the test fixtures (tests/gen_fixtures.sh)
#                      and the firmware's OpenSSL gate are generated from.
#   wolfssl  matches the firmware's library, so a client built this way shares a
#                      DER implementation with the device. Not packaged by
#                      Fedora; build one with scripts/setup_wolfssl_host.sh.
#
# The mbedTLS backend was removed here when the firmware went wolfCrypt-only —
# keeping a third certificate library the project no longer uses anywhere bought
# nothing. Its history is in git if it is ever wanted back.
#
# libsodium is required regardless — it provides the Noise transport and the
# Tier 2 fingerprint hash, neither of which is X.509 work.
set(CANTIL_HOST_CRYPTO "openssl" CACHE STRING
    "X.509 backend for libcantil: openssl or wolfssl")
set_property(CACHE CANTIL_HOST_CRYPTO PROPERTY STRINGS openssl wolfssl)

if(CANTIL_HOST_CRYPTO STREQUAL "openssl")
    pkg_check_modules(X509 REQUIRED libcrypto)
    set(CANTIL_X509_SRC src/x509_openssl.c)
    # No static archive: libcrypto.so is a base-system library present on
    # effectively every Linux target, distros (Fedora included) ship no
    # libcrypto.a, and upstream OpenSSL discourages fully-static linking. So it
    # is linked dynamically even under CANTIL_CLI_STATIC — that option exists to
    # bundle libsodium, which is *not* universally present, not libcrypto.
    set(CANTIL_X509_STATIC_NAMES "")
elseif(CANTIL_HOST_CRYPTO STREQUAL "wolfssl")
    pkg_check_modules(X509 REQUIRED wolfssl)
    set(CANTIL_X509_SRC src/x509_wolfssl.c)
    set(CANTIL_X509_STATIC_NAMES libwolfssl.a)
else()
    message(FATAL_ERROR
        "CANTIL_HOST_CRYPTO must be openssl or wolfssl "
        "(got '${CANTIL_HOST_CRYPTO}')")
endif()

message(STATUS "libcantil X.509 backend: ${CANTIL_HOST_CRYPTO}")

# ── libcantil ─────────────────────────────────────────────────────────────
add_library(cantil STATIC
    src/transport.c
    src/transport_usb.c
    src/discover_usb.c
    src/session.c
    src/trust.c
    ${CANTIL_X509_SRC}
    src/key_store.c
    src/device.c
    src/ca.c
    src/clients.c
    src/pairing.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../common/cbor/cantil_cbor.c
)

target_include_directories(cantil
    PUBLIC  include
    PRIVATE src ${SODIUM_INCLUDE_DIRS} ${X509_INCLUDE_DIRS}
            ${CMAKE_CURRENT_SOURCE_DIR}/../common/cbor
)

target_compile_options(cantil PRIVATE
    -Wall -Wextra -Wpedantic
    ${SODIUM_CFLAGS_OTHER} ${X509_CFLAGS_OTHER}
)

# libcantil is a STATIC library, so its dependencies are "private" in the
# sense that consumers must provide them at link time. Marking PRIVATE keeps
# CMake from auto-propagating them onto the CLI's link line.
target_link_libraries(cantil PRIVATE ${SODIUM_LIBRARIES} ${X509_LIBRARIES})
target_link_directories(cantil PRIVATE ${X509_LIBRARY_DIRS})

# ── cantil CLI tool ────────────────────────────────────────────────────────
#
# CANTIL_CLI_STATIC=ON statically links libsodium into the CLI so the binary
# has no runtime dependencies beyond glibc. Used by scripts/build-appimage.sh
# to produce a self-contained AppImage.
option(CANTIL_CLI_STATIC "Statically link the cantil CLI (AppImage builds)" OFF)

add_executable(cantil-cli cli/main.c)

set_target_properties(cantil-cli PROPERTIES OUTPUT_NAME cantil)

target_include_directories(cantil-cli PRIVATE ${SODIUM_INCLUDE_DIRS} ${X509_INCLUDE_DIRS})
target_compile_options(cantil-cli PRIVATE -Wall -Wextra ${SODIUM_CFLAGS_OTHER})

if(CANTIL_CLI_STATIC)
    # Locate static archives directly and link by path. Using -Wl,-Bstatic on
    # library names would also pick up pthread statically, which we don't want.
    find_library(SODIUM_STATIC_ARCHIVE  NAMES libsodium.a
        HINTS ${SODIUM_LIBRARY_DIRS}  ${SODIUM_STATIC_LIBRARY_DIRS}  REQUIRED)

    # One archive per name the selected backend lists. A backend that lists no
    # names (openssl) is linked dynamically instead — see the note by its
    # CANTIL_X509_STATIC_NAMES above.
    if(CANTIL_X509_STATIC_NAMES)
        set(CANTIL_X509_LINK "")
        foreach(_archive IN LISTS CANTIL_X509_STATIC_NAMES)
            unset(_found CACHE)
            find_library(_found NAMES ${_archive}
                HINTS ${X509_LIBRARY_DIRS} ${X509_STATIC_LIBRARY_DIRS} REQUIRED)
            list(APPEND CANTIL_X509_LINK ${_found})
        endforeach()
        unset(_found CACHE)
    else()
        set(CANTIL_X509_LINK ${X509_LIBRARIES})
        target_link_directories(cantil-cli PRIVATE ${X509_LIBRARY_DIRS})
    endif()

    target_link_libraries(cantil-cli PRIVATE cantil
        ${SODIUM_STATIC_ARCHIVE}
        ${CANTIL_X509_LINK}
        pthread)
else()
    target_link_libraries(cantil-cli cantil ${SODIUM_LIBRARIES} ${X509_LIBRARIES})
    target_link_directories(cantil-cli PRIVATE ${X509_LIBRARY_DIRS})
endif()

# ── tests ──────────────────────────────────────────────────────────────────
#
# Conformance tests for the X.509 seam. Every backend is asked the same
# questions and must give the same answers; see tests/test_x509.c for why the
# expectations are golden values rather than backend-vs-backend comparisons.
#
#   cmake -B build_host -DCANTIL_BUILD_TESTS=ON libcantil && ctest --test-dir build_host
option(CANTIL_BUILD_TESTS "Build libcantil's host tests" OFF)

if(CANTIL_BUILD_TESTS)
    enable_testing()

    add_executable(test_x509 tests/test_x509.c ${CANTIL_X509_SRC})
    target_include_directories(test_x509
        PRIVATE src tests ${X509_INCLUDE_DIRS})
    target_compile_options(test_x509 PRIVATE
        -Wall -Wextra -Wpedantic ${X509_CFLAGS_OTHER})
    target_link_libraries(test_x509 PRIVATE ${X509_LIBRARIES})
    target_link_directories(test_x509 PRIVATE ${X509_LIBRARY_DIRS})

    add_test(NAME x509_${CANTIL_HOST_CRYPTO} COMMAND test_x509)
endif()
