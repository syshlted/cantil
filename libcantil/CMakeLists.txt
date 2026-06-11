cmake_minimum_required(VERSION 3.16)
project(libcantil C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_EXTENSIONS OFF)

find_package(PkgConfig REQUIRED)
pkg_check_modules(SODIUM  REQUIRED libsodium)
pkg_check_modules(MBEDTLS REQUIRED mbedtls mbedx509 mbedcrypto)

# ── libcantil ─────────────────────────────────────────────────────────────
add_library(cantil STATIC
    src/transport.c
    src/transport_usb.c
    src/discover_usb.c
    src/session.c
    src/trust.c
    src/key_store.c
    src/device.c
    src/ca.c
    src/clients.c
    src/pairing.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../common/cbor/cantil_cbor.c
)

target_include_directories(cantil
    PUBLIC  include
    PRIVATE src ${SODIUM_INCLUDE_DIRS} ${MBEDTLS_INCLUDE_DIRS}
            ${CMAKE_CURRENT_SOURCE_DIR}/../common/cbor
)

target_compile_options(cantil PRIVATE
    -Wall -Wextra -Wpedantic
    ${SODIUM_CFLAGS_OTHER} ${MBEDTLS_CFLAGS_OTHER}
)

# libcantil is a STATIC library, so its dependencies are "private" in the
# sense that consumers must provide them at link time. Marking PRIVATE keeps
# CMake from auto-propagating them onto the CLI's link line.
target_link_libraries(cantil PRIVATE ${SODIUM_LIBRARIES} ${MBEDTLS_LIBRARIES})

# ── cantil CLI tool ────────────────────────────────────────────────────────
#
# CANTIL_CLI_STATIC=ON statically links libsodium into the CLI so the binary
# has no runtime dependencies beyond glibc. Used by scripts/build-appimage.sh
# to produce a self-contained AppImage.
option(CANTIL_CLI_STATIC "Statically link the cantil CLI (AppImage builds)" OFF)

add_executable(cantil-cli cli/main.c)

set_target_properties(cantil-cli PROPERTIES OUTPUT_NAME cantil)

target_include_directories(cantil-cli PRIVATE ${SODIUM_INCLUDE_DIRS} ${MBEDTLS_INCLUDE_DIRS})
target_compile_options(cantil-cli PRIVATE -Wall -Wextra ${SODIUM_CFLAGS_OTHER})

if(CANTIL_CLI_STATIC)
    # Locate static archives directly and link by path. Using -Wl,-Bstatic on
    # library names would also pick up pthread statically, which we don't want.
    find_library(SODIUM_STATIC_ARCHIVE  NAMES libsodium.a
        HINTS ${SODIUM_LIBRARY_DIRS}  ${SODIUM_STATIC_LIBRARY_DIRS}  REQUIRED)
    find_library(MBEDTLS_STATIC_ARCHIVE   NAMES libmbedtls.a
        HINTS ${MBEDTLS_LIBRARY_DIRS}  ${MBEDTLS_STATIC_LIBRARY_DIRS}  REQUIRED)
    find_library(MBEDX509_STATIC_ARCHIVE  NAMES libmbedx509.a
        HINTS ${MBEDTLS_LIBRARY_DIRS}  ${MBEDTLS_STATIC_LIBRARY_DIRS}  REQUIRED)
    find_library(MBEDCRYPTO_STATIC_ARCHIVE NAMES libmbedcrypto.a
        HINTS ${MBEDTLS_LIBRARY_DIRS}  ${MBEDTLS_STATIC_LIBRARY_DIRS}  REQUIRED)
    target_link_libraries(cantil-cli PRIVATE cantil
        ${SODIUM_STATIC_ARCHIVE}
        ${MBEDTLS_STATIC_ARCHIVE} ${MBEDX509_STATIC_ARCHIVE} ${MBEDCRYPTO_STATIC_ARCHIVE}
        pthread)
else()
    target_link_libraries(cantil-cli cantil ${SODIUM_LIBRARIES} ${MBEDTLS_LIBRARIES})
endif()
