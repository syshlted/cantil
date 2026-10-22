# SPDX-License-Identifier: GPL-3.0-or-later
#
# Step-1 factory image — creates the LittleFS volume and writes its identity
# marker, then stops. No CA, no transport, no gesture, no key material.
#
# This is the only Cantil binary that contains lfs_format. Production is built
# with CONFIG_FILE_SYSTEM_MKFS=n and physically cannot format the volume; the
# ability to do so lives here, in an image flashed deliberately at a bench.
#
# Build:
#   scripts/build.sh --factory
#
# See docs/roadmap/two-step-provisioning.md.

cmake_minimum_required(VERSION 3.20.0)

# The shared board overlays live in firmware/boards and reference bindings
# under firmware/dts. Point DTS_ROOT at firmware/ so this app resolves them
# exactly as the production app does — the factory image and production MUST
# agree on the storage partition, since the marker's whole purpose is to
# assert that they do.
list(APPEND DTS_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/..)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(cantil_factory VERSION 0.2.0)

target_sources(app PRIVATE
    src/main.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/storage/volume_marker.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/crypto/device_id.c
)

target_include_directories(app PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../src
)
