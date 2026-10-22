# SPDX-License-Identifier: GPL-3.0-or-later
#
# Sparse secure-wipe diagnostic image. Erases+zeroes the external QSPI part
# block by block and records per-block results (and error codes) to a fixed
# region of internal flash, retrievable via the UF2 bootloader's CURRENT.UF2.
# See src/main.c and scripts/decode_wipe_log.py.
#
# Build:
#   scripts/build.sh --source firmware/wipe_diag

cmake_minimum_required(VERSION 3.20.0)

# Shared board overlays live in firmware/boards. Point DTS_ROOT at firmware/ so
# the code-partition-at-0x1000 override (needed for the UF2 bootloader) and the
# p25q16h storage node resolve exactly as they do for production and factory.
list(APPEND DTS_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/..)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(cantil_wipe_diag VERSION 0.2.0)

target_sources(app PRIVATE src/main.c)
