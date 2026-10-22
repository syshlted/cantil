# SPDX-License-Identifier: GPL-3.0-or-later
#
# UF2 family ids for Cantil's boards.
#
# The XIAO BLE ships an Adafruit UF2 bootloader and exposes SWD only on tiny
# underside test points, so dragging a .uf2 onto the mass-storage drive is the
# only routine way to flash one. Zephyr's CMake emits it as a post-build step
# when CONFIG_BUILD_OUTPUT_UF2=y; zephyr-bazel had no equivalent, which meant a
# Bazel-built image could not be flashed at all — the last thing keeping
# CMake/west on the critical path for day-to-day work.
#
# The support now lives where it belongs, in zephyr_app itself (via the overlay
# patch, gap 9): pass `uf2_family` and the app also emits <name>.uf2. It has to
# be there rather than in a genrule here, because the conversion must happen
# inside the app's platform transition — the objcopy that produces the hex only
# resolves in that configuration.

# CONFIG_BUILD_OUTPUT_UF2_FAMILY_ID for the nRF52840 family, as set by the
# board's Kconfig and confirmed against the CMake build's .config. A Kconfig
# *string* has no config_setting to select on, so it is named here rather than
# read from @zephyr_kconfig.
UF2_FAMILY_NRF52840 = "0xada52840"
