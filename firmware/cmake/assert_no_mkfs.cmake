# SPDX-License-Identifier: GPL-3.0-or-later
#
# Post-link assertion: the production image must carry no callable
# filesystem-format entry point.
#
# CONFIG_FILE_SYSTEM_MKFS=n in prj.conf is the intent; this checks the result.
# The two are not the same thing. A board .conf, a snippet, a sysbuild fragment
# or a Zephyr module can turn the symbol back on — Kconfig `select` in
# particular does so silently, with no warning and nothing in the build log —
# and the failure is invisible until a device in the field erases its own CA
# key. So the linked ELF is the thing inspected, not the config.
#
# Expects: NM  — path to the target nm (Zephyr sets CMAKE_NM)
#          ELF — path to zephyr.elf
#
# ── What this can and cannot prove ────────────────────────────────────────
#
# Absent when the check passes:
#   fs_mkfs        the public API. Anything reachable from a command handler,
#                  an error path, or future code goes through here.
#   littlefs_mkfs  the backend op fs_mkfs dispatches to.
#   lfs_format     littlefs's own formatter, and the one that erased unit #2.
#                  No Kconfig removes it, so the build wraps it
#                  (-Wl,--wrap=lfs_format, src/storage/no_format.c) and
#                  --gc-sections then drops the unreferenced original.
#
# Required present:
#   __wrap_lfs_format   the refusing wrapper. Checked because a --wrap flag
#                  that stopped being applied — a reordered link line, a
#                  renamed symbol upstream, a dropped target_link_options —
#                  produces an ELF with no lfs_format either, and would sail
#                  through a banned-symbols-only check while the callers went
#                  back to the real formatter.
#
# A pass therefore means the erase path is not in the image, not merely that
# it is unreachable. What it still cannot prove: that a *future* Zephyr calls
# no other formatter. The wrapper covers lfs_format by name.

if(NOT EXISTS "${ELF}")
    message(FATAL_ERROR "assert_no_mkfs: no ELF at ${ELF}")
endif()

execute_process(
    COMMAND "${NM}" "${ELF}"
    OUTPUT_VARIABLE nm_out
    ERROR_VARIABLE  nm_err
    RESULT_VARIABLE nm_rc
)

# A check that silently passes because the tool failed is worse than no check.
if(NOT nm_rc EQUAL 0)
    message(FATAL_ERROR
        "assert_no_mkfs: '${NM}' failed (${nm_rc}) on ${ELF}\n${nm_err}\n"
        "Cannot verify that no format entry point was linked. Treating an "
        "unverifiable image as a failure rather than assuming it is clean.")
endif()

set(banned fs_mkfs littlefs_mkfs lfs_format)
set(found "")

foreach(sym IN LISTS banned)
    # Defined symbols only: " T fs_mkfs", " t fs_mkfs", " W fs_mkfs".
    # An undefined reference (" U ") would not have linked.
    #
    # The trailing \n keeps `lfs_format` from matching `__wrap_lfs_format`:
    # the pattern needs whitespace immediately before the name, and there the
    # preceding character is an underscore.
    if(nm_out MATCHES "[ \t][A-TV-Za-tv-z][ \t]+${sym}\n")
        list(APPEND found ${sym})
    endif()
endforeach()

if(found)
    string(REPLACE ";" ", " found_str "${found}")
    message(FATAL_ERROR
        "================================================================\n"
        "  Format entry point linked into the production image:\n"
        "      ${found_str}\n"
        "\n"
        "  This build can format the volume that holds the CA private\n"
        "  key. That key has no backup and cannot be exported, so a\n"
        "  format is unrecoverable key loss.\n"
        "\n"
        "  fs_mkfs / littlefs_mkfs: CONFIG_FILE_SYSTEM_MKFS is meant to\n"
        "  be n here. Something has turned it back on — check board .conf\n"
        "  files, snippets, and any Kconfig 'select FILE_SYSTEM_MKFS' in\n"
        "  an enabled module:\n"
        "      grep -rn FILE_SYSTEM_MKFS <build>/zephyr/.config\n"
        "\n"
        "  lfs_format: the --wrap redirected its callers, but something\n"
        "  still references the real one, so --gc-sections kept it. Find\n"
        "  what, and wrap or remove that caller too:\n"
        "      <nm> --print-size <build>/zephyr/zephyr.elf | grep lfs_format\n"
        "\n"
        "  Creating the volume is the step-1 factory image's job\n"
        "  (firmware/factory/, scripts/build.sh --factory).\n"
        "================================================================")
endif()

# Checked last, so that an ELF failing both reports the banned symbols first —
# those name the cause, this only names a missing safeguard.
#
# The wrapper must be present, or `lfs_format` being absent proves nothing: a
# --wrap flag that stopped applying and a wrap that worked produce the same
# banned-symbol result.
if(NOT nm_out MATCHES "[ \t][A-TV-Za-tv-z][ \t]+__wrap_lfs_format\n")
    message(FATAL_ERROR
        "================================================================\n"
        "  __wrap_lfs_format is not in the image.\n"
        "\n"
        "  The build is supposed to link with -Wl,--wrap=lfs_format so\n"
        "  that littlefs_mount()'s format branch resolves to a wrapper\n"
        "  that refuses. Without it, that branch reaches the real\n"
        "  formatter and one cleared mount flag erases the CA key.\n"
        "\n"
        "  Check that firmware/CMakeLists.txt still adds both\n"
        "  src/storage/no_format.c and the --wrap link option, and that\n"
        "  the option survives to the final link:\n"
        "      grep -- --wrap <build>/CMakeFiles/rules.ninja\n"
        "================================================================")
endif()
