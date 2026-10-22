# SPDX-License-Identifier: GPL-3.0-or-later
#
# Shared plumbing for the Cantil ztest suites under Bazel.
#
# Each suite under firmware/tests/ is its own Zephyr application (prj.conf +
# Kconfig + boards/native_sim.overlay) that compiles the *real* firmware
# translation units — that is what makes them conformance tests rather than
# mocks. Bazel cannot reach across a package boundary with a relative source
# path, so the firmware .c files arrive as //firmware: labels (exported there)
# and the headers via //firmware:fw_headers.
#
# Run them with:
#   bazelisk test //firmware/tests/... --config=sim
#
# Suites that mint DER additionally declare `openssl_gate = True`, which adds a
# <suite>_openssl_gate test running the same scripts/openssl_gate.sh that
# scripts/test.sh runs on the CMake path — one implementation, two runners, so
# they cannot drift.

load("@rules_shell//shell:sh_test.bzl", "sh_test")
load("@zephyr//:cc.bzl", "zephyr_cc_library")
load("@zephyr-bazel//bazel_overlay:cc_test.bzl", "ztest")

# Firmware source groups, named after the CMakeLists.txt blocks they mirror.
CRYPTO_SRCS = [
    "//firmware:src/crypto/crypto_wolfssl.c",
    "//firmware:src/crypto/wc_rand.c",
    "//firmware:src/crypto/zeroize.c",
    "//firmware:src/crypto/device_id.c",
]

STORAGE_SRCS = [
    "//firmware:src/storage/storage.c",
    "//firmware:src/storage/volume_marker.c",
]

CA_SRCS = [
    "//firmware:src/ca/ca.c",
    "//firmware:src/ca/der_write.c",
    "//firmware:src/ca/certgen_wolfssl.c",
    "//firmware:src/ca/certparse_wolfssl.c",
]

CBOR_SRCS = ["//common/cbor:cantil_cbor.c"]

# Deps every suite that touches wolfCrypt needs: the wolfSSL library, the
# user-settings header that configures it (also puts firmware/include on the
# path, matching CMake's zephyr_include_directories(${FW}/include)), and the
# firmware headers.
WOLFSSL_DEPS = [
    "//firmware:fw_headers",
    "//firmware:wolfssl",
    "//firmware:wolfssl_config",
]

CBOR_DEPS = ["//common/cbor:cbor_headers"]

# storage.c mounts a real LittleFS on the sim flash partition (each suite's
# boards/native_sim.overlay enlarges it), so it needs both <lfs.h> and the
# library itself alongside Zephyr's littlefs_fs.c glue.
STORAGE_DEPS = ["//firmware:littlefs"]

def cantil_ztest(
        name,
        srcs,
        deps = [],
        includes = ["src"],
        copts = [],
        openssl_gate = False,
        **kwargs):
    """Declares one ztest suite: a Zephyr app library plus its test runner.

    Args:
      name: suite name; must match the directory name.
      srcs: suite sources plus the firmware translation units under test.
      deps: extra cc deps (see WOLFSSL_DEPS / CBOR_DEPS).
      includes: include dirs relative to the suite package (its own src/ by
        default, matching the CMake target_include_directories).
      copts: extra compiler flags.
      openssl_gate: set on suites that emit DER via test_artifacts.h. Adds a
        <name>_openssl_gate test that re-runs the suite binary with
        CANTIL_TEST_ARTIFACT_DIR set and checks the result with the OpenSSL
        CLI — a third implementation, and the only thing that catches a
        writer and reader from the same library agreeing on wrong DER.
      **kwargs: forwarded to ztest().
    """
    zephyr_cc_library(
        name = name + "_lib",
        testonly = True,
        srcs = srcs,
        # The suite's own headers and .inc bodies (test vectors, control
        # shims). Unlike CMake, Bazel only stages files a target declares.
        hdrs = native.glob(
            ["src/**/*.h", "src/**/*.inc"],
            allow_empty = True,
        ),
        # Zephyr's CMake does not -Werror the application (that is gated on
        # CONFIG_COMPILER_WARNINGS_AS_ERRORS=n); zephyr-bazel does. Same
        # demotion as //firmware:app_lib.
        copts = ["-Wno-error", "-Wno-unused-parameter"] + copts,
        includes = includes,
        deps = deps,
    )

    ztest(
        name = name,
        deps = [":" + name + "_lib"],
        **kwargs
    )

    if openssl_gate:
        # Runs the same binary a second time rather than reusing the ztest
        # target's run: Bazel tests have no post-run hook, and the artifact
        # directory has to exist in the environment *before* the suite starts.
        # A native_sim suite costs well under a second, so the duplicate run is
        # cheaper than any mechanism that would avoid it.
        sh_test(
            name = name + "_openssl_gate",
            srcs = ["//firmware/tests:openssl_gate_runner.sh"],
            args = [
                "$(rootpath :{}_bin)".format(name),
                "$(rootpath //scripts:openssl_gate.sh)",
            ],
            data = [
                ":" + name + "_bin",
                "//scripts:openssl_gate.sh",
            ],
            # The gate shells out to the host's `openssl`, which is the entire
            # point — an oracle built by this build system would not be
            # independent of it.
            tags = ["no-sandbox"],
            target_compatible_with = ["@zephyr//boards:sim"],
        )
