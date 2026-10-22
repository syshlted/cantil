#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Invoke the *pinned* Bazel, from inside a flatpak sandbox or from the host.
#
# Usage:
#   ./scripts/bazelisk-shim.sh query //firmware:cantil.uf2
#
# This exists for editor integrations (the VS Code Bazel extension's
# `bazel.executable` setting) that spawn a bare `bazel` binary. Two things go
# wrong with that here:
#
#   1. The host's /usr/bin/bazel is Fedora's real Bazel 9 RPM, which ignores
#      .bazelversion. This tree pins 8.7.0 — under 9 the module graph fails to
#      resolve outright (bazel_tools wants rules_swift 3.x, compatibility level
#      3; rules_apple 4.1.0 pulls 2.4.0, level 2). bazelisk honors the pin.
#   2. When the editor is itself a flatpak, its extension host has neither
#      bazel nor bazelisk on PATH — /usr belongs to the runtime, and the
#      host's lives at /run/host/usr/bin. Running that host binary against the
#      runtime's libc, with a sandbox view of the workspace, is not something
#      to rely on; hop to the host instead.
#
# So: always bazelisk, and go through flatpak-spawn when sandboxed.
# flatpak-spawn preserves the working directory, which Bazel needs to find the
# workspace root.
set -eu

if [ -f /.flatpak-info ]; then
    exec flatpak-spawn --host bazelisk "$@"
fi

exec bazelisk "$@"
