# SPDX-License-Identifier: GPL-3.0-or-later
#
# cppcheck — static analysis for C/C++.
#
# The obvious community image (docker.io/ams21/cppcheck) is broken as of
# 2026-09: its cppcheck binary fails to load libpcre.so.1 at runtime. Building
# from Debian's package instead, which pulls a matching libpcre automatically.
#
# Build: podman build -t cppcheck:local -f docker/cppcheck.Dockerfile docker/
# Run:   podman run --rm -v "$PWD:$PWD:z" -w "$PWD" cppcheck:local <args>
#        (see ~/bin/cppcheck for the wrapper that does this)

FROM debian:trixie-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends cppcheck && \
    rm -rf /var/lib/apt/lists/*

ENTRYPOINT ["cppcheck"]
