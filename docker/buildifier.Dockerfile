# SPDX-License-Identifier: GPL-3.0-or-later
#
# buildifier — formats and lints Bazel BUILD/BUILD.bazel/MODULE.bazel/*.bzl
# files. No official image is published upstream, so this fetches the pinned
# release binary directly (checksum-verified) onto a minimal base.
#
# Build: podman build -t buildifier:local -f docker/buildifier.Dockerfile docker/
# Run:   podman run --rm -v "$PWD:$PWD:z" -w "$PWD" buildifier:local <args>
#        (see ~/bin/buildifier for the wrapper that does this)

FROM alpine:3.20

ARG BUILDIFIER_VERSION=10.1.0
ARG BUILDIFIER_SHA256=31b6a8aa1e5c746696788f428729701770ad91925873d8256cb885c60e12c77e

RUN apk add --no-cache curl && \
    curl -fL -o /usr/local/bin/buildifier \
      "https://github.com/bazel-contrib/buildtools/releases/download/v${BUILDIFIER_VERSION}/buildifier-linux-amd64" && \
    echo "${BUILDIFIER_SHA256}  /usr/local/bin/buildifier" | sha256sum -c - && \
    chmod +x /usr/local/bin/buildifier && \
    apk del curl

ENTRYPOINT ["/usr/local/bin/buildifier"]
