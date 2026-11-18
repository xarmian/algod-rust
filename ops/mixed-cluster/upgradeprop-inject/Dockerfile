# Copyright (c) 2026 Algod DAO
# SPDX-License-Identifier: MIT
# See the LICENSE-MIT file in the repository root for the full license text.

# Issue #2400: a TEST-ONLY go-algorand v5.0.5-stable algod whose block proposer
# can put an arbitrary byte string (e.g. non-UTF-8) into `upgradeprop`.
#
# go accepts any such proposal from any proposer (data/bookkeeping/block.go
# applyUpgradeVote checks only the length and the wait-round range), but an
# unmodified go node only ever proposes the keys of its own ApprovedUpgrades,
# and consensus.json cannot carry a non-UTF-8 key (encoding/json replaces
# invalid UTF-8 with U+FFFD). inject.patch adds an env-driven hook to
# ProcessUpgradeParams (proposer side only); with ALGOD_TEST_INJECT_UPGRADEPROP_HEX
# unset the binary behaves exactly like the release. Only go-node-1 runs this
# image, and only under ops/mixed-cluster/scripts/upgradeprop-nonutf8.sh.
#
# Build (the script does this when the image is missing):
#   docker build -t algod-upgradeprop-inject:local ops/mixed-cluster/upgradeprop-inject

FROM golang:1.25.3-bookworm AS build
RUN apt-get update \
    && apt-get install -y --no-install-recommends autoconf automake libtool build-essential \
    && rm -rf /var/lib/apt/lists/*
ARG GO_ALGORAND_REF=v5.0.5-stable
ADD --keep-git-dir=false https://github.com/algorand/go-algorand.git#${GO_ALGORAND_REF} /src
WORKDIR /src
COPY inject.patch /tmp/inject.patch
RUN git apply --verbose /tmp/inject.patch
# go-algorand's crypto package links the vendored libsodium fork (CLAUDE.md).
RUN make libsodium
RUN go build -buildvcs=false -o /out/algod ./cmd/algod

FROM algorand/algod:5.0.5-stable
COPY --from=build /out/algod /node/bin/algod
