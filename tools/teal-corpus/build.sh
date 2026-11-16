#!/usr/bin/env bash
# Copyright (c) 2026 Algod DAO
# SPDX-License-Identifier: MIT
# See the LICENSE-MIT file in the repository root for the full license text.
#
# Build the Phase 25 go-algorand TEAL corpus driver (issue #2366) against the
# pinned sibling ../go-algorand checkout and stamp the go-algorand tag and commit
# it was built against into the binary (they are printed in every output header).
#
# go-algorand's crypto package links the vendored libsodium fork via cgo, so run
# `make libsodium` in the go-algorand checkout first (CLAUDE.md, CI Workflows).
#
# Usage: build.sh [OUT]   (default OUT=./teal-corpus-go)
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GO_ALGORAND_DIR="${GO_ALGORAND_DIR:-$(cd "$HERE/../../../go-algorand" && pwd)}"
OUT="${1:-$HERE/teal-corpus-go}"
TAG="$(git -C "$GO_ALGORAND_DIR" describe --tags --exact-match 2>/dev/null || echo untagged)"
COMMIT="$(git -C "$GO_ALGORAND_DIR" rev-parse HEAD)"
cd "$HERE"
go build -o "$OUT" -ldflags "-X main.goAlgorandTag=$TAG -X main.goAlgorandCommit=$COMMIT" .
echo "built $OUT (go-algorand $TAG $COMMIT)" >&2
