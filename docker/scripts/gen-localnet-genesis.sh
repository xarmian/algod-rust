#!/usr/bin/env bash

# Copyright (c) 2026 Algod DAO
# SPDX-License-Identifier: MIT
# See the LICENSE-MIT file in the repository root for the full license text.

# Generate the docker localnet `genesis.json` from `genesis.json.in`,
# deriving the `proto` spec-URL from the single shared Rust constant
# `CONSENSUS_CURRENT_VERSION` (crates/core/algo-types/src/consensus.rs)
# rather than hardcoding the V41 URL (BT-284 / Parent: PLAN-262).
#
# This keeps the dev-only localnet genesis tracking the project's current
# consensus version automatically: bumping `CONSENSUS_CURRENT_VERSION`
# regenerates a genesis with the matching proto on the next `localnet-rust-up`.
#
# Go reference: protocol/consensus.go `ConsensusCurrentVersion`.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
consensus_rs="$repo_root/crates/core/algo-types/src/consensus.rs"
template="$repo_root/docker/localnet-rust/data/genesis.json.in"
out="$repo_root/docker/localnet-rust/data/genesis.json"

if [[ ! -f "$consensus_rs" ]]; then
    echo "gen-localnet-genesis: missing $consensus_rs" >&2
    exit 1
fi

# Resolve the alias `CONSENSUS_CURRENT_VERSION` points at, e.g.
#   pub const CONSENSUS_CURRENT_VERSION: &str = CONSENSUS_V41;
# Portable POSIX sed (works under GNU + BSD/macOS) — no `grep -P`/`-oP`.
current_alias="$(sed -n 's/.*CONSENSUS_CURRENT_VERSION:[[:space:]]*&str[[:space:]]*=[[:space:]]*\([A-Z0-9_]*\);.*/\1/p' "$consensus_rs" | head -n1)"
if [[ -z "${current_alias:-}" ]]; then
    echo "gen-localnet-genesis: could not resolve CONSENSUS_CURRENT_VERSION alias from $consensus_rs" >&2
    exit 1
fi

# Resolve that alias to its spec URL. The const spans two lines:
#   pub const CONSENSUS_V41: &str =
#       "https://...";
# Anchor on the const line, then take the first quoted string that follows.
proto_url="$(sed -n "/pub const ${current_alias}:[[:space:]]*&str[[:space:]]*=/,/;/p" "$consensus_rs" \
    | sed -n 's/.*"\([^"]*\)".*/\1/p' | head -n1)"
if [[ -z "${proto_url:-}" ]]; then
    echo "gen-localnet-genesis: could not resolve $current_alias spec URL from $consensus_rs" >&2
    exit 1
fi

sed "s|@CONSENSUS_CURRENT_VERSION@|${proto_url}|" "$template" > "$out"
echo "gen-localnet-genesis: wrote $out (proto = $current_alias -> $proto_url)"
