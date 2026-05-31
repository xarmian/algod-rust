#!/usr/bin/env bash
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

# `pub const CONSENSUS_CURRENT_VERSION: &str = CONSENSUS_V41;`
current_alias="$(grep -oP 'CONSENSUS_CURRENT_VERSION:\s*&str\s*=\s*\K[A-Z0-9_]+' "$consensus_rs")"
if [[ -z "${current_alias:-}" ]]; then
    echo "gen-localnet-genesis: could not resolve CONSENSUS_CURRENT_VERSION alias from $consensus_rs" >&2
    exit 1
fi

# `pub const CONSENSUS_V41: &str =\n    "https://...";`
proto_url="$(grep -A1 -P "pub const ${current_alias}:\s*&str\s*=" "$consensus_rs" \
    | grep -oP '"\K[^"]+(?=")' | head -n1)"
if [[ -z "${proto_url:-}" ]]; then
    echo "gen-localnet-genesis: could not resolve $current_alias spec URL from $consensus_rs" >&2
    exit 1
fi

sed "s|@CONSENSUS_CURRENT_VERSION@|${proto_url}|" "$template" > "$out"
echo "gen-localnet-genesis: wrote $out (proto = $current_alias -> $proto_url)"
